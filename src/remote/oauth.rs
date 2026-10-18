// SPDX-FileCopyrightText: Copyright 2026 Alexander Orlov <info@lifub.com>

//! OAuth 2.0 for installed applications against Google (RFC 8252): a loopback
//! redirect with PKCE S256 (RFC 7636) and a `state` check, a paste-back
//! variant for hosts without a local browser, and the refresh-token source
//! the Drive client uses. Secrets never reach `Debug` output, logs or error
//! messages.

use std::io::{ErrorKind, Read, Write};
use std::net::{Ipv4Addr, TcpListener, TcpStream};
use std::path::Path;
use std::process::Stdio;
use std::sync::mpsc;
use std::time::{Duration, Instant};

use serde::Deserialize;
use sha2::{Digest, Sha256};

use super::gdrive::TokenSource;
use super::{RemoteError, form_encode, form_pairs, hex, read_private_file};
use crate::crypto::fill_random;
use crate::prompt::SecretReader;

pub(crate) const AUTH_URL: &str = "https://accounts.google.com/o/oauth2/v2/auth";
pub(crate) const TOKEN_URL: &str = "https://oauth2.googleapis.com/token";
/// Full Drive access: the remote folder may live under a Drive for desktop
/// "Computers" folder, which the narrower `drive.file` scope cannot reach.
pub(crate) const DRIVE_SCOPE: &str = "https://www.googleapis.com/auth/drive";
/// How long the loopback flow waits for the browser consent.
pub(crate) const CONSENT_TIMEOUT: Duration = Duration::from_secs(600);

const MAX_CLIENT_FILE: u64 = 64 << 10;
const MAX_TOKEN_RESPONSE: u64 = 64 << 10;
const MAX_REDIRECT_REQUEST: usize = 16 << 10;
const MAX_LOOPBACK_CONNECTIONS: usize = 64;
const MAX_SECRET_LEN: usize = 4096;

/// The authorization and token endpoints. Tests point both at the fake.
#[derive(Clone, Debug)]
pub(crate) struct Endpoints {
    pub(crate) auth: String,
    pub(crate) token: String,
}

impl Endpoints {
    pub(crate) fn google() -> Self {
        Self {
            auth: AUTH_URL.to_string(),
            token: TOKEN_URL.to_string(),
        }
    }
}

/// A Google "Desktop app" OAuth client as downloaded from the Cloud console.
#[derive(Clone)]
pub(crate) struct OAuthClient {
    pub(crate) id: String,
    secret: String,
}

impl std::fmt::Debug for OAuthClient {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("OAuthClient")
            .field("id", &self.id)
            .field("secret", &"<redacted>")
            .finish()
    }
}

fn is_token_text(text: &str) -> bool {
    !text.is_empty() && text.len() <= MAX_SECRET_LEN && text.bytes().all(|b| b.is_ascii_graphic())
}

impl OAuthClient {
    /// Loads a client file that only its owner can read or write.
    pub(crate) fn load(path: &Path) -> Result<Self, RemoteError> {
        let context = |detail: String| {
            RemoteError::Local(format!("OAuth client file {}: {detail}", path.display()))
        };
        let bytes = read_private_file(path, MAX_CLIENT_FILE)
            .map_err(|error| match error {
                RemoteError::Local(detail) => {
                    RemoteError::Local(format!("OAuth client file {detail}"))
                }
                other => other,
            })?
            .ok_or_else(|| {
                context(
                    "does not exist; download the Desktop OAuth client JSON from the Google Cloud console and store it with mode 0600"
                        .to_string(),
                )
            })?;
        Self::parse(&bytes).map_err(|error| match error {
            RemoteError::Local(detail) => context(detail),
            other => other,
        })
    }

    /// Parses the downloaded JSON. Only a Desktop ("installed") client may
    /// use a loopback redirect without registering it.
    pub(crate) fn parse(bytes: &[u8]) -> Result<Self, RemoteError> {
        #[derive(Deserialize)]
        struct Download {
            installed: Option<Installed>,
            web: Option<serde_json::Value>,
        }
        #[derive(Deserialize)]
        struct Installed {
            client_id: String,
            client_secret: String,
        }
        // serde_json errors can quote values, so the detail is not reported.
        let download: Download = serde_json::from_slice(bytes).map_err(|_| {
            RemoteError::Local("not a Google OAuth client JSON download".to_string())
        })?;
        let Some(installed) = download.installed else {
            return Err(RemoteError::Local(if download.web.is_some() {
                "is a Web application client; create a Desktop app client instead".to_string()
            } else {
                "has no Desktop app (\"installed\") client".to_string()
            }));
        };
        if !installed.client_id.ends_with(".apps.googleusercontent.com")
            || installed.client_id.len() > 256
            || !is_token_text(&installed.client_id)
        {
            return Err(RemoteError::Local(
                "the client_id is not a Google OAuth client identifier".to_string(),
            ));
        }
        if installed.client_secret.len() > 256 || !is_token_text(&installed.client_secret) {
            return Err(RemoteError::Local(
                "the client_secret is malformed".to_string(),
            ));
        }
        Ok(Self {
            id: installed.client_id,
            secret: installed.client_secret,
        })
    }
}

/// Unpadded base64url (RFC 4648 section 5), as PKCE requires.
fn base64url(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let word = (u32::from(chunk[0]) << 16)
            | (u32::from(chunk.get(1).copied().unwrap_or(0)) << 8)
            | u32::from(chunk.get(2).copied().unwrap_or(0));
        for digit in 0..=chunk.len() {
            out.push(ALPHABET[((word >> (18 - 6 * digit)) & 63) as usize] as char);
        }
    }
    out
}

fn s256_challenge(verifier: &str) -> String {
    let digest: [u8; 32] = Sha256::digest(verifier.as_bytes()).into();
    base64url(&digest)
}

/// One authorization attempt's PKCE verifier and CSRF `state`.
struct Attempt {
    verifier: String,
    state: String,
}

impl Attempt {
    fn new() -> Self {
        let mut verifier = [0u8; 48];
        fill_random(&mut verifier);
        let mut state = [0u8; 16];
        fill_random(&mut state);
        Self {
            verifier: base64url(&verifier),
            state: hex(&state),
        }
    }
}

fn encode_form(params: &[(&str, &str)]) -> String {
    params
        .iter()
        .map(|(key, value)| format!("{}={}", form_encode(key), form_encode(value)))
        .collect::<Vec<_>>()
        .join("&")
}

fn authorization_url(
    endpoints: &Endpoints,
    client: &OAuthClient,
    redirect_uri: &str,
    attempt: &Attempt,
    login_hint: Option<&str>,
) -> String {
    let challenge = s256_challenge(&attempt.verifier);
    let mut params = vec![
        ("client_id", client.id.as_str()),
        ("redirect_uri", redirect_uri),
        ("response_type", "code"),
        ("scope", DRIVE_SCOPE),
        ("code_challenge", challenge.as_str()),
        ("code_challenge_method", "S256"),
        ("state", attempt.state.as_str()),
        // A refresh token is only issued for offline access, and only on
        // a fresh consent.
        ("access_type", "offline"),
        ("prompt", "consent"),
    ];
    if let Some(hint) = login_hint {
        params.push(("login_hint", hint));
    }
    format!("{}?{}", endpoints.auth, encode_form(&params))
}

/// Keeps a provider-chosen error code printable and short.
fn sanitize(text: &str) -> String {
    text.chars()
        .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.'))
        .take(80)
        .collect()
}

/// Extracts the authorization code from a redirect request target or a
/// pasted address. `Ok(None)` is an unrelated request, such as a favicon.
fn code_from_redirect(address: &str, state: &str) -> Result<Option<String>, RemoteError> {
    let address = address.trim();
    let address = address
        .split_once('#')
        .map_or(address, |(before, _)| before);
    let Some((_, query)) = address.split_once('?') else {
        return Ok(None);
    };
    let pairs = form_pairs(query)
        .ok_or_else(|| RemoteError::Auth("the redirect address is malformed".to_string()))?;
    if !pairs.contains_key("code") && !pairs.contains_key("error") {
        return Ok(None);
    }
    if pairs.get("state").map(String::as_str) != Some(state) {
        return Err(RemoteError::Auth(
            "the redirect does not carry this attempt's state value; refusing it".to_string(),
        ));
    }
    if let Some(error) = pairs.get("error") {
        return Err(RemoteError::Auth(format!(
            "Google refused the authorization ({})",
            sanitize(error)
        )));
    }
    let code = &pairs["code"];
    if !is_token_text(code) {
        return Err(RemoteError::Auth(
            "the authorization code is malformed".to_string(),
        ));
    }
    Ok(Some(code.clone()))
}

fn read_request_target(stream: &mut TcpStream) -> std::io::Result<Option<String>> {
    let mut request = Vec::new();
    let mut buffer = [0u8; 2048];
    while !request.windows(4).any(|window| window == b"\r\n\r\n") {
        if request.len() > MAX_REDIRECT_REQUEST {
            return Ok(None);
        }
        let read = stream.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        request.extend_from_slice(&buffer[..read]);
    }
    let line_end = request
        .iter()
        .position(|&byte| byte == b'\r' || byte == b'\n')
        .unwrap_or(request.len());
    let Ok(line) = std::str::from_utf8(&request[..line_end]) else {
        return Ok(None);
    };
    let mut parts = line.split(' ');
    Ok(match (parts.next(), parts.next()) {
        (Some("GET"), Some(target)) => Some(target.to_string()),
        _ => None,
    })
}

fn respond(stream: &mut TcpStream, status: u16, text: &str) {
    let reason = match status {
        200 => "OK",
        404 => "Not Found",
        _ => "Bad Request",
    };
    let _ = write!(
        stream,
        "HTTP/1.1 {status} {reason}\r\nContent-Type: text/plain; charset=utf-8\r\n\
         Content-Length: {}\r\nCache-Control: no-store\r\nReferrer-Policy: no-referrer\r\n\
         Connection: close\r\n\r\n{text}",
        text.len()
    );
    let _ = stream.flush();
}

/// Answers one loopback request. `None` means it was unrelated.
fn answer_redirect(mut stream: TcpStream, state: &str) -> Option<Result<String, RemoteError>> {
    let _ = stream.set_read_timeout(Some(Duration::from_secs(30)));
    let _ = stream.set_write_timeout(Some(Duration::from_secs(10)));
    let Ok(Some(target)) = read_request_target(&mut stream) else {
        respond(&mut stream, 400, "Bad request.");
        return None;
    };
    let outcome = code_from_redirect(&target, state);
    let (status, text) = match &outcome {
        Ok(Some(_)) => (
            200,
            "zerotrust-drive received the authorization. You can close this tab.",
        ),
        Ok(None) => (404, "Not found."),
        Err(_) => (
            400,
            "zerotrust-drive refused this authorization response; see the terminal.",
        ),
    };
    respond(&mut stream, status, text);
    outcome.transpose()
}

/// Serves the loopback redirect until a matching consent, a refusal or the
/// timeout. Each connection gets its own thread, so a browser's idle
/// preconnect cannot hold up the real redirect.
fn await_redirect(
    listener: TcpListener,
    state: &str,
    timeout: Duration,
) -> Result<String, RemoteError> {
    listener.set_nonblocking(true)?;
    let deadline = Instant::now() + timeout;
    let (sender, receiver) = mpsc::channel();
    let mut connections = 0usize;
    loop {
        if let Ok(outcome) = receiver.try_recv() {
            return outcome;
        }
        match listener.accept() {
            Ok((stream, _)) => {
                connections += 1;
                if connections > MAX_LOOPBACK_CONNECTIONS {
                    return Err(RemoteError::Auth(
                        "too many unrelated connections reached the loopback redirect".to_string(),
                    ));
                }
                stream.set_nonblocking(false)?;
                let sender = sender.clone();
                let state = state.to_string();
                std::thread::Builder::new()
                    .name("zdrive-oauth-redirect".to_string())
                    .spawn(move || {
                        if let Some(outcome) = answer_redirect(stream, &state) {
                            let _ = sender.send(outcome);
                        }
                    })?;
            }
            Err(error) if error.kind() == ErrorKind::WouldBlock => {
                if Instant::now() >= deadline {
                    return Err(RemoteError::Auth(format!(
                        "no browser consent arrived within {} s",
                        timeout.as_secs()
                    )));
                }
                std::thread::sleep(Duration::from_millis(25));
            }
            Err(error) if error.kind() == ErrorKind::Interrupted => {}
            Err(error) => return Err(error.into()),
        }
    }
}

#[derive(Deserialize)]
struct TokenResponse {
    access_token: String,
    expires_in: u64,
    #[serde(default)]
    refresh_token: Option<String>,
    #[serde(default)]
    scope: Option<String>,
    #[serde(default)]
    token_type: Option<String>,
}

#[derive(Deserialize)]
struct TokenError {
    error: String,
}

fn token_request(
    agent: &ureq::Agent,
    url: &str,
    form: &[(&str, &str)],
    what: &str,
) -> Result<TokenResponse, RemoteError> {
    let body = encode_form(form);
    let mut response = agent
        .post(url)
        .header("Content-Type", "application/x-www-form-urlencoded")
        .header("Accept", "application/json")
        .send(body.as_bytes())
        .map_err(|error| RemoteError::Network(format!("{what}: {error}")))?;
    let status = response.status().as_u16();
    let bytes = response
        .body_mut()
        .with_config()
        .limit(MAX_TOKEN_RESPONSE)
        .read_to_vec()
        .map_err(|error| {
            RemoteError::Network(format!("{what}: reading the response failed: {error}"))
        })?;
    if status == 200 {
        let token: TokenResponse = serde_json::from_slice(&bytes).map_err(|_| {
            RemoteError::Protocol(format!(
                "{what}: the token response is not the expected JSON"
            ))
        })?;
        if !is_token_text(&token.access_token)
            || token
                .token_type
                .as_deref()
                .is_some_and(|kind| !kind.eq_ignore_ascii_case("bearer"))
        {
            return Err(RemoteError::Protocol(format!(
                "{what}: the response carries no usable bearer token"
            )));
        }
        return Ok(token);
    }
    let error = serde_json::from_slice::<TokenError>(&bytes)
        .map(|body| sanitize(&body.error))
        .unwrap_or_default();
    let rejected = matches!(
        error.as_str(),
        "invalid_grant"
            | "invalid_client"
            | "unauthorized_client"
            | "access_denied"
            | "invalid_scope"
            | "org_internal"
            | "admin_policy_enforced"
            | "disabled_client"
            | "deleted_client"
    );
    Err(match status {
        400 | 401 | 403 if rejected => RemoteError::Auth(format!(
            "{what} was rejected ({error}); run `zdrive remote auth` again"
        )),
        408 | 429 | 500..=599 => RemoteError::Network(format!("{what}: HTTP {status}")),
        _ => RemoteError::Protocol(format!("{what}: HTTP {status} {error}")),
    })
}

/// A completed consent: the long-lived refresh token to keep in the vault.
pub(crate) struct Authorization {
    pub(crate) refresh_token: String,
}

impl std::fmt::Debug for Authorization {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("Authorization { refresh_token: <redacted> }")
    }
}

fn authorization_from(token: TokenResponse) -> Result<Authorization, RemoteError> {
    if let Some(scope) = &token.scope
        && !scope.split(' ').any(|granted| granted == DRIVE_SCOPE)
    {
        return Err(RemoteError::Auth(
            "the consent did not grant full Google Drive access; authorize again and allow access to all Drive files"
                .to_string(),
        ));
    }
    match token.refresh_token {
        Some(refresh_token) if is_token_text(&refresh_token) => Ok(Authorization { refresh_token }),
        _ => Err(RemoteError::Auth(
            "Google returned no refresh token; remove zerotrust-drive at https://myaccount.google.com/permissions and authorize again"
                .to_string(),
        )),
    }
}

/// How the user approves access.
pub(crate) enum Consent<'a> {
    /// Listen on a loopback port and open the consent page in a browser.
    Loopback {
        open: &'a dyn Fn(&str) -> std::io::Result<()>,
        timeout: Duration,
    },
    /// Print the consent page and read the redirected address back, for a
    /// host without a local browser.
    Paste(&'a mut dyn SecretReader),
}

/// Runs one installed-app authorization and exchanges its code.
pub(crate) fn authorize(
    agent: &ureq::Agent,
    client: &OAuthClient,
    endpoints: &Endpoints,
    login_hint: Option<&str>,
    consent: Consent<'_>,
    notice: &mut dyn Write,
) -> Result<Authorization, RemoteError> {
    let attempt = Attempt::new();
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
    let redirect_uri = format!("http://127.0.0.1:{}", listener.local_addr()?.port());
    let url = authorization_url(endpoints, client, &redirect_uri, &attempt, login_hint);
    let code = match consent {
        Consent::Loopback { open, timeout } => {
            writeln!(
                notice,
                "zerotrust-drive: approve access in the browser. If it does not open, visit:\n{url}"
            )?;
            if let Err(error) = open(&url) {
                writeln!(
                    notice,
                    "zerotrust-drive: could not open a browser ({error}); open the address above"
                )?;
            }
            await_redirect(listener, &attempt.state, timeout)?
        }
        Consent::Paste(reader) => {
            drop(listener);
            writeln!(
                notice,
                "zerotrust-drive: open this address in any browser and approve access:\n{url}\n\
                 The browser then fails to load {redirect_uri}; that is expected. Copy that \
                 page's full address from the address bar."
            )?;
            let pasted = reader
                .read_secret("zerotrust-drive: paste the full address: ")
                .map_err(|error| RemoteError::Local(format!("cannot read the address: {error}")))?;
            code_from_redirect(&pasted, &attempt.state)?.ok_or_else(|| {
                RemoteError::Auth(
                    "the pasted text is not the redirected address; it carries no authorization code"
                        .to_string(),
                )
            })?
        }
    };
    let token = token_request(
        agent,
        &endpoints.token,
        &[
            ("code", &code),
            ("client_id", &client.id),
            ("client_secret", &client.secret),
            ("redirect_uri", &redirect_uri),
            ("grant_type", "authorization_code"),
            ("code_verifier", &attempt.verifier),
        ],
        "the authorization code exchange",
    )?;
    authorization_from(token)
}

/// Opens `url` in the default browser without waiting for it. Never uses
/// Apple Events.
pub(crate) fn open_in_browser(url: &str) -> std::io::Result<()> {
    let program = if cfg!(target_os = "macos") {
        "open"
    } else {
        "xdg-open"
    };
    let mut child = std::process::Command::new(program)
        .arg(url)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;
    std::thread::spawn(move || {
        let _ = child.wait();
    });
    Ok(())
}

/// Mints access tokens from a vaulted refresh token.
pub(crate) struct RefreshTokenSource {
    client: OAuthClient,
    refresh_token: String,
    token_url: String,
}

impl RefreshTokenSource {
    pub(crate) fn new(client: OAuthClient, refresh_token: String, endpoints: &Endpoints) -> Self {
        Self {
            client,
            refresh_token,
            token_url: endpoints.token.clone(),
        }
    }
}

impl TokenSource for RefreshTokenSource {
    fn fetch(&self, agent: &ureq::Agent) -> Result<(String, Duration), RemoteError> {
        let token = token_request(
            agent,
            &self.token_url,
            &[
                ("client_id", &self.client.id),
                ("client_secret", &self.client.secret),
                ("refresh_token", &self.refresh_token),
                ("grant_type", "refresh_token"),
            ],
            "the access token refresh",
        )?;
        Ok((
            token.access_token,
            Duration::from_secs(token.expires_in.min(86_400)),
        ))
    }
}

#[cfg(test)]
pub(crate) fn test_client() -> OAuthClient {
    OAuthClient {
        id: "test-client.apps.googleusercontent.com".to_string(),
        secret: "test-client-secret".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::remote::TestDir;
    use crate::remote::fake::{self, FakeDrive, Fault, Op};
    use crate::remote::gdrive::{GoogleDrive, http_agent};
    use std::collections::BTreeMap;
    use std::os::unix::fs::PermissionsExt;
    use std::sync::{Arc, Mutex};
    use std::thread::JoinHandle;

    const DESKTOP: &[u8] = br#"{"installed":{"client_id":"123-abc.apps.googleusercontent.com","project_id":"p","auth_uri":"https://accounts.google.com/o/oauth2/auth","token_uri":"https://oauth2.googleapis.com/token","client_secret":"GOCSPX-not-a-real-secret","redirect_uris":["http://localhost"]}}"#;

    fn endpoints(fake: &FakeDrive) -> Endpoints {
        Endpoints {
            auth: format!("{}/auth", fake.base_url()),
            token: format!("{}/token", fake.base_url()),
        }
    }

    fn query(url: &str) -> BTreeMap<String, String> {
        form_pairs(url.split_once('?').unwrap().1).unwrap()
    }

    /// A raw browser GET; returns the HTTP status.
    fn visit(address: &str) -> u16 {
        let rest = address.strip_prefix("http://").unwrap();
        let (host, target) = rest.split_at(rest.find('/').unwrap_or(rest.len()));
        let target = if target.is_empty() { "/" } else { target };
        let mut stream = TcpStream::connect(host).unwrap();
        write!(
            stream,
            "GET {target} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n"
        )
        .unwrap();
        let mut response = String::new();
        stream.read_to_string(&mut response).unwrap();
        response.split(' ').nth(1).unwrap().parse().unwrap()
    }

    /// A scripted browser: records the consent URL and replays redirects.
    #[derive(Default)]
    struct Browser {
        url: Mutex<Option<String>>,
        visits: Arc<Mutex<Vec<u16>>>,
        thread: Mutex<Option<JoinHandle<()>>>,
    }

    impl Browser {
        fn redirect_with(
            &self,
            make: impl Fn(&BTreeMap<String, String>) -> Vec<String> + Send + Sync + 'static,
        ) -> impl Fn(&str) -> std::io::Result<()> + '_ {
            let make = Arc::new(make);
            move |url: &str| {
                *self.url.lock().unwrap() = Some(url.to_string());
                let params = query(url);
                let make = make.clone();
                let visits = self.visits.clone();
                *self.thread.lock().unwrap() = Some(std::thread::spawn(move || {
                    for address in make(&params) {
                        let status = visit(&address);
                        visits.lock().unwrap().push(status);
                    }
                }));
                Ok(())
            }
        }

        fn finish(&self) -> Vec<u16> {
            if let Some(thread) = self.thread.lock().unwrap().take() {
                thread.join().unwrap();
            }
            self.visits.lock().unwrap().clone()
        }
    }

    #[test]
    fn desktop_client_files_parse_and_other_kinds_are_refused() {
        let client = OAuthClient::parse(DESKTOP).unwrap();
        assert_eq!(client.id, "123-abc.apps.googleusercontent.com");
        assert!(!format!("{client:?}").contains("GOCSPX"));
        let web = br#"{"web":{"client_id":"x.apps.googleusercontent.com","client_secret":"s"}}"#;
        assert!(
            matches!(OAuthClient::parse(web), Err(RemoteError::Local(message)) if message.contains("Desktop app"))
        );
        let foreign = br#"{"installed":{"client_id":"x.example.com","client_secret":"s"}}"#;
        assert!(OAuthClient::parse(foreign).is_err());
        let broken =
            OAuthClient::parse(br#"{"installed":{"client_id":7,"client_secret":"GOCSPX-leak"}}"#)
                .unwrap_err();
        assert!(!broken.to_string().contains("GOCSPX"), "{broken}");
    }

    #[test]
    fn client_files_accessible_to_others_are_refused() {
        let dir = TestDir::new("oauth-client");
        let path = dir.path().join("client.json");
        std::fs::write(&path, DESKTOP).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        let refused = OAuthClient::load(&path).unwrap_err().to_string();
        assert!(refused.contains("chmod 600"), "{refused}");
        assert!(!refused.contains("GOCSPX"));
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(
            OAuthClient::load(&path).unwrap().id,
            "123-abc.apps.googleusercontent.com"
        );
    }

    #[test]
    fn pkce_matches_the_rfc_7636_vector_and_attempts_are_unique() {
        assert_eq!(base64url(&[3, 236, 255, 224, 193]), "A-z_4ME");
        assert_eq!(base64url(b""), "");
        assert_eq!(base64url(b"f"), "Zg");
        assert_eq!(base64url(b"fo"), "Zm8");
        assert_eq!(base64url(b"foo"), "Zm9v");
        assert_eq!(
            s256_challenge("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"),
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
        );
        let first = Attempt::new();
        let second = Attempt::new();
        assert_eq!(first.verifier.len(), 64);
        assert!(
            first
                .verifier
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        );
        assert_ne!(first.verifier, second.verifier);
        assert_ne!(first.state, second.state);
    }

    #[test]
    fn redirects_are_matched_to_their_attempt() {
        assert_eq!(code_from_redirect("/favicon.ico", "s1").unwrap(), None);
        assert_eq!(code_from_redirect("/?foo=bar", "s1").unwrap(), None);
        assert_eq!(
            code_from_redirect(
                "http://127.0.0.1:9/?state=s1&code=4%2F0Ab&scope=x#frag",
                "s1"
            )
            .unwrap()
            .as_deref(),
            Some("4/0Ab")
        );
        assert!(matches!(
            code_from_redirect("/?state=s2&code=c", "s1"),
            Err(RemoteError::Auth(_))
        ));
        assert!(matches!(
            code_from_redirect("/?code=c", "s1"),
            Err(RemoteError::Auth(_))
        ));
        assert!(matches!(
            code_from_redirect("/?state=s1&state=s1&code=c", "s1"),
            Err(RemoteError::Auth(_))
        ));
        let denied = code_from_redirect("/?state=s1&error=access_denied", "s1").unwrap_err();
        assert!(denied.to_string().contains("access_denied"), "{denied}");
        assert!(code_from_redirect("/?state=s1&code=", "s1").is_err());
    }

    #[test]
    fn loopback_consent_exchanges_the_code_with_its_verifier() {
        let fake = FakeDrive::start();
        let browser = Browser::default();
        let open = browser.redirect_with(|params| {
            let redirect = &params["redirect_uri"];
            vec![
                format!("{redirect}/favicon.ico"),
                format!(
                    "{redirect}/?state={}&code={}&scope={}",
                    params["state"],
                    form_encode(fake::AUTH_CODE),
                    form_encode(DRIVE_SCOPE)
                ),
            ]
        });
        let mut notice = Vec::new();
        let authorization = authorize(
            &http_agent(),
            &test_client(),
            &endpoints(&fake),
            Some("tester@example.com"),
            Consent::Loopback {
                open: &open,
                timeout: Duration::from_secs(20),
            },
            &mut notice,
        )
        .unwrap();
        assert_eq!(authorization.refresh_token, fake::REFRESH_TOKEN);
        assert!(!format!("{authorization:?}").contains(fake::REFRESH_TOKEN));
        assert_eq!(browser.finish(), vec![404, 200]);

        let url = browser.url.lock().unwrap().clone().unwrap();
        assert!(String::from_utf8(notice).unwrap().contains(&url));
        let params = query(&url);
        assert_eq!(params["client_id"], test_client().id);
        assert_eq!(params["scope"], DRIVE_SCOPE);
        assert_eq!(params["code_challenge_method"], "S256");
        assert_eq!(params["access_type"], "offline");
        assert_eq!(params["prompt"], "consent");
        assert_eq!(params["login_hint"], "tester@example.com");
        assert!(params["redirect_uri"].starts_with("http://127.0.0.1:"));

        let forms = fake.token_forms();
        let exchange = forms.last().unwrap();
        assert_eq!(exchange["grant_type"], "authorization_code");
        assert_eq!(exchange["code"], fake::AUTH_CODE);
        assert_eq!(exchange["redirect_uri"], params["redirect_uri"]);
        assert_eq!(exchange["client_secret"], "test-client-secret");
        assert_eq!(
            s256_challenge(&exchange["code_verifier"]),
            params["code_challenge"]
        );
    }

    #[test]
    fn a_foreign_state_or_a_refusal_fails_closed() {
        let fake = FakeDrive::start();
        for (query_tail, expected) in [
            ("state=forged&code=stolen", "state value"),
            ("STATE&error=access_denied", "access_denied"),
        ] {
            let browser = Browser::default();
            let tail = query_tail.to_string();
            let open = browser.redirect_with(move |params| {
                let tail = tail.replace("STATE", &format!("state={}", params["state"]));
                vec![format!("{}/?{tail}", params["redirect_uri"])]
            });
            let error = authorize(
                &http_agent(),
                &test_client(),
                &endpoints(&fake),
                None,
                Consent::Loopback {
                    open: &open,
                    timeout: Duration::from_secs(20),
                },
                &mut Vec::new(),
            )
            .unwrap_err();
            assert!(
                matches!(&error, RemoteError::Auth(message) if message.contains(expected)),
                "{error}"
            );
            assert_eq!(browser.finish(), vec![400]);
        }
        assert_eq!(
            fake.count(Op::Token),
            0,
            "nothing reaches the token endpoint"
        );
    }

    #[test]
    fn loopback_consent_times_out() {
        let fake = FakeDrive::start();
        let started = Instant::now();
        let error = authorize(
            &http_agent(),
            &test_client(),
            &endpoints(&fake),
            None,
            Consent::Loopback {
                open: &|_| Err(std::io::Error::other("no display")),
                timeout: Duration::from_millis(200),
            },
            &mut Vec::new(),
        )
        .unwrap_err();
        assert!(
            matches!(error, RemoteError::Auth(message) if message.contains("no browser consent"))
        );
        assert!(started.elapsed() < Duration::from_secs(10));
    }

    /// Reads the consent URL the flow printed and pastes back its redirect.
    struct Paster {
        notice: Arc<Mutex<Vec<u8>>>,
        reply: fn(&BTreeMap<String, String>) -> String,
    }

    impl SecretReader for Paster {
        fn read_secret(&mut self, _prompt: &str) -> std::io::Result<String> {
            let notice = String::from_utf8(self.notice.lock().unwrap().clone()).unwrap();
            let url = notice.lines().find(|line| line.contains("/auth?")).unwrap();
            Ok((self.reply)(&query(url)))
        }
    }

    struct Shared(Arc<Mutex<Vec<u8>>>);

    impl Write for Shared {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(bytes);
            Ok(bytes.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn paste_back_consent_needs_the_full_redirected_address() {
        let fake = FakeDrive::start();
        let run = |reply: fn(&BTreeMap<String, String>) -> String| {
            let buffer = Arc::new(Mutex::new(Vec::new()));
            let mut paster = Paster {
                notice: buffer.clone(),
                reply,
            };
            authorize(
                &http_agent(),
                &test_client(),
                &endpoints(&fake),
                None,
                Consent::Paste(&mut paster),
                &mut Shared(buffer),
            )
        };
        let authorization = run(|params| {
            format!(
                "  {}/?state={}&code={}&scope={}\n",
                params["redirect_uri"],
                params["state"],
                fake::AUTH_CODE,
                form_encode(DRIVE_SCOPE)
            )
        })
        .unwrap();
        assert_eq!(authorization.refresh_token, fake::REFRESH_TOKEN);
        assert!(matches!(
            run(|_| fake::AUTH_CODE.to_string()),
            Err(RemoteError::Auth(_))
        ));
        assert!(matches!(
            run(|params| format!("{}/?state=other&code=c", params["redirect_uri"])),
            Err(RemoteError::Auth(_))
        ));
    }

    #[test]
    fn exchanges_without_drive_scope_or_refresh_token_are_refused() {
        let token = |scope: Option<&str>, refresh: Option<&str>| TokenResponse {
            access_token: "a".to_string(),
            expires_in: 3599,
            refresh_token: refresh.map(str::to_string),
            scope: scope.map(str::to_string),
            token_type: Some("Bearer".to_string()),
        };
        let both = format!("openid {DRIVE_SCOPE}");
        assert!(authorization_from(token(Some(&both), Some("r"))).is_ok());
        assert!(authorization_from(token(None, Some("r"))).is_ok());
        let narrow = authorization_from(token(
            Some("https://www.googleapis.com/auth/drive.file"),
            Some("r"),
        ))
        .unwrap_err();
        assert!(narrow.to_string().contains("full Google Drive access"));
        assert!(authorization_from(token(Some(DRIVE_SCOPE), None)).is_err());
    }

    #[test]
    fn refresh_tokens_mint_access_tokens_for_the_drive_client() {
        let fake = FakeDrive::start();
        let source = RefreshTokenSource::new(
            test_client(),
            fake::REFRESH_TOKEN.to_string(),
            &endpoints(&fake),
        );
        fake.fault(Op::Token, Fault::Status(503, "backendError"));
        let drive =
            GoogleDrive::with_endpoint(fake.base_url(), Box::new(source), FakeDrive::fast_policy());
        assert_eq!(drive.about().unwrap().email, "tester@example.com");
        assert_eq!(
            fake.count(Op::Token),
            2,
            "a transient token failure is retried"
        );
        let refresh = fake.token_forms().pop().unwrap();
        assert_eq!(refresh["grant_type"], "refresh_token");
        assert_eq!(refresh["client_id"], test_client().id);
    }

    #[test]
    fn a_revoked_refresh_token_fails_fast_as_auth() {
        let fake = FakeDrive::start();
        let source =
            RefreshTokenSource::new(test_client(), "revoked".to_string(), &endpoints(&fake));
        let drive =
            GoogleDrive::with_endpoint(fake.base_url(), Box::new(source), FakeDrive::fast_policy());
        let error = drive.about().unwrap_err();
        assert!(
            matches!(&error, RemoteError::Auth(message) if message.contains("invalid_grant")),
            "{error}"
        );
        assert!(!error.to_string().contains("revoked"));
        assert_eq!(
            fake.count(Op::Token),
            1,
            "a rejected grant is never retried"
        );
        assert_eq!(fake.count(Op::About), 0);
    }
}
