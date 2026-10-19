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

use super::config::{ClientKind, Issuer, SCOPE_DRIVE, SCOPE_DRIVE_FILE};
use super::gdrive::TokenSource;
use super::{RemoteError, form_encode, form_pairs, hex, read_private_file};
use crate::crypto::fill_random;
use crate::prompt::SecretReader;

pub(crate) const AUTH_URL: &str = "https://accounts.google.com/o/oauth2/v2/auth";
pub(crate) const TOKEN_URL: &str = "https://oauth2.googleapis.com/token";
pub(crate) const DEVICE_CODE_URL: &str = "https://oauth2.googleapis.com/device/code";
pub(crate) const REVOKE_URL: &str = "https://oauth2.googleapis.com/revoke";
const DEVICE_GRANT: &str = "urn:ietf:params:oauth:grant-type:device_code";
/// How long the loopback flow waits for the browser consent.
pub(crate) const CONSENT_TIMEOUT: Duration = Duration::from_secs(600);
/// The longest a device code is waited for, whatever Google offers.
const MAX_DEVICE_WAIT: Duration = Duration::from_secs(1800);
/// Consecutive transport failures tolerated while polling a device code.
const MAX_DEVICE_POLL_FAILURES: u32 = 5;

const MAX_CLIENT_FILE: u64 = 64 << 10;
const MAX_TOKEN_RESPONSE: u64 = 64 << 10;
const MAX_REDIRECT_REQUEST: usize = 16 << 10;
const MAX_LOOPBACK_CONNECTIONS: usize = 64;
const MAX_SECRET_LEN: usize = 4096;

/// The authorization, token and device-code endpoints. Tests point them at
/// the fake.
#[derive(Clone, Debug)]
pub(crate) struct Endpoints {
    pub(crate) auth: String,
    pub(crate) token: String,
    pub(crate) device: String,
}

impl Endpoints {
    pub(crate) fn google() -> Self {
        Self {
            auth: AUTH_URL.to_string(),
            token: TOKEN_URL.to_string(),
            device: DEVICE_CODE_URL.to_string(),
        }
    }
}

/// A Google installed-app OAuth client: a "Desktop app" client downloaded
/// from the Cloud console, or one of zdrive's bundled clients.
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

/// zdrive's own clients, embedded by release builds from
/// `ZDRIVE_GOOGLE_{DESKTOP,DEVICE}_CLIENT_{ID,SECRET}` at compile time. They
/// are not in the source tree. An installed application cannot keep a
/// client secret confidential (Google's own definition), so a secret
/// extracted from the binary grants nothing beyond what the client already
/// allows: a user's own consent to the files zdrive creates.
const BUNDLED_DESKTOP: (Option<&str>, Option<&str>) = (
    option_env!("ZDRIVE_GOOGLE_DESKTOP_CLIENT_ID"),
    option_env!("ZDRIVE_GOOGLE_DESKTOP_CLIENT_SECRET"),
);
const BUNDLED_DEVICE: (Option<&str>, Option<&str>) = (
    option_env!("ZDRIVE_GOOGLE_DEVICE_CLIENT_ID"),
    option_env!("ZDRIVE_GOOGLE_DEVICE_CLIENT_SECRET"),
);

/// Whether this build carries the bundled (desktop, device) clients.
pub(crate) fn bundled_available() -> (bool, bool) {
    (
        bundled_client(ClientKind::BundledDesktop).is_some(),
        bundled_client(ClientKind::BundledDevice).is_some(),
    )
}

pub(crate) fn bundled_client(kind: ClientKind) -> Option<OAuthClient> {
    let (id, secret) = match kind {
        ClientKind::BundledDesktop => BUNDLED_DESKTOP,
        ClientKind::BundledDevice => BUNDLED_DEVICE,
        ClientKind::Byo => return None,
    };
    OAuthClient::from_parts(id?, secret?).ok()
}

/// The client that issued `issuer`'s tokens: a refresh must use it.
pub(crate) fn client_for(issuer: &Issuer) -> Result<OAuthClient, RemoteError> {
    match (issuer.client, &issuer.client_file) {
        (ClientKind::Byo, Some(file)) => OAuthClient::load(file),
        (ClientKind::Byo, None) => Err(RemoteError::Local(
            "the remote names no OAuth client file".to_string(),
        )),
        (kind, _) => bundled_client(kind).ok_or_else(|| missing_bundled_client(kind)),
    }
}

pub(crate) fn missing_bundled_client(kind: ClientKind) -> RemoteError {
    let which = match kind {
        ClientKind::BundledDevice => "device-code",
        _ => "desktop",
    };
    RemoteError::Local(format!(
        "this zdrive build has no bundled Google {which} client (it was built from source without ZDRIVE_GOOGLE_* values); install a release build, or authorize with your own Desktop OAuth client: `zdrive remote auth --client-file FILE` (see the README, \"Bring your own OAuth client\")"
    ))
}

impl OAuthClient {
    /// A client from its identifier and secret, validated like a download.
    pub(crate) fn from_parts(id: &str, secret: &str) -> Result<Self, RemoteError> {
        if !id.ends_with(".apps.googleusercontent.com") || id.len() > 256 || !is_token_text(id) {
            return Err(RemoteError::Local(
                "the client_id is not a Google OAuth client identifier".to_string(),
            ));
        }
        if secret.len() > 256 || !is_token_text(secret) {
            return Err(RemoteError::Local(
                "the client_secret is malformed".to_string(),
            ));
        }
        Ok(Self {
            id: id.to_string(),
            secret: secret.to_string(),
        })
    }

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
        Self::from_parts(&installed.client_id, &installed.client_secret)
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
    scope: &str,
    login_hint: Option<&str>,
) -> String {
    let challenge = s256_challenge(&attempt.verifier);
    let mut params = vec![
        ("client_id", client.id.as_str()),
        ("redirect_uri", redirect_uri),
        ("response_type", "code"),
        ("scope", scope),
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

/// Posts a form and reads a bounded response: (status, body).
fn post_form(
    agent: &ureq::Agent,
    url: &str,
    form: &[(&str, &str)],
    what: &str,
) -> Result<(u16, Vec<u8>), RemoteError> {
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
    Ok((status, bytes))
}

fn parse_token(bytes: &[u8], what: &str) -> Result<TokenResponse, RemoteError> {
    let token: TokenResponse = serde_json::from_slice(bytes).map_err(|_| {
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
    Ok(token)
}

/// The sanitized OAuth `error` code of a failed response, or "".
fn error_code(bytes: &[u8]) -> String {
    serde_json::from_slice::<TokenError>(bytes)
        .map(|body| sanitize(&body.error))
        .unwrap_or_default()
}

fn rejection(what: &str, status: u16, error: &str) -> RemoteError {
    let rejected = matches!(
        error,
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
    match status {
        400 | 401 | 403 if rejected => RemoteError::Auth(format!(
            "{what} was rejected ({error}); run `zdrive remote auth` again"
        )),
        408 | 429 | 500..=599 => RemoteError::Network(format!("{what}: HTTP {status}")),
        _ => RemoteError::Protocol(format!("{what}: HTTP {status} {error}")),
    }
}

fn token_request(
    agent: &ureq::Agent,
    url: &str,
    form: &[(&str, &str)],
    what: &str,
) -> Result<TokenResponse, RemoteError> {
    let (status, bytes) = post_form(agent, url, form, what)?;
    if status == 200 {
        return parse_token(&bytes, what);
    }
    Err(rejection(what, status, &error_code(&bytes)))
}

/// What a revocation request found.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Revocation {
    Revoked,
    /// Google no longer knew the grant: revoked or expired before.
    AlreadyInvalid,
}

/// Revokes a refresh token and with it the whole grant, so every access
/// token minted from it stops working as well. Google ties a grant to the
/// account and the OAuth project, not to one computer.
pub(crate) fn revoke(
    agent: &ureq::Agent,
    url: &str,
    refresh_token: &str,
) -> Result<Revocation, RemoteError> {
    const WHAT: &str = "revoking the Google sign-in";
    let (status, bytes) = post_form(agent, url, &[("token", refresh_token)], WHAT)?;
    let error = error_code(&bytes);
    match status {
        200 => Ok(Revocation::Revoked),
        400 if error == "invalid_token" => Ok(Revocation::AlreadyInvalid),
        408 | 429 | 500..=599 => Err(RemoteError::Network(format!("{WHAT}: HTTP {status}"))),
        _ => Err(RemoteError::Protocol(format!(
            "{WHAT}: HTTP {status} {error}"
        ))),
    }
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

/// Requires the requested scope (full Drive access covers `drive.file`)
/// and a refresh token.
fn authorization_from(token: TokenResponse, scope: &str) -> Result<Authorization, RemoteError> {
    if let Some(granted) = &token.scope {
        let covered = granted.split(' ').any(|granted| {
            granted == scope || (granted == SCOPE_DRIVE && scope == SCOPE_DRIVE_FILE)
        });
        if !covered {
            return Err(RemoteError::Auth(if scope == SCOPE_DRIVE {
                "the consent did not grant full Google Drive access; authorize again and allow access to all Drive files"
                    .to_string()
            } else {
                "the consent did not grant access to the files zerotrust-drive creates; authorize again and allow it"
                    .to_string()
            }));
        }
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

/// Runs one installed-app authorization for `scope` and exchanges its code.
pub(crate) fn authorize(
    agent: &ureq::Agent,
    client: &OAuthClient,
    endpoints: &Endpoints,
    scope: &str,
    login_hint: Option<&str>,
    consent: Consent<'_>,
    notice: &mut dyn Write,
) -> Result<Authorization, RemoteError> {
    let attempt = Attempt::new();
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
    let redirect_uri = format!("http://127.0.0.1:{}", listener.local_addr()?.port());
    let url = authorization_url(
        endpoints,
        client,
        &redirect_uri,
        &attempt,
        scope,
        login_hint,
    );
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
    authorization_from(token, scope)
}

#[derive(Deserialize)]
struct DeviceCodeResponse {
    device_code: String,
    user_code: String,
    /// Google names it `verification_url`; RFC 8628 `verification_uri`.
    #[serde(alias = "verification_uri")]
    verification_url: String,
    expires_in: u64,
    #[serde(default)]
    interval: Option<u64>,
}

/// The OAuth device flow (RFC 8628) for hosts without a browser: zdrive
/// shows a short code, the user enters it at Google's device page on any
/// phone or computer, and zdrive polls until it is approved. Google allows
/// only the `drive.file` and `drive.appdata` Drive scopes here.
pub(crate) fn authorize_device(
    agent: &ureq::Agent,
    client: &OAuthClient,
    endpoints: &Endpoints,
    scope: &str,
    notice: &mut dyn Write,
    sleep: &dyn Fn(Duration),
) -> Result<Authorization, RemoteError> {
    let what = "the device code request";
    let (status, bytes) = post_form(
        agent,
        &endpoints.device,
        &[("client_id", &client.id), ("scope", scope)],
        what,
    )?;
    if status != 200 {
        return Err(rejection(what, status, &error_code(&bytes)));
    }
    let code: DeviceCodeResponse = serde_json::from_slice(&bytes).map_err(|_| {
        RemoteError::Protocol(format!("{what}: the response is not the expected JSON"))
    })?;
    let printable = |text: &str| is_token_text(text) && text.len() <= 256;
    if !printable(&code.device_code)
        || !printable(&code.user_code)
        || !printable(&code.verification_url)
        || !code.verification_url.starts_with("https://")
    {
        return Err(RemoteError::Protocol(format!(
            "{what}: the response carries no usable device code"
        )));
    }
    let wait = Duration::from_secs(code.expires_in).min(MAX_DEVICE_WAIT);
    writeln!(
        notice,
        "zerotrust-drive: on any phone or computer, open {} and enter the code {}\n\
         zerotrust-drive: the code expires in {} minutes; waiting for the approval...",
        code.verification_url,
        code.user_code,
        wait.as_secs().div_ceil(60)
    )?;
    let deadline = Instant::now() + wait;
    let mut interval = Duration::from_secs(code.interval.unwrap_or(5).clamp(1, 60));
    let mut failures = 0u32;
    let what = "the device code approval";
    loop {
        if Instant::now() >= deadline {
            return Err(device_expired());
        }
        sleep(interval);
        let (status, bytes) = match post_form(
            agent,
            &endpoints.token,
            &[
                ("client_id", &client.id),
                ("client_secret", &client.secret),
                ("device_code", &code.device_code),
                ("grant_type", DEVICE_GRANT),
            ],
            what,
        ) {
            Ok(reply) => reply,
            Err(RemoteError::Network(detail)) => {
                failures += 1;
                if failures >= MAX_DEVICE_POLL_FAILURES {
                    return Err(RemoteError::Network(detail));
                }
                continue;
            }
            Err(error) => return Err(error),
        };
        if status == 200 {
            return authorization_from(parse_token(&bytes, what)?, scope);
        }
        match error_code(&bytes).as_str() {
            "authorization_pending" => failures = 0,
            // RFC 8628 section 3.5: every later poll waits 5 s longer.
            "slow_down" => {
                failures = 0;
                interval += Duration::from_secs(5);
            }
            "access_denied" => {
                return Err(RemoteError::Auth(
                    "the sign-in was declined on Google's device page".to_string(),
                ));
            }
            "expired_token" => return Err(device_expired()),
            _ if matches!(status, 408 | 429 | 500..=599) => {
                failures += 1;
                if failures >= MAX_DEVICE_POLL_FAILURES {
                    return Err(rejection(what, status, ""));
                }
            }
            error => return Err(rejection(what, status, error)),
        }
    }
}

fn device_expired() -> RemoteError {
    RemoteError::Auth(
        "the device code expired before it was approved; run the sign-in again".to_string(),
    )
}

/// Whether this host likely has no usable local browser: Linux without a
/// graphical session, or any SSH login.
pub(crate) fn prefers_device_flow(var: impl Fn(&str) -> Option<std::ffi::OsString>) -> bool {
    let set = |name: &str| var(name).is_some_and(|value| !value.is_empty());
    if set("SSH_CONNECTION") || set("SSH_TTY") {
        return true;
    }
    cfg!(target_os = "linux") && !set("DISPLAY") && !set("WAYLAND_DISPLAY")
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
            device: format!("{}/device/code", fake.base_url()),
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
                    form_encode(SCOPE_DRIVE)
                ),
            ]
        });
        let mut notice = Vec::new();
        let authorization = authorize(
            &http_agent(),
            &test_client(),
            &endpoints(&fake),
            SCOPE_DRIVE,
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
        assert_eq!(params["scope"], SCOPE_DRIVE);
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
                SCOPE_DRIVE,
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
            SCOPE_DRIVE,
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
                SCOPE_DRIVE,
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
                form_encode(SCOPE_DRIVE)
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
        let both = format!("openid {SCOPE_DRIVE}");
        assert!(authorization_from(token(Some(&both), Some("r")), SCOPE_DRIVE).is_ok());
        assert!(authorization_from(token(None, Some("r")), SCOPE_DRIVE).is_ok());
        let narrow =
            authorization_from(token(Some(SCOPE_DRIVE_FILE), Some("r")), SCOPE_DRIVE).unwrap_err();
        assert!(narrow.to_string().contains("full Google Drive access"));
        assert!(authorization_from(token(Some(SCOPE_DRIVE), None), SCOPE_DRIVE).is_err());
        // drive.file is satisfied by itself or by full access, never by
        // an unrelated scope.
        assert!(
            authorization_from(token(Some(SCOPE_DRIVE_FILE), Some("r")), SCOPE_DRIVE_FILE).is_ok()
        );
        assert!(authorization_from(token(Some(SCOPE_DRIVE), Some("r")), SCOPE_DRIVE_FILE).is_ok());
        let unrelated = authorization_from(
            token(
                Some("https://www.googleapis.com/auth/drive.appdata"),
                Some("r"),
            ),
            SCOPE_DRIVE_FILE,
        )
        .unwrap_err();
        assert!(
            unrelated
                .to_string()
                .contains("files zerotrust-drive creates")
        );
    }

    fn device_run(
        fake: &FakeDrive,
        client: &OAuthClient,
        scope: &str,
    ) -> (Result<Authorization, RemoteError>, String, Vec<Duration>) {
        let mut notice = Vec::new();
        let sleeps = Mutex::new(Vec::new());
        let outcome = authorize_device(
            &http_agent(),
            client,
            &endpoints(fake),
            scope,
            &mut notice,
            &|duration| sleeps.lock().unwrap().push(duration),
        );
        (
            outcome,
            String::from_utf8(notice).unwrap(),
            sleeps.into_inner().unwrap(),
        )
    }

    #[test]
    fn device_flow_polls_until_approved_and_slows_down_on_request() {
        let fake = FakeDrive::start();
        fake.script_device_polls(&[
            "authorization_pending",
            "slow_down",
            "authorization_pending",
        ]);
        let (outcome, notice, sleeps) = device_run(&fake, &test_client(), SCOPE_DRIVE_FILE);
        let authorization = outcome.unwrap();
        assert_eq!(authorization.refresh_token, fake::REFRESH_TOKEN);
        assert!(notice.contains(fake::DEVICE_USER_CODE), "{notice}");
        assert!(notice.contains("https://www.google.com/device"), "{notice}");
        assert!(
            !notice.contains(fake::DEVICE_CODE),
            "the device code stays private"
        );
        let seconds: Vec<u64> = sleeps.iter().map(Duration::as_secs).collect();
        assert_eq!(seconds, vec![5, 5, 10, 10]);
        let forms = fake.token_forms();
        assert_eq!(forms.len(), 4);
        for form in &forms {
            assert_eq!(form["grant_type"], DEVICE_GRANT);
            assert_eq!(form["device_code"], fake::DEVICE_CODE);
            assert_eq!(form["client_secret"], "test-client-secret");
        }
        let requests = fake.device_forms();
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0]["scope"], SCOPE_DRIVE_FILE);
        assert_eq!(requests[0]["client_id"], test_client().id);
        assert!(!requests[0].contains_key("client_secret"));
    }

    #[test]
    fn device_flow_refusals_and_expiry_fail_closed() {
        for (script, expected) in [
            ("access_denied", "declined"),
            ("expired_token", "expired"),
            ("invalid_client", "invalid_client"),
        ] {
            let fake = FakeDrive::start();
            fake.script_device_polls(&["authorization_pending", script]);
            let (outcome, _, sleeps) = device_run(&fake, &test_client(), SCOPE_DRIVE_FILE);
            let error = outcome.err().unwrap();
            assert!(
                matches!(&error, RemoteError::Auth(message) if message.contains(expected)),
                "{script}: {error}"
            );
            assert_eq!(sleeps.len(), 2, "{script}");
        }
        // Google refuses full Drive access to device clients up front.
        let fake = FakeDrive::start();
        let (outcome, _, sleeps) = device_run(&fake, &test_client(), SCOPE_DRIVE);
        let error = outcome.err().unwrap();
        assert!(error.to_string().contains("invalid_scope"), "{error}");
        assert!(sleeps.is_empty());
        assert_eq!(fake.count(Op::Token), 0);
        // A code that expires locally is never polled past its lifetime.
        let fake = FakeDrive::start();
        fake.set_device_expiry(0);
        let (outcome, _, sleeps) = device_run(&fake, &test_client(), SCOPE_DRIVE_FILE);
        assert!(outcome.err().unwrap().to_string().contains("expired"));
        assert!(sleeps.is_empty());
    }

    #[test]
    fn transient_device_poll_failures_are_bounded() {
        let fake = FakeDrive::start();
        fake.script_device_polls(&["backendError"; 8]);
        let (outcome, _, sleeps) = device_run(&fake, &test_client(), SCOPE_DRIVE_FILE);
        assert!(matches!(outcome, Err(RemoteError::Network(_))));
        assert_eq!(sleeps.len(), MAX_DEVICE_POLL_FAILURES as usize);
        let fake = FakeDrive::start();
        fake.script_device_polls(&["backendError", "backendError", "authorization_pending"]);
        let (outcome, _, _) = device_run(&fake, &test_client(), SCOPE_DRIVE_FILE);
        assert!(outcome.is_ok());
    }

    #[test]
    fn bundled_clients_are_validated_and_byo_needs_its_file() {
        assert!(bundled_client(ClientKind::Byo).is_none());
        let (desktop, device) = bundled_available();
        assert_eq!(
            desktop,
            bundled_client(ClientKind::BundledDesktop).is_some()
        );
        assert_eq!(device, bundled_client(ClientKind::BundledDevice).is_some());
        let missing = missing_bundled_client(ClientKind::BundledDevice).to_string();
        assert!(missing.contains("--client-file"), "{missing}");
        assert!(missing.contains("device-code"), "{missing}");
        assert!(OAuthClient::from_parts("", "s").is_err());
        assert!(OAuthClient::from_parts("x.apps.googleusercontent.com", "").is_err());
        assert!(OAuthClient::from_parts("x.example.com", "s").is_err());
        assert!(OAuthClient::from_parts("x.apps.googleusercontent.com", "s").is_ok());
        let byo = Issuer {
            client: ClientKind::Byo,
            client_file: None,
            scope: SCOPE_DRIVE.to_string(),
        };
        assert!(client_for(&byo).is_err());
        let dir = TestDir::new("oauth-client-for");
        let path = dir.path().join("client.json");
        std::fs::write(&path, DESKTOP).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(
            client_for(&Issuer::byo(&path)).unwrap().id,
            "123-abc.apps.googleusercontent.com"
        );
    }

    #[test]
    fn hosts_without_a_browser_prefer_the_device_flow() {
        let env = |entries: &'static [(&'static str, &'static str)]| {
            move |name: &str| {
                entries
                    .iter()
                    .find(|(key, _)| *key == name)
                    .map(|(_, value)| std::ffi::OsString::from(value))
            }
        };
        assert!(prefers_device_flow(env(&[("SSH_CONNECTION", "1 2 3 4")])));
        assert!(prefers_device_flow(env(&[
            ("SSH_TTY", "/dev/pts/0"),
            ("DISPLAY", ":0")
        ])));
        assert!(!prefers_device_flow(env(&[("DISPLAY", ":0")])));
        assert!(!prefers_device_flow(env(&[(
            "WAYLAND_DISPLAY",
            "wayland-0"
        )])));
        assert_eq!(
            prefers_device_flow(env(&[])),
            cfg!(target_os = "linux"),
            "a desktop Mac opens its browser"
        );
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
    fn revoking_ends_the_grant_once_and_reports_a_repeat() {
        let fake = FakeDrive::start();
        let url = format!("{}/revoke", fake.base_url());
        assert_eq!(
            revoke(&http_agent(), &url, fake::REFRESH_TOKEN).unwrap(),
            Revocation::Revoked
        );
        assert!(fake.refresh_revoked());
        // The revoked grant mints no more access tokens.
        let source = RefreshTokenSource::new(
            test_client(),
            fake::REFRESH_TOKEN.to_string(),
            &endpoints(&fake),
        );
        let drive =
            GoogleDrive::with_endpoint(fake.base_url(), Box::new(source), FakeDrive::fast_policy());
        assert!(matches!(drive.about(), Err(RemoteError::Auth(_))));
        assert_eq!(
            revoke(&http_agent(), &url, fake::REFRESH_TOKEN).unwrap(),
            Revocation::AlreadyInvalid
        );
        assert_eq!(
            revoke(&http_agent(), &url, "never-issued").unwrap(),
            Revocation::AlreadyInvalid
        );
    }

    #[test]
    fn a_revocation_that_did_not_happen_is_an_error() {
        let fake = FakeDrive::start();
        let url = format!("{}/revoke", fake.base_url());
        fake.fault(Op::Revoke, Fault::Status(503, "backendError"));
        assert!(matches!(
            revoke(&http_agent(), &url, fake::REFRESH_TOKEN),
            Err(RemoteError::Network(_))
        ));
        fake.fault(Op::Revoke, Fault::Drop);
        assert!(matches!(
            revoke(&http_agent(), &url, fake::REFRESH_TOKEN),
            Err(RemoteError::Network(_))
        ));
        fake.fault(Op::Revoke, Fault::Status(401, "unauthorized_client"));
        assert!(matches!(
            revoke(&http_agent(), &url, fake::REFRESH_TOKEN),
            Err(RemoteError::Protocol(_))
        ));
        assert!(!fake.refresh_revoked());
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
