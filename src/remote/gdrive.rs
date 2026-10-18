// SPDX-FileCopyrightText: Copyright 2026 Alexander Orlov <info@lifub.com>

//! Minimal Google Drive v3 REST client for append-only replication.
//!
//! Every create uses a pre-generated file id, so a retry after an ambiguous
//! outcome either creates the file once or receives 409 and reconciles the
//! existing file by id, size and md5. Large files use resumable sessions
//! whose URIs are persisted by the caller, so an upload survives a crash.
//! Requests are paced below Drive's sustained per-user write rate and
//! retried with full-jitter exponential backoff on throttling and 5xx.

use std::collections::BTreeMap;
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::Path;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use ureq::Body;
use ureq::http::Response;

use super::format::valid_file_id;
use super::{RemoteError, hex, md5_file, unhex};
use crate::telemetry::{self, RequestClass};

pub(crate) const GOOGLE_API: &str = "https://www.googleapis.com";
pub(crate) const FOLDER_MIME: &str = "application/vnd.google-apps.folder";
/// Drive's alias for the root of My Drive.
pub(crate) const MY_DRIVE: &str = "root";
/// The app property that marks folders zerotrust-drive created.
pub(crate) const MARKER_KEY: &str = "zdrive";
/// [`MARKER_KEY`] value of an encrypted store folder.
pub(crate) const STORE_MARKER: &str = "store-v1";
/// [`MARKER_KEY`] value of a plain-mode sync folder.
pub(crate) const PLAIN_MARKER: &str = "plain-v1";
const FILE_FIELDS: &str =
    "id,name,size,md5Checksum,mimeType,parents,appProperties,trashed,modifiedTime,version";
const LIST_FIELDS: &str = "nextPageToken,files(id,name,size,md5Checksum,mimeType,parents,appProperties,modifiedTime,version)";
const CHANGE_FIELDS: &str = "nextPageToken,newStartPageToken,changes(changeType,fileId,removed,file(id,name,size,md5Checksum,mimeType,parents,appProperties,trashed,modifiedTime,version))";
/// Longest page token accepted from the changes feed.
const MAX_PAGE_TOKEN: usize = 1024;
/// Files up to this size are created in one multipart request.
pub(crate) const MULTIPART_LIMIT: u64 = 5 << 20;
/// Resumable chunk size; Drive requires a multiple of 256 KiB.
pub(crate) const UPLOAD_CHUNK: u64 = 16 << 20;
const MAX_JSON_RESPONSE: u64 = 32 << 20;
const MAX_ERROR_BODY: u64 = 64 << 10;
const MAX_SESSION_RESTARTS: u32 = 3;

/// Supplies OAuth bearer tokens.
pub(crate) trait TokenSource: Send + Sync {
    /// Obtains a fresh access token and its remaining lifetime.
    fn fetch(&self, agent: &ureq::Agent) -> Result<(String, Duration), RemoteError>;
}

/// Pacing and retry bounds. Tests shrink the delays; production uses
/// [`RetryPolicy::PRODUCTION`].
#[derive(Clone, Copy, Debug)]
pub(crate) struct RetryPolicy {
    pub(crate) base: Duration,
    pub(crate) cap: Duration,
    pub(crate) attempts: u32,
    pub(crate) min_interval: Duration,
    /// Requests that may start together before `min_interval` spacing
    /// applies, so concurrent listings cost one round trip. The sustained
    /// rate stays one per `min_interval`; writes are never bursted.
    pub(crate) burst: u32,
    pub(crate) write_interval: Duration,
}

impl RetryPolicy {
    pub(crate) const PRODUCTION: Self = Self {
        base: Duration::from_secs(1),
        cap: Duration::from_secs(64),
        attempts: 10,
        min_interval: Duration::from_millis(100),
        burst: 8,
        write_interval: Duration::from_millis(400),
    };

    /// This pacing with a smaller retry budget, for callers that have their
    /// own fallback: a mount goes offline, the replicator backs off.
    pub(crate) fn bounded(self, attempts: u32, cap: Duration) -> Self {
        Self {
            attempts: self.attempts.min(attempts),
            cap: self.cap.min(cap),
            ..self
        }
    }

    /// Full jitter: uniform in `[0, min(cap, base * 2^attempt)]`.
    fn delay(&self, attempt: u32) -> Duration {
        let ceiling = self
            .base
            .saturating_mul(1u32 << attempt.min(16))
            .min(self.cap);
        let mut random = [0u8; 8];
        crate::crypto::fill_random(&mut random);
        let fraction = (u64::from_le_bytes(random) >> 11) as f64 / (1u64 << 53) as f64;
        ceiling.mul_f64(fraction)
    }
}

struct Pacer {
    next_any: Mutex<Instant>,
    next_write: Mutex<Instant>,
}

impl Pacer {
    fn new() -> Self {
        let now = Instant::now();
        Self {
            next_any: Mutex::new(now),
            next_write: Mutex::new(now),
        }
    }

    /// Generic cell rate algorithm: `slot` holds the theoretical arrival
    /// time of the next request. Returns when a request arriving at `now`
    /// may start.
    fn admit(slot: &mut Instant, now: Instant, interval: Duration, burst: u32) -> Instant {
        let arrival = (*slot).max(now);
        *slot = arrival + interval;
        let tolerance = interval.saturating_mul(burst.saturating_sub(1));
        arrival
            .checked_sub(tolerance)
            .map_or(now, |start| start.max(now))
    }

    fn reserve(slot: &Mutex<Instant>, interval: Duration, burst: u32) {
        let start = {
            let mut slot = slot.lock().unwrap_or_else(|poison| poison.into_inner());
            Self::admit(&mut slot, Instant::now(), interval, burst)
        };
        let now = Instant::now();
        if start > now {
            std::thread::sleep(start - now);
        }
    }

    fn wait(&self, policy: &RetryPolicy, write: bool) {
        if write {
            Self::reserve(&self.next_write, policy.write_interval, 1);
        }
        Self::reserve(&self.next_any, policy.min_interval, policy.burst);
    }
}

/// Drive file metadata, limited to the fields replication reads.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub(crate) struct DriveFile {
    pub(crate) id: String,
    pub(crate) name: String,
    #[serde(default)]
    size: Option<String>,
    #[serde(default)]
    md5_checksum: Option<String>,
    #[serde(default)]
    pub(crate) mime_type: String,
    #[serde(default)]
    pub(crate) parents: Vec<String>,
    #[serde(default)]
    pub(crate) app_properties: BTreeMap<String, String>,
    /// Only `get` and the changes feed report this; listings exclude
    /// trashed files.
    #[serde(default)]
    pub(crate) trashed: bool,
    /// RFC 3339 time of the last content or metadata change.
    #[serde(default)]
    pub(crate) modified_time: Option<String>,
    /// Drive's monotonically increasing version of this file.
    #[serde(default)]
    pub(crate) version: Option<String>,
}

impl DriveFile {
    /// My Drive under its [`MY_DRIVE`] alias, for when its real id is
    /// hidden.
    fn my_drive() -> Self {
        Self {
            id: MY_DRIVE.to_string(),
            name: "My Drive".to_string(),
            size: None,
            md5_checksum: None,
            mime_type: FOLDER_MIME.to_string(),
            parents: Vec::new(),
            app_properties: BTreeMap::new(),
            trashed: false,
            modified_time: None,
            version: None,
        }
    }

    pub(crate) fn size(&self) -> Option<u64> {
        self.size.as_deref()?.parse().ok()
    }

    pub(crate) fn md5(&self) -> Option<[u8; 16]> {
        unhex::<16>(self.md5_checksum.as_deref()?)
    }

    pub(crate) fn is_folder(&self) -> bool {
        self.mime_type == FOLDER_MIME
    }
}

/// One entry of the Drive changes feed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Change {
    pub(crate) file_id: String,
    /// The file was deleted forever or this client lost access to it.
    pub(crate) removed: bool,
    /// Current metadata, absent for a removal. A trashed file is reported
    /// with `trashed` set rather than as removed.
    pub(crate) file: Option<DriveFile>,
}

/// One page of the changes feed. Exactly one of the tokens is present:
/// `next_page_token` continues this listing, `new_start_page_token` is
/// where the next poll starts.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct ChangesPage {
    pub(crate) changes: Vec<Change>,
    pub(crate) next_page_token: Option<String>,
    pub(crate) new_start_page_token: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RawChangesPage {
    #[serde(default)]
    changes: Vec<RawChange>,
    #[serde(default)]
    next_page_token: Option<String>,
    #[serde(default)]
    new_start_page_token: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RawChange {
    #[serde(default)]
    change_type: Option<String>,
    #[serde(default)]
    file_id: Option<String>,
    #[serde(default)]
    removed: bool,
    #[serde(default)]
    file: Option<DriveFile>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct StartPageToken {
    #[serde(default)]
    start_page_token: Option<String>,
}

fn valid_page_token(token: &str) -> bool {
    !token.is_empty()
        && token.len() <= MAX_PAGE_TOKEN
        && token.bytes().all(|byte| byte.is_ascii_graphic())
}

/// Size and modification time of an open file, taken before reading it, so
/// an upload can prove its source did not change while it was read.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct SourceStamp {
    size: u64,
    mtime: (i64, i64),
}

impl SourceStamp {
    fn of(file: &File) -> std::io::Result<Self> {
        use std::os::unix::fs::MetadataExt;
        let metadata = file.metadata()?;
        Ok(Self {
            size: metadata.len(),
            mtime: (metadata.mtime(), metadata.mtime_nsec()),
        })
    }

    fn unchanged(&self, file: &File, source: &Path) -> Result<(), RemoteError> {
        if Self::of(file)? == *self {
            Ok(())
        } else {
            Err(RemoteError::Local(format!(
                "{} changed while uploading",
                source.display()
            )))
        }
    }
}

/// Opens a regular upload source without following a symlink, and returns
/// its stamp and md5, proven to belong to that stamp.
fn open_source(local: &Path) -> Result<(File, SourceStamp, [u8; 16]), RemoteError> {
    use std::os::unix::fs::OpenOptionsExt;
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(local)?;
    if !file.metadata()?.is_file() {
        return Err(RemoteError::Local(format!(
            "{} is not a regular file",
            local.display()
        )));
    }
    let stamp = SourceStamp::of(&file)?;
    let (md5, len) = md5_open(&mut file)?;
    stamp.unchanged(&file, local)?;
    if len != stamp.size {
        return Err(RemoteError::Local(format!(
            "{} changed while uploading",
            local.display()
        )));
    }
    Ok((file, stamp, md5))
}

/// The whole content of an opened source, proven unchanged since `stamp`.
fn read_source(
    file: &mut File,
    stamp: &SourceStamp,
    md5: [u8; 16],
    local: &Path,
) -> Result<Vec<u8>, RemoteError> {
    file.seek(SeekFrom::Start(0))?;
    let mut bytes = Vec::with_capacity(usize::try_from(stamp.size).unwrap_or(0));
    file.read_to_end(&mut bytes)?;
    stamp.unchanged(file, local)?;
    if bytes.len() as u64 != stamp.size || super::md5_bytes(&bytes) != md5 {
        return Err(RemoteError::Local(format!(
            "{} changed while uploading",
            local.display()
        )));
    }
    Ok(bytes)
}

/// MD5 and length of an open file from its start.
fn md5_open(file: &mut File) -> std::io::Result<([u8; 16], u64)> {
    use md5::Digest;
    file.seek(SeekFrom::Start(0))?;
    let mut hasher = md5::Md5::new();
    let mut buffer = vec![0u8; 1 << 20];
    let mut total = 0u64;
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
        total += read as u64;
    }
    Ok((hasher.finalize().into(), total))
}

/// Persistent identity of one in-flight upload.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct UploadCheckpoint {
    pub(crate) file_id: String,
    #[serde(default)]
    pub(crate) session_uri: Option<String>,
}

#[derive(Deserialize)]
struct ErrorEnvelope {
    error: ErrorBody,
}

#[derive(Deserialize)]
struct ErrorBody {
    #[serde(default)]
    message: String,
    #[serde(default)]
    errors: Vec<ErrorItem>,
}

#[derive(Deserialize)]
struct ErrorItem {
    #[serde(default)]
    reason: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct FileList {
    #[serde(default)]
    next_page_token: Option<String>,
    #[serde(default)]
    files: Vec<DriveFile>,
}

#[derive(Deserialize)]
struct GeneratedIds {
    ids: Vec<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct About {
    #[serde(default)]
    user: Option<AboutUser>,
    #[serde(default)]
    storage_quota: Option<StorageQuota>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct AboutUser {
    #[serde(default)]
    email_address: String,
}

#[derive(Deserialize)]
struct StorageQuota {
    #[serde(default)]
    limit: Option<String>,
    #[serde(default)]
    usage: Option<String>,
}

/// Account identity and storage quota.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct AccountInfo {
    pub(crate) email: String,
    pub(crate) limit: Option<u64>,
    pub(crate) usage: Option<u64>,
}

/// Result of one HTTP attempt. A retry carries its telemetry reason.
enum Outcome {
    Done(Response<Body>),
    Retry(String, Option<Duration>, &'static str),
    Unauthorized(String),
    Fail(RemoteError),
}

/// Result of consuming a successful response body.
enum Step<T> {
    Done(T),
    Retry(String),
    Fail(RemoteError),
}

enum SessionStatus {
    Complete(Box<DriveFile>),
    Offset(u64),
    Expired,
}

pub(crate) fn http_agent() -> ureq::Agent {
    ureq::Agent::config_builder()
        .http_status_as_error(false)
        // Resumable uploads answer 308 without a Location; never follow it.
        .max_redirects(0)
        .user_agent(concat!("zerotrust-drive/", env!("CARGO_PKG_VERSION")))
        .timeout_connect(Some(Duration::from_secs(30)))
        .timeout_recv_response(Some(Duration::from_secs(120)))
        .timeout_send_body(Some(Duration::from_secs(600)))
        .timeout_recv_body(Some(Duration::from_secs(600)))
        .build()
        .new_agent()
}

fn origin(url: &str) -> Option<&str> {
    let (scheme, rest) = url.split_once("://")?;
    let end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    if end == 0 {
        return None;
    }
    Some(&url[..scheme.len() + 3 + end])
}

fn header<'a>(response: &'a Response<Body>, name: &str) -> Option<&'a str> {
    response.headers().get(name)?.to_str().ok()
}

fn retry_after(response: &Response<Body>) -> Option<Duration> {
    header(response, "retry-after")?
        .trim()
        .parse::<u64>()
        .ok()
        .map(Duration::from_secs)
}

fn classify(op: &str, result: Result<Response<Body>, ureq::Error>) -> Outcome {
    let mut response = match result {
        Ok(response) => response,
        Err(error) => return Outcome::Retry(format!("{op}: {error}"), None, "network"),
    };
    let status = response.status().as_u16();
    if (200..300).contains(&status) || status == 308 {
        return Outcome::Done(response);
    }
    let after = retry_after(&response);
    let body = response
        .body_mut()
        .with_config()
        .limit(MAX_ERROR_BODY)
        .read_to_vec()
        .unwrap_or_default();
    let (message, reasons) = match serde_json::from_slice::<ErrorEnvelope>(&body) {
        Ok(envelope) => (
            envelope.error.message,
            envelope
                .error
                .errors
                .into_iter()
                .map(|item| item.reason)
                .collect::<Vec<_>>(),
        ),
        Err(_) => (String::new(), Vec::new()),
    };
    let has = |wanted: &[&str]| {
        reasons
            .iter()
            .any(|reason| wanted.contains(&reason.as_str()))
    };
    let detail = if message.is_empty() {
        format!("{op}: HTTP {status}")
    } else {
        format!("{op}: HTTP {status}: {message}")
    };
    match status {
        401 => Outcome::Unauthorized(detail),
        403 if has(&["rateLimitExceeded", "userRateLimitExceeded"]) => {
            Outcome::Retry(detail, after, "rate_limit")
        }
        403 if has(&["backendError"]) => Outcome::Retry(detail, after, "server"),
        403 if has(&["storageQuotaExceeded", "teamDriveFileLimitExceeded"]) => {
            Outcome::Fail(RemoteError::Quota(detail))
        }
        403 if has(&["dailyLimitExceeded"]) => Outcome::Fail(RemoteError::Quota(detail)),
        404 | 410 => Outcome::Fail(RemoteError::NotFound(detail)),
        409 => Outcome::Fail(RemoteError::Conflict(detail)),
        408 => Outcome::Retry(detail, after, "timeout"),
        429 => Outcome::Retry(detail, after, "rate_limit"),
        500 | 502 | 503 | 504 => Outcome::Retry(detail, after, "server"),
        _ => Outcome::Fail(RemoteError::Protocol(detail)),
    }
}

/// Telemetry class of an operation label; labels never carry names or ids.
/// The first matching keyword wins, so the specific ones come first.
fn request_class(op: &str) -> RequestClass {
    const CLASSES: [(&str, RequestClass); 12] = [
        ("update file content", RequestClass::Upload),
        ("update file", RequestClass::Update),
        ("upload", RequestClass::Upload),
        ("download", RequestClass::Download),
        ("changes", RequestClass::Changes),
        ("list", RequestClass::List),
        ("find", RequestClass::List),
        ("account", RequestClass::About),
        ("metadata", RequestClass::Get),
        ("create", RequestClass::Create),
        ("bin", RequestClass::Trash),
        ("token", RequestClass::Token),
    ];
    CLASSES
        .iter()
        .find(|(keyword, _)| op.contains(keyword))
        .map_or(RequestClass::Other, |(_, class)| *class)
}

/// The token source reports errors rather than statuses: a rejected grant is
/// a 4xx answer and a transport or availability failure counts as network.
fn token_status<T>(fetched: &Result<T, RemoteError>) -> Option<u16> {
    match fetched {
        Ok(_) => Some(200),
        Err(RemoteError::Network(_)) => None,
        Err(RemoteError::Auth(_)) => Some(401),
        Err(_) => Some(400),
    }
}

fn parse_json<T: DeserializeOwned>(op: &str, mut response: Response<Body>) -> Step<T> {
    match response
        .body_mut()
        .with_config()
        .limit(MAX_JSON_RESPONSE)
        .read_to_vec()
    {
        Ok(bytes) => match serde_json::from_slice(&bytes) {
            Ok(value) => Step::Done(value),
            Err(error) => Step::Fail(RemoteError::Protocol(format!(
                "{op}: unexpected response: {error}"
            ))),
        },
        Err(error) => Step::Retry(format!("{op}: read response: {error}")),
    }
}

fn require_id(id: &str) -> Result<(), RemoteError> {
    if valid_file_id(id) {
        Ok(())
    } else {
        Err(RemoteError::Protocol(format!(
            "invalid Drive file id {id:?}"
        )))
    }
}

/// Google Drive v3 client.
pub(crate) struct GoogleDrive {
    agent: ureq::Agent,
    api_base: String,
    tokens: Box<dyn TokenSource>,
    cached: Mutex<Option<(String, Instant)>>,
    policy: RetryPolicy,
    pacer: Pacer,
    multipart_limit: u64,
    chunk: u64,
    /// `ZDRIVE_TRACE_HTTP=1`: one stderr line per request with its operation,
    /// outcome and latency; never a URL, header or body.
    trace: bool,
}

impl GoogleDrive {
    pub(crate) fn new(tokens: Box<dyn TokenSource>) -> Self {
        Self::with_endpoint(GOOGLE_API, tokens, RetryPolicy::PRODUCTION)
    }

    pub(crate) fn with_endpoint(
        api_base: &str,
        tokens: Box<dyn TokenSource>,
        policy: RetryPolicy,
    ) -> Self {
        Self {
            agent: http_agent(),
            api_base: api_base.trim_end_matches('/').to_string(),
            tokens,
            cached: Mutex::new(None),
            policy,
            pacer: Pacer::new(),
            multipart_limit: MULTIPART_LIMIT,
            chunk: UPLOAD_CHUNK,
            trace: std::env::var_os("ZDRIVE_TRACE_HTTP").is_some_and(|value| value == "1"),
        }
    }

    pub(crate) fn retry_policy(&self) -> RetryPolicy {
        self.policy
    }

    /// Applies to every later request.
    pub(crate) fn set_retry_policy(&mut self, policy: RetryPolicy) {
        self.policy = policy;
    }

    /// Smaller upload thresholds let tests exercise multi-chunk sessions.
    #[cfg(test)]
    pub(crate) fn with_upload_sizes(mut self, multipart_limit: u64, chunk: u64) -> Self {
        assert!(
            chunk > 0 && chunk.is_multiple_of(256 << 10),
            "Drive chunks are multiples of 256 KiB"
        );
        self.multipart_limit = multipart_limit;
        self.chunk = chunk;
        self
    }

    fn url(&self, path: &str) -> String {
        format!("{}{path}", self.api_base)
    }

    fn bearer(&self) -> Result<String, RemoteError> {
        let mut cached = self
            .cached
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        if let Some((token, expires)) = cached.as_ref()
            && *expires > Instant::now() + Duration::from_secs(60)
        {
            return Ok(format!("Bearer {token}"));
        }
        let started = Instant::now();
        let fetched = self.tokens.fetch(&self.agent);
        telemetry::remote_request(
            RequestClass::Token,
            token_status(&fetched),
            started.elapsed(),
            1,
        );
        let (token, lifetime) = fetched?;
        *cached = Some((token.clone(), Instant::now() + lifetime));
        Ok(format!("Bearer {token}"))
    }

    fn invalidate(&self, rejected: &str) {
        let mut cached = self
            .cached
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        if cached
            .as_ref()
            .is_some_and(|(token, _)| rejected.strip_prefix("Bearer ") == Some(token.as_str()))
        {
            *cached = None;
        }
    }

    /// One paced HTTP attempt with a current bearer token; `number` counts
    /// the attempts of this request for telemetry.
    fn attempt<S>(&self, op: &str, write: bool, number: u32, send: &mut S) -> (Outcome, String)
    where
        S: FnMut(&ureq::Agent, &str) -> Result<Response<Body>, ureq::Error>,
    {
        let queued = Instant::now();
        self.pacer.wait(&self.policy, write);
        let paced = queued.elapsed();
        let authorizing = Instant::now();
        let bearer = match self.bearer() {
            Ok(bearer) => bearer,
            Err(RemoteError::Network(detail)) => {
                return (Outcome::Retry(detail, None, "network"), String::new());
            }
            Err(error) => return (Outcome::Fail(error), String::new()),
        };
        let token_wait = authorizing.elapsed();
        let started = Instant::now();
        let sent = send(&self.agent, &bearer);
        let status = sent
            .as_ref()
            .ok()
            .map(|response| response.status().as_u16());
        telemetry::remote_request(request_class(op), status, started.elapsed(), number);
        let outcome = classify(op, sent);
        if self.trace {
            let result = match &outcome {
                Outcome::Done(response) => format!("HTTP {}", response.status().as_u16()),
                Outcome::Retry(detail, _, _) => format!("retry ({detail})"),
                Outcome::Unauthorized(_) => "unauthorized".to_string(),
                Outcome::Fail(error) => format!("failed ({error})"),
            };
            eprintln!(
                "zerotrust-drive: http {op}: {result} after {:.0?} (paced {:.0?}, token {:.0?})",
                started.elapsed(),
                paced,
                token_wait
            );
        }
        (outcome, bearer)
    }

    /// Runs an idempotent request with throttling/5xx retries and one token
    /// refresh, then consumes its body with `finish`, which may also ask
    /// for a retry after a truncated body.
    fn run<T, S, F>(
        &self,
        op: &str,
        write: bool,
        mut send: S,
        mut finish: F,
    ) -> Result<T, RemoteError>
    where
        S: FnMut(&ureq::Agent, &str) -> Result<Response<Body>, ureq::Error>,
        F: FnMut(Response<Body>) -> Step<T>,
    {
        let mut refreshed = false;
        let mut attempt = 0u32;
        let mut tries = 0u32;
        loop {
            tries += 1;
            let (outcome, bearer) = self.attempt(op, write, tries, &mut send);
            let detail = match outcome {
                Outcome::Done(response) => match finish(response) {
                    Step::Done(value) => return Ok(value),
                    Step::Fail(error) => return Err(error),
                    Step::Retry(detail) => (detail, None, "body"),
                },
                Outcome::Unauthorized(detail) => {
                    if refreshed {
                        return Err(RemoteError::Auth(detail));
                    }
                    refreshed = true;
                    self.invalidate(&bearer);
                    continue;
                }
                Outcome::Retry(detail, after, reason) => (detail, after, reason),
                Outcome::Fail(error) => return Err(error),
            };
            attempt += 1;
            if attempt >= self.policy.attempts {
                return Err(RemoteError::Network(format!(
                    "{} after {attempt} attempts",
                    detail.0
                )));
            }
            let delay = detail
                .1
                .map(|after| after.min(self.policy.cap))
                .unwrap_or_else(|| self.policy.delay(attempt));
            telemetry::retry(request_class(op), detail.2, delay);
            std::thread::sleep(delay);
        }
    }

    fn run_json<T: DeserializeOwned, S>(
        &self,
        op: &str,
        write: bool,
        send: S,
    ) -> Result<T, RemoteError>
    where
        S: FnMut(&ureq::Agent, &str) -> Result<Response<Body>, ureq::Error>,
    {
        self.run(op, write, send, |response| parse_json(op, response))
    }

    pub(crate) fn about(&self) -> Result<AccountInfo, RemoteError> {
        let url = self.url("/drive/v3/about");
        let about: About = self.run_json("read account", false, |agent, bearer| {
            agent
                .get(&url)
                .header("Authorization", bearer)
                .query("fields", "user(emailAddress),storageQuota(limit,usage)")
                .call()
        })?;
        let quota = about.storage_quota;
        Ok(AccountInfo {
            email: about
                .user
                .map(|user| user.email_address)
                .unwrap_or_default(),
            limit: quota
                .as_ref()
                .and_then(|quota| quota.limit.as_deref()?.parse().ok()),
            usage: quota
                .as_ref()
                .and_then(|quota| quota.usage.as_deref()?.parse().ok()),
        })
    }

    pub(crate) fn get(&self, id: &str) -> Result<DriveFile, RemoteError> {
        require_id(id)?;
        let url = self.url(&format!("/drive/v3/files/{id}"));
        self.run_json("read file metadata", false, |agent, bearer| {
            agent
                .get(&url)
                .header("Authorization", bearer)
                .query("fields", FILE_FIELDS)
                .query("supportsAllDrives", "true")
                .call()
        })
    }

    /// The folder `id`. My Drive itself stays usable through the [`MY_DRIVE`]
    /// alias as a parent, in queries and in creates even where `drive.file`
    /// hides it from `files.get`, so that refusal yields the alias instead.
    pub(crate) fn folder(&self, id: &str) -> Result<DriveFile, RemoteError> {
        match self.get(id) {
            Err(RemoteError::NotFound(_)) if id == MY_DRIVE => Ok(DriveFile::my_drive()),
            result => result,
        }
    }

    /// Every non-trashed child of `parent`, across all pages.
    pub(crate) fn list(
        &self,
        parent: &str,
        folders_only: bool,
    ) -> Result<Vec<DriveFile>, RemoteError> {
        require_id(parent)?;
        let mut query = format!("'{parent}' in parents and trashed = false");
        if folders_only {
            query.push_str(&format!(" and mimeType = '{FOLDER_MIME}'"));
        }
        self.query_all("list folder", &query)
    }

    /// Every non-trashed folder anywhere in the Drive that carries the app
    /// property [`MARKER_KEY`]`=marker`. Under `drive.file` only folders
    /// this app created are visible, whatever they were renamed to.
    pub(crate) fn find_marked_folders(&self, marker: &str) -> Result<Vec<DriveFile>, RemoteError> {
        if marker.is_empty()
            || !marker
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        {
            return Err(RemoteError::Protocol(format!(
                "invalid folder marker {marker:?}"
            )));
        }
        let query = format!(
            "appProperties has {{ key='{MARKER_KEY}' and value='{marker}' }} and mimeType = '{FOLDER_MIME}' and trashed = false"
        );
        self.query_all("find marked folders", &query)
    }

    /// The single folder marked `marker`, or a new one named `name` in My
    /// Drive when none exists; `true` when it was created. Several marked
    /// folders are refused with their ids, so two installs never split one
    /// drive between them.
    pub(crate) fn find_or_create_marked_folder(
        &self,
        marker: &str,
        name: &str,
    ) -> Result<(DriveFile, bool), RemoteError> {
        let mut found = self.find_marked_folders(marker)?;
        match found.len() {
            0 => {
                let id = self.generate_ids(1)?.remove(0);
                let props = BTreeMap::from([(MARKER_KEY.to_string(), marker.to_string())]);
                let folder = self.create_folder_with(MY_DRIVE, name, &id, &props)?;
                Ok((folder, true))
            }
            1 => Ok((found.remove(0), false)),
            _ => {
                let ids: Vec<&str> = found.iter().map(|folder| folder.id.as_str()).collect();
                Err(RemoteError::Conflict(format!(
                    "{} Drive folders are marked as zerotrust-drive {marker} folders (ids {}); move all but one to the bin, or choose one with --folder-id",
                    found.len(),
                    ids.join(", ")
                )))
            }
        }
    }

    fn query_all(&self, op: &'static str, query: &str) -> Result<Vec<DriveFile>, RemoteError> {
        let url = self.url("/drive/v3/files");
        let mut files = Vec::new();
        let mut page_token: Option<String> = None;
        loop {
            let page: FileList = self.run_json(op, false, |agent, bearer| {
                let mut request = agent
                    .get(&url)
                    .header("Authorization", bearer)
                    .query("q", query)
                    .query("fields", LIST_FIELDS)
                    .query("pageSize", "1000")
                    .query("supportsAllDrives", "true")
                    .query("includeItemsFromAllDrives", "true");
                if let Some(token) = page_token.as_deref() {
                    request = request.query("pageToken", token);
                }
                request.call()
            })?;
            files.extend(page.files);
            match page.next_page_token {
                Some(token) if !token.is_empty() => page_token = Some(token),
                _ => break,
            }
        }
        Ok(files)
    }

    pub(crate) fn generate_ids(&self, count: usize) -> Result<Vec<String>, RemoteError> {
        let count = count.clamp(1, 1000);
        let url = self.url("/drive/v3/files/generateIds");
        let generated: GeneratedIds =
            self.run_json("generate file ids", false, |agent, bearer| {
                agent
                    .get(&url)
                    .header("Authorization", bearer)
                    .query("count", count.to_string())
                    .query("space", "drive")
                    .query("type", "files")
                    .call()
            })?;
        if generated.ids.len() != count || !generated.ids.iter().all(|id| valid_file_id(id)) {
            return Err(RemoteError::Protocol(
                "generateIds returned an unexpected id list".to_string(),
            ));
        }
        Ok(generated.ids)
    }

    /// Reconciles a 409 for a pre-generated id: the existing file must be
    /// exactly the one this client meant to create.
    fn reconcile(
        &self,
        id: &str,
        parent: &str,
        name: &str,
        content: Option<(u64, [u8; 16])>,
        folder: bool,
    ) -> Result<DriveFile, RemoteError> {
        let existing = self.get(id)?;
        let content_matches = match content {
            Some((size, md5)) => existing.size() == Some(size) && existing.md5() == Some(md5),
            None => true,
        };
        if existing.name == name
            && existing.is_folder() == folder
            && content_matches
            && self.placed_in(&existing, parent)?
        {
            Ok(existing)
        } else {
            Err(RemoteError::Conflict(format!(
                "Drive file id {id} already exists with different identity or content"
            )))
        }
    }

    /// Whether `file` sits directly in `parent`. Drive reports My Drive's
    /// real id in `parents`, never the [`MY_DRIVE`] alias a caller passed,
    /// and `drive.file` hides that real id, so the alias is checked by
    /// listing My Drive's children instead.
    fn placed_in(&self, file: &DriveFile, parent: &str) -> Result<bool, RemoteError> {
        if file.parents.iter().any(|candidate| candidate == parent) {
            return Ok(true);
        }
        if parent != MY_DRIVE {
            return Ok(false);
        }
        Ok(self
            .list(MY_DRIVE, file.is_folder())?
            .iter()
            .any(|child| child.id == file.id))
    }

    fn metadata_json(
        id: &str,
        parent: &str,
        name: &str,
        mime: Option<&str>,
        props: &BTreeMap<String, String>,
    ) -> Vec<u8> {
        let mut metadata = serde_json::json!({ "id": id, "name": name, "parents": [parent] });
        if let Some(mime) = mime {
            metadata["mimeType"] = serde_json::Value::String(mime.to_string());
        }
        if !props.is_empty() {
            metadata["appProperties"] = serde_json::to_value(props).expect("string map");
        }
        serde_json::to_vec(&metadata).expect("metadata serializes")
    }

    pub(crate) fn create_folder(
        &self,
        parent: &str,
        name: &str,
        id: &str,
    ) -> Result<DriveFile, RemoteError> {
        self.create_folder_with(parent, name, id, &BTreeMap::new())
    }

    /// Creates a folder carrying the app properties `props`.
    pub(crate) fn create_folder_with(
        &self,
        parent: &str,
        name: &str,
        id: &str,
        props: &BTreeMap<String, String>,
    ) -> Result<DriveFile, RemoteError> {
        require_id(parent)?;
        require_id(id)?;
        let url = self.url("/drive/v3/files");
        let body = Self::metadata_json(id, parent, name, Some(FOLDER_MIME), props);
        match self.run_json("create folder", true, |agent, bearer| {
            agent
                .post(&url)
                .header("Authorization", bearer)
                .header("Content-Type", "application/json; charset=UTF-8")
                .query("fields", FILE_FIELDS)
                .query("supportsAllDrives", "true")
                .send(&body[..])
        }) {
            Err(RemoteError::Conflict(_)) => self.reconcile(id, parent, name, None, true),
            other => other,
        }
    }

    /// Creates a small immutable file in one multipart request.
    pub(crate) fn create_small(
        &self,
        parent: &str,
        name: &str,
        id: &str,
        bytes: &[u8],
        props: &BTreeMap<String, String>,
    ) -> Result<DriveFile, RemoteError> {
        require_id(parent)?;
        require_id(id)?;
        let md5 = super::md5_bytes(bytes);
        let metadata = Self::metadata_json(id, parent, name, None, props);
        let (body, content_type) = multipart_body(&metadata, bytes);
        let url = self.url("/upload/drive/v3/files");
        let created = match self.run_json::<DriveFile, _>("upload file", true, |agent, bearer| {
            agent
                .post(&url)
                .header("Authorization", bearer)
                .header("Content-Type", &content_type)
                .query("uploadType", "multipart")
                .query("fields", FILE_FIELDS)
                .query("supportsAllDrives", "true")
                .send(&body[..])
        }) {
            Err(RemoteError::Conflict(_)) => {
                return self.reconcile(id, parent, name, Some((bytes.len() as u64, md5)), false);
            }
            other => other?,
        };
        self.verify_created(&created, id, bytes.len() as u64, md5)
    }

    /// Proves Drive stored exactly the bytes sent under the intended id.
    /// A response without size or md5 is completed from file metadata.
    fn verify_created(
        &self,
        file: &DriveFile,
        id: &str,
        size: u64,
        md5: [u8; 16],
    ) -> Result<DriveFile, RemoteError> {
        let fetched;
        let file = if file.size().is_none() || file.md5().is_none() {
            fetched = self.get(id)?;
            &fetched
        } else {
            file
        };
        if file.id != id || file.size() != Some(size) || file.md5() != Some(md5) {
            return Err(RemoteError::Integrity(format!(
                "Drive stored {} with a different id, size or md5 than was sent",
                file.name
            )));
        }
        Ok(file.clone())
    }

    /// Uploads a local immutable file under the checkpoint's pre-generated
    /// id. `persist` durably records the checkpoint before a session is
    /// used, so a restarted process resumes instead of re-sending.
    pub(crate) fn upload_file(
        &self,
        parent: &str,
        name: &str,
        source: &Path,
        checkpoint: &mut UploadCheckpoint,
        persist: &mut dyn FnMut(&UploadCheckpoint) -> std::io::Result<()>,
    ) -> Result<DriveFile, RemoteError> {
        require_id(parent)?;
        require_id(&checkpoint.file_id)?;
        let (md5, size) = md5_file(source)?;
        if size <= self.multipart_limit {
            let bytes = std::fs::read(source)?;
            if bytes.len() as u64 != size {
                return Err(RemoteError::Local(format!(
                    "{} changed while uploading",
                    source.display()
                )));
            }
            return self.create_small(parent, name, &checkpoint.file_id, &bytes, &BTreeMap::new());
        }
        let mut file = File::open(source)?;
        let mut restarts = 0u32;
        loop {
            let session = match checkpoint.session_uri.clone() {
                Some(session) => session,
                None => match self.start_session(parent, name, &checkpoint.file_id, size)? {
                    Some(session) => {
                        checkpoint.session_uri = Some(session.clone());
                        persist(checkpoint)?;
                        session
                    }
                    None => {
                        return self.reconcile(
                            &checkpoint.file_id,
                            parent,
                            name,
                            Some((size, md5)),
                            false,
                        );
                    }
                },
            };
            let status = match self.send_session(&session, &mut file, size, None) {
                // Another attempt already completed this id.
                Err(RemoteError::Conflict(_)) => {
                    return self.reconcile(
                        &checkpoint.file_id,
                        parent,
                        name,
                        Some((size, md5)),
                        false,
                    );
                }
                other => other?,
            };
            match status {
                SessionStatus::Complete(created) => {
                    return self.verify_created(&created, &checkpoint.file_id, size, md5);
                }
                SessionStatus::Expired => {
                    restarts += 1;
                    if restarts > MAX_SESSION_RESTARTS {
                        return Err(RemoteError::Network(format!(
                            "resumable upload of {name} kept expiring"
                        )));
                    }
                    // A completed upload under this id answers 409 on restart.
                    checkpoint.session_uri = None;
                    persist(checkpoint)?;
                }
                SessionStatus::Offset(_) => {
                    unreachable!("send_session returns only terminal states")
                }
            }
        }
    }

    /// Starts a resumable session; `None` means the id already exists.
    fn start_session(
        &self,
        parent: &str,
        name: &str,
        id: &str,
        size: u64,
    ) -> Result<Option<String>, RemoteError> {
        let metadata = Self::metadata_json(id, parent, name, None, &BTreeMap::new());
        self.open_session(None, &metadata, size)
    }

    /// Opens a resumable session that creates a file (`update` is `None`)
    /// or replaces the content of the file `update` names.
    fn open_session(
        &self,
        update: Option<&str>,
        metadata: &[u8],
        size: u64,
    ) -> Result<Option<String>, RemoteError> {
        let url = match update {
            Some(id) => self.url(&format!("/upload/drive/v3/files/{id}")),
            None => self.url("/upload/drive/v3/files"),
        };
        let expected_origin = origin(&self.api_base).map(str::to_string);
        let result = self.run(
            "start resumable upload",
            true,
            |agent, bearer| {
                let request = match update {
                    Some(_) => agent.patch(&url),
                    None => agent.post(&url),
                };
                request
                    .header("Authorization", bearer)
                    .header("Content-Type", "application/json; charset=UTF-8")
                    .header("X-Upload-Content-Type", "application/octet-stream")
                    .header("X-Upload-Content-Length", size.to_string())
                    .query("uploadType", "resumable")
                    .query("fields", FILE_FIELDS)
                    .query("supportsAllDrives", "true")
                    .send(metadata)
            },
            |response| match header(&response, "location") {
                Some(location)
                    if origin(location).map(str::to_string) == expected_origin
                        && expected_origin.is_some() =>
                {
                    Step::Done(location.to_string())
                }
                _ => Step::Fail(RemoteError::Protocol(
                    "resumable upload session has no same-origin Location".to_string(),
                )),
            },
        );
        match result {
            Ok(session) => Ok(Some(session)),
            Err(RemoteError::Conflict(_)) => Ok(None),
            Err(error) => Err(error),
        }
    }

    fn session_outcome(response: Response<Body>) -> Step<SessionStatus> {
        if response.status().as_u16() == 308 {
            let offset = match header(&response, "range") {
                None => 0,
                Some(range) => match range
                    .strip_prefix("bytes=0-")
                    .and_then(|end| end.parse::<u64>().ok())
                {
                    Some(end) => end + 1,
                    None => {
                        return Step::Fail(RemoteError::Protocol(format!(
                            "resumable upload answered an unexpected Range {range:?}"
                        )));
                    }
                },
            };
            return Step::Done(SessionStatus::Offset(offset));
        }
        match parse_json::<DriveFile>("finish resumable upload", response) {
            Step::Done(file) => Step::Done(SessionStatus::Complete(Box::new(file))),
            Step::Retry(detail) => Step::Retry(detail),
            Step::Fail(error) => Step::Fail(error),
        }
    }

    fn query_session(&self, session: &str, size: u64) -> Result<SessionStatus, RemoteError> {
        match self.run(
            "query resumable upload",
            false,
            |agent, bearer| {
                agent
                    .put(session)
                    .header("Authorization", bearer)
                    .header("Content-Range", format!("bytes */{size}"))
                    .send_empty()
            },
            Self::session_outcome,
        ) {
            Err(RemoteError::NotFound(_)) => Ok(SessionStatus::Expired),
            other => other,
        }
    }

    /// Sends the remaining bytes of a session. Every interrupted chunk is
    /// followed by a status query, because Drive may have kept part of it.
    /// With a `stamp`, every chunk is checked against it after being read,
    /// so the final chunk, which completes the upload, is never sent from a
    /// source that changed since its first byte was read.
    fn send_session(
        &self,
        session: &str,
        file: &mut File,
        size: u64,
        stamp: Option<(&SourceStamp, &Path)>,
    ) -> Result<SessionStatus, RemoteError> {
        let mut offset = match self.query_session(session, size)? {
            SessionStatus::Offset(offset) if offset <= size => offset,
            SessionStatus::Offset(_) => {
                return Err(RemoteError::Protocol(
                    "resumable upload offset exceeds the file".to_string(),
                ));
            }
            terminal => return Ok(terminal),
        };
        let mut failures = 0u32;
        let mut refreshed = false;
        let mut tries = 0u32;
        let mut chunk = Vec::new();
        loop {
            let len = self.chunk.min(size - offset);
            if len == 0 {
                // Everything was acknowledged but no metadata was returned yet.
                return match self.query_session(session, size)? {
                    SessionStatus::Offset(_) => Err(RemoteError::Protocol(
                        "resumable upload acknowledged every byte without completing".to_string(),
                    )),
                    terminal => Ok(terminal),
                };
            }
            chunk.resize(len as usize, 0);
            file.seek(SeekFrom::Start(offset))?;
            file.read_exact(&mut chunk)?;
            if let Some((stamp, source)) = stamp {
                stamp.unchanged(file, source)?;
            }
            let range = format!("bytes {offset}-{}/{size}", offset + len - 1);
            tries += 1;
            let (outcome, bearer) = self.attempt(
                "upload chunk",
                false,
                tries,
                &mut |agent: &ureq::Agent, bearer: &str| {
                    agent
                        .put(session)
                        .header("Authorization", bearer)
                        .header("Content-Range", &range)
                        .send(&chunk[..])
                },
            );
            let detail = match outcome {
                Outcome::Done(response) => match Self::session_outcome(response) {
                    Step::Done(SessionStatus::Offset(next)) if next > offset && next <= size => {
                        offset = next;
                        failures = 0;
                        tries = 0;
                        continue;
                    }
                    Step::Done(SessionStatus::Offset(_)) => {
                        ("upload chunk made no progress".to_string(), "stalled")
                    }
                    Step::Done(terminal) => return Ok(terminal),
                    Step::Retry(detail) => (detail, "body"),
                    Step::Fail(error) => return Err(error),
                },
                Outcome::Unauthorized(detail) => {
                    if refreshed {
                        return Err(RemoteError::Auth(detail));
                    }
                    refreshed = true;
                    self.invalidate(&bearer);
                    (detail, "auth")
                }
                Outcome::Retry(detail, _, reason) => (detail, reason),
                Outcome::Fail(RemoteError::NotFound(_)) => return Ok(SessionStatus::Expired),
                Outcome::Fail(error) => return Err(error),
            };
            failures += 1;
            if failures >= self.policy.attempts {
                return Err(RemoteError::Network(format!(
                    "{} after {failures} attempts",
                    detail.0
                )));
            }
            let delay = self.policy.delay(failures);
            telemetry::retry(RequestClass::Upload, detail.1, delay);
            std::thread::sleep(delay);
            offset = match self.query_session(session, size)? {
                SessionStatus::Offset(confirmed) if confirmed <= size => confirmed,
                SessionStatus::Offset(_) => {
                    return Err(RemoteError::Protocol(
                        "resumable upload offset exceeds the file".to_string(),
                    ));
                }
                terminal => return Ok(terminal),
            };
        }
    }

    /// Exactly `len` bytes starting at `offset`.
    pub(crate) fn read_range(
        &self,
        id: &str,
        offset: u64,
        len: u64,
    ) -> Result<Vec<u8>, RemoteError> {
        require_id(id)?;
        if len == 0 {
            return Ok(Vec::new());
        }
        let url = self.url(&format!("/drive/v3/files/{id}"));
        let range = format!("bytes={offset}-{}", offset + len - 1);
        self.run(
            "download range",
            false,
            |agent, bearer| {
                agent
                    .get(&url)
                    .header("Authorization", bearer)
                    .header("Range", &range)
                    .query("alt", "media")
                    .query("supportsAllDrives", "true")
                    .call()
            },
            |mut response| {
                let status = response.status().as_u16();
                if status != 206 && !(status == 200 && offset == 0) {
                    return Step::Fail(RemoteError::Protocol(format!(
                        "download range answered HTTP {status}"
                    )));
                }
                // A 200 for offset 0 sends the whole file; keep only the range.
                let mut bytes = Vec::with_capacity(len as usize);
                match response
                    .body_mut()
                    .as_reader()
                    .take(len)
                    .read_to_end(&mut bytes)
                {
                    Ok(_) if bytes.len() as u64 == len => Step::Done(bytes),
                    Ok(_) => Step::Retry(format!(
                        "download range returned {} of {len} bytes",
                        bytes.len()
                    )),
                    Err(error) => Step::Retry(format!("download range: {error}")),
                }
            },
        )
    }

    /// Reads a whole small file, bounded by `max_len`.
    pub(crate) fn read_small(
        &self,
        file: &DriveFile,
        max_len: u64,
    ) -> Result<Vec<u8>, RemoteError> {
        let size = file
            .size()
            .ok_or_else(|| RemoteError::Protocol(format!("{} has no size", file.name)))?;
        if size > max_len {
            return Err(RemoteError::Integrity(format!(
                "{} is {size} bytes; at most {max_len} are allowed",
                file.name
            )));
        }
        let bytes = self.read_range(&file.id, 0, size)?;
        if file
            .md5()
            .is_some_and(|md5| md5 != super::md5_bytes(&bytes))
        {
            return Err(RemoteError::Integrity(format!(
                "{} does not match its Drive md5",
                file.name
            )));
        }
        Ok(bytes)
    }

    /// Downloads a whole file into `dest`, resuming from its current length,
    /// then checks the size and md5 Drive reported for it.
    pub(crate) fn download_to(&self, file: &DriveFile, dest: &Path) -> Result<(), RemoteError> {
        require_id(&file.id)?;
        let size = file
            .size()
            .ok_or_else(|| RemoteError::Protocol(format!("{} has no size", file.name)))?;
        let md5 = file
            .md5()
            .ok_or_else(|| RemoteError::Protocol(format!("{} has no md5", file.name)))?;
        let mut options = OpenOptions::new();
        options.read(true).write(true).create(true);
        #[cfg(unix)]
        std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
        let mut output = options.open(dest)?;
        let mut have = output.metadata()?.len();
        if have > size {
            output.set_len(0)?;
            have = 0;
        }
        let url = self.url(&format!("/drive/v3/files/{}", file.id));
        let mut failures = 0u32;
        while have < size {
            output.seek(SeekFrom::Start(have))?;
            let range = format!("bytes={have}-{}", size - 1);
            let start = have;
            let result = self.run(
                "download file",
                false,
                |agent, bearer| {
                    agent
                        .get(&url)
                        .header("Authorization", bearer)
                        .header("Range", &range)
                        .query("alt", "media")
                        .query("supportsAllDrives", "true")
                        .call()
                },
                |response| {
                    let status = response.status().as_u16();
                    if status == 206 || (status == 200 && start == 0) {
                        Step::Done(response)
                    } else {
                        Step::Fail(RemoteError::Protocol(format!(
                            "download answered HTTP {status}"
                        )))
                    }
                },
            )?;
            let mut reader = result.into_body().into_reader().take(size - have);
            let copied = copy_counting(&mut reader, &mut output);
            have += copied.0;
            if let Some(error) = copied.1 {
                if copied.0 == 0 {
                    failures += 1;
                    if failures >= self.policy.attempts {
                        return Err(RemoteError::Network(format!(
                            "download {}: {error}",
                            file.name
                        )));
                    }
                    let delay = self.policy.delay(failures);
                    telemetry::retry(RequestClass::Download, "body", delay);
                    std::thread::sleep(delay);
                } else {
                    failures = 0;
                }
                continue;
            }
            if copied.0 == 0 && have < size {
                return Err(RemoteError::Protocol(format!(
                    "download of {} ended early",
                    file.name
                )));
            }
        }
        output.flush()?;
        output.sync_all()?;
        drop(output);
        let (actual, len) = md5_file(dest)?;
        if len != size || actual != md5 {
            std::fs::remove_file(dest)?;
            return Err(RemoteError::Integrity(format!(
                "downloaded {} does not match its Drive size and md5",
                file.name
            )));
        }
        Ok(())
    }

    /// Replaces the given app properties, as lease heartbeats do.
    pub(crate) fn set_app_properties(
        &self,
        id: &str,
        props: &BTreeMap<String, String>,
    ) -> Result<DriveFile, RemoteError> {
        require_id(id)?;
        let url = self.url(&format!("/drive/v3/files/{id}"));
        let body =
            serde_json::to_vec(&serde_json::json!({ "appProperties": props })).expect("serializes");
        self.run_json("update file properties", true, |agent, bearer| {
            agent
                .patch(&url)
                .header("Authorization", bearer)
                .header("Content-Type", "application/json; charset=UTF-8")
                .query("fields", FILE_FIELDS)
                .query("supportsAllDrives", "true")
                .send(&body[..])
        })
    }

    /// Replaces the content of the existing file `id` with the local file
    /// `local`, keeping its id, name and parents; Drive keeps the previous
    /// content as a revision. Small files go in one multipart request,
    /// larger ones through a resumable session. A source that changes while
    /// it is read fails with [`RemoteError::Local`] before the upload can
    /// complete, and the stored size and md5 are verified.
    pub(crate) fn update_content(&self, id: &str, local: &Path) -> Result<DriveFile, RemoteError> {
        require_id(id)?;
        let (mut file, stamp, md5) = open_source(local)?;
        let size = stamp.size;
        if size <= self.multipart_limit {
            let bytes = read_source(&mut file, &stamp, md5, local)?;
            let (body, content_type) = multipart_body(b"{}", &bytes);
            let url = self.url(&format!("/upload/drive/v3/files/{id}"));
            let updated: DriveFile =
                self.run_json("update file content", true, |agent, bearer| {
                    agent
                        .patch(&url)
                        .header("Authorization", bearer)
                        .header("Content-Type", &content_type)
                        .query("uploadType", "multipart")
                        .query("fields", FILE_FIELDS)
                        .query("supportsAllDrives", "true")
                        .send(&body[..])
                })?;
            return self.verify_created(&updated, id, size, md5);
        }
        let mut restarts = 0u32;
        loop {
            let session = self.open_session(Some(id), b"{}", size)?.ok_or_else(|| {
                RemoteError::Conflict(format!("Drive refused to update the content of {id}"))
            })?;
            match self.send_session(&session, &mut file, size, Some((&stamp, local)))? {
                SessionStatus::Complete(updated) => {
                    return self.verify_created(&updated, id, size, md5);
                }
                SessionStatus::Expired => {
                    restarts += 1;
                    if restarts > MAX_SESSION_RESTARTS {
                        return Err(RemoteError::Network(format!(
                            "resumable update of {id} kept expiring"
                        )));
                    }
                }
                SessionStatus::Offset(_) => {
                    return Err(RemoteError::Protocol(
                        "resumable update ended without a terminal state".to_string(),
                    ));
                }
            }
        }
    }

    /// Creates `name` in `parent` from the local file `local`, under `id`
    /// when given (a pre-generated id makes a retried create idempotent:
    /// an existing file with that id must match exactly) or a fresh one.
    /// Unlike [`Self::upload_file`] it keeps no session checkpoint, and like
    /// [`Self::update_content`] a source that changes while it is read
    /// fails before the upload completes.
    pub(crate) fn create_file(
        &self,
        parent: &str,
        name: &str,
        id: Option<&str>,
        local: &Path,
    ) -> Result<DriveFile, RemoteError> {
        require_id(parent)?;
        let id =
            match id {
                Some(id) => id.to_string(),
                None => self.generate_ids(1)?.into_iter().next().ok_or_else(|| {
                    RemoteError::Protocol("Drive generated no file id".to_string())
                })?,
            };
        require_id(&id)?;
        let (mut file, stamp, md5) = open_source(local)?;
        let size = stamp.size;
        if size <= self.multipart_limit {
            let bytes = read_source(&mut file, &stamp, md5, local)?;
            return self.create_small(parent, name, &id, &bytes, &BTreeMap::new());
        }
        let mut restarts = 0u32;
        loop {
            let Some(session) = self.start_session(parent, name, &id, size)? else {
                return self.reconcile(&id, parent, name, Some((size, md5)), false);
            };
            let status = match self.send_session(&session, &mut file, size, Some((&stamp, local))) {
                Err(RemoteError::Conflict(_)) => {
                    return self.reconcile(&id, parent, name, Some((size, md5)), false);
                }
                other => other?,
            };
            match status {
                SessionStatus::Complete(created) => {
                    return self.verify_created(&created, &id, size, md5);
                }
                SessionStatus::Expired => {
                    restarts += 1;
                    if restarts > MAX_SESSION_RESTARTS {
                        return Err(RemoteError::Network(format!(
                            "resumable upload of {name} kept expiring"
                        )));
                    }
                }
                SessionStatus::Offset(_) => {
                    return Err(RemoteError::Protocol(
                        "resumable upload ended without a terminal state".to_string(),
                    ));
                }
            }
        }
    }

    /// Renames and/or moves `id`, keeping its id and content. A move names
    /// the parent to add and the parent to remove.
    pub(crate) fn update_metadata(
        &self,
        id: &str,
        new_name: Option<&str>,
        add_parent: Option<&str>,
        remove_parent: Option<&str>,
    ) -> Result<DriveFile, RemoteError> {
        require_id(id)?;
        for parent in [add_parent, remove_parent].into_iter().flatten() {
            require_id(parent)?;
        }
        let mut metadata = serde_json::json!({});
        if let Some(name) = new_name {
            if name.is_empty() {
                return Err(RemoteError::Protocol(
                    "a Drive name cannot be empty".to_string(),
                ));
            }
            metadata["name"] = serde_json::Value::String(name.to_string());
        }
        let body = serde_json::to_vec(&metadata).expect("metadata serializes");
        let url = self.url(&format!("/drive/v3/files/{id}"));
        self.run_json("update file metadata", true, |agent, bearer| {
            let mut request = agent
                .patch(&url)
                .header("Authorization", bearer)
                .header("Content-Type", "application/json; charset=UTF-8")
                .query("fields", FILE_FIELDS)
                .query("supportsAllDrives", "true");
            if let Some(parent) = add_parent {
                request = request.query("addParents", parent);
            }
            if let Some(parent) = remove_parent {
                request = request.query("removeParents", parent);
            }
            request.send(&body[..])
        })
    }

    /// The token from which [`Self::changes_page`] reports later changes.
    pub(crate) fn changes_start_token(&self) -> Result<String, RemoteError> {
        let url = self.url("/drive/v3/changes/startPageToken");
        let token: StartPageToken =
            self.run_json("read changes start token", false, |agent, bearer| {
                agent
                    .get(&url)
                    .header("Authorization", bearer)
                    .query("supportsAllDrives", "true")
                    .call()
            })?;
        match token.start_page_token {
            Some(token) if valid_page_token(&token) => Ok(token),
            _ => Err(RemoteError::Protocol(
                "Drive returned no valid changes start token".to_string(),
            )),
        }
    }

    /// One page of changes from `token`, including removals and trashed
    /// files. Changes to shared drives themselves are left out. A change
    /// that is neither removed nor carries file metadata keeps `file`
    /// `None`; the caller reads the file to learn its state.
    pub(crate) fn changes_page(&self, token: &str) -> Result<ChangesPage, RemoteError> {
        if !valid_page_token(token) {
            return Err(RemoteError::Protocol(format!(
                "invalid changes page token {token:?}"
            )));
        }
        let url = self.url("/drive/v3/changes");
        let raw: RawChangesPage = self.run_json("list changes", false, |agent, bearer| {
            agent
                .get(&url)
                .header("Authorization", bearer)
                .query("pageToken", token)
                .query("fields", CHANGE_FIELDS)
                .query("pageSize", "1000")
                .query("includeRemoved", "true")
                .query("spaces", "drive")
                .query("supportsAllDrives", "true")
                .query("includeItemsFromAllDrives", "true")
                .call()
        })?;
        let mut changes = Vec::with_capacity(raw.changes.len());
        for change in raw.changes {
            if change
                .change_type
                .as_deref()
                .is_some_and(|kind| kind != "file")
            {
                continue;
            }
            let file_id = change.file_id.unwrap_or_default();
            require_id(&file_id)?;
            let file = if change.removed { None } else { change.file };
            if let Some(file) = &file
                && file.id != file_id
            {
                return Err(RemoteError::Protocol(format!(
                    "change for {file_id} carries the metadata of {}",
                    file.id
                )));
            }
            changes.push(Change {
                file_id,
                removed: change.removed,
                file,
            });
        }
        let valid = |token: &Option<String>| token.as_deref().is_none_or(valid_page_token);
        if !valid(&raw.next_page_token)
            || !valid(&raw.new_start_page_token)
            || raw.next_page_token.is_some() == raw.new_start_page_token.is_some()
        {
            return Err(RemoteError::Protocol(
                "changes page has no single valid continuation token".to_string(),
            ));
        }
        Ok(ChangesPage {
            changes,
            next_page_token: raw.next_page_token,
            new_start_page_token: raw.new_start_page_token,
        })
    }

    /// Moves a file or folder to the Drive bin, where it stays recoverable
    /// for 30 days. Encrypted replication never removes anything; plain
    /// sync mirrors a local deletion with it.
    pub(crate) fn trash(&self, id: &str) -> Result<DriveFile, RemoteError> {
        require_id(id)?;
        let url = self.url(&format!("/drive/v3/files/{id}"));
        let body = br#"{"trashed":true}"#;
        self.run_json("move to the bin", true, |agent, bearer| {
            agent
                .patch(&url)
                .header("Authorization", bearer)
                .header("Content-Type", "application/json; charset=UTF-8")
                .query("fields", FILE_FIELDS)
                .query("supportsAllDrives", "true")
                .send(&body[..])
        })
    }

    /// Resolves `path` (slash-separated folder names) below `parent`,
    /// creating missing folders when asked. Duplicate names are refused.
    pub(crate) fn resolve_folder_path(
        &self,
        parent: &str,
        path: &str,
        create: bool,
    ) -> Result<DriveFile, RemoteError> {
        let mut current = self.folder(parent)?;
        if !current.is_folder() {
            return Err(RemoteError::Conflict(format!(
                "{} is not a folder",
                current.name
            )));
        }
        for component in path.split('/').filter(|component| !component.is_empty()) {
            if component == "." || component == ".." {
                return Err(RemoteError::Protocol(format!(
                    "unsupported path component {component:?}"
                )));
            }
            let mut matches: Vec<DriveFile> = self
                .list(&current.id, true)?
                .into_iter()
                .filter(|child| child.name == component)
                .collect();
            current = match matches.len() {
                0 if create => {
                    let id = self.generate_ids(1)?.remove(0);
                    self.create_folder(&current.id, component, &id)?
                }
                0 => {
                    return Err(RemoteError::NotFound(format!(
                        "folder {component:?} does not exist"
                    )));
                }
                1 => matches.remove(0),
                _ => {
                    return Err(RemoteError::Conflict(format!(
                        "{} folders are named {component:?}; rename or pass --folder-id",
                        matches.len()
                    )));
                }
            };
        }
        Ok(current)
    }
}

/// A `multipart/related` body of JSON metadata and media, with its
/// content type.
fn multipart_body(metadata: &[u8], bytes: &[u8]) -> (Vec<u8>, String) {
    let mut boundary_bytes = [0u8; 16];
    crate::crypto::fill_random(&mut boundary_bytes);
    let boundary = format!("zdrive-{}", hex(&boundary_bytes));
    let mut body = Vec::with_capacity(bytes.len() + metadata.len() + 256);
    body.extend_from_slice(
        format!("--{boundary}\r\nContent-Type: application/json; charset=UTF-8\r\n\r\n").as_bytes(),
    );
    body.extend_from_slice(metadata);
    body.extend_from_slice(
        format!("\r\n--{boundary}\r\nContent-Type: application/octet-stream\r\n\r\n").as_bytes(),
    );
    body.extend_from_slice(bytes);
    body.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());
    (body, format!("multipart/related; boundary={boundary}"))
}

fn copy_counting(reader: &mut dyn Read, writer: &mut File) -> (u64, Option<std::io::Error>) {
    let mut buffer = vec![0u8; 1 << 20];
    let mut total = 0u64;
    loop {
        match reader.read(&mut buffer) {
            Ok(0) => return (total, None),
            Ok(read) => {
                if let Err(error) = writer.write_all(&buffer[..read]) {
                    return (total, Some(error));
                }
                total += read as u64;
            }
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
            Err(error) => return (total, Some(error)),
        }
    }
}

/// Queues the transient failures Drive answers under load for the next
/// listings: throttling, an unavailable backend and a dropped connection.
#[cfg(test)]
pub(crate) fn fault_listings(fake: &super::fake::FakeDrive) {
    use super::fake::{Fault, Op};
    fake.fault(Op::List, Fault::Status(429, "rateLimitExceeded"));
    fake.fault(Op::List, Fault::Status(503, "backendError"));
    fake.fault(Op::List, Fault::Drop);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pacer_admits_a_burst_then_keeps_the_sustained_interval() {
        let interval = Duration::from_millis(100);
        let now = Instant::now();
        let mut slot = now;
        let starts: Vec<Duration> = (0..6)
            .map(|_| Pacer::admit(&mut slot, now, interval, 4) - now)
            .collect();
        let ms = Duration::from_millis;
        assert_eq!(starts, [ms(0), ms(0), ms(0), ms(0), ms(100), ms(200)]);
        // After an idle second the full burst is available again.
        let later = now + Duration::from_secs(2);
        assert_eq!(Pacer::admit(&mut slot, later, interval, 4), later);

        let mut strict = now;
        let starts: Vec<Duration> = (0..3)
            .map(|_| Pacer::admit(&mut strict, now, interval, 1) - now)
            .collect();
        assert_eq!(starts, [ms(0), ms(100), ms(200)]);
    }

    #[test]
    fn origin_compares_scheme_host_and_port_only() {
        assert_eq!(
            origin("https://www.googleapis.com/upload/x?y=1"),
            Some("https://www.googleapis.com")
        );
        assert_eq!(
            origin("http://127.0.0.1:8080"),
            Some("http://127.0.0.1:8080")
        );
        assert_eq!(
            origin("http://127.0.0.1:8080?x"),
            Some("http://127.0.0.1:8080")
        );
        assert_eq!(origin("https:///x"), None);
        assert_eq!(origin("no-scheme"), None);
    }

    use crate::remote::fake::{FakeDrive, Fault, Op, ROOT_ID, ROOT_REAL_ID};

    fn pattern(len: usize) -> Vec<u8> {
        (0..len)
            .map(|index| (index * 31 + index / 7) as u8)
            .collect()
    }

    fn temp_file(bytes: &[u8]) -> (crate::remote::TestDir, std::path::PathBuf) {
        let dir = crate::remote::TestDir::new("upload");
        let path = dir.path().join("payload");
        std::fs::write(&path, bytes).unwrap();
        (dir, path)
    }

    #[test]
    fn small_files_round_trip_with_verified_md5() {
        let fake = FakeDrive::start();
        let drive = fake.client();
        let id = drive.generate_ids(1).unwrap().remove(0);
        let bytes = pattern(1000);
        let created = drive
            .create_small(ROOT_ID, "a.bin", &id, &bytes, &BTreeMap::new())
            .unwrap();
        assert_eq!(created.size(), Some(1000));
        assert_eq!(drive.read_range(&id, 10, 20).unwrap(), bytes[10..30]);
        assert_eq!(drive.read_small(&created, 1000).unwrap(), bytes);
        assert!(matches!(
            drive.read_small(&created, 999),
            Err(RemoteError::Integrity(_))
        ));
        let listed = drive.list(ROOT_ID, false).unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].md5(), Some(crate::remote::md5_bytes(&bytes)));
        let account = drive.about().unwrap();
        assert_eq!(account.email, "tester@example.com");
        assert_eq!(account.usage, Some(1000));
    }

    #[test]
    fn marked_folders_are_created_once_joined_by_marker_and_never_split() {
        let fake = FakeDrive::start();
        let drive = fake.client();
        // An unmarked folder of the same name is not ours to join.
        fake.insert(ROOT_ID, "ZeroTrust Drive", Some(FOLDER_MIME), b"");
        let (created, fresh) = drive
            .find_or_create_marked_folder(STORE_MARKER, "ZeroTrust Drive")
            .unwrap();
        assert!(fresh);
        let stored = fake.file(&created.id).unwrap();
        assert_eq!(stored.parents, [ROOT_REAL_ID]);
        assert_eq!(stored.mime, FOLDER_MIME);
        assert_eq!(
            stored.app_properties.get(MARKER_KEY).map(String::as_str),
            Some(STORE_MARKER)
        );

        // A second install joins the same folder, even after a rename, and
        // the other mode's marker stays separate.
        let (joined, fresh) = drive
            .find_or_create_marked_folder(STORE_MARKER, "Renamed")
            .unwrap();
        assert!(!fresh);
        assert_eq!(joined.id, created.id);
        let (plain, fresh) = drive
            .find_or_create_marked_folder(PLAIN_MARKER, "ZeroTrust Drive (plain)")
            .unwrap();
        assert!(fresh);
        assert_ne!(plain.id, created.id);

        // Two marked folders are refused rather than guessed between.
        let props = BTreeMap::from([(MARKER_KEY.to_string(), STORE_MARKER.to_string())]);
        let second = drive.generate_ids(1).unwrap().remove(0);
        drive
            .create_folder_with(MY_DRIVE, "Other", &second, &props)
            .unwrap();
        let error = drive
            .find_or_create_marked_folder(STORE_MARKER, "ZeroTrust Drive")
            .unwrap_err();
        assert!(matches!(error, RemoteError::Conflict(_)), "{error}");
        assert!(error.to_string().contains(&created.id), "{error}");
        assert!(error.to_string().contains(&second), "{error}");

        // Markers never reach the query unescaped.
        assert!(matches!(
            drive.find_marked_folders("x' or name contains '"),
            Err(RemoteError::Protocol(_))
        ));
    }

    #[test]
    fn ambiguous_create_reconciles_the_committed_file_once() {
        let fake = FakeDrive::start();
        let drive = fake.client();
        let id = drive.generate_ids(1).unwrap().remove(0);
        fake.fault(Op::Multipart, Fault::CommitThenDrop);
        let created = drive
            .create_small(ROOT_ID, "a.bin", &id, b"payload", &BTreeMap::new())
            .unwrap();
        assert_eq!(created.id, id);
        assert_eq!(fake.files().len(), 1);
        assert_eq!(fake.count(Op::Multipart), 2);
        assert_eq!(fake.count(Op::Get), 1);
        let other = drive.create_small(ROOT_ID, "a.bin", &id, b"different", &BTreeMap::new());
        assert!(matches!(other, Err(RemoteError::Conflict(_))));
    }

    #[test]
    fn a_hidden_my_drive_still_resolves_paths_and_reconciles_creates() {
        let fake = FakeDrive::start();
        fake.hide_my_drive_root(true);
        let drive = fake.client();
        assert!(matches!(drive.get(MY_DRIVE), Err(RemoteError::NotFound(_))));
        let root = drive.folder(MY_DRIVE).unwrap();
        assert_eq!((root.id.as_str(), root.is_folder()), (MY_DRIVE, true));
        // Only the alias is answered locally; other ids stay real lookups.
        assert!(matches!(
            drive.folder(ROOT_REAL_ID),
            Err(RemoteError::NotFound(_))
        ));
        assert!(matches!(
            drive.folder("missing"),
            Err(RemoteError::NotFound(_))
        ));

        let nested = drive
            .resolve_folder_path(MY_DRIVE, "tests/enc", true)
            .unwrap();
        let found = drive
            .resolve_folder_path(MY_DRIVE, "/tests/enc/", false)
            .unwrap();
        assert_eq!(found.id, nested.id);

        // An uncertain create in My Drive reconciles to the committed folder.
        let creates = fake.count(Op::CreateFolder);
        fake.fault(Op::CreateFolder, Fault::CommitThenDrop);
        let (created, fresh) = drive
            .find_or_create_marked_folder(STORE_MARKER, "ZeroTrust Drive")
            .unwrap();
        assert!(fresh);
        assert_eq!(fake.file(&created.id).unwrap().parents, [ROOT_REAL_ID]);
        assert_eq!(fake.count(Op::CreateFolder), creates + 2);

        // The same id committed elsewhere is still a conflict, not My Drive.
        let id = drive.generate_ids(1).unwrap().remove(0);
        drive.create_folder(&nested.id, "x", &id).unwrap();
        assert!(matches!(
            drive.create_folder(MY_DRIVE, "x", &id),
            Err(RemoteError::Conflict(_))
        ));
    }

    #[test]
    fn throttling_and_server_errors_are_retried_but_quota_is_not() {
        let fake = FakeDrive::start();
        let drive = fake.client();
        fake.fault(Op::List, Fault::Status(429, "rateLimitExceeded"));
        fake.fault(Op::List, Fault::Status(403, "userRateLimitExceeded"));
        fake.fault(Op::List, Fault::Status(503, "backendError"));
        fake.fault(Op::List, Fault::Drop);
        assert!(drive.list(ROOT_ID, false).unwrap().is_empty());
        assert_eq!(fake.count(Op::List), 5);
        fake.set_quota(Some(4));
        let id = drive.generate_ids(1).unwrap().remove(0);
        let result = drive.create_small(ROOT_ID, "big", &id, b"12345", &BTreeMap::new());
        assert!(matches!(result, Err(RemoteError::Quota(_))), "{result:?}");
        assert_eq!(fake.count(Op::Multipart), 1);
        fake.fault(Op::Get, Fault::Status(403, "insufficientPermissions"));
        assert!(matches!(drive.get(ROOT_ID), Err(RemoteError::Protocol(_))));
        assert!(matches!(
            drive.get("missing"),
            Err(RemoteError::NotFound(_))
        ));
    }

    #[test]
    fn retries_stop_after_the_attempt_budget() {
        let fake = FakeDrive::start();
        let drive = fake.client();
        for _ in 0..FakeDrive::fast_policy().attempts {
            fake.fault(Op::List, Fault::Status(500, "backendError"));
        }
        assert!(matches!(
            drive.list(ROOT_ID, false),
            Err(RemoteError::Network(_))
        ));
        assert_eq!(fake.pending_faults(), 0);
    }

    #[test]
    fn a_revoked_token_is_refreshed_once() {
        let fake = FakeDrive::start();
        let drive = fake.client();
        drive.list(ROOT_ID, false).unwrap();
        fake.revoke_tokens();
        drive.list(ROOT_ID, false).unwrap();
        assert_eq!(fake.count(Op::List), 3);
    }

    #[test]
    fn listing_follows_every_page() {
        let fake = FakeDrive::start();
        for index in 0..5 {
            fake.insert(ROOT_ID, &format!("f{index}"), None, b"x");
        }
        fake.set_page_size(2);
        let drive = fake.client();
        assert_eq!(drive.list(ROOT_ID, false).unwrap().len(), 5);
        assert_eq!(fake.count(Op::List), 3);
    }

    #[test]
    fn resumable_upload_survives_partial_and_lost_chunks() {
        let fake = FakeDrive::start();
        let drive = fake.client().with_upload_sizes(1024, 256 << 10);
        let bytes = pattern((1 << 20) + 17);
        let (_dir, path) = temp_file(&bytes);
        fake.fault(Op::Chunk, Fault::PartialChunk(1000));
        fake.fault(Op::Chunk, Fault::Drop);
        fake.fault(Op::Chunk, Fault::CommitThenDrop);
        fake.fault(Op::Chunk, Fault::Status(503, "backendError"));
        let mut checkpoint = UploadCheckpoint {
            file_id: drive.generate_ids(1).unwrap().remove(0),
            session_uri: None,
        };
        let mut persisted = Vec::new();
        let created = drive
            .upload_file(
                ROOT_ID,
                "big.zpk",
                &path,
                &mut checkpoint,
                &mut |checkpoint| {
                    persisted.push(checkpoint.clone());
                    Ok(())
                },
            )
            .unwrap();
        assert_eq!(created.size(), Some(bytes.len() as u64));
        assert_eq!(fake.file(&checkpoint.file_id).unwrap().content, bytes);
        assert_eq!(persisted.len(), 1);
        assert!(persisted[0].session_uri.is_some());
        assert_eq!(fake.count(Op::StartSession), 1);
        assert_eq!(fake.pending_faults(), 0);
    }

    #[test]
    fn a_persisted_session_resumes_after_the_process_gave_up() {
        let fake = FakeDrive::start();
        let drive = fake.client().with_upload_sizes(1024, 256 << 10);
        let bytes = pattern(3 * (256 << 10) + 5);
        let (_dir, path) = temp_file(&bytes);
        let mut checkpoint = UploadCheckpoint {
            file_id: drive.generate_ids(1).unwrap().remove(0),
            session_uri: None,
        };
        // Let one chunk land, then fail every attempt of the second.
        fake.fault(Op::Chunk, Fault::PartialChunk(usize::MAX));
        for _ in 0..FakeDrive::fast_policy().attempts {
            fake.fault(Op::Chunk, Fault::Drop);
        }
        let first = drive.upload_file(ROOT_ID, "big.zpk", &path, &mut checkpoint, &mut |_| Ok(()));
        assert!(matches!(first, Err(RemoteError::Network(_))), "{first:?}");
        assert!(fake.file(&checkpoint.file_id).is_none());
        let saved = checkpoint.clone();
        let mut resumed = saved.clone();
        let restarted = fake.client().with_upload_sizes(1024, 256 << 10);
        restarted
            .upload_file(ROOT_ID, "big.zpk", &path, &mut resumed, &mut |_| Ok(()))
            .unwrap();
        assert_eq!(resumed, saved);
        assert_eq!(fake.count(Op::StartSession), 1);
        assert_eq!(fake.file(&checkpoint.file_id).unwrap().content, bytes);
    }

    #[test]
    fn an_expired_session_restarts_under_the_same_id() {
        let fake = FakeDrive::start();
        let drive = fake.client().with_upload_sizes(1024, 256 << 10);
        let bytes = pattern((256 << 10) * 2 + 1);
        let (_dir, path) = temp_file(&bytes);
        fake.fault(Op::Chunk, Fault::PartialChunk(usize::MAX));
        fake.fault(Op::Chunk, Fault::ExpireSession);
        let mut checkpoint = UploadCheckpoint {
            file_id: drive.generate_ids(1).unwrap().remove(0),
            session_uri: None,
        };
        drive
            .upload_file(ROOT_ID, "big.zpk", &path, &mut checkpoint, &mut |_| Ok(()))
            .unwrap();
        assert_eq!(fake.count(Op::StartSession), 2);
        assert_eq!(fake.file(&checkpoint.file_id).unwrap().content, bytes);
        // A completed id is reconciled, not uploaded again.
        let mut again = UploadCheckpoint {
            file_id: checkpoint.file_id.clone(),
            session_uri: None,
        };
        drive
            .upload_file(ROOT_ID, "big.zpk", &path, &mut again, &mut |_| Ok(()))
            .unwrap();
        assert_eq!(fake.count(Op::StartSession), 3);
        assert_eq!(fake.files().len(), 1);
    }

    #[test]
    fn a_cross_origin_session_location_is_refused() {
        let fake = FakeDrive::start();
        fake.use_foreign_session_location(true);
        let drive = fake.client().with_upload_sizes(1024, 256 << 10);
        let (_dir, path) = temp_file(&pattern(4096));
        let mut checkpoint = UploadCheckpoint {
            file_id: drive.generate_ids(1).unwrap().remove(0),
            session_uri: None,
        };
        let result = drive.upload_file(ROOT_ID, "x", &path, &mut checkpoint, &mut |_| Ok(()));
        assert!(
            matches!(result, Err(RemoteError::Protocol(_))),
            "{result:?}"
        );
        assert!(checkpoint.session_uri.is_none());
    }

    #[test]
    fn missing_checksums_in_a_create_response_are_fetched() {
        let fake = FakeDrive::start();
        fake.omit_checksums_on_create(true);
        let drive = fake.client();
        let id = drive.generate_ids(1).unwrap().remove(0);
        let created = drive
            .create_small(ROOT_ID, "a", &id, b"abc", &BTreeMap::new())
            .unwrap();
        assert_eq!(created.size(), Some(3));
        assert_eq!(fake.count(Op::Get), 1);
    }

    #[test]
    fn downloads_resume_truncated_bodies_and_reject_corruption() {
        let fake = FakeDrive::start();
        let bytes = pattern(300_000);
        let id = fake.insert(ROOT_ID, "pack", None, &bytes);
        let drive = fake.client();
        let file = drive.get(&id).unwrap();
        let dir = crate::remote::TestDir::new("download");
        let dest = dir.path().join("pack.partial");
        fake.fault(Op::Media, Fault::TruncateBody(1000));
        fake.fault(Op::Media, Fault::Drop);
        drive.download_to(&file, &dest).unwrap();
        assert_eq!(std::fs::read(&dest).unwrap(), bytes);
        assert_eq!(fake.count(Op::Media), 3);
        std::fs::remove_file(&dest).unwrap();
        fake.fault(Op::Media, Fault::CorruptBody);
        assert!(matches!(
            drive.download_to(&file, &dest),
            Err(RemoteError::Integrity(_))
        ));
        assert!(!dest.exists());
        fake.fault(Op::Media, Fault::TruncateBody(10));
        assert_eq!(drive.read_range(&id, 5, 100).unwrap(), bytes[5..105]);
    }

    #[test]
    fn folder_paths_resolve_create_and_refuse_ambiguity() {
        let fake = FakeDrive::start();
        let drive = fake.client();
        let created = drive.resolve_folder_path(ROOT_ID, "a/b/c", true).unwrap();
        let found = drive
            .resolve_folder_path(ROOT_ID, "/a//b/c/", false)
            .unwrap();
        assert_eq!(created.id, found.id);
        assert!(matches!(
            drive.resolve_folder_path(ROOT_ID, "a/x", false),
            Err(RemoteError::NotFound(_))
        ));
        let a = drive.resolve_folder_path(ROOT_ID, "a", false).unwrap();
        fake.insert(&a.id, "b", Some(FOLDER_MIME), b"");
        assert!(matches!(
            drive.resolve_folder_path(ROOT_ID, "a/b", false),
            Err(RemoteError::Conflict(_))
        ));
        assert!(drive.resolve_folder_path(ROOT_ID, "a/../b", true).is_err());
        let folder_id = drive.generate_ids(1).unwrap().remove(0);
        fake.fault(Op::CreateFolder, Fault::CommitThenDrop);
        drive.create_folder(ROOT_ID, "solo", &folder_id).unwrap();
        assert_eq!(
            fake.children(ROOT_ID)
                .iter()
                .filter(|file| file.name == "solo")
                .count(),
            1
        );
    }

    #[test]
    fn app_properties_are_updated_in_place() {
        let fake = FakeDrive::start();
        let id = fake.insert(ROOT_ID, "lease", None, b"{}");
        let drive = fake.client();
        let props = BTreeMap::from([("heartbeat".to_string(), "42".to_string())]);
        let updated = drive.set_app_properties(&id, &props).unwrap();
        assert_eq!(updated.app_properties, props);
    }

    #[test]
    fn content_updates_keep_the_id_and_verify_the_stored_bytes() {
        let fake = FakeDrive::start();
        let drive = fake.client().with_upload_sizes(1024, 256 << 10);
        let (dir, path) = temp_file(b"first");
        let created = drive.create_file(ROOT_ID, "doc.txt", None, &path).unwrap();
        assert_eq!(fake.file(&created.id).unwrap().content, b"first");
        std::fs::write(&path, b"second version").unwrap();
        let updated = drive.update_content(&created.id, &path).unwrap();
        assert_eq!(updated.id, created.id);
        assert_eq!(updated.size(), Some(14));
        let stored = fake.file(&created.id).unwrap();
        assert_eq!(stored.content, b"second version");
        assert_eq!((stored.name.as_str(), stored.version), ("doc.txt", 2));
        assert_eq!(fake.count(Op::UpdateMedia), 1);

        let large = pattern((1 << 20) + 5);
        std::fs::write(&path, &large).unwrap();
        fake.fault(Op::Chunk, Fault::PartialChunk(700));
        fake.fault(Op::Chunk, Fault::Drop);
        fake.fault(Op::Chunk, Fault::ExpireSession);
        let updated = drive.update_content(&created.id, &path).unwrap();
        assert_eq!(updated.size(), Some(large.len() as u64));
        assert_eq!(fake.file(&created.id).unwrap().content, large);
        assert_eq!(fake.count(Op::UpdateSession), 2);
        assert_eq!(fake.files().len(), 1);
        assert!(matches!(
            drive.update_content("missing-id", &path),
            Err(RemoteError::NotFound(_))
        ));
        std::os::unix::fs::symlink(&path, dir.path().join("link")).unwrap();
        assert!(
            drive
                .update_content(&created.id, &dir.path().join("link"))
                .is_err()
        );
        assert_eq!(fake.file(&created.id).unwrap().content, large);
    }

    #[test]
    fn creates_under_a_pregenerated_id_are_idempotent() {
        let fake = FakeDrive::start();
        let drive = fake.client().with_upload_sizes(1024, 256 << 10);
        let (_dir, path) = temp_file(b"payload");
        let id = drive.generate_ids(1).unwrap().remove(0);
        fake.fault(Op::Multipart, Fault::CommitThenDrop);
        let created = drive
            .create_file(ROOT_ID, "a.txt", Some(&id), &path)
            .unwrap();
        assert_eq!(created.id, id);
        let again = drive
            .create_file(ROOT_ID, "a.txt", Some(&id), &path)
            .unwrap();
        assert_eq!(again.id, id);
        assert_eq!(fake.files().len(), 1);

        let large = pattern((1 << 20) + 9);
        std::fs::write(&path, &large).unwrap();
        let id = drive.generate_ids(1).unwrap().remove(0);
        fake.fault(Op::Chunk, Fault::CommitThenDrop);
        let created = drive
            .create_file(ROOT_ID, "b.bin", Some(&id), &path)
            .unwrap();
        assert_eq!(fake.file(&created.id).unwrap().content, large);
        let again = drive
            .create_file(ROOT_ID, "b.bin", Some(&id), &path)
            .unwrap();
        assert_eq!(again.id, id);
        std::fs::write(&path, b"other").unwrap();
        assert!(matches!(
            drive.create_file(ROOT_ID, "b.bin", Some(&id), &path),
            Err(RemoteError::Conflict(_))
        ));
        assert_eq!(fake.files().len(), 2);
    }

    #[test]
    fn a_source_changed_mid_upload_never_completes_the_upload() {
        let fake = FakeDrive::start();
        let drive = fake.client().with_upload_sizes(1024, 256 << 10);
        let (_dir, path) = temp_file(b"old");
        let created = drive
            .create_file(ROOT_ID, "moving.bin", None, &path)
            .unwrap();
        let first = pattern(1 << 20);
        std::fs::write(&path, &first).unwrap();
        fake.hold(crate::remote::fake::Hold {
            op: Op::Chunk,
            suffix: "moving.bin",
            skip: 1,
            commit: false,
        });
        let result = std::thread::scope(|scope| {
            let upload = scope.spawn(|| drive.update_content(&created.id, &path));
            let deadline = Instant::now() + Duration::from_secs(20);
            while fake.held() == 0 && Instant::now() < deadline {
                std::thread::sleep(Duration::from_millis(10));
            }
            assert_eq!(fake.held(), 1);
            let mut changed = first.clone();
            changed[(1 << 20) - 1] ^= 0xff;
            std::thread::sleep(Duration::from_millis(20));
            std::fs::write(&path, &changed).unwrap();
            fake.release_held();
            upload.join().unwrap()
        });
        assert!(
            matches!(&result, Err(RemoteError::Local(message)) if message.contains("changed while uploading")),
            "{result:?}"
        );
        assert_eq!(fake.file(&created.id).unwrap().content, b"old");
    }

    #[test]
    fn metadata_updates_rename_and_move_but_never_into_a_descendant() {
        let fake = FakeDrive::start();
        let drive = fake.client();
        let a = fake.insert(ROOT_ID, "a", Some(FOLDER_MIME), b"");
        let b = fake.insert(&a, "b", Some(FOLDER_MIME), b"");
        let file = fake.insert(&a, "f.txt", None, b"x");
        let moved = drive
            .update_metadata(&file, Some("g.txt"), Some(&b), Some(&a))
            .unwrap();
        assert_eq!(moved.name, "g.txt");
        assert_eq!(moved.parents, vec![b.clone()]);
        let renamed = drive
            .update_metadata(&file, Some("h.txt"), None, None)
            .unwrap();
        assert_eq!(
            (renamed.name.as_str(), renamed.parents.clone()),
            ("h.txt", vec![b.clone()])
        );
        assert!(
            drive
                .update_metadata(&a, None, Some(&b), Some(ROOT_ID))
                .is_err()
        );
        assert!(drive.update_metadata(&file, Some(""), None, None).is_err());
        assert_eq!(
            fake.file(&a).unwrap().parents,
            vec![ROOT_REAL_ID.to_string()]
        );
    }

    #[test]
    fn the_changes_feed_pages_through_every_change_once_per_file() {
        let fake = FakeDrive::start();
        let drive = fake.client();
        let start = drive.changes_start_token().unwrap();
        let folder = fake.insert(ROOT_ID, "dir", Some(FOLDER_MIME), b"");
        let kept = fake.insert(&folder, "kept.txt", None, b"1");
        fake.update_foreign(&kept, b"22");
        fake.rename_foreign(&kept, "renamed.txt");
        let binned = fake.insert(&folder, "binned.txt", None, b"3");
        let (_dir, path) = temp_file(b"4");
        let doomed = drive
            .create_file(&folder, "doomed.txt", None, &path)
            .unwrap();
        drive.trash(&binned).unwrap();
        fake.delete_foreign(&doomed.id);
        fake.set_page_size(2);
        let mut token = start;
        let mut changes = Vec::new();
        let next_start = loop {
            let page = drive.changes_page(&token).unwrap();
            assert!(page.changes.len() <= 2);
            changes.extend(page.changes);
            match (page.next_page_token, page.new_start_page_token) {
                (Some(next), None) => token = next,
                (None, Some(start)) => break start,
                other => panic!("bad continuation {other:?}"),
            }
        };
        let ids: Vec<&str> = changes
            .iter()
            .map(|change| change.file_id.as_str())
            .collect();
        assert_eq!(
            ids,
            vec![
                folder.as_str(),
                kept.as_str(),
                binned.as_str(),
                doomed.id.as_str()
            ]
        );
        let kept_change = changes[1].file.as_ref().unwrap();
        assert_eq!(kept_change.name, "renamed.txt");
        assert_eq!(kept_change.size(), Some(2));
        assert_eq!(kept_change.version.as_deref(), Some("3"));
        assert!(kept_change.modified_time.is_some());
        assert!(changes[2].file.as_ref().unwrap().trashed);
        assert!(changes[3].removed && changes[3].file.is_none());
        let names: Vec<String> = drive
            .list(&folder, false)
            .unwrap()
            .into_iter()
            .map(|file| file.name)
            .collect();
        assert_eq!(names, vec!["renamed.txt".to_string()]);
        let idle = drive.changes_page(&next_start).unwrap();
        assert!(idle.changes.is_empty());
        assert_eq!(idle.new_start_page_token, Some(next_start));
        assert!(drive.changes_page("").is_err());
        assert!(drive.changes_page("not a token").is_err());
    }

    #[test]
    fn every_operation_label_has_its_telemetry_class() {
        let source = include_str!("gdrive.rs");
        let code = &source[..source.find("\nmod tests {").expect("test module")];
        let expected = [
            ("read account", RequestClass::About),
            ("read file metadata", RequestClass::Get),
            ("list folder", RequestClass::List),
            ("find marked folders", RequestClass::List),
            ("generate file ids", RequestClass::Other),
            ("create folder", RequestClass::Create),
            ("upload file", RequestClass::Upload),
            ("start resumable upload", RequestClass::Upload),
            ("query resumable upload", RequestClass::Upload),
            ("upload chunk", RequestClass::Upload),
            ("download range", RequestClass::Download),
            ("download file", RequestClass::Download),
            ("update file properties", RequestClass::Update),
            ("update file content", RequestClass::Upload),
            ("update file metadata", RequestClass::Update),
            ("read changes start token", RequestClass::Changes),
            ("list changes", RequestClass::Changes),
            ("move to the bin", RequestClass::Trash),
        ];
        for (label, class) in expected {
            assert!(
                code.contains(&format!("\"{label}\"")),
                "{label:?} is no longer an operation label"
            );
            assert_eq!(request_class(label), class, "{label:?}");
        }
    }

    #[test]
    fn full_jitter_stays_within_the_capped_ceiling() {
        let policy = RetryPolicy::PRODUCTION;
        for attempt in 0..20 {
            assert!(policy.delay(attempt) <= policy.cap);
        }
        assert!(policy.delay(0) <= policy.base);
    }

    #[test]
    fn a_bounded_policy_keeps_the_pacing_and_never_widens_the_budget() {
        let policy = RetryPolicy::PRODUCTION.bounded(3, Duration::from_secs(4));
        assert_eq!(policy.attempts, 3);
        assert_eq!(policy.cap, Duration::from_secs(4));
        assert_eq!(policy.base, RetryPolicy::PRODUCTION.base);
        assert_eq!(
            policy.write_interval,
            RetryPolicy::PRODUCTION.write_interval
        );
        let tighter = policy.bounded(10, Duration::from_secs(64));
        assert_eq!(tighter.attempts, 3);
        assert_eq!(tighter.cap, Duration::from_secs(4));
    }
}
