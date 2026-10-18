// SPDX-FileCopyrightText: Copyright 2026 Alexander Orlov <info@lifub.com>

//! In-process fake of the Google Drive v3 and OAuth token endpoints that
//! replication uses, with scripted faults. Plain HTTP on 127.0.0.1, one
//! thread per connection, `Connection: close` on every response.

use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use serde_json::{Value, json};

use super::RemoteError;
use super::gdrive::{FOLDER_MIME, GoogleDrive, RetryPolicy, TokenSource};
use super::{hex, md5_bytes};

pub(crate) const ROOT_ID: &str = "root";
pub(crate) const REFRESH_TOKEN: &str = "fake-refresh-token";
pub(crate) const AUTH_CODE: &str = "fake-authorization-code";

/// Endpoint classes faults and counters refer to.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) enum Op {
    Token,
    About,
    List,
    Get,
    Media,
    GenerateIds,
    CreateFolder,
    Multipart,
    StartSession,
    Chunk,
    QuerySession,
    Patch,
}

/// One scripted failure, consumed by the next request of its [`Op`].
#[derive(Clone, Debug)]
pub(crate) enum Fault {
    /// Answer with this status and Drive error reason; nothing is applied.
    Status(u16, &'static str),
    /// Close the connection without answering; nothing is applied.
    Drop,
    /// Apply the request, then close without answering.
    CommitThenDrop,
    /// Keep only the first bytes of an upload chunk, then close.
    PartialChunk(usize),
    /// Send full headers but only this many body bytes, then close.
    TruncateBody(usize),
    /// Flip the first byte of a media body.
    CorruptBody,
    /// Omit the most recently created file from a listing.
    ListLag,
    /// Forget the resumable session before handling the request.
    ExpireSession,
}

#[derive(Clone, Debug)]
pub(crate) struct FakeFile {
    pub(crate) id: String,
    pub(crate) name: String,
    pub(crate) parents: Vec<String>,
    pub(crate) mime: String,
    pub(crate) content: Vec<u8>,
    pub(crate) app_properties: BTreeMap<String, String>,
}

struct Session {
    metadata: Value,
    size: u64,
    received: Vec<u8>,
    created: Option<String>,
}

#[derive(Default)]
struct State {
    files: BTreeMap<String, FakeFile>,
    creation_order: Vec<String>,
    sessions: HashMap<String, Session>,
    faults: VecDeque<(Op, Fault)>,
    tokens: HashSet<String>,
    counts: HashMap<Op, usize>,
    next_id: u64,
    quota_limit: Option<u64>,
    page_size: Option<usize>,
    omit_checksums: bool,
    foreign_location: bool,
    token_forms: Vec<BTreeMap<String, String>>,
}

impl State {
    fn new_id(&mut self, prefix: &str) -> String {
        self.next_id += 1;
        format!("{prefix}{:012}", self.next_id)
    }

    fn issue_token(&mut self) -> String {
        let token = self.new_id("access-");
        self.tokens.insert(token.clone());
        token
    }

    fn take_fault(&mut self, op: Op) -> Option<Fault> {
        let index = self
            .faults
            .iter()
            .position(|(candidate, _)| *candidate == op)?;
        self.faults.remove(index).map(|(_, fault)| fault)
    }

    fn usage(&self) -> u64 {
        self.files
            .values()
            .map(|file| file.content.len() as u64)
            .sum()
    }

    fn file_json(&self, file: &FakeFile) -> Value {
        let mut value = json!({
            "id": file.id,
            "name": file.name,
            "mimeType": file.mime,
            "parents": file.parents,
        });
        if !file.app_properties.is_empty() {
            value["appProperties"] = json!(file.app_properties);
        }
        if file.mime != FOLDER_MIME {
            value["size"] = json!(file.content.len().to_string());
            value["md5Checksum"] = json!(hex(&md5_bytes(&file.content)));
        }
        value
    }

    fn create(&mut self, metadata: &Value, content: Vec<u8>) -> Reply {
        let id = match metadata.get("id").and_then(Value::as_str) {
            Some(id) => id.to_string(),
            None => self.new_id("auto"),
        };
        if self.files.contains_key(&id) {
            return Reply::error(
                409,
                "duplicate",
                "A file already exists with the provided ID.",
            );
        }
        let parents: Vec<String> = match metadata.get("parents").and_then(Value::as_array) {
            Some(parents) => parents
                .iter()
                .filter_map(|parent| parent.as_str().map(str::to_string))
                .collect(),
            None => vec![ROOT_ID.to_string()],
        };
        for parent in &parents {
            if !self
                .files
                .get(parent)
                .is_some_and(|file| file.mime == FOLDER_MIME)
            {
                return Reply::error(404, "notFound", "File not found.");
            }
        }
        if let Some(limit) = self.quota_limit
            && self.usage() + content.len() as u64 > limit
        {
            return Reply::error(
                403,
                "storageQuotaExceeded",
                "The user's Drive storage quota has been exceeded.",
            );
        }
        let file = FakeFile {
            id: id.clone(),
            name: metadata
                .get("name")
                .and_then(Value::as_str)
                .unwrap_or("Untitled")
                .to_string(),
            parents,
            mime: metadata
                .get("mimeType")
                .and_then(Value::as_str)
                .unwrap_or("application/octet-stream")
                .to_string(),
            content,
            app_properties: metadata
                .get("appProperties")
                .and_then(|props| serde_json::from_value(props.clone()).ok())
                .unwrap_or_default(),
        };
        let mut body = self.file_json(&file);
        if self.omit_checksums
            && let Some(object) = body.as_object_mut()
        {
            object.remove("size");
            object.remove("md5Checksum");
        }
        self.files.insert(id.clone(), file);
        self.creation_order.push(id);
        Reply::json(200, &body)
    }
}

struct Request {
    method: String,
    path: String,
    query: BTreeMap<String, String>,
    headers: BTreeMap<String, String>,
    body: Vec<u8>,
}

struct Reply {
    status: u16,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

impl Reply {
    fn json(status: u16, value: &Value) -> Self {
        Self {
            status,
            headers: vec![(
                "Content-Type".into(),
                "application/json; charset=UTF-8".into(),
            )],
            body: serde_json::to_vec(value).expect("json"),
        }
    }

    fn error(status: u16, reason: &str, message: &str) -> Self {
        Self::json(
            status,
            &json!({ "error": { "code": status, "message": message, "errors": [{ "reason": reason, "message": message }] } }),
        )
    }

    fn empty(status: u16) -> Self {
        Self {
            status,
            headers: Vec::new(),
            body: Vec::new(),
        }
    }
}

/// A running fake server. Dropping it stops accepting connections.
pub(crate) struct FakeDrive {
    base: String,
    state: Arc<Mutex<State>>,
    stop: Arc<AtomicBool>,
}

impl FakeDrive {
    pub(crate) fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind fake drive");
        let base = format!("http://{}", listener.local_addr().expect("local addr"));
        let mut state = State::default();
        state.files.insert(
            ROOT_ID.to_string(),
            FakeFile {
                id: ROOT_ID.to_string(),
                name: "My Drive".to_string(),
                parents: Vec::new(),
                mime: FOLDER_MIME.to_string(),
                content: Vec::new(),
                app_properties: BTreeMap::new(),
            },
        );
        let state = Arc::new(Mutex::new(state));
        let stop = Arc::new(AtomicBool::new(false));
        let (thread_state, thread_stop, thread_base) = (state.clone(), stop.clone(), base.clone());
        std::thread::Builder::new()
            .name("fake-drive".into())
            .spawn(move || {
                for stream in listener.incoming() {
                    if thread_stop.load(Ordering::SeqCst) {
                        break;
                    }
                    let Ok(stream) = stream else { continue };
                    let (state, base) = (thread_state.clone(), thread_base.clone());
                    std::thread::spawn(move || serve(stream, &state, &base));
                }
            })
            .expect("spawn fake drive");
        Self { base, state, stop }
    }

    fn lock(&self) -> MutexGuard<'_, State> {
        self.state
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
    }

    pub(crate) fn base_url(&self) -> &str {
        &self.base
    }

    pub(crate) fn fast_policy() -> RetryPolicy {
        RetryPolicy {
            base: Duration::from_millis(1),
            cap: Duration::from_millis(5),
            attempts: 6,
            min_interval: Duration::ZERO,
            burst: 1,
            write_interval: Duration::ZERO,
        }
    }

    pub(crate) fn tokens(&self) -> Box<dyn TokenSource> {
        Box::new(FakeTokens {
            state: self.state.clone(),
        })
    }

    pub(crate) fn client(&self) -> GoogleDrive {
        GoogleDrive::with_endpoint(&self.base, self.tokens(), Self::fast_policy())
    }

    pub(crate) fn fault(&self, op: Op, fault: Fault) {
        self.lock().faults.push_back((op, fault));
    }

    pub(crate) fn pending_faults(&self) -> usize {
        self.lock().faults.len()
    }

    pub(crate) fn count(&self, op: Op) -> usize {
        self.lock().counts.get(&op).copied().unwrap_or(0)
    }

    pub(crate) fn revoke_tokens(&self) {
        self.lock().tokens.clear();
    }

    pub(crate) fn set_quota(&self, limit: Option<u64>) {
        self.lock().quota_limit = limit;
    }

    pub(crate) fn set_page_size(&self, size: usize) {
        self.lock().page_size = Some(size);
    }

    pub(crate) fn omit_checksums_on_create(&self, omit: bool) {
        self.lock().omit_checksums = omit;
    }

    pub(crate) fn use_foreign_session_location(&self, foreign: bool) {
        self.lock().foreign_location = foreign;
    }

    pub(crate) fn token_forms(&self) -> Vec<BTreeMap<String, String>> {
        self.lock().token_forms.clone()
    }

    pub(crate) fn files(&self) -> Vec<FakeFile> {
        self.lock()
            .files
            .values()
            .filter(|file| file.id != ROOT_ID)
            .cloned()
            .collect()
    }

    pub(crate) fn file(&self, id: &str) -> Option<FakeFile> {
        self.lock().files.get(id).cloned()
    }

    pub(crate) fn children(&self, parent: &str) -> Vec<FakeFile> {
        self.lock()
            .files
            .values()
            .filter(|file| file.parents.iter().any(|candidate| candidate == parent))
            .cloned()
            .collect()
    }

    /// Adds a file as another client would, bypassing faults.
    pub(crate) fn insert(
        &self,
        parent: &str,
        name: &str,
        mime: Option<&str>,
        content: &[u8],
    ) -> String {
        let mut state = self.lock();
        let id = state.new_id("foreign");
        let mut metadata = json!({ "id": id, "name": name, "parents": [parent] });
        if let Some(mime) = mime {
            metadata["mimeType"] = json!(mime);
        }
        let reply = state.create(&metadata, content.to_vec());
        assert_eq!(reply.status, 200, "fake insert failed");
        id
    }

    /// Replaces stored bytes in place, as storage corruption would.
    pub(crate) fn overwrite(&self, id: &str, content: &[u8]) {
        self.lock().files.get_mut(id).expect("file exists").content = content.to_vec();
    }

    pub(crate) fn remove(&self, id: &str) {
        let mut state = self.lock();
        state.files.remove(id);
        state.creation_order.retain(|candidate| candidate != id);
    }
}

impl Drop for FakeDrive {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        let _ = TcpStream::connect(self.base.trim_start_matches("http://"));
    }
}

struct FakeTokens {
    state: Arc<Mutex<State>>,
}

impl TokenSource for FakeTokens {
    fn fetch(&self, _agent: &ureq::Agent) -> Result<(String, Duration), RemoteError> {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        Ok((state.issue_token(), Duration::from_secs(3600)))
    }
}

fn percent_decode(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        let byte = bytes[index];
        if byte == b'+' {
            out.push(b' ');
        } else if byte == b'%'
            && index + 2 < bytes.len()
            && let Ok(decoded) = u8::from_str_radix(&text[index + 1..index + 3], 16)
        {
            out.push(decoded);
            index += 2;
        } else {
            out.push(byte);
        }
        index += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn parse_pairs(text: &str) -> BTreeMap<String, String> {
    text.split('&')
        .filter(|pair| !pair.is_empty())
        .map(|pair| {
            let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
            (percent_decode(key), percent_decode(value))
        })
        .collect()
}

fn read_request(stream: &TcpStream) -> std::io::Result<Request> {
    let mut reader = BufReader::new(stream.try_clone()?);
    let mut line = String::new();
    reader.read_line(&mut line)?;
    let mut parts = line.split_whitespace();
    let method = parts.next().unwrap_or_default().to_string();
    let target = parts.next().unwrap_or_default().to_string();
    let mut headers = BTreeMap::new();
    loop {
        let mut header = String::new();
        if reader.read_line(&mut header)? == 0 || header == "\r\n" || header == "\n" {
            break;
        }
        if let Some((name, value)) = header.split_once(':') {
            headers.insert(name.trim().to_ascii_lowercase(), value.trim().to_string());
        }
    }
    if headers
        .get("expect")
        .is_some_and(|value| value.eq_ignore_ascii_case("100-continue"))
    {
        stream
            .try_clone()?
            .write_all(b"HTTP/1.1 100 Continue\r\n\r\n")?;
    }
    let mut body = Vec::new();
    if headers
        .get("transfer-encoding")
        .is_some_and(|value| value.eq_ignore_ascii_case("chunked"))
    {
        loop {
            let mut size = String::new();
            reader.read_line(&mut size)?;
            let size = usize::from_str_radix(size.trim().split(';').next().unwrap_or("0"), 16)
                .map_err(|_| std::io::Error::other("bad chunk size"))?;
            let mut chunk = vec![0u8; size + 2];
            reader.read_exact(&mut chunk)?;
            if size == 0 {
                break;
            }
            body.extend_from_slice(&chunk[..size]);
        }
    } else if let Some(len) = headers.get("content-length") {
        let len: usize = len
            .parse()
            .map_err(|_| std::io::Error::other("bad length"))?;
        body.resize(len, 0);
        reader.read_exact(&mut body)?;
    }
    let (path, query) = target.split_once('?').unwrap_or((&target, ""));
    Ok(Request {
        method,
        path: path.to_string(),
        query: parse_pairs(query),
        headers,
        body,
    })
}

fn reason(status: u16) -> &'static str {
    match status {
        200 => "OK",
        206 => "Partial Content",
        308 => "Resume Incomplete",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        409 => "Conflict",
        416 => "Range Not Satisfiable",
        429 => "Too Many Requests",
        _ => "Status",
    }
}

fn write_reply(stream: &mut TcpStream, reply: &Reply, body_limit: Option<usize>) {
    let mut head = format!("HTTP/1.1 {} {}\r\n", reply.status, reason(reply.status));
    for (name, value) in &reply.headers {
        head.push_str(&format!("{name}: {value}\r\n"));
    }
    head.push_str(&format!(
        "Content-Length: {}\r\nConnection: close\r\n\r\n",
        reply.body.len()
    ));
    let body = match body_limit {
        Some(limit) => &reply.body[..limit.min(reply.body.len())],
        None => &reply.body[..],
    };
    let _ = stream.write_all(head.as_bytes());
    let _ = stream.write_all(body);
    let _ = stream.flush();
}

fn classify(request: &Request) -> Option<(Op, Option<String>)> {
    let path = request.path.as_str();
    let file_id = |prefix: &str| path.strip_prefix(prefix).map(str::to_string);
    match request.method.as_str() {
        "POST" if path == "/token" => Some((Op::Token, None)),
        "GET" if path == "/drive/v3/about" => Some((Op::About, None)),
        "GET" if path == "/drive/v3/files/generateIds" => Some((Op::GenerateIds, None)),
        "GET" if path == "/drive/v3/files" => Some((Op::List, None)),
        "GET" if request.query.get("alt").is_some_and(|alt| alt == "media") => {
            Some((Op::Media, file_id("/drive/v3/files/")))
        }
        "GET" => Some((Op::Get, file_id("/drive/v3/files/"))),
        "POST" if path == "/drive/v3/files" => Some((Op::CreateFolder, None)),
        "POST" if path == "/upload/drive/v3/files" => {
            match request.query.get("uploadType").map(String::as_str) {
                Some("multipart") => Some((Op::Multipart, None)),
                Some("resumable") => Some((Op::StartSession, None)),
                _ => None,
            }
        }
        "PUT" if path == "/upload/drive/v3/files" => {
            let session = request.query.get("upload_id").cloned();
            if request
                .headers
                .get("content-range")
                .is_some_and(|range| range.starts_with("bytes */"))
            {
                Some((Op::QuerySession, session))
            } else {
                Some((Op::Chunk, session))
            }
        }
        "PATCH" => Some((Op::Patch, file_id("/drive/v3/files/"))),
        _ => None,
    }
}

fn serve(mut stream: TcpStream, state: &Mutex<State>, base: &str) {
    let _ = stream.set_read_timeout(Some(Duration::from_secs(30)));
    let Ok(request) = read_request(&stream) else {
        return;
    };
    let Some((op, target)) = classify(&request) else {
        write_reply(
            &mut stream,
            &Reply::error(400, "badRequest", "unsupported fake route"),
            None,
        );
        return;
    };
    let mut guard = state.lock().unwrap_or_else(|poison| poison.into_inner());
    *guard.counts.entry(op).or_default() += 1;
    if op != Op::Token {
        let authorized = request
            .headers
            .get("authorization")
            .and_then(|value| value.strip_prefix("Bearer "))
            .is_some_and(|token| guard.tokens.contains(token));
        if !authorized {
            drop(guard);
            write_reply(
                &mut stream,
                &Reply::error(401, "authError", "Invalid Credentials"),
                None,
            );
            return;
        }
    }
    let fault = guard.take_fault(op);
    match &fault {
        Some(Fault::Status(status, why)) => {
            drop(guard);
            write_reply(
                &mut stream,
                &Reply::error(*status, why, "scripted fault"),
                None,
            );
            return;
        }
        Some(Fault::Drop) => {
            drop(guard);
            let _ = stream.shutdown(Shutdown::Both);
            return;
        }
        Some(Fault::ExpireSession) => {
            if let Some(session) = &target {
                guard.sessions.remove(session);
            }
        }
        _ => {}
    }
    let chunk_limit = match &fault {
        Some(Fault::PartialChunk(limit)) => Some(*limit),
        _ => None,
    };
    let mut reply = handle(
        &mut guard,
        op,
        target.as_deref(),
        &request,
        base,
        chunk_limit,
    );
    if op == Op::List
        && matches!(fault, Some(Fault::ListLag))
        && let Some(latest) = guard.creation_order.last().cloned()
        && let Ok(mut value) = serde_json::from_slice::<Value>(&reply.body)
        && let Some(files) = value.get_mut("files").and_then(Value::as_array_mut)
    {
        files.retain(|file| file.get("id").and_then(Value::as_str) != Some(latest.as_str()));
        reply = Reply::json(reply.status, &value);
    }
    drop(guard);
    match fault {
        Some(Fault::CommitThenDrop) | Some(Fault::PartialChunk(_)) => {
            let _ = stream.shutdown(Shutdown::Both);
        }
        Some(Fault::TruncateBody(limit)) => {
            write_reply(&mut stream, &reply, Some(limit));
            let _ = stream.shutdown(Shutdown::Both);
        }
        Some(Fault::CorruptBody) => {
            if let Some(first) = reply.body.first_mut() {
                *first ^= 0xff;
            }
            write_reply(&mut stream, &reply, None);
        }
        _ => write_reply(&mut stream, &reply, None),
    }
}

fn parse_range(header: &str, len: u64) -> Option<(u64, u64)> {
    let spec = header.strip_prefix("bytes=")?;
    let (start, end) = spec.split_once('-')?;
    let start: u64 = start.parse().ok()?;
    let last = len.checked_sub(1)?;
    let end = if end.is_empty() {
        last
    } else {
        end.parse::<u64>().ok()?.min(last)
    };
    (start <= end).then_some((start, end))
}

fn multipart(request: &Request) -> Option<(Value, Vec<u8>)> {
    let content_type = request.headers.get("content-type")?;
    let boundary = content_type.split("boundary=").nth(1)?.trim_matches('"');
    let delimiter = format!("--{boundary}");
    let body = &request.body;
    let find = |haystack: &[u8], needle: &[u8], from: usize| {
        haystack
            .get(from..)?
            .windows(needle.len())
            .position(|window| window == needle)
            .map(|position| position + from)
    };
    let mut parts = Vec::new();
    let mut cursor = find(body, delimiter.as_bytes(), 0)? + delimiter.len();
    let closing = format!("\r\n{delimiter}");
    loop {
        if body.get(cursor..)?.starts_with(b"--") {
            break;
        }
        let headers_end = find(body, b"\r\n\r\n", cursor)? + 4;
        let end = find(body, closing.as_bytes(), headers_end)?;
        parts.push(body[headers_end..end].to_vec());
        cursor = end + closing.len();
    }
    if parts.len() != 2 {
        return None;
    }
    let metadata = serde_json::from_slice(&parts[0]).ok()?;
    Some((metadata, parts.remove(1)))
}

fn session_reply(state: &mut State, session_id: &str) -> Reply {
    let Some(session) = state.sessions.get(session_id) else {
        return Reply::error(404, "notFound", "Upload session not found.");
    };
    if let Some(id) = &session.created {
        let file = state.files.get(id).cloned().expect("created file");
        return Reply::json(200, &state.file_json(&file));
    }
    let received = session.received.len() as u64;
    if received < session.size {
        let mut reply = Reply::empty(308);
        if received > 0 {
            reply
                .headers
                .push(("Range".into(), format!("bytes=0-{}", received - 1)));
        }
        return reply;
    }
    let (metadata, content) = (session.metadata.clone(), session.received.clone());
    let reply = state.create(&metadata, content);
    if reply.status == 200
        && let Some(id) = metadata.get("id").and_then(Value::as_str)
        && let Some(session) = state.sessions.get_mut(session_id)
    {
        session.created = Some(id.to_string());
    }
    reply
}

fn handle(
    state: &mut State,
    op: Op,
    target: Option<&str>,
    request: &Request,
    base: &str,
    chunk_limit: Option<usize>,
) -> Reply {
    match op {
        Op::Token => {
            let form = parse_pairs(&String::from_utf8_lossy(&request.body));
            state.token_forms.push(form.clone());
            let grant = form.get("grant_type").map(String::as_str);
            let valid = match grant {
                Some("refresh_token") => {
                    form.get("refresh_token").map(String::as_str) == Some(REFRESH_TOKEN)
                }
                Some("authorization_code") => {
                    form.get("code").map(String::as_str) == Some(AUTH_CODE)
                        && form.contains_key("code_verifier")
                }
                _ => false,
            };
            if !valid {
                return Reply::json(
                    400,
                    &json!({ "error": "invalid_grant", "error_description": "Bad Request" }),
                );
            }
            let mut body = json!({
                "access_token": state.issue_token(),
                "expires_in": 3599,
                "token_type": "Bearer",
                "scope": "https://www.googleapis.com/auth/drive",
            });
            if grant == Some("authorization_code") {
                body["refresh_token"] = json!(REFRESH_TOKEN);
            }
            Reply::json(200, &body)
        }
        Op::About => Reply::json(
            200,
            &json!({
                "user": { "emailAddress": "tester@example.com" },
                "storageQuota": {
                    "limit": state.quota_limit.map(|limit| limit.to_string()),
                    "usage": state.usage().to_string(),
                },
            }),
        ),
        Op::GenerateIds => {
            let count: usize = request
                .query
                .get("count")
                .and_then(|count| count.parse().ok())
                .unwrap_or(10);
            let ids: Vec<String> = (0..count).map(|_| state.new_id("gen")).collect();
            Reply::json(
                200,
                &json!({ "kind": "drive#generatedIds", "space": "drive", "ids": ids }),
            )
        }
        Op::List => {
            let query = request.query.get("q").cloned().unwrap_or_default();
            let Some((parent, rest)) = query
                .strip_prefix('\'')
                .and_then(|rest| rest.split_once("' in parents and trashed = false"))
            else {
                return Reply::error(400, "invalidQuery", "unsupported query");
            };
            let folders_only = match rest {
                "" => false,
                filter if filter == format!(" and mimeType = '{FOLDER_MIME}'") => true,
                _ => return Reply::error(400, "invalidQuery", "unsupported query"),
            };
            let matches: Vec<Value> = state
                .files
                .values()
                .filter(|file| file.parents.iter().any(|candidate| candidate == parent))
                .filter(|file| !folders_only || file.mime == FOLDER_MIME)
                .map(|file| state.file_json(file))
                .collect();
            let requested: usize = request
                .query
                .get("pageSize")
                .and_then(|size| size.parse().ok())
                .unwrap_or(100);
            let page_size = state.page_size.unwrap_or(requested).min(requested).max(1);
            let start: usize = request
                .query
                .get("pageToken")
                .and_then(|token| token.parse().ok())
                .unwrap_or(0);
            let end = (start + page_size).min(matches.len());
            let mut body = json!({ "files": matches[start.min(end)..end] });
            if end < matches.len() {
                body["nextPageToken"] = json!(end.to_string());
            }
            Reply::json(200, &body)
        }
        Op::Get | Op::Media | Op::Patch => {
            let Some(file) = target.and_then(|id| state.files.get(id)).cloned() else {
                return Reply::error(404, "notFound", "File not found.");
            };
            match op {
                Op::Get => Reply::json(200, &state.file_json(&file)),
                Op::Media => match request.headers.get("range") {
                    None => Reply {
                        status: 200,
                        headers: vec![("Content-Type".into(), "application/octet-stream".into())],
                        body: file.content,
                    },
                    Some(range) => match parse_range(range, file.content.len() as u64) {
                        Some((start, end)) => Reply {
                            status: 206,
                            headers: vec![(
                                "Content-Range".into(),
                                format!("bytes {start}-{end}/{}", file.content.len()),
                            )],
                            body: file.content[start as usize..=end as usize].to_vec(),
                        },
                        None => Reply::error(416, "requestedRangeNotSatisfiable", "bad range"),
                    },
                },
                _ => {
                    let Ok(patch) = serde_json::from_slice::<Value>(&request.body) else {
                        return Reply::error(400, "parseError", "bad json");
                    };
                    let props: BTreeMap<String, String> = patch
                        .get("appProperties")
                        .and_then(|props| serde_json::from_value(props.clone()).ok())
                        .unwrap_or_default();
                    let stored = state.files.get_mut(&file.id).expect("exists");
                    stored.app_properties.extend(props);
                    let stored = stored.clone();
                    Reply::json(200, &state.file_json(&stored))
                }
            }
        }
        Op::CreateFolder => match serde_json::from_slice::<Value>(&request.body) {
            Ok(metadata) => state.create(&metadata, Vec::new()),
            Err(_) => Reply::error(400, "parseError", "bad json"),
        },
        Op::Multipart => match multipart(request) {
            Some((metadata, content)) => state.create(&metadata, content),
            None => Reply::error(400, "badContent", "malformed multipart body"),
        },
        Op::StartSession => {
            let Some(size) = request
                .headers
                .get("x-upload-content-length")
                .and_then(|size| size.parse::<u64>().ok())
            else {
                return Reply::error(400, "badRequest", "missing upload length");
            };
            let Ok(metadata) = serde_json::from_slice::<Value>(&request.body) else {
                return Reply::error(400, "parseError", "bad json");
            };
            if metadata
                .get("id")
                .and_then(Value::as_str)
                .is_some_and(|id| state.files.contains_key(id))
            {
                return Reply::error(
                    409,
                    "duplicate",
                    "A file already exists with the provided ID.",
                );
            }
            let session = state.new_id("session");
            state.sessions.insert(
                session.clone(),
                Session {
                    metadata,
                    size,
                    received: Vec::new(),
                    created: None,
                },
            );
            let origin = if state.foreign_location {
                "http://203.0.113.9"
            } else {
                base
            };
            let mut reply = Reply::empty(200);
            reply.headers.push((
                "Location".into(),
                format!("{origin}/upload/drive/v3/files?uploadType=resumable&upload_id={session}"),
            ));
            reply
        }
        Op::QuerySession => match target {
            Some(session) => session_reply(state, session),
            None => Reply::error(404, "notFound", "Upload session not found."),
        },
        Op::Chunk => {
            let Some(session_id) = target else {
                return Reply::error(404, "notFound", "Upload session not found.");
            };
            let Some(session) = state.sessions.get_mut(session_id) else {
                return Reply::error(404, "notFound", "Upload session not found.");
            };
            let range = request
                .headers
                .get("content-range")
                .cloned()
                .unwrap_or_default();
            let parsed = range.strip_prefix("bytes ").and_then(|spec| {
                let (span, total) = spec.split_once('/')?;
                let (start, end) = span.split_once('-')?;
                Some((
                    start.parse::<u64>().ok()?,
                    end.parse::<u64>().ok()?,
                    total.parse::<u64>().ok()?,
                ))
            });
            let Some((start, end, total)) = parsed else {
                return Reply::error(400, "badRequest", "bad Content-Range");
            };
            let received = session.received.len() as u64;
            if total != session.size
                || start > received
                || end < start
                || end - start + 1 != request.body.len() as u64
                || end >= total
            {
                return Reply::error(
                    400,
                    "badRequest",
                    "Content-Range does not match the session",
                );
            }
            let skip = ((received - start) as usize).min(request.body.len());
            let mut body = &request.body[skip..];
            if let Some(limit) = chunk_limit {
                body = &body[..limit.min(body.len())];
            }
            session.received.extend_from_slice(body);
            session_reply(state, session_id)
        }
    }
}

#[test]
fn percent_decoding_handles_escapes_and_plus() {
    assert_eq!(percent_decode("a%20b+c%27"), "a b c'");
    assert_eq!(percent_decode("100%"), "100%");
    assert_eq!(percent_decode("%4"), "%4");
}
