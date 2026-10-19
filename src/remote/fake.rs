// SPDX-FileCopyrightText: Copyright 2026 Alexander Orlov <info@lifub.com>

//! In-process fake of the Google Drive v3 and OAuth token endpoints that
//! replication uses, with scripted faults. Plain HTTP on 127.0.0.1, one
//! thread per connection, `Connection: close` on every response.

use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use serde_json::{Value, json};

use super::RemoteError;
use super::gdrive::{FOLDER_MIME, GoogleDrive, RetryPolicy, TokenSource};
use super::{hex, md5_bytes};

/// The alias Drive accepts for My Drive's root in file ids, queries,
/// parents and moves.
pub(crate) const ROOT_ID: &str = "root";
/// My Drive's real folder id. As on Drive, `parents` always reports this,
/// never the alias.
pub(crate) const ROOT_REAL_ID: &str = "0AFakeMyDriveRootFolder";

/// The real id behind Drive's `root` alias; any other id is itself.
fn resolve(id: &str) -> &str {
    if id == ROOT_ID { ROOT_REAL_ID } else { id }
}
pub(crate) const REFRESH_TOKEN: &str = "fake-refresh-token";
pub(crate) const AUTH_CODE: &str = "fake-authorization-code";
pub(crate) const DEVICE_CODE: &str = "fake-device-code";
pub(crate) const DEVICE_USER_CODE: &str = "FAKE-USER-CODE";

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
    DeviceCode,
    /// Multipart content update of an existing file.
    UpdateMedia,
    /// Start of a resumable content update of an existing file.
    UpdateSession,
    ChangesStart,
    Changes,
    /// OAuth token revocation.
    Revoke,
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

/// A request the server receives but never answers, so a test can kill
/// its client at exactly that point. Consumed by its first match.
#[derive(Clone, Debug)]
pub(crate) struct Hold {
    pub(crate) op: Op,
    /// Only requests for a file whose name ends with this.
    pub(crate) suffix: &'static str,
    /// Matching requests to answer normally first.
    pub(crate) skip: usize,
    /// Apply the request before withholding the answer.
    pub(crate) commit: bool,
}

#[derive(Clone, Debug)]
pub(crate) struct FakeFile {
    pub(crate) id: String,
    pub(crate) name: String,
    pub(crate) parents: Vec<String>,
    pub(crate) mime: String,
    pub(crate) content: Vec<u8>,
    pub(crate) app_properties: BTreeMap<String, String>,
    /// Explicitly moved to the bin; descendants of a trashed folder are
    /// trashed implicitly.
    pub(crate) trashed: bool,
    /// Bumped by every change, as Drive's `version`.
    pub(crate) version: u64,
    /// Change sequence number of the last change, rendered as
    /// `modifiedTime`.
    pub(crate) modified: u64,
}

struct Session {
    metadata: Value,
    size: u64,
    received: Vec<u8>,
    created: Option<String>,
    /// The file whose content this session replaces, for an update.
    update_of: Option<String>,
}

#[derive(Default)]
struct State {
    files: BTreeMap<String, FakeFile>,
    creation_order: Vec<String>,
    sessions: HashMap<String, Session>,
    faults: VecDeque<(Op, Fault)>,
    hold: Option<Hold>,
    held: usize,
    tokens: HashSet<String>,
    /// [`REFRESH_TOKEN`]'s grant was revoked.
    refresh_revoked: bool,
    counts: HashMap<Op, usize>,
    next_id: u64,
    quota_limit: Option<u64>,
    page_size: Option<usize>,
    omit_checksums: bool,
    foreign_location: bool,
    /// Every API request fails with 503, as during an outage.
    offline: bool,
    /// `files.get` of My Drive's root answers 404, as under `drive.file`.
    root_hidden: bool,
    token_forms: Vec<BTreeMap<String, String>>,
    device_forms: Vec<BTreeMap<String, String>>,
    /// OAuth error codes the next device-code polls answer with.
    device_polls: VecDeque<String>,
    device_expires_in: Option<u64>,
    /// The changes feed: sequence number and file id, in order.
    changes: Vec<(u64, String)>,
    /// Sequence number of the next change; tokens are these numbers.
    next_change: u64,
    /// Bumped by [`FakeDrive::release_held`]; parked requests then close.
    release_epoch: u64,
}

impl State {
    /// Records a change of `id` and returns its sequence number.
    fn log_change(&mut self, id: &str) -> u64 {
        let seq = self.next_change;
        self.next_change += 1;
        self.changes.push((seq, id.to_string()));
        seq
    }

    /// Records a change of an existing file and bumps its version.
    fn touch(&mut self, id: &str) {
        let seq = self.log_change(id);
        if let Some(file) = self.files.get_mut(id) {
            file.version += 1;
            file.modified = seq;
        }
    }

    /// Whether the file or any folder above it is in the bin.
    fn effectively_trashed(&self, file: &FakeFile) -> bool {
        let mut current = file;
        for _ in 0..64 {
            if current.trashed {
                return true;
            }
            let Some(parent) = current
                .parents
                .first()
                .and_then(|parent| self.files.get(parent))
            else {
                return false;
            };
            current = parent;
        }
        false
    }

    /// Whether `id` is `ancestor` or lies below it.
    fn is_within(&self, id: &str, ancestor: &str) -> bool {
        let mut current = id.to_string();
        for _ in 0..64 {
            if current == ancestor {
                return true;
            }
            match self
                .files
                .get(&current)
                .and_then(|file| file.parents.first())
            {
                Some(parent) => current = parent.clone(),
                None => return false,
            }
        }
        false
    }

    fn change_json(&self, id: &str) -> Value {
        match self.files.get(id) {
            Some(file) => json!({
                "kind": "drive#change",
                "changeType": "file",
                "fileId": id,
                "removed": false,
                "file": self.file_json(file),
            }),
            None => json!({
                "kind": "drive#change",
                "changeType": "file",
                "fileId": id,
                "removed": true,
            }),
        }
    }

    fn new_id(&mut self, prefix: &str) -> String {
        self.next_id += 1;
        format!("{prefix}{:012}", self.next_id)
    }

    fn issue_token(&mut self) -> String {
        let token = self.new_id("access-");
        self.tokens.insert(token.clone());
        token
    }

    fn take_hold(&mut self, op: Op, target: Option<&str>, request: &Request) -> Option<Hold> {
        let suffix = self.hold.as_ref().filter(|hold| hold.op == op)?.suffix;
        if !request_name(self, op, target, request).is_some_and(|name| name.ends_with(suffix)) {
            return None;
        }
        let hold = self.hold.as_mut()?;
        if hold.skip > 0 {
            hold.skip -= 1;
            return None;
        }
        self.hold.take()
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
            "trashed": self.effectively_trashed(file),
            "version": file.version.to_string(),
            "modifiedTime": modified_time(file.modified),
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

    /// Replaces the content of an existing file, as a media update.
    fn replace_content(&mut self, id: &str, metadata: &Value, content: Vec<u8>) -> Reply {
        let Some(old) = self.files.get(id).map(|file| file.content.len() as u64) else {
            return Reply::error(404, "notFound", "File not found.");
        };
        if self
            .files
            .get(id)
            .is_some_and(|file| file.mime == FOLDER_MIME)
        {
            return Reply::error(400, "badContent", "A folder has no content.");
        }
        if let Some(limit) = self.quota_limit
            && self.usage() - old + content.len() as u64 > limit
        {
            return Reply::error(
                403,
                "storageQuotaExceeded",
                "The user's Drive storage quota has been exceeded.",
            );
        }
        let stored = self.files.get_mut(id).expect("exists");
        if let Some(name) = metadata.get("name").and_then(Value::as_str) {
            stored.name = name.to_string();
        }
        stored.content = content;
        self.touch(id);
        let file = self.files.get(id).cloned().expect("exists");
        Reply::json(200, &self.file_json(&file))
    }

    /// Applies a metadata update: name, bin state, app properties (a null
    /// value deletes one) and a move through `addParents`/`removeParents`.
    fn patch_metadata(
        &mut self,
        id: &str,
        patch: &Value,
        add: Option<&String>,
        remove: Option<&String>,
    ) -> Reply {
        let Some(file) = self.files.get(id).cloned() else {
            return Reply::error(404, "notFound", "File not found.");
        };
        let mut parents = file.parents.clone();
        for parent in remove
            .into_iter()
            .flat_map(|list| list.split(','))
            .map(resolve)
        {
            if !parents.iter().any(|candidate| candidate == parent) {
                return Reply::error(400, "badRequest", "removeParents names no parent");
            }
            parents.retain(|candidate| candidate != parent);
        }
        for parent in add
            .into_iter()
            .flat_map(|list| list.split(','))
            .map(resolve)
        {
            if !self
                .files
                .get(parent)
                .is_some_and(|folder| folder.mime == FOLDER_MIME)
            {
                return Reply::error(404, "notFound", "File not found.");
            }
            if self.is_within(parent, id) {
                return Reply::error(400, "badRequest", "A folder cannot contain itself.");
            }
            if !parents.iter().any(|candidate| candidate == parent) {
                parents.push(parent.to_string());
            }
        }
        let name = match patch.get("name") {
            None => None,
            Some(Value::String(name)) if !name.is_empty() => Some(name.clone()),
            Some(_) => return Reply::error(400, "badRequest", "Invalid name."),
        };
        let stored = self.files.get_mut(id).expect("exists");
        stored.parents = parents;
        if let Some(name) = name {
            stored.name = name;
        }
        if let Some(trashed) = patch.get("trashed").and_then(Value::as_bool) {
            stored.trashed = trashed;
        }
        if let Some(props) = patch.get("appProperties").and_then(Value::as_object) {
            for (key, value) in props {
                match value.as_str() {
                    Some(value) => {
                        stored.app_properties.insert(key.clone(), value.to_string());
                    }
                    None => {
                        stored.app_properties.remove(key);
                    }
                }
            }
        }
        self.touch(id);
        let file = self.files.get(id).cloned().expect("exists");
        Reply::json(200, &self.file_json(&file))
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
                .filter_map(|parent| parent.as_str().map(|id| resolve(id).to_string()))
                .collect(),
            None => vec![ROOT_REAL_ID.to_string()],
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
        let seq = self.log_change(&id);
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
            trashed: false,
            version: 1,
            modified: seq,
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
            ROOT_REAL_ID.to_string(),
            FakeFile {
                id: ROOT_REAL_ID.to_string(),
                name: "My Drive".to_string(),
                parents: Vec::new(),
                mime: FOLDER_MIME.to_string(),
                content: Vec::new(),
                app_properties: BTreeMap::new(),
                trashed: false,
                version: 1,
                modified: 0,
            },
        );
        state.next_change = 1;
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

    pub(crate) fn hold(&self, hold: Hold) {
        self.lock().hold = Some(hold);
    }

    /// Requests the server has stopped answering.
    pub(crate) fn held(&self) -> usize {
        self.lock().held
    }

    /// Closes every parked request without an answer, as a connection
    /// lost mid-request; the client sees a transport failure.
    pub(crate) fn release_held(&self) {
        self.lock().release_epoch += 1;
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

    pub(crate) fn refresh_revoked(&self) -> bool {
        self.lock().refresh_revoked
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

    /// Emulates `drive.file`: My Drive's root stays usable as a parent and
    /// in queries, but `files.get` of it answers 404.
    pub(crate) fn hide_my_drive_root(&self, hidden: bool) {
        self.lock().root_hidden = hidden;
    }

    pub(crate) fn set_offline(&self, offline: bool) {
        self.lock().offline = offline;
    }

    pub(crate) fn use_foreign_session_location(&self, foreign: bool) {
        self.lock().foreign_location = foreign;
    }

    pub(crate) fn token_forms(&self) -> Vec<BTreeMap<String, String>> {
        self.lock().token_forms.clone()
    }

    pub(crate) fn device_forms(&self) -> Vec<BTreeMap<String, String>> {
        self.lock().device_forms.clone()
    }

    /// Answer the next device-code polls with these OAuth error codes, in
    /// order; later polls are approved.
    pub(crate) fn script_device_polls(&self, errors: &[&str]) {
        self.lock()
            .device_polls
            .extend(errors.iter().map(|error| (*error).to_string()));
    }

    pub(crate) fn set_device_expiry(&self, seconds: u64) {
        self.lock().device_expires_in = Some(seconds);
    }

    pub(crate) fn files(&self) -> Vec<FakeFile> {
        self.lock()
            .files
            .values()
            .filter(|file| file.id != ROOT_REAL_ID)
            .cloned()
            .collect()
    }

    pub(crate) fn file(&self, id: &str) -> Option<FakeFile> {
        self.lock().files.get(resolve(id)).cloned()
    }

    pub(crate) fn children(&self, parent: &str) -> Vec<FakeFile> {
        let parent = resolve(parent);
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
        state.log_change(id);
    }

    /// Deletes a file or folder forever, with everything below it, as
    /// another client emptying the bin would.
    pub(crate) fn delete_foreign(&self, id: &str) {
        let mut state = self.lock();
        let doomed: Vec<String> = state
            .files
            .keys()
            .filter(|candidate| state.is_within(candidate, id))
            .cloned()
            .collect();
        for gone in doomed {
            state.files.remove(&gone);
            state.creation_order.retain(|candidate| *candidate != gone);
            state.log_change(&gone);
        }
    }

    /// Replaces the content of a file as another client would: a new
    /// version and a change in the feed.
    pub(crate) fn update_foreign(&self, id: &str, content: &[u8]) {
        let mut state = self.lock();
        state.files.get_mut(id).expect("file exists").content = content.to_vec();
        state.touch(id);
    }

    /// Renames a file as another client would.
    pub(crate) fn rename_foreign(&self, id: &str, name: &str) {
        let mut state = self.lock();
        state.files.get_mut(id).expect("file exists").name = name.to_string();
        state.touch(id);
    }

    /// Moves a file into the folder `parent` as another client would.
    pub(crate) fn move_foreign(&self, id: &str, parent: &str) {
        let parent = resolve(parent);
        let mut state = self.lock();
        assert!(
            state
                .files
                .get(parent)
                .is_some_and(|folder| folder.mime == FOLDER_MIME),
            "fake move target is not a folder"
        );
        state.files.get_mut(id).expect("file exists").parents = vec![parent.to_string()];
        state.touch(id);
    }

    /// Moves a file or folder to the bin, or restores it, as another
    /// client would. Only the item itself gets a change, as the worst case
    /// for a client that must infer what happened to its descendants.
    pub(crate) fn trash_foreign(&self, id: &str, trashed: bool) {
        let mut state = self.lock();
        state.files.get_mut(id).expect("file exists").trashed = trashed;
        state.touch(id);
    }

    /// The current changes token, as `changes/getStartPageToken` answers.
    pub(crate) fn change_token(&self) -> u64 {
        self.lock().next_change
    }
}

/// A fixed-epoch RFC 3339 rendering of a change sequence number, so later
/// changes have later times.
fn modified_time(seq: u64) -> String {
    let (days, rest) = (seq / 86_400, seq % 86_400);
    format!(
        "2026-01-{:02}T{:02}:{:02}:{:02}.000Z",
        1 + days.min(27),
        rest / 3600,
        rest % 3600 / 60,
        rest % 60
    )
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
    let file_id = |prefix: &str| path.strip_prefix(prefix).map(|id| resolve(id).to_string());
    match request.method.as_str() {
        "POST" if path == "/token" => Some((Op::Token, None)),
        "POST" if path == "/device/code" => Some((Op::DeviceCode, None)),
        "POST" if path == "/revoke" => Some((Op::Revoke, None)),
        "GET" if path == "/drive/v3/about" => Some((Op::About, None)),
        "GET" if path == "/drive/v3/files/generateIds" => Some((Op::GenerateIds, None)),
        "GET" if path == "/drive/v3/files" => Some((Op::List, None)),
        "GET" if path == "/drive/v3/changes/startPageToken" => Some((Op::ChangesStart, None)),
        "GET" if path == "/drive/v3/changes" => Some((Op::Changes, None)),
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
        "PATCH" if path.starts_with("/upload/drive/v3/files/") => {
            let target = file_id("/upload/drive/v3/files/");
            match request.query.get("uploadType").map(String::as_str) {
                Some("multipart") => Some((Op::UpdateMedia, target)),
                Some("resumable") => Some((Op::UpdateSession, target)),
                _ => None,
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
    if !matches!(op, Op::Token | Op::DeviceCode | Op::Revoke) {
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
    if guard.offline && !matches!(op, Op::Token | Op::DeviceCode | Op::Revoke) {
        drop(guard);
        write_reply(
            &mut stream,
            &Reply::error(503, "backendError", "offline"),
            None,
        );
        return;
    }
    if let Some(hold) = guard.take_hold(op, target.as_deref(), &request) {
        if hold.commit {
            handle(&mut guard, op, target.as_deref(), &request, base, None);
        }
        guard.held += 1;
        let epoch = guard.release_epoch;
        drop(guard);
        park(&mut stream, state, epoch);
        return;
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

/// Keeps the connection open without answering until the client goes away
/// or the test releases held requests.
fn park(stream: &mut TcpStream, state: &Mutex<State>, epoch: u64) {
    let _ = stream.set_read_timeout(Some(Duration::from_millis(100)));
    let deadline = Instant::now() + Duration::from_secs(180);
    let mut sink = [0u8; 8192];
    while Instant::now() < deadline {
        let released = state
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
            .release_epoch
            != epoch;
        if released {
            let _ = stream.shutdown(Shutdown::Both);
            return;
        }
        match stream.read(&mut sink) {
            Ok(0) => return,
            Ok(_) => {}
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) => {}
            Err(_) => return,
        }
    }
}

/// The name of the file a request creates, uploads or reads.
fn request_name(state: &State, op: Op, target: Option<&str>, request: &Request) -> Option<String> {
    let metadata = match op {
        Op::Multipart => multipart(request)?.0,
        Op::StartSession | Op::CreateFolder => serde_json::from_slice(&request.body).ok()?,
        Op::Chunk | Op::QuerySession => {
            let session = state.sessions.get(target?)?;
            if let Some(id) = &session.update_of {
                return state.files.get(id).map(|file| file.name.clone());
            }
            session.metadata.clone()
        }
        Op::Get | Op::Media | Op::Patch | Op::UpdateMedia | Op::UpdateSession => {
            return state.files.get(target?).map(|file| file.name.clone());
        }
        _ => return None,
    };
    metadata.get("name")?.as_str().map(str::to_string)
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

fn open_session(
    state: &mut State,
    base: &str,
    metadata: Value,
    size: u64,
    update_of: Option<String>,
) -> Reply {
    let session = state.new_id("session");
    state.sessions.insert(
        session.clone(),
        Session {
            metadata,
            size,
            received: Vec::new(),
            created: None,
            update_of,
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
    if let Some(id) = session.update_of.clone() {
        let reply = state.replace_content(&id, &metadata, content);
        if reply.status == 200
            && let Some(session) = state.sessions.get_mut(session_id)
        {
            session.created = Some(id);
        }
        return reply;
    }
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
            let device = grant == Some("urn:ietf:params:oauth:grant-type:device_code");
            let valid = match grant {
                Some("refresh_token") => {
                    form.get("refresh_token").map(String::as_str) == Some(REFRESH_TOKEN)
                        && !state.refresh_revoked
                }
                Some("authorization_code") => {
                    form.get("code").map(String::as_str) == Some(AUTH_CODE)
                        && form.contains_key("code_verifier")
                }
                _ if device => {
                    if form.get("device_code").map(String::as_str) != Some(DEVICE_CODE) {
                        false
                    } else if let Some(error) = state.device_polls.pop_front() {
                        // The statuses Google answers these codes with.
                        let status = match error.as_str() {
                            "authorization_pending" => 428,
                            "slow_down" | "access_denied" => 403,
                            "invalid_client" => 401,
                            "backendError" => 503,
                            _ => 400,
                        };
                        return Reply::json(status, &json!({ "error": error }));
                    } else {
                        true
                    }
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
                "scope": if device {
                    "https://www.googleapis.com/auth/drive.file"
                } else {
                    "https://www.googleapis.com/auth/drive"
                },
            });
            if grant == Some("authorization_code") || device {
                body["refresh_token"] = json!(REFRESH_TOKEN);
            }
            Reply::json(200, &body)
        }
        Op::Revoke => {
            let form = parse_pairs(&String::from_utf8_lossy(&request.body));
            if form.get("token").map(String::as_str) == Some(REFRESH_TOKEN)
                && !state.refresh_revoked
            {
                // Google ends the whole grant, access tokens included.
                state.refresh_revoked = true;
                state.tokens.clear();
                Reply::json(200, &json!({}))
            } else {
                Reply::json(
                    400,
                    &json!({ "error": "invalid_token", "error_description": "Token expired or revoked" }),
                )
            }
        }
        Op::DeviceCode => {
            let form = parse_pairs(&String::from_utf8_lossy(&request.body));
            state.device_forms.push(form.clone());
            // Device clients may only ask for these Drive scopes.
            let allowed = form.get("scope").is_some_and(|scope| {
                scope.split(' ').all(|scope| {
                    matches!(
                        scope,
                        "https://www.googleapis.com/auth/drive.file"
                            | "https://www.googleapis.com/auth/drive.appdata"
                    )
                })
            });
            if !allowed {
                return Reply::json(400, &json!({ "error": "invalid_scope" }));
            }
            Reply::json(
                200,
                &json!({
                    "device_code": DEVICE_CODE,
                    "user_code": DEVICE_USER_CODE,
                    "verification_url": "https://www.google.com/device",
                    "expires_in": state.device_expires_in.unwrap_or(1800),
                    "interval": 5,
                }),
            )
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
            let marked_suffix = format!(" }} and mimeType = '{FOLDER_MIME}' and trashed = false");
            if let Some(marker) = query
                .strip_prefix("appProperties has { key='zdrive' and value='")
                .and_then(|rest| rest.strip_suffix(marked_suffix.as_str()))
                .and_then(|rest| rest.strip_suffix('\''))
            {
                let matches: Vec<Value> = state
                    .files
                    .values()
                    .filter(|file| file.mime == FOLDER_MIME)
                    .filter(|file| {
                        file.app_properties.get("zdrive").map(String::as_str) == Some(marker)
                    })
                    .map(|file| state.file_json(file))
                    .collect();
                return Reply::json(200, &json!({ "files": matches }));
            }
            let Some((parent, rest)) = query
                .strip_prefix('\'')
                .and_then(|rest| rest.split_once("' in parents and trashed = false"))
            else {
                return Reply::error(400, "invalidQuery", "unsupported query");
            };
            let parent = resolve(parent);
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
                .filter(|file| !state.effectively_trashed(file))
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
            if state.root_hidden && target == Some(ROOT_REAL_ID) {
                return Reply::error(404, "notFound", "File not found: .");
            }
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
                    state.patch_metadata(
                        &file.id,
                        &patch,
                        request.query.get("addParents"),
                        request.query.get("removeParents"),
                    )
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
            open_session(state, base, metadata, size, None)
        }
        Op::UpdateSession => {
            let Some(id) = target.filter(|id| state.files.contains_key(*id)) else {
                return Reply::error(404, "notFound", "File not found.");
            };
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
            open_session(state, base, metadata, size, Some(id.to_string()))
        }
        Op::UpdateMedia => {
            let Some(id) = target else {
                return Reply::error(404, "notFound", "File not found.");
            };
            match multipart(request) {
                Some((metadata, content)) => state.replace_content(id, &metadata, content),
                None => Reply::error(400, "badContent", "malformed multipart body"),
            }
        }
        Op::ChangesStart => Reply::json(
            200,
            &json!({
                "kind": "drive#startPageToken",
                "startPageToken": state.next_change.to_string(),
            }),
        ),
        Op::Changes => {
            let Some(start) = request
                .query
                .get("pageToken")
                .and_then(|token| token.parse::<u64>().ok())
                .filter(|token| (1..=state.next_change).contains(token))
            else {
                return Reply::error(400, "invalidPageToken", "Invalid page token.");
            };
            let requested: usize = request
                .query
                .get("pageSize")
                .and_then(|size| size.parse().ok())
                .unwrap_or(100);
            let page_size = state.page_size.unwrap_or(requested).min(requested).max(1);
            let pending: Vec<(u64, String)> = state
                .changes
                .iter()
                .filter(|(seq, _)| *seq >= start)
                .cloned()
                .collect();
            // Like Drive, one listing reports only the latest change of a file.
            let latest: HashMap<&str, u64> = pending
                .iter()
                .map(|(seq, id)| (id.as_str(), *seq))
                .collect();
            let mut changes = Vec::new();
            let mut next = None;
            for (seq, id) in &pending {
                if latest.get(id.as_str()) != Some(seq) {
                    continue;
                }
                if changes.len() == page_size {
                    next = Some(*seq);
                    break;
                }
                changes.push(state.change_json(id));
            }
            let mut body = json!({ "kind": "drive#changeList", "changes": changes });
            match next {
                Some(seq) => body["nextPageToken"] = json!(seq.to_string()),
                None => body["newStartPageToken"] = json!(state.next_change.to_string()),
            }
            Reply::json(200, &body)
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
