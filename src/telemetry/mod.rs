// SPDX-FileCopyrightText: Copyright 2026 Alexander Orlov <info@lifub.com>

//! Local-only telemetry: lifecycle records, periodic metric snapshots,
//! errors and remote summaries, appended as JSONL below
//! `$XDG_STATE_HOME/zerotrust-drive/telemetry/<instance>/`. Nothing is
//! ever sent anywhere; `zdrive telemetry export` packs the files for a
//! user who chooses to share them.
//!
//! Privacy is enforced by the API shape: every name, tag and key is a
//! `&'static str` from this code base and every value a number or bool,
//! so no file name, path, content, credential or address can reach a
//! record. The one free-form input, a panic message, is recorded only at
//! [`Level::Full`] and only after [`redact_panic_message`].
//!
//! Recording never blocks the caller: FUSE and request metrics are
//! atomics, records go through a bounded queue whose overflow is counted,
//! and one background thread owns the files.

mod cli;
mod histogram;
mod metrics;
mod report;
mod system;
mod tar;
mod writer;

pub(crate) use cli::{TelemetryCommand, human_bytes, run, stored_bytes};
pub(crate) use system::kernel_release;

use std::cell::Cell;
use std::path::Path;
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::mpsc::{Receiver, SyncSender, TrySendError, sync_channel};
use std::sync::{Arc, Mutex, Once, OnceLock, PoisonError, RwLock};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use serde_json::{Map, Value};

use metrics::Metrics;
use writer::{Message, Writer};

/// Environment variable overriding the configured level.
pub(crate) const ENV_VAR: &str = "ZDRIVE_TELEMETRY";
/// Level configuration below the config directory.
pub(crate) const CONFIG_FILE: &str = "telemetry.json";
/// Telemetry root below the state directory.
pub(crate) const DIR_NAME: &str = "telemetry";
pub(crate) const DEFAULT_INSTANCE: &str = "zdrive";
pub(crate) const SCHEMA: u64 = 1;
pub(crate) const RETENTION_DAYS: i64 = 30;
const SLOW_OP: Duration = Duration::from_millis(250);
const QUEUE_CAPACITY: usize = 1024;
const STOP_WAIT: Duration = Duration::from_secs(2);
const PANIC_FLUSH_WAIT: Duration = Duration::from_millis(500);
const WRITER_THREAD: &str = "zdrive-telemetry";
const MAX_PANIC_MESSAGE: usize = 200;

/// How much is collected.
#[derive(
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    clap::ValueEnum,
    serde::Serialize,
    serde::Deserialize,
)]
#[serde(rename_all = "lowercase")]
pub(crate) enum Level {
    /// Write nothing; existing data is kept until `purge`.
    Off,
    /// Lifecycle, minute snapshots, errors, sync and remote summaries.
    Standard,
    /// Adds 10-second snapshots, slow operations, every remote request,
    /// step events and redacted panic messages.
    Full,
}

impl Level {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Off => "off",
            Self::Standard => "standard",
            Self::Full => "full",
        }
    }

    /// Case-insensitive `off`, `standard` or `full`.
    pub(crate) fn parse(text: &str) -> Option<Self> {
        match text.trim().to_ascii_lowercase().as_str() {
            "off" => Some(Self::Off),
            "standard" => Some(Self::Standard),
            "full" => Some(Self::Full),
            _ => None,
        }
    }

    fn from_u8(value: u8) -> Self {
        match value {
            1 => Self::Standard,
            2 => Self::Full,
            _ => Self::Off,
        }
    }

    pub(crate) fn snapshot_interval(self) -> Duration {
        match self {
            Self::Full => Duration::from_secs(10),
            Self::Off | Self::Standard => Duration::from_secs(60),
        }
    }

    /// Total bytes kept per instance.
    pub(crate) fn cap_bytes(self) -> u64 {
        match self {
            Self::Full => 256 << 20,
            Self::Off | Self::Standard => 64 << 20,
        }
    }
}

const VALID_LEVELS: &str = "off, standard or full";

/// Where the effective level came from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum LevelSource {
    Cli,
    Env,
    Config,
    Default,
}

impl LevelSource {
    pub(crate) fn describe(self) -> &'static str {
        match self {
            Self::Cli => "command-line flag --telemetry",
            Self::Env => "environment variable ZDRIVE_TELEMETRY",
            Self::Config => "config file",
            Self::Default => "default",
        }
    }
}

#[derive(serde::Serialize, serde::Deserialize)]
struct ConfigFile {
    level: String,
}

/// The configured level in `config_dir/telemetry.json`, if any.
pub(crate) fn config_level(config_dir: &Path) -> Result<Option<Level>, String> {
    let path = config_dir.join(CONFIG_FILE);
    let Some(bytes) =
        crate::remote::read_private_file(&path, 4096).map_err(|error| error.to_string())?
    else {
        return Ok(None);
    };
    let config: ConfigFile = serde_json::from_slice(&bytes).map_err(|error| {
        format!(
            "{}: {error}; expected {{\"level\":\"standard\"}}",
            path.display()
        )
    })?;
    Level::parse(&config.level).map(Some).ok_or_else(|| {
        format!(
            "{}: invalid telemetry level {:?}; valid levels are {VALID_LEVELS}",
            path.display(),
            truncate(&config.level, 32)
        )
    })
}

/// Writes `config_dir/telemetry.json` (0600 in a 0700 directory).
pub(crate) fn save_config_level(config_dir: &Path, level: Level) -> Result<(), String> {
    crate::remote::ensure_private_dir(config_dir).map_err(|error| error.to_string())?;
    let mut bytes = serde_json::to_vec(&ConfigFile {
        level: level.as_str().to_string(),
    })
    .map_err(|error| error.to_string())?;
    bytes.push(b'\n');
    crate::remote::write_private_file(&config_dir.join(CONFIG_FILE), &bytes)
        .map_err(|error| error.to_string())
}

/// The effective level: CLI flag, then `ZDRIVE_TELEMETRY`, then the
/// config file, then [`Level::Standard`]. An empty environment value
/// counts as unset; an invalid one is an error naming the valid levels.
pub(crate) fn resolve_level(
    cli: Option<Level>,
    env: Option<&str>,
    config_dir: &Path,
) -> Result<(Level, LevelSource), String> {
    if let Some(level) = cli {
        return Ok((level, LevelSource::Cli));
    }
    if let Some(value) = env.filter(|value| !value.trim().is_empty()) {
        return Level::parse(value)
            .map(|level| (level, LevelSource::Env))
            .ok_or_else(|| {
                format!(
                    "invalid {ENV_VAR} value {:?}; valid levels are {VALID_LEVELS}",
                    truncate(value, 32)
                )
            });
    }
    Ok(match config_level(config_dir)? {
        Some(level) => (level, LevelSource::Config),
        None => (Level::Standard, LevelSource::Default),
    })
}

/// Instance names follow the remote-name rule `[a-z0-9][a-z0-9_-]{0,62}`.
pub(crate) fn validate_instance(name: &str) -> Result<(), String> {
    let bytes = name.as_bytes();
    let valid = !bytes.is_empty()
        && bytes.len() <= 63
        && (bytes[0].is_ascii_lowercase() || bytes[0].is_ascii_digit())
        && bytes
            .iter()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || b"_-".contains(byte));
    if valid {
        Ok(())
    } else {
        Err(format!(
            "invalid telemetry instance {:?}; use 1-63 characters from a-z, 0-9, '_' and '-', \
             starting with a letter or digit",
            truncate(name, 64)
        ))
    }
}

fn truncate(text: &str, max_chars: usize) -> String {
    text.chars().take(max_chars).collect()
}

/// What a process announces when it starts collecting.
#[derive(Clone, Debug)]
pub(crate) struct Start {
    pub instance: String,
    pub level: Level,
    /// `"mount"`, `"plain"`, `"remote"` or `"maintenance"`.
    pub mode: &'static str,
    /// `"none"` or `"google-drive"`.
    pub remote_kind: &'static str,
    pub service: bool,
}

/// FUSE operations implemented by `ZeroTrustFs`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum FuseOp {
    Init,
    Destroy,
    Lookup,
    Getattr,
    Setattr,
    Open,
    Read,
    Write,
    Flush,
    Release,
    Fsync,
    Mknod,
    Create,
    Mkdir,
    Unlink,
    Rmdir,
    Rename,
    Readdir,
    Fsyncdir,
    Statfs,
    Access,
    Other,
}

impl FuseOp {
    pub(crate) const ALL: [Self; 22] = [
        Self::Init,
        Self::Destroy,
        Self::Lookup,
        Self::Getattr,
        Self::Setattr,
        Self::Open,
        Self::Read,
        Self::Write,
        Self::Flush,
        Self::Release,
        Self::Fsync,
        Self::Mknod,
        Self::Create,
        Self::Mkdir,
        Self::Unlink,
        Self::Rmdir,
        Self::Rename,
        Self::Readdir,
        Self::Fsyncdir,
        Self::Statfs,
        Self::Access,
        Self::Other,
    ];

    pub(crate) fn name(self) -> &'static str {
        match self {
            Self::Init => "init",
            Self::Destroy => "destroy",
            Self::Lookup => "lookup",
            Self::Getattr => "getattr",
            Self::Setattr => "setattr",
            Self::Open => "open",
            Self::Read => "read",
            Self::Write => "write",
            Self::Flush => "flush",
            Self::Release => "release",
            Self::Fsync => "fsync",
            Self::Mknod => "mknod",
            Self::Create => "create",
            Self::Mkdir => "mkdir",
            Self::Unlink => "unlink",
            Self::Rmdir => "rmdir",
            Self::Rename => "rename",
            Self::Readdir => "readdir",
            Self::Fsyncdir => "fsyncdir",
            Self::Statfs => "statfs",
            Self::Access => "access",
            Self::Other => "other",
        }
    }
}

/// Remote provider request kinds.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum RequestClass {
    About,
    Get,
    List,
    Create,
    Upload,
    Download,
    Update,
    Trash,
    Changes,
    Token,
    Other,
}

impl RequestClass {
    pub(crate) const ALL: [Self; 11] = [
        Self::About,
        Self::Get,
        Self::List,
        Self::Create,
        Self::Upload,
        Self::Download,
        Self::Update,
        Self::Trash,
        Self::Changes,
        Self::Token,
        Self::Other,
    ];

    pub(crate) fn name(self) -> &'static str {
        match self {
            Self::About => "about",
            Self::Get => "get",
            Self::List => "list",
            Self::Create => "create",
            Self::Upload => "upload",
            Self::Download => "download",
            Self::Update => "update",
            Self::Trash => "trash",
            Self::Changes => "changes",
            Self::Token => "token",
            Self::Other => "other",
        }
    }
}

/// An event field value. Strings are limited to `&'static str` tags.
#[derive(Clone, Copy, Debug, PartialEq)]
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) enum Field {
    U64(u64),
    I64(i64),
    F64(f64),
    Bool(bool),
    Tag(&'static str),
}

impl Field {
    fn to_value(self) -> Value {
        match self {
            Self::U64(value) => value.into(),
            Self::I64(value) => value.into(),
            // Non-finite values have no JSON form and become null.
            Self::F64(value) => {
                serde_json::Number::from_f64(value).map_or(Value::Null, Value::Number)
            }
            Self::Bool(value) => value.into(),
            Self::Tag(value) => value.into(),
        }
    }
}

/// One JSONL record; the header keys `schema`, `v`, `ts` and `kind` come
/// first in every line.
pub(crate) struct Record {
    pub(crate) kind: &'static str,
    pub(crate) ts: u64,
    pub(crate) body: Map<String, Value>,
}

impl Record {
    pub(crate) fn new(kind: &'static str) -> Self {
        Self::at(kind, system::now_ms())
    }

    pub(crate) fn at(kind: &'static str, ts: u64) -> Self {
        Self {
            kind,
            ts,
            body: Map::new(),
        }
    }

    pub(crate) fn with(mut self, key: &'static str, value: impl Into<Value>) -> Self {
        self.body.insert(key.to_string(), value.into());
        self
    }

    pub(crate) fn line(&self) -> String {
        let mut line = format!(
            "{{\"schema\":{SCHEMA},\"v\":\"{}\",\"ts\":{},\"kind\":\"{}\"",
            env!("CARGO_PKG_VERSION"),
            self.ts,
            self.kind
        );
        for (key, value) in &self.body {
            if matches!(key.as_str(), "schema" | "v" | "ts" | "kind") {
                continue;
            }
            line.push(',');
            line.push_str(&Value::String(key.clone()).to_string());
            line.push(':');
            line.push_str(&value.to_string());
        }
        line.push('}');
        line
    }
}

/// Writer tuning; [`Options::for_level`] is what production uses.
#[derive(Clone, Debug)]
pub(crate) struct Options {
    pub(crate) cap_bytes: u64,
    pub(crate) retention_days: i64,
    pub(crate) tick: Duration,
    pub(crate) queue_capacity: usize,
    /// Leave the writer unstarted until [`Telemetry::resume`] (tests).
    pub(crate) paused: bool,
}

impl Options {
    pub(crate) fn for_level(level: Level) -> Self {
        Self {
            cap_bytes: level.cap_bytes(),
            retention_days: RETENTION_DAYS,
            tick: level.snapshot_interval(),
            queue_capacity: QUEUE_CAPACITY,
            paused: false,
        }
    }
}

pub(crate) struct Shared {
    level: AtomicU8,
    pub(crate) metrics: Metrics,
}

struct Runtime {
    thread: Option<JoinHandle<()>>,
    #[cfg_attr(not(test), allow(dead_code))]
    paused: Option<(Writer, Receiver<Message>, Record)>,
}

/// One telemetry session. Production uses the process-global instance
/// behind the free functions; tests create their own against a temp dir.
pub(crate) struct Telemetry {
    shared: Arc<Shared>,
    sender: RwLock<Option<SyncSender<Message>>>,
    runtime: Mutex<Option<Runtime>>,
}

impl Telemetry {
    pub(crate) fn new() -> Self {
        Self {
            shared: Arc::new(Shared {
                level: AtomicU8::new(Level::Off as u8),
                metrics: Metrics::new(),
            }),
            sender: RwLock::new(None),
            runtime: Mutex::new(None),
        }
    }

    pub(crate) fn level(&self) -> Level {
        Level::from_u8(self.shared.level.load(Ordering::Relaxed))
    }

    pub(crate) fn start(&self, start: Start, state_dir: &Path) -> Result<(), String> {
        let options = Options::for_level(start.level);
        self.start_with(start, state_dir, options)
    }

    /// Starts the writer thread; a no-op while already started or for
    /// [`Level::Off`]. The directory is created lazily by the writer, so a
    /// broken one shows up as counted write errors, not as a start error.
    pub(crate) fn start_with(
        &self,
        start: Start,
        state_dir: &Path,
        options: Options,
    ) -> Result<(), String> {
        validate_instance(&start.instance)?;
        let mut runtime = self.runtime.lock().unwrap_or_else(PoisonError::into_inner);
        if runtime.is_some() || start.level == Level::Off {
            return Ok(());
        }
        self.shared.metrics.reset();
        let dir = state_dir.join(DIR_NAME).join(&start.instance);
        let (sender, receiver) = sync_channel(options.queue_capacity.max(1));
        let first = start_record(&start);
        let paused = options.paused;
        let writer = Writer::new(dir, Arc::clone(&self.shared), options, start.level);
        let next = if paused {
            Runtime {
                thread: None,
                paused: Some((writer, receiver, first)),
            }
        } else {
            Runtime {
                thread: Some(spawn_writer(writer, receiver, first)?),
                paused: None,
            }
        };
        *self.sender.write().unwrap_or_else(PoisonError::into_inner) = Some(sender);
        self.shared
            .level
            .store(start.level as u8, Ordering::Relaxed);
        *runtime = Some(next);
        Ok(())
    }

    /// Starts a writer created with [`Options::paused`].
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn resume(&self) -> Result<(), String> {
        let mut runtime = self.runtime.lock().unwrap_or_else(PoisonError::into_inner);
        let Some(runtime) = runtime.as_mut() else {
            return Ok(());
        };
        if let Some((writer, receiver, first)) = runtime.paused.take() {
            runtime.thread = Some(spawn_writer(writer, receiver, first)?);
        }
        Ok(())
    }

    /// Writes the final snapshot and the stop record, then waits at most
    /// two seconds for the writer.
    pub(crate) fn stop(&self, reason: &'static str, exit_code: i32) {
        self.shared.level.store(Level::Off as u8, Ordering::Relaxed);
        let sender = self
            .sender
            .write()
            .unwrap_or_else(PoisonError::into_inner)
            .take();
        let runtime = self
            .runtime
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take();
        let (Some(sender), Some(runtime)) = (sender, runtime) else {
            return;
        };
        let Some(thread) = runtime.thread else {
            return;
        };
        let deadline = Instant::now() + STOP_WAIT;
        let (done, finished) = sync_channel(1);
        let message = Message::Stop {
            reason,
            exit_code,
            done,
        };
        if send_until(&sender, message, deadline) {
            drop(sender);
            if finished
                .recv_timeout(deadline.saturating_duration_since(Instant::now()))
                .is_ok()
            {
                let _ = thread.join();
            }
        }
    }

    /// Waits up to two seconds until everything queued so far is on disk.
    pub(crate) fn flush(&self) {
        self.request(Message::Flush, STOP_WAIT, false);
    }

    /// Writes a snapshot now and waits for it (tests and diagnostics).
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn snapshot(&self) {
        self.request(Message::Snapshot, STOP_WAIT, false);
    }

    fn request(&self, message: fn(SyncSender<()>) -> Message, wait: Duration, nonblocking: bool) {
        if self.level() == Level::Off {
            return;
        }
        let sender = if nonblocking {
            match self.sender.try_read() {
                Ok(guard) => guard.clone(),
                Err(_) => return,
            }
        } else {
            self.sender
                .read()
                .unwrap_or_else(PoisonError::into_inner)
                .clone()
        };
        let Some(sender) = sender else {
            return;
        };
        let deadline = Instant::now() + wait;
        let (ack, acked) = sync_channel(1);
        if send_until(&sender, message(ack), deadline) {
            let _ = acked.recv_timeout(deadline.saturating_duration_since(Instant::now()));
        }
    }

    fn send(&self, record: Record) {
        let guard = self.sender.read().unwrap_or_else(PoisonError::into_inner);
        self.enqueue(guard.as_ref(), record);
    }

    fn enqueue(&self, sender: Option<&SyncSender<Message>>, record: Record) {
        let Some(sender) = sender else {
            return;
        };
        let message = Message::Line {
            ts: record.ts,
            text: record.line(),
        };
        if let Err(TrySendError::Full(_) | TrySendError::Disconnected(_)) = sender.try_send(message)
        {
            self.shared.metrics.drops.fetch_add(1, Ordering::Relaxed);
        }
    }

    pub(crate) fn fuse_op(&self, op: FuseOp, elapsed: Duration, errno: Option<i32>, bytes: u64) {
        let level = self.level();
        if level == Level::Off {
            return;
        }
        let micros = micros(elapsed);
        self.shared.metrics.fuse(op, micros, errno, bytes);
        if level == Level::Full && elapsed > SLOW_OP {
            self.send(
                Record::new("slow_op")
                    .with("op", op.name())
                    .with("elapsed_us", micros)
                    .with("errno", errno.map_or(Value::Null, errno_value)),
            );
        }
    }

    pub(crate) fn remote_request(
        &self,
        class: RequestClass,
        status: Option<u16>,
        elapsed: Duration,
        attempt: u32,
    ) {
        let level = self.level();
        if level == Level::Off {
            return;
        }
        let micros = micros(elapsed);
        self.shared.metrics.remote(class, status, micros);
        if level == Level::Full {
            self.send(
                Record::new("request")
                    .with("class", class.name())
                    .with("status", status.map_or(Value::Null, Value::from))
                    .with("elapsed_us", micros)
                    .with("attempt", attempt),
            );
        }
    }

    pub(crate) fn retry(&self, class: RequestClass, reason: &'static str, backoff: Duration) {
        let level = self.level();
        if level == Level::Off {
            return;
        }
        let backoff_ms = u64::try_from(backoff.as_millis()).unwrap_or(u64::MAX);
        self.shared.metrics.retry(class, reason, backoff_ms);
        if level == Level::Full {
            self.event(
                Level::Full,
                "remote.retry",
                &[
                    ("class", Field::Tag(class.name())),
                    ("reason", Field::Tag(reason)),
                    ("backoff_ms", Field::U64(backoff_ms)),
                ],
            );
        }
    }

    pub(crate) fn event(&self, min: Level, name: &'static str, fields: &[(&'static str, Field)]) {
        let level = self.level();
        if level == Level::Off || level < min {
            return;
        }
        let fields: Map<String, Value> = fields
            .iter()
            .map(|(key, value)| ((*key).to_string(), value.to_value()))
            .collect();
        self.send(
            Record::new("event")
                .with("name", name)
                .with("fields", Value::Object(fields)),
        );
    }

    pub(crate) fn duration(&self, name: &'static str, elapsed: Duration) {
        if self.level() != Level::Off {
            self.shared.metrics.duration(name, micros(elapsed));
        }
    }

    pub(crate) fn counter(&self, name: &'static str, delta: u64) {
        if self.level() != Level::Off {
            self.shared.metrics.counter(name, delta);
        }
    }

    /// Records a panic without ever blocking on a lock the panicking
    /// thread might hold.
    fn record_panic(&self, location: Option<String>, message: Option<&str>) {
        let level = self.level();
        if level == Level::Off {
            return;
        }
        let current = std::thread::current();
        let thread_name = current.name();
        let mut record = Record::new("panic")
            .with(
                "location",
                location.unwrap_or_else(|| "unknown".to_string()),
            )
            .with("thread", thread_label(thread_name))
            .with("pid", std::process::id());
        if level == Level::Full
            && let Some(message) = message
        {
            record = record.with("message", redact_panic_message(message));
        }
        if let Ok(guard) = self.sender.try_read() {
            self.enqueue(guard.as_ref(), record);
        } else {
            self.shared.metrics.drops.fetch_add(1, Ordering::Relaxed);
        }
        if thread_name != Some(WRITER_THREAD) {
            self.request(Message::Flush, PANIC_FLUSH_WAIT, true);
        }
    }
}

fn spawn_writer(
    writer: Writer,
    receiver: Receiver<Message>,
    first: Record,
) -> Result<JoinHandle<()>, String> {
    std::thread::Builder::new()
        .name(WRITER_THREAD.to_string())
        .spawn(move || writer.run(receiver, first))
        .map_err(|error| format!("start the telemetry writer: {error}"))
}

/// Tries to queue `message` until `deadline`; `false` when it could not.
fn send_until(sender: &SyncSender<Message>, mut message: Message, deadline: Instant) -> bool {
    loop {
        match sender.try_send(message) {
            Ok(()) => return true,
            Err(TrySendError::Disconnected(_)) => return false,
            Err(TrySendError::Full(returned)) => {
                if Instant::now() >= deadline {
                    return false;
                }
                message = returned;
                std::thread::sleep(Duration::from_millis(2));
            }
        }
    }
}

fn micros(elapsed: Duration) -> u64 {
    u64::try_from(elapsed.as_micros()).unwrap_or(u64::MAX)
}

fn errno_value(code: i32) -> Value {
    match system::errno_name(code) {
        Some(name) => name.into(),
        None => code.into(),
    }
}

fn start_record(start: &Start) -> Record {
    Record::new("start")
        .with("version", env!("CARGO_PKG_VERSION"))
        .with("os", std::env::consts::OS)
        .with("arch", std::env::consts::ARCH)
        .with("kernel", system::kernel_release())
        .with("fuse", system::fuse_flavour())
        .with("instance", start.instance.as_str())
        .with("mode", start.mode)
        .with("remote_kind", start.remote_kind)
        .with("level", start.level.as_str())
        .with("service", start.service)
        .with("pid", std::process::id())
}

/// Thread names are reported only when they are known `zdrive-*` names.
fn thread_label(name: Option<&str>) -> &'static str {
    match name {
        Some("main") => "main",
        Some("zdrive-telemetry") => "zdrive-telemetry",
        Some("zdrive-replicator") => "zdrive-replicator",
        Some("zdrive-signals") => "zdrive-signals",
        Some("zdrive-oauth-redirect") => "zdrive-oauth-redirect",
        Some(name) if name.starts_with("zdrive-") => "zdrive-other",
        _ => "other",
    }
}

/// Source location of a panic. Absolute paths (dependencies, the standard
/// library) keep only their last three components so no home directory or
/// user name is recorded.
fn panic_location(file: &str, line: u32, column: u32) -> String {
    let file = if file.starts_with('/') || file.contains('\\') {
        let parts: Vec<&str> = file
            .split(['/', '\\'])
            .filter(|part| !part.is_empty())
            .collect();
        parts[parts.len().saturating_sub(3)..].join("/")
    } else {
        file.to_string()
    };
    format!("{file}:{line}:{column}")
}

/// Redacts a panic message before it is recorded:
/// double-quoted segments become `"<str>"`; any whitespace-separated token
/// containing `/` or `\` becomes `<path>`, one containing `@` becomes
/// `<email>`, and a dotted name such as `report.pdf` becomes `<name>`;
/// the result is truncated to 200 characters.
pub(crate) fn redact_panic_message(message: &str) -> String {
    let mut unquoted = String::with_capacity(message.len());
    let mut in_quote = false;
    for ch in message.chars() {
        if ch == '"' {
            if in_quote {
                unquoted.push_str("<str>\"");
            } else {
                unquoted.push('"');
            }
            in_quote = !in_quote;
        } else if !in_quote {
            unquoted.push(ch);
        }
    }
    if in_quote {
        unquoted.push_str("<str>");
    }
    let tokens: Vec<String> = unquoted
        .split_whitespace()
        .map(|token| {
            if token.contains(['/', '\\']) {
                "<path>".to_string()
            } else if token.contains('@') {
                "<email>".to_string()
            } else if dotted_name(token) {
                "<name>".to_string()
            } else {
                token.to_string()
            }
        })
        .collect();
    truncate(&tokens.join(" "), MAX_PANIC_MESSAGE)
}

/// A token like `name.ext` or `host.example`: an interior dot between
/// alphanumerics that is not part of a number such as `1.5` or `0.18.0`.
fn dotted_name(token: &str) -> bool {
    let core = token.trim_matches(|ch: char| !ch.is_alphanumeric());
    let bytes = core.as_bytes();
    let has_interior_dot = bytes.windows(3).any(|window| {
        window[1] == b'.' && window[0].is_ascii_alphanumeric() && window[2].is_ascii_alphanumeric()
    });
    has_interior_dot
        && !core
            .bytes()
            .all(|byte| byte.is_ascii_digit() || byte == b'.')
}

// Process-global session behind the free functions. `LEVEL` mirrors the
// global session's level so a disabled call costs one relaxed load.
static LEVEL: AtomicU8 = AtomicU8::new(0);
static GLOBAL: OnceLock<Telemetry> = OnceLock::new();

fn global() -> Option<&'static Telemetry> {
    if LEVEL.load(Ordering::Relaxed) == Level::Off as u8 {
        return None;
    }
    GLOBAL.get()
}

/// The process-wide level: one relaxed atomic load; `Off` until [`start`].
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) fn level() -> Level {
    Level::from_u8(LEVEL.load(Ordering::Relaxed))
}

/// Starts process-wide collection. Idempotent. An error leaves telemetry
/// off; the caller is expected to continue without it.
pub(crate) fn start(start: Start, state_dir: &Path) -> Result<(), String> {
    let telemetry = GLOBAL.get_or_init(Telemetry::new);
    telemetry.start(start, state_dir)?;
    LEVEL.store(telemetry.level() as u8, Ordering::Relaxed);
    Ok(())
}

/// Writes the final snapshot and the stop record and waits at most two
/// seconds for them to reach the disk.
pub(crate) fn stop(reason: &'static str, exit_code: i32) {
    LEVEL.store(Level::Off as u8, Ordering::Relaxed);
    if let Some(telemetry) = GLOBAL.get() {
        telemetry.stop(reason, exit_code);
    }
}

/// Records one FUSE operation. Hot path: atomics only (plus one queued
/// record for a slow operation at [`Level::Full`]).
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) fn fuse_op(op: FuseOp, elapsed: Duration, errno: Option<i32>) {
    if let Some(telemetry) = global() {
        telemetry.fuse_op(op, elapsed, errno, 0);
    }
}

/// Records one remote request attempt; `status: None` is a transport error.
pub(crate) fn remote_request(
    class: RequestClass,
    status: Option<u16>,
    elapsed: Duration,
    attempt: u32,
) {
    if let Some(telemetry) = global() {
        telemetry.remote_request(class, status, elapsed, attempt);
    }
}

/// Records one backoff before a retry, e.g. reason `"rate_limit"`,
/// `"server"`, `"network"` or `"auth"`.
pub(crate) fn retry(class: RequestClass, reason: &'static str, backoff: Duration) {
    if let Some(telemetry) = global() {
        telemetry.retry(class, reason, backoff);
    }
}

/// Emits an `event` record when the level is at least `min`.
pub(crate) fn event(min: Level, name: &'static str, fields: &[(&'static str, Field)]) {
    if let Some(telemetry) = global() {
        telemetry.event(min, name, fields);
    }
}

/// Adds a sample to the named log2 histogram, e.g. `"v2.commit"`.
pub(crate) fn duration(name: &'static str, elapsed: Duration) {
    if let Some(telemetry) = global() {
        telemetry.duration(name, elapsed);
    }
}

/// Adds `delta` to the named counter.
pub(crate) fn counter(name: &'static str, delta: u64) {
    if let Some(telemetry) = global() {
        telemetry.counter(name, delta);
    }
}

/// Records panics, then runs the previously installed hook. Installs once.
pub(crate) fn install_panic_hook() {
    static INSTALL: Once = Once::new();
    INSTALL.call_once(|| {
        let previous = std::panic::take_hook();
        std::panic::set_hook(Box::new(move |info| {
            if let Some(telemetry) = global() {
                let location = info.location().map(|location| {
                    panic_location(location.file(), location.line(), location.column())
                });
                let payload = info.payload();
                let message = payload
                    .downcast_ref::<&str>()
                    .copied()
                    .or_else(|| payload.downcast_ref::<String>().map(String::as_str));
                telemetry.record_panic(location, message);
            }
            previous(info);
        }));
    });
}

/// Waits up to two seconds until every queued record is on disk.
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) fn flush() {
    if let Some(telemetry) = global() {
        telemetry.flush();
    }
}

/// Times one FUSE operation from creation to drop, so every reply path,
/// early returns included, is recorded exactly once.
///
/// ```ignore
/// let call = FuseCall::begin(FuseOp::Lookup);
/// reply.error(call.fail(fuser::Errno::ENOENT));
/// ```
pub(crate) struct FuseCall {
    op: FuseOp,
    started: Option<Instant>,
    errno: Cell<Option<i32>>,
    bytes: Cell<u64>,
}

impl FuseCall {
    /// Reads the clock only while telemetry is on.
    pub(crate) fn begin(op: FuseOp) -> Self {
        Self {
            op,
            started: global().map(|_| Instant::now()),
            errno: Cell::new(None),
            bytes: Cell::new(0),
        }
    }

    /// Notes the error the operation replies with and passes it through.
    pub(crate) fn fail<E: Copy + Into<i32>>(&self, error: E) -> E {
        self.errno.set(Some(error.into()));
        error
    }

    /// Notes the bytes a read or write transferred.
    pub(crate) fn bytes(&self, count: u64) {
        self.bytes.set(self.bytes.get().saturating_add(count));
    }
}

impl Drop for FuseCall {
    fn drop(&mut self) {
        if let (Some(started), Some(telemetry)) = (self.started, global()) {
            telemetry.fuse_op(
                self.op,
                started.elapsed(),
                self.errno.get(),
                self.bytes.get(),
            );
        }
    }
}

#[cfg(test)]
pub(crate) mod test_support;

#[cfg(test)]
mod tests;
