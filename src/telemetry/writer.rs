// SPDX-FileCopyrightText: Copyright 2026 Alexander Orlov <info@lifub.com>

//! The single background thread that owns the telemetry files: it appends
//! queued records, writes periodic snapshots, rotates by UTC day and
//! enforces retention and the size cap. Every failure is counted and
//! otherwise ignored, so a broken telemetry directory never reaches the
//! filesystem.

use std::fs::{File, OpenOptions};
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::sync::mpsc::{Receiver, RecvTimeoutError, SyncSender};
use std::time::{Duration, Instant};

use serde_json::Value;

use super::{Level, Options, Record, Shared, system};

pub(crate) enum Message {
    Line {
        ts: u64,
        text: String,
    },
    #[cfg_attr(not(test), allow(dead_code))]
    Snapshot(SyncSender<()>),
    Flush(SyncSender<()>),
    Stop {
        reason: &'static str,
        exit_code: i32,
        done: SyncSender<()>,
    },
}

struct DayFile {
    day: i64,
    file: File,
}

pub(crate) struct Writer {
    dir: PathBuf,
    shared: Arc<Shared>,
    options: Options,
    level: Level,
    started: Instant,
    last_snapshot: Instant,
    seq: u64,
    cpu_ms: (u64, u64),
    current: Option<DayFile>,
    /// Bytes in the instance directory, valid while `current` is open.
    dir_bytes: u64,
    /// The day the cap was found exhausted, to avoid rescanning per line.
    capped_day: Option<i64>,
}

impl Writer {
    pub(crate) fn new(dir: PathBuf, shared: Arc<Shared>, options: Options, level: Level) -> Self {
        let now = Instant::now();
        let cpu_ms = system::usage().map_or((0, 0), |usage| (usage.user_ms, usage.sys_ms));
        Self {
            dir,
            shared,
            options,
            level,
            started: now,
            last_snapshot: now,
            seq: 0,
            cpu_ms,
            current: None,
            dir_bytes: 0,
            capped_day: None,
        }
    }

    pub(crate) fn run(mut self, receiver: Receiver<Message>, first: Record) {
        self.write_record(&first);
        let mut next = Instant::now() + self.options.tick;
        loop {
            let wait = next.saturating_duration_since(Instant::now());
            match receiver.recv_timeout(wait) {
                Ok(Message::Line { ts, text }) => self.write_line(ts, &text),
                Ok(Message::Snapshot(ack)) => {
                    self.snapshot();
                    self.sync();
                    let _ = ack.try_send(());
                }
                Ok(Message::Flush(ack)) => {
                    self.sync();
                    let _ = ack.try_send(());
                }
                Ok(Message::Stop {
                    reason,
                    exit_code,
                    done,
                }) => {
                    // Records queued before the stop were handled above.
                    self.snapshot();
                    let uptime_ms = millis(self.started.elapsed());
                    self.write_record(
                        &Record::new("stop")
                            .with("reason", reason)
                            .with("exit_code", exit_code)
                            .with("uptime_ms", uptime_ms),
                    );
                    self.sync();
                    let _ = done.try_send(());
                    return;
                }
                Err(RecvTimeoutError::Timeout) => {
                    self.snapshot();
                    next = Instant::now() + self.options.tick;
                }
                Err(RecvTimeoutError::Disconnected) => {
                    self.sync();
                    return;
                }
            }
        }
    }

    fn snapshot(&mut self) {
        let now = Instant::now();
        self.seq += 1;
        let mut record = Record::new("snapshot")
            .with("seq", self.seq)
            .with("level", self.level.as_str())
            .with("interval_ms", millis(now - self.last_snapshot))
            .with("uptime_ms", millis(now - self.started));
        self.last_snapshot = now;
        for (key, value) in self.shared.metrics.take() {
            record.body.insert(key, value);
        }
        if let Some(usage) = system::usage() {
            let mut rusage = serde_json::Map::new();
            rusage.insert("max_rss_bytes".to_string(), usage.max_rss_bytes.into());
            rusage.insert(
                "user_ms".to_string(),
                usage.user_ms.saturating_sub(self.cpu_ms.0).into(),
            );
            rusage.insert(
                "sys_ms".to_string(),
                usage.sys_ms.saturating_sub(self.cpu_ms.1).into(),
            );
            self.cpu_ms = (usage.user_ms, usage.sys_ms);
            record
                .body
                .insert("rusage".to_string(), Value::Object(rusage));
        }
        if let Some(fds) = system::open_fds() {
            record = record.with("fds", fds);
        }
        let metrics = &self.shared.metrics;
        record = record
            .with("drops", metrics.drops.swap(0, Ordering::Relaxed))
            .with("cap_drops", metrics.cap_drops.swap(0, Ordering::Relaxed))
            .with(
                "write_errors",
                metrics.write_errors.swap(0, Ordering::Relaxed),
            );
        self.write_record(&record);
    }

    fn write_record(&mut self, record: &Record) {
        self.write_line(record.ts, &record.line());
    }

    fn write_line(&mut self, ts: u64, text: &str) {
        let shared = Arc::clone(&self.shared);
        let metrics = &shared.metrics;
        let day = system::utc_day(ts);
        if self.current.as_ref().map(|current| current.day) != Some(day) && self.open(day).is_err()
        {
            metrics.write_errors.fetch_add(1, Ordering::Relaxed);
            self.current = None;
            return;
        }
        let needed = text.len() as u64 + 1;
        if self.dir_bytes.saturating_add(needed) > self.options.cap_bytes {
            if self.capped_day != Some(day) {
                let _ = self.enforce(day, needed);
            }
            if self.dir_bytes.saturating_add(needed) > self.options.cap_bytes {
                self.capped_day = Some(day);
                metrics.cap_drops.fetch_add(1, Ordering::Relaxed);
                return;
            }
        }
        let Some(current) = self.current.as_mut() else {
            metrics.write_errors.fetch_add(1, Ordering::Relaxed);
            return;
        };
        let mut line = Vec::with_capacity(text.len() + 1);
        line.extend_from_slice(text.as_bytes());
        line.push(b'\n');
        match current.file.write_all(&line) {
            Ok(()) => self.dir_bytes = self.dir_bytes.saturating_add(needed),
            Err(_) => {
                metrics.write_errors.fetch_add(1, Ordering::Relaxed);
                // Reopen and rescan on the next record.
                self.current = None;
            }
        }
    }

    fn open(&mut self, day: i64) -> std::io::Result<()> {
        self.current = None;
        if let Some(root) = self.dir.parent() {
            ensure_private_dir(root)?;
        }
        ensure_private_dir(&self.dir)?;
        let file = OpenOptions::new()
            .append(true)
            .create(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(self.dir.join(system::day_file_name(day)))?;
        if !file.metadata()?.is_file() {
            return Err(std::io::Error::other(
                "telemetry file is not a regular file",
            ));
        }
        self.current = Some(DayFile { day, file });
        self.capped_day = None;
        self.enforce(day, 0)
    }

    /// Deletes files past retention, then the oldest other files while the
    /// directory plus `needed` bytes exceeds the cap; recomputes `dir_bytes`.
    fn enforce(&mut self, today: i64, needed: u64) -> std::io::Result<()> {
        let current = self.current.as_ref().map(|current| current.day);
        let mut files = day_files(&self.dir)?;
        let mut total = 0u64;
        files.retain(|(day, path, len)| {
            let expired = today - day > self.options.retention_days && Some(*day) != current;
            if expired && std::fs::remove_file(path).is_ok() {
                return false;
            }
            total = total.saturating_add(*len);
            true
        });
        for (day, path, len) in &files {
            if total.saturating_add(needed) <= self.options.cap_bytes {
                break;
            }
            if Some(*day) != current && std::fs::remove_file(path).is_ok() {
                total = total.saturating_sub(*len);
            }
        }
        self.dir_bytes = total;
        Ok(())
    }

    fn sync(&mut self) {
        if let Some(current) = self.current.as_ref()
            && current.file.sync_data().is_err()
        {
            self.shared
                .metrics
                .write_errors
                .fetch_add(1, Ordering::Relaxed);
        }
    }
}

/// `(day, path, length)` of every day file in `dir`, oldest first.
pub(crate) fn day_files(dir: &Path) -> std::io::Result<Vec<(i64, PathBuf, u64)>> {
    let mut files = Vec::new();
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let Some(day) = entry
            .file_name()
            .to_str()
            .and_then(system::parse_day_file_name)
        else {
            continue;
        };
        let metadata = entry.metadata()?;
        if metadata.is_file() {
            files.push((day, entry.path(), metadata.len()));
        }
    }
    files.sort();
    Ok(files)
}

fn ensure_private_dir(path: &Path) -> std::io::Result<()> {
    crate::remote::ensure_private_dir(path)
        .map_err(|error| std::io::Error::other(error.to_string()))
}

fn millis(duration: Duration) -> u64 {
    u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
}
