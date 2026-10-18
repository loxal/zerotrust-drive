// SPDX-FileCopyrightText: Copyright 2026 Alexander Orlov <info@lifub.com>

//! Test helpers: telemetry against a temp dir, and readers for what it
//! wrote. Reusable from any test in the crate.

use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard, PoisonError};

use serde_json::Value;

use crate::remote::TestDir;

use super::{DEFAULT_INSTANCE, DIR_NAME, GLOBAL, Level, Options, Start, Telemetry, writer};

/// A private [`Telemetry`] writing below a temp dir; stopped on drop.
pub(crate) struct TestTelemetry {
    pub(crate) telemetry: Telemetry,
    dir: TestDir,
}

impl TestTelemetry {
    pub(crate) fn start(level: Level) -> Self {
        Self::start_with(level, Options::for_level(level))
    }

    pub(crate) fn start_with(level: Level, options: Options) -> Self {
        let dir = TestDir::new("telemetry");
        let telemetry = Telemetry::new();
        telemetry
            .start_with(start(level, "mount"), &dir.path().join("state"), options)
            .expect("start telemetry");
        Self { telemetry, dir }
    }

    /// The `state_dir` passed to start.
    pub(crate) fn state_dir(&self) -> PathBuf {
        self.dir.path().join("state")
    }

    pub(crate) fn instance_dir(&self) -> PathBuf {
        self.state_dir().join(DIR_NAME).join(DEFAULT_INSTANCE)
    }

    /// Flushes, then parses every record written so far.
    pub(crate) fn records(&self) -> Vec<Value> {
        self.telemetry.flush();
        read_records(&self.instance_dir())
    }

    /// Flushes, then returns every byte below the telemetry directory.
    pub(crate) fn raw_bytes(&self) -> Vec<u8> {
        self.telemetry.flush();
        raw_bytes(&self.state_dir().join(DIR_NAME))
    }
}

impl std::ops::Deref for TestTelemetry {
    type Target = Telemetry;

    fn deref(&self) -> &Telemetry {
        &self.telemetry
    }
}

impl Drop for TestTelemetry {
    fn drop(&mut self) {
        self.telemetry.stop("test", 0);
    }
}

/// Serializes tests that use the process-global session.
static GLOBAL_TEST_LOCK: Mutex<()> = Mutex::new(());

/// The process-global session started in a temp dir, so the free functions
/// and every hook record into it. Holds a lock so only one such test runs
/// at a time; stops the session on drop.
pub(crate) struct GlobalSession {
    dir: TestDir,
    _lock: MutexGuard<'static, ()>,
}

impl GlobalSession {
    pub(crate) fn start(level: Level, mode: &'static str) -> Self {
        let lock = GLOBAL_TEST_LOCK
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let dir = TestDir::new("telemetry-global");
        super::stop("test", 0);
        super::start(start(level, mode), &dir.path().join("state")).expect("start telemetry");
        Self { dir, _lock: lock }
    }

    pub(crate) fn instance_dir(&self) -> PathBuf {
        self.dir
            .path()
            .join("state")
            .join(DIR_NAME)
            .join(DEFAULT_INSTANCE)
    }

    /// Writes a snapshot of everything recorded so far and waits for it.
    pub(crate) fn snapshot(&self) {
        if let Some(telemetry) = GLOBAL.get() {
            telemetry.snapshot();
        }
    }

    pub(crate) fn records(&self) -> Vec<Value> {
        super::flush();
        read_records(&self.instance_dir())
    }

    pub(crate) fn raw_bytes(&self) -> Vec<u8> {
        super::flush();
        raw_bytes(&self.dir.path().join("state").join(DIR_NAME))
    }

    /// Stops the session like a process exit would, keeping the files.
    pub(crate) fn stop(&self, reason: &'static str, exit_code: i32) {
        super::stop(reason, exit_code);
    }
}

impl Drop for GlobalSession {
    fn drop(&mut self) {
        super::stop("test", 0);
    }
}

fn start(level: Level, mode: &'static str) -> Start {
    Start {
        instance: DEFAULT_INSTANCE.to_string(),
        level,
        mode,
        remote_kind: "none",
        service: false,
    }
}

/// Every record of every day file in `dir`, oldest file first.
pub(crate) fn read_records(dir: &Path) -> Vec<Value> {
    let Ok(files) = writer::day_files(dir) else {
        return Vec::new();
    };
    let mut records = Vec::new();
    for (_, path, _) in files {
        let text = std::fs::read_to_string(&path).expect("read telemetry file");
        for line in text.lines() {
            records.push(serde_json::from_str(line).expect("telemetry line is JSON"));
        }
    }
    records
}

/// The records of one kind.
pub(crate) fn of_kind<'a>(records: &'a [Value], kind: &str) -> Vec<&'a Value> {
    records
        .iter()
        .filter(|record| record["kind"] == kind)
        .collect()
}

/// Every byte of every file below `dir`, recursively.
pub(crate) fn raw_bytes(dir: &Path) -> Vec<u8> {
    let mut bytes = Vec::new();
    let Ok(entries) = std::fs::read_dir(dir) else {
        return bytes;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        // File names count too: none may carry a name either.
        bytes.extend_from_slice(entry.file_name().as_encoded_bytes());
        bytes.push(b'\n');
        if path.is_dir() {
            bytes.extend(raw_bytes(&path));
        } else if let Ok(content) = std::fs::read(&path) {
            bytes.extend(content);
        }
    }
    bytes
}
