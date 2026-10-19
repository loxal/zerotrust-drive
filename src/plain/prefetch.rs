// SPDX-FileCopyrightText: Copyright 2026 Alexander Orlov <info@lifub.com>

//! Parallel downloads for a mirror's first pass over many new files: a few
//! workers fetch the next files of the pass into `.zdrive-tmp-*` files at
//! the top of the local folder while the cycle installs them one by one in
//! its usual order, with its usual checks. A staged file that is not taken
//! is removed when the pass ends; one a crash leaves behind is cleared by
//! the next scan's debris recovery like any other temporary file.

use std::collections::{HashMap, VecDeque};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, mpsc};
use std::thread::Scope;

use super::local::{self, TEMP_PREFIX};
use crate::remote::RemoteError;
use crate::remote::gdrive::{DriveFile, GoogleDrive};

/// Concurrent downloads; Drive's request pacing still bounds them.
const WORKERS: usize = 4;
/// Files staged or in flight ahead of the install.
const WINDOW: usize = 8;
/// Free space prefetching leaves, as a download does.
const RESERVE: u64 = 1 << 30;

struct Job {
    file: DriveFile,
    temp: PathBuf,
}

/// A downloaded (or failed) file waiting for its install.
pub(super) struct Staged {
    pub(super) temp: PathBuf,
    pub(super) result: Result<(), RemoteError>,
}

pub(super) struct Prefetch {
    jobs: Option<mpsc::Sender<Job>>,
    done: mpsc::Receiver<(String, Result<(), RemoteError>)>,
    /// Set when the pass ends: workers take no further job.
    cancel: Arc<AtomicBool>,
    queue: VecDeque<DriveFile>,
    inflight: HashMap<String, (DriveFile, PathBuf)>,
    finished: HashMap<String, (DriveFile, PathBuf, Result<(), RemoteError>)>,
}

impl Prefetch {
    /// Starts the workers in `scope` and stages the first files of
    /// `queue`, in install order, below `root`.
    pub(super) fn start<'scope, 'env: 'scope>(
        scope: &'scope Scope<'scope, 'env>,
        drive: &'env GoogleDrive,
        root: &Path,
        queue: Vec<DriveFile>,
    ) -> Self {
        let (jobs, job_rx) = mpsc::channel::<Job>();
        let (done_tx, done) = mpsc::channel();
        let job_rx = Arc::new(Mutex::new(job_rx));
        let cancel = Arc::new(AtomicBool::new(false));
        for _ in 0..WORKERS.min(queue.len()) {
            let (job_rx, done_tx, cancel) = (job_rx.clone(), done_tx.clone(), cancel.clone());
            scope.spawn(move || {
                loop {
                    let job = job_rx
                        .lock()
                        .unwrap_or_else(|poison| poison.into_inner())
                        .recv();
                    let Ok(job) = job else { break };
                    let result = if cancel.load(Ordering::SeqCst) {
                        Err(RemoteError::Local("the pass ended".to_string()))
                    } else {
                        drive.download_to(&job.file, &job.temp)
                    };
                    if done_tx.send((job.file.id.clone(), result)).is_err() {
                        break;
                    }
                }
            });
        }
        let mut prefetch = Self {
            jobs: Some(jobs),
            done,
            cancel,
            queue: queue.into(),
            inflight: HashMap::new(),
            finished: HashMap::new(),
        };
        prefetch.top_up(root);
        prefetch
    }

    /// Hands out jobs until [`WINDOW`] files are staged or in flight. Stops
    /// for good when the disk runs short; the install then reports it.
    pub(super) fn top_up(&mut self, root: &Path) {
        let Some(jobs) = &self.jobs else {
            return;
        };
        while self.inflight.len() + self.finished.len() < WINDOW {
            let Some(file) = self.queue.pop_front() else {
                break;
            };
            let size = file.size().unwrap_or(0);
            if local::free_bytes(root).is_ok_and(|free| free < size.saturating_add(RESERVE)) {
                self.queue.clear();
                break;
            }
            let temp = root.join(format!("{TEMP_PREFIX}{}", super::pull::serial()));
            let created = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o666)
                .custom_flags(libc::O_NOFOLLOW)
                .open(&temp);
            if created.is_err() {
                // The install downloads it itself and reports any problem.
                continue;
            }
            let id = file.id.clone();
            let job = Job {
                file: file.clone(),
                temp: temp.clone(),
            };
            if jobs.send(job).is_err() {
                let _ = std::fs::remove_file(&temp);
                self.queue.clear();
                break;
            }
            self.inflight.insert(id, (file, temp));
        }
    }

    /// The staged download of `file`, waiting for it if it is in flight;
    /// `None` when it was never staged or Drive's copy changed since.
    pub(super) fn take(&mut self, file: &DriveFile) -> Option<Staged> {
        while self.inflight.contains_key(&file.id) {
            match self.done.recv() {
                Ok((id, result)) => self.landed(id, result),
                Err(_) => break,
            }
        }
        let (staged, temp, result) = self.finished.remove(&file.id)?;
        if staged.md5() != file.md5() || staged.size() != file.size() {
            let _ = std::fs::remove_file(&temp);
            return None;
        }
        Some(Staged { temp, result })
    }

    fn landed(&mut self, id: String, result: Result<(), RemoteError>) {
        if let Some((file, temp)) = self.inflight.remove(&id) {
            self.finished.insert(id, (file, temp, result));
        }
    }

    /// Ends the pass: no new jobs, waits for the downloads in flight, and
    /// removes every staged file that was not taken.
    pub(super) fn finish(mut self) {
        self.cancel.store(true, Ordering::SeqCst);
        self.jobs = None;
        while let Ok((id, result)) = self.done.recv() {
            self.landed(id, result);
        }
        let temps = self
            .finished
            .drain()
            .map(|(_, (_, temp, _))| temp)
            .chain(self.inflight.drain().map(|(_, (_, temp))| temp));
        for temp in temps {
            let _ = std::fs::remove_file(temp);
        }
    }
}
