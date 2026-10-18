// SPDX-FileCopyrightText: Copyright 2026 Alexander Orlov <info@lifub.com>

//! Automatic replication while a store is mounted (`zdrive --remote NAME`).
//!
//! Before the mount, the local store catches up with the remote: an empty
//! directory is filled from it and an existing replica fast-forwards. While
//! the drive is mounted, every local root publication wakes the replicator
//! thread, which pushes the newest generation; a burst of commits becomes
//! one push. When idle, it watches the remote for another writer and renews
//! this replica's lease. On unmount it pushes the final generation within a
//! bounded wait.
//!
//! Remote trouble never touches local durability. Transient failures retry
//! with backoff. Another writer blocks new writes until remount, so the
//! replicas cannot diverge any further. Anything that needs the operator
//! stops replication; local writes continue and the exit status reports it.

use std::path::Path;
use std::sync::{Arc, Condvar, Mutex, MutexGuard, PoisonError};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use crate::crypto::RecoveryFingerprint;
use crate::fs::{FsInner, StoreFormat};
use crate::prompt::TerminalReader;
use crate::telemetry::{self, Field, Level};

use super::RemoteError;
use super::cli::{self, Action, StoreKind};
use super::config::{Paths, RemoteConfig, RemoteMode, RemoteName};
use super::gdrive::GoogleDrive;
use super::lease;
use super::oauth;
use super::state::RemoteState;
use super::sync::{self, LocalStore, PushReport, Relation, Remote, Watch};

/// Exit status of a mount that ended before the remote held its final
/// generation (`EX_TEMPFAIL`). Local data is durable either way.
pub(crate) const EXIT_UNSYNCED: i32 = 75;
/// How long an unmount waits for the final push.
pub(crate) const FINAL_WAIT: Duration = Duration::from_secs(600);
/// When the unmount starts saying that it waits for the upload.
const QUIET_WAIT: Duration = Duration::from_secs(2);
/// Retry budget of the requests before mounting: an unreachable Google
/// Drive mounts offline within seconds instead of after minutes of backoff.
const STARTUP_ATTEMPTS: u32 = 3;
const STARTUP_RETRY_CAP: Duration = Duration::from_secs(4);
/// Retry budget of one replicator request; the replicator's own backoff
/// ([`Timing::MOUNT`]) retries a failed push for as long as the mount runs.
const PUSH_ATTEMPTS: u32 = 4;
const PUSH_RETRY_CAP: Duration = Duration::from_secs(16);

/// Intervals of the replicator; tests shorten them.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Timing {
    /// Between checks for another writer while idle.
    pub(crate) watch: Duration,
    /// First and longest pause after a failed push.
    pub(crate) first_retry: Duration,
    pub(crate) max_retry: Duration,
    /// Longest pause between attempts of the final push.
    pub(crate) max_final_retry: Duration,
    pub(crate) heartbeat: Duration,
}

impl Timing {
    pub(crate) const MOUNT: Self = Self {
        watch: Duration::from_secs(60),
        first_retry: Duration::from_secs(5),
        max_retry: Duration::from_secs(60),
        max_final_retry: Duration::from_secs(30),
        heartbeat: lease::HEARTBEAT,
    };
}

/// How automatic sync ended.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Outcome {
    /// The remote holds the final local generation.
    Synced(u64),
    /// Another replica's fresh lease kept the mount read-only.
    ReadOnly,
    /// Another writer appeared; writes were blocked until remount.
    Blocked(String),
    /// Replication stopped on a problem that needs the operator.
    Failed(String),
    /// The final push did not finish; the next push or mount resumes it.
    Unfinished(String),
}

fn note(name: &RemoteName, message: &str) {
    eprintln!("zerotrust-drive: remote {name}: {message}");
}

/// A remote ready for a mount: the local store has caught up with it.
pub(crate) struct Prepared {
    name: RemoteName,
    display: String,
    drive: GoogleDrive,
    folder_id: String,
    state: RemoteState,
    passphrase: String,
    /// Why the mount must stay read-only.
    read_only: Option<String>,
}

/// Brings the store in the anchored directory `base` up to the remote head
/// before it is mounted. The caller holds the drive-operation lock.
pub(crate) fn prepare(
    remote: &str,
    canonical: &Path,
    base: &Path,
    lock: &crate::DriveOperationLock,
    passphrase: Option<String>,
    passphrase_file: Option<&Path>,
    terminal: Option<&mut TerminalReader>,
) -> Result<Prepared, String> {
    let paths = Paths::from_env().map_err(|error| error.to_string())?;
    let name = RemoteName::parse(remote).map_err(|error| error.to_string())?;
    let config = RemoteConfig::load(&paths, &name).map_err(|error| error.to_string())?;
    if config.mode != RemoteMode::Encrypted {
        return Err(format!(
            "remote {name} stores plain files and cannot back an encrypted mount; sync it with `zdrive sync --remote {name} --dir DIR`"
        ));
    }
    let client = oauth::client_for(&config.issuer()).map_err(|error| error.to_string())?;
    let display = canonical.display().to_string();
    let kind = cli::inspect_store(base, &display)?;
    if kind == StoreKind::V1 {
        return Err(format!(
            "{display} is a v1 store; automatic remote sync needs v2: run `zdrive --migrate-v2 --encrypted-dir {display}` first"
        ));
    }
    // A new store may be created below, so its passphrase is confirmed.
    let passphrase = cli::read_passphrase(
        passphrase,
        passphrase_file,
        terminal,
        kind == StoreKind::Absent,
    )?;
    let mut drive = cli::open_drive(client, &paths, &config, &name, Some(&passphrase))?;
    let policy = drive.retry_policy();
    drive.set_retry_policy(policy.bounded(STARTUP_ATTEMPTS, STARTUP_RETRY_CAP));
    let state_dir = cli::replica_state(&paths, &name, canonical)?;
    let mut online = true;
    let log = |message: &str| note(&name, message);
    let remote = Remote {
        drive: &drive,
        folder_id: &config.folder_id,
        log: &log,
    };
    note(&name, &format!("syncing with {}", config.folder_hint));
    lock.revalidate()?;
    match cli::execute(
        Action::Pull,
        kind,
        &remote,
        base,
        &display,
        &passphrase,
        &state_dir,
    ) {
        Ok(summary) => {
            for line in summary.lines {
                note(&name, &line);
            }
        }
        Err(RemoteError::Network(error)) if kind == StoreKind::V2 => {
            online = false;
            offline(&name, &error);
        }
        Err(RemoteError::NotFound(_)) if kind != StoreKind::PendingBootstrap => {
            match drive.get(&config.folder_id) {
                Ok(folder) if !folder.trashed => note(
                    &name,
                    "the remote holds no store yet; the first upload creates it",
                ),
                Ok(_) | Err(RemoteError::NotFound(_)) => {
                    return Err(format!(
                        "the Drive folder of remote {name} ({}) no longer exists; choose another with `zdrive remote auth --remote {name}`",
                        config.folder_hint
                    ));
                }
                Err(RemoteError::Network(error)) if kind == StoreKind::V2 => {
                    online = false;
                    offline(&name, &error);
                }
                Err(error) => return Err(refusal(&name, &error)),
            }
        }
        Err(error) => return Err(refusal(&name, &error)),
    }
    let state = RemoteState::open(&state_dir, &config.folder_id)
        .map_err(|error| format!("remote {name}: {error}; the drive was not mounted"))?;
    // Offline, the leases are unreadable as well; fork detection still
    // protects the remote once it is reachable.
    let read_only = online
        .then(|| foreign_lease(&drive, &state, &name))
        .flatten();
    drive.set_retry_policy(policy.bounded(PUSH_ATTEMPTS, PUSH_RETRY_CAP));
    Ok(Prepared {
        name,
        display,
        drive,
        folder_id: config.folder_id,
        state,
        passphrase,
        read_only,
    })
}

fn offline(name: &RemoteName, error: &str) {
    offline_event("mount");
    note(
        name,
        &format!("{error}; mounting offline - changes upload once Google Drive is reachable"),
    );
}

fn offline_event(phase: &'static str) {
    telemetry::event(
        Level::Standard,
        "remote.offline",
        &[("phase", Field::Tag(phase))],
    );
}

/// Records one replicator step: its duration always, an event at `full`.
fn record_step(duration: &'static str, step: &'static str, started: Instant, ok: bool) {
    let elapsed = started.elapsed();
    telemetry::duration(duration, elapsed);
    telemetry::event(
        Level::Full,
        "replicator.step",
        &[
            ("step", Field::Tag(step)),
            ("ok", Field::Bool(ok)),
            ("elapsed_ms", Field::U64(millis(elapsed))),
        ],
    );
}

fn millis(elapsed: Duration) -> u64 {
    u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX)
}

/// Records how the final push of an unmount ended.
fn record_final_push(outcome: &Outcome, uploaded: bool, timed_out: bool, elapsed: Duration) {
    let tag = match outcome {
        Outcome::Synced(_) if uploaded => "pushed",
        Outcome::Synced(_) | Outcome::ReadOnly => "nothing",
        Outcome::Unfinished(_) if timed_out => "timeout",
        Outcome::Unfinished(_) => "interrupted",
        Outcome::Blocked(_) | Outcome::Failed(_) => "failed",
    };
    telemetry::event(
        Level::Standard,
        "remote.final_push",
        &[
            ("outcome", Field::Tag(tag)),
            ("elapsed_ms", Field::U64(millis(elapsed))),
        ],
    );
}

fn refusal(name: &RemoteName, error: &RemoteError) -> String {
    let advice = match error {
        RemoteError::Diverged(_) => {
            "; mount without --remote to read the local files, then resolve it with `zdrive remote status`"
        }
        _ => "",
    };
    format!("remote {name}: {error}; the drive was not mounted{advice}")
}

/// Why the mount must stay read-only: another replica renewed its lease
/// recently. A failed lookup only warns; fork detection still protects.
fn foreign_lease(drive: &GoogleDrive, state: &RemoteState, name: &RemoteName) -> Option<String> {
    let folder = state.record.layout.as_ref()?.leases.clone();
    match lease::fresh_peers(
        drive,
        &folder,
        state.record.lease.as_ref(),
        lease::unix_now(),
    ) {
        Ok(peers) => peers.into_iter().min_by_key(|peer| peer.age).map(|peer| {
            format!(
                "another replica ({}) of remote {name} renewed its lease {} s ago, so this mount is read-only and the replicas cannot diverge; unmount the other one, or wait {} minutes after it stopped, then mount again",
                peer.replica.get(..8).unwrap_or(&peer.replica),
                peer.age,
                lease::FRESH.as_secs() / 60
            )
        }),
        Err(error) => {
            note(name, &format!("cannot read the leases: {error}"));
            None
        }
    }
}

impl Prepared {
    pub(crate) fn passphrase(&self) -> &str {
        &self.passphrase
    }

    /// Starts automatic sync for the mounted store `inner`.
    pub(crate) fn start(self, inner: Arc<FsInner>) -> Result<Replicator, String> {
        self.start_with(inner, Timing::MOUNT)
    }

    fn start_with(self, inner: Arc<FsInner>, timing: Timing) -> Result<Replicator, String> {
        let Prepared {
            name,
            display,
            drive,
            folder_id,
            state,
            read_only,
            ..
        } = self;
        if let Some(reason) = read_only {
            note(&name, &format!("WARNING: {reason}"));
            telemetry::event(
                Level::Standard,
                "remote.read_only",
                &[("cause", Field::Tag("foreign_lease"))],
            );
            inner.block_writes_for_remote(reason);
            return Ok(Replicator {
                name,
                display,
                shared: Arc::new(Shared::default()),
                thread: None,
            });
        }
        let worker = Worker::new(
            name.clone(),
            display.clone(),
            drive,
            folder_id,
            state,
            inner,
            timing,
        )?;
        let shared = Arc::new(Shared::default());
        let observed = Arc::clone(&shared);
        if !worker
            .inner
            .observe_v2_commits(Box::new(move || observed.mark_dirty()))
        {
            return Err("automatic remote sync is already running for this mount".to_string());
        }
        let running = Arc::clone(&shared);
        let thread = std::thread::Builder::new()
            .name("zdrive-replicator".to_string())
            .spawn(move || worker.run(&running))
            .map_err(|error| format!("cannot start automatic remote sync: {error}"))?;
        Ok(Replicator {
            name,
            display,
            shared,
            thread: Some(thread),
        })
    }
}

#[derive(Default)]
struct Shared {
    signal: Mutex<Signal>,
    wake: Condvar,
}

#[derive(Default)]
struct Signal {
    /// A local root was published since the replicator last looked.
    dirty: bool,
    /// The drive is unmounted: push the final generation.
    stop: bool,
    /// Leave the final push unfinished.
    abandoned: bool,
    /// The final push uploaded a new generation.
    uploaded: bool,
    outcome: Option<Outcome>,
}

impl Shared {
    fn lock(&self) -> MutexGuard<'_, Signal> {
        self.signal.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Runs under the mount's persistence lock: only flags and wakes.
    fn mark_dirty(&self) {
        self.lock().dirty = true;
        self.wake.notify_all();
    }

    fn abandon(&self) {
        self.lock().abandoned = true;
        self.wake.notify_all();
    }
}

/// Automatic sync of one mount.
pub(crate) struct Replicator {
    name: RemoteName,
    display: String,
    shared: Arc<Shared>,
    thread: Option<JoinHandle<()>>,
}

impl Replicator {
    /// Pushes the final generation after the drive was unmounted and its
    /// state flushed. Waits at most `limit`; a signal abandons the wait.
    pub(crate) fn finish(&mut self, limit: Duration) -> Outcome {
        let Some(thread) = self.thread.take() else {
            record_final_push(&Outcome::ReadOnly, false, false, Duration::ZERO);
            return Outcome::ReadOnly;
        };
        self.shared.lock().stop = true;
        self.shared.wake.notify_all();
        let abandon = Arc::clone(&self.shared);
        crate::shutdown::finishing(Box::new(move || abandon.abandon()));
        let started = Instant::now();
        let deadline = started + limit;
        let mut announced = false;
        let mut timed_out = false;
        let mut signal = self.shared.lock();
        let outcome = loop {
            if let Some(outcome) = signal.outcome.clone() {
                break outcome;
            }
            if signal.abandoned {
                break Outcome::Unfinished("the upload was interrupted".to_string());
            }
            let now = Instant::now();
            if now >= deadline {
                // The worker stops after its current attempt.
                signal.abandoned = true;
                timed_out = true;
                self.shared.wake.notify_all();
                break Outcome::Unfinished(format!(
                    "the upload did not finish within {} s",
                    limit.as_secs()
                ));
            }
            let mut until = deadline;
            if !announced {
                if now >= started + QUIET_WAIT {
                    announced = true;
                    let hint = if crate::shutdown::is_unattended() {
                        format!(
                            "uploading the final generation for up to {} s; the next start uploads whatever is left",
                            limit.as_secs()
                        )
                    } else {
                        "uploading the final generation; press Ctrl+C to leave it for the next push"
                            .to_string()
                    };
                    note(&self.name, &hint);
                } else {
                    until = until.min(started + QUIET_WAIT);
                }
            }
            signal = self
                .shared
                .wake
                .wait_timeout(signal, until - now)
                .unwrap_or_else(PoisonError::into_inner)
                .0;
        };
        let uploaded = signal.uploaded;
        drop(signal);
        crate::shutdown::session_ended();
        let outcome = if !matches!(outcome, Outcome::Unfinished(_)) && thread.join().is_err() {
            Outcome::Failed("the replicator thread panicked".to_string())
        } else {
            outcome
        };
        record_final_push(&outcome, uploaded, timed_out, started.elapsed());
        outcome
    }

    /// Reports `outcome` and returns the process exit status.
    pub(crate) fn report(&self, outcome: &Outcome) -> i32 {
        report(&self.name, &self.display, outcome)
    }
}

fn report(name: &RemoteName, display: &str, outcome: &Outcome) -> i32 {
    let retry = format!("zdrive remote push --remote {name} --encrypted-dir {display}");
    match outcome {
        Outcome::Synced(number) => {
            note(name, &format!("holds the final generation {number}"));
            0
        }
        Outcome::ReadOnly => 0,
        Outcome::Blocked(reason) => {
            note(name, &format!("not synced: {reason}"));
            EXIT_UNSYNCED
        }
        Outcome::Failed(reason) => {
            note(
                name,
                &format!("not synced: {reason}; local data is safe. Fix it, then run `{retry}`"),
            );
            EXIT_UNSYNCED
        }
        Outcome::Unfinished(reason) => {
            note(
                name,
                &format!(
                    "not synced: {reason}; local data is safe. Run `{retry}` or mount again to finish the upload"
                ),
            );
            EXIT_UNSYNCED
        }
    }
}

/// What the replicator does next.
enum Event {
    Push,
    Watch,
    Beat,
    Stop,
}

enum Step {
    Retry(RemoteError),
    Halt(Outcome),
}

/// Schedule of the replicator loop.
struct Plan {
    /// A local generation may be newer than the remote head.
    pending: bool,
    retry_at: Option<Instant>,
    delay: Duration,
    failing: bool,
    next_watch: Instant,
    next_beat: Instant,
    synced: Option<u64>,
}

struct Worker {
    name: RemoteName,
    display: String,
    drive: GoogleDrive,
    folder_id: String,
    state: RemoteState,
    inner: Arc<FsInner>,
    key: [u8; 32],
    kdf_bytes: Vec<u8>,
    timing: Timing,
    leased: bool,
}

impl Worker {
    fn new(
        name: RemoteName,
        display: String,
        drive: GoogleDrive,
        folder_id: String,
        state: RemoteState,
        inner: Arc<FsInner>,
        timing: Timing,
    ) -> Result<Self, String> {
        if inner.format != StoreFormat::V2 || inner.v2_namespace_pin().is_none() {
            return Err("automatic remote sync needs a v2 store".to_string());
        }
        let kdf_bytes = match inner.kdf_fingerprint() {
            RecoveryFingerprint::Exact { bytes } => bytes.clone(),
            RecoveryFingerprint::Ciphertext { .. } => {
                return Err("_kdf.json has an unexpected fingerprint kind".to_string());
            }
        };
        let key = *inner.key.read().unwrap_or_else(PoisonError::into_inner);
        Ok(Self {
            name,
            display,
            drive,
            folder_id,
            state,
            inner,
            key,
            kdf_bytes,
            timing,
            leased: false,
        })
    }

    fn run(mut self, shared: &Shared) {
        let outcome = self.serve(shared);
        self.release();
        shared.lock().outcome = Some(outcome);
        shared.wake.notify_all();
    }

    /// Runs one sync operation against the mounted store.
    fn sync<T>(
        &mut self,
        operation: impl FnOnce(&Remote<'_>, &LocalStore<'_>, &mut RemoteState) -> Result<T, RemoteError>,
    ) -> Result<T, RemoteError> {
        let Self {
            name,
            display,
            drive,
            folder_id,
            state,
            inner,
            key,
            kdf_bytes,
            ..
        } = self;
        let pin = inner
            .v2_namespace_pin()
            .ok_or_else(|| RemoteError::Local("the mount lost its v2 namespace".to_string()))?;
        let name = &*name;
        let log = |message: &str| note(name, message);
        let remote = Remote {
            drive,
            folder_id,
            log: &log,
        };
        let local = LocalStore {
            base: &inner.base_path,
            key,
            kdf_bytes,
            kdf_fingerprint: inner.kdf_fingerprint(),
            pin,
            display,
        };
        operation(&remote, &local, state)
    }

    fn serve(&mut self, shared: &Shared) -> Outcome {
        let now = Instant::now();
        let mut plan = Plan {
            pending: true,
            retry_at: None,
            delay: self.timing.first_retry,
            failing: false,
            next_watch: now + self.timing.watch,
            next_beat: now,
            synced: None,
        };
        loop {
            match next_event(shared, &mut plan) {
                Event::Stop => return self.finish(shared, &plan),
                Event::Push => {
                    plan.pending = false;
                    let started = Instant::now();
                    let pushed = self.sync(sync::push);
                    record_step("replicator.push", "push", started, pushed.is_ok());
                    match pushed {
                        Ok(report) => {
                            if plan.failing {
                                note(&self.name, "Google Drive is reachable again");
                                telemetry::event(Level::Standard, "remote.online", &[]);
                            }
                            self.pushed(&report);
                            plan.synced = Some(report.number);
                            plan.retry_at = None;
                            plan.delay = self.timing.first_retry;
                            plan.failing = false;
                            plan.next_watch = Instant::now() + self.timing.watch;
                        }
                        Err(error) => match self.classify(error) {
                            Step::Halt(outcome) => return self.halt(outcome),
                            Step::Retry(error) => {
                                if !plan.failing {
                                    offline_event("replicate");
                                    note(
                                        &self.name,
                                        &format!(
                                            "upload failed: {error}; retrying with backoff - local writes are safe"
                                        ),
                                    );
                                }
                                plan.failing = true;
                                plan.pending = true;
                                plan.retry_at = Some(Instant::now() + plan.delay);
                                plan.delay = (plan.delay * 2).min(self.timing.max_retry);
                            }
                        },
                    }
                }
                Event::Watch => {
                    plan.next_watch = Instant::now() + self.timing.watch;
                    let started = Instant::now();
                    let watched = self.sync(sync::watch);
                    record_step("replicator.watch", "watch", started, watched.is_ok());
                    match watched {
                        Ok(watch) => match watch.relation {
                            Relation::Equal => {}
                            Relation::LocalAhead
                            | Relation::NoRemoteStore
                            | Relation::RemoteEmpty => {
                                plan.pending = true;
                            }
                            Relation::RemoteAhead
                            | Relation::Diverged
                            | Relation::Forked
                            | Relation::DifferentStore => {
                                let outcome = self.blocked(&watch);
                                return self.halt(outcome);
                            }
                        },
                        Err(error @ RemoteError::Auth(_)) => {
                            return self.halt(Outcome::Failed(error.to_string()));
                        }
                        // The next watch or push retries.
                        Err(_) => {}
                    }
                }
                Event::Beat => {
                    plan.next_beat = Instant::now() + self.timing.heartbeat;
                    let started = Instant::now();
                    let renewed = self.beat();
                    record_step("replicator.beat", "beat", started, renewed);
                }
            }
        }
    }

    /// Pushes until the remote holds the final generation, retrying
    /// transient failures until the unmount stops waiting.
    fn finish(&mut self, shared: &Shared, plan: &Plan) -> Outcome {
        if !plan.pending
            && let Some(number) = plan.synced
        {
            return Outcome::Synced(number);
        }
        let mut delay = self.timing.first_retry.min(self.timing.max_final_retry);
        let mut reported = false;
        loop {
            let started = Instant::now();
            let pushed = self.sync(sync::push);
            record_step("replicator.final", "final", started, pushed.is_ok());
            let error = match pushed {
                Ok(report) => {
                    self.pushed(&report);
                    shared.lock().uploaded = !report.up_to_date;
                    return Outcome::Synced(report.number);
                }
                Err(error) => match self.classify(error) {
                    Step::Halt(outcome) => return self.halt(outcome),
                    Step::Retry(error) => error,
                },
            };
            // Offline with nothing new: the remote already holds this head.
            if let Ok(Some(number)) = self.sync(|_, local, state| sync::synced_head(local, state)) {
                return Outcome::Synced(number);
            }
            if !reported {
                reported = true;
                note(
                    &self.name,
                    &format!("final upload failed: {error}; retrying"),
                );
            }
            let signal = shared.lock();
            let (signal, _) = shared
                .wake
                .wait_timeout_while(signal, delay, |signal| !signal.abandoned)
                .unwrap_or_else(PoisonError::into_inner);
            if signal.abandoned {
                return Outcome::Unfinished(error.to_string());
            }
            drop(signal);
            delay = (delay * 2).min(self.timing.max_final_retry);
        }
    }

    fn pushed(&self, report: &PushReport) {
        if !report.up_to_date {
            note(
                &self.name,
                &format!(
                    "uploaded generation {}: {}",
                    report.number,
                    cli::transfer(
                        report.generations,
                        report.objects,
                        report.packs,
                        report.bytes
                    )
                ),
            );
        }
    }

    fn classify(&mut self, error: RemoteError) -> Step {
        match error {
            RemoteError::Network(_)
            | RemoteError::Quota(_)
            | RemoteError::Protocol(_)
            | RemoteError::Local(_) => Step::Retry(error),
            // Also raised for a colliding file id: only a remote that moved
            // past this replica blocks writes.
            RemoteError::Conflict(_) => match self.sync(sync::watch) {
                Ok(watch)
                    if matches!(
                        watch.relation,
                        Relation::RemoteAhead
                            | Relation::Diverged
                            | Relation::Forked
                            | Relation::DifferentStore
                    ) =>
                {
                    Step::Halt(self.blocked(&watch))
                }
                _ => Step::Retry(error),
            },
            RemoteError::Diverged(message) => Step::Halt(Outcome::Blocked(format!(
                "{message}; copy the files you changed out of the read-only drive, move {} aside and mount again to start from the remote copy",
                self.display
            ))),
            RemoteError::Auth(_) | RemoteError::Integrity(_) | RemoteError::NotFound(_) => {
                Step::Halt(Outcome::Failed(error.to_string()))
            }
        }
    }

    /// Describes another writer `watch` found.
    fn blocked(&self, watch: &Watch) -> Outcome {
        let remote = watch.remote.map_or_else(
            || "another store".to_string(),
            |number| format!("generation {number}"),
        );
        let unpushed = self
            .state
            .record
            .synced
            .as_ref()
            .is_none_or(|synced| synced.number != watch.local);
        let advice = if watch.relation == Relation::RemoteAhead && !unpushed {
            "unmount and mount again to fast-forward to it".to_string()
        } else {
            format!(
                "both histories are preserved; copy the files you changed out of the read-only drive, move {} aside and mount again to start from the remote copy",
                self.display
            )
        };
        Outcome::Blocked(format!(
            "another replica published {remote} while local generation {} was mounted; {advice}",
            watch.local
        ))
    }

    fn halt(&mut self, outcome: Outcome) -> Outcome {
        let tag = match &outcome {
            Outcome::Blocked(_) => "blocked",
            Outcome::Failed(_) => "failed",
            _ => "other",
        };
        telemetry::event(
            Level::Standard,
            "remote.halt",
            &[("outcome", Field::Tag(tag))],
        );
        match &outcome {
            Outcome::Blocked(reason) => {
                self.inner.block_writes_for_remote(reason.clone());
                note(
                    &self.name,
                    &format!("WARNING: the drive is now read-only: {reason}"),
                );
            }
            Outcome::Failed(reason) => note(
                &self.name,
                &format!(
                    "ERROR: automatic sync stopped: {reason}; local writes continue but stay on this machine"
                ),
            ),
            _ => {}
        }
        outcome
    }

    /// Creates or renews the lease once the remote layout exists. Failures
    /// wait for the next heartbeat; push and watch report lasting ones.
    /// Returns false only when a renewal failed.
    fn beat(&mut self) -> bool {
        let Some(folder) = self
            .state
            .record
            .layout
            .as_ref()
            .map(|layout| layout.leases.clone())
        else {
            return true;
        };
        let renewed =
            lease::acquire(&self.drive, &folder, &mut self.state, lease::unix_now()).is_ok();
        self.leased |= renewed;
        renewed
    }

    fn release(&mut self) {
        if !self.leased {
            return;
        }
        if let Some(record) = &self.state.record.lease
            && let Err(error) = lease::release(&self.drive, record, lease::unix_now())
        {
            note(&self.name, &format!("cannot release the lease: {error}"));
        }
    }
}

fn next_event(shared: &Shared, plan: &mut Plan) -> Event {
    let mut signal = shared.lock();
    loop {
        plan.pending |= std::mem::take(&mut signal.dirty);
        if signal.stop {
            return Event::Stop;
        }
        let now = Instant::now();
        let mut until = plan.next_beat;
        if plan.pending {
            let at = plan.retry_at.unwrap_or(now);
            if at <= now {
                return Event::Push;
            }
            until = until.min(at);
        } else {
            if plan.next_watch <= now {
                return Event::Watch;
            }
            until = until.min(plan.next_watch);
        }
        if plan.next_beat <= now {
            return Event::Beat;
        }
        signal = shared
            .wake
            .wait_timeout(signal, until - now)
            .unwrap_or_else(PoisonError::into_inner)
            .0;
    }
}

#[cfg(test)]
#[path = "mount_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "bench_tests.rs"]
mod bench;
