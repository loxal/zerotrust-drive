// SPDX-FileCopyrightText: Copyright 2026 Alexander Orlov <info@lifub.com>

//! One plain sync cycle, and the loop that repeats it.

use std::collections::{BTreeSet, HashMap, HashSet};
use std::fs::File;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use super::local::{self, Scan, Stat, Trash};
use super::prefetch::Prefetch;
use super::state::{self, Entry, State};
use super::{CycleReport, PlainOptions, Progress, check_marker};
use crate::refusal::{Class, Failure};
use crate::remote::RemoteError;
use crate::remote::gdrive::{DriveFile, GoogleDrive, MY_DRIVE};

const SAVE_EVERY_OPS: u32 = 200;
const SAVE_EVERY: Duration = Duration::from_secs(15);
/// Rewriting a large index every 15 s would cost more than the work it
/// protects; above this many items it is saved at most once a minute.
const LARGE_INDEX: usize = 10_000;
const SAVE_EVERY_LARGE: Duration = Duration::from_secs(60);
const MAX_BACKOFF: Duration = Duration::from_secs(300);
/// How long a cycle keeps working after a stop request before it saves
/// what it did and ends: a first sync can run for hours, and a service
/// manager stops waiting long before.
const STOP_GRACE: Duration = Duration::from_secs(20);
/// Parked items not refused again for this long are forgotten.
const PARKED_RETENTION: i64 = 7 * 24 * 3600;
/// Pause between progress reports of a long cycle.
const PROGRESS_EVERY: Duration = Duration::from_secs(10);

/// Why a cycle ended early. Work done before it is kept in the state; the
/// changes position is not advanced, so the next cycle repeats the rest.
#[derive(Debug)]
pub(super) enum Fatal {
    /// Offline, throttled, unauthorised or a local failure to record state.
    Transient(String),
    /// The Drive folder cannot be synced: gone, in the bin or not marked.
    Refused(String),
    /// A stop request outlasted [`STOP_GRACE`]; the work done is saved.
    Stopped,
}

impl Fatal {
    fn message(self) -> String {
        match self {
            Self::Transient(message) | Self::Refused(message) => message,
            Self::Stopped => {
                "stopped before the cycle finished; the next sync continues where it ended"
                    .to_string()
            }
        }
    }
}

/// Errors that end a cycle rather than one item: without a connection or
/// authorisation every further request would fail the same way.
pub(super) fn ends_cycle(error: &RemoteError) -> bool {
    matches!(error, RemoteError::Network(_) | RemoteError::Auth(_))
}

/// The latest known state of each changed remote item, in first-seen order:
/// its metadata, or `None` once removed or no longer visible.
#[derive(Default)]
pub(super) struct Latest {
    pub(super) items: Vec<(String, Option<DriveFile>)>,
    slots: HashMap<String, usize>,
}

impl Latest {
    fn put(&mut self, id: String, file: Option<DriveFile>) {
        match self.slots.get(&id) {
            Some(&slot) => self.items[slot].1 = file,
            None => {
                self.slots.insert(id.clone(), self.items.len());
                self.items.push((id, file));
            }
        }
    }

    fn contains(&self, id: &str) -> bool {
        self.slots.contains_key(id)
    }
}

/// The working set of one cycle.
pub(super) struct Cycle<'a> {
    pub(super) drive: &'a GoogleDrive,
    pub(super) options: &'a PlainOptions,
    pub(super) root: &'a Path,
    pub(super) state: &'a mut State,
    pub(super) report: CycleReport,
    pub(super) trash: Trash<'a>,
    pub(super) host: String,
    /// Local time stamp of conflict names made in this cycle.
    pub(super) stamp: String,
    /// Exact local names known to exist: the scan, plus what this cycle
    /// created. A path the OS finds but that is not here is another
    /// spelling (case or normalization) of an existing name.
    pub(super) present: BTreeSet<String>,
    /// Unindexed local items by inode, to recognise local renames.
    pub(super) unindexed: HashMap<u64, Stat>,
    /// Drive ids to read again next cycle.
    pub(super) retry: BTreeSet<String>,
    /// Whether phase A changed the local folder, so phase B rescans.
    pub(super) mutated: bool,
    /// The local file system ran short of space: further downloads wait.
    pub(super) disk_short: bool,
    /// Why Drive deletions are held this cycle regardless of their number:
    /// the local folder may not be the one that was synced.
    pub(super) unbound: Option<String>,
    /// Unix seconds at the start of the cycle, for parked items.
    pub(super) now: i64,
    /// Downloads staged ahead of their install, during a mirror's pass.
    pub(super) prefetch: Option<Prefetch>,
    /// New files and bytes the pull set out to download, for progress.
    pub(super) planned: (u64, u64),
    stop: &'a dyn Fn() -> bool,
    ops: u32,
    saved: Instant,
    reported: Instant,
}

impl<'a> Cycle<'a> {
    /// Records a failed step. A connection or authorisation failure ends
    /// the cycle; anything else is reported and retried next cycle.
    pub(super) fn fail(&mut self, what: &str, error: RemoteError) -> Result<(), Fatal> {
        if ends_cycle(&error) {
            return Err(Fatal::Transient(format!("{what}: {error}")));
        }
        self.report.errors.push(format!("{what}: {error}"));
        Ok(())
    }

    /// [`fail`](Self::fail) for a step on Drive item `id`: retried next
    /// cycle, or parked for hours when Drive refuses this account the step,
    /// which retrying every few seconds could not change.
    pub(super) fn fail_item(
        &mut self,
        what: &str,
        id: &str,
        error: RemoteError,
    ) -> Result<(), Fatal> {
        self.fail_versioned(what, id, None, error)
    }

    /// [`fail_item`](Self::fail_item) for a step on `file` as last read.
    pub(super) fn fail_on(
        &mut self,
        what: &str,
        file: &DriveFile,
        error: RemoteError,
    ) -> Result<(), Fatal> {
        self.fail_versioned(what, &file.id, file.version.as_ref(), error)
    }

    fn fail_versioned(
        &mut self,
        what: &str,
        id: &str,
        version: Option<&String>,
        error: RemoteError,
    ) -> Result<(), Fatal> {
        let denied = matches!(error, RemoteError::Denied(_));
        self.fail(what, error)?;
        if denied {
            self.park(id, version);
        } else {
            self.retry.insert(id.to_string());
        }
        Ok(())
    }

    /// Sets `id` aside: Drive refuses this account a step on it. A version
    /// newer than `version` releases it.
    pub(super) fn park(&mut self, id: &str, version: Option<&String>) {
        self.state.park(id, self.now, version);
        self.retry.remove(id);
        self.report.parked += 1;
    }

    pub(super) fn parked(&self, id: &str) -> bool {
        self.state.is_parked(id, self.now)
    }

    pub(super) fn save(&mut self) -> Result<(), Fatal> {
        self.ops = 0;
        self.saved = Instant::now();
        self.state
            .save()
            .map_err(|error| Fatal::Transient(format!("cannot save the sync state: {error}")))
    }

    /// Saves now and then during long cycles, so a crash repeats little,
    /// and ends the cycle once a stop request outlasted its grace.
    pub(super) fn tick(&mut self) -> Result<(), Fatal> {
        self.ops += 1;
        let every = if self.state.len() > LARGE_INDEX {
            SAVE_EVERY_LARGE
        } else {
            SAVE_EVERY
        };
        if self.ops >= SAVE_EVERY_OPS || self.saved.elapsed() >= every {
            self.save()?;
        }
        if let Some(progress) = self.options.progress
            && self.reported.elapsed() >= PROGRESS_EVERY
        {
            self.reported = Instant::now();
            progress(&Progress {
                downloaded: self.report.downloaded,
                download_bytes: self.report.download_bytes,
                uploaded: self.report.uploaded,
                upload_bytes: self.report.upload_bytes,
                planned: self.planned.0,
                planned_bytes: self.planned.1,
            });
        }
        if (self.stop)() {
            return Err(Fatal::Stopped);
        }
        Ok(())
    }

    /// Whether the indexed item now lives, unindexed, under another local
    /// name.
    pub(super) fn renamed_locally(&self, entry: &Entry) -> bool {
        self.unindexed
            .get(&entry.inode)
            .is_some_and(|stat| entry.same_item(stat))
    }

    /// Checks by its `.zdrive-root-id` that the local folder is the one the
    /// index was bound to; a folder replaced by another file system with
    /// the same root inode, or restored without that file, is not. The file
    /// is (re)written while that is safe: for a new index, while nothing
    /// indexed is missing, for the index of a zdrive before 0.19 while some
    /// indexed item is present, and on an explicit `--allow-deletions`.
    /// Otherwise Drive deletions are held for this cycle.
    fn bind_root(&mut self, scan: &Scan) -> Result<(), Fatal> {
        let read = local::read_root_id(self.root)
            .map_err(|error| Fatal::Transient(format!("read {}: {error}", local::ROOT_ID_FILE)))?;
        if read.is_some() && read == self.state.root_id {
            return Ok(());
        }
        let entries = self.state.entries();
        let missing = entries
            .keys()
            .any(|rel| scan.readable(rel) && !scan.items.contains_key(rel.as_str()));
        let present = entries
            .keys()
            .any(|rel| scan.items.contains_key(rel.as_str()));
        let safe = entries.is_empty()
            || !missing
            || (self.state.root_id.is_none() && present)
            || self.options.allow_deletions.is_some();
        if !safe {
            self.unbound = Some(match read {
                None => format!("it has no {}", local::ROOT_ID_FILE),
                Some(_) => format!("its {} belongs to another sync", local::ROOT_ID_FILE),
            });
            return Ok(());
        }
        let id = local::write_root_id(self.root)
            .map_err(|error| Fatal::Transient(format!("write {}: {error}", local::ROOT_ID_FILE)))?;
        self.state.root_id = Some(id);
        self.save()
    }

    fn adopt_scan(&mut self, scan: &Scan) {
        self.present = scan.items.keys().cloned().collect();
        self.unindexed = scan
            .items
            .iter()
            .filter(|(rel, _)| self.state.entry(rel).is_none())
            .map(|(_, stat)| (stat.inode, *stat))
            .collect();
    }

    /// The remote changes since the last cycle, or the whole remote tree on
    /// the first cycle, plus the items queued for another look.
    fn fetch_delta(&mut self) -> Result<(Latest, String, bool), Fatal> {
        let mut latest = Latest::default();
        let (token, bootstrap) = match self.state.start_page_token.clone() {
            Some(token) => match self.changes_since(&token, &mut latest) {
                Ok(next) => (next, false),
                Err(error) if ends_cycle(&error) => {
                    return Err(Fatal::Transient(format!("read the Drive changes: {error}")));
                }
                Err(error) => {
                    self.report.errors.push(format!(
                        "the Drive changes feed refused the saved position ({error}); listing the whole folder again"
                    ));
                    latest = Latest::default();
                    (self.list_tree(&mut latest)?, true)
                }
            },
            None => (self.list_tree(&mut latest)?, true),
        };
        // Parked items whose pause ended are read again like retries.
        let now = self.now;
        self.state
            .parked
            .retain(|_, parked| parked.until + PARKED_RETENTION > now);
        let due: Vec<String> = self
            .state
            .parked
            .iter()
            .filter(|(_, parked)| parked.until <= now)
            .map(|(id, _)| id.clone())
            .collect();
        let retry: Vec<String> = self.state.retry.iter().cloned().chain(due).collect();
        for id in retry {
            if latest.contains(&id) {
                continue;
            }
            match self.drive.get(&id) {
                Ok(file) => latest.put(id, Some(file)),
                Err(RemoteError::NotFound(_)) => latest.put(id, None),
                Err(error) => {
                    self.fail("read a Drive item again", error)?;
                    self.retry.insert(id);
                }
            }
        }
        Ok((latest, token, bootstrap))
    }

    fn changes_since(&mut self, token: &str, latest: &mut Latest) -> Result<String, RemoteError> {
        let mut token = token.to_string();
        loop {
            let page = self.drive.changes_page(&token)?;
            for change in page.changes {
                let file = match (change.removed, change.file) {
                    (true, _) => None,
                    (false, Some(file)) => Some(file),
                    (false, None) => match self.drive.get(&change.file_id) {
                        Ok(file) => Some(file),
                        Err(RemoteError::NotFound(_)) => None,
                        Err(error) => return Err(error),
                    },
                };
                latest.put(change.file_id, file);
            }
            match (page.next_page_token, page.new_start_page_token) {
                (Some(next), _) => token = next,
                (None, Some(start)) => return Ok(start),
                (None, None) => {
                    return Err(RemoteError::Protocol(
                        "changes page without a continuation".to_string(),
                    ));
                }
            }
        }
    }

    /// Lists the whole remote tree. The changes token is taken first, so
    /// nothing changed during the listing is missed. A listing must be
    /// complete: anything indexed but not listed counts as removed.
    fn list_tree(&mut self, latest: &mut Latest) -> Result<String, Fatal> {
        let transient =
            |what: &str, error: RemoteError| Fatal::Transient(format!("{what}: {error}"));
        let token = self
            .drive
            .changes_start_token()
            .map_err(|error| transient("read the Drive changes position", error))?;
        let mut listed = HashSet::new();
        if self.options.mirror {
            // The children of many folders per request instead of one
            // request per folder; zdrive's own folders are not entered.
            let everything = self
                .drive
                .list_below(&self.state.folder_id, &|folder| !super::own_folder(folder))
                .map_err(|error| transient("list My Drive", error))?;
            for item in everything {
                listed.insert(item.id.clone());
                latest.put(item.id.clone(), Some(item));
            }
            self.forget_unlisted(&listed, latest);
            return Ok(token);
        }
        let mut queue = vec![self.state.folder_id.clone()];
        while let Some(parent) = queue.pop() {
            let children = self
                .drive
                .list(&parent, false)
                .map_err(|error| transient("list the Drive folder", error))?;
            for child in children {
                if child.is_folder()
                    && local::valid_name(&child.name)
                    && !local::ignored(&child.name)
                {
                    queue.push(child.id.clone());
                }
                listed.insert(child.id.clone());
                latest.put(child.id.clone(), Some(child));
            }
        }
        self.forget_unlisted(&listed, latest);
        Ok(token)
    }

    /// A listing is complete: anything indexed but not listed is removed.
    fn forget_unlisted(&self, listed: &HashSet<String>, latest: &mut Latest) {
        let gone: Vec<String> = self
            .state
            .entries()
            .values()
            .filter(|entry| !listed.contains(&entry.id))
            .map(|entry| entry.id.clone())
            .collect();
        for id in gone {
            latest.put(id, None);
        }
    }

    /// Puts what this cycle learned into the state after a fatal error, so
    /// the next cycle does not repeat finished work.
    fn abort(&mut self, fatal: Fatal) -> Fatal {
        let retry = std::mem::take(&mut self.retry);
        self.state.retry.extend(retry);
        match self.save() {
            Ok(()) => fatal,
            Err(save) => Fatal::Transient(format!("{}; {}", fatal.message(), save.message())),
        }
    }
}

/// An open instance: the lock, and the state it protects.
struct Session<'a> {
    options: &'a PlainOptions,
    state: State,
    excluded: Vec<PathBuf>,
    _lock: File,
}

impl<'a> Session<'a> {
    fn open(options: &'a PlainOptions) -> Result<Self, String> {
        let (state, lock) = state::open(options)?;
        let mut excluded = vec![options.trash_dir.clone()];
        if let Some(parent) = options.state_file.parent() {
            excluded.push(parent.to_path_buf());
        }
        excluded.retain(|path| path.starts_with(&options.local_dir));
        Ok(Self {
            options,
            state,
            excluded,
            _lock: lock,
        })
    }

    fn cycle(
        &mut self,
        drive: &GoogleDrive,
        stop: &dyn Fn() -> bool,
    ) -> Result<CycleReport, Fatal> {
        let started = Instant::now();
        let options = self.options;
        let root = options.local_dir.as_path();
        if options.mirror {
            verify_my_drive(drive, &options.folder_id)?;
        } else {
            verify_folder(drive, &options.folder_id)?;
        }
        crate::remote::ensure_private_dir(&options.trash_dir)
            .map_err(|error| Fatal::Transient(error.to_string()))?;
        let mut report = CycleReport::default();
        let now = local::now_secs();
        for base in [options.trash_dir.clone(), root.join(local::FALLBACK_TRASH)] {
            if let Err(error) = local::purge(&base, now) {
                report
                    .errors
                    .push(format!("cannot purge the trash: {error}"));
            }
        }
        let excluded = &self.excluded;
        let scan_started = Instant::now();
        let mut scan = local::scan(root, excluded).map_err(Fatal::Transient)?;
        let mut cycle = Cycle {
            drive,
            options,
            root,
            state: &mut self.state,
            report,
            trash: Trash::new(&options.trash_dir, root),
            host: local::host_tag(&options.host),
            stamp: local::local_stamp(now),
            present: BTreeSet::new(),
            unindexed: HashMap::new(),
            retry: BTreeSet::new(),
            mutated: false,
            disk_short: false,
            unbound: None,
            now,
            prefetch: None,
            planned: (0, 0),
            stop,
            ops: 0,
            saved: Instant::now(),
            reported: Instant::now(),
        };
        if !scan.debris.is_empty() {
            let errors = local::recover_debris(root, &scan.debris, &mut cycle.trash);
            cycle.report.errors.extend(errors);
            scan = local::scan(root, excluded).map_err(Fatal::Transient)?;
        }
        cycle.report.scan = scan_started.elapsed();
        if let Err(fatal) = cycle.bind_root(&scan) {
            return Err(cycle.abort(fatal));
        }
        cycle.adopt_scan(&scan);
        let remote_started = Instant::now();
        let (latest, token, bootstrap) = match cycle.fetch_delta() {
            Ok(delta) => delta,
            Err(fatal) => return Err(cycle.abort(fatal)),
        };
        cycle.report.remote = remote_started.elapsed();
        if let Err(fatal) = cycle.pull(latest.items, bootstrap) {
            return Err(cycle.abort(fatal));
        }
        if cycle.mutated {
            let rescan_started = Instant::now();
            scan = match local::scan(root, excluded) {
                Ok(scan) => scan,
                Err(error) => return Err(cycle.abort(Fatal::Transient(error))),
            };
            cycle.report.scan += rescan_started.elapsed();
        }
        if let Err(fatal) = cycle.push(&scan) {
            return Err(cycle.abort(fatal));
        }
        cycle.state.start_page_token = Some(token);
        cycle.state.retry = std::mem::take(&mut cycle.retry);
        cycle.save()?;
        let mut report = cycle.report;
        report.scanned = scan.items.len() as u64;
        report.skipped_special += scan.special;
        report.errors.extend(scan.errors);
        report.total = started.elapsed();
        Ok(report)
    }
}

/// Refuses a mirror whose folder is not this account's My Drive, or that
/// lost the full Drive access a mirror needs.
fn verify_my_drive(drive: &GoogleDrive, id: &str) -> Result<(), Fatal> {
    let root = drive.get(MY_DRIVE).map_err(|error| match error {
        RemoteError::NotFound(_) => Fatal::Refused(
            "My Drive is not visible to zdrive: a mirror needs full Drive access; run `zdrive remote auth --mirror` again".to_string(),
        ),
        other => Fatal::Transient(format!("read My Drive: {other}")),
    })?;
    if root.id != id {
        return Err(Fatal::Refused(format!(
            "this mirror belongs to the My Drive {id}, but the signed-in account's My Drive is {}; sign in with the account the mirror was set up with",
            root.id
        )));
    }
    Ok(())
}

/// Refuses a Drive folder that is gone, in the bin or not marked for plain
/// sync.
fn verify_folder(drive: &GoogleDrive, id: &str) -> Result<(), Fatal> {
    let folder = drive.get(id).map_err(|error| match error {
        RemoteError::NotFound(_) => Fatal::Refused(format!(
            "the Drive folder {id} no longer exists or is not visible to zdrive"
        )),
        other => Fatal::Transient(format!("read the Drive folder: {other}")),
    })?;
    if folder.trashed {
        return Err(Fatal::Refused(format!(
            "the Drive folder {id} ({}) is in the Drive bin; restore it to keep syncing",
            folder.name
        )));
    }
    check_marker(&folder).map_err(Fatal::Refused)
}

/// Runs one sync cycle: remote changes are applied locally, then local
/// changes are pushed.
pub(crate) fn sync_once(
    drive: &GoogleDrive,
    options: &PlainOptions,
) -> Result<CycleReport, String> {
    let mut session = Session::open(options)?;
    session.cycle(drive, &|| false).map_err(Fatal::message)
}

/// Loops: a cycle now, then every `interval`, until `stop()` returns true;
/// then runs one final cycle and returns. `on_cycle` is called after each
/// cycle (Ok or Err). Errors in a cycle are retried next interval with
/// capped backoff (offline tolerant), never exit the loop.
///
/// Only opening the instance (lock, state binding) and a refused Drive
/// folder before any cycle succeeded return early with `Err`; the refused
/// folder is classed, because it stays refused until the operator acts.
pub(crate) fn watch(
    drive: &GoogleDrive,
    options: &PlainOptions,
    interval: Duration,
    stop: &dyn Fn() -> bool,
    on_cycle: &mut dyn FnMut(&Result<CycleReport, String>),
) -> Result<(), Failure> {
    watch_with_grace(drive, options, interval, STOP_GRACE, stop, on_cycle)
}

/// [`watch`] with how long a running cycle may go on after `stop()`
/// first returned true.
pub(super) fn watch_with_grace(
    drive: &GoogleDrive,
    options: &PlainOptions,
    interval: Duration,
    grace: Duration,
    stop: &dyn Fn() -> bool,
    on_cycle: &mut dyn FnMut(&Result<CycleReport, String>),
) -> Result<(), Failure> {
    let mut session = Session::open(options)?;
    let mut failures = 0u32;
    let mut synced = false;
    // A cycle that is still running when the stop request comes finishes
    // within STOP_GRACE; the final cycle gets what is left of it.
    let requested: std::cell::Cell<Option<Instant>> = std::cell::Cell::new(None);
    let overdue = || {
        if !stop() {
            return false;
        }
        let since = requested.get().unwrap_or_else(|| {
            let now = Instant::now();
            requested.set(Some(now));
            now
        });
        since.elapsed() >= grace
    };
    loop {
        let result = session.cycle(drive, &overdue);
        if !synced && let Err(Fatal::Refused(message)) = &result {
            let message = message.clone();
            on_cycle(&Err(message.clone()));
            return Err(Failure::refused(Class::DriveFolder, message));
        }
        synced |= result.is_ok();
        if matches!(result, Err(Fatal::Stopped)) {
            on_cycle(&result.map_err(Fatal::message));
            return Ok(());
        }
        let result = result.map_err(Fatal::message);
        failures = if result.is_ok() {
            0
        } else {
            failures.saturating_add(1)
        };
        on_cycle(&result);
        if wait(stop, backoff(interval, failures)) {
            break;
        }
    }
    let result = session.cycle(drive, &overdue).map_err(Fatal::message);
    on_cycle(&result);
    Ok(())
}

/// [`watch`] until SIGINT or SIGTERM: the first signal finishes the current
/// cycle and runs a final one, a second exits at once. Requires
/// `shutdown::install()` and no FUSE mount in this process.
pub(crate) fn watch_until_signalled(
    drive: &GoogleDrive,
    options: &PlainOptions,
    interval: Duration,
    on_cycle: &mut dyn FnMut(&Result<CycleReport, String>),
) -> Result<(), Failure> {
    crate::shutdown::stoppable();
    watch(
        drive,
        options,
        interval,
        &crate::shutdown::stop_requested,
        on_cycle,
    )
}

/// The pause after a cycle: `interval`, doubled per consecutive failure up
/// to 32 times, capped at five minutes (or `interval` when that is longer).
fn backoff(interval: Duration, failures: u32) -> Duration {
    if failures == 0 {
        return interval;
    }
    let factor = 1u32 << (failures - 1).min(5);
    interval
        .saturating_mul(factor)
        .min(MAX_BACKOFF.max(interval))
}

/// Sleeps up to `total` in short slices; true as soon as `stop` says so.
fn wait(stop: &dyn Fn() -> bool, total: Duration) -> bool {
    let deadline = Instant::now() + total;
    loop {
        if stop() {
            return true;
        }
        let now = Instant::now();
        if now >= deadline {
            return false;
        }
        std::thread::sleep((deadline - now).min(Duration::from_millis(100)));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backoff_doubles_per_failure_up_to_a_cap() {
        let second = Duration::from_secs(1);
        assert_eq!(backoff(second, 0), second);
        assert_eq!(backoff(second, 1), second);
        assert_eq!(backoff(second, 2), 2 * second);
        assert_eq!(backoff(second, 6), 32 * second);
        assert_eq!(backoff(second, 60), 32 * second);
        assert_eq!(backoff(Duration::from_secs(60), 9), MAX_BACKOFF);
        assert_eq!(
            backoff(Duration::from_secs(600), 9),
            Duration::from_secs(600)
        );
    }
}
