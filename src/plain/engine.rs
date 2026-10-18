// SPDX-FileCopyrightText: Copyright 2026 Alexander Orlov <info@lifub.com>

//! One plain sync cycle, and the loop that repeats it.

use std::collections::{BTreeSet, HashMap, HashSet};
use std::fs::File;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use super::local::{self, Scan, Stat, Trash};
use super::state::{self, Entry, State};
use super::{CycleReport, PlainOptions, check_marker};
use crate::remote::RemoteError;
use crate::remote::gdrive::{DriveFile, GoogleDrive};

const SAVE_EVERY_OPS: u32 = 200;
const SAVE_EVERY: Duration = Duration::from_secs(15);
const MAX_BACKOFF: Duration = Duration::from_secs(300);

/// Why a cycle ended early. Work done before it is kept in the state; the
/// changes position is not advanced, so the next cycle repeats the rest.
#[derive(Debug)]
pub(super) enum Fatal {
    /// Offline, throttled, unauthorised or a local failure to record state.
    Transient(String),
    /// The Drive folder cannot be synced: gone, in the bin or not marked.
    Refused(String),
}

impl Fatal {
    fn message(self) -> String {
        match self {
            Self::Transient(message) | Self::Refused(message) => message,
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
    ops: u32,
    saved: Instant,
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

    pub(super) fn save(&mut self) -> Result<(), Fatal> {
        self.ops = 0;
        self.saved = Instant::now();
        self.state
            .save()
            .map_err(|error| Fatal::Transient(format!("cannot save the sync state: {error}")))
    }

    /// Saves now and then during long cycles, so a crash repeats little.
    pub(super) fn tick(&mut self) -> Result<(), Fatal> {
        self.ops += 1;
        if self.ops >= SAVE_EVERY_OPS || self.saved.elapsed() >= SAVE_EVERY {
            self.save()?;
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
        let retry: Vec<String> = self.state.retry.iter().cloned().collect();
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
        Ok(token)
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

    fn cycle(&mut self, drive: &GoogleDrive) -> Result<CycleReport, Fatal> {
        let started = Instant::now();
        let options = self.options;
        let root = options.local_dir.as_path();
        verify_folder(drive, &options.folder_id)?;
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
            ops: 0,
            saved: Instant::now(),
        };
        if !scan.debris.is_empty() {
            let errors = local::recover_debris(root, &scan.debris, &mut cycle.trash);
            cycle.report.errors.extend(errors);
            scan = local::scan(root, excluded).map_err(Fatal::Transient)?;
        }
        cycle.report.scan = scan_started.elapsed();
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
    session.cycle(drive).map_err(Fatal::message)
}

/// Loops: a cycle now, then every `interval`, until `stop()` returns true;
/// then runs one final cycle and returns. `on_cycle` is called after each
/// cycle (Ok or Err). Errors in a cycle are retried next interval with
/// capped backoff (offline tolerant), never exit the loop.
///
/// Only opening the instance (lock, state binding) and a refused Drive
/// folder before any cycle succeeded return early with `Err`.
pub(crate) fn watch(
    drive: &GoogleDrive,
    options: &PlainOptions,
    interval: Duration,
    stop: &dyn Fn() -> bool,
    on_cycle: &mut dyn FnMut(&Result<CycleReport, String>),
) -> Result<(), String> {
    let mut session = Session::open(options)?;
    let mut failures = 0u32;
    let mut synced = false;
    loop {
        let result = session.cycle(drive);
        if !synced && let Err(Fatal::Refused(message)) = &result {
            let message = message.clone();
            on_cycle(&Err(message.clone()));
            return Err(message);
        }
        synced |= result.is_ok();
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
    let result = session.cycle(drive).map_err(Fatal::message);
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
) -> Result<(), String> {
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
