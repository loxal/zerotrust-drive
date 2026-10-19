// SPDX-FileCopyrightText: Copyright 2026 Alexander Orlov <info@lifub.com>

//! Opt-in plain (unencrypted) two-way sync between an ordinary local folder
//! and one marked Google Drive folder. Nothing here touches the encrypted
//! store or FUSE.
//!
//! Every cycle applies the Drive changes feed since the last cycle, then
//! pushes local changes found by a scan against the index in
//! [`state`]. The rules that keep user data safe:
//!
//! - A download lands in a `.zdrive-tmp-*` file in the target folder, is
//!   checked against Drive's size and md5 and fsynced, and only then takes
//!   the file's name, and only if the local file is still the one the index
//!   last synced. Otherwise both versions are kept and the remote one gets
//!   the name `name (conflict YYYY-MM-DD HHMMSS host).ext`, locally and on
//!   Drive.
//! - A local deletion moves the Drive file to the Drive bin (recoverable for
//!   30 days). A remote deletion moves the local file into the local trash
//!   (`trash_dir/<UTC time>/<path>`, purged after 30 days); a file that
//!   changed locally is kept and uploaded again instead.
//! - A file modified less than `stable_age` ago is left for a later cycle,
//!   and an upload whose source changes while it is read never completes.
//! - Symlinks, sockets, fifos, devices, other file systems and names that
//!   are not UTF-8 are skipped and counted; `.DS_Store`, `._*` and zdrive's
//!   own `.zdrive-*` names are ignored on both sides.
//!
//! - A cycle moves nothing to the Drive bin when it would bin more than 50
//!   synced items that are also more than a tenth of the index, when every
//!   one of ten or more synced items is missing, or when the local folder
//!   lost its `.zdrive-root-id`: an emptied, replaced or unmounted folder
//!   must not empty Drive. `allow_deletions` releases one reviewed batch.
//! - A Drive folder is binned in one step only while everything below it is
//!   synced and unchanged; otherwise its synced contents are binned one by
//!   one and the folder stays.
//!
//! Names are compared as the exact bytes the OS reports (see [`local`]).
//! Under the default `drive.file` scope zdrive only sees files it created
//! itself, so files added through the Drive web UI do not sync down; with
//! the full `drive` scope they do. A mirror (`PlainOptions::mirror`) syncs
//! all of My Drive under that scope and never renames anything on Drive:
//! duplicate and unrepresentable Drive names get local names of their own,
//! remembered in the index, and zdrive's own folders are left out.

pub(crate) mod cli;
#[cfg(test)]
mod crash_tests;
mod engine;
#[cfg(test)]
mod guard_tests;
mod local;
#[cfg(test)]
mod mirror_tests;
mod prefetch;
mod pull;
mod push;
mod state;
#[cfg(test)]
mod tests;

use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::PathBuf;
use std::time::Duration;

pub(crate) use engine::{sync_once, watch_until_signalled};
pub(crate) use local::{OWN_PREFIX, free_bytes as free_space};
pub(crate) use state::{lock_existing, lock_path};

use crate::remote::RemoteError;
use crate::remote::format::MARKER_NAME;
use crate::remote::gdrive::{
    DriveFile, GoogleDrive, MARKER_KEY, MY_DRIVE, PLAIN_MARKER, STORE_MARKER,
};

/// How old a modification must be before a file is uploaded.
pub(crate) const DEFAULT_STABLE_AGE: Duration = Duration::from_secs(2);

#[derive(Clone, Debug)]
pub(crate) struct PlainOptions {
    /// Canonical absolute local folder (an ordinary folder, no FUSE).
    pub local_dir: PathBuf,
    /// The marked Drive folder.
    pub folder_id: String,
    /// `$XDG_STATE_HOME/zerotrust-drive/plain/<name>.json`; written
    /// atomically as 0600 in a 0700 folder, locked through `<file>.lock`.
    pub state_file: PathBuf,
    /// `$XDG_DATA_HOME/zerotrust-drive/<name>/trash`, the recoverable local
    /// trash with 30-day retention.
    pub trash_dir: PathBuf,
    /// Short host name used in conflict copy names.
    pub host: String,
    /// Files modified more recently than this are left for a later cycle.
    pub stable_age: Duration,
    /// A mirror of all of My Drive: `folder_id` is My Drive's real id, Drive
    /// names that cannot be local names are mapped instead of skipped, and
    /// nothing is ever renamed on Drive to resolve a name clash.
    pub mirror: bool,
    /// Drive deletions this run may apply although the mass-deletion guard
    /// holds them (`zdrive sync --allow-deletions N`); a service never sets
    /// it.
    pub allow_deletions: Option<u64>,
    /// Called every few seconds while a long cycle runs.
    pub progress: Option<fn(&Progress)>,
}

/// What a running cycle has done so far.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct Progress {
    pub downloaded: u64,
    pub download_bytes: u64,
    pub uploaded: u64,
    pub upload_bytes: u64,
    /// New files, and their bytes, this cycle set out to download.
    pub planned: u64,
    pub planned_bytes: u64,
}

#[derive(Debug, Default, Clone)]
pub(crate) struct CycleReport {
    /// Files and folders in the local folder after the cycle.
    pub scanned: u64,
    pub uploaded: u64,
    pub upload_bytes: u64,
    pub downloaded: u64,
    pub download_bytes: u64,
    /// Renames and moves applied in either direction.
    pub moved: u64,
    /// Local deletions moved to the Drive bin (a folder counts once).
    pub remote_trashed: u64,
    /// Remote deletions applied locally: files moved to the local trash
    /// and folders removed once emptied, each counted.
    pub local_trashed: u64,
    pub conflicts: u64,
    /// Folders created locally or on Drive.
    pub folders_created: u64,
    /// Files left for a later cycle because they were still changing.
    pub skipped_unstable: u64,
    /// Local items that are not regular files or folders, and Drive items
    /// without content (Google Docs and the like).
    pub skipped_special: u64,
    /// Indexed items missing locally whose deletion on Drive was held back
    /// by the mass-deletion guard, and why; nothing was moved to the bin.
    pub held_deletions: u64,
    pub held_reason: Option<String>,
    /// Items set aside because Drive refuses this account the step (not
    /// the owner, no download or edit right); retried hours later.
    pub parked: u64,
    /// Drive folders left in place after their synced contents were binned,
    /// because they hold items zdrive does not sync.
    pub kept_folders: u64,
    /// Per-item problems, retried next cycle. Human-readable and may name
    /// relative paths: for the user, not for telemetry.
    pub errors: Vec<String>,
    /// Time spent scanning the local folder.
    pub scan: Duration,
    /// Time spent reading the Drive changes.
    pub remote: Duration,
    pub total: Duration,
}

/// What a mirror of My Drive brings to this computer, as setup shows it
/// before the first download.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct MyDriveSize {
    /// Files with content below My Drive, and their bytes.
    pub files: u64,
    pub bytes: u64,
    /// Google Docs, shortcuts and other items without a file, which stay
    /// on Drive only.
    pub without_content: u64,
}

/// Sizes the My Drive whose real id is `root` with one flat listing,
/// leaving out what a mirror leaves out: zdrive's own folders and items
/// outside My Drive.
pub(crate) fn my_drive_size(drive: &GoogleDrive, root: &str) -> Result<MyDriveSize, RemoteError> {
    const GOOGLE_APPS: &str = "application/vnd.google-apps.";
    let items = drive.list_everything()?;
    let by_id: HashMap<&str, &DriveFile> =
        items.iter().map(|item| (item.id.as_str(), item)).collect();
    let stores: HashSet<&str> = items
        .iter()
        .filter(|item| item.name == MARKER_NAME && !item.is_folder())
        .filter_map(|item| item.parents.first().map(String::as_str))
        .collect();
    let mut inside: HashMap<&str, bool> = HashMap::new();
    let mut size = MyDriveSize::default();
    for item in &items {
        if item.is_folder() || !in_my_drive(item, root, &by_id, &stores, &mut inside) {
            continue;
        }
        if item.mime_type.starts_with(GOOGLE_APPS) || item.md5().is_none() {
            size.without_content += 1;
        } else {
            size.files += 1;
            size.bytes += item.size().unwrap_or(0);
        }
    }
    Ok(size)
}

/// Whether `item`'s first parents lead to `root` without passing one of
/// zdrive's own folders; folder results are remembered in `inside`.
fn in_my_drive<'a>(
    item: &'a DriveFile,
    root: &str,
    by_id: &HashMap<&'a str, &'a DriveFile>,
    stores: &HashSet<&str>,
    inside: &mut HashMap<&'a str, bool>,
) -> bool {
    const MAX_DEPTH: usize = 256;
    let mut chain: Vec<&'a str> = Vec::new();
    let mut current = item;
    let result = loop {
        let Some(parent) = current.parents.first().map(String::as_str) else {
            break false;
        };
        if parent == root {
            break true;
        }
        if let Some(&known) = inside.get(parent) {
            break known;
        }
        let Some(&folder) = by_id.get(parent) else {
            break false;
        };
        let own = matches!(
            folder.app_properties.get(MARKER_KEY).map(String::as_str),
            Some(STORE_MARKER | PLAIN_MARKER)
        );
        if own || stores.contains(parent) || chain.len() >= MAX_DEPTH {
            break false;
        }
        chain.push(folder.id.as_str());
        current = folder;
    };
    for id in chain {
        inside.insert(id, result);
    }
    result
}

#[derive(Clone, Debug)]
pub(crate) enum FolderChoice {
    Existing(DriveFile),
    Created(DriveFile),
}

/// Whether `folder` carries the plain sync marker; a reason otherwise.
pub(crate) fn check_marker(folder: &DriveFile) -> Result<(), String> {
    if !folder.is_folder() {
        return Err(format!("Drive item {} is not a folder", folder.id));
    }
    match folder.app_properties.get(MARKER_KEY).map(String::as_str) {
        Some(PLAIN_MARKER) => Ok(()),
        Some(STORE_MARKER) => Err(format!(
            "Drive folder {} ({}) holds an encrypted zerotrust-drive store; plain sync never writes into it",
            folder.id, folder.name
        )),
        _ => Err(format!(
            "Drive folder {} ({}) is not marked for plain sync (app property {MARKER_KEY}={PLAIN_MARKER}); zdrive only syncs folders it created for that",
            folder.id, folder.name
        )),
    }
}

/// Finds the app-visible folder named `name` under `parent` ("root" = My
/// Drive) carrying the marker, or creates and marks it. Several marked
/// matches => Err listing their ids. An unmarked same-name folder is NOT
/// adopted silently: Err explaining it.
///
/// In My Drive the single marked folder is joined whatever it was renamed
/// to (see `GoogleDrive::find_or_create_marked_folder`), so one Drive
/// account has one plain folder there.
pub(crate) fn find_or_create_folder(
    drive: &GoogleDrive,
    parent: &str,
    name: &str,
) -> Result<FolderChoice, String> {
    if parent != MY_DRIVE {
        return find_or_create_child_folder(drive, parent, name);
    }
    check_folder_name(name)?;
    let marked = drive
        .find_marked_folders(PLAIN_MARKER)
        .map_err(|error| error.to_string())?;
    if marked.iter().all(|folder| folder.trashed) {
        refuse_unmarked(drive, parent, name)?;
    }
    let (folder, created) = drive
        .find_or_create_marked_folder(PLAIN_MARKER, name)
        .map_err(|error| error.to_string())?;
    Ok(if created {
        FolderChoice::Created(folder)
    } else {
        FolderChoice::Existing(folder)
    })
}

/// The marked folder named exactly `name` directly below `parent`, created
/// and marked when absent: for an explicit folder path, where other marked
/// folders elsewhere are irrelevant. Refusals as [`find_or_create_folder`].
/// Matched by listing `parent`, never by comparing `parents` ids: Drive
/// reports My Drive's real id there, not the "root" alias.
pub(crate) fn find_or_create_child_folder(
    drive: &GoogleDrive,
    parent: &str,
    name: &str,
) -> Result<FolderChoice, String> {
    check_folder_name(name)?;
    let (here, unmarked): (Vec<DriveFile>, Vec<DriveFile>) = drive
        .list(parent, true)
        .map_err(|error| error.to_string())?
        .into_iter()
        .filter(|folder| folder.name == name)
        .partition(|folder| check_marker(folder).is_ok());
    match here.len() {
        0 => {
            refuse_namesakes(name, &unmarked)?;
            let id = drive
                .generate_ids(1)
                .map_err(|error| error.to_string())?
                .into_iter()
                .next()
                .ok_or("Drive generated no folder id")?;
            let props = BTreeMap::from([(MARKER_KEY.to_string(), PLAIN_MARKER.to_string())]);
            drive
                .create_folder_with(parent, name, &id, &props)
                .map(FolderChoice::Created)
                .map_err(|error| error.to_string())
        }
        1 => Ok(FolderChoice::Existing(here[0].clone())),
        _ => Err(format!(
            "{} Drive folders named {name:?} are marked for plain sync (ids {}); move all but one to the bin",
            here.len(),
            here.iter()
                .map(|folder| folder.id.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        )),
    }
}

fn check_folder_name(name: &str) -> Result<(), String> {
    if !local::valid_name(name) || local::ignored(name) {
        return Err(format!("{name:?} cannot be the name of a synced folder"));
    }
    Ok(())
}

/// Refuses when `parent` holds a folder named `name` that zdrive did not
/// mark for plain sync: it is never adopted.
fn refuse_unmarked(drive: &GoogleDrive, parent: &str, name: &str) -> Result<(), String> {
    let unmarked: Vec<DriveFile> = drive
        .list(parent, true)
        .map_err(|error| error.to_string())?
        .into_iter()
        .filter(|folder| folder.name == name && check_marker(folder).is_err())
        .collect();
    refuse_namesakes(name, &unmarked)
}

fn refuse_namesakes(name: &str, unmarked: &[DriveFile]) -> Result<(), String> {
    if unmarked.is_empty() {
        return Ok(());
    }
    Err(format!(
        "a Drive folder named {name:?} that zdrive did not create for plain sync already exists (id {}); it is not adopted, so rename it or choose another name",
        unmarked
            .iter()
            .map(|folder| folder.id.as_str())
            .collect::<Vec<_>>()
            .join(", ")
    ))
}
