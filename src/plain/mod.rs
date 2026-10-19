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
//! Names are compared as the exact bytes the OS reports (see [`local`]).
//! Under the default `drive.file` scope zdrive only sees files it created
//! itself, so files added through the Drive web UI do not sync down; with
//! the full `drive` scope they do.

pub(crate) mod cli;
#[cfg(test)]
mod crash_tests;
mod engine;
mod local;
mod pull;
mod push;
mod state;
#[cfg(test)]
mod tests;

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::time::Duration;

pub(crate) use engine::{sync_once, watch_until_signalled};
pub(crate) use state::{lock_existing, lock_path};

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
    /// Per-item problems, retried next cycle. Human-readable and may name
    /// relative paths: for the user, not for telemetry.
    pub errors: Vec<String>,
    /// Time spent scanning the local folder.
    pub scan: Duration,
    /// Time spent reading the Drive changes.
    pub remote: Duration,
    pub total: Duration,
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
