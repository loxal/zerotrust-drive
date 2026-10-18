// SPDX-FileCopyrightText: Copyright 2026 Alexander Orlov <info@lifub.com>

//! Phase B of a cycle: pushing local changes to Drive.
//!
//! A remote step is taken only after re-reading the remote item, so a
//! change made on Drive after this cycle's changes were read is never
//! overwritten or deleted: the item is retried next cycle, whose phase A
//! sees that change first.

use std::collections::{BTreeSet, HashMap};

use super::engine::{Cycle, Fatal};
use super::local::{self, Kind, Scan, Stat, split_rel, within};
use super::state::Entry;
use crate::remote::RemoteError;
use crate::remote::gdrive::DriveFile;
use crate::remote::hex;

/// Ids reserved per `generateIds` request (Drive's maximum).
const ID_BATCH: usize = 1000;

fn md5_hex(file: &DriveFile) -> Option<String> {
    file.md5().map(|md5| hex(&md5))
}

impl Cycle<'_> {
    pub(super) fn push(&mut self, scan: &Scan) -> Result<(), Fatal> {
        let same_kind = |entry: &Entry, stat: &Stat| entry.dir == (stat.kind == Kind::Dir);
        // Indexed items no longer found locally. Nothing below an
        // unreadable folder counts as gone.
        let mut missing: BTreeSet<String> = self
            .state
            .entries()
            .iter()
            .filter(|(rel, entry)| {
                scan.readable(rel)
                    && !scan
                        .items
                        .get(rel.as_str())
                        .is_some_and(|stat| same_kind(entry, stat))
            })
            .map(|(rel, _)| rel.clone())
            .collect();
        let by_inode: HashMap<u64, String> = missing
            .iter()
            .filter_map(|rel| {
                let entry = self.state.entry(rel)?;
                (entry.inode != 0).then(|| (entry.inode, rel.clone()))
            })
            .collect();
        let renamed_from = |state: &super::state::State, stat: &Stat| -> Option<String> {
            let old = by_inode.get(&stat.inode)?;
            state
                .entry(old)
                .is_some_and(|entry| entry.same_item(stat))
                .then(|| old.clone())
        };
        // Phase A has adopted any create of an earlier cycle that reached
        // Drive, so ids reserved for paths that are gone are free to drop.
        let stale: Vec<String> = self
            .state
            .pending
            .keys()
            .filter(|rel| {
                !scan.items.contains_key(rel.as_str())
                    || self
                        .state
                        .entry(rel)
                        .is_some_and(|entry| same_kind(entry, &scan.items[rel.as_str()]))
            })
            .cloned()
            .collect();
        for rel in stale {
            self.state.pending.remove(&rel);
        }
        // Reserve ids before creating anything, and record them, so an
        // interrupted create is recognised instead of repeated.
        let fresh: Vec<String> = scan
            .items
            .iter()
            .filter(|(rel, stat)| {
                !self
                    .state
                    .entry(rel)
                    .is_some_and(|entry| same_kind(entry, stat))
                    && !self.state.pending.contains_key(rel.as_str())
                    && renamed_from(self.state, stat).is_none()
            })
            .map(|(rel, _)| rel.clone())
            .collect();
        for chunk in fresh.chunks(ID_BATCH) {
            match self.drive.generate_ids(chunk.len()) {
                Ok(ids) => {
                    for (rel, id) in chunk.iter().zip(ids) {
                        self.state.pending.insert(rel.clone(), id);
                    }
                }
                Err(error) => {
                    self.fail("reserve Drive ids", error)?;
                    break;
                }
            }
        }
        if !fresh.is_empty() {
            self.save()?;
        }
        // Parents sort before their contents.
        let mut blocked: Vec<String> = Vec::new();
        for (rel, stat) in &scan.items {
            if blocked.iter().any(|top| within(rel, top)) {
                continue;
            }
            if let Some(entry) = self.state.entry(rel).cloned() {
                if same_kind(&entry, stat) {
                    if entry.dir {
                        if let Some(entry) = self.state.entry_mut(rel) {
                            entry.inode = stat.inode;
                        }
                    } else if !entry.unchanged(stat) {
                        self.push_content(rel, &entry, stat)?;
                    }
                    continue;
                }
                // A file became a folder or the other way round.
                missing.remove(rel);
                if !self.trash_remote(rel, &entry)? {
                    blocked.push(rel.clone());
                    continue;
                }
            }
            let (parent_rel, name) = split_rel(rel);
            let Some(parent_id) = self.state.dir_id(parent_rel) else {
                blocked.push(rel.clone());
                continue;
            };
            if let Some(old) = renamed_from(self.state, stat)
                && missing.contains(&old)
                && self.push_move(&old, rel, &parent_id, name, stat, &mut missing)?
            {
                continue;
            }
            if !self.create(rel, name, &parent_id, stat)? {
                blocked.push(rel.clone());
            }
        }
        let mut refused: Vec<String> = Vec::new();
        for rel in missing {
            if refused.iter().any(|top| within(&rel, top)) {
                continue;
            }
            let Some(entry) = self.state.entry(&rel).cloned() else {
                continue;
            };
            if !matches!(local::lstat(&self.root.join(&rel)), Ok(None)) {
                continue;
            }
            if !self.trash_remote(&rel, &entry)? {
                refused.push(rel);
            }
        }
        Ok(())
    }

    /// Uploads new content of the indexed file at `rel`.
    fn push_content(&mut self, rel: &str, entry: &Entry, stat: &Stat) -> Result<(), Fatal> {
        if stat.recent(self.options.stable_age) {
            self.report.skipped_unstable += 1;
            return Ok(());
        }
        let path = self.root.join(rel);
        let local_md5 = match md5_stable(&path, stat) {
            Ok(Some(md5)) => md5,
            Ok(None) => {
                self.report.skipped_unstable += 1;
                return Ok(());
            }
            Err(error) => {
                self.report
                    .errors
                    .push(format!("cannot read {rel}: {error}"));
                return Ok(());
            }
        };
        if Some(&local_md5) == entry.md5.as_ref() {
            if let Some(entry) = self.state.entry_mut(rel) {
                entry.set_stat(stat);
            }
            return self.tick();
        }
        let remote = match self.drive.get(&entry.id) {
            Ok(remote) => remote,
            Err(RemoteError::NotFound(_)) => {
                // Deleted on Drive for good; uploaded as new next cycle.
                self.state.remove(rel);
                return Ok(());
            }
            Err(error) => {
                self.fail(&format!("read the Drive copy of {rel}"), error)?;
                self.retry.insert(entry.id.clone());
                return Ok(());
            }
        };
        if remote.trashed || md5_hex(&remote) != entry.md5 {
            // Changed on Drive too: next cycle's phase A keeps both.
            self.retry.insert(entry.id.clone());
            return Ok(());
        }
        match self.drive.update_content(&entry.id, &path) {
            Ok(updated) => {
                if let Some(indexed) = self.state.entry_mut(rel) {
                    indexed.md5 = md5_hex(&updated).or(Some(local_md5));
                    indexed.set_stat(stat);
                    indexed.version = updated.version.clone();
                    indexed.modified = updated.modified_time.clone();
                }
                self.report.uploaded += 1;
                self.report.upload_bytes += updated.size().unwrap_or(stat.size);
            }
            Err(RemoteError::Local(message)) => {
                if local::lstat(&path).ok().flatten().as_ref() != Some(stat) {
                    self.report.skipped_unstable += 1;
                } else {
                    self.report.errors.push(format!("upload {rel}: {message}"));
                }
            }
            Err(error) => {
                self.fail(&format!("upload {rel}"), error)?;
                self.retry.insert(entry.id.clone());
            }
        }
        self.tick()
    }

    /// The indexed item at `old` was renamed or moved locally to `rel`.
    /// False when its Drive copy is gone, so it is created as new instead.
    fn push_move(
        &mut self,
        old: &str,
        rel: &str,
        parent_id: &str,
        name: &str,
        stat: &Stat,
        missing: &mut BTreeSet<String>,
    ) -> Result<bool, Fatal> {
        let Some(entry) = self.state.entry(old).cloned() else {
            return Ok(false);
        };
        let forget = |missing: &mut BTreeSet<String>| missing.retain(|path| !within(path, old));
        let remote = match self.drive.get(&entry.id) {
            Ok(remote) if !remote.trashed => remote,
            Ok(_) | Err(RemoteError::NotFound(_)) => {
                self.state.remove_tree(old);
                forget(missing);
                return Ok(false);
            }
            Err(error) => {
                forget(missing);
                self.fail(&format!("read the Drive copy of {old}"), error)?;
                self.retry.insert(entry.id.clone());
                return Ok(true);
            }
        };
        let current = remote.parents.first().map(String::as_str);
        let add = (current != Some(parent_id)).then_some(parent_id);
        let remove = if add.is_some() { current } else { None };
        let new_name = (remote.name != name).then_some(name);
        if (add.is_some() || new_name.is_some())
            && let Err(error) = self.drive.update_metadata(&entry.id, new_name, add, remove)
        {
            forget(missing);
            self.fail(&format!("move {old} to {rel} on Drive"), error)?;
            self.retry.insert(entry.id.clone());
            return Ok(true);
        }
        self.state.rename_tree(old, rel);
        if let Some(moved) = self.state.entry_mut(rel) {
            moved.inode = stat.inode;
        }
        forget(missing);
        self.report.moved += 1;
        self.tick()?;
        Ok(true)
    }

    /// Creates the unindexed local item `rel` on Drive under its reserved
    /// id. False when a folder could not be created, so its contents wait.
    fn create(
        &mut self,
        rel: &str,
        name: &str,
        parent_id: &str,
        stat: &Stat,
    ) -> Result<bool, Fatal> {
        let folder = stat.kind == Kind::Dir;
        if !folder && stat.recent(self.options.stable_age) {
            self.report.skipped_unstable += 1;
            return Ok(true);
        }
        let id = match self.state.pending.get(rel).cloned() {
            Some(id) => id,
            None => match self.drive.generate_ids(1) {
                Ok(ids) => {
                    let Some(id) = ids.into_iter().next() else {
                        return Ok(false);
                    };
                    self.state.pending.insert(rel.to_string(), id.clone());
                    self.save()?;
                    id
                }
                Err(error) => {
                    self.fail("reserve a Drive id", error)?;
                    return Ok(false);
                }
            },
        };
        let path = self.root.join(rel);
        if folder {
            match self.drive.create_folder(parent_id, name, &id) {
                Ok(created) => {
                    self.state.pending.remove(rel);
                    self.state.insert(
                        rel,
                        Entry {
                            id,
                            dir: true,
                            inode: stat.inode,
                            version: created.version,
                            modified: created.modified_time,
                            ..Entry::default()
                        },
                    );
                    self.report.folders_created += 1;
                }
                Err(RemoteError::Conflict(message)) => {
                    // The reserved id names something else on Drive.
                    self.state.pending.remove(rel);
                    self.report
                        .errors
                        .push(format!("create the folder {rel}: {message}"));
                    return Ok(false);
                }
                Err(error) => {
                    self.fail(&format!("create the folder {rel}"), error)?;
                    return Ok(false);
                }
            }
            self.tick()?;
            return Ok(true);
        }
        match self.drive.create_file(parent_id, name, Some(&id), &path) {
            Ok(created) => {
                self.state.pending.remove(rel);
                let mut entry = Entry {
                    id,
                    md5: md5_hex(&created),
                    version: created.version.clone(),
                    modified: created.modified_time.clone(),
                    ..Entry::default()
                };
                entry.set_stat(stat);
                self.state.insert(rel, entry);
                self.report.uploaded += 1;
                self.report.upload_bytes += created.size().unwrap_or(stat.size);
            }
            Err(RemoteError::Conflict(message)) => {
                self.adopt_created(rel, name, parent_id, &id, &message)?
            }
            Err(RemoteError::Local(message)) => {
                if local::lstat(&path).ok().flatten().as_ref() != Some(stat) {
                    self.report.skipped_unstable += 1;
                } else {
                    self.report.errors.push(format!("upload {rel}: {message}"));
                }
            }
            Err(error) => self.fail(&format!("upload {rel}"), error)?,
        }
        self.tick()?;
        Ok(true)
    }

    /// The reserved id already exists on Drive with other content: an
    /// earlier create that completed before the file changed. It is
    /// adopted with an unknown local stat, so the next cycle compares and
    /// uploads the current content; anything else releases the id.
    fn adopt_created(
        &mut self,
        rel: &str,
        name: &str,
        parent_id: &str,
        id: &str,
        message: &str,
    ) -> Result<(), Fatal> {
        match self.drive.get(id) {
            Ok(existing)
                if !existing.trashed
                    && existing.name == name
                    && existing.parents.iter().any(|parent| parent == parent_id) =>
            {
                self.state.pending.remove(rel);
                self.state.insert(
                    rel,
                    Entry {
                        id: id.to_string(),
                        md5: md5_hex(&existing),
                        size: existing.size().unwrap_or(0),
                        version: existing.version.clone(),
                        modified: existing.modified_time.clone(),
                        ..Entry::default()
                    },
                );
                Ok(())
            }
            Ok(_) | Err(RemoteError::NotFound(_)) => {
                self.state.pending.remove(rel);
                self.report.errors.push(format!("upload {rel}: {message}"));
                Ok(())
            }
            Err(error) => self.fail(&format!("read the Drive copy of {rel}"), error),
        }
    }

    /// Moves the Drive copy of the item indexed at `rel`, which is gone
    /// locally, to the Drive bin. False (retried next cycle) when Drive
    /// changed it since: an edit or move there wins over the deletion.
    fn trash_remote(&mut self, rel: &str, entry: &Entry) -> Result<bool, Fatal> {
        let remote = match self.drive.get(&entry.id) {
            Ok(remote) => remote,
            Err(RemoteError::NotFound(_)) => {
                self.state.remove_tree(rel);
                return Ok(true);
            }
            Err(error) => {
                self.fail(&format!("read the Drive copy of {rel}"), error)?;
                self.retry.insert(entry.id.clone());
                return Ok(false);
            }
        };
        if remote.trashed {
            self.state.remove_tree(rel);
            return Ok(true);
        }
        let (parent_rel, name) = split_rel(rel);
        let same_place = remote.name == name
            && remote.parents.first().map(String::as_str)
                == self.state.dir_id(parent_rel).as_deref();
        if !same_place || (!entry.dir && md5_hex(&remote) != entry.md5) {
            self.retry.insert(entry.id.clone());
            return Ok(false);
        }
        match self.drive.trash(&entry.id) {
            Ok(_) | Err(RemoteError::NotFound(_)) => {
                self.state.remove_tree(rel);
                self.report.remote_trashed += 1;
                self.tick()?;
                Ok(true)
            }
            Err(error) => {
                self.fail(&format!("move {rel} to the Drive bin"), error)?;
                self.retry.insert(entry.id.clone());
                Ok(false)
            }
        }
    }
}

/// The hex md5 of a file, provided it did not change while it was read.
fn md5_stable(path: &std::path::Path, before: &Stat) -> std::io::Result<Option<String>> {
    let (md5, _) = crate::remote::md5_file(path)?;
    Ok((local::lstat(path)?.as_ref() == Some(before)).then(|| hex(&md5)))
}
