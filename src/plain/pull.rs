// SPDX-FileCopyrightText: Copyright 2026 Alexander Orlov <info@lifub.com>

//! Phase A of a cycle: applying remote changes to the local folder.
//!
//! Removals come first (deepest first), then additions, moves and content
//! changes (shallowest first, so a folder exists before its children), then
//! folders whose remote counterpart went away. Nothing is ever unlinked:
//! a removed file goes to the local trash, a replaced file is set aside
//! and trashed only once its successor is in place.

use std::collections::{HashMap, HashSet};
use std::io;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use super::engine::{Cycle, Fatal};
use super::local::{self, ASIDE_PREFIX, Kind, Stat, TEMP_PREFIX, join_rel, split_rel};
use super::state::Entry;
use crate::remote::gdrive::DriveFile;
use crate::remote::{hex, md5_file};

/// Deepest folder chain followed upwards on Drive.
const MAX_DEPTH: usize = 256;
/// Google Docs, Sheets, shortcuts and the like: no content to download.
const NATIVE_PREFIX: &str = "application/vnd.google-apps.";

static SERIAL: AtomicU64 = AtomicU64::new(0);

/// A unique name for zdrive's own working files in this process.
fn serial() -> String {
    format!(
        "{}.{}",
        std::process::id(),
        SERIAL.fetch_add(1, Ordering::Relaxed)
    )
}

/// Where a remote item belongs locally.
enum Place {
    /// At this relative path.
    Inside(String),
    /// Not (or no longer) in the synced folder, or in the bin.
    Outside,
    /// Its name, or a parent's, is one neither side syncs.
    Ignored,
    /// Its name, or a parent's (`own` false), cannot be a local name.
    Invalid { own: bool },
}

/// A remote item to add, move or update locally.
struct Upsert {
    file: DriveFile,
    rel: String,
    known: bool,
}

impl Upsert {
    fn key(&self) -> (usize, bool, &str) {
        (depth(&self.rel), !self.known, self.rel.as_str())
    }
}

fn depth(rel: &str) -> usize {
    rel.bytes().filter(|byte| *byte == b'/').count()
}

fn md5_hex(file: &DriveFile) -> Option<String> {
    file.md5().map(|md5| hex(&md5))
}

enum Step {
    Done,
    /// Waits for another item of this pass to move out of the way.
    Defer,
}

/// What became of a local move.
enum Moved {
    Done,
    /// Something else has the target name.
    Occupied,
    /// Reported; retried next cycle.
    Failed,
}

/// How a verified download takes its place.
enum Target {
    /// Only where nothing exists yet.
    Absent,
    /// Over the file the index describes, and only while it is unchanged.
    Replace(Entry),
}

/// A file's md5 and size, provided it did not change while it was read.
fn stable_md5(path: &Path, before: &Stat) -> io::Result<Option<String>> {
    let (md5, _) = md5_file(path)?;
    Ok((local::lstat(path)?.as_ref() == Some(before)).then(|| hex(&md5)))
}

impl Cycle<'_> {
    /// Applies the latest state of each changed remote item.
    pub(super) fn pull(
        &mut self,
        items: Vec<(String, Option<DriveFile>)>,
        bootstrap: bool,
    ) -> Result<(), Fatal> {
        let overlay: HashMap<String, Option<DriveFile>> = items.into_iter().collect();
        let mut gone: Vec<String> = Vec::new();
        let mut upserts = Vec::new();
        for (id, file) in &overlay {
            let known = self.state.path_of(id).map(str::to_string);
            let Some(file) = file else {
                gone.extend(known);
                continue;
            };
            match self.locate(file, &overlay, None) {
                Place::Inside(rel) => {
                    if !file.is_folder()
                        && (file.mime_type.starts_with(NATIVE_PREFIX) || file.md5().is_none())
                    {
                        self.report.skipped_special += 1;
                        continue;
                    }
                    upserts.push(Upsert {
                        file: file.clone(),
                        rel,
                        known: known.is_some(),
                    });
                }
                Place::Outside | Place::Ignored => gone.extend(known),
                Place::Invalid { own } => {
                    if own {
                        self.report.errors.push(format!(
                            "the Drive name {:?} cannot be a local file name, so it is not synced",
                            file.name
                        ));
                        if known.is_some() {
                            self.retry.insert(id.clone());
                        }
                    }
                }
            }
        }
        let keep: HashSet<String> = upserts.iter().map(|up| up.file.id.clone()).collect();
        gone.sort_by(|a, b| depth(b).cmp(&depth(a)).then_with(|| b.cmp(a)));
        let mut gone_dirs = Vec::new();
        for rel in gone {
            self.remove_gone(&rel, &keep, &mut gone_dirs)?;
        }
        self.settle(upserts, &overlay, bootstrap)?;
        gone_dirs.sort_by(|a, b| depth(b).cmp(&depth(a)).then_with(|| b.cmp(a)));
        for rel in gone_dirs {
            self.remove_gone_dir(&rel);
        }
        Ok(())
    }

    /// Follows `file`'s parents up to the synced folder. `settled` names
    /// the items already handled in this pass, whose index path is current;
    /// any other ancestor is taken from the changes when they name it.
    fn locate(
        &self,
        file: &DriveFile,
        overlay: &HashMap<String, Option<DriveFile>>,
        settled: Option<&HashSet<String>>,
    ) -> Place {
        let mut names: Vec<&str> = Vec::new();
        let mut current = file;
        for _ in 0..MAX_DEPTH {
            if current.trashed {
                return Place::Outside;
            }
            if local::ignored(&current.name) {
                return Place::Ignored;
            }
            if !local::valid_name(&current.name) {
                return Place::Invalid {
                    own: names.is_empty(),
                };
            }
            names.push(&current.name);
            let Some(parent) = current.parents.first() else {
                return Place::Outside;
            };
            let from_index = |dir: String| {
                let below = names.iter().rev().copied().collect::<Vec<_>>().join("/");
                Place::Inside(join_rel(&dir, &below))
            };
            if *parent == self.state.folder_id {
                return from_index(String::new());
            }
            if settled.is_some_and(|done| done.contains(parent))
                && let Some(dir) = self.state.dir_path(parent)
            {
                return from_index(dir);
            }
            match overlay.get(parent) {
                Some(Some(next)) => current = next,
                Some(None) => return Place::Outside,
                None => {
                    return match self.state.dir_path(parent) {
                        Some(dir) => from_index(dir),
                        None => Place::Outside,
                    };
                }
            }
        }
        Place::Outside
    }

    /// The indexed item at `rel` left the synced folder on Drive. A folder
    /// takes its indexed contents along, except what moved elsewhere inside
    /// (`keep`); the folder itself is handled once its contents are.
    fn remove_gone(
        &mut self,
        rel: &str,
        keep: &HashSet<String>,
        gone_dirs: &mut Vec<String>,
    ) -> Result<(), Fatal> {
        let Some(entry) = self.state.entry(rel).cloned() else {
            return Ok(());
        };
        if !entry.dir {
            return self.remove_gone_file(rel, &entry);
        }
        for below in self.state.below(rel).into_iter().rev() {
            let Some(child) = self.state.entry(&below).cloned() else {
                continue;
            };
            if keep.contains(&child.id) {
                continue;
            }
            if child.dir {
                self.state.remove(&below);
                gone_dirs.push(below);
            } else {
                self.remove_gone_file(&below, &child)?;
            }
        }
        self.state.remove(rel);
        gone_dirs.push(rel.to_string());
        Ok(())
    }

    /// A file removed on Drive goes to the local trash if it is still what
    /// was synced; a local edit is kept and uploaded again as a new file.
    fn remove_gone_file(&mut self, rel: &str, entry: &Entry) -> Result<(), Fatal> {
        let path = self.root.join(rel);
        let stat = match local::lstat(&path) {
            Ok(stat) => stat,
            Err(error) => {
                self.report
                    .errors
                    .push(format!("cannot read {rel}: {error}"));
                self.retry.insert(entry.id.clone());
                return Ok(());
            }
        };
        match stat {
            Some(stat) if entry.unchanged(&stat) => match self.trash.take(rel) {
                Ok(trashed) => {
                    self.mutated = true;
                    // A write that slipped in between the check and the
                    // move makes it a kept local edit after all.
                    if local::lstat(&trashed).ok().flatten() != Some(stat) {
                        if let Err(error) = local::rename_noreplace(&trashed, &path) {
                            self.report.errors.push(format!(
                                "{rel} changed while it was moved to the trash, where it remains ({}): {error}",
                                trashed.display()
                            ));
                        }
                    } else {
                        self.report.local_trashed += 1;
                    }
                    self.state.remove(rel);
                }
                Err(error) => {
                    self.report
                        .errors
                        .push(format!("cannot move {rel} to the trash: {error}"));
                    self.retry.insert(entry.id.clone());
                }
            },
            _ => {
                self.state.remove(rel);
            }
        }
        self.tick()
    }

    /// A folder removed on Drive: removed locally once nothing is left in
    /// it that zdrive would sync; otherwise kept, and created again on
    /// Drive with what is left.
    fn remove_gone_dir(&mut self, rel: &str) {
        if self.state.entry(rel).is_some() {
            return;
        }
        let path = self.root.join(rel);
        if !matches!(local::lstat(&path), Ok(Some(stat)) if stat.kind == Kind::Dir) {
            return;
        }
        let names = match std::fs::read_dir(&path) {
            Ok(entries) => entries
                .map(|entry| entry.map(|entry| entry.file_name()))
                .collect::<Result<Vec<_>, _>>(),
            Err(error) => Err(error),
        };
        let names = match names {
            Ok(names) => names,
            Err(error) => {
                self.report
                    .errors
                    .push(format!("cannot read {rel}: {error}"));
                return;
            }
        };
        let result = if names.is_empty() {
            std::fs::remove_dir(&path)
        } else if names
            .iter()
            .all(|name| name.to_str().is_some_and(local::ignored))
        {
            self.trash.take(rel).map(|_| ())
        } else {
            return;
        };
        match result {
            Ok(()) => {
                self.report.local_trashed += 1;
                self.mutated = true;
            }
            Err(error) => self
                .report
                .errors
                .push(format!("cannot remove the folder {rel}: {error}")),
        }
    }

    /// Handles additions, moves and content changes until every item is
    /// placed. An item whose name is taken by one that moves away later in
    /// the pass waits for it; when nothing moves any more, what still
    /// collides is kept under a conflict name.
    fn settle(
        &mut self,
        mut queue: Vec<Upsert>,
        overlay: &HashMap<String, Option<DriveFile>>,
        bootstrap: bool,
    ) -> Result<(), Fatal> {
        let mut settled = HashSet::new();
        let mut moving: HashSet<String> = queue
            .iter()
            .filter(|up| {
                self.state
                    .path_of(&up.file.id)
                    .is_some_and(|old| old != up.rel)
            })
            .map(|up| up.file.id.clone())
            .collect();
        let mut force = false;
        loop {
            queue.sort_by(|a, b| a.key().cmp(&b.key()));
            let mut deferred = Vec::new();
            let mut progress = false;
            for up in queue {
                match self.upsert(&up, overlay, &settled, &moving, force, bootstrap)? {
                    Step::Done => {
                        moving.remove(&up.file.id);
                        settled.insert(up.file.id);
                        progress = true;
                        self.tick()?;
                    }
                    Step::Defer => deferred.push(up),
                }
            }
            if !deferred.is_empty() {
                force = !progress;
                queue = deferred;
                continue;
            }
            queue = self.list_new_folders(&settled, overlay)?;
            if queue.is_empty() {
                return Ok(());
            }
            force = false;
        }
    }

    /// The children of folders that arrived through the changes feed and
    /// were not reported themselves (a folder moved in from elsewhere).
    fn list_new_folders(
        &mut self,
        settled: &HashSet<String>,
        overlay: &HashMap<String, Option<DriveFile>>,
    ) -> Result<Vec<Upsert>, Fatal> {
        let mut found = Vec::new();
        for id in std::mem::take(&mut self.state.relist) {
            if self.state.dir_path(&id).is_none() {
                continue;
            }
            let children = match self.drive.list(&id, false) {
                Ok(children) => children,
                Err(error) => {
                    self.state.relist.insert(id);
                    self.fail("list a new Drive folder", error)?;
                    continue;
                }
            };
            for child in children {
                if settled.contains(&child.id)
                    || overlay.contains_key(&child.id)
                    || (!child.is_folder()
                        && (child.mime_type.starts_with(NATIVE_PREFIX) || child.md5().is_none()))
                {
                    continue;
                }
                if let Place::Inside(rel) = self.locate(&child, overlay, Some(settled)) {
                    let known = self.state.path_of(&child.id).is_some();
                    found.push(Upsert {
                        file: child,
                        rel,
                        known,
                    });
                }
            }
        }
        Ok(found)
    }

    fn upsert(
        &mut self,
        up: &Upsert,
        overlay: &HashMap<String, Option<DriveFile>>,
        settled: &HashSet<String>,
        moving: &HashSet<String>,
        force: bool,
        bootstrap: bool,
    ) -> Result<Step, Fatal> {
        let file = &up.file;
        let Place::Inside(rel) = self.locate(file, overlay, Some(settled)) else {
            self.report.errors.push(format!(
                "{} moved on Drive during the sync; retried next cycle",
                up.rel
            ));
            self.retry.insert(file.id.clone());
            return Ok(Step::Done);
        };
        let (parent_rel, _) = split_rel(&rel);
        let parent_ok = file
            .parents
            .first()
            .is_some_and(|parent| self.state.dir_id(parent_rel).as_deref() == Some(parent));
        if !parent_ok {
            if !force {
                return Ok(Step::Defer);
            }
            self.report.errors.push(format!(
                "{rel}: its folder is not synced yet; retried next cycle"
            ));
            self.retry.insert(file.id.clone());
            return Ok(Step::Done);
        }
        match self.state.path_of(&file.id).map(str::to_string) {
            Some(old) => self.update_known(file, &old, &rel, force, moving, bootstrap),
            None => self.add_new(file, &rel, force, moving, bootstrap),
        }
    }

    /// An indexed item changed on Drive: renamed or moved, and/or new
    /// content.
    fn update_known(
        &mut self,
        file: &DriveFile,
        old: &str,
        rel: &str,
        force: bool,
        moving: &HashSet<String>,
        bootstrap: bool,
    ) -> Result<Step, Fatal> {
        let Some(entry) = self.state.entry(old).cloned() else {
            return Ok(Step::Done);
        };
        if entry.dir != file.is_folder() {
            self.report
                .errors
                .push(format!("{old} changed kind on Drive; it is left alone"));
            return Ok(Step::Done);
        }
        let remote_md5 = md5_hex(file);
        let content_changed = !entry.dir && remote_md5 != entry.md5;
        let mut at = old.to_string();
        if old != rel {
            let current = match self.lstat_rel(old, &file.id) {
                Some(current) => current,
                None => return Ok(Step::Done),
            };
            match current {
                None => {
                    let echo = local::lstat(&self.root.join(rel))
                        .ok()
                        .flatten()
                        .is_some_and(|stat| entry.same_item(&stat));
                    if echo {
                        // A move this replica made but did not record.
                        self.state.rename_tree(old, rel);
                        self.note_moved(old, rel);
                        at = rel.to_string();
                    } else if self.renamed_locally(&entry) {
                        // Renamed on both sides: the local name wins in
                        // phase B; the content follows next cycle.
                        self.retry.insert(file.id.clone());
                        return Ok(Step::Done);
                    } else {
                        // Deleted here, moved there: the move wins.
                        self.state.remove_tree(old);
                        return self.add_new(file, rel, force, moving, bootstrap);
                    }
                }
                Some(stat) if content_changed && !entry.unchanged(&stat) => {
                    // Edited on both sides and moved on Drive: the local
                    // edit stays put and is uploaded as a new file.
                    self.state.remove(old);
                    return self.add_new(file, rel, force, moving, bootstrap);
                }
                Some(_) => match self.move_local(old, rel) {
                    Moved::Done => at = rel.to_string(),
                    Moved::Occupied if !force => return Ok(Step::Defer),
                    Moved::Occupied => {
                        let (parent_rel, name) = split_rel(rel);
                        let Some(target) = self.free_conflict_name(parent_rel, name, entry.dir)
                        else {
                            self.report
                                .errors
                                .push(format!("no free conflict name next to {rel}"));
                            self.retry.insert(file.id.clone());
                            return Ok(Step::Done);
                        };
                        let (_, new_name) = split_rel(&target);
                        if let Err(error) =
                            self.drive
                                .update_metadata(&file.id, Some(new_name), None, None)
                        {
                            self.fail(&format!("rename {rel} on Drive"), error)?;
                            self.retry.insert(file.id.clone());
                            return Ok(Step::Done);
                        }
                        match self.move_local(old, &target) {
                            Moved::Done => {
                                self.report.conflicts += 1;
                                at = target;
                            }
                            _ => {
                                self.retry.insert(file.id.clone());
                                return Ok(Step::Done);
                            }
                        }
                    }
                    Moved::Failed => {
                        self.retry.insert(file.id.clone());
                        return Ok(Step::Done);
                    }
                },
            }
        }
        if !content_changed {
            if let Some(entry) = self.state.entry_mut(&at) {
                entry.version = file.version.clone();
                entry.modified = file.modified_time.clone();
            }
            return Ok(Step::Done);
        }
        self.update_content(file, &at)?;
        Ok(Step::Done)
    }

    /// New remote content for the indexed file at `at`.
    fn update_content(&mut self, file: &DriveFile, at: &str) -> Result<(), Fatal> {
        let Some(entry) = self.state.entry(at).cloned() else {
            return Ok(());
        };
        let path = self.root.join(at);
        let Some(current) = self.lstat_rel(at, &file.id) else {
            return Ok(());
        };
        match current {
            None if self.renamed_locally(&entry) => {
                self.retry.insert(file.id.clone());
                Ok(())
            }
            None => {
                self.state.remove(at);
                self.download(file, at, Target::Absent)
            }
            Some(stat) if stat.kind != Kind::File => self.remote_conflict(file, at, false),
            Some(stat) if entry.unchanged(&stat) => self.download(file, at, Target::Replace(entry)),
            Some(stat) => {
                let local = match stable_md5(&path, &stat) {
                    Ok(Some(local)) => local,
                    Ok(None) => {
                        self.report.skipped_unstable += 1;
                        self.retry.insert(file.id.clone());
                        return Ok(());
                    }
                    Err(error) => {
                        self.report
                            .errors
                            .push(format!("cannot read {at}: {error}"));
                        self.retry.insert(file.id.clone());
                        return Ok(());
                    }
                };
                if Some(&local) == md5_hex(file).as_ref() {
                    self.link_file(at, file, &stat);
                    Ok(())
                } else if Some(&local) == entry.md5.as_ref() {
                    // Touched, not edited: still the synced content.
                    let mut entry = entry;
                    entry.set_stat(&stat);
                    self.state.insert(at, entry.clone());
                    self.download(file, at, Target::Replace(entry))
                } else {
                    self.remote_conflict(file, at, false)
                }
            }
        }
    }

    /// A remote item not in the index, at `rel`.
    fn add_new(
        &mut self,
        file: &DriveFile,
        rel: &str,
        force: bool,
        moving: &HashSet<String>,
        bootstrap: bool,
    ) -> Result<Step, Fatal> {
        if let Some(occupant) = self.state.entry(rel)
            && occupant.id != file.id
        {
            if !force && moving.contains(&occupant.id) {
                return Ok(Step::Defer);
            }
            self.remote_conflict(file, rel, bootstrap)?;
            return Ok(Step::Done);
        }
        if self.state.pending.get(rel) == Some(&file.id) {
            // Created by this replica in a cycle that did not finish; the
            // zero stat makes phase B compare the content.
            self.state.pending.remove(rel);
            let mut entry = Entry {
                id: file.id.clone(),
                dir: file.is_folder(),
                md5: md5_hex(file),
                size: file.size().unwrap_or(0),
                version: file.version.clone(),
                modified: file.modified_time.clone(),
                ..Entry::default()
            };
            if entry.dir
                && let Ok(Some(stat)) = local::lstat(&self.root.join(rel))
                && stat.kind == Kind::Dir
            {
                entry.inode = stat.inode;
            }
            self.state.insert(rel, entry);
            return Ok(Step::Done);
        }
        let Some(current) = self.lstat_rel(rel, &file.id) else {
            return Ok(Step::Done);
        };
        if current.is_some() && !self.present.contains(rel) {
            // Another spelling of an existing name (case or Unicode
            // normalization), or created after the scan.
            self.remote_conflict(file, rel, bootstrap)?;
            return Ok(Step::Done);
        }
        match (file.is_folder(), current) {
            (true, None) => match self.ensure_dir(rel) {
                Ok(stat) => {
                    self.report.folders_created += 1;
                    self.index_dir(rel, file, &stat, bootstrap);
                }
                Err(error) => {
                    self.report
                        .errors
                        .push(format!("cannot create the folder {rel}: {error}"));
                    self.retry.insert(file.id.clone());
                }
            },
            (true, Some(stat)) if stat.kind == Kind::Dir => {
                self.index_dir(rel, file, &stat, bootstrap);
            }
            (false, None) => self.download(file, rel, Target::Absent)?,
            (false, Some(stat)) if stat.kind == Kind::File => {
                match stable_md5(&self.root.join(rel), &stat) {
                    Ok(Some(local)) if Some(&local) == md5_hex(file).as_ref() => {
                        self.link_file(rel, file, &stat);
                    }
                    Ok(Some(_)) => self.remote_conflict(file, rel, bootstrap)?,
                    Ok(None) => {
                        self.report.skipped_unstable += 1;
                        self.retry.insert(file.id.clone());
                    }
                    Err(error) => {
                        self.report
                            .errors
                            .push(format!("cannot read {rel}: {error}"));
                        self.retry.insert(file.id.clone());
                    }
                }
            }
            _ => self.remote_conflict(file, rel, bootstrap)?,
        }
        Ok(Step::Done)
    }

    /// Both sides have something different at `rel`: the local item keeps
    /// the name, and the remote one is renamed to a conflict name on Drive
    /// first, then placed under that name locally.
    fn remote_conflict(
        &mut self,
        file: &DriveFile,
        rel: &str,
        bootstrap: bool,
    ) -> Result<(), Fatal> {
        let folder = file.is_folder();
        let (parent_rel, name) = split_rel(rel);
        let Some(target) = self.free_conflict_name(parent_rel, name, folder) else {
            self.report
                .errors
                .push(format!("no free conflict name next to {rel}"));
            self.retry.insert(file.id.clone());
            return Ok(());
        };
        let (_, new_name) = split_rel(&target);
        let renamed = match self
            .drive
            .update_metadata(&file.id, Some(new_name), None, None)
        {
            Ok(renamed) => renamed,
            Err(error) => {
                self.fail(&format!("rename the Drive copy of {rel}"), error)?;
                self.retry.insert(file.id.clone());
                return Ok(());
            }
        };
        if let Some(old) = self.state.path_of(&file.id).map(str::to_string) {
            self.state.remove(&old);
        }
        self.report.conflicts += 1;
        if !folder {
            let source = if renamed.md5().is_some() && renamed.size().is_some() {
                renamed
            } else {
                let mut source = file.clone();
                source.name = new_name.to_string();
                source
            };
            return self.download(&source, &target, Target::Absent);
        }
        match self.ensure_dir(&target) {
            Ok(stat) => {
                self.report.folders_created += 1;
                self.index_dir(&target, &renamed, &stat, bootstrap);
            }
            Err(error) => {
                self.report
                    .errors
                    .push(format!("cannot create the folder {target}: {error}"));
                self.retry.insert(file.id.clone());
            }
        }
        Ok(())
    }

    /// Downloads `file` next to `rel`, verifies it and moves it into place.
    fn download(&mut self, file: &DriveFile, rel: &str, target: Target) -> Result<(), Fatal> {
        let (parent_rel, _) = split_rel(rel);
        if let Err(error) = self.ensure_dir(parent_rel) {
            self.report
                .errors
                .push(format!("cannot create the folder of {rel}: {error}"));
            self.retry.insert(file.id.clone());
            return Ok(());
        }
        let temp = self
            .root
            .join(join_rel(parent_rel, &format!("{TEMP_PREFIX}{}", serial())));
        let created = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o666)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&temp);
        if let Err(error) = created {
            self.report
                .errors
                .push(format!("cannot create a download file for {rel}: {error}"));
            self.retry.insert(file.id.clone());
            return Ok(());
        }
        if let Err(error) = self.drive.download_to(file, &temp) {
            self.remove_temp(&temp);
            self.fail(&format!("download {rel}"), error)?;
            self.retry.insert(file.id.clone());
            return Ok(());
        }
        let placed = match target {
            Target::Absent => self.put_absent(&temp, rel),
            Target::Replace(entry) => self.put_replace(&temp, rel, &entry),
        };
        let placed = match placed {
            Ok(placed) => placed,
            Err(error) => {
                self.remove_temp(&temp);
                self.report
                    .errors
                    .push(format!("cannot put {rel} in place: {error}"));
                self.retry.insert(file.id.clone());
                return Ok(());
            }
        };
        self.mutated = true;
        self.report.downloaded += 1;
        self.report.download_bytes += file.size().unwrap_or(0);
        let stat = local::lstat(&self.root.join(&placed)).ok().flatten();
        if placed != rel
            && let Some(old) = self.state.path_of(&file.id).map(str::to_string)
        {
            self.state.remove(&old);
        }
        self.index_file(&placed, file, stat);
        self.present.insert(placed.clone());
        if placed != rel {
            // Its name was taken meanwhile: Drive gets the conflict name
            // too, so both replicas agree.
            self.report.conflicts += 1;
            let (_, new_name) = split_rel(&placed);
            if let Err(error) = self
                .drive
                .update_metadata(&file.id, Some(new_name), None, None)
            {
                self.fail(&format!("rename the Drive copy of {rel}"), error)?;
                self.retry.insert(file.id.clone());
            }
        }
        Ok(())
    }

    /// Moves the verified download `temp` to `rel` if that name is free,
    /// otherwise to a conflict name next to it. Returns where it went.
    fn put_absent(&mut self, temp: &Path, rel: &str) -> io::Result<String> {
        match local::rename_noreplace(temp, &self.root.join(rel)) {
            Ok(()) => {
                self.sync_parent(rel);
                Ok(rel.to_string())
            }
            Err(error) if error.raw_os_error() == Some(libc::EEXIST) => {
                self.put_conflict(temp, rel)
            }
            Err(error) => Err(error),
        }
    }

    fn put_conflict(&mut self, temp: &Path, rel: &str) -> io::Result<String> {
        let (parent_rel, name) = split_rel(rel);
        for _ in 0..8 {
            let Some(candidate) = self.free_conflict_name(parent_rel, name, false) else {
                break;
            };
            match local::rename_noreplace(temp, &self.root.join(&candidate)) {
                Ok(()) => {
                    self.sync_parent(&candidate);
                    return Ok(candidate);
                }
                Err(error) if error.raw_os_error() == Some(libc::EEXIST) => {}
                Err(error) => return Err(error),
            }
        }
        Err(io::Error::from_raw_os_error(libc::EEXIST))
    }

    /// Replaces the file at `rel` with the verified download `temp`, but
    /// only while it still is the copy the index describes. The old version
    /// is set aside first (so a crash leaves it recoverable next to its
    /// name), then moved to the trash once the new one is in place.
    fn put_replace(&mut self, temp: &Path, rel: &str, entry: &Entry) -> io::Result<String> {
        let path = self.root.join(rel);
        let Some(current) = local::lstat(&path)? else {
            return self.put_absent(temp, rel);
        };
        if !entry.unchanged(&current) {
            return self.put_conflict(temp, rel);
        }
        let metadata = std::fs::symlink_metadata(&path)?;
        std::fs::set_permissions(temp, metadata.permissions())?;
        let (parent_rel, name) = split_rel(rel);
        let aside_name = format!("{ASIDE_PREFIX}{}-{name}", serial());
        let aside_rel = join_rel(parent_rel, &aside_name);
        // A name too long for an aside goes straight to the trash; a crash
        // before the download is in place then leaves it there, and the
        // next cycle downloads again.
        let aside: PathBuf = if aside_name.len() <= local::NAME_MAX {
            let aside = self.root.join(&aside_rel);
            match local::rename_noreplace(&path, &aside) {
                Ok(()) => aside,
                Err(error) if error.kind() == io::ErrorKind::NotFound => {
                    return self.put_absent(temp, rel);
                }
                Err(error) => return Err(error),
            }
        } else {
            match self.trash.take(rel) {
                Ok(trashed) => trashed,
                Err(error) if error.kind() == io::ErrorKind::NotFound => {
                    return self.put_absent(temp, rel);
                }
                Err(error) => return Err(error),
            }
        };
        let in_place = aside.starts_with(self.root) && aside.parent() == path.parent();
        let verified = local::lstat(&aside).ok().flatten() == Some(current);
        let placed = match local::rename_noreplace(temp, &path) {
            Ok(()) => {
                self.sync_parent(rel);
                rel.to_string()
            }
            Err(error) if error.raw_os_error() == Some(libc::EEXIST) => {
                self.put_conflict(temp, rel)?
            }
            Err(error) => {
                if let Err(back) = local::rename_noreplace(&aside, &path) {
                    self.report.errors.push(format!(
                        "{rel} could not be put back from {}: {back}",
                        aside.display()
                    ));
                }
                return Err(error);
            }
        };
        if verified {
            if in_place && let Err(error) = self.trash.take_as(&aside_rel, rel) {
                self.report.errors.push(format!(
                    "the previous version of {rel} stays at {aside_name}: {error}"
                ));
            }
        } else {
            // Written to between the check and the move: that edit is kept
            // under a conflict name and uploaded as a new file.
            let kept = self
                .free_conflict_name(parent_rel, name, false)
                .ok_or_else(|| io::Error::from_raw_os_error(libc::EEXIST))
                .and_then(|conflict| {
                    local::rename_noreplace(&aside, &self.root.join(&conflict)).map(|()| conflict)
                });
            match kept {
                Ok(conflict) => {
                    self.report.conflicts += 1;
                    self.present.insert(conflict);
                }
                Err(error) => self.report.errors.push(format!(
                    "a local edit of {rel} stays at {}: {error}",
                    aside.display()
                )),
            }
        }
        Ok(placed)
    }

    fn remove_temp(&mut self, temp: &Path) {
        match std::fs::remove_file(temp) {
            Err(error) if error.kind() != io::ErrorKind::NotFound => {
                self.report.errors.push(format!(
                    "cannot remove the download file {}: {error}",
                    temp.display()
                ))
            }
            _ => {}
        }
    }

    fn sync_parent(&mut self, rel: &str) {
        let (parent_rel, _) = split_rel(rel);
        if let Err(error) = local::fsync_dir(&self.root.join(parent_rel)) {
            self.report
                .errors
                .push(format!("cannot flush the folder of {rel}: {error}"));
        }
    }

    /// `lstat` of a relative path; `None` after reporting a failure.
    fn lstat_rel(&mut self, rel: &str, id: &str) -> Option<Option<Stat>> {
        match local::lstat(&self.root.join(rel)) {
            Ok(stat) => Some(stat),
            Err(error) => {
                self.report
                    .errors
                    .push(format!("cannot read {rel}: {error}"));
                self.retry.insert(id.to_string());
                None
            }
        }
    }

    /// Moves the indexed item at `old` to `rel` locally, never over
    /// anything.
    fn move_local(&mut self, old: &str, rel: &str) -> Moved {
        let (parent_rel, _) = split_rel(rel);
        if let Err(error) = self.ensure_dir(parent_rel) {
            self.report
                .errors
                .push(format!("cannot create the folder of {rel}: {error}"));
            return Moved::Failed;
        }
        match local::move_path(&self.root.join(old), &self.root.join(rel)) {
            Ok(()) => {
                self.sync_parent(old);
                self.sync_parent(rel);
                self.state.rename_tree(old, rel);
                self.note_moved(old, rel);
                self.report.moved += 1;
                self.mutated = true;
                Moved::Done
            }
            Err(error) if matches!(error.raw_os_error(), Some(libc::EEXIST | libc::ENOTEMPTY)) => {
                Moved::Occupied
            }
            Err(error) => {
                self.report
                    .errors
                    .push(format!("cannot move {old} to {rel}: {error}"));
                Moved::Failed
            }
        }
    }

    /// Keeps the set of present names current after a local move.
    fn note_moved(&mut self, old: &str, rel: &str) {
        let moved: Vec<String> = self
            .present
            .range(old.to_string()..)
            .take_while(|path| path.starts_with(old))
            .filter(|path| local::within(path, old))
            .cloned()
            .collect();
        for path in moved {
            self.present.remove(&path);
            self.present.insert(format!("{rel}{}", &path[old.len()..]));
        }
        self.present.insert(rel.to_string());
    }

    /// The first conflict name next to `rel` that nothing uses.
    pub(super) fn free_conflict_name(
        &self,
        parent_rel: &str,
        name: &str,
        dir: bool,
    ) -> Option<String> {
        (1..=1000).find_map(|n| {
            let candidate = join_rel(
                parent_rel,
                &local::conflict_name(name, dir, &self.stamp, &self.host, n),
            );
            let free = self.state.entry(&candidate).is_none()
                && !self.present.contains(&candidate)
                && matches!(local::lstat(&self.root.join(&candidate)), Ok(None));
            free.then_some(candidate)
        })
    }

    /// Creates the folder `rel` and any missing parents, refusing to pass
    /// through anything but real folders (a symlink in particular).
    pub(super) fn ensure_dir(&mut self, rel: &str) -> io::Result<Stat> {
        let mut path = self.root.to_path_buf();
        let mut stat =
            local::lstat(&path)?.ok_or_else(|| io::Error::from(io::ErrorKind::NotFound))?;
        if rel.is_empty() {
            return Ok(stat);
        }
        let mut walked = String::new();
        for component in rel.split('/') {
            path.push(component);
            walked = join_rel(&walked, component);
            stat = match local::lstat(&path)? {
                Some(stat) if stat.kind == Kind::Dir => stat,
                Some(_) => return Err(io::Error::from_raw_os_error(libc::ENOTDIR)),
                None => {
                    std::fs::create_dir(&path)?;
                    if let Some(parent) = path.parent() {
                        local::fsync_dir(parent)?;
                    }
                    self.mutated = true;
                    self.present.insert(walked.clone());
                    local::lstat(&path)?
                        .filter(|stat| stat.kind == Kind::Dir)
                        .ok_or_else(|| io::Error::from_raw_os_error(libc::ENOTDIR))?
                }
            };
        }
        Ok(stat)
    }

    fn index_dir(&mut self, rel: &str, file: &DriveFile, stat: &Stat, bootstrap: bool) {
        self.state.insert(
            rel,
            Entry {
                id: file.id.clone(),
                dir: true,
                inode: stat.inode,
                version: file.version.clone(),
                modified: file.modified_time.clone(),
                ..Entry::default()
            },
        );
        self.present.insert(rel.to_string());
        if !bootstrap {
            self.state.relist.insert(file.id.clone());
        }
    }

    fn link_file(&mut self, rel: &str, file: &DriveFile, stat: &Stat) {
        self.index_file(rel, file, Some(*stat));
    }

    fn index_file(&mut self, rel: &str, file: &DriveFile, stat: Option<Stat>) {
        let mut entry = Entry {
            id: file.id.clone(),
            md5: md5_hex(file),
            version: file.version.clone(),
            modified: file.modified_time.clone(),
            ..Entry::default()
        };
        if let Some(stat) = stat.filter(|stat| stat.kind == Kind::File) {
            entry.set_stat(&stat);
        }
        self.state.insert(rel, entry);
    }
}
