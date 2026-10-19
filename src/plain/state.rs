// SPDX-FileCopyrightText: Copyright 2026 Alexander Orlov <info@lifub.com>

//! The plain sync index: what was last in sync on both sides, bound to one
//! local folder and one Drive folder, and the lock that keeps a second
//! process away from it.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fs::File;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use super::PlainOptions;
use super::local::{Kind, Stat};
use crate::remote::{ensure_private_dir, read_private_file, write_private_file};

pub(crate) const STATE_FORMAT: &str = "zerotrust-drive-plain-state";
pub(crate) const STATE_VERSION: u32 = 1;
const MAX_STATE_BYTES: u64 = 1 << 30;

fn is_false(value: &bool) -> bool {
    !*value
}

/// One synced file or folder. The stat fields describe the local copy the
/// index last saw in sync with Drive's `md5`.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Entry {
    pub(crate) id: String,
    #[serde(default, skip_serializing_if = "is_false")]
    pub(crate) dir: bool,
    /// Hex md5 of the content, for files.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) md5: Option<String>,
    #[serde(default)]
    pub(crate) size: u64,
    #[serde(default)]
    pub(crate) mtime_ns: i64,
    #[serde(default)]
    pub(crate) inode: u64,
    /// Drive's `version` and `modifiedTime` when last seen.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) version: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) modified: Option<String>,
}

impl Entry {
    /// Whether the local item still is exactly what was synced.
    pub(crate) fn unchanged(&self, stat: &Stat) -> bool {
        if self.dir {
            stat.kind == Kind::Dir
        } else {
            stat.kind == Kind::File
                && stat.size == self.size
                && stat.mtime_ns == self.mtime_ns
                && stat.inode == self.inode
        }
    }

    /// Whether `stat` is this item under another name: the same inode and,
    /// for a file, the same size and modification time, so a reused inode
    /// is not taken for a rename.
    pub(crate) fn same_item(&self, stat: &Stat) -> bool {
        self.inode != 0
            && stat.inode == self.inode
            && if self.dir {
                stat.kind == Kind::Dir
            } else {
                stat.kind == Kind::File && stat.size == self.size && stat.mtime_ns == self.mtime_ns
            }
    }

    pub(crate) fn set_stat(&mut self, stat: &Stat) {
        self.inode = stat.inode;
        if !self.dir {
            self.size = stat.size;
            self.mtime_ns = stat.mtime_ns;
        }
    }
}

/// The state file. Paths are relative to the local folder, `/`-separated.
#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct State {
    format: String,
    version: u32,
    pub(crate) local_dir: PathBuf,
    /// Inode of the local folder when it was bound; a different one means
    /// the folder was replaced or an unmounted mount point is in its place.
    pub(crate) local_inode: u64,
    pub(crate) folder_id: String,
    /// Changes after this token are not yet applied locally; `None` until
    /// the first full listing.
    #[serde(default)]
    pub(crate) start_page_token: Option<String>,
    #[serde(default)]
    entries: BTreeMap<String, Entry>,
    /// Pre-generated Drive ids of creates in flight, so an interrupted
    /// create is recognised instead of duplicated.
    #[serde(default)]
    pub(crate) pending: BTreeMap<String, String>,
    /// Drive ids to read again next cycle, after a failed or deferred step.
    #[serde(default)]
    pub(crate) retry: BTreeSet<String>,
    /// Drive folders that arrived through the changes feed and whose
    /// children still have to be listed: a folder moved into the synced
    /// folder brings children the feed does not repeat.
    #[serde(default)]
    pub(crate) relist: BTreeSet<String>,
    #[serde(skip)]
    by_id: HashMap<String, String>,
    #[serde(skip)]
    path: PathBuf,
}

#[cfg(test)]
thread_local! {
    /// Saves left before a save fails, to simulate a crash between a
    /// remote step and recording it.
    static SAVES_UNTIL_FAILURE: std::cell::Cell<Option<u32>> = const { std::cell::Cell::new(None) };
}

#[cfg(test)]
pub(crate) fn fail_save_after(saves: Option<u32>) {
    SAVES_UNTIL_FAILURE.with(|cell| cell.set(saves));
}

impl State {
    pub(crate) fn entry(&self, rel: &str) -> Option<&Entry> {
        self.entries.get(rel)
    }

    pub(crate) fn entry_mut(&mut self, rel: &str) -> Option<&mut Entry> {
        self.entries.get_mut(rel)
    }

    pub(crate) fn entries(&self) -> &BTreeMap<String, Entry> {
        &self.entries
    }

    pub(crate) fn path_of(&self, id: &str) -> Option<&str> {
        self.by_id.get(id).map(String::as_str)
    }

    /// Local path of the indexed folder `id`; "" for the synced folder.
    pub(crate) fn dir_path(&self, id: &str) -> Option<String> {
        if id == self.folder_id {
            return Some(String::new());
        }
        let rel = self.by_id.get(id)?;
        self.entries
            .get(rel)
            .is_some_and(|entry| entry.dir)
            .then(|| rel.clone())
    }

    /// Drive id of the folder at local path `rel` ("" for the top).
    pub(crate) fn dir_id(&self, rel: &str) -> Option<String> {
        if rel.is_empty() {
            return Some(self.folder_id.clone());
        }
        self.entries
            .get(rel)
            .filter(|entry| entry.dir)
            .map(|entry| entry.id.clone())
    }

    /// Indexes `entry` at `rel`, dropping whatever was indexed there and
    /// any other path of the same id.
    pub(crate) fn insert(&mut self, rel: &str, entry: Entry) {
        if let Some(old) = self.by_id.get(&entry.id).cloned()
            && old != rel
        {
            self.entries.remove(&old);
        }
        if let Some(previous) = self.entries.get(rel)
            && previous.id != entry.id
        {
            self.by_id.remove(&previous.id);
        }
        self.by_id.insert(entry.id.clone(), rel.to_string());
        self.entries.insert(rel.to_string(), entry);
    }

    pub(crate) fn remove(&mut self, rel: &str) -> Option<Entry> {
        let entry = self.entries.remove(rel)?;
        if self.by_id.get(&entry.id).is_some_and(|path| path == rel) {
            self.by_id.remove(&entry.id);
        }
        Some(entry)
    }

    /// Paths strictly below `rel`, in path order.
    pub(crate) fn below(&self, rel: &str) -> Vec<String> {
        let start = format!("{rel}/");
        let end = format!("{rel}0");
        self.entries
            .range(start..end)
            .map(|(path, _)| path.clone())
            .collect()
    }

    /// Drops `rel` and everything indexed below it.
    pub(crate) fn remove_tree(&mut self, rel: &str) {
        for path in self.below(rel) {
            self.remove(&path);
        }
        self.remove(rel);
    }

    /// Re-roots the entry at `from`, and everything below it, at `to`.
    pub(crate) fn rename_tree(&mut self, from: &str, to: &str) {
        if from == to {
            return;
        }
        let mut moved = Vec::new();
        for path in self.below(from) {
            if let Some(entry) = self.remove(&path) {
                moved.push((format!("{to}{}", &path[from.len()..]), entry));
            }
        }
        if let Some(entry) = self.remove(from) {
            moved.push((to.to_string(), entry));
        }
        for (path, entry) in moved {
            self.insert(&path, entry);
        }
    }

    pub(crate) fn save(&self) -> Result<(), String> {
        #[cfg(test)]
        {
            let left = SAVES_UNTIL_FAILURE.with(std::cell::Cell::get);
            if let Some(left) = left {
                if left == 0 {
                    return Err("injected state save failure".to_string());
                }
                SAVES_UNTIL_FAILURE.with(|cell| cell.set(Some(left - 1)));
            }
        }
        let bytes = serde_json::to_vec(self)
            .map_err(|error| format!("cannot encode the sync state: {error}"))?;
        write_private_file(&self.path, &bytes).map_err(|error| error.to_string())
    }
}

/// The lock file next to the state file.
pub(crate) fn lock_path(state_file: &Path) -> PathBuf {
    let mut name = state_file
        .file_name()
        .map(std::ffi::OsStr::to_os_string)
        .unwrap_or_default();
    name.push(".lock");
    state_file.with_file_name(name)
}

/// Takes the instance lock, then loads the state or starts a new one bound
/// to `options`. The lock is held as long as the returned file is open.
pub(crate) fn open(options: &PlainOptions) -> Result<(State, File), String> {
    let parent = options
        .state_file
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .ok_or_else(|| format!("{} has no parent folder", options.state_file.display()))?;
    ensure_private_dir(parent).map_err(|error| error.to_string())?;
    let lock = lock_exclusive(&lock_path(&options.state_file))?;
    let root = std::fs::symlink_metadata(&options.local_dir)
        .map_err(|error| format!("{}: {error}", options.local_dir.display()))?;
    if !root.is_dir() {
        return Err(format!(
            "{} is not a folder (symbolic links are not followed)",
            options.local_dir.display()
        ));
    }
    let inode = std::os::unix::fs::MetadataExt::ino(&root);
    let bytes = read_private_file(&options.state_file, MAX_STATE_BYTES)
        .map_err(|error| error.to_string())?;
    let Some(bytes) = bytes else {
        let state = State {
            format: STATE_FORMAT.to_string(),
            version: STATE_VERSION,
            local_dir: options.local_dir.clone(),
            local_inode: inode,
            folder_id: options.folder_id.clone(),
            start_page_token: None,
            entries: BTreeMap::new(),
            pending: BTreeMap::new(),
            retry: BTreeSet::new(),
            relist: BTreeSet::new(),
            by_id: HashMap::new(),
            path: options.state_file.clone(),
        };
        return Ok((state, lock));
    };
    let mut state: State = serde_json::from_slice(&bytes).map_err(|error| {
        format!(
            "{} is not a readable plain sync state: {error}",
            options.state_file.display()
        )
    })?;
    if state.format != STATE_FORMAT || state.version != STATE_VERSION {
        return Err(format!(
            "{} has format {} version {}, but this zdrive reads {STATE_FORMAT} version {STATE_VERSION}",
            options.state_file.display(),
            state.format,
            state.version
        ));
    }
    let start_over = format!(
        "remove {} to bind it from scratch",
        options.state_file.display()
    );
    if state.local_dir != options.local_dir {
        return Err(format!(
            "{} belongs to the local folder {}, not {}; {start_over}",
            options.state_file.display(),
            state.local_dir.display(),
            options.local_dir.display()
        ));
    }
    if state.folder_id != options.folder_id {
        return Err(format!(
            "{} belongs to the Drive folder {}, not {}; {start_over}",
            options.state_file.display(),
            state.folder_id,
            options.folder_id
        ));
    }
    if state.local_inode != inode {
        return Err(format!(
            "{} is no longer the folder that was synced (it was replaced, restored from a backup or is an unmounted mount point), so its missing files are not deleted from Drive; {start_over}",
            options.local_dir.display()
        ));
    }
    state.path = options.state_file.clone();
    state.by_id = state
        .entries
        .iter()
        .map(|(rel, entry)| (entry.id.clone(), rel.clone()))
        .collect();
    Ok((state, lock))
}

const LOCK_GRACE: std::time::Duration = std::time::Duration::from_secs(1);

/// Takes an existing instance lock as a sync would; `remote remove` holds
/// it while it deletes.
pub(crate) fn lock_existing(path: &Path) -> Result<File, String> {
    lock_exclusive(path)
}

fn lock_exclusive(path: &Path) -> Result<File, String> {
    use std::os::fd::AsRawFd;
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .map_err(|error| format!("{}: {error}", path.display()))?;
    let metadata = file
        .metadata()
        .map_err(|error| format!("{}: {error}", path.display()))?;
    // SAFETY: getuid has no preconditions and cannot fail.
    if !metadata.is_file() || metadata.uid() != unsafe { libc::getuid() } {
        return Err(format!(
            "{} is not a lock file owned by the current user",
            path.display()
        ));
    }
    // A holder that is exiting, or a child spawned while the lock was held
    // and not yet past exec, releases it within moments: wait briefly.
    let deadline = std::time::Instant::now() + LOCK_GRACE;
    loop {
        // SAFETY: the descriptor is owned by `file` for the whole call.
        if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0 {
            return Ok(file);
        }
        let error = std::io::Error::last_os_error();
        if error.raw_os_error() != Some(libc::EWOULDBLOCK) {
            return Err(format!("lock {}: {error}", path.display()));
        }
        if std::time::Instant::now() >= deadline {
            return Err(format!(
                "another zdrive process is already syncing this remote (lock {}); stop it first - a remote has one plain replica per computer",
                path.display()
            ));
        }
        std::thread::sleep(std::time::Duration::from_millis(25));
    }
}
