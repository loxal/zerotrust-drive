// SPDX-FileCopyrightText: Copyright 2026 Alexander Orlov <info@lifub.com>

//! Local, per-remote replication state under
//! `$XDG_STATE_HOME/zerotrust-drive/remotes/<name>/`, never inside the store.
//!
//! ```text
//! lock                     flock held for the whole sync operation
//! state.json               last synced head, verified layout, pending ids
//! headers/<md5>-<size>.hdr pack headers, keyed by content
//! outgoing/<pack>.zpk      sealed packs not yet confirmed remote
//! outgoing/<pack>.zpk.json their upload checkpoints
//! incoming/<pack>.zpk      downloaded packs, deleted after a pull
//! ```
//!
//! Everything here is a cache or a resumption aid. Fast-forward decisions are
//! made from the authenticated generation graph, so deleting this directory
//! loses only work in progress and cached headers.

use std::fs::File;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use super::format::{parse_pack_name, valid_file_id};
use super::gdrive::UploadCheckpoint;
use super::{RemoteError, ensure_private_dir, read_private_file, unhex, write_private_file};

const STATE_FORMAT: &str = "zerotrust-drive-remote-state";
const STATE_VERSION: u32 = 1;
const STATE_FILE: &str = "state.json";
pub(crate) const LOCK_FILE: &str = "lock";
const HEADERS_DIR: &str = "headers";
pub(crate) const OUTGOING_DIR: &str = "outgoing";
const INCOMING_DIR: &str = "incoming";
/// Damaged local objects a pull replaced, kept as evidence; never cleared.
const DAMAGED_DIR: &str = "damaged";
const MAX_STATE_FILE: u64 = 64 * 1024;
const MAX_CHECKPOINT_FILE: u64 = 16 * 1024;
/// A full header for `MAX_PACK_OBJECTS` entries.
const MAX_HEADER_FILE: u64 = 15 << 20;

/// Generation this replica last confirmed equal to the remote head.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SyncedHead {
    pub(crate) number: u64,
    /// Hex `ObjectRef` id followed by its digest.
    pub(crate) generation: String,
    pub(crate) record: String,
    /// Hex md5 of the record's bytes. While the record still lists with
    /// this md5, its generation needs no second download.
    #[serde(default)]
    pub(crate) record_md5: Option<String>,
    pub(crate) encrypted_dir: String,
    pub(crate) unix_seconds: u64,
}

/// Provider ids chosen before a create, so a retried create after an
/// ambiguous outcome reuses them instead of leaving duplicates.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PendingLayout {
    pub(crate) packs: String,
    pub(crate) roots: String,
    pub(crate) leases: String,
    pub(crate) kdf: String,
    pub(crate) marker: String,
}

/// This replica's advisory writer lease. The id is chosen and saved before
/// the lease file is created, so a retried create reuses it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct LeaseRecord {
    /// Random hex id naming this replica in `leases/`.
    pub(crate) replica: String,
    pub(crate) file_id: String,
    /// The leases folder the file belongs to; a new remote layout gets a
    /// new lease.
    pub(crate) folder: String,
    /// Whether Drive confirmed the create.
    pub(crate) created: bool,
}

/// The layout a verified marker commits to. A later operation checks it
/// against one listing of the remote folder instead of reading the marker
/// and `_kdf.json` again; any mismatch falls back to the full read.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct KnownLayout {
    pub(crate) marker: String,
    /// Hex md5 of the marker, as Drive lists it.
    pub(crate) marker_md5: String,
    pub(crate) kdf: String,
    pub(crate) kdf_md5: String,
    pub(crate) packs: String,
    pub(crate) roots: String,
    pub(crate) leases: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PendingRoot {
    pub(crate) name: String,
    pub(crate) file_id: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct StateRecord {
    format: String,
    version: u32,
    folder_id: String,
    #[serde(default)]
    pub(crate) synced: Option<SyncedHead>,
    #[serde(default)]
    pub(crate) pending_layout: Option<PendingLayout>,
    #[serde(default)]
    pub(crate) pending_root: Option<PendingRoot>,
    #[serde(default)]
    pub(crate) layout: Option<KnownLayout>,
    #[serde(default)]
    pub(crate) lease: Option<LeaseRecord>,
}

impl StateRecord {
    fn new(folder_id: &str) -> Self {
        Self {
            format: STATE_FORMAT.to_string(),
            version: STATE_VERSION,
            folder_id: folder_id.to_string(),
            synced: None,
            pending_layout: None,
            pending_root: None,
            layout: None,
            lease: None,
        }
    }

    fn validate(&self) -> Result<(), String> {
        if self.format != STATE_FORMAT {
            return Err(format!("format is not {STATE_FORMAT}"));
        }
        if self.version != STATE_VERSION {
            return Err(format!(
                "version {} is not supported; upgrade zdrive",
                self.version
            ));
        }
        let ids = self
            .pending_layout
            .iter()
            .flat_map(|layout| {
                [
                    &layout.packs,
                    &layout.roots,
                    &layout.leases,
                    &layout.kdf,
                    &layout.marker,
                ]
            })
            .chain(self.pending_root.iter().map(|root| &root.file_id))
            .chain(self.synced.iter().map(|synced| &synced.record))
            .chain(self.layout.iter().flat_map(|layout| {
                [
                    &layout.marker,
                    &layout.kdf,
                    &layout.packs,
                    &layout.roots,
                    &layout.leases,
                ]
            }))
            .chain(
                self.lease
                    .iter()
                    .flat_map(|lease| [&lease.file_id, &lease.folder]),
            )
            .chain(std::iter::once(&self.folder_id));
        if ids.into_iter().any(|id| !valid_file_id(id)) {
            return Err("names an invalid provider id".to_string());
        }
        let md5s = self
            .layout
            .iter()
            .flat_map(|layout| [&layout.marker_md5, &layout.kdf_md5])
            .chain(
                self.synced
                    .iter()
                    .filter_map(|synced| synced.record_md5.as_ref()),
            );
        if md5s.into_iter().any(|md5| unhex::<16>(md5).is_none()) {
            return Err("names an invalid md5".to_string());
        }
        if self
            .lease
            .as_ref()
            .is_some_and(|lease| unhex::<16>(&lease.replica).is_none())
        {
            return Err("names an invalid lease replica".to_string());
        }
        Ok(())
    }
}

/// A sealed pack waiting in `outgoing/`, with its upload checkpoint if one
/// was recorded.
#[derive(Debug)]
pub(crate) struct OutgoingPack {
    pub(crate) name: String,
    pub(crate) path: PathBuf,
    pub(crate) checkpoint: Option<UploadCheckpoint>,
}

/// Exclusive handle on one remote's local state. Dropping it releases the
/// lock.
#[derive(Debug)]
pub(crate) struct RemoteState {
    dir: PathBuf,
    _lock: File,
    pub(crate) record: StateRecord,
}

impl RemoteState {
    /// Locks and loads the state for the remote folder `folder_id`. State
    /// for any other folder id is discarded with its caches.
    pub(crate) fn open(dir: &Path, folder_id: &str) -> Result<Self, RemoteError> {
        if !valid_file_id(folder_id) {
            return Err(RemoteError::Local(
                "remote folder id is not a valid provider id".to_string(),
            ));
        }
        ensure_private_dir(dir)?;
        let lock = lock_exclusive(&dir.join(LOCK_FILE))?;
        let state_path = dir.join(STATE_FILE);
        let loaded = match read_private_file(&state_path, MAX_STATE_FILE)? {
            None => None,
            Some(bytes) => {
                let record: StateRecord = serde_json::from_slice(&bytes).map_err(|error| {
                    RemoteError::Local(format!("{}: {error}", state_path.display()))
                })?;
                record.validate().map_err(|error| {
                    RemoteError::Local(format!("{}: {error}", state_path.display()))
                })?;
                Some(record)
            }
        };
        let record = match loaded {
            Some(record) if record.folder_id == folder_id => record,
            _ => {
                for name in [HEADERS_DIR, OUTGOING_DIR, INCOMING_DIR] {
                    remove_tree(&dir.join(name))?;
                }
                StateRecord::new(folder_id)
            }
        };
        for name in [HEADERS_DIR, OUTGOING_DIR, INCOMING_DIR] {
            ensure_private_dir(&dir.join(name))?;
        }
        let state = Self {
            dir: dir.to_path_buf(),
            _lock: lock,
            record,
        };
        state.save()?;
        Ok(state)
    }

    pub(crate) fn save(&self) -> Result<(), RemoteError> {
        let bytes = serde_json::to_vec_pretty(&self.record)
            .map_err(|error| RemoteError::Local(error.to_string()))?;
        write_private_file(&self.dir.join(STATE_FILE), &bytes)
    }

    pub(crate) fn outgoing_dir(&self) -> PathBuf {
        self.dir.join(OUTGOING_DIR)
    }

    pub(crate) fn incoming_dir(&self) -> PathBuf {
        self.dir.join(INCOMING_DIR)
    }

    /// Where a pull keeps the bytes of a damaged local object it replaced;
    /// created on first use.
    pub(crate) fn damaged_dir(&self) -> PathBuf {
        self.dir.join(DAMAGED_DIR)
    }

    /// Cached header of the pack named `name`, if any.
    pub(crate) fn cached_header(&self, name: &str) -> Result<Option<Vec<u8>>, RemoteError> {
        let Some(path) = self.header_path(name) else {
            return Ok(None);
        };
        read_private_file(&path, MAX_HEADER_FILE)
    }

    pub(crate) fn store_header(&self, name: &str, header: &[u8]) -> Result<(), RemoteError> {
        let path = self
            .header_path(name)
            .ok_or_else(|| RemoteError::Local(format!("{name:?} is not a pack name")))?;
        write_private_file(&path, header)
    }

    fn header_path(&self, name: &str) -> Option<PathBuf> {
        parse_pack_name(name)?;
        let stem = name.strip_suffix(".zpk")?;
        Some(self.dir.join(HEADERS_DIR).join(format!("{stem}.hdr")))
    }

    /// Sealed packs in `outgoing/`, sorted by name. Temporary files and
    /// checkpoints without a pack are leftovers of an interrupted run and
    /// are removed.
    pub(crate) fn outgoing_packs(&self) -> Result<Vec<OutgoingPack>, RemoteError> {
        let dir = self.outgoing_dir();
        let mut packs = Vec::new();
        let mut checkpoints = Vec::new();
        for entry in std::fs::read_dir(&dir)? {
            let entry = entry?;
            let name = entry.file_name().into_string().map_err(|_| {
                RemoteError::Local(format!("{} holds a non-UTF-8 name", dir.display()))
            })?;
            if !entry.file_type()?.is_file() {
                return Err(RemoteError::Local(format!(
                    "{} is not a regular file",
                    entry.path().display()
                )));
            }
            if parse_pack_name(&name).is_some() {
                packs.push(name);
            } else if let Some(pack) = name.strip_suffix(".json")
                && parse_pack_name(pack).is_some()
            {
                checkpoints.push(pack.to_string());
            } else if name.starts_with('.') && name.ends_with(".tmp") {
                std::fs::remove_file(entry.path())?;
            } else {
                return Err(RemoteError::Local(format!(
                    "unexpected file {} in the outgoing pack queue",
                    entry.path().display()
                )));
            }
        }
        for pack in checkpoints {
            if !packs.contains(&pack) {
                std::fs::remove_file(dir.join(format!("{pack}.json")))?;
            }
        }
        packs.sort();
        packs
            .into_iter()
            .map(|name| {
                let checkpoint = self.load_checkpoint(&name)?;
                Ok(OutgoingPack {
                    path: dir.join(&name),
                    name,
                    checkpoint,
                })
            })
            .collect()
    }

    fn load_checkpoint(&self, pack: &str) -> Result<Option<UploadCheckpoint>, RemoteError> {
        let path = self.outgoing_dir().join(format!("{pack}.json"));
        let Some(bytes) = read_private_file(&path, MAX_CHECKPOINT_FILE)? else {
            return Ok(None);
        };
        let checkpoint: UploadCheckpoint = serde_json::from_slice(&bytes)
            .map_err(|error| RemoteError::Local(format!("{}: {error}", path.display())))?;
        if !valid_file_id(&checkpoint.file_id) {
            return Err(RemoteError::Local(format!(
                "{} names an invalid provider id",
                path.display()
            )));
        }
        Ok(Some(checkpoint))
    }

    pub(crate) fn save_checkpoint(
        &self,
        pack: &str,
        checkpoint: &UploadCheckpoint,
    ) -> std::io::Result<()> {
        let bytes = serde_json::to_vec(checkpoint).map_err(std::io::Error::other)?;
        write_private_file(&self.outgoing_dir().join(format!("{pack}.json")), &bytes)
            .map_err(|error| std::io::Error::other(error.to_string()))
    }

    /// Retires a pack once the remote copy is verified: the pack goes first,
    /// so a crash leaves at worst an orphan checkpoint.
    pub(crate) fn finish_outgoing(&self, pack: &str) -> Result<(), RemoteError> {
        let dir = self.outgoing_dir();
        remove_if_present(&dir.join(pack))?;
        remove_if_present(&dir.join(format!("{pack}.json")))?;
        File::open(&dir)?.sync_all()?;
        Ok(())
    }

    pub(crate) fn clear_incoming(&self) -> Result<(), RemoteError> {
        let dir = self.incoming_dir();
        remove_tree(&dir)?;
        ensure_private_dir(&dir)
    }
}

fn remove_if_present(path: &Path) -> std::io::Result<()> {
    match std::fs::remove_file(path) {
        Err(error) if error.kind() != std::io::ErrorKind::NotFound => Err(error),
        _ => Ok(()),
    }
}

/// Removes a cache directory this module owns, refusing to follow a symlink.
pub(crate) fn remove_tree(path: &Path) -> Result<(), RemoteError> {
    match std::fs::symlink_metadata(path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
        Ok(metadata) if metadata.file_type().is_dir() => Ok(std::fs::remove_dir_all(path)?),
        Ok(_) => Err(RemoteError::Local(format!(
            "{} is not a real directory",
            path.display()
        ))),
    }
}

/// How often a contended lock is retried before reporting another holder.
/// `flock` belongs to the open file description, which a child forked by
/// any thread of this process shares until its exec closes it; a lock
/// dropped and retaken in that window looks held for a moment. A real
/// holder keeps it for a whole sync, far longer than these retries.
const LOCK_ATTEMPTS: u32 = 20;
const LOCK_RETRY_PAUSE: std::time::Duration = std::time::Duration::from_millis(5);

/// Locks a replica's existing lock file as a sync would, without waiting
/// for a holder; `remote remove` holds it while it deletes.
pub(crate) fn lock_existing(path: &Path) -> Result<File, RemoteError> {
    lock_exclusive(path)
}

fn lock_exclusive(path: &Path) -> Result<File, RemoteError> {
    lock_exclusive_with(path, LOCK_ATTEMPTS, &mut |_| {
        std::thread::sleep(LOCK_RETRY_PAUSE)
    })
}

fn lock_exclusive_with(
    path: &Path,
    attempts: u32,
    pause: &mut dyn FnMut(u32),
) -> Result<File, RemoteError> {
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
        .map_err(|error| RemoteError::Local(format!("{}: {error}", path.display())))?;
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.uid() != super::current_uid() {
        return Err(RemoteError::Local(format!(
            "{} is not a lock file owned by the current user",
            path.display()
        )));
    }
    let mut attempt = 1;
    loop {
        // SAFETY: the descriptor is owned by `file` for the whole call.
        if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0 {
            return Ok(file);
        }
        let error = std::io::Error::last_os_error();
        match error.raw_os_error() {
            Some(libc::EWOULDBLOCK) if attempt < attempts => {
                pause(attempt);
                attempt += 1;
            }
            Some(libc::EWOULDBLOCK) => {
                return Err(RemoteError::Conflict(
                    "another zdrive process is syncing this remote; wait for it to finish"
                        .to_string(),
                ));
            }
            Some(libc::EINTR) => {}
            _ => {
                return Err(RemoteError::Local(format!(
                    "lock {}: {error}",
                    path.display()
                )));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::remote::TestDir;
    use crate::remote::format::pack_name;

    fn state_dir(test: &TestDir) -> PathBuf {
        test.path().join("state").join("remotes").join("main")
    }

    #[test]
    fn lock_is_exclusive_until_dropped() {
        let test = TestDir::new("state-lock");
        let dir = state_dir(&test);
        let first = RemoteState::open(&dir, "folder1").unwrap();
        assert!(matches!(
            RemoteState::open(&dir, "folder1"),
            Err(RemoteError::Conflict(_))
        ));
        drop(first);
        RemoteState::open(&dir, "folder1").unwrap();
    }

    #[test]
    fn lock_waits_out_a_descriptor_a_fork_briefly_shares() {
        use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
        let test = TestDir::new("state-lock-fork");
        std::fs::create_dir_all(test.path()).unwrap();
        let path = test.path().join("lock");
        let held = lock_exclusive_with(&path, 1, &mut |_| unreachable!()).unwrap();
        // A forked child's copy of the descriptor keeps the lock after the
        // parent closes its own.
        // SAFETY: dup returns a fresh descriptor that OwnedFd now owns.
        let inherited = unsafe { OwnedFd::from_raw_fd(libc::dup(held.as_raw_fd())) };
        drop(held);
        assert!(matches!(
            lock_exclusive_with(&path, 1, &mut |_| unreachable!()),
            Err(RemoteError::Conflict(_))
        ));
        let mut inherited = Some(inherited);
        let mut pauses = Vec::new();
        lock_exclusive_with(&path, 3, &mut |attempt| {
            pauses.push(attempt);
            // The child execs, closing its copy.
            inherited.take();
        })
        .unwrap();
        assert_eq!(pauses, [1]);
    }

    #[test]
    fn record_round_trips_and_resets_for_another_folder() {
        let test = TestDir::new("state-record");
        let dir = state_dir(&test);
        let name = pack_name(&[3; 16], 99);
        {
            let mut state = RemoteState::open(&dir, "folder1").unwrap();
            state.record.synced = Some(SyncedHead {
                number: 4,
                generation: "ab".repeat(48),
                record: "r".to_string(),
                record_md5: Some("cd".repeat(16)),
                encrypted_dir: "/tmp/x".to_string(),
                unix_seconds: 1,
            });
            state.record.pending_root = Some(PendingRoot {
                name: "n".to_string(),
                file_id: "id_1".to_string(),
            });
            state.save().unwrap();
            state.store_header(&name, b"header").unwrap();
            std::fs::write(state.outgoing_dir().join(&name), b"pack").unwrap();
        }
        {
            let state = RemoteState::open(&dir, "folder1").unwrap();
            assert_eq!(state.record.synced.as_ref().unwrap().number, 4);
            assert_eq!(state.record.pending_root.as_ref().unwrap().file_id, "id_1");
            assert_eq!(state.cached_header(&name).unwrap().unwrap(), b"header");
            assert_eq!(state.outgoing_packs().unwrap().len(), 1);
        }
        let state = RemoteState::open(&dir, "folder2").unwrap();
        assert_eq!(state.record.synced, None);
        assert_eq!(state.record.pending_root, None);
        assert_eq!(state.cached_header(&name).unwrap(), None);
        assert!(state.outgoing_packs().unwrap().is_empty());
    }

    #[test]
    fn refuses_tampered_or_unknown_state() {
        let test = TestDir::new("state-tamper");
        let dir = state_dir(&test);
        drop(RemoteState::open(&dir, "folder1").unwrap());
        let path = dir.join(STATE_FILE);
        let mut value: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        value["pending_root"] = serde_json::json!({"name": "n", "file_id": "../x"});
        write_private_file(&path, &serde_json::to_vec(&value).unwrap()).unwrap();
        assert!(matches!(
            RemoteState::open(&dir, "folder1"),
            Err(RemoteError::Local(_))
        ));
        value["pending_root"] = serde_json::Value::Null;
        let layout = serde_json::json!({
            "marker": "m", "marker_md5": "ab".repeat(16), "kdf": "k",
            "kdf_md5": "cd".repeat(16), "packs": "p", "roots": "r", "leases": "l",
        });
        value["layout"] = layout.clone();
        write_private_file(&path, &serde_json::to_vec(&value).unwrap()).unwrap();
        assert!(
            RemoteState::open(&dir, "folder1")
                .unwrap()
                .record
                .layout
                .is_some()
        );
        for (field, bad) in [("kdf_md5", "zz".repeat(16)), ("roots", "../r".to_string())] {
            let mut tampered = layout.clone();
            tampered[field] = serde_json::json!(bad);
            value["layout"] = tampered;
            write_private_file(&path, &serde_json::to_vec(&value).unwrap()).unwrap();
            assert!(
                matches!(
                    RemoteState::open(&dir, "folder1"),
                    Err(RemoteError::Local(_))
                ),
                "{field}"
            );
        }
        value["layout"] = serde_json::Value::Null;
        let lease = serde_json::json!({
            "replica": "0f".repeat(16), "file_id": "lease_1", "folder": "l", "created": true,
        });
        value["lease"] = lease.clone();
        write_private_file(&path, &serde_json::to_vec(&value).unwrap()).unwrap();
        assert!(
            RemoteState::open(&dir, "folder1")
                .unwrap()
                .record
                .lease
                .is_some_and(|lease| lease.created)
        );
        for (field, bad) in [
            ("replica", "0f".repeat(15)),
            ("replica", "zz".repeat(16)),
            ("file_id", "../x".to_string()),
            ("folder", "a/b".to_string()),
        ] {
            let mut tampered = lease.clone();
            tampered[field] = serde_json::json!(bad);
            value["lease"] = tampered;
            write_private_file(&path, &serde_json::to_vec(&value).unwrap()).unwrap();
            assert!(
                matches!(
                    RemoteState::open(&dir, "folder1"),
                    Err(RemoteError::Local(_))
                ),
                "{field}"
            );
        }
        value["lease"] = serde_json::Value::Null;
        value["synced"] = serde_json::json!({
            "number": 1, "generation": "ab".repeat(48), "record": "r",
            "record_md5": "short", "encrypted_dir": "/x", "unix_seconds": 1,
        });
        write_private_file(&path, &serde_json::to_vec(&value).unwrap()).unwrap();
        assert!(matches!(
            RemoteState::open(&dir, "folder1"),
            Err(RemoteError::Local(_))
        ));
        value["synced"] = serde_json::Value::Null;
        value["surprise"] = serde_json::json!(1);
        write_private_file(&path, &serde_json::to_vec(&value).unwrap()).unwrap();
        assert!(RemoteState::open(&dir, "folder1").is_err());
        value.as_object_mut().unwrap().remove("surprise");
        value["version"] = serde_json::json!(STATE_VERSION + 1);
        write_private_file(&path, &serde_json::to_vec(&value).unwrap()).unwrap();
        let error = RemoteState::open(&dir, "folder1").unwrap_err().to_string();
        assert!(error.contains("upgrade zdrive"), "{error}");
    }

    #[test]
    fn outgoing_queue_resumes_checkpoints_and_drops_leftovers() {
        let test = TestDir::new("state-outgoing");
        let state = RemoteState::open(&state_dir(&test), "folder1").unwrap();
        let dir = state.outgoing_dir();
        let kept = pack_name(&[1; 16], 10);
        let orphan = pack_name(&[2; 16], 20);
        std::fs::write(dir.join(&kept), b"pack").unwrap();
        let checkpoint = UploadCheckpoint {
            file_id: "file_1".to_string(),
            session_uri: Some("https://upload.example/session".to_string()),
        };
        state.save_checkpoint(&kept, &checkpoint).unwrap();
        state
            .save_checkpoint(
                &orphan,
                &UploadCheckpoint {
                    file_id: "file_2".to_string(),
                    session_uri: None,
                },
            )
            .unwrap();
        std::fs::write(dir.join(format!(".{kept}.1.0.tmp")), b"partial").unwrap();

        let packs = state.outgoing_packs().unwrap();
        assert_eq!(packs.len(), 1);
        assert_eq!(packs[0].name, kept);
        assert_eq!(packs[0].checkpoint.as_ref(), Some(&checkpoint));
        assert!(!dir.join(format!("{orphan}.json")).exists());
        assert!(!dir.join(format!(".{kept}.1.0.tmp")).exists());

        state.finish_outgoing(&kept).unwrap();
        assert!(state.outgoing_packs().unwrap().is_empty());

        std::fs::write(dir.join("unexpected"), b"x").unwrap();
        assert!(state.outgoing_packs().is_err());
    }

    #[test]
    fn header_cache_accepts_only_pack_names() {
        let test = TestDir::new("state-headers");
        let state = RemoteState::open(&state_dir(&test), "folder1").unwrap();
        assert!(state.store_header("../escape.zpk", b"x").is_err());
        assert_eq!(state.cached_header("../escape.zpk").unwrap(), None);
    }
}
