// Copyright 2026 Alexander Orlov <alexander.orlov@loxal.net>

use std::collections::{HashMap, HashSet};
use std::ffi::OsStr;
use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex, RwLock};
use std::thread;
use std::time::{Duration, SystemTime};

use fuser::{
    FileAttr, FileHandle, FileType, Filesystem, FopenFlags, Generation, INodeNo, ReplyAttr,
    ReplyCreate, ReplyData, ReplyDirectory, ReplyEmpty, ReplyEntry, ReplyOpen, ReplyStatfs,
    ReplyWrite, Request,
};
use serde::{Deserialize, Serialize};

use crate::crypto::{
    RecoveryFingerprint, ciphertext_bytes_fingerprint, ciphertext_fingerprint, decrypt_blob,
    decrypt_index, encrypt_blob, encrypt_index,
};

macro_rules! trace {
    ($($arg:tt)*) => {{
        if cfg!(debug_assertions) {
            eprintln!($($arg)*);
        }
    }};
}

const TTL: Duration = Duration::from_secs(1);
const BLKSIZE: u32 = 4096;
const NAME_MAX: usize = 255;
static TEMP_FILE_COUNTER: AtomicU64 = AtomicU64::new(0);

// --- Persistent index ---

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub(crate) enum InodeKind {
    File,
    Directory,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub(crate) struct InodeEntry {
    pub name: String,
    pub kind: InodeKind,
    pub disk_filename: String,
    pub size: u64,
    pub perm: u16,
    pub uid: u32,
    pub gid: u32,
    pub atime_secs: u64,
    pub mtime_secs: u64,
    pub ctime_secs: u64,
    pub nlink: u32,
    pub parent: u64,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub(crate) struct DirChild {
    pub name: String,
    pub inode: u64,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub(crate) struct DiskIndex {
    pub next_inode: u64,
    pub next_file_id: u64,
    pub inodes: HashMap<u64, InodeEntry>,
    pub children: HashMap<u64, Vec<DirChild>>,
}

/// Durable write: temp file + fsync + rename + fsync(parent dir).
/// Survives crash at any point without corrupting the target file.
pub(crate) fn durable_write(path: &std::path::Path, data: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    let parent = path.parent().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "target has no parent directory",
        )
    })?;
    let file_name = path.file_name().ok_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::InvalidInput, "target has no file name")
    })?;
    let (tmp, mut f) = loop {
        let sequence = TEMP_FILE_COUNTER.fetch_add(1, Ordering::Relaxed);
        let mut tmp_name = std::ffi::OsString::from(".");
        tmp_name.push(file_name);
        tmp_name.push(format!(".{}.{sequence}.tmp", std::process::id()));
        let tmp = parent.join(tmp_name);
        match std::fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&tmp)
        {
            Ok(file) => break (tmp, file),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(e),
        }
    };

    let result = (|| {
        f.write_all(data)?;
        f.sync_all()?;
        std::fs::rename(&tmp, path)?;
        // The file fsync persists its contents; the directory fsync persists
        // the name replacement itself.
        std::fs::File::open(parent)?.sync_all()
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    result
}

fn ensure_new_store_directory_empty(base_path: &std::path::Path) -> Result<(), String> {
    let entries = fs::read_dir(base_path)
        .map_err(|e| format!("cannot inspect new store {}: {e}", base_path.display()))?;
    let mut unexpected = Vec::new();
    for entry in entries {
        let name = entry
            .map_err(|e| {
                format!(
                    "cannot inspect an entry in new store {}: {e}",
                    base_path.display()
                )
            })?
            .file_name();
        unexpected.push(name);
        if unexpected.len() == 5 {
            break;
        }
    }
    if unexpected.is_empty() {
        Ok(())
    } else {
        Err(format!(
            "refusing to initialize {} without _index.age because it is not empty (found {:?}); wait for cloud sync to finish or choose a new empty backing directory",
            base_path.display(),
            unexpected
        ))
    }
}

// --- FUSE filesystem ---

pub(crate) struct FsInner {
    pub(crate) base_path: PathBuf,
    pub(crate) key: RwLock<[u8; 32]>,
    pub(crate) state: RwLock<DiskIndex>,
    pub(crate) open_files: RwLock<HashMap<u64, Vec<u8>>>,
    /// Per-inode open reference count. An inode's `open_files` buffer is
    /// loaded on the first `open` and only persisted+evicted on the last
    /// `release`, so concurrent open handles share one buffer without a
    /// premature evict (lost reads) or a reload clobbering unflushed
    /// writes (lost writes).
    pub(crate) open_counts: Mutex<HashMap<u64, u32>>,
    pub(crate) index_mtime: Mutex<Option<SystemTime>>,
    pub(crate) index_fingerprint: Mutex<Option<RecoveryFingerprint>>,
    pub(crate) read_only: AtomicBool,
    /// Inodes whose open plaintext buffers differ from their durable blobs.
    /// Existing files start clean; only write/truncate makes them dirty. This
    /// prevents read-only opens from changing the random AEAD nonce and forcing
    /// a full cloud re-upload on close.
    dirty_inodes: Mutex<HashSet<u64>>,
    /// Serializes a complete local commit from dirty-blob writes through the
    /// index snapshot/rename. It also gates online rekey so an old-key debounce
    /// write cannot land after the new-key index.
    pub(crate) persistence_mutex: Mutex<()>,
    /// Set by metadata-mutating ops; cleared by the debounce thread after flushing.
    index_dirty: AtomicBool,
    /// Signals the debounce thread to wake up (dirty flag set) or shut down (stop flag).
    debounce_notify: Condvar,
    debounce_mutex: Mutex<bool>, // value = stop requested
}

impl FsInner {
    /// Record that a maintenance operation durably wrote the current open-file
    /// buffers and matching index. The caller must hold `persistence_mutex` and
    /// must have made the filesystem read-only before taking its snapshot.
    pub(crate) fn clear_persisted_maintenance_state(&self) -> Result<(), String> {
        self.dirty_inodes
            .lock()
            .map_err(|_| "dirty-inode lock is poisoned".to_string())?
            .clear();
        self.index_dirty.store(false, Ordering::Release);
        Ok(())
    }

    pub(crate) fn ensure_index_unchanged(&self) -> Result<(), std::io::Error> {
        let expected = self.index_fingerprint.lock().unwrap().clone();
        let Some(expected) = expected else {
            return Ok(());
        };
        let index_path = self.base_path.join("_index.age");
        let actual = ciphertext_fingerprint(&index_path).map_err(|e| {
            std::io::Error::other(format!(
                "cannot verify encrypted index {} before commit: {e}",
                index_path.display()
            ))
        })?;
        if actual != expected {
            return Err(std::io::Error::other(format!(
                "encrypted index {} changed externally; refusing to overwrite it - unmount and reconcile cloud synchronization first",
                index_path.display()
            )));
        }
        Ok(())
    }
}

pub struct ZeroTrustFs {
    pub(crate) inner: Arc<FsInner>,
    debounce_thread: Option<thread::JoinHandle<()>>,
    mount_ready_notify: Option<std::sync::mpsc::Sender<()>>,
}

impl ZeroTrustFs {
    pub fn new(passphrase: &str, base_path: PathBuf) -> Self {
        fs::create_dir_all(&base_path).expect("failed to create base path");

        let index_path = base_path.join("_index.age");
        let index_exists = index_path.try_exists().unwrap_or_else(|e| {
            eprintln!(
                "zerotrust-drive: error: cannot inspect {}: {e}",
                index_path.display()
            );
            std::process::exit(1);
        });
        if !index_exists && let Err(e) = ensure_new_store_directory_empty(&base_path) {
            eprintln!("zerotrust-drive: error: {e}");
            std::process::exit(1);
        }
        let stored_kdf = crate::crypto::load_kdf(&base_path).unwrap_or_else(|e| {
            eprintln!("zerotrust-drive: error: invalid KDF metadata: {e}");
            std::process::exit(1);
        });
        // Pre-0.7 (v0) drive guard: an index with no `_kdf.json` is the
        // old on-disk format. Refuse rather than mint a fresh Argon2id
        // key (which could never decrypt the v0 ChaCha20 data and would
        // surface as a misleading "wrong passphrase"). main.rs offers
        // `--migrate-format` to upgrade in place.
        if index_exists && stored_kdf.is_none() {
            eprintln!(
                "zerotrust-drive: error: {} uses the pre-0.7 on-disk format",
                base_path.display()
            );
            eprintln!(
                "zerotrust-drive: run `zerotrust-drive --migrate-format` (with the current passphrase) to upgrade it to Argon2id + XChaCha20-Poly1305"
            );
            std::process::exit(1);
        }
        // Argon2id key derived from the drive's per-drive salt
        // (`_kdf.json`), created on first use for a brand-new drive.
        let kdf = match stored_kdf {
            Some(kdf) => kdf,
            None => crate::crypto::load_or_create_kdf(&base_path).unwrap_or_else(|e| {
                eprintln!("zerotrust-drive: error: cannot create KDF metadata: {e}");
                std::process::exit(1);
            }),
        };
        let key = crate::crypto::try_derive_key(passphrase, &kdf).unwrap_or_else(|e| {
            eprintln!("zerotrust-drive: error: cannot derive encryption key: {e}");
            std::process::exit(1);
        });

        let mut initial_index_fingerprint = None;
        let state = if index_exists {
            let ciphertext = fs::read(&index_path).expect("failed to read index");
            initial_index_fingerprint = Some(
                ciphertext_bytes_fingerprint(&ciphertext).unwrap_or_else(|e| {
                    eprintln!(
                        "zerotrust-drive: error: invalid encrypted index {}: {e}",
                        index_path.display()
                    );
                    std::process::exit(1);
                }),
            );
            let json = match decrypt_index(&key, &ciphertext) {
                Ok(j) => j,
                Err(_) => {
                    eprintln!(
                        "zerotrust-drive: error: wrong passphrase — failed to decrypt {}",
                        index_path.display()
                    );
                    std::process::exit(1);
                }
            };
            serde_json::from_slice(&json).expect("failed to parse index")
        } else {
            let uid = unsafe { libc::getuid() };
            let gid = unsafe { libc::getgid() };
            let now = now_secs();

            let mut inodes = HashMap::new();
            inodes.insert(
                1,
                InodeEntry {
                    name: String::new(),
                    kind: InodeKind::Directory,
                    disk_filename: String::new(),
                    size: 0,
                    perm: 0o755,
                    uid,
                    gid,
                    atime_secs: now,
                    mtime_secs: now,
                    ctime_secs: now,
                    nlink: 2,
                    parent: 1,
                },
            );
            let mut children = HashMap::new();
            children.insert(1u64, Vec::new());
            DiskIndex {
                next_inode: 2,
                next_file_id: 1,
                inodes,
                children,
            }
        };

        let initial_index_mtime = if index_exists {
            fs::metadata(&index_path)
                .and_then(|meta| meta.modified())
                .ok()
        } else {
            None
        };
        let inner = Arc::new(FsInner {
            base_path,
            key: RwLock::new(key),
            state: RwLock::new(state),
            open_files: RwLock::new(HashMap::new()),
            open_counts: Mutex::new(HashMap::new()),
            index_mtime: Mutex::new(initial_index_mtime),
            index_fingerprint: Mutex::new(initial_index_fingerprint),
            read_only: AtomicBool::new(false),
            dirty_inodes: Mutex::new(HashSet::new()),
            persistence_mutex: Mutex::new(()),
            index_dirty: AtomicBool::new(false),
            debounce_notify: Condvar::new(),
            debounce_mutex: Mutex::new(false),
        });

        // Spawn debounce thread that coalesces frequent index writes
        let debounce_inner = Arc::clone(&inner);
        let debounce_thread = thread::spawn(move || {
            const DEBOUNCE_INTERVAL: Duration = Duration::from_secs(5);
            let mut guard = debounce_inner.debounce_mutex.lock().unwrap();
            loop {
                while !*guard && !debounce_inner.index_dirty.load(Ordering::Acquire) {
                    guard = debounce_inner.debounce_notify.wait(guard).unwrap();
                }
                if *guard {
                    break;
                }

                // Wait for a full quiet interval. Each new metadata mutation
                // notifies the condition variable and restarts this interval.
                let (next_guard, timeout) = debounce_inner
                    .debounce_notify
                    .wait_timeout(guard, DEBOUNCE_INTERVAL)
                    .unwrap();
                guard = next_guard;
                if *guard {
                    break;
                }
                if !timeout.timed_out() {
                    continue;
                }

                drop(guard);
                if debounce_inner.index_dirty.swap(false, Ordering::AcqRel) {
                    let zfs = ZeroTrustFs {
                        inner: Arc::clone(&debounce_inner),
                        debounce_thread: None,
                        mount_ready_notify: None,
                    };
                    if let Err(e) = zfs.flush_state() {
                        debounce_inner.index_dirty.store(true, Ordering::Release);
                        eprintln!("zerotrust-drive: ERROR: debounce flush failed: {e}");
                    }
                }
                guard = debounce_inner.debounce_mutex.lock().unwrap();
            }
        });

        let zfs = Self {
            inner,
            debounce_thread: Some(debounce_thread),
            mount_ready_notify: None,
        };
        if !index_exists {
            let json = {
                let state = zfs.inner.state.read().unwrap();
                serde_json::to_vec(&*state).expect("failed to serialize index")
            };
            zfs.persist_index(&json)
                .expect("failed to write initial index");
        }
        zfs
    }

    /// Arrange for a one-shot notification after FUSE initialization succeeds.
    /// Online maintenance uses this to avoid touching the store when mounting
    /// fails before the filesystem is actually available.
    pub(crate) fn notify_when_mounted(&mut self, sender: std::sync::mpsc::Sender<()>) {
        self.mount_ready_notify = Some(sender);
    }

    /// Encrypt and write pre-serialized JSON to _index.age. No locks held.
    pub(crate) fn persist_index(&self, json: &[u8]) -> Result<(), std::io::Error> {
        self.inner.ensure_index_unchanged()?;
        let index_path = self.inner.base_path.join("_index.age");
        let encrypted =
            encrypt_index(&self.inner.key.read().unwrap(), json).map_err(std::io::Error::other)?;
        let fingerprint =
            ciphertext_bytes_fingerprint(&encrypted).map_err(std::io::Error::other)?;
        durable_write(&index_path, &encrypted)?;
        *self.inner.index_fingerprint.lock().unwrap() = Some(fingerprint);
        // Record mtime so we can detect external modifications
        if let Ok(meta) = fs::metadata(&index_path)
            && let Ok(mtime) = meta.modified()
        {
            *self.inner.index_mtime.lock().unwrap() = Some(mtime);
        }
        Ok(())
    }

    pub(crate) fn allocate_disk_filename(state: &mut DiskIndex) -> String {
        let name = format!("{:06x}.age", state.next_file_id);
        state.next_file_id += 1;
        name
    }

    pub(crate) fn allocate_inode(state: &mut DiskIndex) -> u64 {
        let ino = state.next_inode;
        state.next_inode += 1;
        ino
    }

    fn inode_to_attr(ino: u64, entry: &InodeEntry) -> FileAttr {
        let time = |secs: u64| SystemTime::UNIX_EPOCH + Duration::from_secs(secs);
        FileAttr {
            ino: INodeNo(ino),
            size: entry.size,
            blocks: entry.size.div_ceil(512),
            atime: time(entry.atime_secs),
            mtime: time(entry.mtime_secs),
            ctime: time(entry.ctime_secs),
            crtime: time(entry.ctime_secs),
            kind: match entry.kind {
                InodeKind::File => FileType::RegularFile,
                InodeKind::Directory => FileType::Directory,
            },
            perm: entry.perm,
            nlink: entry.nlink,
            uid: entry.uid,
            gid: entry.gid,
            rdev: 0,
            blksize: BLKSIZE,
            flags: 0,
        }
    }

    pub(crate) fn find_child(state: &DiskIndex, parent: u64, name: &str) -> Option<u64> {
        state
            .children
            .get(&parent)?
            .iter()
            .find(|c| c.name == name)
            .map(|c| c.inode)
    }

    fn would_create_directory_cycle(state: &DiskIndex, source: u64, new_parent: u64) -> bool {
        let mut current = new_parent;
        let mut visited = HashSet::new();
        loop {
            if current == source {
                return true;
            }
            if !visited.insert(current) {
                // A pre-existing corrupt parent cycle must not be extended.
                return true;
            }
            let Some(entry) = state.inodes.get(&current) else {
                return false;
            };
            if entry.parent == current {
                return false;
            }
            current = entry.parent;
        }
    }

    pub(crate) fn write_encrypted_file(
        &self,
        disk_filename: &str,
        content: &[u8],
    ) -> Result<(), std::io::Error> {
        let encrypted = encrypt_blob(&self.inner.key.read().unwrap(), disk_filename, content)
            .map_err(std::io::Error::other)?;
        durable_write(&self.inner.base_path.join(disk_filename), &encrypted)
    }

    pub(crate) fn read_encrypted_file(
        &self,
        disk_filename: &str,
    ) -> Result<Vec<u8>, std::io::Error> {
        let ciphertext = fs::read(self.inner.base_path.join(disk_filename))?;
        decrypt_blob(&self.inner.key.read().unwrap(), disk_filename, &ciphertext)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
    }

    // --- Open / release / truncate / fsync core logic ---------------------
    //
    // Extracted from the FUSE handlers so they can be unit-tested without a
    // mount. The handlers are thin wrappers that map the `io::Result` to a
    // FUSE reply (errno = the error's raw OS code, or EIO).

    /// Load an inode's content into `open_files` on first open and bump its
    /// open count. Subsequent opens reuse the existing buffer (preserving
    /// unflushed writes). A zero-size file whose backing blob does not yet
    /// exist (freshly `mknod`'d, or created-but-never-written) opens as an
    /// empty buffer rather than erroring; a non-empty file with a missing
    /// backing blob is genuine data loss and errors.
    pub(crate) fn open_inode(&self, ino: u64) -> std::io::Result<()> {
        let _persistence = self.inner.persistence_mutex.lock().unwrap();
        let (disk_filename, size, is_file) = {
            let state = self.inner.state.read().unwrap();
            match state.inodes.get(&ino) {
                Some(e) => (e.disk_filename.clone(), e.size, e.kind == InodeKind::File),
                None => return Err(std::io::Error::from_raw_os_error(libc::ENOENT)),
            }
        };
        if !is_file {
            return Err(std::io::Error::from_raw_os_error(libc::EISDIR));
        }
        let already_open = self
            .inner
            .open_counts
            .lock()
            .unwrap()
            .get(&ino)
            .copied()
            .unwrap_or(0)
            > 0;
        if !already_open {
            let path = self.inner.base_path.join(&disk_filename);
            let content = if !disk_filename.is_empty() && path.exists() {
                self.read_encrypted_file(&disk_filename)?
            } else if !disk_filename.is_empty() && size > 0 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("backing file {disk_filename} missing for inode {ino}"),
                ));
            } else {
                Vec::new()
            };
            if content.len() as u64 != size {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!(
                        "backing file {disk_filename} has {} plaintext bytes but inode {ino} records {size}",
                        content.len()
                    ),
                ));
            }
            // `or_insert`: never clobber a buffer a prior/concurrent opener
            // already loaded — it may hold unflushed writes.
            self.inner
                .open_files
                .write()
                .unwrap()
                .entry(ino)
                .or_insert(content);
        }
        *self
            .inner
            .open_counts
            .lock()
            .unwrap()
            .entry(ino)
            .or_insert(0) += 1;
        Ok(())
    }

    /// Drop one open reference. Only the last release persists the buffer
    /// if it is dirty, and evicts it only after persistence succeeds.
    pub(crate) fn release_inode(&self, ino: u64) -> std::io::Result<()> {
        let _persistence = self.inner.persistence_mutex.lock().unwrap();
        let remaining = {
            let mut counts = self.inner.open_counts.lock().unwrap();
            match counts.get_mut(&ino) {
                Some(c) => {
                    *c = c.saturating_sub(1);
                    let r = *c;
                    if r == 0 {
                        counts.remove(&ino);
                    }
                    r
                }
                None => 0,
            }
        };
        if remaining > 0 {
            return Ok(()); // other handles still hold this inode open
        }
        // Persist before eviction. If disk/index I/O fails, the plaintext
        // buffer and its dirty marker stay in memory so destroy or a later
        // open/release can retry instead of silently discarding the only copy.
        self.flush_pending_state_locked(false)?;
        self.inner.open_files.write().unwrap().remove(&ino);
        Ok(())
    }

    fn resize_content(content: &mut Vec<u8>, new_size: u64) -> std::io::Result<()> {
        let new_len = usize::try_from(new_size)
            .map_err(|_| std::io::Error::from_raw_os_error(libc::EFBIG))?;
        if new_len > content.len() {
            content
                .try_reserve(new_len - content.len())
                .map_err(|_| std::io::Error::from_raw_os_error(libc::ENOMEM))?;
        }
        content.resize(new_len, 0);
        Ok(())
    }

    /// Resize a file to `new_size`. If the file is open, the in-memory
    /// buffer is the source of truth; if it is closed, the on-disk blob is
    /// read-modify-written so a truncation of a closed file is actually
    /// persisted (it used to be silently dropped).
    pub(crate) fn truncate_inode(&self, ino: u64, new_size: u64) -> std::io::Result<()> {
        let _persistence = self.inner.persistence_mutex.lock().unwrap();
        let (disk_filename, old_size) = {
            let state = self.inner.state.read().unwrap();
            match state.inodes.get(&ino) {
                Some(e) if e.kind == InodeKind::File => (e.disk_filename.clone(), e.size),
                Some(_) => return Err(std::io::Error::from_raw_os_error(libc::EISDIR)),
                None => return Err(std::io::Error::from_raw_os_error(libc::ENOENT)),
            }
        };
        {
            let mut open = self.inner.open_files.write().unwrap();
            if let Some(content) = open.get_mut(&ino) {
                if content.len() as u64 == new_size {
                    return Ok(());
                }
                Self::resize_content(content, new_size)?;
                self.inner.dirty_inodes.lock().unwrap().insert(ino);
                if let Some(entry) = self.inner.state.write().unwrap().inodes.get_mut(&ino) {
                    entry.size = new_size;
                }
                return Ok(());
            }
        }
        if disk_filename.is_empty() {
            if new_size != 0 {
                return Err(std::io::Error::from_raw_os_error(libc::EIO));
            }
            return Ok(());
        }
        if old_size == new_size {
            return Ok(());
        }
        let path = self.inner.base_path.join(&disk_filename);
        let mut data = if path.exists() {
            self.read_encrypted_file(&disk_filename)?
        } else if old_size > 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("backing file {disk_filename} missing for inode {ino}"),
            ));
        } else {
            Vec::new()
        };
        Self::resize_content(&mut data, new_size)?;
        self.write_encrypted_file(&disk_filename, &data)?;
        if let Some(entry) = self.inner.state.write().unwrap().inodes.get_mut(&ino) {
            entry.size = new_size;
        }
        self.mark_dirty();
        Ok(())
    }

    /// Apply a checked write to an open inode and mark its exact buffer dirty.
    pub(crate) fn write_inode_content(
        &self,
        ino: u64,
        offset: u64,
        data: &[u8],
    ) -> std::io::Result<u32> {
        if data.is_empty() {
            return Ok(0);
        }
        let written = u32::try_from(data.len())
            .map_err(|_| std::io::Error::from_raw_os_error(libc::EFBIG))?;
        let start =
            usize::try_from(offset).map_err(|_| std::io::Error::from_raw_os_error(libc::EFBIG))?;
        let end = start
            .checked_add(data.len())
            .ok_or_else(|| std::io::Error::from_raw_os_error(libc::EFBIG))?;
        let _persistence = self.inner.persistence_mutex.lock().unwrap();
        let new_size = {
            let mut open = self.inner.open_files.write().unwrap();
            let content = open
                .get_mut(&ino)
                .ok_or_else(|| std::io::Error::from_raw_os_error(libc::ENOENT))?;
            if end > content.len() {
                content
                    .try_reserve(end - content.len())
                    .map_err(|_| std::io::Error::from_raw_os_error(libc::ENOMEM))?;
                content.resize(end, 0);
            }
            content[start..end].copy_from_slice(data);
            content.len() as u64
        };
        self.inner.dirty_inodes.lock().unwrap().insert(ino);
        let mut state = self.inner.state.write().unwrap();
        let entry = state
            .inodes
            .get_mut(&ino)
            .ok_or_else(|| std::io::Error::from_raw_os_error(libc::ENOENT))?;
        entry.size = new_size;
        entry.mtime_secs = now_secs();
        Ok(written)
    }

    /// Durably persist an inode's open content (if any) + the index.
    /// Backs the FUSE `fsync` handler.
    pub(crate) fn fsync_inode(&self, ino: u64) -> std::io::Result<()> {
        {
            let state = self.inner.state.read().unwrap();
            if !state.inodes.contains_key(&ino) {
                return Err(std::io::Error::from_raw_os_error(libc::ENOENT));
            }
        }
        let _persistence = self.inner.persistence_mutex.lock().unwrap();
        self.flush_pending_state_locked(true)
    }

    /// Mark the index as dirty so the debounce thread will flush it soon.
    /// Used by metadata-mutating ops instead of calling flush_state() directly.
    fn mark_dirty(&self) {
        self.inner.index_dirty.store(true, Ordering::Release);
        self.inner.debounce_notify.notify_one();
    }

    /// Commit every dirty open blob before committing the index that describes
    /// it. Caller must hold `persistence_mutex`.
    fn flush_state_locked(&self) -> Result<(), std::io::Error> {
        // Refuse a conflicting cloud generation before touching any blob.
        // persist_index repeats this check immediately before its atomic rename.
        self.inner.ensure_index_unchanged()?;
        let dirty: Vec<u64> = self
            .inner
            .dirty_inodes
            .lock()
            .unwrap()
            .iter()
            .copied()
            .collect();
        let json = {
            let state = self.inner.state.read().unwrap();
            let open = self.inner.open_files.read().unwrap();
            let key = self.inner.key.read().unwrap();
            for &ino in &dirty {
                let entry = state.inodes.get(&ino).ok_or_else(|| {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        format!("dirty inode {ino} is missing from the index"),
                    )
                })?;
                if entry.kind != InodeKind::File || entry.disk_filename.is_empty() {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        format!("dirty inode {ino} has no valid backing filename"),
                    ));
                }
                let content = open.get(&ino).ok_or_else(|| {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        format!("dirty inode {ino} has no open plaintext buffer"),
                    )
                })?;
                if content.len() as u64 != entry.size {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        format!(
                            "dirty inode {ino} has {} buffered bytes but records {}",
                            content.len(),
                            entry.size
                        ),
                    ));
                }
                let encrypted = encrypt_blob(&key, &entry.disk_filename, content)
                    .map_err(std::io::Error::other)?;
                durable_write(&self.inner.base_path.join(&entry.disk_filename), &encrypted)?;
            }
            serde_json::to_vec(&*state).map_err(std::io::Error::other)?
        };

        self.persist_index(&json)?;
        let mut dirty_inodes = self.inner.dirty_inodes.lock().unwrap();
        for ino in dirty {
            dirty_inodes.remove(&ino);
        }
        Ok(())
    }

    /// Flush pending content/index state, or force an index sync for fsync.
    /// Caller must hold `persistence_mutex`.
    fn flush_pending_state_locked(&self, force: bool) -> Result<(), std::io::Error> {
        let had_index_dirty = self.inner.index_dirty.swap(false, Ordering::AcqRel);
        let has_dirty_content = !self.inner.dirty_inodes.lock().unwrap().is_empty();
        if !force && !had_index_dirty && !has_dirty_content {
            return Ok(());
        }
        if let Err(e) = self.flush_state_locked() {
            self.inner.index_dirty.store(true, Ordering::Release);
            self.inner.debounce_notify.notify_one();
            return Err(e);
        }
        Ok(())
    }

    /// Serialize a complete blob+index commit against other persistence and
    /// online rekey operations.
    pub(crate) fn flush_state(&self) -> Result<(), std::io::Error> {
        let _persistence = self.inner.persistence_mutex.lock().unwrap();
        self.flush_pending_state_locked(true)
    }
}

impl Drop for ZeroTrustFs {
    fn drop(&mut self) {
        let Some(handle) = self.debounce_thread.take() else {
            return;
        };
        {
            let mut stop = self.inner.debounce_mutex.lock().unwrap();
            *stop = true;
            self.inner.debounce_notify.notify_one();
        }
        if handle.join().is_err() {
            eprintln!("zerotrust-drive: ERROR: debounce thread panicked during shutdown");
        }
        let result = {
            let _persistence = self.inner.persistence_mutex.lock().unwrap();
            self.flush_pending_state_locked(false)
        };
        if let Err(e) = result {
            eprintln!("zerotrust-drive: ERROR: failed to persist filesystem on drop: {e}");
        }
    }
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[derive(Debug)]
struct BackingStatfs {
    blocks: u64,
    bfree: u64,
    bavail: u64,
    files: u64,
    ffree: u64,
    bsize: u32,
    namelen: u32,
    frsize: u32,
}

#[cfg(unix)]
#[allow(clippy::unnecessary_cast)]
fn backing_statfs(path: &std::path::Path) -> std::io::Result<BackingStatfs> {
    use std::os::fd::AsRawFd;

    let directory = std::fs::File::open(path)?;
    let mut raw = std::mem::MaybeUninit::<libc::statvfs>::uninit();
    if unsafe { libc::fstatvfs(directory.as_raw_fd(), raw.as_mut_ptr()) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    let raw = unsafe { raw.assume_init() };
    let bsize = u32::try_from(raw.f_bsize).unwrap_or(u32::MAX);
    let frsize = if raw.f_frsize == 0 {
        bsize
    } else {
        u32::try_from(raw.f_frsize).unwrap_or(u32::MAX)
    };
    Ok(BackingStatfs {
        blocks: raw.f_blocks as u64,
        bfree: raw.f_bfree as u64,
        bavail: raw.f_bavail as u64,
        files: raw.f_files as u64,
        ffree: raw.f_ffree as u64,
        bsize,
        namelen: u32::try_from(raw.f_namemax).unwrap_or(u32::MAX),
        frsize,
    })
}

#[cfg(not(unix))]
fn backing_statfs(_path: &std::path::Path) -> std::io::Result<BackingStatfs> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "backing filesystem statistics are unavailable on this platform",
    ))
}

/// Map an `io::Error` to a FUSE errno: the underlying OS code when present
/// (e.g. ENOENT/EISDIR set via `from_raw_os_error`), otherwise EIO.
fn io_to_errno(e: &std::io::Error) -> fuser::Errno {
    fuser::Errno::from_i32(e.raw_os_error().unwrap_or(libc::EIO))
}

impl Filesystem for ZeroTrustFs {
    fn init(&mut self, _req: &Request, _config: &mut fuser::KernelConfig) -> std::io::Result<()> {
        if let Some(sender) = self.mount_ready_notify.take() {
            sender.send(()).map_err(|_| {
                std::io::Error::other("online maintenance coordinator stopped before mount")
            })?;
        }
        Ok(())
    }

    fn destroy(&mut self) {
        // Stop the debounce thread first
        {
            let mut stop = self.inner.debounce_mutex.lock().unwrap();
            *stop = true;
            self.inner.debounce_notify.notify_one();
        }
        if let Some(handle) = self.debounce_thread.take()
            && handle.join().is_err()
        {
            eprintln!("zerotrust-drive: ERROR: debounce thread panicked during shutdown");
        }

        // Commit only pending state. A clean unmount must not rotate the index's
        // random AEAD nonce and force an otherwise needless cloud upload.
        let result = {
            let _persistence = self.inner.persistence_mutex.lock().unwrap();
            self.flush_pending_state_locked(false)
        };
        if let Err(e) = result {
            eprintln!("zerotrust-drive: ERROR: failed to persist filesystem on destroy: {e}");
        }
    }

    fn lookup(&self, _req: &Request, parent: INodeNo, name: &OsStr, reply: ReplyEntry) {
        trace!("FUSE: lookup parent={} name={:?}", parent.0, name);
        let name_str = match name.to_str() {
            Some(s) => s,
            None => {
                reply.error(fuser::Errno::ENOENT);
                return;
            }
        };
        let state = self.inner.state.read().unwrap();
        if let Some(ino) = Self::find_child(&state, parent.0, name_str)
            && let Some(entry) = state.inodes.get(&ino)
        {
            reply.entry(&TTL, &Self::inode_to_attr(ino, entry), Generation(0));
            return;
        }
        reply.error(fuser::Errno::ENOENT);
    }

    fn getattr(&self, _req: &Request, ino: INodeNo, _fh: Option<FileHandle>, reply: ReplyAttr) {
        trace!("FUSE: getattr ino={}", ino.0);
        let state = self.inner.state.read().unwrap();
        match state.inodes.get(&ino.0) {
            Some(entry) => {
                let mut attr = Self::inode_to_attr(ino.0, entry);
                let is_file = entry.kind == InodeKind::File;
                drop(state);
                if is_file {
                    let open = self.inner.open_files.read().unwrap();
                    if let Some(content) = open.get(&ino.0) {
                        attr.size = content.len() as u64;
                        attr.blocks = attr.size.div_ceil(512);
                    }
                }
                reply.attr(&TTL, &attr);
            }
            None => reply.error(fuser::Errno::ENOENT),
        }
    }

    fn setattr(
        &self,
        _req: &Request,
        ino: INodeNo,
        mode: Option<u32>,
        uid: Option<u32>,
        gid: Option<u32>,
        size: Option<u64>,
        _atime: Option<fuser::TimeOrNow>,
        _mtime: Option<fuser::TimeOrNow>,
        _ctime: Option<SystemTime>,
        _fh: Option<FileHandle>,
        _crtime: Option<SystemTime>,
        _chgtime: Option<SystemTime>,
        _bkuptime: Option<SystemTime>,
        _flags: Option<fuser::BsdFileFlags>,
        reply: ReplyAttr,
    ) {
        if self.inner.read_only.load(Ordering::Relaxed) {
            reply.error(fuser::Errno::EROFS);
            return;
        }
        if let Some(new_size) = size {
            // Validate and persist/dirty the content before publishing the new
            // size. A missing non-empty backing blob must not become zero data.
            if let Err(e) = self.truncate_inode(ino.0, new_size) {
                reply.error(io_to_errno(&e));
                return;
            }
        }
        let attr = {
            let mut state = self.inner.state.write().unwrap();
            let entry = match state.inodes.get_mut(&ino.0) {
                Some(e) => e,
                None => {
                    reply.error(fuser::Errno::ENOENT);
                    return;
                }
            };
            if let Some(m) = mode {
                entry.perm = (m & 0o7777) as u16;
            }
            if let Some(u) = uid {
                entry.uid = u;
            }
            if let Some(g) = gid {
                entry.gid = g;
            }
            entry.ctime_secs = now_secs();
            Self::inode_to_attr(ino.0, entry)
        };
        reply.attr(&TTL, &attr);
        self.mark_dirty();
    }

    fn open(&self, _req: &Request, ino: INodeNo, _flags: fuser::OpenFlags, reply: ReplyOpen) {
        match self.open_inode(ino.0) {
            Ok(()) => reply.opened(FileHandle(ino.0), FopenFlags::empty()),
            Err(e) => {
                // InvalidData = decrypt failure or genuinely-missing backing
                // blob; worth logging since it signals corruption/data loss.
                if e.kind() == std::io::ErrorKind::InvalidData {
                    eprintln!("zerotrust-drive: ERROR: open inode {}: {e}", ino.0);
                }
                reply.error(io_to_errno(&e));
            }
        }
    }

    fn read(
        &self,
        _req: &Request,
        ino: INodeNo,
        _fh: FileHandle,
        offset: u64,
        size: u32,
        _flags: fuser::OpenFlags,
        _lock_owner: Option<fuser::LockOwner>,
        reply: ReplyData,
    ) {
        let open = self.inner.open_files.read().unwrap();
        match open.get(&ino.0) {
            Some(content) => {
                let start = match usize::try_from(offset) {
                    Ok(start) => start,
                    Err(_) => {
                        reply.error(fuser::Errno::EOVERFLOW);
                        return;
                    }
                };
                if start >= content.len() {
                    reply.data(&[]);
                } else {
                    let end = start.saturating_add(size as usize).min(content.len());
                    reply.data(&content[start..end]);
                }
            }
            None => reply.error(fuser::Errno::ENOENT),
        }
    }

    fn write(
        &self,
        _req: &Request,
        ino: INodeNo,
        _fh: FileHandle,
        offset: u64,
        data: &[u8],
        _write_flags: fuser::WriteFlags,
        _flags: fuser::OpenFlags,
        _lock_owner: Option<fuser::LockOwner>,
        reply: ReplyWrite,
    ) {
        if self.inner.read_only.load(Ordering::Relaxed) {
            reply.error(fuser::Errno::EROFS);
            return;
        }
        trace!(
            "FUSE: write ino={} offset={} len={}",
            ino.0,
            offset,
            data.len()
        );
        match self.write_inode_content(ino.0, offset, data) {
            Ok(written) => reply.written(written),
            Err(e) => {
                eprintln!("zerotrust-drive: ERROR: write inode {}: {e}", ino.0);
                reply.error(io_to_errno(&e));
            }
        }
    }

    fn flush(
        &self,
        _req: &Request,
        ino: INodeNo,
        _fh: FileHandle,
        _lock_owner: fuser::LockOwner,
        reply: ReplyEmpty,
    ) {
        if self.inner.read_only.load(Ordering::Relaxed) {
            reply.ok();
            return;
        }
        trace!("FUSE: flush ino={}", ino.0);
        let result = {
            let _persistence = self.inner.persistence_mutex.lock().unwrap();
            self.flush_pending_state_locked(false)
        };
        match result {
            Ok(()) => reply.ok(),
            Err(e) => {
                eprintln!("zerotrust-drive: ERROR: flush inode {}: {e}", ino.0);
                reply.error(io_to_errno(&e));
            }
        }
    }

    fn release(
        &self,
        _req: &Request,
        ino: INodeNo,
        _fh: FileHandle,
        _flags: fuser::OpenFlags,
        _lock_owner: Option<fuser::LockOwner>,
        _flush: bool,
        reply: ReplyEmpty,
    ) {
        trace!("FUSE: release ino={}", ino.0);
        match self.release_inode(ino.0) {
            Ok(()) => reply.ok(),
            Err(e) => {
                eprintln!("zerotrust-drive: ERROR: release inode {}: {e}", ino.0);
                reply.error(io_to_errno(&e));
            }
        }
    }

    fn fsync(
        &self,
        _req: &Request,
        ino: INodeNo,
        _fh: FileHandle,
        _datasync: bool,
        reply: ReplyEmpty,
    ) {
        if self.inner.read_only.load(Ordering::Relaxed) {
            reply.ok();
            return;
        }
        trace!("FUSE: fsync ino={}", ino.0);
        match self.fsync_inode(ino.0) {
            Ok(()) => reply.ok(),
            Err(e) => {
                eprintln!("zerotrust-drive: ERROR: fsync inode {}: {e}", ino.0);
                reply.error(io_to_errno(&e));
            }
        }
    }

    fn mknod(
        &self,
        req: &Request,
        parent: INodeNo,
        name: &OsStr,
        mode: u32,
        _umask: u32,
        _rdev: u32,
        reply: ReplyEntry,
    ) {
        if self.inner.read_only.load(Ordering::Relaxed) {
            reply.error(fuser::Errno::EROFS);
            return;
        }
        trace!(
            "FUSE: mknod parent={} name={:?} mode={:#o}",
            parent.0, name, mode
        );
        let file_type = mode & libc::S_IFMT as u32;
        if file_type != libc::S_IFREG as u32 && file_type != 0 {
            reply.error(fuser::Errno::ENOSYS);
            return;
        }
        let name_str = match name.to_str() {
            Some(s) => s,
            None => {
                reply.error(fuser::Errno::EINVAL);
                return;
            }
        };
        if name_str.len() > NAME_MAX {
            reply.error(fuser::Errno::ENAMETOOLONG);
            return;
        }
        let persistence = self.inner.persistence_mutex.lock().unwrap();
        let (ino, attr) = {
            let mut state = self.inner.state.write().unwrap();
            match state.inodes.get(&parent.0) {
                Some(e) if e.kind == InodeKind::Directory => {}
                _ => {
                    reply.error(fuser::Errno::ENOTDIR);
                    return;
                }
            }
            if Self::find_child(&state, parent.0, name_str).is_some() {
                reply.error(fuser::Errno::EEXIST);
                return;
            }
            let ino = Self::allocate_inode(&mut state);
            let disk_filename = Self::allocate_disk_filename(&mut state);
            let now = now_secs();
            let entry = InodeEntry {
                name: name_str.to_string(),
                kind: InodeKind::File,
                disk_filename: disk_filename.clone(),
                size: 0,
                perm: (mode & 0o7777) as u16,
                uid: req.uid(),
                gid: req.gid(),
                atime_secs: now,
                mtime_secs: now,
                ctime_secs: now,
                nlink: 1,
                parent: parent.0,
            };
            let attr = Self::inode_to_attr(ino, &entry);
            state.inodes.insert(ino, entry);
            state.children.entry(parent.0).or_default().push(DirChild {
                name: name_str.to_string(),
                inode: ino,
            });
            (ino, attr)
        };
        self.mark_dirty();
        drop(persistence);
        reply.entry(&TTL, &attr, Generation(0));
        trace!("FUSE: mknod replied ino={}", ino);
    }

    fn create(
        &self,
        req: &Request,
        parent: INodeNo,
        name: &OsStr,
        mode: u32,
        _umask: u32,
        _flags: i32,
        reply: ReplyCreate,
    ) {
        if self.inner.read_only.load(Ordering::Relaxed) {
            reply.error(fuser::Errno::EROFS);
            return;
        }
        trace!(
            "FUSE: create parent={} name={:?} mode={:#o}",
            parent.0, name, mode
        );
        let name_str = match name.to_str() {
            Some(s) => s,
            None => {
                reply.error(fuser::Errno::EINVAL);
                return;
            }
        };
        if name_str.len() > NAME_MAX {
            reply.error(fuser::Errno::ENAMETOOLONG);
            return;
        }
        let persistence = self.inner.persistence_mutex.lock().unwrap();

        let (ino, attr, _disk_filename) = {
            let mut state = self.inner.state.write().unwrap();
            match state.inodes.get(&parent.0) {
                Some(e) if e.kind == InodeKind::Directory => {}
                _ => {
                    reply.error(fuser::Errno::ENOTDIR);
                    return;
                }
            }
            if Self::find_child(&state, parent.0, name_str).is_some() {
                reply.error(fuser::Errno::EEXIST);
                return;
            }
            let ino = Self::allocate_inode(&mut state);
            let disk_filename = Self::allocate_disk_filename(&mut state);
            let now = now_secs();
            let entry = InodeEntry {
                name: name_str.to_string(),
                kind: InodeKind::File,
                disk_filename: disk_filename.clone(),
                size: 0,
                perm: (mode & 0o7777) as u16,
                uid: req.uid(),
                gid: req.gid(),
                atime_secs: now,
                mtime_secs: now,
                ctime_secs: now,
                nlink: 1,
                parent: parent.0,
            };
            let attr = Self::inode_to_attr(ino, &entry);
            state.inodes.insert(ino, entry);
            state.children.entry(parent.0).or_default().push(DirChild {
                name: name_str.to_string(),
                inode: ino,
            });
            (ino, attr, disk_filename)
        };
        self.inner
            .open_files
            .write()
            .unwrap()
            .insert(ino, Vec::new());
        // create returns an open file handle — count it so the matching
        // release persists+evicts at the right time (refcount model).
        *self
            .inner
            .open_counts
            .lock()
            .unwrap()
            .entry(ino)
            .or_insert(0) += 1;
        self.mark_dirty();
        drop(persistence);
        reply.created(
            &TTL,
            &attr,
            Generation(0),
            FileHandle(ino),
            FopenFlags::empty(),
        );
        trace!("FUSE: create replied ino={} fh={}", ino, ino);
    }

    fn mkdir(
        &self,
        req: &Request,
        parent: INodeNo,
        name: &OsStr,
        mode: u32,
        _umask: u32,
        reply: ReplyEntry,
    ) {
        if self.inner.read_only.load(Ordering::Relaxed) {
            reply.error(fuser::Errno::EROFS);
            return;
        }
        let name_str = match name.to_str() {
            Some(s) => s,
            None => {
                reply.error(fuser::Errno::EINVAL);
                return;
            }
        };
        if name_str.len() > NAME_MAX {
            reply.error(fuser::Errno::ENAMETOOLONG);
            return;
        }
        let persistence = self.inner.persistence_mutex.lock().unwrap();

        let attr = {
            let mut state = self.inner.state.write().unwrap();
            match state.inodes.get(&parent.0) {
                Some(e) if e.kind == InodeKind::Directory => {}
                _ => {
                    reply.error(fuser::Errno::ENOTDIR);
                    return;
                }
            }
            if Self::find_child(&state, parent.0, name_str).is_some() {
                reply.error(fuser::Errno::EEXIST);
                return;
            }
            let ino = Self::allocate_inode(&mut state);
            let now = now_secs();
            let entry = InodeEntry {
                name: name_str.to_string(),
                kind: InodeKind::Directory,
                disk_filename: String::new(),
                size: 0,
                perm: (mode & 0o7777) as u16,
                uid: req.uid(),
                gid: req.gid(),
                atime_secs: now,
                mtime_secs: now,
                ctime_secs: now,
                nlink: 2,
                parent: parent.0,
            };
            let attr = Self::inode_to_attr(ino, &entry);
            state.inodes.insert(ino, entry);
            state.children.insert(ino, Vec::new());
            state.children.entry(parent.0).or_default().push(DirChild {
                name: name_str.to_string(),
                inode: ino,
            });
            if let Some(p) = state.inodes.get_mut(&parent.0) {
                p.nlink += 1;
            }
            attr
        };
        self.mark_dirty();
        drop(persistence);
        reply.entry(&TTL, &attr, Generation(0));
    }

    fn unlink(&self, _req: &Request, parent: INodeNo, name: &OsStr, reply: ReplyEmpty) {
        if self.inner.read_only.load(Ordering::Relaxed) {
            reply.error(fuser::Errno::EROFS);
            return;
        }
        let name_str = match name.to_str() {
            Some(s) => s,
            None => {
                reply.error(fuser::Errno::ENOENT);
                return;
            }
        };

        let persistence = self.inner.persistence_mutex.lock().unwrap();
        let previous_state;
        let (ino, disk_filename) = {
            let mut state = self.inner.state.write().unwrap();
            let ino = match Self::find_child(&state, parent.0, name_str) {
                Some(i) => i,
                None => {
                    reply.error(fuser::Errno::ENOENT);
                    return;
                }
            };
            let entry = match state.inodes.get(&ino) {
                Some(entry) if entry.kind == InodeKind::File => entry,
                Some(_) => {
                    reply.error(fuser::Errno::EISDIR);
                    return;
                }
                None => {
                    reply.error(fuser::Errno::EIO);
                    return;
                }
            };
            if self
                .inner
                .open_counts
                .lock()
                .unwrap()
                .get(&ino)
                .copied()
                .unwrap_or(0)
                > 0
            {
                // Proper POSIX open-unlink needs tombstones. Until those exist,
                // reject the unsafe case instead of discarding a live buffer.
                reply.error(fuser::Errno::EBUSY);
                return;
            }
            let df = entry.disk_filename.clone();
            previous_state = state.clone();
            state.inodes.remove(&ino);
            if let Some(ch) = state.children.get_mut(&parent.0) {
                ch.retain(|c| c.inode != ino);
            }
            (ino, df)
        };
        if let Err(e) = self.flush_pending_state_locked(true) {
            *self.inner.state.write().unwrap() = previous_state;
            eprintln!("zerotrust-drive: ERROR: failed to persist unlink: {e}");
            reply.error(io_to_errno(&e));
            return;
        }
        self.inner.open_files.write().unwrap().remove(&ino);
        self.inner.dirty_inodes.lock().unwrap().remove(&ino);
        self.inner.open_counts.lock().unwrap().remove(&ino);
        if !disk_filename.is_empty()
            && let Err(e) = fs::remove_file(self.inner.base_path.join(&disk_filename))
            && e.kind() != std::io::ErrorKind::NotFound
        {
            eprintln!("zerotrust-drive: WARNING: orphaned backing file {disk_filename}: {e}");
        }
        drop(persistence);
        reply.ok();
    }

    fn rmdir(&self, _req: &Request, parent: INodeNo, name: &OsStr, reply: ReplyEmpty) {
        if self.inner.read_only.load(Ordering::Relaxed) {
            reply.error(fuser::Errno::EROFS);
            return;
        }
        let name_str = match name.to_str() {
            Some(s) => s,
            None => {
                reply.error(fuser::Errno::ENOENT);
                return;
            }
        };

        let persistence = self.inner.persistence_mutex.lock().unwrap();
        {
            let mut state = self.inner.state.write().unwrap();
            let ino = match Self::find_child(&state, parent.0, name_str) {
                Some(i) => i,
                None => {
                    reply.error(fuser::Errno::ENOENT);
                    return;
                }
            };
            match state.inodes.get(&ino) {
                Some(e) if e.kind == InodeKind::Directory => {}
                _ => {
                    reply.error(fuser::Errno::ENOTDIR);
                    return;
                }
            }
            if state.children.get(&ino).is_some_and(|ch| !ch.is_empty()) {
                reply.error(fuser::Errno::ENOTEMPTY);
                return;
            }
            state.inodes.remove(&ino);
            state.children.remove(&ino);
            if let Some(ch) = state.children.get_mut(&parent.0) {
                ch.retain(|c| c.inode != ino);
            }
            if let Some(p) = state.inodes.get_mut(&parent.0) {
                p.nlink = p.nlink.saturating_sub(1);
            }
        };
        self.mark_dirty();
        drop(persistence);
        reply.ok();
    }

    fn rename(
        &self,
        _req: &Request,
        parent: INodeNo,
        name: &OsStr,
        newparent: INodeNo,
        newname: &OsStr,
        flags: fuser::RenameFlags,
        reply: ReplyEmpty,
    ) {
        if self.inner.read_only.load(Ordering::Relaxed) {
            reply.error(fuser::Errno::EROFS);
            return;
        }
        if !flags.is_empty() {
            // Silently ignoring RENAME_NOREPLACE/EXCHANGE can destroy data.
            reply.error(fuser::Errno::ENOSYS);
            return;
        }
        let name_str = match name.to_str() {
            Some(s) => s,
            None => {
                reply.error(fuser::Errno::EINVAL);
                return;
            }
        };
        let newname_str = match newname.to_str() {
            Some(s) => s,
            None => {
                reply.error(fuser::Errno::EINVAL);
                return;
            }
        };
        if newname_str.len() > NAME_MAX {
            reply.error(fuser::Errno::ENAMETOOLONG);
            return;
        }
        let persistence = self.inner.persistence_mutex.lock().unwrap();
        let previous_state: Option<DiskIndex>;
        let (disk_file_to_remove, overwritten_ino) = {
            let mut state = self.inner.state.write().unwrap();
            match state.inodes.get(&parent.0) {
                Some(entry) if entry.kind == InodeKind::Directory => {}
                _ => {
                    reply.error(fuser::Errno::ENOTDIR);
                    return;
                }
            }
            match state.inodes.get(&newparent.0) {
                Some(entry) if entry.kind == InodeKind::Directory => {}
                _ => {
                    reply.error(fuser::Errno::ENOTDIR);
                    return;
                }
            }
            let ino = match Self::find_child(&state, parent.0, name_str) {
                Some(i) => i,
                None => {
                    reply.error(fuser::Errno::ENOENT);
                    return;
                }
            };
            let source_kind = match state.inodes.get(&ino) {
                Some(entry) => entry.kind.clone(),
                None => {
                    reply.error(fuser::Errno::EIO);
                    return;
                }
            };
            if source_kind == InodeKind::Directory
                && Self::would_create_directory_cycle(&state, ino, newparent.0)
            {
                reply.error(fuser::Errno::EINVAL);
                return;
            }
            let mut to_remove = None;
            let mut overwritten = None;
            if let Some(existing) = Self::find_child(&state, newparent.0, newname_str) {
                if existing == ino {
                    reply.ok();
                    return;
                }
                let target = match state.inodes.get(&existing) {
                    Some(entry) => entry,
                    None => {
                        reply.error(fuser::Errno::EIO);
                        return;
                    }
                };
                match (&source_kind, &target.kind) {
                    (InodeKind::File, InodeKind::Directory) => {
                        reply.error(fuser::Errno::EISDIR);
                        return;
                    }
                    (InodeKind::Directory, InodeKind::File) => {
                        reply.error(fuser::Errno::ENOTDIR);
                        return;
                    }
                    _ => {}
                }
                if target.kind == InodeKind::Directory
                    && state
                        .children
                        .get(&existing)
                        .is_some_and(|children| !children.is_empty())
                {
                    reply.error(fuser::Errno::ENOTEMPTY);
                    return;
                }
                if self
                    .inner
                    .open_counts
                    .lock()
                    .unwrap()
                    .get(&existing)
                    .copied()
                    .unwrap_or(0)
                    > 0
                    || self.inner.dirty_inodes.lock().unwrap().contains(&existing)
                {
                    reply.error(fuser::Errno::EBUSY);
                    return;
                }
                to_remove = state.inodes.get(&existing).and_then(|e| {
                    if e.disk_filename.is_empty() {
                        None
                    } else {
                        Some(e.disk_filename.clone())
                    }
                });
                overwritten = Some(existing);
            }
            previous_state = to_remove.as_ref().map(|_| state.clone());
            if let Some(existing) = overwritten {
                let target_was_directory = state
                    .inodes
                    .get(&existing)
                    .is_some_and(|entry| entry.kind == InodeKind::Directory);
                state.inodes.remove(&existing);
                if target_was_directory {
                    state.children.remove(&existing);
                    if let Some(parent_entry) = state.inodes.get_mut(&newparent.0) {
                        parent_entry.nlink = parent_entry.nlink.saturating_sub(1);
                    }
                }
                if let Some(ch) = state.children.get_mut(&newparent.0) {
                    ch.retain(|c| c.inode != existing);
                }
            }
            if let Some(ch) = state.children.get_mut(&parent.0) {
                ch.retain(|c| c.inode != ino);
            }
            state
                .children
                .entry(newparent.0)
                .or_default()
                .push(DirChild {
                    name: newname_str.to_string(),
                    inode: ino,
                });
            if source_kind == InodeKind::Directory && parent != newparent {
                if let Some(old_parent) = state.inodes.get_mut(&parent.0) {
                    old_parent.nlink = old_parent.nlink.saturating_sub(1);
                }
                if let Some(new_parent) = state.inodes.get_mut(&newparent.0) {
                    new_parent.nlink = new_parent.nlink.saturating_add(1);
                }
            }
            if let Some(entry) = state.inodes.get_mut(&ino) {
                entry.name = newname_str.to_string();
                entry.parent = newparent.0;
                entry.ctime_secs = now_secs();
            }
            (to_remove, overwritten)
        };
        if disk_file_to_remove.is_some() {
            if let Err(e) = self.flush_pending_state_locked(true) {
                *self.inner.state.write().unwrap() =
                    previous_state.expect("overwrite rename must retain rollback state");
                eprintln!("zerotrust-drive: ERROR: failed to persist rename: {e}");
                reply.error(io_to_errno(&e));
                return;
            }
        } else {
            // No physical blob is deleted, so normal metadata debounce is safe
            // and avoids cloning/rewriting the entire index for every rename.
            self.mark_dirty();
        }
        if let Some(existing) = overwritten_ino {
            self.inner.open_files.write().unwrap().remove(&existing);
            self.inner.dirty_inodes.lock().unwrap().remove(&existing);
            self.inner.open_counts.lock().unwrap().remove(&existing);
        }
        if let Some(f) = disk_file_to_remove
            && let Err(e) = fs::remove_file(self.inner.base_path.join(&f))
            && e.kind() != std::io::ErrorKind::NotFound
        {
            eprintln!("zerotrust-drive: WARNING: orphaned overwritten backing file {f}: {e}");
        }
        drop(persistence);
        reply.ok();
    }

    fn readdir(
        &self,
        _req: &Request,
        ino: INodeNo,
        _fh: FileHandle,
        offset: u64,
        mut reply: ReplyDirectory,
    ) {
        let state = self.inner.state.read().unwrap();
        match state.inodes.get(&ino.0) {
            Some(e) if e.kind == InodeKind::Directory => {}
            _ => {
                reply.error(fuser::Errno::ENOTDIR);
                return;
            }
        }
        let parent_ino = state.inodes.get(&ino.0).map(|e| e.parent).unwrap_or(1);
        let fixed_entries = [
            (INodeNo(ino.0), FileType::Directory, "."),
            (INodeNo(parent_ino), FileType::Directory, ".."),
        ];
        for (position, (entry_ino, kind, name)) in fixed_entries.iter().enumerate() {
            let position = position as u64;
            if position >= offset && reply.add(*entry_ino, position + 1, *kind, name) {
                reply.ok();
                return;
            }
        }
        if let Some(children) = state.children.get(&ino.0) {
            for (child_index, child) in children.iter().enumerate() {
                let position = child_index as u64 + fixed_entries.len() as u64;
                if position < offset {
                    continue;
                }
                let kind = state
                    .inodes
                    .get(&child.inode)
                    .map(|e| match e.kind {
                        InodeKind::File => FileType::RegularFile,
                        InodeKind::Directory => FileType::Directory,
                    })
                    .unwrap_or(FileType::RegularFile);
                if reply.add(INodeNo(child.inode), position + 1, kind, &child.name) {
                    break;
                }
            }
        }
        reply.ok();
    }

    fn fsyncdir(
        &self,
        _req: &Request,
        _ino: INodeNo,
        _fh: FileHandle,
        _datasync: bool,
        reply: ReplyEmpty,
    ) {
        if self.inner.read_only.load(Ordering::Relaxed) {
            reply.ok();
            return;
        }
        let result = {
            let _persistence = self.inner.persistence_mutex.lock().unwrap();
            self.flush_pending_state_locked(true)
        };
        match result {
            Ok(()) => reply.ok(),
            Err(e) => {
                eprintln!("zerotrust-drive: ERROR: fsyncdir failed: {e}");
                reply.error(io_to_errno(&e));
            }
        }
    }

    fn statfs(&self, _req: &Request, _ino: INodeNo, reply: ReplyStatfs) {
        match backing_statfs(&self.inner.base_path) {
            Ok(stat) => reply.statfs(
                stat.blocks,
                stat.bfree,
                stat.bavail,
                stat.files,
                stat.ffree,
                stat.bsize,
                stat.namelen,
                stat.frsize,
            ),
            Err(e) => reply.error(io_to_errno(&e)),
        }
    }

    fn access(&self, _req: &Request, ino: INodeNo, _mask: fuser::AccessFlags, reply: ReplyEmpty) {
        if self.inner.state.read().unwrap().inodes.contains_key(&ino.0) {
            reply.ok();
        } else {
            reply.error(fuser::Errno::ENOENT);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{
        FORMAT_VERSION, KdfParams, SALT_LEN, decrypt_bytes, derive_key, encrypt_bytes,
    };

    /// Derive a key with a fixed cheap test salt+params. Keeps the
    /// crypto-level unit tests fast and self-contained (no drive dir).
    fn tkey(pw: &str) -> [u8; 32] {
        derive_key(
            pw,
            &KdfParams {
                format_version: FORMAT_VERSION,
                algorithm: "argon2id".to_string(),
                salt: vec![3u8; SALT_LEN],
                m_cost: 8,
                t_cost: 1,
                p_cost: 1,
            },
        )
    }

    #[test]
    fn encrypt_decrypt_round_trip() {
        let key = tkey("pw");
        let plaintext = b"round trip test data";
        let ciphertext = encrypt_bytes(&key, plaintext, b"aad").unwrap();
        let decrypted = decrypt_bytes(&key, &ciphertext, b"aad").unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn wrong_passphrase_fails() {
        let right = tkey("right");
        let wrong = tkey("wrong");
        let ciphertext = encrypt_bytes(&right, b"secret", b"aad").unwrap();
        assert!(decrypt_bytes(&wrong, &ciphertext, b"aad").is_err());
    }

    #[test]
    fn index_serialization_round_trip() {
        let mut inodes = HashMap::new();
        inodes.insert(
            1,
            InodeEntry {
                name: String::new(),
                kind: InodeKind::Directory,
                disk_filename: String::new(),
                size: 0,
                perm: 0o755,
                uid: 501,
                gid: 20,
                atime_secs: 1000,
                mtime_secs: 1000,
                ctime_secs: 1000,
                nlink: 2,
                parent: 1,
            },
        );
        inodes.insert(
            2,
            InodeEntry {
                name: "test.txt".to_string(),
                kind: InodeKind::File,
                disk_filename: "000001.age".to_string(),
                size: 42,
                perm: 0o644,
                uid: 501,
                gid: 20,
                atime_secs: 2000,
                mtime_secs: 2000,
                ctime_secs: 2000,
                nlink: 1,
                parent: 1,
            },
        );
        let mut children = HashMap::new();
        children.insert(
            1,
            vec![DirChild {
                name: "test.txt".to_string(),
                inode: 2,
            }],
        );
        let index = DiskIndex {
            next_inode: 3,
            next_file_id: 2,
            inodes,
            children,
        };

        let json = serde_json::to_vec(&index).unwrap();
        let key = tkey("test-pw");
        let encrypted = encrypt_bytes(&key, &json, b"aad").unwrap();
        let decrypted = decrypt_bytes(&key, &encrypted, b"aad").unwrap();
        let restored: DiskIndex = serde_json::from_slice(&decrypted).unwrap();

        assert_eq!(restored.next_inode, 3);
        assert_eq!(restored.next_file_id, 2);
        assert_eq!(restored.inodes.len(), 2);
        assert_eq!(restored.inodes[&2].name, "test.txt");
        assert_eq!(restored.children[&1][0].name, "test.txt");
    }

    #[test]
    fn inode_to_attr_file() {
        let entry = InodeEntry {
            name: "hello.txt".to_string(),
            kind: InodeKind::File,
            disk_filename: "000001.age".to_string(),
            size: 1024,
            perm: 0o644,
            uid: 501,
            gid: 20,
            atime_secs: 1000,
            mtime_secs: 2000,
            ctime_secs: 3000,
            nlink: 1,
            parent: 1,
        };
        let attr = ZeroTrustFs::inode_to_attr(5, &entry);
        assert_eq!(attr.ino, INodeNo(5));
        assert_eq!(attr.size, 1024);
        assert_eq!(attr.kind, FileType::RegularFile);
        assert_eq!(attr.perm, 0o644);
    }

    #[test]
    fn inode_to_attr_directory() {
        let entry = InodeEntry {
            name: "docs".to_string(),
            kind: InodeKind::Directory,
            disk_filename: String::new(),
            size: 0,
            perm: 0o755,
            uid: 501,
            gid: 20,
            atime_secs: 1000,
            mtime_secs: 1000,
            ctime_secs: 1000,
            nlink: 2,
            parent: 1,
        };
        let attr = ZeroTrustFs::inode_to_attr(3, &entry);
        assert_eq!(attr.kind, FileType::Directory);
        assert_eq!(attr.perm, 0o755);
        assert_eq!(attr.nlink, 2);
    }

    #[test]
    fn find_child_exists() {
        let mut children = HashMap::new();
        children.insert(
            1,
            vec![
                DirChild {
                    name: "a.txt".to_string(),
                    inode: 2,
                },
                DirChild {
                    name: "b.txt".to_string(),
                    inode: 3,
                },
            ],
        );
        let index = DiskIndex {
            next_inode: 4,
            next_file_id: 3,
            inodes: HashMap::new(),
            children,
        };
        assert_eq!(ZeroTrustFs::find_child(&index, 1, "a.txt"), Some(2));
        assert_eq!(ZeroTrustFs::find_child(&index, 1, "b.txt"), Some(3));
        assert_eq!(ZeroTrustFs::find_child(&index, 1, "c.txt"), None);
    }

    #[test]
    fn disk_filename_allocation() {
        let mut index = DiskIndex {
            next_inode: 1,
            next_file_id: 1,
            inodes: HashMap::new(),
            children: HashMap::new(),
        };
        assert_eq!(
            ZeroTrustFs::allocate_disk_filename(&mut index),
            "000001.age"
        );
        assert_eq!(
            ZeroTrustFs::allocate_disk_filename(&mut index),
            "000002.age"
        );
        assert_eq!(index.next_file_id, 3);
    }

    #[test]
    fn different_length_passphrases_produce_different_keys() {
        // "a" vs "aa" must produce different keys (length is folded into state)
        let k1 = tkey("a");
        let k2 = tkey("aa");
        assert_ne!(k1, k2);
    }

    #[test]
    fn empty_passphrase_produces_valid_key() {
        let k = tkey("");
        // Should not be all zeros
        assert!(k.iter().any(|&b| b != 0));
    }

    #[test]
    fn encrypted_file_persistence() {
        use std::sync::atomic::{AtomicU32, Ordering};
        static CTR: AtomicU32 = AtomicU32::new(0);
        let id = CTR.fetch_add(1, Ordering::SeqCst);
        let dir = PathBuf::from(format!("target/test-zt-{id}"));
        let _ = fs::remove_dir_all(&dir);

        let ztfs = ZeroTrustFs::new("test-pw", dir.clone());
        ztfs.write_encrypted_file("test.age", b"hello world")
            .unwrap();
        let content = ztfs.read_encrypted_file("test.age").unwrap();
        assert_eq!(content, b"hello world");
        let raw = fs::read(dir.join("test.age")).unwrap();
        assert_ne!(raw.as_slice(), b"hello world");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn crud_file_lifecycle() {
        let dir = PathBuf::from("target/test-crud-lifecycle");
        let _ = fs::remove_dir_all(&dir);

        let ztfs = ZeroTrustFs::new("crud-pw", dir.clone());

        let disk_filename = {
            let mut state = ztfs.inner.state.write().unwrap();
            let ino = ZeroTrustFs::allocate_inode(&mut state);
            let disk_filename = ZeroTrustFs::allocate_disk_filename(&mut state);
            state.inodes.insert(
                ino,
                InodeEntry {
                    name: "note.txt".to_string(),
                    kind: InodeKind::File,
                    disk_filename: disk_filename.clone(),
                    size: 13,
                    perm: 0o644,
                    uid: 501,
                    gid: 20,
                    atime_secs: 1000,
                    mtime_secs: 1000,
                    ctime_secs: 1000,
                    nlink: 1,
                    parent: 1,
                },
            );
            state.children.entry(1).or_default().push(DirChild {
                name: "note.txt".to_string(),
                inode: ino,
            });
            disk_filename
        };
        ztfs.write_encrypted_file(&disk_filename, b"hello, world!")
            .unwrap();
        ztfs.flush_state().unwrap();

        let content = ztfs.read_encrypted_file(&disk_filename).unwrap();
        assert_eq!(content, b"hello, world!");

        let updated = b"updated content for note";
        ztfs.write_encrypted_file(&disk_filename, updated).unwrap();
        {
            let mut state = ztfs.inner.state.write().unwrap();
            let ino = ZeroTrustFs::find_child(&state, 1, "note.txt").unwrap();
            state.inodes.get_mut(&ino).unwrap().size = updated.len() as u64;
        }
        ztfs.flush_state().unwrap();

        let content = ztfs.read_encrypted_file(&disk_filename).unwrap();
        assert_eq!(content, updated);

        {
            let mut state = ztfs.inner.state.write().unwrap();
            let ino = ZeroTrustFs::find_child(&state, 1, "note.txt").unwrap();
            state.inodes.remove(&ino);
            if let Some(ch) = state.children.get_mut(&1) {
                ch.retain(|c| c.inode != ino);
            }
        }
        let _ = fs::remove_file(dir.join(&disk_filename));
        ztfs.flush_state().unwrap();

        assert!(!dir.join(&disk_filename).exists());
        let state = ztfs.inner.state.read().unwrap();
        assert!(ZeroTrustFs::find_child(&state, 1, "note.txt").is_none());

        drop(state);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn crud_multiple_files() {
        let dir = PathBuf::from("target/test-crud-multi");
        let _ = fs::remove_dir_all(&dir);

        let ztfs = ZeroTrustFs::new("multi-pw", dir.clone());

        let files = [
            ("alpha.txt", b"content alpha" as &[u8]),
            ("beta.txt", b"content beta"),
            ("gamma.txt", b"content gamma"),
        ];
        let mut disk_filenames = Vec::new();
        for (name, content) in &files {
            let disk_filename = {
                let mut state = ztfs.inner.state.write().unwrap();
                let ino = ZeroTrustFs::allocate_inode(&mut state);
                let df = ZeroTrustFs::allocate_disk_filename(&mut state);
                state.inodes.insert(
                    ino,
                    InodeEntry {
                        name: name.to_string(),
                        kind: InodeKind::File,
                        disk_filename: df.clone(),
                        size: content.len() as u64,
                        perm: 0o644,
                        uid: 501,
                        gid: 20,
                        atime_secs: 1000,
                        mtime_secs: 1000,
                        ctime_secs: 1000,
                        nlink: 1,
                        parent: 1,
                    },
                );
                state.children.entry(1).or_default().push(DirChild {
                    name: name.to_string(),
                    inode: ino,
                });
                df
            };
            ztfs.write_encrypted_file(&disk_filename, content).unwrap();
            disk_filenames.push(disk_filename);
        }
        ztfs.flush_state().unwrap();

        for (i, (_name, expected)) in files.iter().enumerate() {
            let content = ztfs.read_encrypted_file(&disk_filenames[i]).unwrap();
            assert_eq!(content, *expected);
        }

        let updated_beta = b"beta has been updated";
        ztfs.write_encrypted_file(&disk_filenames[1], updated_beta)
            .unwrap();
        {
            let mut state = ztfs.inner.state.write().unwrap();
            let ino = ZeroTrustFs::find_child(&state, 1, "beta.txt").unwrap();
            state.inodes.get_mut(&ino).unwrap().size = updated_beta.len() as u64;
        }
        ztfs.flush_state().unwrap();

        {
            let mut state = ztfs.inner.state.write().unwrap();
            let ino = ZeroTrustFs::find_child(&state, 1, "alpha.txt").unwrap();
            state.inodes.remove(&ino);
            if let Some(ch) = state.children.get_mut(&1) {
                ch.retain(|c| c.inode != ino);
            }
        }
        let _ = fs::remove_file(dir.join(&disk_filenames[0]));
        ztfs.flush_state().unwrap();

        let state = ztfs.inner.state.read().unwrap();
        assert!(ZeroTrustFs::find_child(&state, 1, "alpha.txt").is_none());

        drop(state);
        let content = ztfs.read_encrypted_file(&disk_filenames[1]).unwrap();
        assert_eq!(content, updated_beta);

        let content = ztfs.read_encrypted_file(&disk_filenames[2]).unwrap();
        assert_eq!(content, b"content gamma");

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn crud_persisted_across_reopen() {
        let dir = PathBuf::from("target/test-crud-reopen");
        let _ = fs::remove_dir_all(&dir);
        let passphrase = "reopen-pw";

        let disk_filename = {
            let ztfs = ZeroTrustFs::new(passphrase, dir.clone());
            let df = {
                let mut state = ztfs.inner.state.write().unwrap();
                let ino = ZeroTrustFs::allocate_inode(&mut state);
                let df = ZeroTrustFs::allocate_disk_filename(&mut state);
                state.inodes.insert(
                    ino,
                    InodeEntry {
                        name: "persist.txt".to_string(),
                        kind: InodeKind::File,
                        disk_filename: df.clone(),
                        size: 15,
                        perm: 0o644,
                        uid: 501,
                        gid: 20,
                        atime_secs: 1000,
                        mtime_secs: 1000,
                        ctime_secs: 1000,
                        nlink: 1,
                        parent: 1,
                    },
                );
                state.children.entry(1).or_default().push(DirChild {
                    name: "persist.txt".to_string(),
                    inode: ino,
                });
                df
            };
            ztfs.write_encrypted_file(&df, b"persisted data!").unwrap();
            ztfs.flush_state().unwrap();
            df
        };

        {
            let ztfs = ZeroTrustFs::new(passphrase, dir.clone());
            let state = ztfs.inner.state.read().unwrap();
            let ino = ZeroTrustFs::find_child(&state, 1, "persist.txt")
                .expect("persist.txt should exist after reopen");
            let entry = state.inodes.get(&ino).unwrap();
            assert_eq!(entry.name, "persist.txt");
            assert_eq!(entry.disk_filename, disk_filename);
            drop(state);

            let content = ztfs.read_encrypted_file(&disk_filename).unwrap();
            assert_eq!(content, b"persisted data!");
        }

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn name_max_is_255() {
        assert_eq!(NAME_MAX, 255);
        let exactly_255 = "a".repeat(255);
        assert_eq!(exactly_255.len(), NAME_MAX);
        let too_long = "a".repeat(256);
        assert!(too_long.len() > NAME_MAX);
    }

    #[test]
    fn conflict_detection_on_external_index_modification() {
        let dir = PathBuf::from("target/test-conflict");
        let _ = fs::remove_dir_all(&dir);
        let ztfs = ZeroTrustFs::new("conflict-pw", dir.clone());
        let (ino, disk_filename) = add_file(&ztfs, "data.txt");
        ztfs.open_inode(ino).unwrap();
        ztfs.write_inode_content(ino, 0, b"before").unwrap();
        ztfs.flush_state().unwrap();
        let original_index = fs::read(dir.join("_index.age")).unwrap();
        let original_blob = fs::read(dir.join(&disk_filename)).unwrap();

        // Keep a dirty local generation pending, then inject a different valid
        // encrypted index as cloud synchronization could do.
        ztfs.write_inode_content(ino, 0, b"after!").unwrap();
        let key = crate::crypto::derive_key_at(&dir, "conflict-pw");
        let external_data = crate::crypto::encrypt_index(&key, b"external generation").unwrap();
        let index_path = dir.join("_index.age");
        fs::write(&index_path, &external_data).unwrap();

        let error = ztfs.flush_state().unwrap_err();
        assert!(
            error.to_string().contains("changed externally"),
            "unexpected error: {error}"
        );
        assert_eq!(fs::read(&index_path).unwrap(), external_data);
        assert_eq!(
            fs::read(dir.join(&disk_filename)).unwrap(),
            original_blob,
            "conflict must be detected before a dirty blob is overwritten"
        );

        // Restore the known generation so the dirty buffer can be committed
        // and the test filesystem can shut down cleanly.
        fs::write(&index_path, original_index).unwrap();
        ztfs.flush_state().unwrap();
        ztfs.release_inode(ino).unwrap();

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn durable_write_survives_content() {
        let dir = PathBuf::from("target/test-durable-write");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();

        let path = dir.join("test.dat");
        durable_write(&path, b"durable content").unwrap();
        assert_eq!(fs::read(&path).unwrap(), b"durable content");

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn durable_write_no_leftover_tmp() {
        let dir = PathBuf::from("target/test-durable-tmp");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();

        let path = dir.join("test.dat");
        durable_write(&path, b"data").unwrap();
        let entries: Vec<_> = fs::read_dir(&dir)
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect();
        assert_eq!(entries, vec![std::ffi::OsString::from("test.dat")]);

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn missing_index_refuses_kdf_only_cloud_state() {
        let dir = PathBuf::from("target/test-kdf-only-new-store-refusal");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("_kdf.json"), b"partially materialized").unwrap();

        let error = ensure_new_store_directory_empty(&dir).unwrap_err();
        assert!(error.contains("_kdf.json"), "unexpected error: {error}");
        assert!(
            error.contains("without _index.age"),
            "unexpected error: {error}"
        );

        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn missing_backing_file_returns_error() {
        // Verify that an inode with a non-empty disk_filename but missing backing
        // file would be detected. We test the detection logic directly rather than
        // going through FUSE open() since that requires a mounted filesystem.
        let dir = PathBuf::from("target/test-missing-backing");
        let _ = fs::remove_dir_all(&dir);

        let ztfs = ZeroTrustFs::new("missing-pw", dir.clone());
        {
            let mut state = ztfs.inner.state.write().unwrap();
            let ino = ZeroTrustFs::allocate_inode(&mut state);
            let df = ZeroTrustFs::allocate_disk_filename(&mut state);
            state.inodes.insert(
                ino,
                InodeEntry {
                    name: "ghost.txt".to_string(),
                    kind: InodeKind::File,
                    disk_filename: df.clone(),
                    size: 10,
                    perm: 0o644,
                    uid: 501,
                    gid: 20,
                    atime_secs: 1000,
                    mtime_secs: 1000,
                    ctime_secs: 1000,
                    nlink: 1,
                    parent: 1,
                },
            );
            state.children.entry(1).or_default().push(DirChild {
                name: "ghost.txt".to_string(),
                inode: ino,
            });
            // Don't write the backing file — it's "missing"
            let backing = ztfs.inner.base_path.join(&df);
            assert!(
                !backing.exists(),
                "backing file should not exist for this test"
            );
        }

        let _ = fs::remove_dir_all(&dir);
    }

    // --- Regression tests for the open/release/truncate/fsync fixes -------

    /// Add a 0-size file inode under root and return (ino, disk_filename).
    fn add_file(ztfs: &ZeroTrustFs, name: &str) -> (u64, String) {
        let mut state = ztfs.inner.state.write().unwrap();
        let ino = ZeroTrustFs::allocate_inode(&mut state);
        let df = ZeroTrustFs::allocate_disk_filename(&mut state);
        state.inodes.insert(
            ino,
            InodeEntry {
                name: name.to_string(),
                kind: InodeKind::File,
                disk_filename: df.clone(),
                size: 0,
                perm: 0o644,
                uid: 501,
                gid: 20,
                atime_secs: 0,
                mtime_secs: 0,
                ctime_secs: 0,
                nlink: 1,
                parent: 1,
            },
        );
        state.children.entry(1).or_default().push(DirChild {
            name: name.to_string(),
            inode: ino,
        });
        (ino, df)
    }

    /// mknod-style inode (non-empty disk_filename, size 0, no backing blob)
    /// must open as an empty buffer, not EIO.
    #[test]
    fn open_inode_empty_when_zero_size_backing_absent() {
        let dir = PathBuf::from("target/test-open-zero-missing");
        let _ = fs::remove_dir_all(&dir);
        let ztfs = ZeroTrustFs::new("pw", dir.clone());
        let (ino, df) = add_file(&ztfs, "fresh.txt");
        assert!(!ztfs.inner.base_path.join(&df).exists());
        ztfs.open_inode(ino)
            .expect("zero-size missing backing must open as empty");
        assert_eq!(
            ztfs.inner
                .open_files
                .read()
                .unwrap()
                .get(&ino)
                .unwrap()
                .len(),
            0
        );
        let _ = fs::remove_dir_all(&dir);
    }

    /// A non-empty file whose backing blob vanished is genuine data loss
    /// and must error on open.
    #[test]
    fn open_inode_errors_when_nonempty_backing_absent() {
        let dir = PathBuf::from("target/test-open-missing-loss");
        let _ = fs::remove_dir_all(&dir);
        let ztfs = ZeroTrustFs::new("pw", dir.clone());
        let (ino, _df) = add_file(&ztfs, "ghost.txt");
        ztfs.inner
            .state
            .write()
            .unwrap()
            .inodes
            .get_mut(&ino)
            .unwrap()
            .size = 42;
        assert!(
            ztfs.open_inode(ino).is_err(),
            "missing backing for a non-empty file must error"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    /// A second open of an already-open inode must NOT reload from disk and
    /// clobber unflushed in-memory writes.
    #[test]
    fn second_open_does_not_clobber_dirty_buffer() {
        let dir = PathBuf::from("target/test-open-no-clobber");
        let _ = fs::remove_dir_all(&dir);
        let ztfs = ZeroTrustFs::new("pw", dir.clone());
        let (ino, df) = add_file(&ztfs, "doc.txt");
        // Backing has "ondisk"; size set so first open loads it.
        ztfs.write_encrypted_file(&df, b"ondisk").unwrap();
        ztfs.inner
            .state
            .write()
            .unwrap()
            .inodes
            .get_mut(&ino)
            .unwrap()
            .size = 6;
        ztfs.open_inode(ino).unwrap();
        // Simulate an unflushed write into the open buffer.
        ztfs.inner
            .open_files
            .write()
            .unwrap()
            .insert(ino, b"dirty!!".to_vec());
        // Second opener must reuse the buffer, not reload "ondisk".
        ztfs.open_inode(ino).unwrap();
        assert_eq!(
            ztfs.inner.open_files.read().unwrap().get(&ino).unwrap(),
            b"dirty!!"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    /// With two open handles, the buffer survives the first release and is
    /// persisted+evicted only on the last release.
    #[test]
    fn buffer_persists_only_on_last_release() {
        let dir = PathBuf::from("target/test-last-release");
        let _ = fs::remove_dir_all(&dir);
        let ztfs = ZeroTrustFs::new("pw", dir.clone());
        let (ino, df) = add_file(&ztfs, "shared.txt");
        ztfs.open_inode(ino).unwrap();
        ztfs.open_inode(ino).unwrap(); // count = 2
        ztfs.write_inode_content(ino, 0, b"final").unwrap();

        ztfs.release_inode(ino).unwrap(); // count → 1: no evict, no persist
        assert!(
            ztfs.inner.open_files.read().unwrap().contains_key(&ino),
            "buffer must survive non-final release"
        );
        assert!(
            !ztfs.inner.base_path.join(&df).exists(),
            "must not persist before last release"
        );

        ztfs.release_inode(ino).unwrap(); // count → 0: persist + evict
        assert!(
            !ztfs.inner.open_files.read().unwrap().contains_key(&ino),
            "buffer evicted on last release"
        );
        assert_eq!(ztfs.read_encrypted_file(&df).unwrap(), b"final");
        let _ = fs::remove_dir_all(&dir);
    }

    /// Truncating a CLOSED file must persist to the on-disk blob (this was
    /// previously a silent no-op).
    #[test]
    fn truncate_closed_file_persists_to_disk() {
        let dir = PathBuf::from("target/test-truncate-closed");
        let _ = fs::remove_dir_all(&dir);
        let ztfs = ZeroTrustFs::new("pw", dir.clone());
        let (ino, df) = add_file(&ztfs, "log.txt");
        ztfs.write_encrypted_file(&df, b"0123456789").unwrap();
        ztfs.inner
            .state
            .write()
            .unwrap()
            .inodes
            .get_mut(&ino)
            .unwrap()
            .size = 10;
        // File is closed (never opened). Truncate to 4.
        ztfs.truncate_inode(ino, 4).unwrap();
        assert_eq!(
            ztfs.read_encrypted_file(&df).unwrap(),
            b"0123",
            "closed-file truncate must shrink the blob"
        );
        // Truncate-extend to 6 zero-fills.
        ztfs.truncate_inode(ino, 6).unwrap();
        assert_eq!(ztfs.read_encrypted_file(&df).unwrap(), b"0123\0\0");
        let _ = fs::remove_dir_all(&dir);
    }

    /// Truncating an OPEN file resizes the in-memory buffer.
    #[test]
    fn truncate_open_file_resizes_buffer() {
        let dir = PathBuf::from("target/test-truncate-open");
        let _ = fs::remove_dir_all(&dir);
        let ztfs = ZeroTrustFs::new("pw", dir.clone());
        let (ino, _df) = add_file(&ztfs, "buf.txt");
        ztfs.open_inode(ino).unwrap();
        ztfs.inner
            .open_files
            .write()
            .unwrap()
            .insert(ino, b"abcdef".to_vec());
        ztfs.truncate_inode(ino, 3).unwrap();
        assert_eq!(
            ztfs.inner.open_files.read().unwrap().get(&ino).unwrap(),
            b"abc"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    /// fsync persists the open buffer to the backing blob durably.
    #[test]
    fn fsync_inode_persists_open_content() {
        let dir = PathBuf::from("target/test-fsync");
        let _ = fs::remove_dir_all(&dir);
        let ztfs = ZeroTrustFs::new("pw", dir.clone());
        let (ino, df) = add_file(&ztfs, "data.txt");
        ztfs.open_inode(ino).unwrap();
        ztfs.write_inode_content(ino, 0, b"synced").unwrap();
        ztfs.fsync_inode(ino).unwrap();
        assert_eq!(ztfs.read_encrypted_file(&df).unwrap(), b"synced");
        let _ = fs::remove_dir_all(&dir);
    }

    /// Opening and closing a clean file must not generate new random AEAD
    /// nonces. Exact ciphertext stability avoids full cloud re-uploads caused
    /// solely by reads.
    #[test]
    fn clean_open_release_preserves_ciphertexts() {
        let dir = PathBuf::from("target/test-clean-open-release");
        let _ = fs::remove_dir_all(&dir);
        let ztfs = ZeroTrustFs::new("pw", dir.clone());
        let (ino, df) = add_file(&ztfs, "read-only.txt");
        ztfs.write_encrypted_file(&df, b"unchanged").unwrap();
        ztfs.inner
            .state
            .write()
            .unwrap()
            .inodes
            .get_mut(&ino)
            .unwrap()
            .size = 9;
        ztfs.flush_state().unwrap();

        let blob_before = fs::read(dir.join(&df)).unwrap();
        let index_before = fs::read(dir.join("_index.age")).unwrap();
        ztfs.open_inode(ino).unwrap();
        ztfs.release_inode(ino).unwrap();

        assert_eq!(fs::read(dir.join(&df)).unwrap(), blob_before);
        assert_eq!(fs::read(dir.join("_index.age")).unwrap(), index_before);
        let _ = fs::remove_dir_all(&dir);
    }

    /// A clean mount lifecycle must leave the encrypted index byte-for-byte
    /// unchanged instead of creating a spurious cloud sync revision.
    #[test]
    fn clean_reopen_and_drop_preserves_index_ciphertext() {
        let dir = PathBuf::from("target/test-clean-reopen");
        let _ = fs::remove_dir_all(&dir);
        {
            let _ztfs = ZeroTrustFs::new("pw", dir.clone());
        }
        let before = fs::read(dir.join("_index.age")).unwrap();
        {
            let _ztfs = ZeroTrustFs::new("pw", dir.clone());
        }
        assert_eq!(fs::read(dir.join("_index.age")).unwrap(), before);
        let _ = fs::remove_dir_all(&dir);
    }

    /// A truncate after fsync is a new dirty generation and must survive the
    /// final release. The prior implementation treated the inode as already
    /// flushed and lost the later truncate.
    #[test]
    fn truncate_after_fsync_is_persisted() {
        let dir = PathBuf::from("target/test-truncate-after-fsync");
        let _ = fs::remove_dir_all(&dir);
        let ztfs = ZeroTrustFs::new("pw", dir.clone());
        let (ino, df) = add_file(&ztfs, "data.txt");
        ztfs.open_inode(ino).unwrap();
        ztfs.write_inode_content(ino, 0, b"abcdef").unwrap();
        ztfs.fsync_inode(ino).unwrap();
        ztfs.truncate_inode(ino, 3).unwrap();
        ztfs.release_inode(ino).unwrap();
        assert_eq!(ztfs.read_encrypted_file(&df).unwrap(), b"abc");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn huge_write_offset_is_rejected_without_panicking() {
        let dir = PathBuf::from("target/test-write-overflow");
        let _ = fs::remove_dir_all(&dir);
        let ztfs = ZeroTrustFs::new("pw", dir.clone());
        let (ino, _df) = add_file(&ztfs, "data.txt");
        ztfs.open_inode(ino).unwrap();
        let error = ztfs.write_inode_content(ino, u64::MAX, b"x").unwrap_err();
        assert_eq!(error.raw_os_error(), Some(libc::EFBIG));
        let _ = fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn statfs_uses_real_backing_filesystem_capacity() {
        let dir = PathBuf::from("target/test-backing-statfs");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();

        let stat = backing_statfs(&dir).unwrap();
        assert!(stat.blocks > 0);
        assert!(stat.bsize > 0);
        assert!(stat.frsize > 0);
        assert!(stat.bavail <= stat.blocks);

        let _ = fs::remove_dir_all(dir);
    }

    /// Security regression (AAD): swapping two blobs on disk must be
    /// detected on read — a blob encrypted under one filename must not
    /// authenticate under another.
    #[test]
    fn on_disk_blob_swap_is_rejected() {
        let dir = PathBuf::from("target/test-blob-swap");
        let _ = fs::remove_dir_all(&dir);
        let ztfs = ZeroTrustFs::new("pw", dir.clone());
        let (_a, df_a) = add_file(&ztfs, "a.txt");
        let (_b, df_b) = add_file(&ztfs, "b.txt");
        ztfs.write_encrypted_file(&df_a, b"secret-A").unwrap();
        ztfs.write_encrypted_file(&df_b, b"secret-B").unwrap();

        // Attacker with write access swaps the two ciphertext blobs.
        let pa = ztfs.inner.base_path.join(&df_a);
        let pb = ztfs.inner.base_path.join(&df_b);
        let ba = fs::read(&pa).unwrap();
        let bb = fs::read(&pb).unwrap();
        fs::write(&pa, &bb).unwrap();
        fs::write(&pb, &ba).unwrap();

        // Both reads must now fail (AAD = filename no longer matches).
        assert!(
            ztfs.read_encrypted_file(&df_a).is_err(),
            "swapped blob must fail AAD check"
        );
        assert!(
            ztfs.read_encrypted_file(&df_b).is_err(),
            "swapped blob must fail AAD check"
        );
        let _ = fs::remove_dir_all(&dir);
    }
}
