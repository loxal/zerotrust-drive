// Copyright 2026 Alexander Orlov <alexander.orlov@loxal.net>

use std::collections::HashMap;
use std::ffi::OsStr;
use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, SystemTime};

use fuser::{
    FileAttr, FileHandle, FileType, Filesystem, FopenFlags, Generation, INodeNo,
    ReplyAttr, ReplyCreate, ReplyData, ReplyDirectory, ReplyEmpty, ReplyEntry,
    ReplyOpen, ReplyStatfs, ReplyWrite, Request,
};
use serde::{Deserialize, Serialize};

use crate::crypto::{decrypt_bytes, derive_key, encrypt_bytes};

macro_rules! trace {
    ($($arg:tt)*) => {{
        use std::io::Write;
        if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open("target/fuse.log") {
            let _ = writeln!(f, $($arg)*);
        }
    }};
}

const TTL: Duration = Duration::from_secs(1);
const BLKSIZE: u32 = 4096;

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

#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct DiskIndex {
    pub next_inode: u64,
    pub next_file_id: u64,
    pub inodes: HashMap<u64, InodeEntry>,
    pub children: HashMap<u64, Vec<DirChild>>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
struct ManifestEntry {
    filename: String,
    renamed: bool,
}

// --- FUSE filesystem ---

pub(crate) struct FsInner {
    pub(crate) base_path: PathBuf,
    pub(crate) key: RwLock<[u8; 32]>,
    pub(crate) state: Mutex<DiskIndex>,
    pub(crate) open_files: Mutex<HashMap<u64, Vec<u8>>>,
    pub(crate) index_mtime: Mutex<Option<SystemTime>>,
    pub(crate) read_only: AtomicBool,
}

pub struct ZeroTrustFs {
    pub(crate) inner: Arc<FsInner>,
}

impl ZeroTrustFs {
    pub fn new(passphrase: &str, base_path: PathBuf) -> Self {
        let key = derive_key(passphrase);
        fs::create_dir_all(&base_path).expect("failed to create base path");

        let index_path = base_path.join("_index.age");
        let state = if index_path.exists() {
            let ciphertext = fs::read(&index_path).expect("failed to read index");
            let json = decrypt_bytes(&key, &ciphertext).expect("failed to decrypt index");
            serde_json::from_slice(&json).expect("failed to parse index")
        } else {
            let uid = unsafe { libc::getuid() };
            let gid = unsafe { libc::getgid() };
            let now = now_secs();

            let mut inodes = HashMap::new();
            inodes.insert(1, InodeEntry {
                name: String::new(), kind: InodeKind::Directory, disk_filename: String::new(),
                size: 0, perm: 0o755, uid, gid,
                atime_secs: now, mtime_secs: now, ctime_secs: now, nlink: 2, parent: 1,
            });
            let mut children = HashMap::new();
            children.insert(1u64, Vec::new());
            DiskIndex { next_inode: 2, next_file_id: 1, inodes, children }
        };

        let json = serde_json::to_vec(&state).expect("failed to serialize index");
        let inner = FsInner {
            base_path, key: RwLock::new(key),
            state: Mutex::new(state), open_files: Mutex::new(HashMap::new()),
            index_mtime: Mutex::new(None),
            read_only: AtomicBool::new(false),
        };
        let zfs = Self {
            inner: Arc::new(inner),
        };
        zfs.persist_index(&json);
        zfs
    }

    /// Encrypt and write pre-serialized JSON to _index.age. No locks held.
    pub(crate) fn persist_index(&self, json: &[u8]) {
        let index_path = self.inner.base_path.join("_index.age");
        let encrypted = encrypt_bytes(&*self.inner.key.read().unwrap(), json).expect("failed to encrypt index");
        fs::write(&index_path, encrypted).expect("failed to write index");
        // Record mtime so we can detect external modifications
        if let Ok(meta) = fs::metadata(&index_path) {
            if let Ok(mtime) = meta.modified() {
                *self.inner.index_mtime.lock().unwrap() = Some(mtime);
            }
        }
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
            ino: INodeNo(ino), size: entry.size, blocks: (entry.size + 511) / 512,
            atime: time(entry.atime_secs), mtime: time(entry.mtime_secs),
            ctime: time(entry.ctime_secs), crtime: time(entry.ctime_secs),
            kind: match entry.kind {
                InodeKind::File => FileType::RegularFile,
                InodeKind::Directory => FileType::Directory,
            },
            perm: entry.perm, nlink: entry.nlink, uid: entry.uid, gid: entry.gid,
            rdev: 0, blksize: BLKSIZE, flags: 0,
        }
    }

    pub(crate) fn find_child(state: &DiskIndex, parent: u64, name: &str) -> Option<u64> {
        state.children.get(&parent)?.iter().find(|c| c.name == name).map(|c| c.inode)
    }

    pub(crate) fn write_encrypted_file(&self, disk_filename: &str, content: &[u8]) {
        let encrypted = encrypt_bytes(&*self.inner.key.read().unwrap(), content).expect("failed to encrypt file");
        fs::write(self.inner.base_path.join(disk_filename), encrypted).expect("failed to write file");
    }

    pub(crate) fn read_encrypted_file(&self, disk_filename: &str) -> Vec<u8> {
        let ciphertext = fs::read(self.inner.base_path.join(disk_filename)).expect("failed to read file");
        decrypt_bytes(&*self.inner.key.read().unwrap(), &ciphertext).expect("failed to decrypt file")
    }

    /// Lock state, serialize, drop lock, encrypt+write. Safe to call without any locks held.
    /// Detects external modifications to _index.age (e.g. by Google Drive sync) and warns.
    pub(crate) fn flush_state(&self) {
        // Check for external modification of the index
        let index_path = self.inner.base_path.join("_index.age");
        let our_mtime = *self.inner.index_mtime.lock().unwrap();
        if let (Some(ours), Ok(meta)) = (our_mtime, fs::metadata(&index_path)) {
            if let Ok(disk_mtime) = meta.modified() {
                if disk_mtime != ours {
                    let msg = "zerotrust-drive: WARNING: _index.age was modified externally (e.g. by cloud sync) — overwriting with in-memory state";
                    eprintln!("{msg}");
                    trace!("{msg}");
                }
            }
        }

        let json = {
            let state = self.inner.state.lock().unwrap();
            serde_json::to_vec(&*state).expect("failed to serialize index")
        };
        // Lock is dropped here — safe to do slow encryption
        self.persist_index(&json);
    }
}

fn now_secs() -> u64 {
    SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap().as_secs()
}

// --- Rekey (passphrase rotation) ---

/// Clean up orphaned staging directory from a previously interrupted rekey (before manifest).
pub fn cleanup_stale_staging(base_path: &std::path::Path) {
    let staging_dir = base_path.join(".rekey_staging");
    if staging_dir.exists() && !base_path.join("_rekey.manifest").exists() {
        eprintln!("zerotrust-drive: removing stale staging directory");
        let _ = std::fs::remove_dir_all(&staging_dir);
    }
}

/// Verify that the new passphrase matches the files already in `.rekey_staging/`.
/// Picks the first `.age` file in the staging dir and tries to decrypt it with the new key.
pub fn verify_staged_passphrase(new_passphrase: &str, base_path: &std::path::Path) -> Result<(), String> {
    let staging_dir = base_path.join(".rekey_staging");
    let new_key = derive_key(new_passphrase);
    for entry in std::fs::read_dir(&staging_dir).map_err(|e| e.to_string())? {
        let entry = entry.map_err(|e| e.to_string())?;
        let name = entry.file_name().to_string_lossy().to_string();
        if name.ends_with(".age") {
            let ciphertext = std::fs::read(entry.path()).map_err(|e| e.to_string())?;
            return decrypt_bytes(&new_key, &ciphertext)
                .map(|_| ())
                .map_err(|_| "staged files were encrypted with a different passphrase".to_string());
        }
    }
    Err("no staged files found to verify".to_string())
}

/// Complete an interrupted rekey by finishing the rename pass from the manifest.
/// Returns `true` if recovery was performed.
pub fn recover_interrupted_rekey(base_path: &std::path::Path) -> bool {
    let manifest_path = base_path.join("_rekey.manifest");
    if !manifest_path.exists() {
        return false;
    }
    eprintln!("zerotrust-drive: detected interrupted rekey — completing...");
    let manifest_json = std::fs::read(&manifest_path).expect("failed to read rekey manifest");
    let mut entries: Vec<ManifestEntry> =
        serde_json::from_slice(&manifest_json).expect("failed to parse rekey manifest");
    let staging_dir = base_path.join(".rekey_staging");
    for i in 0..entries.len() {
        if entries[i].renamed {
            continue;
        }
        let staged = staging_dir.join(&entries[i].filename);
        if staged.exists() {
            let original = base_path.join(&entries[i].filename);
            std::fs::rename(&staged, &original)
                .unwrap_or_else(|_| panic!("failed to rename staging/{} -> {}", entries[i].filename, entries[i].filename));
            entries[i].renamed = true;
            let updated = serde_json::to_vec(&entries).expect("failed to serialize manifest");
            std::fs::write(&manifest_path, &updated).expect("failed to update manifest");
        }
    }
    let _ = std::fs::remove_dir_all(&staging_dir);
    let _ = std::fs::remove_file(&manifest_path);
    let _ = std::fs::remove_file(base_path.join("_rekey.lock"));
    eprintln!("zerotrust-drive: interrupted rekey completed successfully");
    true
}

/// Re-encrypt all files and the index with a new passphrase. Atomic and crash-safe.
///
/// Uses a staged-write approach with a `.rekey_staging/` subfolder:
/// 1. Re-encrypted files are written into `.rekey_staging/`
/// 2. A `_rekey.manifest` records which files need renaming (commit point)
/// 3. A rename pass atomically swaps each file into place
///
/// If interrupted before the manifest: stale staging dir is cleaned on next run.
/// If interrupted during the rename pass: `recover_interrupted_rekey()` completes it.
pub fn rekey(old_passphrase: &str, new_passphrase: &str, base_path: &std::path::Path, resume: bool) {
    // Recover from any previous interrupted rekey first
    recover_interrupted_rekey(base_path);
    if resume {
        let staging_dir = base_path.join(".rekey_staging");
        if staging_dir.exists() {
            match verify_staged_passphrase(new_passphrase, base_path) {
                Ok(()) => eprintln!("zerotrust-drive: passphrase verified — resuming interrupted rekey"),
                Err(e) => {
                    eprintln!("zerotrust-drive: error: cannot resume — {e}");
                    std::process::exit(1);
                }
            }
        } else {
            eprintln!("zerotrust-drive: nothing to resume — starting fresh");
        }
    } else {
        cleanup_stale_staging(base_path);
    }

    // Acquire lock (when resuming, the lock is expected from the interrupted run)
    let lock_path = base_path.join("_rekey.lock");
    if lock_path.exists() && !resume {
        eprintln!(
            "zerotrust-drive: error: lock file exists at {} — another rekey may be in progress",
            lock_path.display()
        );
        eprintln!("zerotrust-drive: if you are sure no other process is running, delete it manually");
        std::process::exit(1);
    }
    std::fs::write(&lock_path, std::process::id().to_string()).expect("failed to create lock file");

    // Derive keys
    let old_key = derive_key(old_passphrase);
    let new_key = derive_key(new_passphrase);

    // Decrypt and validate the index with the old passphrase
    let index_path = base_path.join("_index.age");
    let index_ciphertext = std::fs::read(&index_path).expect("failed to read _index.age");
    let index_json = match decrypt_bytes(&old_key, &index_ciphertext) {
        Ok(json) => json,
        Err(_) => {
            let _ = std::fs::remove_file(&lock_path);
            eprintln!("zerotrust-drive: error: failed to decrypt _index.age — wrong passphrase?");
            std::process::exit(1);
        }
    };
    let index: DiskIndex = serde_json::from_slice(&index_json).expect("failed to parse index");

    // Collect all data files (only files, not directories)
    let disk_files: Vec<String> = index
        .inodes
        .values()
        .filter(|e| e.kind == InodeKind::File && !e.disk_filename.is_empty())
        .map(|e| e.disk_filename.clone())
        .collect();

    let staging_dir = base_path.join(".rekey_staging");
    std::fs::create_dir_all(&staging_dir).expect("failed to create staging dir");

    let total = disk_files.len() + 1;
    eprintln!(
        "zerotrust-drive: re-encrypting {} file(s) + index with new passphrase...",
        disk_files.len()
    );

    // Phase 1: Staging — re-encrypt each data file into .rekey_staging/
    let mut skipped = 0usize;
    for (i, filename) in disk_files.iter().enumerate() {
        let staged_path = staging_dir.join(filename);
        if resume && staged_path.exists() {
            skipped += 1;
            continue;
        }
        let file_path = base_path.join(filename);

        let ciphertext =
            std::fs::read(&file_path).unwrap_or_else(|_| panic!("failed to read {filename}"));
        let plaintext = decrypt_bytes(&old_key, &ciphertext)
            .unwrap_or_else(|_| panic!("failed to decrypt {filename} — data may be corrupted"));
        let new_ciphertext = encrypt_bytes(&new_key, &plaintext).expect("failed to re-encrypt");
        std::fs::write(&staged_path, new_ciphertext)
            .unwrap_or_else(|_| panic!("failed to write staging/{filename}"));

        eprintln!(
            "zerotrust-drive: [{}/{}] re-encrypted {}",
            i + 1,
            total,
            filename
        );
    }
    if skipped > 0 {
        eprintln!("zerotrust-drive: skipped {skipped} already-staged file(s)");
    }

    // Re-encrypt the index
    let staged_index = staging_dir.join("_index.age");
    if !resume || !staged_index.exists() {
        let new_index_ciphertext =
            encrypt_bytes(&new_key, &index_json).expect("failed to re-encrypt index");
        std::fs::write(&staged_index, new_index_ciphertext)
            .expect("failed to write staging/_index.age");
        eprintln!("zerotrust-drive: [{total}/{total}] re-encrypted _index.age");
    }

    // Phase 2: Write manifest (commit point)
    let mut manifest: Vec<ManifestEntry> = disk_files
        .iter()
        .cloned()
        .chain(std::iter::once("_index.age".to_string()))
        .map(|f| ManifestEntry { filename: f, renamed: false })
        .collect();
    let manifest_path = base_path.join("_rekey.manifest");
    let manifest_json = serde_json::to_vec(&manifest).expect("failed to serialize manifest");
    std::fs::write(&manifest_path, &manifest_json)
        .expect("failed to write rekey manifest");

    // Phase 3: Rename pass — swap staged files over originals
    for i in 0..manifest.len() {
        let original = base_path.join(&manifest[i].filename);
        let staged = staging_dir.join(&manifest[i].filename);
        std::fs::rename(&staged, &original)
            .unwrap_or_else(|_| panic!("failed to rename staging/{} -> {}", manifest[i].filename, manifest[i].filename));
        manifest[i].renamed = true;
        let updated = serde_json::to_vec(&manifest).expect("failed to serialize manifest");
        std::fs::write(&manifest_path, &updated).expect("failed to update manifest");
    }

    // Cleanup
    let _ = std::fs::remove_dir_all(&staging_dir);
    let _ = std::fs::remove_file(base_path.join("_rekey.manifest"));
    let _ = std::fs::remove_file(&lock_path);

    eprintln!("zerotrust-drive: re-encryption complete — all files now use the new passphrase");
}

/// Re-encrypt all files online (while filesystem is mounted). Sets read-only mode during rotation.
pub fn rekey_online(old_passphrase: &str, new_passphrase: &str, base_path: &std::path::Path, inner: &FsInner, resume: bool) {
    // 1. Set read-only
    inner.read_only.store(true, Ordering::SeqCst);
    eprintln!("zerotrust-drive: filesystem is now read-only — write operations will return EROFS until re-encryption completes");
    eprintln!("zerotrust-drive: flushing open files before re-encryption...");

    // 2. Flush all open files to disk with old key
    {
        let key = inner.key.read().unwrap();
        let open = inner.open_files.lock().unwrap();
        let state = inner.state.lock().unwrap();
        for (&ino, content) in open.iter() {
            if let Some(entry) = state.inodes.get(&ino) {
                if !entry.disk_filename.is_empty() {
                    let encrypted = encrypt_bytes(&key, content).expect("failed to encrypt");
                    std::fs::write(inner.base_path.join(&entry.disk_filename), encrypted).expect("failed to write");
                }
            }
        }
        // Also persist index
        let json = serde_json::to_vec(&*state).expect("failed to serialize index");
        let encrypted = encrypt_bytes(&key, &json).expect("failed to encrypt index");
        std::fs::write(inner.base_path.join("_index.age"), encrypted).expect("failed to write index");
    }

    // 3. Handle resume vs fresh
    if resume {
        let staging_dir = base_path.join(".rekey_staging");
        if staging_dir.exists() {
            if let Err(e) = verify_staged_passphrase(new_passphrase, base_path) {
                inner.read_only.store(false, Ordering::SeqCst);
                eprintln!("zerotrust-drive: error: cannot resume — {e}");
                return;
            }
            eprintln!("zerotrust-drive: passphrase verified — resuming interrupted rekey");
        }
    } else {
        cleanup_stale_staging(base_path);
    }

    // 4. Acquire lock
    let lock_path = base_path.join("_rekey.lock");
    std::fs::write(&lock_path, std::process::id().to_string()).expect("failed to create lock file");

    // 5. Derive keys and do staging
    let old_key = derive_key(old_passphrase);
    let new_key = derive_key(new_passphrase);

    let index_ciphertext = std::fs::read(base_path.join("_index.age")).expect("failed to read _index.age");
    let index_json = decrypt_bytes(&old_key, &index_ciphertext).expect("failed to decrypt _index.age");
    let index: DiskIndex = serde_json::from_slice(&index_json).expect("failed to parse index");

    let disk_files: Vec<String> = index.inodes.values()
        .filter(|e| e.kind == InodeKind::File && !e.disk_filename.is_empty())
        .map(|e| e.disk_filename.clone())
        .collect();

    let staging_dir = base_path.join(".rekey_staging");
    std::fs::create_dir_all(&staging_dir).expect("failed to create staging dir");

    let total = disk_files.len() + 1;
    eprintln!("zerotrust-drive: re-encrypting {} file(s) + index with new passphrase...", disk_files.len());

    let mut skipped = 0usize;
    for (i, filename) in disk_files.iter().enumerate() {
        let staged_path = staging_dir.join(filename);
        if resume && staged_path.exists() {
            skipped += 1;
            continue;
        }
        let ciphertext = std::fs::read(base_path.join(filename)).unwrap_or_else(|_| panic!("failed to read {filename}"));
        let plaintext = decrypt_bytes(&old_key, &ciphertext)
            .unwrap_or_else(|_| panic!("failed to decrypt {filename}"));
        let new_ciphertext = encrypt_bytes(&new_key, &plaintext).expect("failed to re-encrypt");
        std::fs::write(&staged_path, new_ciphertext).unwrap_or_else(|_| panic!("failed to write staging/{filename}"));
        eprintln!("zerotrust-drive: [{}/{}] re-encrypted {}", i + 1, total, filename);
    }
    if skipped > 0 {
        eprintln!("zerotrust-drive: skipped {skipped} already-staged file(s)");
    }

    let staged_index = staging_dir.join("_index.age");
    if !resume || !staged_index.exists() {
        let new_index_ciphertext = encrypt_bytes(&new_key, &index_json).expect("failed to re-encrypt index");
        std::fs::write(&staged_index, new_index_ciphertext).expect("failed to write staging/_index.age");
        eprintln!("zerotrust-drive: [{total}/{total}] re-encrypted _index.age");
    }

    // 6. Write manifest (commit point)
    let mut manifest: Vec<ManifestEntry> = disk_files.iter().cloned()
        .chain(std::iter::once("_index.age".to_string()))
        .map(|f| ManifestEntry { filename: f, renamed: false })
        .collect();
    let manifest_path = base_path.join("_rekey.manifest");
    let manifest_json = serde_json::to_vec(&manifest).expect("failed to serialize manifest");
    std::fs::write(&manifest_path, &manifest_json).expect("failed to write manifest");

    // 7. Rename pass
    for i in 0..manifest.len() {
        std::fs::rename(staging_dir.join(&manifest[i].filename), base_path.join(&manifest[i].filename))
            .unwrap_or_else(|_| panic!("failed to rename staging/{} -> {}", manifest[i].filename, manifest[i].filename));
        manifest[i].renamed = true;
        let updated = serde_json::to_vec(&manifest).expect("failed to serialize manifest");
        std::fs::write(&manifest_path, &updated).expect("failed to update manifest");
    }

    let _ = std::fs::remove_dir_all(&staging_dir);
    let _ = std::fs::remove_file(&manifest_path);
    let _ = std::fs::remove_file(&lock_path);

    // 8. Swap key
    {
        let mut key = inner.key.write().unwrap();
        *key = new_key;
    }

    // 9. Re-flush open files with new key
    {
        let key = inner.key.read().unwrap();
        let open = inner.open_files.lock().unwrap();
        let state = inner.state.lock().unwrap();
        for (&ino, content) in open.iter() {
            if let Some(entry) = state.inodes.get(&ino) {
                if !entry.disk_filename.is_empty() {
                    let encrypted = encrypt_bytes(&key, content).expect("failed to encrypt");
                    std::fs::write(inner.base_path.join(&entry.disk_filename), encrypted).expect("failed to write");
                }
            }
        }
        let json = serde_json::to_vec(&*state).expect("failed to serialize index");
        let encrypted = encrypt_bytes(&key, &json).expect("failed to encrypt index");
        std::fs::write(inner.base_path.join("_index.age"), encrypted).expect("failed to write index");
        if let Ok(meta) = std::fs::metadata(inner.base_path.join("_index.age")) {
            if let Ok(mtime) = meta.modified() {
                *inner.index_mtime.lock().unwrap() = Some(mtime);
            }
        }
    }

    // 10. Unlock
    inner.read_only.store(false, Ordering::SeqCst);
    eprintln!("zerotrust-drive: passphrase rotation complete — filesystem is read-write again");
    eprintln!("zerotrust-drive: all files are now encrypted with the new passphrase");
    eprintln!("zerotrust-drive: remember to update ZEROTRUST_PASSPHRASE before next mount");
}

impl Filesystem for ZeroTrustFs {
    fn init(&mut self, _req: &Request, _config: &mut fuser::KernelConfig) -> std::io::Result<()> {
        Ok(())
    }

    fn destroy(&mut self) {
        let open = self.inner.open_files.lock().unwrap();
        let state = self.inner.state.lock().unwrap();
        for (&ino, content) in open.iter() {
            if let Some(entry) = state.inodes.get(&ino) {
                if !entry.disk_filename.is_empty() {
                    self.write_encrypted_file(&entry.disk_filename, content);
                }
            }
        }
        let json = serde_json::to_vec(&*state).expect("failed to serialize");
        drop(state);
        drop(open);
        self.persist_index(&json);
    }

    fn lookup(&self, _req: &Request, parent: INodeNo, name: &OsStr, reply: ReplyEntry) {
        trace!("FUSE: lookup parent={} name={:?}", parent.0, name);
        let name_str = match name.to_str() {
            Some(s) => s,
            None => { reply.error(fuser::Errno::ENOENT); return; }
        };
        let state = self.inner.state.lock().unwrap();
        if let Some(ino) = Self::find_child(&state, parent.0, name_str) {
            if let Some(entry) = state.inodes.get(&ino) {
                reply.entry(&TTL, &Self::inode_to_attr(ino, entry), Generation(0));
                return;
            }
        }
        reply.error(fuser::Errno::ENOENT);
    }

    fn getattr(&self, _req: &Request, ino: INodeNo, _fh: Option<FileHandle>, reply: ReplyAttr) {
        trace!("FUSE: getattr ino={}", ino.0);
        let state = self.inner.state.lock().unwrap();
        match state.inodes.get(&ino.0) {
            Some(entry) => {
                let mut attr = Self::inode_to_attr(ino.0, entry);
                let is_file = entry.kind == InodeKind::File;
                drop(state);
                if is_file {
                    let open = self.inner.open_files.lock().unwrap();
                    if let Some(content) = open.get(&ino.0) {
                        attr.size = content.len() as u64;
                        attr.blocks = (attr.size + 511) / 512;
                    }
                }
                reply.attr(&TTL, &attr);
            }
            None => reply.error(fuser::Errno::ENOENT),
        }
    }

    fn setattr(
        &self, _req: &Request, ino: INodeNo,
        mode: Option<u32>, uid: Option<u32>, gid: Option<u32>, size: Option<u64>,
        _atime: Option<fuser::TimeOrNow>, _mtime: Option<fuser::TimeOrNow>,
        _ctime: Option<SystemTime>, _fh: Option<FileHandle>,
        _crtime: Option<SystemTime>, _chgtime: Option<SystemTime>,
        _bkuptime: Option<SystemTime>, _flags: Option<fuser::BsdFileFlags>,
        reply: ReplyAttr,
    ) {
        if self.inner.read_only.load(Ordering::Relaxed) {
            reply.error(fuser::Errno::EROFS);
            return;
        }
        {
            let mut state = self.inner.state.lock().unwrap();
            let entry = match state.inodes.get_mut(&ino.0) {
                Some(e) => e,
                None => { reply.error(fuser::Errno::ENOENT); return; }
            };
            if let Some(m) = mode { entry.perm = (m & 0o7777) as u16; }
            if let Some(u) = uid { entry.uid = u; }
            if let Some(g) = gid { entry.gid = g; }
            if let Some(new_size) = size { entry.size = new_size; }
            entry.ctime_secs = now_secs();
        }
        if let Some(new_size) = size {
            let mut open = self.inner.open_files.lock().unwrap();
            if let Some(content) = open.get_mut(&ino.0) {
                content.resize(new_size as usize, 0);
            }
        }
        let attr = {
            let state = self.inner.state.lock().unwrap();
            Self::inode_to_attr(ino.0, state.inodes.get(&ino.0).unwrap())
        };
        reply.attr(&TTL, &attr);
        self.flush_state();
    }

    fn open(&self, _req: &Request, ino: INodeNo, _flags: fuser::OpenFlags, reply: ReplyOpen) {
        let disk_filename = {
            let state = self.inner.state.lock().unwrap();
            match state.inodes.get(&ino.0) {
                Some(entry) if entry.kind == InodeKind::File => entry.disk_filename.clone(),
                Some(_) => { reply.error(fuser::Errno::EISDIR); return; }
                None => { reply.error(fuser::Errno::ENOENT); return; }
            }
        };
        let content = if !disk_filename.is_empty() && self.inner.base_path.join(&disk_filename).exists() {
            self.read_encrypted_file(&disk_filename)
        } else {
            Vec::new()
        };
        self.inner.open_files.lock().unwrap().insert(ino.0, content);
        reply.opened(FileHandle(ino.0), FopenFlags::empty());
    }

    fn read(
        &self, _req: &Request, ino: INodeNo, _fh: FileHandle, offset: u64, size: u32,
        _flags: fuser::OpenFlags, _lock_owner: Option<fuser::LockOwner>, reply: ReplyData,
    ) {
        let open = self.inner.open_files.lock().unwrap();
        match open.get(&ino.0) {
            Some(content) => {
                let start = offset as usize;
                if start >= content.len() {
                    reply.data(&[]);
                } else {
                    let end = (start + size as usize).min(content.len());
                    reply.data(&content[start..end]);
                }
            }
            None => reply.error(fuser::Errno::ENOENT),
        }
    }

    fn write(
        &self, _req: &Request, ino: INodeNo, _fh: FileHandle, offset: u64, data: &[u8],
        _write_flags: fuser::WriteFlags, _flags: fuser::OpenFlags,
        _lock_owner: Option<fuser::LockOwner>, reply: ReplyWrite,
    ) {
        if self.inner.read_only.load(Ordering::Relaxed) {
            reply.error(fuser::Errno::EROFS);
            return;
        }
        trace!("FUSE: write ino={} offset={} len={}", ino.0, offset, data.len());
        let new_size = {
            let mut open = self.inner.open_files.lock().unwrap();
            match open.get_mut(&ino.0) {
                Some(content) => {
                    let start = offset as usize;
                    let end = start + data.len();
                    if end > content.len() { content.resize(end, 0); }
                    content[start..end].copy_from_slice(data);
                    content.len() as u64
                }
                None => { reply.error(fuser::Errno::ENOENT); return; }
            }
        };
        {
            let mut state = self.inner.state.lock().unwrap();
            if let Some(entry) = state.inodes.get_mut(&ino.0) {
                entry.size = new_size;
                entry.mtime_secs = now_secs();
            }
        }
        reply.written(data.len() as u32);
    }

    fn flush(
        &self, _req: &Request, ino: INodeNo, _fh: FileHandle,
        _lock_owner: fuser::LockOwner, reply: ReplyEmpty,
    ) {
        if self.inner.read_only.load(Ordering::Relaxed) {
            reply.ok();
            return;
        }
        trace!("FUSE: flush ino={}", ino.0);
        reply.ok();
        let content = self.inner.open_files.lock().unwrap().get(&ino.0).cloned();
        if let Some(data) = content {
            let disk_filename = {
                let state = self.inner.state.lock().unwrap();
                state.inodes.get(&ino.0).map(|e| e.disk_filename.clone()).unwrap_or_default()
            };
            if !disk_filename.is_empty() {
                self.write_encrypted_file(&disk_filename, &data);
            }
            self.flush_state();
        }
    }

    fn release(
        &self, _req: &Request, ino: INodeNo, _fh: FileHandle, _flags: fuser::OpenFlags,
        _lock_owner: Option<fuser::LockOwner>, _flush: bool, reply: ReplyEmpty,
    ) {
        if self.inner.read_only.load(Ordering::Relaxed) {
            reply.ok();  // keep in open_files, don't evict
            return;
        }
        trace!("FUSE: release ino={}", ino.0);
        reply.ok();
        let content = self.inner.open_files.lock().unwrap().remove(&ino.0);
        if let Some(data) = content {
            let disk_filename = {
                let state = self.inner.state.lock().unwrap();
                state.inodes.get(&ino.0).map(|e| e.disk_filename.clone()).unwrap_or_default()
            };
            if !disk_filename.is_empty() {
                self.write_encrypted_file(&disk_filename, &data);
            }
            self.flush_state();
        }
    }

    fn mknod(
        &self, req: &Request, parent: INodeNo, name: &OsStr,
        mode: u32, _umask: u32, _rdev: u32, reply: ReplyEntry,
    ) {
        if self.inner.read_only.load(Ordering::Relaxed) {
            reply.error(fuser::Errno::EROFS);
            return;
        }
        trace!("FUSE: mknod parent={} name={:?} mode={:#o}", parent.0, name, mode);
        let file_type = mode & libc::S_IFMT as u32;
        if file_type != libc::S_IFREG as u32 && file_type != 0 {
            reply.error(fuser::Errno::ENOSYS);
            return;
        }
        let name_str = match name.to_str() {
            Some(s) => s,
            None => { reply.error(fuser::Errno::EINVAL); return; }
        };
        let (ino, attr) = {
            let mut state = self.inner.state.lock().unwrap();
            match state.inodes.get(&parent.0) {
                Some(e) if e.kind == InodeKind::Directory => {}
                _ => { reply.error(fuser::Errno::ENOTDIR); return; }
            }
            if Self::find_child(&state, parent.0, name_str).is_some() {
                reply.error(fuser::Errno::EEXIST); return;
            }
            let ino = Self::allocate_inode(&mut state);
            let disk_filename = Self::allocate_disk_filename(&mut state);
            let now = now_secs();
            let entry = InodeEntry {
                name: name_str.to_string(), kind: InodeKind::File,
                disk_filename: disk_filename.clone(), size: 0,
                perm: (mode & 0o7777) as u16, uid: req.uid(), gid: req.gid(),
                atime_secs: now, mtime_secs: now, ctime_secs: now, nlink: 1, parent: parent.0,
            };
            let attr = Self::inode_to_attr(ino, &entry);
            state.inodes.insert(ino, entry);
            state.children.entry(parent.0).or_default().push(DirChild {
                name: name_str.to_string(), inode: ino,
            });
            (ino, attr)
        };
        reply.entry(&TTL, &attr, Generation(0));
        trace!("FUSE: mknod replied ino={}", ino);
    }

    fn create(
        &self, req: &Request, parent: INodeNo, name: &OsStr,
        mode: u32, _umask: u32, _flags: i32, reply: ReplyCreate,
    ) {
        if self.inner.read_only.load(Ordering::Relaxed) {
            reply.error(fuser::Errno::EROFS);
            return;
        }
        trace!("FUSE: create parent={} name={:?} mode={:#o}", parent.0, name, mode);
        let name_str = match name.to_str() {
            Some(s) => s,
            None => { reply.error(fuser::Errno::EINVAL); return; }
        };

        let (ino, attr, _disk_filename) = {
            let mut state = self.inner.state.lock().unwrap();
            match state.inodes.get(&parent.0) {
                Some(e) if e.kind == InodeKind::Directory => {}
                _ => { reply.error(fuser::Errno::ENOTDIR); return; }
            }
            if Self::find_child(&state, parent.0, name_str).is_some() {
                reply.error(fuser::Errno::EEXIST); return;
            }
            let ino = Self::allocate_inode(&mut state);
            let disk_filename = Self::allocate_disk_filename(&mut state);
            let now = now_secs();
            let entry = InodeEntry {
                name: name_str.to_string(), kind: InodeKind::File,
                disk_filename: disk_filename.clone(), size: 0,
                perm: (mode & 0o7777) as u16, uid: req.uid(), gid: req.gid(),
                atime_secs: now, mtime_secs: now, ctime_secs: now, nlink: 1, parent: parent.0,
            };
            let attr = Self::inode_to_attr(ino, &entry);
            state.inodes.insert(ino, entry);
            state.children.entry(parent.0).or_default().push(DirChild {
                name: name_str.to_string(), inode: ino,
            });
            (ino, attr, disk_filename)
        };
        self.inner.open_files.lock().unwrap().insert(ino, Vec::new());
        reply.created(&TTL, &attr, Generation(0), FileHandle(ino), FopenFlags::empty());
        trace!("FUSE: create replied ino={} fh={}", ino, ino);
    }

    fn mkdir(
        &self, req: &Request, parent: INodeNo, name: &OsStr,
        mode: u32, _umask: u32, reply: ReplyEntry,
    ) {
        if self.inner.read_only.load(Ordering::Relaxed) {
            reply.error(fuser::Errno::EROFS);
            return;
        }
        let name_str = match name.to_str() {
            Some(s) => s,
            None => { reply.error(fuser::Errno::EINVAL); return; }
        };

        let attr = {
            let mut state = self.inner.state.lock().unwrap();
            match state.inodes.get(&parent.0) {
                Some(e) if e.kind == InodeKind::Directory => {}
                _ => { reply.error(fuser::Errno::ENOTDIR); return; }
            }
            if Self::find_child(&state, parent.0, name_str).is_some() {
                reply.error(fuser::Errno::EEXIST); return;
            }
            let ino = Self::allocate_inode(&mut state);
            let now = now_secs();
            let entry = InodeEntry {
                name: name_str.to_string(), kind: InodeKind::Directory,
                disk_filename: String::new(), size: 0,
                perm: (mode & 0o7777) as u16, uid: req.uid(), gid: req.gid(),
                atime_secs: now, mtime_secs: now, ctime_secs: now, nlink: 2, parent: parent.0,
            };
            let attr = Self::inode_to_attr(ino, &entry);
            state.inodes.insert(ino, entry);
            state.children.insert(ino, Vec::new());
            state.children.entry(parent.0).or_default().push(DirChild {
                name: name_str.to_string(), inode: ino,
            });
            if let Some(p) = state.inodes.get_mut(&parent.0) { p.nlink += 1; }
            attr
        };
        reply.entry(&TTL, &attr, Generation(0));
        self.flush_state();
    }

    fn unlink(&self, _req: &Request, parent: INodeNo, name: &OsStr, reply: ReplyEmpty) {
        if self.inner.read_only.load(Ordering::Relaxed) {
            reply.error(fuser::Errno::EROFS);
            return;
        }
        let name_str = match name.to_str() {
            Some(s) => s,
            None => { reply.error(fuser::Errno::ENOENT); return; }
        };

        let disk_filename = {
            let mut state = self.inner.state.lock().unwrap();
            let ino = match Self::find_child(&state, parent.0, name_str) {
                Some(i) => i,
                None => { reply.error(fuser::Errno::ENOENT); return; }
            };
            let df = state.inodes.get(&ino).map(|e| e.disk_filename.clone()).unwrap_or_default();
            state.inodes.remove(&ino);
            if let Some(ch) = state.children.get_mut(&parent.0) { ch.retain(|c| c.inode != ino); }
            self.inner.open_files.lock().unwrap().remove(&ino);
            df
        };
        reply.ok();
        self.flush_state();
        if !disk_filename.is_empty() {
            let _ = fs::remove_file(self.inner.base_path.join(&disk_filename));
        }
    }

    fn rmdir(&self, _req: &Request, parent: INodeNo, name: &OsStr, reply: ReplyEmpty) {
        if self.inner.read_only.load(Ordering::Relaxed) {
            reply.error(fuser::Errno::EROFS);
            return;
        }
        let name_str = match name.to_str() {
            Some(s) => s,
            None => { reply.error(fuser::Errno::ENOENT); return; }
        };

        {
            let mut state = self.inner.state.lock().unwrap();
            let ino = match Self::find_child(&state, parent.0, name_str) {
                Some(i) => i,
                None => { reply.error(fuser::Errno::ENOENT); return; }
            };
            match state.inodes.get(&ino) {
                Some(e) if e.kind == InodeKind::Directory => {}
                _ => { reply.error(fuser::Errno::ENOTDIR); return; }
            }
            if state.children.get(&ino).is_some_and(|ch| !ch.is_empty()) {
                reply.error(fuser::Errno::ENOTEMPTY); return;
            }
            state.inodes.remove(&ino);
            state.children.remove(&ino);
            if let Some(ch) = state.children.get_mut(&parent.0) { ch.retain(|c| c.inode != ino); }
            if let Some(p) = state.inodes.get_mut(&parent.0) { p.nlink = p.nlink.saturating_sub(1); }
        };
        reply.ok();
        self.flush_state();
    }

    fn rename(
        &self, _req: &Request, parent: INodeNo, name: &OsStr,
        newparent: INodeNo, newname: &OsStr, _flags: fuser::RenameFlags, reply: ReplyEmpty,
    ) {
        if self.inner.read_only.load(Ordering::Relaxed) {
            reply.error(fuser::Errno::EROFS);
            return;
        }
        let name_str = match name.to_str() {
            Some(s) => s, None => { reply.error(fuser::Errno::EINVAL); return; }
        };
        let newname_str = match newname.to_str() {
            Some(s) => s, None => { reply.error(fuser::Errno::EINVAL); return; }
        };

        let disk_file_to_remove = {
            let mut state = self.inner.state.lock().unwrap();
            let ino = match Self::find_child(&state, parent.0, name_str) {
                Some(i) => i,
                None => { reply.error(fuser::Errno::ENOENT); return; }
            };
            let mut to_remove = None;
            if let Some(existing) = Self::find_child(&state, newparent.0, newname_str) {
                to_remove = state.inodes.get(&existing).and_then(|e| {
                    if e.disk_filename.is_empty() { None } else { Some(e.disk_filename.clone()) }
                });
                state.inodes.remove(&existing);
                if let Some(ch) = state.children.get_mut(&newparent.0) { ch.retain(|c| c.inode != existing); }
            }
            if let Some(ch) = state.children.get_mut(&parent.0) { ch.retain(|c| c.inode != ino); }
            state.children.entry(newparent.0).or_default().push(DirChild {
                name: newname_str.to_string(), inode: ino,
            });
            if let Some(entry) = state.inodes.get_mut(&ino) {
                entry.name = newname_str.to_string();
                entry.parent = newparent.0;
                entry.ctime_secs = now_secs();
            }
            to_remove
        };
        reply.ok();
        self.flush_state();
        if let Some(f) = disk_file_to_remove {
            let _ = fs::remove_file(self.inner.base_path.join(&f));
        }
    }

    fn readdir(
        &self, _req: &Request, ino: INodeNo, _fh: FileHandle, offset: u64,
        mut reply: ReplyDirectory,
    ) {
        let state = self.inner.state.lock().unwrap();
        match state.inodes.get(&ino.0) {
            Some(e) if e.kind == InodeKind::Directory => {}
            _ => { reply.error(fuser::Errno::ENOTDIR); return; }
        }
        let parent_ino = state.inodes.get(&ino.0).map(|e| e.parent).unwrap_or(1);
        let mut entries: Vec<(INodeNo, FileType, String)> = vec![
            (INodeNo(ino.0), FileType::Directory, ".".to_string()),
            (INodeNo(parent_ino), FileType::Directory, "..".to_string()),
        ];
        if let Some(children) = state.children.get(&ino.0) {
            for child in children {
                let kind = state.inodes.get(&child.inode)
                    .map(|e| match e.kind {
                        InodeKind::File => FileType::RegularFile,
                        InodeKind::Directory => FileType::Directory,
                    })
                    .unwrap_or(FileType::RegularFile);
                entries.push((INodeNo(child.inode), kind, child.name.clone()));
            }
        }
        for (i, (entry_ino, kind, name)) in entries.iter().enumerate().skip(offset as usize) {
            if reply.add(*entry_ino, (i + 1) as u64, *kind, name) { break; }
        }
        reply.ok();
    }

    fn statfs(&self, _req: &Request, _ino: INodeNo, reply: ReplyStatfs) {
        let state = self.inner.state.lock().unwrap();
        let files = state.inodes.len() as u64;
        reply.statfs(1_000_000, 900_000, 900_000, files, 1_000_000 - files, BLKSIZE, 255, 0);
    }

    fn access(&self, _req: &Request, ino: INodeNo, _mask: fuser::AccessFlags, reply: ReplyEmpty) {
        if self.inner.state.lock().unwrap().inodes.contains_key(&ino.0) {
            reply.ok();
        } else {
            reply.error(fuser::Errno::ENOENT);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::derive_key;

    #[test]
    fn encrypt_decrypt_round_trip() {
        let key = derive_key("pw");
        let plaintext = b"round trip test data";
        let ciphertext = encrypt_bytes(&key, plaintext).unwrap();
        let decrypted = decrypt_bytes(&key, &ciphertext).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn wrong_passphrase_fails() {
        let right = derive_key("right");
        let wrong = derive_key("wrong");
        let ciphertext = encrypt_bytes(&right, b"secret").unwrap();
        assert!(decrypt_bytes(&wrong, &ciphertext).is_err());
    }

    #[test]
    fn index_serialization_round_trip() {
        let mut inodes = HashMap::new();
        inodes.insert(1, InodeEntry {
            name: String::new(), kind: InodeKind::Directory, disk_filename: String::new(),
            size: 0, perm: 0o755, uid: 501, gid: 20,
            atime_secs: 1000, mtime_secs: 1000, ctime_secs: 1000, nlink: 2, parent: 1,
        });
        inodes.insert(2, InodeEntry {
            name: "test.txt".to_string(), kind: InodeKind::File,
            disk_filename: "000001.age".to_string(), size: 42, perm: 0o644, uid: 501, gid: 20,
            atime_secs: 2000, mtime_secs: 2000, ctime_secs: 2000, nlink: 1, parent: 1,
        });
        let mut children = HashMap::new();
        children.insert(1, vec![DirChild { name: "test.txt".to_string(), inode: 2 }]);
        let index = DiskIndex { next_inode: 3, next_file_id: 2, inodes, children };

        let json = serde_json::to_vec(&index).unwrap();
        let key = derive_key("test-pw");
        let encrypted = encrypt_bytes(&key, &json).unwrap();
        let decrypted = decrypt_bytes(&key, &encrypted).unwrap();
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
            name: "hello.txt".to_string(), kind: InodeKind::File,
            disk_filename: "000001.age".to_string(), size: 1024, perm: 0o644, uid: 501, gid: 20,
            atime_secs: 1000, mtime_secs: 2000, ctime_secs: 3000, nlink: 1, parent: 1,
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
            name: "docs".to_string(), kind: InodeKind::Directory,
            disk_filename: String::new(), size: 0, perm: 0o755, uid: 501, gid: 20,
            atime_secs: 1000, mtime_secs: 1000, ctime_secs: 1000, nlink: 2, parent: 1,
        };
        let attr = ZeroTrustFs::inode_to_attr(3, &entry);
        assert_eq!(attr.kind, FileType::Directory);
        assert_eq!(attr.perm, 0o755);
        assert_eq!(attr.nlink, 2);
    }

    #[test]
    fn find_child_exists() {
        let mut children = HashMap::new();
        children.insert(1, vec![
            DirChild { name: "a.txt".to_string(), inode: 2 },
            DirChild { name: "b.txt".to_string(), inode: 3 },
        ]);
        let index = DiskIndex { next_inode: 4, next_file_id: 3, inodes: HashMap::new(), children };
        assert_eq!(ZeroTrustFs::find_child(&index, 1, "a.txt"), Some(2));
        assert_eq!(ZeroTrustFs::find_child(&index, 1, "b.txt"), Some(3));
        assert_eq!(ZeroTrustFs::find_child(&index, 1, "c.txt"), None);
    }

    #[test]
    fn disk_filename_allocation() {
        let mut index = DiskIndex {
            next_inode: 1, next_file_id: 1, inodes: HashMap::new(), children: HashMap::new(),
        };
        assert_eq!(ZeroTrustFs::allocate_disk_filename(&mut index), "000001.age");
        assert_eq!(ZeroTrustFs::allocate_disk_filename(&mut index), "000002.age");
        assert_eq!(index.next_file_id, 3);
    }

    #[test]
    fn encrypted_file_persistence() {
        use std::sync::atomic::{AtomicU32, Ordering};
        static CTR: AtomicU32 = AtomicU32::new(0);
        let id = CTR.fetch_add(1, Ordering::SeqCst);
        let dir = PathBuf::from(format!("target/test-zt-{id}"));
        let _ = fs::remove_dir_all(&dir);

        let ztfs = ZeroTrustFs::new("test-pw", dir.clone());
        ztfs.write_encrypted_file("test.age", b"hello world");
        let content = ztfs.read_encrypted_file("test.age");
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
            let mut state = ztfs.inner.state.lock().unwrap();
            let ino = ZeroTrustFs::allocate_inode(&mut state);
            let disk_filename = ZeroTrustFs::allocate_disk_filename(&mut state);
            state.inodes.insert(ino, InodeEntry {
                name: "note.txt".to_string(), kind: InodeKind::File,
                disk_filename: disk_filename.clone(), size: 13, perm: 0o644,
                uid: 501, gid: 20, atime_secs: 1000, mtime_secs: 1000, ctime_secs: 1000,
                nlink: 1, parent: 1,
            });
            state.children.entry(1).or_default().push(DirChild {
                name: "note.txt".to_string(), inode: ino,
            });
            disk_filename
        };
        ztfs.write_encrypted_file(&disk_filename, b"hello, world!");
        ztfs.flush_state();

        let content = ztfs.read_encrypted_file(&disk_filename);
        assert_eq!(content, b"hello, world!");

        let updated = b"updated content for note";
        ztfs.write_encrypted_file(&disk_filename, updated);
        {
            let mut state = ztfs.inner.state.lock().unwrap();
            let ino = ZeroTrustFs::find_child(&state, 1, "note.txt").unwrap();
            state.inodes.get_mut(&ino).unwrap().size = updated.len() as u64;
        }
        ztfs.flush_state();

        let content = ztfs.read_encrypted_file(&disk_filename);
        assert_eq!(content, updated);

        {
            let mut state = ztfs.inner.state.lock().unwrap();
            let ino = ZeroTrustFs::find_child(&state, 1, "note.txt").unwrap();
            state.inodes.remove(&ino);
            if let Some(ch) = state.children.get_mut(&1) { ch.retain(|c| c.inode != ino); }
        }
        let _ = fs::remove_file(dir.join(&disk_filename));
        ztfs.flush_state();

        assert!(!dir.join(&disk_filename).exists());
        let state = ztfs.inner.state.lock().unwrap();
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
                let mut state = ztfs.inner.state.lock().unwrap();
                let ino = ZeroTrustFs::allocate_inode(&mut state);
                let df = ZeroTrustFs::allocate_disk_filename(&mut state);
                state.inodes.insert(ino, InodeEntry {
                    name: name.to_string(), kind: InodeKind::File,
                    disk_filename: df.clone(), size: content.len() as u64, perm: 0o644,
                    uid: 501, gid: 20, atime_secs: 1000, mtime_secs: 1000, ctime_secs: 1000,
                    nlink: 1, parent: 1,
                });
                state.children.entry(1).or_default().push(DirChild {
                    name: name.to_string(), inode: ino,
                });
                df
            };
            ztfs.write_encrypted_file(&disk_filename, content);
            disk_filenames.push(disk_filename);
        }
        ztfs.flush_state();

        for (i, (_name, expected)) in files.iter().enumerate() {
            let content = ztfs.read_encrypted_file(&disk_filenames[i]);
            assert_eq!(content, *expected);
        }

        let updated_beta = b"beta has been updated";
        ztfs.write_encrypted_file(&disk_filenames[1], updated_beta);
        {
            let mut state = ztfs.inner.state.lock().unwrap();
            let ino = ZeroTrustFs::find_child(&state, 1, "beta.txt").unwrap();
            state.inodes.get_mut(&ino).unwrap().size = updated_beta.len() as u64;
        }
        ztfs.flush_state();

        {
            let mut state = ztfs.inner.state.lock().unwrap();
            let ino = ZeroTrustFs::find_child(&state, 1, "alpha.txt").unwrap();
            state.inodes.remove(&ino);
            if let Some(ch) = state.children.get_mut(&1) { ch.retain(|c| c.inode != ino); }
        }
        let _ = fs::remove_file(dir.join(&disk_filenames[0]));
        ztfs.flush_state();

        let state = ztfs.inner.state.lock().unwrap();
        assert!(ZeroTrustFs::find_child(&state, 1, "alpha.txt").is_none());

        drop(state);
        let content = ztfs.read_encrypted_file(&disk_filenames[1]);
        assert_eq!(content, updated_beta);

        let content = ztfs.read_encrypted_file(&disk_filenames[2]);
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
                let mut state = ztfs.inner.state.lock().unwrap();
                let ino = ZeroTrustFs::allocate_inode(&mut state);
                let df = ZeroTrustFs::allocate_disk_filename(&mut state);
                state.inodes.insert(ino, InodeEntry {
                    name: "persist.txt".to_string(), kind: InodeKind::File,
                    disk_filename: df.clone(), size: 15, perm: 0o644,
                    uid: 501, gid: 20, atime_secs: 1000, mtime_secs: 1000, ctime_secs: 1000,
                    nlink: 1, parent: 1,
                });
                state.children.entry(1).or_default().push(DirChild {
                    name: "persist.txt".to_string(), inode: ino,
                });
                df
            };
            ztfs.write_encrypted_file(&df, b"persisted data!");
            ztfs.flush_state();
            df
        };

        {
            let ztfs = ZeroTrustFs::new(passphrase, dir.clone());
            let state = ztfs.inner.state.lock().unwrap();
            let ino = ZeroTrustFs::find_child(&state, 1, "persist.txt")
                .expect("persist.txt should exist after reopen");
            let entry = state.inodes.get(&ino).unwrap();
            assert_eq!(entry.name, "persist.txt");
            assert_eq!(entry.disk_filename, disk_filename);
            drop(state);

            let content = ztfs.read_encrypted_file(&disk_filename);
            assert_eq!(content, b"persisted data!");
        }

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn rekey_basic() {
        let dir = PathBuf::from("target/test-rekey-basic");
        let _ = fs::remove_dir_all(&dir);
        let old_pw = "old-passphrase";
        let new_pw = "new-passphrase";

        // Create a filesystem with some files
        {
            let ztfs = ZeroTrustFs::new(old_pw, dir.clone());
            let mut state = ztfs.inner.state.lock().unwrap();
            let ino = ZeroTrustFs::allocate_inode(&mut state);
            let df = ZeroTrustFs::allocate_disk_filename(&mut state);
            state.inodes.insert(ino, InodeEntry {
                name: "secret.txt".to_string(), kind: InodeKind::File,
                disk_filename: df.clone(), size: 11, perm: 0o644,
                uid: 501, gid: 20, atime_secs: 1000, mtime_secs: 1000, ctime_secs: 1000,
                nlink: 1, parent: 1,
            });
            state.children.entry(1).or_default().push(DirChild {
                name: "secret.txt".to_string(), inode: ino,
            });
            drop(state);
            ztfs.write_encrypted_file(&df, b"secret data");
            ztfs.flush_state();
        }

        // Rekey
        rekey(old_pw, new_pw, &dir, false);

        // Old passphrase should fail
        let old_key = derive_key(old_pw);
        let index_ct = fs::read(dir.join("_index.age")).unwrap();
        assert!(decrypt_bytes(&old_key, &index_ct).is_err());

        // New passphrase should work
        let ztfs = ZeroTrustFs::new(new_pw, dir.clone());
        let state = ztfs.inner.state.lock().unwrap();
        let ino = ZeroTrustFs::find_child(&state, 1, "secret.txt").expect("file should exist");
        let df = state.inodes.get(&ino).unwrap().disk_filename.clone();
        drop(state);
        let content = ztfs.read_encrypted_file(&df);
        assert_eq!(content, b"secret data");

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn rekey_multiple_files() {
        let dir = PathBuf::from("target/test-rekey-multi");
        let _ = fs::remove_dir_all(&dir);
        let old_pw = "multi-old";
        let new_pw = "multi-new";

        let files_data: Vec<(&str, &[u8])> = vec![
            ("alpha.txt", b"alpha content"),
            ("beta.txt", b"beta content"),
            ("gamma.txt", b"gamma content"),
        ];

        {
            let ztfs = ZeroTrustFs::new(old_pw, dir.clone());
            for (name, content) in &files_data {
                let df = {
                    let mut state = ztfs.inner.state.lock().unwrap();
                    let ino = ZeroTrustFs::allocate_inode(&mut state);
                    let df = ZeroTrustFs::allocate_disk_filename(&mut state);
                    state.inodes.insert(ino, InodeEntry {
                        name: name.to_string(), kind: InodeKind::File,
                        disk_filename: df.clone(), size: content.len() as u64, perm: 0o644,
                        uid: 501, gid: 20, atime_secs: 1000, mtime_secs: 1000, ctime_secs: 1000,
                        nlink: 1, parent: 1,
                    });
                    state.children.entry(1).or_default().push(DirChild {
                        name: name.to_string(), inode: ino,
                    });
                    df
                };
                ztfs.write_encrypted_file(&df, content);
            }
            ztfs.flush_state();
        }

        rekey(old_pw, new_pw, &dir, false);

        // Verify all files with new passphrase
        let ztfs = ZeroTrustFs::new(new_pw, dir.clone());
        let state = ztfs.inner.state.lock().unwrap();
        for (name, expected) in &files_data {
            let ino = ZeroTrustFs::find_child(&state, 1, name).expect("file should exist");
            let df = state.inodes.get(&ino).unwrap().disk_filename.clone();
            let content = ztfs.read_encrypted_file(&df);
            assert_eq!(content, *expected, "mismatch for {name}");
        }

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn cleanup_stale_staging_test() {
        let dir = PathBuf::from("target/test-cleanup-stale");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();

        // Create a stale staging directory and a real .age file
        let staging_dir = dir.join(".rekey_staging");
        fs::create_dir_all(&staging_dir).unwrap();
        fs::write(dir.join("000001.age"), b"original").unwrap();
        fs::write(staging_dir.join("000001.age"), b"staged").unwrap();
        fs::write(staging_dir.join("000002.age"), b"orphan").unwrap();

        cleanup_stale_staging(&dir);

        assert!(dir.join("000001.age").exists(), "original should remain");
        assert!(!staging_dir.exists(), "staging dir should be removed");

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn recover_interrupted_rekey_test() {
        let dir = PathBuf::from("target/test-recover-rekey");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();

        // Simulate an interrupted rekey: some files renamed, some still in staging
        let staging_dir = dir.join(".rekey_staging");
        fs::create_dir_all(&staging_dir).unwrap();

        fs::write(dir.join("000001.age"), b"already-renamed-new").unwrap();
        fs::write(dir.join("000002.age"), b"old-data").unwrap();
        fs::write(staging_dir.join("000002.age"), b"new-data").unwrap();
        fs::write(dir.join("_index.age"), b"old-index").unwrap();
        fs::write(staging_dir.join("_index.age"), b"new-index").unwrap();

        let manifest = vec![
            ManifestEntry { filename: "000001.age".to_string(), renamed: true },
            ManifestEntry { filename: "000002.age".to_string(), renamed: false },
            ManifestEntry { filename: "_index.age".to_string(), renamed: false },
        ];
        fs::write(
            dir.join("_rekey.manifest"),
            serde_json::to_vec(&manifest).unwrap(),
        )
        .unwrap();
        fs::write(dir.join("_rekey.lock"), b"12345").unwrap();

        let recovered = recover_interrupted_rekey(&dir);
        assert!(recovered);

        // 000001.age was already renamed (not in staging), should be untouched
        assert_eq!(fs::read(dir.join("000001.age")).unwrap(), b"already-renamed-new");
        // 000002.age should now have new-data
        assert_eq!(fs::read(dir.join("000002.age")).unwrap(), b"new-data");
        // _index.age should now have new-index
        assert_eq!(fs::read(dir.join("_index.age")).unwrap(), b"new-index");
        // Manifest, lock, and staging dir should be cleaned up
        assert!(!dir.join("_rekey.manifest").exists());
        assert!(!dir.join("_rekey.lock").exists());
        assert!(!staging_dir.exists());

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn rekey_online_basic() {
        let dir = PathBuf::from("target/test-rekey-online");
        let _ = fs::remove_dir_all(&dir);
        let old_pw = "online-old";
        let new_pw = "online-new";

        // Create a filesystem with a file
        let ztfs = ZeroTrustFs::new(old_pw, dir.clone());
        {
            let mut state = ztfs.inner.state.lock().unwrap();
            let ino = ZeroTrustFs::allocate_inode(&mut state);
            let df = ZeroTrustFs::allocate_disk_filename(&mut state);
            state.inodes.insert(ino, InodeEntry {
                name: "online.txt".to_string(), kind: InodeKind::File,
                disk_filename: df.clone(), size: 12, perm: 0o644,
                uid: 501, gid: 20, atime_secs: 1000, mtime_secs: 1000, ctime_secs: 1000,
                nlink: 1, parent: 1,
            });
            state.children.entry(1).or_default().push(DirChild {
                name: "online.txt".to_string(), inode: ino,
            });
        }
        ztfs.write_encrypted_file("000001.age", b"online data!");
        ztfs.flush_state();

        // Simulate an open file (content in RAM)
        ztfs.inner.open_files.lock().unwrap().insert(2, b"online data!".to_vec());

        // Verify read_only starts as false
        assert!(!ztfs.inner.read_only.load(Ordering::Relaxed));

        // Run rekey_online
        rekey_online(old_pw, new_pw, &dir, &ztfs.inner, false);

        // Verify read_only is restored to false
        assert!(!ztfs.inner.read_only.load(Ordering::Relaxed));

        // Verify key was swapped to new key
        let expected_new_key = derive_key(new_pw);
        assert_eq!(*ztfs.inner.key.read().unwrap(), expected_new_key);

        // Verify old passphrase can't decrypt the index
        let old_key = derive_key(old_pw);
        let index_ct = fs::read(dir.join("_index.age")).unwrap();
        assert!(decrypt_bytes(&old_key, &index_ct).is_err());

        // Verify new passphrase can open the filesystem
        let ztfs2 = ZeroTrustFs::new(new_pw, dir.clone());
        let state = ztfs2.inner.state.lock().unwrap();
        let ino = ZeroTrustFs::find_child(&state, 1, "online.txt").expect("file should exist");
        let df = state.inodes.get(&ino).unwrap().disk_filename.clone();
        drop(state);
        let content = ztfs2.read_encrypted_file(&df);
        assert_eq!(content, b"online data!");

        // Verify no staging artifacts remain
        assert!(!dir.join(".rekey_staging").exists());
        assert!(!dir.join("_rekey.manifest").exists());
        assert!(!dir.join("_rekey.lock").exists());

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn rekey_online_read_only_during_operation() {
        let dir = PathBuf::from("target/test-rekey-online-ro");
        let _ = fs::remove_dir_all(&dir);
        let old_pw = "ro-old";
        let new_pw = "ro-new";

        let ztfs = ZeroTrustFs::new(old_pw, dir.clone());
        {
            let mut state = ztfs.inner.state.lock().unwrap();
            let ino = ZeroTrustFs::allocate_inode(&mut state);
            let df = ZeroTrustFs::allocate_disk_filename(&mut state);
            state.inodes.insert(ino, InodeEntry {
                name: "test.txt".to_string(), kind: InodeKind::File,
                disk_filename: df.clone(), size: 4, perm: 0o644,
                uid: 501, gid: 20, atime_secs: 1000, mtime_secs: 1000, ctime_secs: 1000,
                nlink: 1, parent: 1,
            });
            state.children.entry(1).or_default().push(DirChild {
                name: "test.txt".to_string(), inode: ino,
            });
        }
        ztfs.write_encrypted_file("000001.age", b"test");
        ztfs.flush_state();

        // Manually set read_only and verify it blocks
        ztfs.inner.read_only.store(true, Ordering::SeqCst);
        assert!(ztfs.inner.read_only.load(Ordering::Relaxed));

        // Restore and run real rekey
        ztfs.inner.read_only.store(false, Ordering::SeqCst);
        rekey_online(old_pw, new_pw, &dir, &ztfs.inner, false);

        // After rekey, read_only should be false
        assert!(!ztfs.inner.read_only.load(Ordering::Relaxed));

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn conflict_detection_on_external_index_modification() {
        let dir = PathBuf::from("target/test-conflict");
        let _ = fs::remove_dir_all(&dir);

        let ztfs = ZeroTrustFs::new("conflict-pw", dir.clone());

        ztfs.flush_state();
        let mtime_before = *ztfs.inner.index_mtime.lock().unwrap();
        assert!(mtime_before.is_some());

        std::thread::sleep(Duration::from_millis(100));
        let index_path = dir.join("_index.age");
        let external_data = b"externally modified data";
        fs::write(&index_path, external_data).unwrap();

        let disk_mtime = fs::metadata(&index_path).unwrap().modified().unwrap();
        assert_ne!(Some(disk_mtime), mtime_before, "disk mtime should differ after external write");

        ztfs.flush_state();
        let mtime_after = *ztfs.inner.index_mtime.lock().unwrap();
        assert!(mtime_after.is_some());
        assert_ne!(mtime_before, mtime_after, "mtime should be updated after flush");

        let ciphertext = fs::read(&index_path).unwrap();
        let key = derive_key("conflict-pw");
        let json = decrypt_bytes(&key, &ciphertext).expect("index should be decryptable");
        let _index: DiskIndex = serde_json::from_slice(&json).expect("index should be valid JSON");

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn resume_rekey_same_passphrase() {
        let dir = PathBuf::from("target/test-resume-same-pw");
        let _ = fs::remove_dir_all(&dir);
        let old_pw = "resume-old";
        let new_pw = "resume-new";

        // Create filesystem with 3 files
        let ztfs = ZeroTrustFs::new(old_pw, dir.clone());
        {
            let mut state = ztfs.inner.state.lock().unwrap();
            for i in 1..=3 {
                let ino = ZeroTrustFs::allocate_inode(&mut state);
                let df = ZeroTrustFs::allocate_disk_filename(&mut state);
                state.inodes.insert(ino, InodeEntry {
                    name: format!("file{i}.txt"), kind: InodeKind::File,
                    disk_filename: df.clone(), size: 5, perm: 0o644,
                    uid: 501, gid: 20, atime_secs: 1000, mtime_secs: 1000, ctime_secs: 1000,
                    nlink: 1, parent: 1,
                });
                state.children.entry(1).or_default().push(DirChild {
                    name: format!("file{i}.txt"), inode: ino,
                });
            }
        }
        ztfs.write_encrypted_file("000001.age", b"aaa");
        ztfs.write_encrypted_file("000002.age", b"bbb");
        ztfs.write_encrypted_file("000003.age", b"ccc");
        ztfs.flush_state();

        // Simulate partial staging: re-encrypt only file 1 into staging
        let staging_dir = dir.join(".rekey_staging");
        fs::create_dir_all(&staging_dir).unwrap();
        let new_key = derive_key(new_pw);
        let old_key = derive_key(old_pw);
        let ct = fs::read(dir.join("000001.age")).unwrap();
        let pt = decrypt_bytes(&old_key, &ct).unwrap();
        let new_ct = encrypt_bytes(&new_key, &pt).unwrap();
        fs::write(staging_dir.join("000001.age"), &new_ct).unwrap();
        // Also create a lock file as if interrupted
        fs::write(dir.join("_rekey.lock"), b"99999").unwrap();

        // Verify passphrase validation works
        assert!(verify_staged_passphrase(new_pw, &dir).is_ok());
        assert!(verify_staged_passphrase("wrong-pw", &dir).is_err());

        // Resume rekey — should skip file 1, re-encrypt files 2, 3 and index
        rekey(old_pw, new_pw, &dir, true);

        // All files should now decrypt with new passphrase
        let ztfs2 = ZeroTrustFs::new(new_pw, dir.clone());
        let state = ztfs2.inner.state.lock().unwrap();
        for filename in &["000001.age", "000002.age", "000003.age"] {
            let content = ztfs2.read_encrypted_file(filename);
            assert!(!content.is_empty(), "{filename} should be readable with new key");
        }
        drop(state);

        // Old passphrase should fail
        let old_key = derive_key(old_pw);
        let index_ct = fs::read(dir.join("_index.age")).unwrap();
        assert!(decrypt_bytes(&old_key, &index_ct).is_err());

        // No artifacts
        assert!(!dir.join(".rekey_staging").exists());
        assert!(!dir.join("_rekey.manifest").exists());
        assert!(!dir.join("_rekey.lock").exists());

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn resume_rekey_wrong_passphrase() {
        let dir = PathBuf::from("target/test-resume-wrong-pw");
        let _ = fs::remove_dir_all(&dir);

        // Create a staged file encrypted with key A
        let staging_dir = dir.join(".rekey_staging");
        fs::create_dir_all(&staging_dir).unwrap();
        let key_a = derive_key("passphrase-a");
        let ct = encrypt_bytes(&key_a, b"some data").unwrap();
        fs::write(staging_dir.join("000001.age"), ct).unwrap();

        // Verify with correct passphrase succeeds
        assert!(verify_staged_passphrase("passphrase-a", &dir).is_ok());

        // Verify with wrong passphrase fails
        let result = verify_staged_passphrase("passphrase-b", &dir);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("different passphrase"));

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn fresh_rekey_wipes_stale_staging() {
        let dir = PathBuf::from("target/test-fresh-wipes-staging");
        let _ = fs::remove_dir_all(&dir);
        let old_pw = "wipe-old";
        let new_pw = "wipe-new";

        // Create filesystem with 1 file
        let ztfs = ZeroTrustFs::new(old_pw, dir.clone());
        {
            let mut state = ztfs.inner.state.lock().unwrap();
            let ino = ZeroTrustFs::allocate_inode(&mut state);
            let df = ZeroTrustFs::allocate_disk_filename(&mut state);
            state.inodes.insert(ino, InodeEntry {
                name: "file.txt".to_string(), kind: InodeKind::File,
                disk_filename: df.clone(), size: 5, perm: 0o644,
                uid: 501, gid: 20, atime_secs: 1000, mtime_secs: 1000, ctime_secs: 1000,
                nlink: 1, parent: 1,
            });
            state.children.entry(1).or_default().push(DirChild {
                name: "file.txt".to_string(), inode: ino,
            });
        }
        ztfs.write_encrypted_file("000001.age", b"data");
        ztfs.flush_state();

        // Create stale staging with a file encrypted with a DIFFERENT key
        let staging_dir = dir.join(".rekey_staging");
        fs::create_dir_all(&staging_dir).unwrap();
        let different_key = derive_key("some-other-passphrase");
        let stale_ct = encrypt_bytes(&different_key, b"stale").unwrap();
        fs::write(staging_dir.join("000001.age"), &stale_ct).unwrap();

        // Fresh rekey (resume=false) should wipe staging and succeed
        rekey(old_pw, new_pw, &dir, false);

        // Verify new passphrase works
        let ztfs2 = ZeroTrustFs::new(new_pw, dir.clone());
        let content = ztfs2.read_encrypted_file("000001.age");
        assert_eq!(content, b"data");

        // Verify stale staging is gone
        assert!(!dir.join(".rekey_staging").exists());

        let _ = fs::remove_dir_all(&dir);
    }
}
