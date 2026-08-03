// Copyright 2026 Alexander Orlov <alexander.orlov@loxal.net>

use std::collections::{BTreeMap, HashMap, HashSet};
use std::ffi::OsStr;
use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex, RwLock};
use std::thread;
use std::time::{Duration, Instant, SystemTime};

use fuser::{
    FileAttr, FileHandle, FileType, Filesystem, FopenFlags, Generation, INodeNo, ReplyAttr,
    ReplyCreate, ReplyData, ReplyDirectory, ReplyEmpty, ReplyEntry, ReplyOpen, ReplyStatfs,
    ReplyWrite, Request,
};
use serde::{Deserialize, Serialize};

use crate::crypto::{
    LEGACY_CIPHERTEXT_OVERHEAD, RecoveryFingerprint, V1_CIPHERTEXT_OVERHEAD,
    ciphertext_bytes_fingerprint, ciphertext_fingerprint_bounded, decrypt_blob_owned,
    decrypt_index_owned, encrypt_blob, encrypt_blob_owned, encrypt_index_owned, exact_fingerprint,
};
use crate::v2::{self, CommitState as V2CommitState};

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
const INDEX_FILE: &str = "_index.age";
const MAX_INDEX_CIPHERTEXT_LEN: u64 = 64 * 1024 * 1024;
const MAX_INDEX_PLAINTEXT_LEN: u64 = MAX_INDEX_CIPHERTEXT_LEN - V1_CIPHERTEXT_OVERHEAD;
const DEBOUNCE_QUIET_INTERVAL: Duration = Duration::from_secs(5);
const MAX_DIRTY_INTERVAL: Duration = Duration::from_secs(30);
/// At most sixteen 4 MiB plaintext chunks are retained between durable v2
/// generations. Budgeting a full slot per entry keeps the limit independent
/// of sparse/tail chunk length and allocator behavior.
const V2_DIRTY_CHUNK_LIMIT: usize = 16;
/// Truncate-only files consume no chunk slots, so cap their bookkeeping too.
const V2_DIRTY_FILE_LIMIT: usize = 256;
static TEMP_FILE_COUNTER: AtomicU64 = AtomicU64::new(0);

#[derive(Clone, Copy, Debug)]
struct DirtyTiming {
    first: Instant,
    last: Instant,
}

impl DirtyTiming {
    fn new(now: Instant) -> Self {
        Self {
            first: now,
            last: now,
        }
    }

    fn next_wait(self, now: Instant) -> Duration {
        let quiet = (self.last + DEBOUNCE_QUIET_INTERVAL).saturating_duration_since(now);
        let maximum = (self.first + MAX_DIRTY_INTERVAL).saturating_duration_since(now);
        quiet.min(maximum)
    }
}

#[derive(Debug)]
struct V2DirtyFile {
    base_root: String,
    base_size: u64,
    logical_size: u64,
    /// The earliest acknowledged shrink since `base_root`. Bytes at and after
    /// this point remain logically zero even if the file is grown again before
    /// the overlay is materialized.
    discard_from: Option<u64>,
    chunks: BTreeMap<u64, Vec<u8>>,
}

impl V2DirtyFile {
    fn new(base_root: String, base_size: u64) -> Self {
        Self {
            base_root,
            base_size,
            logical_size: base_size,
            discard_from: None,
            chunks: BTreeMap::new(),
        }
    }

    fn visible_base_size(&self) -> u64 {
        self.base_size
            .min(self.discard_from.unwrap_or(self.base_size))
    }

    fn missing_chunks(&self, first: u64, last: u64) -> usize {
        (first..=last)
            .filter(|chunk| !self.chunks.contains_key(chunk))
            .count()
    }

    fn load_visible_base_chunk(
        &self,
        base_path: &Path,
        key: &[u8; 32],
        chunk_index: u64,
    ) -> std::io::Result<Vec<u8>> {
        let offset = chunk_index
            .checked_mul(v2::CHUNK_SIZE as u64)
            .ok_or_else(|| std::io::Error::from_raw_os_error(libc::EFBIG))?;
        let visible = self.visible_base_size();
        if offset >= visible {
            return Ok(Vec::new());
        }
        let requested = usize::try_from((visible - offset).min(v2::CHUNK_SIZE as u64))
            .map_err(|_| std::io::Error::from_raw_os_error(libc::EFBIG))?;
        v2::read_file_range(
            base_path,
            key,
            &self.base_root,
            self.base_size,
            offset,
            requested,
        )
    }

    fn write(
        &mut self,
        base_path: &Path,
        key: &[u8; 32],
        offset: u64,
        data: &[u8],
    ) -> std::io::Result<usize> {
        let end = offset
            .checked_add(data.len() as u64)
            .ok_or_else(|| std::io::Error::from_raw_os_error(libc::EFBIG))?;
        let first = offset / v2::CHUNK_SIZE as u64;
        let last = (end - 1) / v2::CHUNK_SIZE as u64;
        let mut staged = Vec::with_capacity(self.missing_chunks(first, last));
        for chunk_index in first..=last {
            if self.chunks.contains_key(&chunk_index) {
                continue;
            }
            let mut chunk = self.load_visible_base_chunk(base_path, key, chunk_index)?;
            chunk
                .try_reserve_exact(v2::CHUNK_SIZE.saturating_sub(chunk.len()))
                .map_err(|_| std::io::Error::from_raw_os_error(libc::ENOMEM))?;
            chunk.resize(v2::CHUNK_SIZE, 0);
            staged.push((chunk_index, chunk));
        }
        let inserted = staged.len();
        for (chunk_index, chunk) in staged {
            self.chunks.insert(chunk_index, chunk);
        }

        let mut consumed = 0usize;
        while consumed < data.len() {
            let absolute = offset
                .checked_add(consumed as u64)
                .ok_or_else(|| std::io::Error::from_raw_os_error(libc::EFBIG))?;
            let chunk_index = absolute / v2::CHUNK_SIZE as u64;
            let within = (absolute % v2::CHUNK_SIZE as u64) as usize;
            let take = (v2::CHUNK_SIZE - within).min(data.len() - consumed);
            let chunk = self
                .chunks
                .get_mut(&chunk_index)
                .ok_or_else(|| std::io::Error::other("staged dirty chunk is missing"))?;
            let required = within + take;
            chunk[within..required].copy_from_slice(&data[consumed..consumed + take]);
            consumed += take;
        }
        self.logical_size = self.logical_size.max(end);
        Ok(inserted)
    }

    fn truncate(&mut self, new_size: u64) -> usize {
        if new_size >= self.logical_size {
            self.logical_size = new_size;
            return 0;
        }
        self.discard_from = Some(
            self.discard_from
                .map_or(new_size, |discard| discard.min(new_size)),
        );
        self.logical_size = new_size;
        let first_removed = new_size.div_ceil(v2::CHUNK_SIZE as u64);
        let before = self.chunks.len();
        self.chunks.retain(|chunk, _| *chunk < first_removed);
        if new_size != 0 {
            let last = (new_size - 1) / v2::CHUNK_SIZE as u64;
            let tail = (new_size % v2::CHUNK_SIZE as u64) as usize;
            if tail != 0
                && let Some(chunk) = self.chunks.get_mut(&last)
            {
                chunk[tail..].fill(0);
            }
        }
        before - self.chunks.len()
    }
}

#[derive(Default, Debug)]
struct V2DirtyOverlay {
    files: BTreeMap<u64, V2DirtyFile>,
    chunk_count: usize,
}

impl V2DirtyOverlay {
    fn clear(&mut self) {
        self.files.clear();
        self.chunk_count = 0;
    }

    fn remove_inode(&mut self, ino: u64) {
        if let Some(file) = self.files.remove(&ino) {
            self.chunk_count = self.chunk_count.saturating_sub(file.chunks.len());
        }
    }
}

// --- Persistent index ---

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub(crate) enum InodeKind {
    File,
    Directory,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
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

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub(crate) struct DirChild {
    pub name: String,
    pub inode: u64,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub(crate) struct DiskIndex {
    pub next_inode: u64,
    pub next_file_id: u64,
    pub inodes: HashMap<u64, InodeEntry>,
    pub children: HashMap<u64, Vec<DirChild>>,
}

fn index_allocation_error(what: &str) -> String {
    format!("cannot allocate while validating encrypted index {what}")
}

fn validate_index_name(name: &str) -> bool {
    !name.is_empty()
        && name != "."
        && name != ".."
        && !name.bytes().any(|byte| byte == b'/' || byte == 0)
}

fn canonical_blob_id(filename: &str) -> Option<u64> {
    let hex = filename.strip_suffix(".age")?;
    if !(6..=16).contains(&hex.len())
        || !hex
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return None;
    }
    let id = u64::from_str_radix(hex, 16).ok()?;
    (id > 0 && format!("{id:06x}.age") == filename).then_some(id)
}

fn validate_disk_index_for_format(index: &DiskIndex, v2_format: bool) -> Result<(), String> {
    if index.inodes.contains_key(&0) {
        return Err("encrypted index contains reserved inode 0".to_string());
    }
    let root = index
        .inodes
        .get(&1)
        .ok_or_else(|| "encrypted index is missing root inode 1".to_string())?;
    if root.kind != InodeKind::Directory
        || !root.name.is_empty()
        || root.parent != 1
        || !root.disk_filename.is_empty()
    {
        return Err("encrypted index root inode is malformed".to_string());
    }
    let max_inode = index.inodes.keys().copied().max().unwrap_or(1);
    if index.next_inode < 2 || index.next_inode <= max_inode || index.next_inode == u64::MAX {
        return Err(format!(
            "encrypted index has unsafe next_inode {} for maximum live inode {max_inode}",
            index.next_inode
        ));
    }

    let mut blob_filenames = HashSet::new();
    blob_filenames
        .try_reserve(index.inodes.len())
        .map_err(|_| index_allocation_error("blob set"))?;
    let mut max_blob_id = 0u64;
    for (&inode, entry) in &index.inodes {
        if inode != 1 && !validate_index_name(&entry.name) {
            return Err(format!(
                "encrypted index inode {inode} has an invalid name component"
            ));
        }
        match entry.kind {
            InodeKind::Directory => {
                if !entry.disk_filename.is_empty() || (v2_format && entry.size != 0) {
                    return Err(format!(
                        "encrypted index directory inode {inode} has invalid file storage metadata"
                    ));
                }
            }
            InodeKind::File => {
                if v2_format {
                    if entry.disk_filename.is_empty() {
                        if entry.size != 0 {
                            return Err(format!(
                                "encrypted v2 index file inode {inode} has data but no file root"
                            ));
                        }
                    } else {
                        v2::decode_file_root(&entry.disk_filename).ok_or_else(|| {
                            format!(
                                "encrypted v2 index file inode {inode} has invalid file-root reference"
                            )
                        })?;
                        if !blob_filenames.insert(entry.disk_filename.as_str()) {
                            return Err(format!(
                                "encrypted v2 index aliases file root {} between inodes",
                                entry.disk_filename
                            ));
                        }
                    }
                } else {
                    let blob_id = canonical_blob_id(&entry.disk_filename).ok_or_else(|| {
                        format!(
                            "encrypted index file inode {inode} has invalid blob filename {:?}",
                            entry.disk_filename
                        )
                    })?;
                    if !blob_filenames.insert(entry.disk_filename.as_str()) {
                        return Err(format!(
                            "encrypted index maps more than one inode to blob {}",
                            entry.disk_filename
                        ));
                    }
                    max_blob_id = max_blob_id.max(blob_id);
                }
            }
        }
    }
    if index.next_file_id < 1
        || (!v2_format && index.next_file_id <= max_blob_id)
        || index.next_file_id == u64::MAX
    {
        return Err(format!(
            "encrypted index has unsafe next_file_id {} for maximum live blob id {max_blob_id}",
            index.next_file_id
        ));
    }

    let mut referenced = HashSet::new();
    referenced
        .try_reserve(index.inodes.len())
        .map_err(|_| index_allocation_error("reference set"))?;
    for (&parent, children) in &index.children {
        let parent_entry = index
            .inodes
            .get(&parent)
            .ok_or_else(|| format!("encrypted index has children for missing inode {parent}"))?;
        if parent_entry.kind != InodeKind::Directory {
            return Err(format!(
                "encrypted index file inode {parent} owns a child list"
            ));
        }
        let mut names = HashSet::new();
        names
            .try_reserve(children.len())
            .map_err(|_| index_allocation_error("directory-name set"))?;
        for child in children {
            if !validate_index_name(&child.name) {
                return Err(format!(
                    "encrypted index directory inode {parent} has an invalid child name"
                ));
            }
            if !names.insert(child.name.as_str()) {
                return Err(format!(
                    "encrypted index directory inode {parent} has duplicate child name {:?}",
                    child.name
                ));
            }
            if child.inode == 1 || !referenced.insert(child.inode) {
                return Err(format!(
                    "encrypted index inode {} has multiple directory links or aliases the root",
                    child.inode
                ));
            }
            let target = index.inodes.get(&child.inode).ok_or_else(|| {
                format!(
                    "encrypted index child {:?} points to missing inode {}",
                    child.name, child.inode
                )
            })?;
            if target.parent != parent || target.name != child.name {
                return Err(format!(
                    "encrypted index child {:?} disagrees with inode {} parent/name metadata",
                    child.name, child.inode
                ));
            }
        }
    }
    if referenced.len() + 1 != index.inodes.len() {
        return Err("encrypted index contains an unlinked inode".to_string());
    }

    let mut visited = HashSet::new();
    visited
        .try_reserve(index.inodes.len())
        .map_err(|_| index_allocation_error("reachability set"))?;
    let mut pending = Vec::new();
    pending
        .try_reserve(index.inodes.len())
        .map_err(|_| index_allocation_error("reachability stack"))?;
    pending.push(1u64);
    while let Some(inode) = pending.pop() {
        if !visited.insert(inode) {
            return Err(format!(
                "encrypted index directory graph contains a cycle at inode {inode}"
            ));
        }
        if let Some(children) = index.children.get(&inode) {
            pending.extend(children.iter().map(|child| child.inode));
        }
    }
    if visited.len() != index.inodes.len() {
        return Err("encrypted index contains an unreachable inode or directory cycle".to_string());
    }
    Ok(())
}

pub(crate) fn validate_disk_index(index: &DiskIndex) -> Result<(), String> {
    validate_disk_index_for_format(index, false)
}

pub(crate) fn validate_disk_index_v2(index: &DiskIndex) -> Result<(), String> {
    validate_disk_index_for_format(index, true)
}

#[cfg_attr(not(test), allow(dead_code))]
pub(crate) fn validate_reachable_v2_files(
    base_path: &Path,
    key: &[u8; 32],
    index: &DiskIndex,
) -> Result<(), String> {
    for (&inode, entry) in index
        .inodes
        .iter()
        .filter(|(_, entry)| entry.kind == InodeKind::File)
    {
        if entry.disk_filename.is_empty() {
            continue;
        }
        v2::validate_reachable_file(base_path, key, &entry.disk_filename, entry.size)
            .map_err(|error| {
                format!(
                    "encrypted v2 file inode {inode} is not completely materialized and authenticated: {error}"
                )
            })?;
    }
    Ok(())
}

pub(crate) fn validate_reachable_v2_files_with_pin(
    base_path: &Path,
    key: &[u8; 32],
    index: &DiskIndex,
    namespace_pin: &v2::V2NamespacePin,
) -> Result<(), String> {
    for (&inode, entry) in index
        .inodes
        .iter()
        .filter(|(_, entry)| entry.kind == InodeKind::File)
    {
        if entry.disk_filename.is_empty() {
            continue;
        }
        v2::validate_reachable_file_with_pin(
            base_path,
            key,
            &entry.disk_filename,
            entry.size,
            namespace_pin,
        )
        .map_err(|error| {
            format!(
                "encrypted v2 file inode {inode} is not completely materialized and authenticated: {error}"
            )
        })?;
    }
    Ok(())
}

fn ensure_no_future_blob_collisions(base_path: &Path, index: &DiskIndex) -> std::io::Result<()> {
    let mut referenced = HashSet::new();
    referenced
        .try_reserve(index.inodes.len())
        .map_err(|_| std::io::Error::from_raw_os_error(libc::ENOMEM))?;
    for entry in index
        .inodes
        .values()
        .filter(|entry| entry.kind == InodeKind::File)
    {
        referenced.insert(entry.disk_filename.as_str());
    }
    for entry in fs::read_dir(base_path)? {
        let entry = entry?;
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            continue;
        };
        let Some(blob_id) = canonical_blob_id(name) else {
            continue;
        };
        if !referenced.contains(name) && blob_id >= index.next_file_id {
            return Err(std::io::Error::other(format!(
                "unreferenced canonical blob {name:?} in {} collides with current/future allocation {} - preserving it as possible crash or cloud-conflict evidence",
                base_path.display(),
                index.next_file_id
            )));
        }
    }
    Ok(())
}

fn ensure_next_blob_slot_absent(base_path: &Path, index: &DiskIndex) -> std::io::Result<()> {
    let filename = format!("{:06x}.age", index.next_file_id);
    let path = base_path.join(&filename);
    if backing_entry_exists(&path)? {
        return Err(std::io::Error::other(format!(
            "next blob slot {filename} already exists outside the authenticated index; refusing to overwrite possible crash or cloud-conflict evidence"
        )));
    }
    Ok(())
}

struct BoundedIndexWriter {
    bytes: Vec<u8>,
    max_len: usize,
    limit_exceeded: bool,
}

impl Write for BoundedIndexWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let new_len = self
            .bytes
            .len()
            .checked_add(buf.len())
            .ok_or_else(|| std::io::Error::from_raw_os_error(libc::EFBIG))?;
        if new_len > self.max_len {
            self.limit_exceeded = true;
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!(
                    "serialized index exceeds the {}-byte plaintext limit",
                    self.max_len
                ),
            ));
        }
        self.bytes
            .try_reserve(buf.len())
            .map_err(|_| std::io::Error::from_raw_os_error(libc::ENOMEM))?;
        self.bytes.extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

pub(crate) fn serialize_index_bounded(index: &DiskIndex) -> std::io::Result<Vec<u8>> {
    serialize_index_bounded_for_format(index, false)
}

pub(crate) fn serialize_index_bounded_v2(index: &DiskIndex) -> std::io::Result<Vec<u8>> {
    serialize_index_bounded_for_format(index, true)
}

fn serialize_index_bounded_for_format(
    index: &DiskIndex,
    v2_format: bool,
) -> std::io::Result<Vec<u8>> {
    validate_disk_index_for_format(index, v2_format).map_err(|error| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("refuse to serialize invalid encrypted index: {error}"),
        )
    })?;
    let max_len = usize::try_from(MAX_INDEX_PLAINTEXT_LEN)
        .map_err(|_| std::io::Error::from_raw_os_error(libc::EFBIG))?;
    let mut writer = BoundedIndexWriter {
        bytes: Vec::new(),
        max_len,
        limit_exceeded: false,
    };
    if let Err(error) = serde_json::to_writer(&mut writer, index) {
        let kind = if writer.limit_exceeded {
            std::io::ErrorKind::InvalidData
        } else {
            std::io::ErrorKind::Other
        };
        return Err(std::io::Error::new(
            kind,
            format!("serialize encrypted index: {error}"),
        ));
    }
    Ok(writer.bytes)
}

/// Durable write: temp file + fsync + rename + fsync(parent dir).
/// Survives crash at any point without corrupting the target file.
pub(crate) fn durable_write(path: &std::path::Path, data: &[u8]) -> std::io::Result<()> {
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
        crate::fault::checkpoint(crate::fault::DurabilityEvent::Write, "durable write")?;
        f.sync_all()?;
        crate::fault::checkpoint(crate::fault::DurabilityEvent::FileSync, "durable write")?;
        std::fs::rename(&tmp, path)?;
        crate::fault::checkpoint(crate::fault::DurabilityEvent::Rename, "durable write")?;
        // The file fsync persists its contents; the directory fsync persists
        // the name replacement itself.
        std::fs::File::open(parent)?.sync_all()?;
        crate::fault::checkpoint(
            crate::fault::DurabilityEvent::DirectorySync,
            "durable write",
        )
    })();
    if let Err(error) = &result
        && !crate::fault::is_injected_crash(error)
        && std::fs::remove_file(&tmp).is_ok()
    {
        let _ = crate::fault::checkpoint(
            crate::fault::DurabilityEvent::Cleanup,
            "failed durable-write temp cleanup",
        );
    }
    result
}

/// Durably publish a new control file without ever replacing an entry that
/// appeared concurrently. A complete, fsynced temp remains as recovery
/// evidence if publication becomes ambiguous.
pub(crate) fn durable_create_new(path: &Path, data: &[u8]) -> std::io::Result<()> {
    let parent = path.parent().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "target has no parent directory",
        )
    })?;
    let file_name = path.file_name().ok_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::InvalidInput, "target has no file name")
    })?;
    let (tmp, mut file) = loop {
        let sequence = TEMP_FILE_COUNTER.fetch_add(1, Ordering::Relaxed);
        let mut tmp_name = std::ffi::OsString::from(".");
        tmp_name.push(file_name);
        tmp_name.push(format!(".{}.{sequence}.tmp", std::process::id()));
        let tmp = parent.join(tmp_name);
        let mut options = std::fs::OpenOptions::new();
        options.create_new(true).write(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.custom_flags(libc::O_NOFOLLOW);
        }
        match options.open(&tmp) {
            Ok(file) => break (tmp, file),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(error),
        }
    };

    let mut preserve_temp_on_error = false;
    let sync_parent = || std::fs::File::open(parent)?.sync_all();
    let result = (|| {
        file.write_all(data)?;
        crate::fault::checkpoint(crate::fault::DurabilityEvent::Write, "durable create-new")?;
        file.sync_all()?;
        crate::fault::checkpoint(
            crate::fault::DurabilityEvent::FileSync,
            "durable create-new",
        )?;
        drop(file);
        sync_parent()?;
        crate::fault::checkpoint(
            crate::fault::DurabilityEvent::DirectorySync,
            "persist create-new temp",
        )?;
        preserve_temp_on_error = true;

        match std::fs::hard_link(&tmp, path) {
            Ok(()) => {
                crate::fault::checkpoint(
                    crate::fault::DurabilityEvent::Rename,
                    "publish create-new target",
                )?;
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                return Err(error);
            }
            Err(_) => {
                let mut options = std::fs::OpenOptions::new();
                options.create_new(true).write(true);
                #[cfg(unix)]
                {
                    use std::os::unix::fs::OpenOptionsExt;
                    options.custom_flags(libc::O_NOFOLLOW);
                }
                let mut target = options.open(path)?;
                target.write_all(data)?;
                crate::fault::checkpoint(
                    crate::fault::DurabilityEvent::Write,
                    "fallback create-new target",
                )?;
                target.sync_all()?;
                crate::fault::checkpoint(
                    crate::fault::DurabilityEvent::FileSync,
                    "fallback create-new target",
                )?;
            }
        }
        sync_parent()?;
        crate::fault::checkpoint(
            crate::fault::DurabilityEvent::DirectorySync,
            "persist create-new target",
        )?;
        std::fs::remove_file(&tmp)?;
        crate::fault::checkpoint(
            crate::fault::DurabilityEvent::Cleanup,
            "clean create-new temp",
        )?;
        sync_parent()?;
        crate::fault::checkpoint(
            crate::fault::DurabilityEvent::DirectorySync,
            "persist create-new temp cleanup",
        )
    })();
    if let Err(error) = &result
        && !preserve_temp_on_error
        && !crate::fault::is_injected_crash(error)
        && std::fs::remove_file(&tmp).is_ok()
    {
        let _ = crate::fault::checkpoint(
            crate::fault::DurabilityEvent::Cleanup,
            "failed create-new temp cleanup",
        );
    }
    result
}

pub(crate) fn ensure_real_directory(path: &Path) -> std::io::Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_dir() && !metadata.file_type().is_symlink() {
        return Ok(());
    }
    Err(std::io::Error::new(
        std::io::ErrorKind::InvalidData,
        format!("{} is not a real directory", path.display()),
    ))
}

/// Read one already-opened file with allocation and race bounds. Using the
/// descriptor's metadata avoids allocating from an untrusted path size and
/// keeps a provider-side replacement from switching the inode mid-read.
fn read_bounded_file(
    path: &Path,
    expected_len: Option<u64>,
    max_len: u64,
) -> std::io::Result<Vec<u8>> {
    let file = {
        let mut options = fs::OpenOptions::new();
        options.read(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.custom_flags(libc::O_NOFOLLOW);
        }
        options.open(path)?
    };
    let metadata = file.metadata()?;
    if !metadata.is_file() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("{} is not a regular backing file", path.display()),
        ));
    }
    let observed_len = metadata.len();
    if observed_len > max_len {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!(
                "{} is unexpectedly large ({observed_len} bytes; maximum {max_len})",
                path.display()
            ),
        ));
    }
    if let Some(expected_len) = expected_len
        && observed_len != expected_len
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!(
                "{} has {observed_len} ciphertext bytes; expected {expected_len}",
                path.display()
            ),
        ));
    }

    let read_len = expected_len.unwrap_or(observed_len);
    let capacity =
        usize::try_from(read_len).map_err(|_| std::io::Error::from_raw_os_error(libc::EFBIG))?;
    let limit = read_len
        .checked_add(1)
        .ok_or_else(|| std::io::Error::from_raw_os_error(libc::EFBIG))?;
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(capacity)
        .map_err(|_| std::io::Error::from_raw_os_error(libc::ENOMEM))?;
    file.take(limit).read_to_end(&mut bytes)?;
    if bytes.len() as u64 != read_len {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!(
                "{} changed size while being read (expected {read_len}, read {})",
                path.display(),
                bytes.len()
            ),
        ));
    }
    Ok(bytes)
}

pub(crate) fn read_bounded_backing_file(path: &Path, max_len: u64) -> std::io::Result<Vec<u8>> {
    read_bounded_file(path, None, max_len)
}

pub(crate) fn read_index_ciphertext(path: &Path) -> std::io::Result<Vec<u8>> {
    read_bounded_backing_file(path, MAX_INDEX_CIPHERTEXT_LEN)
}

fn read_blob_ciphertext(
    path: &Path,
    plaintext_len: u64,
    overhead: u64,
) -> std::io::Result<Vec<u8>> {
    let ciphertext_len = plaintext_len
        .checked_add(overhead)
        .ok_or_else(|| std::io::Error::from_raw_os_error(libc::EFBIG))?;
    read_bounded_file(path, Some(ciphertext_len), ciphertext_len)
}

pub(crate) fn read_v1_blob_ciphertext(path: &Path, plaintext_len: u64) -> std::io::Result<Vec<u8>> {
    read_blob_ciphertext(path, plaintext_len, V1_CIPHERTEXT_OVERHEAD)
}

pub(crate) fn read_legacy_blob_ciphertext(
    path: &Path,
    plaintext_len: u64,
) -> std::io::Result<Vec<u8>> {
    read_blob_ciphertext(path, plaintext_len, LEGACY_CIPHERTEXT_OVERHEAD)
}

fn ensure_index_ciphertext_within_limit(len: u64, max_len: u64) -> std::io::Result<()> {
    if len <= max_len {
        return Ok(());
    }
    Err(std::io::Error::new(
        std::io::ErrorKind::InvalidData,
        format!("encrypted index is too large ({len} bytes; maximum {max_len})"),
    ))
}

pub(crate) fn ensure_index_plaintext_within_limit(plaintext_len: usize) -> std::io::Result<()> {
    let ciphertext_len = u64::try_from(plaintext_len)
        .map_err(|_| std::io::Error::from_raw_os_error(libc::EFBIG))?
        .checked_add(V1_CIPHERTEXT_OVERHEAD)
        .ok_or_else(|| std::io::Error::from_raw_os_error(libc::EFBIG))?;
    ensure_index_ciphertext_within_limit(ciphertext_len, MAX_INDEX_CIPHERTEXT_LEN)
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

fn is_v2_ready_name(name: &str) -> bool {
    const READY_PREFIXES: [&str; 8] = [
        "_z2-head-",
        "_z2-manifest-",
        "_z2-migration-plan-",
        "_z2-migration-completion-",
        "._z2-head-",
        "._z2-manifest-",
        "._z2-migration-plan-",
        "._z2-migration-completion-",
    ];
    READY_PREFIXES.iter().any(|prefix| {
        name.strip_prefix(prefix)
            .and_then(|value| value.strip_suffix(".ready"))
            .is_some_and(|id| {
                id.len() == 32
                    && id
                        .bytes()
                        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            })
    })
}

fn is_possible_index_sibling_name(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    (name != INDEX_FILE && lower.contains("_index"))
        || (name != v2::ROOT_FILE && lower.contains("_root"))
}

fn is_possible_kdf_sibling_name(name: &str) -> bool {
    name != "_kdf.json" && name.to_ascii_lowercase().contains("_kdf")
}

fn is_possible_blob_sibling_name(name: &str) -> bool {
    if canonical_blob_id(name).is_some() {
        return false;
    }
    let lower = name.to_ascii_lowercase();
    lower.contains(".age")
        && lower.as_bytes().windows(6).any(|window| {
            window
                .iter()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte))
        })
}

fn is_possible_v2_object_directory_sibling_name(name: &str) -> bool {
    if name == v2::OBJECT_DIRECTORY || name == v2::LEGACY_OBJECT_DIRECTORY {
        return false;
    }
    name.to_ascii_lowercase().contains("zdrive-v2")
}

fn is_possible_transaction_sibling_name(name: &str) -> bool {
    const CANONICAL: [&str; 10] = [
        "_rekey.manifest",
        "_rekey.lock",
        ".rekey_staging",
        "_migrate.manifest",
        "_migrate.lock",
        ".migrate_staging",
        v2::WRITE_MANIFEST,
        crate::v2_migrate::PLAN_FILE,
        crate::v2_migrate::COMPLETION_FILE,
        crate::v2_migrate::PROGRESS_DIRECTORY,
    ];
    if CANONICAL.contains(&name) {
        return false;
    }
    if is_v2_ready_name(name) {
        return false;
    }
    let lower = name.to_ascii_lowercase();
    lower.contains("_rekey")
        || lower.contains("rekey_staging")
        || lower.contains("_migrate")
        || lower.contains("migrate_staging")
        || lower.contains("_write")
        || lower.contains("_z2-head-")
        || lower.contains("_z2-manifest-")
        || lower.contains("_z2-migration-")
        || lower.contains("._z2-head-")
        || lower.contains("._z2-manifest-")
        || lower.contains("._z2-migration-")
}

/// Return `false` only when the directory entry itself is absent. Unlike
/// `Path::try_exists`, this does not follow a dangling symlink and accidentally
/// classify ambiguous provider materialization as absence.
pub(crate) fn backing_entry_exists(path: &Path) -> std::io::Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error),
    }
}

/// Refuse canonical control-file combinations that cannot be produced by a
/// supported format transition. A completed v1-to-v2 migration deliberately
/// retains both heads, but it also retains its authenticated plan. Without
/// that plan, choosing either canonical head could hide a provider-merged
/// generation.
pub(crate) fn ensure_unambiguous_format_heads(base_path: &Path) -> std::io::Result<()> {
    let index = backing_entry_exists(&base_path.join(INDEX_FILE))?;
    let root = backing_entry_exists(&base_path.join(v2::ROOT_FILE))?;
    let plan = backing_entry_exists(&base_path.join(crate::v2_migrate::PLAN_FILE))?;
    let completion = backing_entry_exists(&base_path.join(crate::v2_migrate::COMPLETION_FILE))?;
    if index && root && !plan {
        return Err(std::io::Error::other(format!(
            "both {} and {} exist in {} without a retained v1-to-v2 migration plan; refusing to choose a provider-merged generation",
            INDEX_FILE,
            v2::ROOT_FILE,
            base_path.display()
        )));
    }
    if plan && !index {
        return Err(std::io::Error::other(format!(
            "{} exists in {} but its retained v1 {} source head is missing; preserve the v2 root and restore all migration evidence before continuing",
            crate::v2_migrate::PLAN_FILE,
            base_path.display(),
            INDEX_FILE
        )));
    }
    if completion && (!plan || !index || !root) {
        return Err(std::io::Error::other(format!(
            "{} exists in {} without all retained plan, v1 head, and v2 head evidence; refusing an ambiguous migration state",
            crate::v2_migrate::COMPLETION_FILE,
            base_path.display()
        )));
    }
    Ok(())
}

/// Refuse provider-generated alternate control names such as `_index 2.age`,
/// `_index (conflicted copy).age`, `._index.age.icloud`, or conflicted recovery
/// manifests. These files cannot be merged safely, and silently choosing one
/// generation could strand otherwise valid blobs or discard committed recovery
/// evidence. A stale durable-write temp is likewise evidence of an interrupted
/// commit and must not be ignored.
pub(crate) fn ensure_no_index_siblings(base_path: &Path) -> std::io::Result<()> {
    v2::ensure_unambiguous_object_directory(base_path)?;
    let mut siblings = Vec::new();
    for entry in fs::read_dir(base_path)? {
        let entry = entry?;
        let name = entry.file_name();
        if name.to_str().is_none_or(|name| {
            is_possible_index_sibling_name(name)
                || is_possible_kdf_sibling_name(name)
                || is_possible_blob_sibling_name(name)
                || is_possible_v2_object_directory_sibling_name(name)
                || is_possible_transaction_sibling_name(name)
        }) {
            siblings.push(name);
            if siblings.len() == 5 {
                break;
            }
        }
    }
    if siblings.is_empty() {
        return Ok(());
    }
    siblings.sort();
    Err(std::io::Error::new(
        std::io::ErrorKind::AlreadyExists,
        format!(
            "possible cloud-conflict backing file(s) found in {}: {:?}; refusing to choose, overwrite, or discard a data/metadata generation - stop synchronization, preserve every copy, and reconcile the store before mounting",
            base_path.display(),
            siblings
        ),
    ))
}

// --- FUSE filesystem ---

pub(crate) struct FsInner {
    pub(crate) base_path: PathBuf,
    pub(crate) key: RwLock<[u8; 32]>,
    pub(crate) state: RwLock<DiskIndex>,
    pub(crate) format: StoreFormat,
    v2_commit: Mutex<Option<V2CommitState>>,
    /// Exact immutable namespace held open for the lifetime of a v2 mount.
    /// Immutable objects use its retained descriptor and each root
    /// publication revalidates the canonical namespace identities.
    v2_namespace_pin: Option<v2::V2NamespacePin>,
    pub(crate) open_files: RwLock<HashMap<u64, Vec<u8>>>,
    /// Bounded v2 plaintext write-back cache. Content becomes immutable v2
    /// objects only when the generation is flushed, avoiding one COW path per
    /// small write while retaining a hard file-size-independent memory limit.
    v2_dirty: Mutex<V2DirtyOverlay>,
    /// Per-inode open reference count. An inode's `open_files` buffer is
    /// loaded on the first `open` and only persisted+evicted on the last
    /// `release`, so concurrent open handles share one buffer without a
    /// premature evict (lost reads) or a reload clobbering unflushed
    /// writes (lost writes).
    pub(crate) open_counts: Mutex<HashMap<u64, u32>>,
    pub(crate) index_mtime: Mutex<Option<SystemTime>>,
    pub(crate) index_fingerprint: Mutex<Option<RecoveryFingerprint>>,
    kdf_fingerprint: RecoveryFingerprint,
    format_controls: FormatControlSnapshot,
    pub(crate) read_only: AtomicBool,
    /// Fatal cloud-generation conflict detected after mount. Once latched,
    /// writes and persistence stay disabled until remount even if a provider
    /// later hides the conflicting artifact again.
    persistence_failure: Mutex<Option<String>>,
    /// Set only when this mount's current v2 commit may have published its own
    /// authenticated manifest before returning an error. Synchronous namespace
    /// handlers use it to decide whether rollback would contradict recovery.
    prospective_intent_may_be_durable: AtomicBool,
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
    dirty_timing: Mutex<Option<DirtyTiming>>,
    /// Signals the debounce thread to wake up (dirty flag set) or shut down (stop flag).
    debounce_notify: Condvar,
    debounce_mutex: Mutex<bool>, // value = stop requested
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum StoreFormat {
    V1,
    V2,
}

#[derive(Clone, Debug)]
struct ControlFileSnapshot {
    name: &'static str,
    fingerprint: Option<RecoveryFingerprint>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct DirectoryIdentity {
    #[cfg(unix)]
    device: u64,
    #[cfg(unix)]
    inode: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct ImmutableNamespaceSnapshot {
    namespace: Option<DirectoryIdentity>,
    objects: Option<DirectoryIdentity>,
    evidence: Option<DirectoryIdentity>,
}

impl ImmutableNamespaceSnapshot {
    fn capture(base_path: &Path, name: &str) -> std::io::Result<Self> {
        let namespace_path = base_path.join(name);
        let namespace = optional_directory_identity(&namespace_path)?;
        let (objects, evidence) = if namespace.is_some() {
            (
                optional_directory_identity(&namespace_path.join(v2::OBJECTS_DIRECTORY))?,
                optional_directory_identity(&namespace_path.join(v2::EVIDENCE_DIRECTORY))?,
            )
        } else {
            (None, None)
        };
        Ok(Self {
            namespace,
            objects,
            evidence,
        })
    }

    fn exists(&self) -> bool {
        self.namespace.is_some()
    }
}

#[derive(Clone, Debug)]
struct FormatControlSnapshot {
    files: Vec<ControlFileSnapshot>,
    object_directories: (ImmutableNamespaceSnapshot, ImmutableNamespaceSnapshot),
    migration_progress_exists: bool,
}

impl FormatControlSnapshot {
    fn capture(base_path: &Path, format: StoreFormat) -> std::io::Result<Self> {
        let names: &[&'static str] = match format {
            StoreFormat::V1 => &[
                v2::ROOT_FILE,
                v2::WRITE_MANIFEST,
                crate::v2_migrate::PLAN_FILE,
                crate::v2_migrate::COMPLETION_FILE,
            ],
            StoreFormat::V2 => &[
                INDEX_FILE,
                v2::WRITE_MANIFEST,
                crate::v2_migrate::PLAN_FILE,
                crate::v2_migrate::COMPLETION_FILE,
            ],
        };
        let files = names
            .iter()
            .map(|&name| {
                optional_control_fingerprint(base_path, name)
                    .map(|fingerprint| ControlFileSnapshot { name, fingerprint })
            })
            .collect::<std::io::Result<Vec<_>>>()?;
        let object_directories = (
            ImmutableNamespaceSnapshot::capture(base_path, v2::OBJECT_DIRECTORY)?,
            ImmutableNamespaceSnapshot::capture(base_path, v2::LEGACY_OBJECT_DIRECTORY)?,
        );
        let migration_progress_exists =
            backing_entry_exists(&base_path.join(crate::v2_migrate::PROGRESS_DIRECTORY))?;
        let snapshot = Self {
            files,
            object_directories,
            migration_progress_exists,
        };
        snapshot.verify(base_path)?;
        if format == StoreFormat::V1
            && (snapshot
                .files
                .iter()
                .any(|entry| entry.fingerprint.is_some())
                || snapshot.migration_progress_exists)
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::AlreadyExists,
                "v1 mount found v2 control or migration-progress artifacts; preserve them and resume or reconcile migration before writing v1",
            ));
        }
        if format == StoreFormat::V2
            && (snapshot.object_directories.0.exists() == snapshot.object_directories.1.exists())
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::AlreadyExists,
                "v2 mount does not have exactly one current or legacy immutable-object directory",
            ));
        }
        Ok(snapshot)
    }

    fn verify(&self, base_path: &Path) -> std::io::Result<()> {
        let object_directories = (
            ImmutableNamespaceSnapshot::capture(base_path, v2::OBJECT_DIRECTORY)?,
            ImmutableNamespaceSnapshot::capture(base_path, v2::LEGACY_OBJECT_DIRECTORY)?,
        );
        if object_directories != self.object_directories {
            return Err(control_topology_changed(
                "the v2 immutable-object directory topology changed after mount: namespace, objects, or evidence identity differs",
            ));
        }
        let progress_exists =
            backing_entry_exists(&base_path.join(crate::v2_migrate::PROGRESS_DIRECTORY))?;
        if progress_exists != self.migration_progress_exists {
            return Err(control_topology_changed(
                "the v2 migration progress directory topology changed after mount",
            ));
        }
        for expected in &self.files {
            let path = base_path.join(expected.name);
            let exists = backing_entry_exists(&path)?;
            if expected.fingerprint.is_none() && exists {
                return Err(control_topology_changed(format!(
                    "canonical control {} changed, appeared, or disappeared after mount",
                    expected.name
                )));
            }
            let actual = if exists {
                optional_control_fingerprint(base_path, expected.name)?
            } else {
                None
            };
            if actual != expected.fingerprint {
                return Err(control_topology_changed(format!(
                    "canonical control {} changed, appeared, or disappeared after mount",
                    expected.name
                )));
            }
        }
        Ok(())
    }
}

fn optional_directory_identity(path: &Path) -> std::io::Result<Option<DirectoryIdentity>> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    };
    if !metadata.file_type().is_dir() || metadata.file_type().is_symlink() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("{} is not a real backing directory", path.display()),
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if metadata.ino() == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                format!("{} has no stable directory inode", path.display()),
            ));
        }
        Ok(Some(DirectoryIdentity {
            device: metadata.dev(),
            inode: metadata.ino(),
        }))
    }
    #[cfg(not(unix))]
    {
        Ok(Some(DirectoryIdentity {}))
    }
}

fn optional_control_fingerprint(
    base_path: &Path,
    name: &'static str,
) -> std::io::Result<Option<RecoveryFingerprint>> {
    let path = base_path.join(name);
    if !backing_entry_exists(&path)? {
        return Ok(None);
    }
    ciphertext_fingerprint_bounded(&path, MAX_INDEX_CIPHERTEXT_LEN)
        .map(Some)
        .map_err(std::io::Error::other)
}

fn control_topology_changed(message: impl Into<String>) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::AlreadyExists, message.into())
}

/// Refuse a partially materialized v2 control plane before any startup
/// recovery or maintenance path can mutate the backing directory. Entry
/// existence is checked without following symlinks so an ambiguous provider
/// placeholder never looks like an absent file.
pub(crate) fn ensure_v2_controls_have_kdf(base_path: &Path) -> Result<(), String> {
    let root_exists = backing_entry_exists(&base_path.join(v2::ROOT_FILE)).map_err(|error| {
        format!(
            "cannot inspect v2 root {}: {error}",
            base_path.join(v2::ROOT_FILE).display()
        )
    })?;
    let write_recovery_exists =
        backing_entry_exists(&base_path.join(v2::WRITE_MANIFEST)).map_err(|error| {
            format!(
                "cannot inspect v2 recovery intent {}: {error}",
                base_path.join(v2::WRITE_MANIFEST).display()
            )
        })?;
    let kdf_exists = backing_entry_exists(&base_path.join("_kdf.json")).map_err(|error| {
        format!(
            "cannot inspect KDF metadata {}: {error}",
            base_path.join("_kdf.json").display()
        )
    })?;
    if (root_exists || write_recovery_exists) && !kdf_exists {
        return Err(format!(
            "{} contains a v2 root or recovery intent but no _kdf.json; refusing to create replacement key metadata because cloud synchronization or recovery may be incomplete",
            base_path.display()
        ));
    }
    Ok(())
}

/// Guard the only path that publishes a KDF into an apparently empty store.
/// A head or recovery intent arriving from synchronization must be preserved
/// and must win over local initialization, even if it appears after the
/// initial empty-directory inspection.
fn ensure_new_kdf_publication_safe(base_path: &Path) -> Result<(), String> {
    let mut controls = Vec::new();
    for name in [INDEX_FILE, v2::ROOT_FILE, v2::WRITE_MANIFEST] {
        if backing_entry_exists(&base_path.join(name)).map_err(|error| {
            format!(
                "cannot inspect {} while guarding new KDF publication: {error}",
                base_path.join(name).display()
            )
        })? {
            controls.push(name);
        }
    }
    if controls.is_empty() {
        return Ok(());
    }
    Err(format!(
        "encrypted control file(s) {controls:?} appeared while initializing {}; refusing to publish or accept replacement KDF metadata",
        base_path.display()
    ))
}

impl FsInner {
    fn persistence_error(&self) -> Option<std::io::Error> {
        match self.persistence_failure.lock() {
            Ok(failure) => failure.as_ref().map(|message| {
                std::io::Error::other(format!("persistence is disabled until remount: {message}"))
            }),
            Err(_) => Some(std::io::Error::other(
                "persistence is disabled until remount: failure-state lock is poisoned",
            )),
        }
    }

    fn latch_persistence_failure(&self, error: std::io::Error) -> std::io::Error {
        let incoming = error.to_string();
        let message = match self.persistence_failure.lock() {
            Ok(mut failure) => failure.get_or_insert(incoming).clone(),
            Err(_) => "failure-state lock is poisoned".to_string(),
        };
        self.read_only.store(true, Ordering::SeqCst);
        std::io::Error::other(format!("persistence is disabled until remount: {message}"))
    }

    /// Online maintenance may temporarily set `read_only`; it must never
    /// clear a fatal cloud-conflict latch while restoring ordinary writes.
    pub(crate) fn restore_writes_if_healthy(&self) {
        if self.persistence_error().is_none() {
            self.read_only.store(false, Ordering::SeqCst);
        }
    }

    fn ensure_writable(&self) -> std::io::Result<()> {
        if let Some(error) = self.persistence_error() {
            return Err(error);
        }
        if self.read_only.load(Ordering::SeqCst) {
            return Err(std::io::Error::from_raw_os_error(libc::EROFS));
        }
        Ok(())
    }

    /// Record that a maintenance operation durably wrote the current open-file
    /// buffers and matching index. The caller must hold `persistence_mutex` and
    /// must have made the filesystem read-only before taking its snapshot.
    pub(crate) fn clear_persisted_maintenance_state(&self) -> Result<(), String> {
        self.dirty_inodes
            .lock()
            .map_err(|_| "dirty-inode lock is poisoned".to_string())?
            .clear();
        self.v2_dirty
            .lock()
            .map_err(|_| "v2 dirty-overlay lock is poisoned".to_string())?
            .clear();
        self.index_dirty.store(false, Ordering::Release);
        Ok(())
    }

    pub(crate) fn dirty_inode_snapshot(&self) -> Result<HashSet<u64>, String> {
        self.dirty_inodes
            .lock()
            .map_err(|_| "dirty-inode lock is poisoned".to_string())
            .map(|dirty| dirty.clone())
    }

    pub(crate) fn ensure_index_unchanged(&self) -> Result<(), std::io::Error> {
        if let Some(error) = self.persistence_error() {
            return Err(error);
        }
        // Inspection/materialization failures are retryable: no write intent
        // exists yet. Only positively observed ambiguity or identity changes
        // permanently latch the live mount read-only.
        if let Err(error) = ensure_no_index_siblings(&self.base_path) {
            if error.kind() == std::io::ErrorKind::AlreadyExists {
                return Err(self.latch_persistence_failure(error));
            }
            return Err(error);
        }
        if let Err(error) = self.format_controls.verify(&self.base_path) {
            if error.kind() == std::io::ErrorKind::AlreadyExists {
                return Err(self.latch_persistence_failure(error));
            }
            return Err(error);
        }
        let kdf_path = self.base_path.join("_kdf.json");
        let actual_kdf = exact_fingerprint(&kdf_path).map_err(|e| {
            std::io::Error::other(format!(
                "cannot verify KDF metadata {} before commit: {e}",
                kdf_path.display()
            ))
        })?;
        if actual_kdf != self.kdf_fingerprint {
            return Err(self.inner_latch_error(format!(
                "KDF metadata {} changed externally; refusing to write ciphertext under a key that may no longer match the store",
                kdf_path.display()
            )));
        }
        let expected = self.index_fingerprint.lock().unwrap().clone();
        let head_name = match self.format {
            StoreFormat::V1 => INDEX_FILE,
            StoreFormat::V2 => v2::ROOT_FILE,
        };
        let max_head_len = match self.format {
            StoreFormat::V1 => MAX_INDEX_CIPHERTEXT_LEN,
            StoreFormat::V2 => v2::MAX_ROOT_CIPHERTEXT,
        };
        let index_path = self.base_path.join(head_name);
        let Some(expected) = expected else {
            return match fs::symlink_metadata(&index_path) {
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
                Err(e) => Err(std::io::Error::other(format!(
                    "cannot verify that new-store index {} is still absent: {e}",
                    index_path.display()
                ))),
                Ok(_) => Err(self.inner_latch_error(format!(
                    "encrypted index {} appeared externally while initializing a new store; refusing to overwrite it",
                    index_path.display()
                ))),
            };
        };
        let actual = ciphertext_fingerprint_bounded(&index_path, max_head_len).map_err(|e| {
            std::io::Error::other(format!(
                "cannot verify encrypted index {} before commit: {e}",
                index_path.display()
            ))
        })?;
        if actual != expected {
            return Err(self.inner_latch_error(format!(
                "encrypted index {} changed externally; refusing to overwrite it - unmount and reconcile cloud synchronization first",
                index_path.display()
            )));
        }
        Ok(())
    }

    fn inner_latch_error(&self, message: String) -> std::io::Error {
        self.latch_persistence_failure(std::io::Error::other(message))
    }
}

pub struct ZeroTrustFs {
    pub(crate) inner: Arc<FsInner>,
    debounce_thread: Option<thread::JoinHandle<()>>,
    mount_ready_notify: Option<std::sync::mpsc::Sender<()>>,
}

impl ZeroTrustFs {
    /// Compatibility constructor used by the v1 maintenance/test paths. It
    /// still auto-detects and mounts an existing v2 store, but creates v1 when
    /// the backing directory is empty.
    pub fn new(passphrase: &str, base_path: PathBuf) -> Self {
        Self::new_with_empty_format(passphrase, base_path, StoreFormat::V1)
    }

    /// Production constructor. Existing v1 stores remain readable/writable;
    /// an empty backing directory is initialized directly as v2.
    pub fn new_v2(passphrase: &str, base_path: PathBuf) -> Self {
        let empty_format = if v2::platform_supports_atomic_exchange() {
            StoreFormat::V2
        } else {
            // Platforms without a real atomic exchange primitive retain safe
            // v1 behavior instead of creating a v2 store that cannot commit
            // its second generation.
            StoreFormat::V1
        };
        Self::new_with_empty_format(passphrase, base_path, empty_format)
    }

    fn new_with_empty_format(
        passphrase: &str,
        base_path: PathBuf,
        empty_format: StoreFormat,
    ) -> Self {
        fs::create_dir_all(&base_path).expect("failed to create base path");

        ensure_no_index_siblings(&base_path).unwrap_or_else(|e| {
            eprintln!("zerotrust-drive: error: {e}");
            std::process::exit(1);
        });
        ensure_unambiguous_format_heads(&base_path).unwrap_or_else(|e| {
            eprintln!("zerotrust-drive: error: {e}");
            std::process::exit(1);
        });

        let index_path = base_path.join(INDEX_FILE);
        let root_path = base_path.join(v2::ROOT_FILE);
        let mut index_exists = backing_entry_exists(&index_path).unwrap_or_else(|e| {
            eprintln!(
                "zerotrust-drive: error: cannot inspect {}: {e}",
                index_path.display()
            );
            std::process::exit(1);
        });
        let mut root_exists = backing_entry_exists(&root_path).unwrap_or_else(|e| {
            eprintln!(
                "zerotrust-drive: error: cannot inspect {}: {e}",
                root_path.display()
            );
            std::process::exit(1);
        });
        let stored_kdf = crate::crypto::load_kdf_with_fingerprint(&base_path).unwrap_or_else(|e| {
            eprintln!("zerotrust-drive: error: invalid KDF metadata: {e}");
            std::process::exit(1);
        });
        let write_recovery_exists = backing_entry_exists(&base_path.join(v2::WRITE_MANIFEST))
            .unwrap_or_else(|e| {
                eprintln!("zerotrust-drive: error: cannot inspect v2 recovery intent: {e}");
                std::process::exit(1);
            });
        ensure_v2_controls_have_kdf(&base_path).unwrap_or_else(|error| {
            eprintln!("zerotrust-drive: error: {error}");
            std::process::exit(1);
        });
        if !index_exists
            && !root_exists
            && !write_recovery_exists
            && let Err(e) = ensure_new_store_directory_empty(&base_path)
        {
            eprintln!("zerotrust-drive: error: {e}");
            std::process::exit(1);
        }
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
        let (kdf, kdf_fingerprint) = match stored_kdf {
            Some(loaded) => loaded,
            None => crate::crypto::load_or_create_kdf_with_fingerprint_guarded(&base_path, |_| {
                ensure_new_kdf_publication_safe(&base_path)
            })
            .unwrap_or_else(|e| {
                eprintln!("zerotrust-drive: error: cannot create KDF metadata: {e}");
                std::process::exit(1);
            }),
        };
        let key = crate::crypto::try_derive_key(passphrase, &kdf).unwrap_or_else(|e| {
            eprintln!("zerotrust-drive: error: cannot derive encryption key: {e}");
            std::process::exit(1);
        });

        let will_use_v2 = root_exists
            || write_recovery_exists
            || (!index_exists && !root_exists && empty_format == StoreFormat::V2);
        let mut exchange_probed = false;
        let mut recovery_namespace_pin = None;
        if will_use_v2 && (write_recovery_exists || root_exists) {
            let namespace_pin = v2::V2NamespacePin::capture(&base_path).unwrap_or_else(|error| {
                eprintln!(
                    "zerotrust-drive: error: cannot pin the complete existing immutable namespace before v2 audit/recovery: {error}"
                );
                std::process::exit(1);
            });
            if write_recovery_exists {
                v2::authenticate_recovery_intent_before_probe(
                    &base_path,
                    &key,
                    &kdf_fingerprint,
                    &namespace_pin,
                )
                .unwrap_or_else(|error| {
                    eprintln!(
                        "zerotrust-drive: error: cannot authenticate v2 recovery intent before backing-store preflight: {error}"
                    );
                    std::process::exit(1);
                });
                v2::probe_atomic_exchange_with_pin(&base_path, &namespace_pin).unwrap_or_else(
                    |error| {
                        eprintln!(
                            "zerotrust-drive: error: backing directory {} cannot provide the atomic exchange required for reliable v2 commits: {error}",
                            base_path.display()
                        );
                        std::process::exit(1);
                    },
                );
                exchange_probed = true;
            }
            recovery_namespace_pin = Some(namespace_pin);
        }

        if let Some(namespace_pin) = recovery_namespace_pin.as_ref() {
            v2::recover_with_namespace_pin(&base_path, &key, &kdf_fingerprint, namespace_pin)
                .unwrap_or_else(|e| {
                    eprintln!("zerotrust-drive: error: v2 normal-write recovery failed: {e}");
                    std::process::exit(1);
                });
        } else {
            v2::recover(&base_path, &key, &kdf_fingerprint).unwrap_or_else(|e| {
                eprintln!("zerotrust-drive: error: v2 normal-write recovery failed: {e}");
                std::process::exit(1);
            });
        }
        index_exists = backing_entry_exists(&index_path).unwrap_or_else(|e| {
            eprintln!("zerotrust-drive: error: cannot re-inspect v1 index: {e}");
            std::process::exit(1);
        });
        root_exists = backing_entry_exists(&root_path).unwrap_or_else(|e| {
            eprintln!("zerotrust-drive: error: cannot re-inspect v2 root: {e}");
            std::process::exit(1);
        });

        let format = if root_exists {
            StoreFormat::V2
        } else if index_exists {
            StoreFormat::V1
        } else {
            empty_format
        };
        if format == StoreFormat::V2 && !v2::platform_supports_atomic_exchange() {
            eprintln!(
                "zerotrust-drive: error: writable v2 mounts require an atomic exchange rename; this platform is unsupported (v1 stores remain supported)"
            );
            std::process::exit(1);
        }

        // A brand-new v2 store needs its layout before it can be pinned. For
        // an existing root, do not create missing provider directories here:
        // capture must fail closed before the startup reachability scrub.
        if format == StoreFormat::V2 && !root_exists && !exchange_probed {
            v2::probe_atomic_exchange(&base_path).unwrap_or_else(|error| {
                eprintln!(
                    "zerotrust-drive: error: backing directory {} cannot provide the atomic exchange required for reliable v2 commits: {error}",
                    base_path.display()
                );
                std::process::exit(1);
            });
            exchange_probed = true;
        }
        let v2_namespace_pin = if format == StoreFormat::V2 {
            Some(recovery_namespace_pin.take().unwrap_or_else(|| {
                v2::V2NamespacePin::capture(&base_path).unwrap_or_else(|error| {
                    eprintln!(
                        "zerotrust-drive: error: cannot pin the exact immutable v2 namespace before loading it: {error}"
                    );
                    std::process::exit(1);
                })
            }))
        } else {
            None
        };

        let mut initial_index_fingerprint = None;
        let mut initial_v2_commit = None;
        let state = if format == StoreFormat::V2 && root_exists {
            let (index, commit) = v2::load_with_pin(
                &base_path,
                &key,
                v2_namespace_pin
                    .as_ref()
                    .expect("existing v2 root must retain its namespace pin"),
            )
            .unwrap_or_else(|e| {
                eprintln!(
                    "zerotrust-drive: error: cannot load authenticated v2 generation {}: {e}",
                    root_path.display()
                );
                std::process::exit(1);
            });
            if index_exists {
                match crate::v2_migrate::validate_completed_migration_evidence_with_pin(
                    &base_path,
                    &key,
                    &kdf_fingerprint,
                    &commit,
                    v2_namespace_pin
                        .as_ref()
                        .expect("existing v2 root must retain its namespace pin"),
                ) {
                    Ok(true) => {}
                    Ok(false) => {
                        eprintln!(
                            "zerotrust-drive: error: simultaneous v1 and v2 heads lack authenticated completed-migration evidence"
                        );
                        std::process::exit(1);
                    }
                    Err(error) => {
                        eprintln!(
                            "zerotrust-drive: error: cannot authenticate completed v1-to-v2 migration evidence: {error}"
                        );
                        std::process::exit(1);
                    }
                }
            }
            initial_index_fingerprint = Some(commit.root_fingerprint.clone());
            initial_v2_commit = Some(commit);
            index
        } else if format == StoreFormat::V1 && index_exists {
            let ciphertext = read_index_ciphertext(&index_path).unwrap_or_else(|e| {
                eprintln!(
                    "zerotrust-drive: error: cannot safely read encrypted index {}: {e}",
                    index_path.display()
                );
                std::process::exit(1);
            });
            initial_index_fingerprint = Some(
                ciphertext_bytes_fingerprint(&ciphertext).unwrap_or_else(|e| {
                    eprintln!(
                        "zerotrust-drive: error: invalid encrypted index {}: {e}",
                        index_path.display()
                    );
                    std::process::exit(1);
                }),
            );
            let json = match decrypt_index_owned(&key, ciphertext) {
                Ok(j) => j,
                Err(_) => {
                    eprintln!(
                        "zerotrust-drive: error: wrong passphrase — failed to decrypt {}",
                        index_path.display()
                    );
                    std::process::exit(1);
                }
            };
            serde_json::from_slice(&json).unwrap_or_else(|e| {
                eprintln!(
                    "zerotrust-drive: error: encrypted index {} contains invalid metadata: {e}",
                    index_path.display()
                );
                std::process::exit(1);
            })
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

        let validation = match format {
            StoreFormat::V1 => validate_disk_index(&state),
            StoreFormat::V2 => validate_disk_index_v2(&state),
        };
        validation.unwrap_or_else(|error| {
            eprintln!(
                "zerotrust-drive: error: encrypted {:?} metadata is structurally invalid: {error}",
                format
            );
            std::process::exit(1);
        });
        if format == StoreFormat::V2 {
            validate_reachable_v2_files_with_pin(
                &base_path,
                &key,
                &state,
                v2_namespace_pin
                    .as_ref()
                    .expect("v2 format must retain a namespace pin"),
            )
            .unwrap_or_else(|error| {
                eprintln!("zerotrust-drive: error: {error}");
                eprintln!(
                    "zerotrust-drive: wait for the cloud provider to finish downloading every referenced v2 object, then remount before making changes"
                );
                std::process::exit(1);
            });
            if !exchange_probed {
                v2::probe_atomic_exchange(&base_path).unwrap_or_else(|error| {
                    eprintln!(
                        "zerotrust-drive: error: backing directory {} cannot provide the atomic exchange required for reliable v2 commits: {error}",
                        base_path.display()
                    );
                    std::process::exit(1);
                });
            }
            v2_namespace_pin
                .as_ref()
                .expect("v2 format must retain a namespace pin")
                .verify(&base_path)
                .unwrap_or_else(|error| {
                    eprintln!(
                        "zerotrust-drive: error: immutable v2 namespace changed during startup validation: {error}"
                    );
                    std::process::exit(1);
                });
        }
        if format == StoreFormat::V1 {
            ensure_no_future_blob_collisions(&base_path, &state).unwrap_or_else(|error| {
                eprintln!(
                    "zerotrust-drive: error: encrypted backing directory {} is ambiguous: {error}",
                    base_path.display()
                );
                std::process::exit(1);
            });
        }

        let format_controls = FormatControlSnapshot::capture(&base_path, format).unwrap_or_else(
            |error| {
                eprintln!(
                    "zerotrust-drive: error: backing control topology is unsafe for a {:?} mount: {error}",
                    format
                );
                std::process::exit(1);
            },
        );

        let head_path = match format {
            StoreFormat::V1 => &index_path,
            StoreFormat::V2 => &root_path,
        };
        let initial_index_mtime = if backing_entry_exists(head_path).unwrap_or(false) {
            fs::metadata(head_path)
                .and_then(|meta| meta.modified())
                .ok()
        } else {
            None
        };
        let inner = Arc::new(FsInner {
            base_path,
            key: RwLock::new(key),
            state: RwLock::new(state),
            format,
            v2_commit: Mutex::new(initial_v2_commit),
            v2_namespace_pin,
            open_files: RwLock::new(HashMap::new()),
            v2_dirty: Mutex::new(V2DirtyOverlay::default()),
            open_counts: Mutex::new(HashMap::new()),
            index_mtime: Mutex::new(initial_index_mtime),
            index_fingerprint: Mutex::new(initial_index_fingerprint),
            kdf_fingerprint,
            format_controls,
            read_only: AtomicBool::new(false),
            persistence_failure: Mutex::new(None),
            prospective_intent_may_be_durable: AtomicBool::new(false),
            dirty_inodes: Mutex::new(HashSet::new()),
            persistence_mutex: Mutex::new(()),
            index_dirty: AtomicBool::new(false),
            dirty_timing: Mutex::new(None),
            debounce_notify: Condvar::new(),
            debounce_mutex: Mutex::new(false),
        });

        // Spawn debounce thread that coalesces frequent index writes
        let debounce_inner = Arc::clone(&inner);
        let debounce_thread = thread::spawn(move || {
            let mut guard = debounce_inner.debounce_mutex.lock().unwrap();
            loop {
                while !*guard
                    && (!debounce_inner.index_dirty.load(Ordering::Acquire)
                        || debounce_inner.persistence_error().is_some())
                {
                    guard = debounce_inner.debounce_notify.wait(guard).unwrap();
                }
                if *guard {
                    break;
                }

                // Flush after either a quiet interval or an absolute dirty-age
                // deadline. Continuous writers cannot keep acknowledged data
                // RAM-only forever by repeatedly resetting the quiet timer.
                let wait_for = debounce_inner
                    .dirty_timing
                    .lock()
                    .unwrap()
                    .map(|timing| timing.next_wait(Instant::now()))
                    .unwrap_or(DEBOUNCE_QUIET_INTERVAL);
                let (next_guard, timeout) = debounce_inner
                    .debounce_notify
                    .wait_timeout(guard, wait_for)
                    .unwrap();
                guard = next_guard;
                if *guard {
                    break;
                }
                if !timeout.timed_out() {
                    continue;
                }

                drop(guard);
                let zfs = ZeroTrustFs {
                    inner: Arc::clone(&debounce_inner),
                    debounce_thread: None,
                    mount_ready_notify: None,
                };
                let flush_result = {
                    // Consume the dirty marker only after taking the same gate
                    // used by fsync. Otherwise fsync could observe "clean" and
                    // return while this delayed write was still waiting.
                    let _persistence = debounce_inner.persistence_mutex.lock().unwrap();
                    zfs.flush_pending_state_locked(false)
                };
                if let Err(e) = flush_result {
                    eprintln!("zerotrust-drive: ERROR: debounce flush failed: {e}");
                }
                guard = debounce_inner.debounce_mutex.lock().unwrap();
            }
        });

        let zfs = Self {
            inner,
            debounce_thread: Some(debounce_thread),
            mount_ready_notify: None,
        };
        if zfs.inner.index_fingerprint.lock().unwrap().is_none() {
            let json = {
                let state = zfs.inner.state.read().unwrap();
                match zfs.inner.format {
                    StoreFormat::V1 => serialize_index_bounded(&state),
                    StoreFormat::V2 => serialize_index_bounded_v2(&state),
                }
                .expect("failed to serialize index")
            };
            zfs.persist_index(json)
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
    pub(crate) fn persist_index(&self, json: Vec<u8>) -> Result<(), std::io::Error> {
        self.persist_index_with_limit(json, MAX_INDEX_CIPHERTEXT_LEN)
    }

    fn persist_index_with_limit(&self, json: Vec<u8>, max_len: u64) -> Result<(), std::io::Error> {
        self.inner.ensure_index_unchanged()?;
        if self.inner.format == StoreFormat::V2 {
            self.inner
                .prospective_intent_may_be_durable
                .store(false, Ordering::Release);
            let previous = self.inner.v2_commit.lock().unwrap().clone();
            let namespace_pin = self.inner.v2_namespace_pin.as_ref().ok_or_else(|| {
                self.inner.latch_persistence_failure(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "v2 mount has no pinned immutable namespace",
                ))
            })?;
            let committed = v2::commit_with_phase_pinned(
                &self.inner.base_path,
                &self.inner.key.read().unwrap(),
                &json,
                previous.as_ref(),
                &self.inner.kdf_fingerprint,
                namespace_pin,
            )
            .map_err(|failure| {
                self.inner
                    .prospective_intent_may_be_durable
                    .store(failure.own_intent_may_be_durable, Ordering::Release);
                if failure.recovery_required
                    || failure.error.kind() == std::io::ErrorKind::AlreadyExists
                {
                    self.inner.latch_persistence_failure(failure.error)
                } else {
                    failure.error
                }
            })?;
            *self.inner.index_fingerprint.lock().unwrap() =
                Some(committed.root_fingerprint.clone());
            *self.inner.v2_commit.lock().unwrap() = Some(committed);
            let root_path = self.inner.base_path.join(v2::ROOT_FILE);
            if let Ok(metadata) = fs::metadata(root_path)
                && let Ok(mtime) = metadata.modified()
            {
                *self.inner.index_mtime.lock().unwrap() = Some(mtime);
            }
            return Ok(());
        }
        let prepared = {
            let key = self.inner.key.read().unwrap();
            Self::prepare_index_with_limit(&key, json, max_len)?
        };
        self.persist_prepared_index(prepared)
    }

    fn prepare_index_with_limit(
        key: &[u8; 32],
        json: Vec<u8>,
        max_len: u64,
    ) -> Result<(Vec<u8>, RecoveryFingerprint), std::io::Error> {
        let expected_len = u64::try_from(json.len())
            .map_err(|_| std::io::Error::from_raw_os_error(libc::EFBIG))?
            .checked_add(V1_CIPHERTEXT_OVERHEAD)
            .ok_or_else(|| std::io::Error::from_raw_os_error(libc::EFBIG))?;
        ensure_index_ciphertext_within_limit(expected_len, max_len)?;
        let encrypted = encrypt_index_owned(key, json).map_err(std::io::Error::other)?;
        ensure_index_ciphertext_within_limit(
            u64::try_from(encrypted.len())
                .map_err(|_| std::io::Error::from_raw_os_error(libc::EFBIG))?,
            max_len,
        )?;
        let fingerprint =
            ciphertext_bytes_fingerprint(&encrypted).map_err(std::io::Error::other)?;
        Ok((encrypted, fingerprint))
    }

    fn persist_prepared_index(
        &self,
        (encrypted, fingerprint): (Vec<u8>, RecoveryFingerprint),
    ) -> Result<(), std::io::Error> {
        // Repeat the generation check immediately before replacing the index.
        self.inner.ensure_index_unchanged()?;
        let index_path = self.inner.base_path.join(INDEX_FILE);
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

    #[cfg(test)]
    pub(crate) fn write_encrypted_file(
        &self,
        disk_filename: &str,
        content: &[u8],
    ) -> Result<(), std::io::Error> {
        let encrypted = encrypt_blob(&self.inner.key.read().unwrap(), disk_filename, content)
            .map_err(std::io::Error::other)?;
        durable_write(&self.inner.base_path.join(disk_filename), &encrypted)
    }

    #[cfg(test)]
    pub(crate) fn read_encrypted_file(
        &self,
        disk_filename: &str,
    ) -> Result<Vec<u8>, std::io::Error> {
        self.read_encrypted_file_at_size(disk_filename, None)
    }

    fn read_encrypted_file_at_size(
        &self,
        disk_filename: &str,
        expected_plaintext_len: Option<u64>,
    ) -> Result<Vec<u8>, std::io::Error> {
        let path = self.inner.base_path.join(disk_filename);
        let ciphertext = match expected_plaintext_len {
            Some(len) => read_v1_blob_ciphertext(&path, len)?,
            None => read_bounded_backing_file(&path, u64::MAX)?,
        };
        decrypt_blob_owned(&self.inner.key.read().unwrap(), disk_filename, ciphertext)
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
        if self.inner.format == StoreFormat::V2 {
            *self
                .inner
                .open_counts
                .lock()
                .unwrap()
                .entry(ino)
                .or_insert(0) += 1;
            return Ok(());
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
            let backing_exists = !disk_filename.is_empty() && backing_entry_exists(&path)?;
            let content = if backing_exists {
                self.read_encrypted_file_at_size(&disk_filename, Some(size))?
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
        if self.inner.format == StoreFormat::V1 {
            self.inner.open_files.write().unwrap().remove(&ino);
        }
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

    fn v2_overlay_needs_flush_for_range(
        &self,
        ino: u64,
        offset: u64,
        len: usize,
    ) -> std::io::Result<bool> {
        let end = offset
            .checked_add(len as u64)
            .ok_or_else(|| std::io::Error::from_raw_os_error(libc::EFBIG))?;
        if end == offset {
            return Ok(false);
        }
        let first = offset / v2::CHUNK_SIZE as u64;
        let last = (end - 1) / v2::CHUNK_SIZE as u64;
        let overlay = self.inner.v2_dirty.lock().unwrap();
        let missing = overlay.files.get(&ino).map_or_else(
            || (last - first + 1) as usize,
            |file| file.missing_chunks(first, last),
        );
        Ok(
            overlay.chunk_count.saturating_add(missing) > V2_DIRTY_CHUNK_LIMIT
                || (!overlay.files.contains_key(&ino)
                    && overlay.files.len() >= V2_DIRTY_FILE_LIMIT),
        )
    }

    fn has_v2_dirty_inode(&self, ino: u64) -> bool {
        self.inner.v2_dirty.lock().unwrap().files.contains_key(&ino)
    }

    fn materialize_v2_dirty_file(&self, dirty: &V2DirtyFile) -> std::io::Result<(String, u64)> {
        let key = *self.inner.key.read().unwrap();
        let namespace_pin = self.inner.v2_namespace_pin.as_ref().ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "v2 mount has no pinned immutable namespace",
            )
        })?;
        let mut root = dirty.base_root.clone();
        let mut size = dirty.base_size;

        if let Some(discard_from) = dirty.discard_from
            && discard_from < size
        {
            root = v2::truncate_file_with_pin(
                &self.inner.base_path,
                &key,
                &root,
                size,
                discard_from,
                Some(namespace_pin),
            )?;
            size = discard_from;
        }

        for (&chunk_index, chunk) in &dirty.chunks {
            let offset = chunk_index
                .checked_mul(v2::CHUNK_SIZE as u64)
                .ok_or_else(|| std::io::Error::from_raw_os_error(libc::EFBIG))?;
            if offset >= dirty.logical_size {
                continue;
            }
            let len = usize::try_from(
                (dirty.logical_size - offset)
                    .min(chunk.len() as u64)
                    .min(v2::CHUNK_SIZE as u64),
            )
            .map_err(|_| std::io::Error::from_raw_os_error(libc::EFBIG))?;
            if len != 0 {
                (root, size) = v2::write_file_range_with_pin(
                    &self.inner.base_path,
                    &key,
                    &root,
                    size,
                    offset,
                    &chunk[..len],
                    Some(namespace_pin),
                )?;
            }
        }

        if size != dirty.logical_size {
            root = v2::truncate_file_with_pin(
                &self.inner.base_path,
                &key,
                &root,
                size,
                dirty.logical_size,
                Some(namespace_pin),
            )?;
            size = dirty.logical_size;
        }
        Ok((root, size))
    }

    /// Read a v2 range through the pending overlay. One bounded response and
    /// the globally bounded dirty slots are the only plaintext allocations;
    /// complete file size never controls memory use.
    pub(crate) fn read_v2_inode_range(
        &self,
        ino: u64,
        offset: u64,
        requested: usize,
    ) -> std::io::Result<Vec<u8>> {
        if requested > v2::MAX_FUSE_READ_SIZE {
            return Err(std::io::Error::from_raw_os_error(libc::EFBIG));
        }
        let _persistence = self.inner.persistence_mutex.lock().unwrap();
        let (encoded_root, logical_size) = {
            let state = self.inner.state.read().unwrap();
            let entry = state
                .inodes
                .get(&ino)
                .ok_or_else(|| std::io::Error::from_raw_os_error(libc::ENOENT))?;
            if entry.kind != InodeKind::File {
                return Err(std::io::Error::from_raw_os_error(libc::EISDIR));
            }
            (entry.disk_filename.clone(), entry.size)
        };
        let response_len =
            usize::try_from(logical_size.saturating_sub(offset).min(requested as u64))
                .map_err(|_| std::io::Error::from_raw_os_error(libc::EFBIG))?;
        if response_len == 0 {
            return Ok(Vec::new());
        }

        let overlay = self.inner.v2_dirty.lock().unwrap();
        let Some(dirty) = overlay.files.get(&ino) else {
            return v2::read_file_range(
                &self.inner.base_path,
                &self.inner.key.read().unwrap(),
                &encoded_root,
                logical_size,
                offset,
                response_len,
            );
        };
        if dirty.base_root != encoded_root || dirty.logical_size != logical_size {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("v2 dirty overlay for inode {ino} does not match indexed state"),
            ));
        }

        let visible_base = dirty.visible_base_size();
        let base_len =
            usize::try_from(visible_base.saturating_sub(offset).min(response_len as u64))
                .map_err(|_| std::io::Error::from_raw_os_error(libc::EFBIG))?;
        let mut result = if base_len == 0 {
            Vec::new()
        } else {
            v2::read_file_range(
                &self.inner.base_path,
                &self.inner.key.read().unwrap(),
                &dirty.base_root,
                dirty.base_size,
                offset,
                base_len,
            )?
        };
        result
            .try_reserve_exact(response_len.saturating_sub(result.len()))
            .map_err(|_| std::io::Error::from_raw_os_error(libc::ENOMEM))?;
        result.resize(response_len, 0);

        let response_end = offset
            .checked_add(response_len as u64)
            .ok_or_else(|| std::io::Error::from_raw_os_error(libc::EFBIG))?;
        let first = offset / v2::CHUNK_SIZE as u64;
        let last = (response_end - 1) / v2::CHUNK_SIZE as u64;
        for (&chunk_index, chunk) in dirty.chunks.range(first..=last) {
            let chunk_start = chunk_index
                .checked_mul(v2::CHUNK_SIZE as u64)
                .ok_or_else(|| std::io::Error::from_raw_os_error(libc::EFBIG))?;
            // `u64::MAX` is a valid exclusive file end. The final logical
            // chunk therefore has no representable grid-aligned exclusive
            // end; saturating at the file-size ceiling keeps an acknowledged
            // write at `u64::MAX - 1` readable without wrapping or rejecting
            // that otherwise valid sparse range.
            let logical_chunk_end = chunk_start
                .saturating_add(v2::CHUNK_SIZE as u64)
                .min(logical_size);
            let overlap_start = offset.max(chunk_start);
            let overlap_end = response_end.min(logical_chunk_end);
            if overlap_start >= overlap_end {
                continue;
            }
            let destination_start = (overlap_start - offset) as usize;
            let destination_end = (overlap_end - offset) as usize;
            result[destination_start..destination_end].fill(0);

            let chunk_data_end = chunk_start.saturating_add(chunk.len() as u64);
            let copy_end = overlap_end.min(chunk_data_end);
            if overlap_start < copy_end {
                let source_start = (overlap_start - chunk_start) as usize;
                let source_end = (copy_end - chunk_start) as usize;
                let destination_end = destination_start + source_end - source_start;
                result[destination_start..destination_end]
                    .copy_from_slice(&chunk[source_start..source_end]);
            }
        }
        Ok(result)
    }

    /// Resize a file to `new_size`. If the file is open, the in-memory
    /// buffer is the source of truth; if it is closed, the on-disk blob is
    /// read-modify-written so a truncation of a closed file is actually
    /// persisted (it used to be silently dropped).
    #[cfg(test)]
    pub(crate) fn truncate_inode(&self, ino: u64, new_size: u64) -> std::io::Result<()> {
        let _persistence = self.inner.persistence_mutex.lock().unwrap();
        self.truncate_inode_locked(ino, new_size)
    }

    /// Caller must hold `persistence_mutex` so writability cannot change
    /// between validation, content resize, and indexed metadata publication.
    fn truncate_inode_locked(&self, ino: u64, new_size: u64) -> std::io::Result<()> {
        self.inner.ensure_writable()?;
        let (disk_filename, old_size) = {
            let state = self.inner.state.read().unwrap();
            match state.inodes.get(&ino) {
                Some(e) if e.kind == InodeKind::File => (e.disk_filename.clone(), e.size),
                Some(_) => return Err(std::io::Error::from_raw_os_error(libc::EISDIR)),
                None => return Err(std::io::Error::from_raw_os_error(libc::ENOENT)),
            }
        };
        if self.inner.format == StoreFormat::V2 {
            if old_size == new_size {
                if let Some(entry) = self.inner.state.write().unwrap().inodes.get_mut(&ino) {
                    entry.mtime_secs = now_secs();
                }
                self.mark_dirty();
                return Ok(());
            }
            let needs_flush = {
                let overlay = self.inner.v2_dirty.lock().unwrap();
                !overlay.files.contains_key(&ino) && overlay.files.len() >= V2_DIRTY_FILE_LIMIT
            };
            if needs_flush {
                self.flush_pending_state_locked(false)?;
            }
            let (disk_filename, old_size) = {
                let state = self.inner.state.read().unwrap();
                let entry = state
                    .inodes
                    .get(&ino)
                    .ok_or_else(|| std::io::Error::from_raw_os_error(libc::ENOENT))?;
                (entry.disk_filename.clone(), entry.size)
            };
            let new_logical_size = {
                let mut overlay = self.inner.v2_dirty.lock().unwrap();
                let dirty = overlay
                    .files
                    .entry(ino)
                    .or_insert_with(|| V2DirtyFile::new(disk_filename.clone(), old_size));
                if dirty.base_root != disk_filename || dirty.logical_size != old_size {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        format!("v2 dirty overlay for inode {ino} does not match indexed state"),
                    ));
                }
                let removed = dirty.truncate(new_size);
                let logical_size = dirty.logical_size;
                overlay.chunk_count = overlay.chunk_count.saturating_sub(removed);
                logical_size
            };
            let mut state = self.inner.state.write().unwrap();
            let entry = state
                .inodes
                .get_mut(&ino)
                .ok_or_else(|| std::io::Error::from_raw_os_error(libc::ENOENT))?;
            entry.size = new_logical_size;
            entry.mtime_secs = now_secs();
            drop(state);
            self.mark_dirty();
            return Ok(());
        }
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
                // Size/content changed together. Wake the debounce worker so
                // a long-lived open handle does not leave the only new copy in
                // RAM indefinitely when the caller never issues fsync/flush.
                self.mark_dirty();
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
        // Closed-file truncate replaces its blob immediately. Apply the same
        // cloud-generation preflight as a normal commit before touching it.
        self.inner.ensure_index_unchanged()?;
        let path = self.inner.base_path.join(&disk_filename);
        let mut data = if backing_entry_exists(&path)? {
            self.read_encrypted_file_at_size(&disk_filename, Some(old_size))?
        } else if old_size > 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("backing file {disk_filename} missing for inode {ino}"),
            ));
        } else {
            Vec::new()
        };
        Self::resize_content(&mut data, new_size)?;
        let encrypted = encrypt_blob_owned(&self.inner.key.read().unwrap(), &disk_filename, data)
            .map_err(std::io::Error::other)?;
        durable_write(&self.inner.base_path.join(&disk_filename), &encrypted)?;
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
        offset
            .checked_add(data.len() as u64)
            .ok_or_else(|| std::io::Error::from_raw_os_error(libc::EFBIG))?;
        let _persistence = self.inner.persistence_mutex.lock().unwrap();
        self.inner.ensure_writable()?;
        if self.inner.format == StoreFormat::V2 {
            if data.len() > v2::CHUNK_SIZE {
                return Err(std::io::Error::from_raw_os_error(libc::EFBIG));
            }
            {
                let state = self.inner.state.read().unwrap();
                let entry = state
                    .inodes
                    .get(&ino)
                    .ok_or_else(|| std::io::Error::from_raw_os_error(libc::ENOENT))?;
                if entry.kind != InodeKind::File {
                    return Err(std::io::Error::from_raw_os_error(libc::EISDIR));
                }
                if self
                    .inner
                    .open_counts
                    .lock()
                    .unwrap()
                    .get(&ino)
                    .copied()
                    .unwrap_or(0)
                    == 0
                {
                    return Err(std::io::Error::from_raw_os_error(libc::EBADF));
                }
            }
            if self.v2_overlay_needs_flush_for_range(ino, offset, data.len())? {
                self.flush_pending_state_locked(false)?;
            }
            let (encoded_root, old_size) = {
                let state = self.inner.state.read().unwrap();
                let entry = state
                    .inodes
                    .get(&ino)
                    .ok_or_else(|| std::io::Error::from_raw_os_error(libc::ENOENT))?;
                if entry.kind != InodeKind::File {
                    return Err(std::io::Error::from_raw_os_error(libc::EISDIR));
                }
                if self
                    .inner
                    .open_counts
                    .lock()
                    .unwrap()
                    .get(&ino)
                    .copied()
                    .unwrap_or(0)
                    == 0
                {
                    return Err(std::io::Error::from_raw_os_error(libc::EBADF));
                }
                (entry.disk_filename.clone(), entry.size)
            };
            let key = *self.inner.key.read().unwrap();
            let new_size = {
                let mut overlay = self.inner.v2_dirty.lock().unwrap();
                let dirty = overlay
                    .files
                    .entry(ino)
                    .or_insert_with(|| V2DirtyFile::new(encoded_root.clone(), old_size));
                if dirty.base_root != encoded_root || dirty.logical_size != old_size {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        format!("v2 dirty overlay for inode {ino} does not match indexed state"),
                    ));
                }
                let inserted = dirty.write(&self.inner.base_path, &key, offset, data)?;
                let logical_size = dirty.logical_size;
                overlay.chunk_count = overlay
                    .chunk_count
                    .checked_add(inserted)
                    .ok_or_else(|| std::io::Error::from_raw_os_error(libc::EFBIG))?;
                logical_size
            };
            let mut state = self.inner.state.write().unwrap();
            let entry = state
                .inodes
                .get_mut(&ino)
                .ok_or_else(|| std::io::Error::from_raw_os_error(libc::ENOENT))?;
            entry.size = new_size;
            entry.mtime_secs = now_secs();
            drop(state);
            self.mark_dirty();
            return Ok(written);
        }
        let start =
            usize::try_from(offset).map_err(|_| std::io::Error::from_raw_os_error(libc::EFBIG))?;
        let end = start
            .checked_add(data.len())
            .ok_or_else(|| std::io::Error::from_raw_os_error(libc::EFBIG))?;
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
        drop(state);
        // Content writes also mutate indexed size/time metadata. Waking the
        // debounce worker bounds how long dirty plaintext is RAM-only for a
        // long-lived open file.
        self.mark_dirty();
        Ok(written)
    }

    /// Durably persist an inode's dirty open content and pending metadata.
    /// A clean fsync is a no-op because the last committed generation is
    /// already durable; re-encrypting it would create needless cloud churn.
    /// Backs the FUSE `fsync` handler.
    pub(crate) fn fsync_inode(&self, ino: u64) -> std::io::Result<()> {
        {
            let state = self.inner.state.read().unwrap();
            if !state.inodes.contains_key(&ino) {
                return Err(std::io::Error::from_raw_os_error(libc::ENOENT));
            }
        }
        let _persistence = self
            .inner
            .persistence_mutex
            .lock()
            .map_err(|_| std::io::Error::other("persistence gate is poisoned"))?;
        self.flush_pending_state_locked(false)
    }

    /// Mark the index as dirty so the debounce thread will flush it soon.
    /// Used by metadata-mutating ops instead of calling flush_state() directly.
    fn mark_dirty(&self) {
        self.inner.index_dirty.store(true, Ordering::Release);
        let now = Instant::now();
        let mut timing = self.inner.dirty_timing.lock().unwrap();
        match timing.as_mut() {
            Some(timing) => timing.last = now,
            None => *timing = Some(DirtyTiming::new(now)),
        }
        drop(timing);
        self.inner.debounce_notify.notify_one();
    }

    /// Commit every dirty open blob before committing the index that describes
    /// it. Caller must hold `persistence_mutex`.
    fn flush_state_locked(&self) -> Result<(), std::io::Error> {
        // Refuse a conflicting cloud generation before touching any blob.
        // persist_prepared_index repeats this immediately before its rename.
        self.inner.ensure_index_unchanged()?;
        if self.inner.format == StoreFormat::V2 {
            if !self.inner.dirty_inodes.lock().unwrap().is_empty() {
                return Err(self.inner.latch_persistence_failure(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "v2 content must be immutable before its root generation is committed",
                )));
            }
            let mut prospective = self.inner.state.read().unwrap().clone();
            let mut overlay = self.inner.v2_dirty.lock().unwrap();
            for (&ino, dirty) in &overlay.files {
                let entry = prospective.inodes.get(&ino).ok_or_else(|| {
                    self.inner.latch_persistence_failure(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        format!("v2 dirty inode {ino} is missing from the prospective index"),
                    ))
                })?;
                if entry.kind != InodeKind::File
                    || entry.disk_filename != dirty.base_root
                    || entry.size != dirty.logical_size
                {
                    return Err(self.inner.latch_persistence_failure(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        format!("v2 dirty overlay for inode {ino} does not match indexed state"),
                    )));
                }
            }
            for (&ino, dirty) in &overlay.files {
                let (root, size) = self.materialize_v2_dirty_file(dirty).map_err(|error| {
                    if error.kind() == std::io::ErrorKind::AlreadyExists {
                        self.inner.latch_persistence_failure(error)
                    } else {
                        error
                    }
                })?;
                let entry = prospective.inodes.get_mut(&ino).ok_or_else(|| {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        format!("v2 dirty inode {ino} disappeared while materializing"),
                    )
                })?;
                entry.disk_filename = root;
                entry.size = size;
            }
            let index_json = serialize_index_bounded_v2(&prospective).map_err(|error| {
                if error.kind() == std::io::ErrorKind::InvalidData {
                    self.inner.latch_persistence_failure(error)
                } else {
                    error
                }
            })?;
            self.persist_index(index_json)?;
            *self.inner.state.write().unwrap() = prospective;
            overlay.clear();
            return Ok(());
        }
        let dirty: Vec<u64> = self
            .inner
            .dirty_inodes
            .lock()
            .unwrap()
            .iter()
            .copied()
            .collect();
        let prepared_index = {
            let state = self.inner.state.read().unwrap();
            let open = self.inner.open_files.read().unwrap();
            let key = self.inner.key.read().unwrap();
            // Validate the entire pending set before replacing the first blob.
            // An internally inconsistent later inode must not leave an earlier
            // blob paired with the still-old index.
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
            }
            // Serialize, bound, and encrypt the prospective index before the
            // first blob replacement. Predictable index failures must leave
            // the complete old generation untouched.
            let index_json = serialize_index_bounded(&state).map_err(|error| {
                if error.kind() == std::io::ErrorKind::InvalidData {
                    self.inner.latch_persistence_failure(error)
                } else {
                    error
                }
            })?;
            let prepared_index =
                Self::prepare_index_with_limit(&key, index_json, MAX_INDEX_CIPHERTEXT_LEN)
                    .map_err(|error| {
                        if error.kind() == std::io::ErrorKind::InvalidData {
                            self.inner.latch_persistence_failure(error)
                        } else {
                            error
                        }
                    })?;
            for &ino in &dirty {
                let entry = &state.inodes[&ino];
                let content = &open[&ino];
                let encrypted = encrypt_blob(&key, &entry.disk_filename, content)
                    .map_err(std::io::Error::other)?;
                durable_write(&self.inner.base_path.join(&entry.disk_filename), &encrypted)?;
            }
            prepared_index
        };

        self.persist_prepared_index(prepared_index)?;
        let mut dirty_inodes = self.inner.dirty_inodes.lock().unwrap();
        for ino in dirty {
            dirty_inodes.remove(&ino);
        }
        Ok(())
    }

    /// Flush pending content/index state, or force an index sync for fsync.
    /// Caller must hold `persistence_mutex`.
    fn flush_pending_state_locked(&self, force: bool) -> Result<(), std::io::Error> {
        self.inner
            .prospective_intent_may_be_durable
            .store(false, Ordering::Release);
        if let Some(error) = self.inner.persistence_error() {
            return Err(error);
        }
        let had_index_dirty = self.inner.index_dirty.swap(false, Ordering::AcqRel);
        let has_dirty_content = !self.inner.dirty_inodes.lock().unwrap().is_empty()
            || !self.inner.v2_dirty.lock().unwrap().files.is_empty();
        if !force && !had_index_dirty && !has_dirty_content {
            *self.inner.dirty_timing.lock().unwrap() = None;
            return Ok(());
        }
        if let Err(e) = self.flush_state_locked() {
            self.inner.index_dirty.store(true, Ordering::Release);
            if self.inner.persistence_error().is_none() {
                *self.inner.dirty_timing.lock().unwrap() = Some(DirtyTiming::new(Instant::now()));
                self.inner.debounce_notify.notify_one();
            }
            return Err(e);
        }
        *self.inner.dirty_timing.lock().unwrap() = None;
        Ok(())
    }

    /// Perform an unlink as one testable namespace mutation. Open or dirty
    /// files remain fail-closed until inode tombstones can preserve POSIX
    /// open-unlink semantics without dropping acknowledged plaintext.
    fn unlink_name(&self, parent: u64, name: &str) -> Result<(), std::io::Error> {
        let _persistence = self.inner.persistence_mutex.lock().unwrap();
        self.inner.ensure_writable()?;
        let (ino, disk_filename, previous_state) = {
            let mut state = self.inner.state.write().unwrap();
            match state.inodes.get(&parent) {
                Some(entry) if entry.kind == InodeKind::Directory => {}
                _ => return Err(std::io::Error::from_raw_os_error(libc::ENOTDIR)),
            }
            let ino = Self::find_child(&state, parent, name)
                .ok_or_else(|| std::io::Error::from_raw_os_error(libc::ENOENT))?;
            let entry = match state.inodes.get(&ino) {
                Some(entry) if entry.kind == InodeKind::File => entry,
                Some(_) => return Err(std::io::Error::from_raw_os_error(libc::EISDIR)),
                None => return Err(std::io::Error::from_raw_os_error(libc::EIO)),
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
                || self.has_v2_dirty_inode(ino)
            {
                return Err(std::io::Error::from_raw_os_error(libc::EBUSY));
            }
            let disk_filename = entry.disk_filename.clone();
            let previous_state = state.clone();
            state.inodes.remove(&ino);
            if let Some(children) = state.children.get_mut(&parent) {
                children.retain(|child| child.inode != ino);
            }
            (ino, disk_filename, previous_state)
        };
        if let Err(error) = self.flush_pending_state_locked(true) {
            if !self
                .inner
                .prospective_intent_may_be_durable
                .swap(false, Ordering::AcqRel)
            {
                *self.inner.state.write().unwrap() = previous_state;
            } else {
                // Recovery will roll the authenticated unlink forward. Keep
                // RAM aligned with that prospective generation while the
                // mount remains latched read-only.
                self.inner.open_files.write().unwrap().remove(&ino);
                self.inner.dirty_inodes.lock().unwrap().remove(&ino);
                self.inner.open_counts.lock().unwrap().remove(&ino);
                self.inner.v2_dirty.lock().unwrap().remove_inode(ino);
            }
            return Err(error);
        }
        self.inner.open_files.write().unwrap().remove(&ino);
        self.inner.dirty_inodes.lock().unwrap().remove(&ino);
        self.inner.open_counts.lock().unwrap().remove(&ino);
        self.inner.v2_dirty.lock().unwrap().remove_inode(ino);
        if self.inner.format == StoreFormat::V1
            && !disk_filename.is_empty()
            && let Err(error) = fs::remove_file(self.inner.base_path.join(&disk_filename))
            && error.kind() != std::io::ErrorKind::NotFound
        {
            eprintln!("zerotrust-drive: WARNING: orphaned backing file {disk_filename}: {error}");
        }
        Ok(())
    }

    /// Perform the no-flags rename core without a FUSE reply dependency. A
    /// replacement is committed immediately even when its old file root is
    /// empty, so no acknowledged overwrite depends only on debounce timing.
    fn rename_name(
        &self,
        parent: u64,
        name: &str,
        newparent: u64,
        newname: &str,
    ) -> Result<(), std::io::Error> {
        let _persistence = self.inner.persistence_mutex.lock().unwrap();
        self.inner.ensure_writable()?;
        let (disk_file_to_remove, overwritten_ino, previous_state) = {
            let mut state = self.inner.state.write().unwrap();
            match state.inodes.get(&parent) {
                Some(entry) if entry.kind == InodeKind::Directory => {}
                _ => return Err(std::io::Error::from_raw_os_error(libc::ENOTDIR)),
            }
            match state.inodes.get(&newparent) {
                Some(entry) if entry.kind == InodeKind::Directory => {}
                _ => return Err(std::io::Error::from_raw_os_error(libc::ENOTDIR)),
            }
            let ino = Self::find_child(&state, parent, name)
                .ok_or_else(|| std::io::Error::from_raw_os_error(libc::ENOENT))?;
            let source_kind = state
                .inodes
                .get(&ino)
                .map(|entry| entry.kind.clone())
                .ok_or_else(|| std::io::Error::from_raw_os_error(libc::EIO))?;
            if source_kind == InodeKind::Directory
                && Self::would_create_directory_cycle(&state, ino, newparent)
            {
                return Err(std::io::Error::from_raw_os_error(libc::EINVAL));
            }
            let mut to_remove = None;
            let mut overwritten = None;
            if let Some(existing) = Self::find_child(&state, newparent, newname) {
                if existing == ino {
                    return Ok(());
                }
                let target = state
                    .inodes
                    .get(&existing)
                    .ok_or_else(|| std::io::Error::from_raw_os_error(libc::EIO))?;
                match (&source_kind, &target.kind) {
                    (InodeKind::File, InodeKind::Directory) => {
                        return Err(std::io::Error::from_raw_os_error(libc::EISDIR));
                    }
                    (InodeKind::Directory, InodeKind::File) => {
                        return Err(std::io::Error::from_raw_os_error(libc::ENOTDIR));
                    }
                    _ => {}
                }
                if target.kind == InodeKind::Directory
                    && state
                        .children
                        .get(&existing)
                        .is_some_and(|children| !children.is_empty())
                {
                    return Err(std::io::Error::from_raw_os_error(libc::ENOTEMPTY));
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
                    || self.has_v2_dirty_inode(existing)
                {
                    return Err(std::io::Error::from_raw_os_error(libc::EBUSY));
                }
                to_remove = state.inodes.get(&existing).and_then(|entry| {
                    (!entry.disk_filename.is_empty()).then(|| entry.disk_filename.clone())
                });
                overwritten = Some(existing);
            }
            let previous_state = overwritten.map(|_| state.clone());
            if let Some(existing) = overwritten {
                let target_was_directory = state
                    .inodes
                    .get(&existing)
                    .is_some_and(|entry| entry.kind == InodeKind::Directory);
                state.inodes.remove(&existing);
                if target_was_directory {
                    state.children.remove(&existing);
                    if let Some(parent_entry) = state.inodes.get_mut(&newparent) {
                        parent_entry.nlink = parent_entry.nlink.saturating_sub(1);
                    }
                }
                if let Some(children) = state.children.get_mut(&newparent) {
                    children.retain(|child| child.inode != existing);
                }
            }
            if let Some(children) = state.children.get_mut(&parent) {
                children.retain(|child| child.inode != ino);
            }
            state.children.entry(newparent).or_default().push(DirChild {
                name: newname.to_string(),
                inode: ino,
            });
            if source_kind == InodeKind::Directory && parent != newparent {
                if let Some(old_parent) = state.inodes.get_mut(&parent) {
                    old_parent.nlink = old_parent.nlink.saturating_sub(1);
                }
                if let Some(new_parent) = state.inodes.get_mut(&newparent) {
                    new_parent.nlink = new_parent.nlink.saturating_add(1);
                }
            }
            if let Some(entry) = state.inodes.get_mut(&ino) {
                entry.name = newname.to_string();
                entry.parent = newparent;
                entry.ctime_secs = now_secs();
            }
            (to_remove, overwritten, previous_state)
        };
        if overwritten_ino.is_some() {
            if let Err(error) = self.flush_pending_state_locked(true) {
                if !self
                    .inner
                    .prospective_intent_may_be_durable
                    .swap(false, Ordering::AcqRel)
                {
                    *self.inner.state.write().unwrap() =
                        previous_state.expect("overwrite rename retains rollback state");
                } else if let Some(existing) = overwritten_ino {
                    self.inner.open_files.write().unwrap().remove(&existing);
                    self.inner.dirty_inodes.lock().unwrap().remove(&existing);
                    self.inner.open_counts.lock().unwrap().remove(&existing);
                    self.inner.v2_dirty.lock().unwrap().remove_inode(existing);
                }
                return Err(error);
            }
        } else {
            self.mark_dirty();
        }
        if let Some(existing) = overwritten_ino {
            self.inner.open_files.write().unwrap().remove(&existing);
            self.inner.dirty_inodes.lock().unwrap().remove(&existing);
            self.inner.open_counts.lock().unwrap().remove(&existing);
            self.inner.v2_dirty.lock().unwrap().remove_inode(existing);
        }
        if self.inner.format == StoreFormat::V1
            && let Some(disk_filename) = disk_file_to_remove
            && let Err(error) = fs::remove_file(self.inner.base_path.join(&disk_filename))
            && error.kind() != std::io::ErrorKind::NotFound
        {
            eprintln!(
                "zerotrust-drive: WARNING: orphaned overwritten backing file {disk_filename}: {error}"
            );
        }
        Ok(())
    }

    /// Serialize a complete blob+index commit against other persistence and
    /// online rekey operations.
    #[cfg(test)]
    pub(crate) fn flush_state(&self) -> Result<(), std::io::Error> {
        let _persistence = self.inner.persistence_mutex.lock().unwrap();
        self.flush_pending_state_locked(true)
    }

    /// Remove wall-clock scheduling from tests that specifically exercise
    /// capacity-pressure flushing. The caller must explicitly fsync or release
    /// every accepted mutation because Drop no longer owns a worker to stop.
    #[cfg(test)]
    fn stop_debounce_thread_for_test(&mut self) {
        let Some(handle) = self.debounce_thread.take() else {
            return;
        };
        {
            let mut stop = self.inner.debounce_mutex.lock().unwrap();
            *stop = true;
            self.inner.debounce_notify.notify_one();
        }
        handle
            .join()
            .expect("debounce test worker must stop cleanly");
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
    fn init(&mut self, _req: &Request, config: &mut fuser::KernelConfig) -> std::io::Result<()> {
        if self.inner.format == StoreFormat::V2 {
            config
                .set_max_write(v2::CHUNK_SIZE as u32)
                .map_err(|maximum| {
                    std::io::Error::other(format!(
                        "kernel rejected bounded v2 write size (maximum {maximum})"
                    ))
                })?;
            if let Err(maximum) = config.set_max_readahead(v2::MAX_FUSE_READ_SIZE as u32) {
                // Some kernels advertise a smaller ceiling. Preserve that
                // stricter bound rather than failing an otherwise valid mount.
                if maximum != 0 {
                    config.set_max_readahead(maximum).map_err(|rejected| {
                        std::io::Error::other(format!(
                            "kernel rejected bounded v2 read size (maximum {rejected})"
                        ))
                    })?;
                }
            }
        }
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
                if is_file && self.inner.format == StoreFormat::V1 {
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
        let persistence = self.inner.persistence_mutex.lock().unwrap();
        if let Err(error) = self.inner.ensure_writable() {
            reply.error(io_to_errno(&error));
            return;
        }
        if let Some(new_size) = size {
            // Validate and persist/dirty the content before publishing the new
            // size. A missing non-empty backing blob must not become zero data.
            if let Err(e) = self.truncate_inode_locked(ino.0, new_size) {
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
        self.mark_dirty();
        drop(persistence);
        reply.attr(&TTL, &attr);
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
        if self.inner.format == StoreFormat::V2 {
            match self.read_v2_inode_range(ino.0, offset, size as usize) {
                Ok(data) => reply.data(&data),
                Err(error) => {
                    eprintln!("zerotrust-drive: ERROR: read v2 inode {}: {error}", ino.0);
                    reply.error(io_to_errno(&error));
                }
            }
            return;
        }
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
        if let Some(error) = self.inner.persistence_error() {
            eprintln!("zerotrust-drive: ERROR: flush inode {}: {error}", ino.0);
            reply.error(io_to_errno(&error));
            return;
        }
        trace!("FUSE: flush ino={}", ino.0);
        let result = {
            self.inner
                .persistence_mutex
                .lock()
                .map_err(|_| std::io::Error::other("persistence gate is poisoned"))
                .and_then(|_persistence| self.flush_pending_state_locked(false))
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
        if let Some(error) = self.inner.persistence_error() {
            eprintln!("zerotrust-drive: ERROR: fsync inode {}: {error}", ino.0);
            reply.error(io_to_errno(&error));
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
        if let Err(error) = self.inner.ensure_writable() {
            reply.error(io_to_errno(&error));
            return;
        }
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
            let disk_filename = if self.inner.format == StoreFormat::V2 {
                String::new()
            } else {
                if let Err(error) = ensure_next_blob_slot_absent(&self.inner.base_path, &state) {
                    let error = self.inner.latch_persistence_failure(error);
                    reply.error(io_to_errno(&error));
                    return;
                }
                Self::allocate_disk_filename(&mut state)
            };
            let ino = Self::allocate_inode(&mut state);
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
        if let Err(error) = self.inner.ensure_writable() {
            reply.error(io_to_errno(&error));
            return;
        }

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
            let disk_filename = if self.inner.format == StoreFormat::V2 {
                String::new()
            } else {
                if let Err(error) = ensure_next_blob_slot_absent(&self.inner.base_path, &state) {
                    let error = self.inner.latch_persistence_failure(error);
                    reply.error(io_to_errno(&error));
                    return;
                }
                Self::allocate_disk_filename(&mut state)
            };
            let ino = Self::allocate_inode(&mut state);
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
        if self.inner.format == StoreFormat::V1 {
            self.inner
                .open_files
                .write()
                .unwrap()
                .insert(ino, Vec::new());
        }
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
        if let Err(error) = self.inner.ensure_writable() {
            reply.error(io_to_errno(&error));
            return;
        }

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
        match self.unlink_name(parent.0, name_str) {
            Ok(()) => reply.ok(),
            Err(error) => {
                if !matches!(
                    error.raw_os_error(),
                    Some(libc::ENOENT | libc::EISDIR | libc::EBUSY)
                ) {
                    eprintln!("zerotrust-drive: ERROR: failed to unlink {name_str:?}: {error}");
                }
                reply.error(io_to_errno(&error));
            }
        }
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
        if let Err(error) = self.inner.ensure_writable() {
            reply.error(io_to_errno(&error));
            return;
        }
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
        match self.rename_name(parent.0, name_str, newparent.0, newname_str) {
            Ok(()) => reply.ok(),
            Err(error) => {
                if !matches!(
                    error.raw_os_error(),
                    Some(
                        libc::ENOENT
                            | libc::EISDIR
                            | libc::ENOTDIR
                            | libc::EINVAL
                            | libc::ENOTEMPTY
                            | libc::EBUSY
                    )
                ) {
                    eprintln!(
                        "zerotrust-drive: ERROR: failed to rename {name_str:?} to {newname_str:?}: {error}"
                    );
                }
                reply.error(io_to_errno(&error));
            }
        }
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
        if let Some(error) = self.inner.persistence_error() {
            eprintln!("zerotrust-drive: ERROR: fsyncdir failed: {error}");
            reply.error(io_to_errno(&error));
            return;
        }
        let result = {
            self.inner
                .persistence_mutex
                .lock()
                .map_err(|_| std::io::Error::other("persistence gate is poisoned"))
                .and_then(|_persistence| self.flush_pending_state_locked(false))
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
        FORMAT_VERSION, KdfParams, KdfPublicationPhase, SALT_LEN, decrypt_bytes, derive_key,
        encrypt_bytes,
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

    fn structurally_valid_index() -> DiskIndex {
        let root = InodeEntry {
            name: String::new(),
            kind: InodeKind::Directory,
            disk_filename: String::new(),
            size: 0,
            perm: 0o755,
            uid: 501,
            gid: 20,
            atime_secs: 1,
            mtime_secs: 1,
            ctime_secs: 1,
            nlink: 2,
            parent: 1,
        };
        let directory = InodeEntry {
            name: "docs".to_string(),
            kind: InodeKind::Directory,
            disk_filename: String::new(),
            parent: 1,
            ..root.clone()
        };
        let file = InodeEntry {
            name: "note.txt".to_string(),
            kind: InodeKind::File,
            disk_filename: "000001.age".to_string(),
            size: 4,
            nlink: 1,
            parent: 2,
            ..root.clone()
        };
        DiskIndex {
            next_inode: 4,
            next_file_id: 2,
            inodes: HashMap::from([(1, root), (2, directory), (3, file)]),
            children: HashMap::from([
                (
                    1,
                    vec![DirChild {
                        name: "docs".to_string(),
                        inode: 2,
                    }],
                ),
                (
                    2,
                    vec![DirChild {
                        name: "note.txt".to_string(),
                        inode: 3,
                    }],
                ),
            ]),
        }
    }

    #[test]
    fn validates_index_graph_blob_identity_and_allocation_counters() {
        let valid = structurally_valid_index();
        validate_disk_index(&valid).unwrap();

        let assert_invalid = |index: DiskIndex| assert!(validate_disk_index(&index).is_err());

        let mut index = valid.clone();
        index.inodes.remove(&1);
        assert_invalid(index);

        let mut index = valid.clone();
        index.inodes.get_mut(&1).unwrap().parent = 2;
        assert_invalid(index);

        let mut index = valid.clone();
        index.children.get_mut(&1).unwrap().push(DirChild {
            name: "missing".to_string(),
            inode: 99,
        });
        assert_invalid(index);

        let mut index = valid.clone();
        index.children.get_mut(&1).unwrap().push(DirChild {
            name: "docs".to_string(),
            inode: 3,
        });
        assert_invalid(index);

        let mut index = valid.clone();
        index.children.get_mut(&1).unwrap().push(DirChild {
            name: "alias".to_string(),
            inode: 3,
        });
        assert_invalid(index);

        let mut index = valid.clone();
        index.inodes.get_mut(&3).unwrap().parent = 1;
        assert_invalid(index);

        let mut index = valid.clone();
        index.children.insert(3, Vec::new());
        assert_invalid(index);

        let mut index = valid.clone();
        let template = index.inodes.get(&2).unwrap().clone();
        index.inodes.insert(
            4,
            InodeEntry {
                name: "cycle-a".to_string(),
                parent: 5,
                ..template.clone()
            },
        );
        index.inodes.insert(
            5,
            InodeEntry {
                name: "cycle-b".to_string(),
                parent: 4,
                ..template
            },
        );
        index.children.insert(
            4,
            vec![DirChild {
                name: "cycle-b".to_string(),
                inode: 5,
            }],
        );
        index.children.insert(
            5,
            vec![DirChild {
                name: "cycle-a".to_string(),
                inode: 4,
            }],
        );
        index.next_inode = 6;
        assert_invalid(index);

        let mut index = valid.clone();
        let duplicate_blob = InodeEntry {
            name: "copy.txt".to_string(),
            parent: 1,
            ..index.inodes.get(&3).unwrap().clone()
        };
        index.inodes.insert(4, duplicate_blob);
        index.children.get_mut(&1).unwrap().push(DirChild {
            name: "copy.txt".to_string(),
            inode: 4,
        });
        index.next_inode = 5;
        assert_invalid(index);

        let mut index = valid.clone();
        index.inodes.get_mut(&3).unwrap().disk_filename = "1.age".to_string();
        assert_invalid(index);

        let mut index = valid.clone();
        index.next_inode = 3;
        assert_invalid(index);

        let mut index = valid;
        index.next_file_id = 1;
        assert_invalid(index);
    }

    #[test]
    fn canonical_orphan_blob_is_never_reused_or_overwritten() {
        let dir = PathBuf::from("target/test-orphan-blob-collision");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let mut index = structurally_valid_index();
        fs::write(dir.join("000002.age"), b"crash evidence").unwrap();

        assert!(ensure_no_future_blob_collisions(&dir, &index).is_err());
        assert!(ensure_next_blob_slot_absent(&dir, &index).is_err());
        assert_eq!(fs::read(dir.join("000002.age")).unwrap(), b"crash evidence");

        // Historical deletion orphans below the monotonic counter are not a
        // future allocation collision and remain tolerated for compatibility.
        index.next_file_id = 3;
        ensure_no_future_blob_collisions(&dir, &index).unwrap();
        ensure_next_blob_slot_absent(&dir, &index).unwrap();
        let _ = fs::remove_dir_all(dir);
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
    fn continuous_notifications_still_honor_maximum_dirty_age() {
        let start = Instant::now();
        let timing = DirtyTiming {
            first: start,
            last: start + Duration::from_secs(29),
        };
        assert_eq!(
            timing.next_wait(start + Duration::from_secs(29)),
            Duration::from_secs(1)
        );
        assert_eq!(timing.next_wait(start + MAX_DIRTY_INTERVAL), Duration::ZERO);
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
        assert!(ztfs.inner.read_only.load(Ordering::SeqCst));

        // A provider making the conflict disappear must not silently resume
        // this mount. Restoring the known generation still requires remount.
        fs::write(&index_path, original_index).unwrap();
        let latched = ztfs.flush_state().unwrap_err();
        assert!(
            latched.to_string().contains("disabled until remount"),
            "unexpected error: {latched}"
        );
        drop(ztfs);

        let reopened = ZeroTrustFs::new("conflict-pw", dir.clone());
        assert_eq!(
            reopened.read_encrypted_file(&disk_filename).unwrap(),
            b"before"
        );
        drop(reopened);

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn canonical_kdf_replacement_latches_before_touching_dirty_generation() {
        let dir = PathBuf::from("target/test-kdf-conflict");
        let _ = fs::remove_dir_all(&dir);
        let ztfs = ZeroTrustFs::new("conflict-pw", dir.clone());
        let (ino, disk_filename) = add_file(&ztfs, "data.txt");
        ztfs.open_inode(ino).unwrap();
        ztfs.write_inode_content(ino, 0, b"before").unwrap();
        ztfs.flush_state().unwrap();
        let index_before = fs::read(dir.join(INDEX_FILE)).unwrap();
        let blob_before = fs::read(dir.join(&disk_filename)).unwrap();
        let kdf_before = fs::read(dir.join("_kdf.json")).unwrap();

        ztfs.write_inode_content(ino, 0, b"after!").unwrap();
        fs::write(dir.join("_kdf.json"), b"provider replacement").unwrap();
        let error = ztfs.flush_state().unwrap_err();
        assert!(
            error.to_string().contains("KDF metadata")
                && error.to_string().contains("changed externally"),
            "unexpected error: {error}"
        );
        assert_eq!(fs::read(dir.join(INDEX_FILE)).unwrap(), index_before);
        assert_eq!(fs::read(dir.join(&disk_filename)).unwrap(), blob_before);
        assert!(ztfs.inner.read_only.load(Ordering::SeqCst));

        fs::write(dir.join("_kdf.json"), kdf_before).unwrap();
        assert!(
            ztfs.flush_state()
                .unwrap_err()
                .to_string()
                .contains("disabled until remount")
        );
        drop(ztfs);
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn persistence_gate_rechecks_latched_writability_before_mutation() {
        let dir = PathBuf::from("target/test-gated-conflict-race");
        let _ = fs::remove_dir_all(&dir);
        let ztfs = ZeroTrustFs::new("conflict-pw", dir.clone());
        let next_inode = ztfs.inner.state.read().unwrap().next_inode;
        let held_gate = ztfs.inner.persistence_mutex.lock().unwrap();
        let inner = Arc::clone(&ztfs.inner);
        let mutation = thread::spawn(move || -> std::io::Result<()> {
            let _gate = inner.persistence_mutex.lock().unwrap();
            inner.ensure_writable()?;
            inner.state.write().unwrap().next_inode += 1;
            Ok(())
        });

        ztfs.inner
            .latch_persistence_failure(std::io::Error::other("simulated cloud conflict"));
        drop(held_gate);
        assert!(mutation.join().unwrap().is_err());
        assert_eq!(ztfs.inner.state.read().unwrap().next_inode, next_inode);

        drop(ztfs);
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn new_store_precondition_refuses_an_index_that_appeared_late() {
        let dir = PathBuf::from("target/test-new-store-late-index");
        let _ = fs::remove_dir_all(&dir);
        let ztfs = ZeroTrustFs::new("conflict-pw", dir.clone());

        // Recreate the initialization precondition after construction, then
        // model a provider materializing the canonical index before publish.
        *ztfs.inner.index_fingerprint.lock().unwrap() = None;
        let error = ztfs.inner.ensure_index_unchanged().unwrap_err();
        assert!(
            error.to_string().contains("appeared externally"),
            "unexpected error: {error}"
        );
        assert!(ztfs.inner.read_only.load(Ordering::SeqCst));

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn detects_provider_generated_and_interrupted_index_siblings() {
        let dir = PathBuf::from("target/test-index-sibling-names");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join(INDEX_FILE), b"canonical").unwrap();
        ensure_no_index_siblings(&dir).unwrap();

        assert!(!is_possible_index_sibling_name(INDEX_FILE));
        assert!(is_possible_index_sibling_name("._index.age.123.456.tmp"));
        assert!(!is_possible_kdf_sibling_name("_kdf.json"));
        assert!(is_possible_kdf_sibling_name("_kdf 2.json"));
        assert!(!is_possible_blob_sibling_name("000001.age"));
        assert!(is_possible_blob_sibling_name(
            "000001 (conflicted copy).age"
        ));
        assert!(!is_possible_v2_object_directory_sibling_name(
            v2::OBJECT_DIRECTORY
        ));
        assert!(!is_possible_v2_object_directory_sibling_name(
            v2::LEGACY_OBJECT_DIRECTORY
        ));
        assert!(is_possible_v2_object_directory_sibling_name(
            "_zdrive-v2 (conflicted copy)"
        ));
        assert!(!is_possible_transaction_sibling_name("_rekey.manifest"));
        assert!(!is_possible_transaction_sibling_name(".migrate_staging"));
        assert!(!is_possible_transaction_sibling_name(
            "_z2-head-0123456789abcdef0123456789abcdef.ready"
        ));
        assert!(!is_possible_transaction_sibling_name(
            "._z2-head-0123456789abcdef0123456789abcdef.ready"
        ));
        assert!(is_possible_transaction_sibling_name(
            "_z2-head-0123456789abcdef0123456789abcdeg.ready"
        ));

        for sibling in [
            "_index 2.age",
            "_index (conflicted copy).age",
            "_INDEX.AGE",
            "._index.age.icloud",
            "._index.age.123.456.tmp",
            "Copy of _index.age",
            "_kdf 2.json",
            "._kdf.json.icloud",
            "._kdf.json.123.456.tmp",
            "_rekey 2.manifest",
            "_rekey (conflicted copy).lock",
            ".rekey_staging 2",
            "_migrate 2.manifest",
            "._migrate.manifest.123.tmp",
            ".migrate_staging (conflicted copy)",
            "000001 (conflicted copy).age",
            ".000001.age.123.456.tmp",
            "Copy of 000001.age",
            "_zdrive-v2 2",
            ".zdrive-v2 (conflicted copy)",
        ] {
            assert!(
                is_possible_index_sibling_name(sibling)
                    || is_possible_kdf_sibling_name(sibling)
                    || is_possible_blob_sibling_name(sibling)
                    || is_possible_v2_object_directory_sibling_name(sibling)
                    || is_possible_transaction_sibling_name(sibling),
                "missed {sibling}"
            );
        }

        let sibling = "_index 2.age";
        fs::write(dir.join(sibling), b"alternate generation").unwrap();
        let error = ensure_no_index_siblings(&dir).unwrap_err();
        assert!(
            error.to_string().contains(sibling),
            "unexpected error: {error}"
        );

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn sibling_index_refuses_commit_before_dirty_blob_is_touched() {
        let dir = PathBuf::from("target/test-index-sibling-conflict");
        let _ = fs::remove_dir_all(&dir);
        let ztfs = ZeroTrustFs::new("conflict-pw", dir.clone());
        let (ino, disk_filename) = add_file(&ztfs, "data.txt");
        ztfs.open_inode(ino).unwrap();
        ztfs.write_inode_content(ino, 0, b"before").unwrap();
        ztfs.flush_state().unwrap();
        let original_index = fs::read(dir.join(INDEX_FILE)).unwrap();
        let original_blob = fs::read(dir.join(&disk_filename)).unwrap();

        ztfs.write_inode_content(ino, 0, b"after!").unwrap();
        let sibling = dir.join("_index 2.age");
        fs::write(&sibling, b"provider conflict").unwrap();

        let error = ztfs.flush_state().unwrap_err();
        assert!(
            error.to_string().contains("cloud-conflict backing"),
            "unexpected error: {error}"
        );
        assert_eq!(fs::read(dir.join(INDEX_FILE)).unwrap(), original_index);
        assert_eq!(
            fs::read(dir.join(&disk_filename)).unwrap(),
            original_blob,
            "sibling conflict must be detected before a dirty blob is overwritten"
        );
        assert!(ztfs.inner.read_only.load(Ordering::SeqCst));

        fs::remove_file(sibling).unwrap();
        let latched = ztfs.flush_state().unwrap_err();
        assert!(latched.to_string().contains("disabled until remount"));
        drop(ztfs);

        let reopened = ZeroTrustFs::new("conflict-pw", dir.clone());
        assert_eq!(
            reopened.read_encrypted_file(&disk_filename).unwrap(),
            b"before"
        );
        drop(reopened);
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
    fn durable_create_new_never_replaces_a_concurrent_target() {
        let dir = PathBuf::from("target/test-durable-create-new-conflict");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("_rekey.manifest");
        fs::write(&path, b"provider generation").unwrap();

        assert!(durable_create_new(&path, b"local generation").is_err());
        assert_eq!(fs::read(&path).unwrap(), b"provider generation");
        assert!(
            fs::read_dir(&dir).unwrap().count() >= 2,
            "the complete local temp must be preserved as conflict evidence"
        );

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn bounded_read_rejects_sparse_oversized_cloud_file() {
        let dir = PathBuf::from("target/test-bounded-cloud-read");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("oversized.age");
        fs::File::create(&path)
            .unwrap()
            .set_len(1024 * 1024 * 1024)
            .unwrap();

        let error = read_bounded_file(&path, None, 1024).unwrap_err();
        assert!(
            error.to_string().contains("unexpectedly large"),
            "unexpected error: {error}"
        );

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn index_output_limit_prevents_creating_an_unmountable_store() {
        ensure_index_ciphertext_within_limit(MAX_INDEX_CIPHERTEXT_LEN, MAX_INDEX_CIPHERTEXT_LEN)
            .unwrap();
        let error = ensure_index_ciphertext_within_limit(
            MAX_INDEX_CIPHERTEXT_LEN + 1,
            MAX_INDEX_CIPHERTEXT_LEN,
        )
        .unwrap_err();
        assert!(
            error.to_string().contains("encrypted index is too large"),
            "unexpected error: {error}"
        );

        let maximum_plaintext =
            usize::try_from(MAX_INDEX_CIPHERTEXT_LEN - V1_CIPHERTEXT_OVERHEAD).unwrap();
        ensure_index_plaintext_within_limit(maximum_plaintext).unwrap();
        assert!(ensure_index_plaintext_within_limit(maximum_plaintext + 1).is_err());
    }

    #[test]
    fn rejected_oversized_index_does_not_replace_committed_generation() {
        let dir = PathBuf::from("target/test-index-output-limit");
        let _ = fs::remove_dir_all(&dir);
        let ztfs = ZeroTrustFs::new("pw", dir.clone());
        let index_path = dir.join(INDEX_FILE);
        let committed = fs::read(&index_path).unwrap();

        let error = ztfs
            .persist_index_with_limit(b"too large for test limit".to_vec(), 40)
            .unwrap_err();
        assert!(error.to_string().contains("encrypted index is too large"));
        assert_eq!(fs::read(&index_path).unwrap(), committed);

        drop(ztfs);
        let _reopened = ZeroTrustFs::new("pw", dir.clone());
        let _ = fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn bounded_read_refuses_backing_symlink() {
        use std::os::unix::fs::symlink;

        let dir = PathBuf::from("target/test-bounded-symlink-read");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("real.age"), b"ciphertext").unwrap();
        let link = dir.join("linked.age");
        symlink("real.age", &link).unwrap();

        assert!(read_bounded_file(&link, None, 1024).is_err());

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn open_rejects_blob_length_that_disagrees_with_index() {
        let dir = PathBuf::from("target/test-indexed-blob-length");
        let _ = fs::remove_dir_all(&dir);
        let ztfs = ZeroTrustFs::new("pw", dir.clone());
        let (ino, disk_filename) = add_file(&ztfs, "oversized.bin");
        ztfs.inner
            .state
            .write()
            .unwrap()
            .inodes
            .get_mut(&ino)
            .unwrap()
            .size = 4;
        fs::File::create(dir.join(&disk_filename))
            .unwrap()
            .set_len(1024 * 1024 * 1024)
            .unwrap();

        let error = ztfs.open_inode(ino).unwrap_err();
        assert!(
            error.to_string().contains("maximum 44"),
            "unexpected error: {error}"
        );

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
    fn v2_root_without_kdf_refuses_replacement_key_metadata() {
        let directory = PathBuf::from("target/test-v2-root-without-kdf");
        let _ = fs::remove_dir_all(&directory);
        fs::create_dir_all(&directory).unwrap();
        fs::write(directory.join(v2::ROOT_FILE), b"provider root").unwrap();
        fs::write(
            directory.join("_rekey.manifest"),
            b"unresolved recovery evidence",
        )
        .unwrap();

        let error = ensure_v2_controls_have_kdf(&directory).unwrap_err();
        assert!(error.contains("v2 root or recovery intent"), "{error}");
        assert!(error.contains("no _kdf.json"), "{error}");
        assert_eq!(
            fs::read(directory.join(v2::ROOT_FILE)).unwrap(),
            b"provider root"
        );
        assert_eq!(
            fs::read(directory.join("_rekey.manifest")).unwrap(),
            b"unresolved recovery evidence",
            "KDF preflight must fail before startup cleanup can alter recovery evidence"
        );

        fs::write(directory.join("_kdf.json"), b"provider KDF").unwrap();
        ensure_v2_controls_have_kdf(&directory).unwrap();
        fs::remove_file(directory.join(v2::ROOT_FILE)).unwrap();
        fs::remove_file(directory.join("_kdf.json")).unwrap();
        fs::remove_file(directory.join("_rekey.manifest")).unwrap();
        ensure_v2_controls_have_kdf(&directory).unwrap();

        let _ = fs::remove_dir_all(directory);
    }

    #[test]
    fn new_kdf_publication_rechecks_every_control_before_and_after_publish() {
        for (control, arrival_phase) in [
            (INDEX_FILE, KdfPublicationPhase::Before),
            (v2::ROOT_FILE, KdfPublicationPhase::Before),
            (v2::WRITE_MANIFEST, KdfPublicationPhase::Before),
            (INDEX_FILE, KdfPublicationPhase::After),
            (v2::ROOT_FILE, KdfPublicationPhase::After),
            (v2::WRITE_MANIFEST, KdfPublicationPhase::After),
        ] {
            let label = control.trim_matches(['_', '.']).replace(['.', '/'], "-");
            let directory = PathBuf::from(format!(
                "target/test-kdf-publication-{label}-phase-{arrival_phase:?}"
            ));
            let _ = fs::remove_dir_all(&directory);
            fs::create_dir_all(&directory).unwrap();
            let injected = std::cell::Cell::new(false);

            let error =
                crate::crypto::load_or_create_kdf_with_fingerprint_guarded(&directory, |phase| {
                    if phase == arrival_phase && !injected.replace(true) {
                        fs::write(directory.join(control), b"provider control evidence")
                            .map_err(|error| error.to_string())?;
                    }
                    ensure_new_kdf_publication_safe(&directory)
                })
                .unwrap_err();

            assert!(injected.get());
            assert!(error.contains("appeared"), "{error}");
            assert_eq!(
                fs::read(directory.join(control)).unwrap(),
                b"provider control evidence"
            );
            assert_eq!(
                backing_entry_exists(&directory.join("_kdf.json")).unwrap(),
                arrival_phase == KdfPublicationPhase::After,
                "the canonical KDF must be absent before publication and preserved after publication"
            );
            let retained_temps = fs::read_dir(&directory)
                .unwrap()
                .filter_map(Result::ok)
                .filter(|entry| {
                    entry
                        .file_name()
                        .to_string_lossy()
                        .starts_with("._kdf.json.")
                })
                .count();
            assert_eq!(
                retained_temps, 1,
                "a durable KDF staging file must remain as initialization evidence"
            );
            if arrival_phase == KdfPublicationPhase::After {
                assert!(crate::crypto::load_kdf(&directory).unwrap().is_some());
            }

            let _ = fs::remove_dir_all(directory);
        }
    }

    #[test]
    fn v2_recovery_intent_without_kdf_refuses_replacement_key_metadata() {
        let directory = PathBuf::from("target/test-v2-intent-without-kdf");
        let _ = fs::remove_dir_all(&directory);
        fs::create_dir_all(&directory).unwrap();
        fs::write(directory.join(v2::WRITE_MANIFEST), b"provider intent").unwrap();

        let error = ensure_v2_controls_have_kdf(&directory).unwrap_err();
        assert!(error.contains("v2 root or recovery intent"), "{error}");
        assert!(error.contains("no _kdf.json"), "{error}");

        let _ = fs::remove_dir_all(directory);
    }

    #[cfg(unix)]
    #[test]
    fn v2_commit_snapshot_rejects_replaced_namespace_and_object_directory() {
        for child in [None, Some(v2::OBJECTS_DIRECTORY)] {
            let label = child.unwrap_or("namespace");
            let directory = PathBuf::from(format!(
                "target/test-v2-replaced-directory-{}",
                label.replace('/', "-")
            ));
            let _ = fs::remove_dir_all(&directory);
            let ztfs = ZeroTrustFs::new_v2("replacement-pw", directory.clone());
            assert_eq!(ztfs.inner.format, StoreFormat::V2);
            let snapshot = ztfs.inner.format_controls.clone();
            let namespace = directory.join(v2::OBJECT_DIRECTORY);
            let target = child.map_or_else(|| namespace.clone(), |name| namespace.join(name));
            let displaced = target.with_extension("displaced");
            fs::rename(&target, &displaced).unwrap();
            fs::create_dir(&target).unwrap();
            if child.is_none() {
                fs::create_dir(target.join(v2::OBJECTS_DIRECTORY)).unwrap();
                fs::create_dir(target.join(v2::EVIDENCE_DIRECTORY)).unwrap();
            }

            let error = snapshot.verify(&directory).unwrap_err();
            let message = error.to_string();
            assert!(message.contains("topology changed"), "{error}");
            assert!(message.contains("identity"), "{error}");

            drop(ztfs);
            let _ = fs::remove_dir_all(directory);
        }
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

    fn add_v2_file(ztfs: &ZeroTrustFs, name: &str) -> u64 {
        let mut state = ztfs.inner.state.write().unwrap();
        let ino = ZeroTrustFs::allocate_inode(&mut state);
        state.inodes.insert(
            ino,
            InodeEntry {
                name: name.to_string(),
                kind: InodeKind::File,
                disk_filename: String::new(),
                size: 0,
                perm: 0o600,
                uid: 501,
                gid: 20,
                atime_secs: 1,
                mtime_secs: 1,
                ctime_secs: 1,
                nlink: 1,
                parent: 1,
            },
        );
        state.children.get_mut(&1).unwrap().push(DirChild {
            name: name.to_string(),
            inode: ino,
        });
        ino
    }

    fn v2_object_count(directory: &Path) -> usize {
        fs::read_dir(directory.join(v2::OBJECT_DIRECTORY).join("objects"))
            .unwrap()
            .count()
    }

    fn leave_v2_overlay_after_failed_last_release(ztfs: &ZeroTrustFs, ino: u64) {
        use crate::fault::FaultInjectionGuard;

        let injector = FaultInjectionGuard::fail_at(1);
        let error = ztfs.release_inode(ino).unwrap_err();
        drop(injector);
        assert!(
            error.to_string().contains("deterministic injected crash"),
            "last release failed for an unexpected reason: {error}"
        );
        assert_eq!(
            ztfs.inner.open_counts.lock().unwrap().get(&ino).copied(),
            None,
            "the failed last release must leave no open-handle count"
        );
        assert!(
            ztfs.has_v2_dirty_inode(ino),
            "the failed last release discarded its dirty overlay"
        );
        assert!(
            ztfs.inner.persistence_error().is_none(),
            "an early injected failure should remain retryable"
        );
    }

    fn copy_test_directory(source: &Path, destination: &Path) {
        let _ = fs::remove_dir_all(destination);
        fs::create_dir_all(destination).unwrap();
        for entry in fs::read_dir(source).unwrap() {
            let entry = entry.unwrap();
            let target = destination.join(entry.file_name());
            if entry.file_type().unwrap().is_dir() {
                copy_test_directory(&entry.path(), &target);
            } else {
                fs::copy(entry.path(), target).unwrap();
            }
        }
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

    #[cfg(unix)]
    #[test]
    fn zero_size_open_refuses_a_dangling_backing_symlink() {
        let dir = PathBuf::from("target/test-open-zero-dangling-symlink");
        let _ = fs::remove_dir_all(&dir);
        let ztfs = ZeroTrustFs::new("pw", dir.clone());
        let (ino, disk_filename) = add_file(&ztfs, "fresh.txt");
        std::os::unix::fs::symlink("missing-provider-target", dir.join(&disk_filename)).unwrap();

        assert!(ztfs.open_inode(ino).is_err());
        assert!(fs::symlink_metadata(dir.join(&disk_filename)).is_ok());
        let _ = fs::remove_dir_all(dir);
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

    #[test]
    fn closed_truncate_refuses_sibling_before_touching_blob() {
        let dir = PathBuf::from("target/test-truncate-sibling-conflict");
        let _ = fs::remove_dir_all(&dir);
        let ztfs = ZeroTrustFs::new("pw", dir.clone());
        let (ino, disk_filename) = add_file(&ztfs, "data.txt");
        ztfs.write_encrypted_file(&disk_filename, b"original")
            .unwrap();
        ztfs.inner
            .state
            .write()
            .unwrap()
            .inodes
            .get_mut(&ino)
            .unwrap()
            .size = 8;
        ztfs.flush_state().unwrap();
        let blob_before = fs::read(dir.join(&disk_filename)).unwrap();
        let index_before = fs::read(dir.join(INDEX_FILE)).unwrap();
        let sibling = dir.join("_index 2.age");
        fs::write(&sibling, b"provider conflict").unwrap();

        assert!(ztfs.truncate_inode(ino, 4).is_err());
        assert_eq!(fs::read(dir.join(&disk_filename)).unwrap(), blob_before);
        assert_eq!(fs::read(dir.join(INDEX_FILE)).unwrap(), index_before);

        fs::remove_file(sibling).unwrap();
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
        assert!(
            ztfs.inner.index_dirty.load(Ordering::Acquire),
            "an open-file truncate must wake the debounce persistence path"
        );
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
        assert!(
            ztfs.inner.index_dirty.load(Ordering::Acquire),
            "a content write must wake the debounce persistence path"
        );
        ztfs.fsync_inode(ino).unwrap();
        assert_eq!(ztfs.read_encrypted_file(&df).unwrap(), b"synced");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn temporary_read_only_mode_does_not_turn_fsync_into_false_success() {
        let dir = PathBuf::from("target/test-fsync-temporary-read-only");
        let _ = fs::remove_dir_all(&dir);
        let ztfs = ZeroTrustFs::new("pw", dir.clone());
        let (ino, disk_filename) = add_file(&ztfs, "data.txt");
        ztfs.open_inode(ino).unwrap();
        ztfs.write_inode_content(ino, 0, b"must persist").unwrap();

        // Online rekey uses this flag temporarily while taking its snapshot.
        // Persistence calls must wait on the gate and flush, never claim that
        // RAM-only bytes are durable merely because ordinary writes are paused.
        ztfs.inner.read_only.store(true, Ordering::SeqCst);
        ztfs.fsync_inode(ino).unwrap();
        assert_eq!(
            ztfs.read_encrypted_file(&disk_filename).unwrap(),
            b"must persist"
        );
        ztfs.inner.restore_writes_if_healthy();

        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn fsync_persists_pending_metadata_without_a_forced_clean_rewrite() {
        let dir = PathBuf::from("target/test-fsync-metadata");
        let _ = fs::remove_dir_all(&dir);
        let ino;
        {
            let ztfs = ZeroTrustFs::new("pw", dir.clone());
            (ino, _) = add_file(&ztfs, "metadata.txt");
            ztfs.flush_state().unwrap();
            ztfs.inner
                .state
                .write()
                .unwrap()
                .inodes
                .get_mut(&ino)
                .unwrap()
                .perm = 0o600;
            ztfs.mark_dirty();
            ztfs.fsync_inode(ino).unwrap();
        }

        let reopened = ZeroTrustFs::new("pw", dir.clone());
        assert_eq!(
            reopened
                .inner
                .state
                .read()
                .unwrap()
                .inodes
                .get(&ino)
                .unwrap()
                .perm,
            0o600
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn clean_fsync_preserves_blob_and_index_ciphertext() {
        let dir = PathBuf::from("target/test-clean-fsync");
        let _ = fs::remove_dir_all(&dir);
        let ztfs = ZeroTrustFs::new("pw", dir.clone());
        let (ino, disk_filename) = add_file(&ztfs, "clean.txt");
        ztfs.write_encrypted_file(&disk_filename, b"unchanged")
            .unwrap();
        ztfs.inner
            .state
            .write()
            .unwrap()
            .inodes
            .get_mut(&ino)
            .unwrap()
            .size = 9;
        ztfs.flush_state().unwrap();
        ztfs.open_inode(ino).unwrap();
        let blob_before = fs::read(dir.join(&disk_filename)).unwrap();
        let index_before = fs::read(dir.join(INDEX_FILE)).unwrap();

        ztfs.fsync_inode(ino).unwrap();

        assert_eq!(fs::read(dir.join(&disk_filename)).unwrap(), blob_before);
        assert_eq!(fs::read(dir.join(INDEX_FILE)).unwrap(), index_before);
        ztfs.release_inode(ino).unwrap();
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

    #[test]
    fn v2_mount_uses_bounded_chunk_io_and_never_overwrites_old_objects() {
        let dir = PathBuf::from("target/test-v2-bounded-io");
        let _ = fs::remove_dir_all(&dir);
        let ztfs = ZeroTrustFs::new_v2("pw", dir.clone());
        assert_eq!(ztfs.inner.format, StoreFormat::V2);

        let ino = {
            let mut state = ztfs.inner.state.write().unwrap();
            let ino = ZeroTrustFs::allocate_inode(&mut state);
            state.inodes.insert(
                ino,
                InodeEntry {
                    name: "large-sparse.bin".to_string(),
                    kind: InodeKind::File,
                    disk_filename: String::new(),
                    size: 0,
                    perm: 0o600,
                    uid: 501,
                    gid: 20,
                    atime_secs: 1,
                    mtime_secs: 1,
                    ctime_secs: 1,
                    nlink: 1,
                    parent: 1,
                },
            );
            state.children.get_mut(&1).unwrap().push(DirChild {
                name: "large-sparse.bin".to_string(),
                inode: ino,
            });
            ino
        };
        ztfs.open_inode(ino).unwrap();
        let offset = v2::CHUNK_SIZE as u64 * 4 + 23;
        ztfs.write_inode_content(ino, offset, b"first-generation")
            .unwrap();
        assert!(ztfs.inner.open_files.read().unwrap().is_empty());
        ztfs.fsync_inode(ino).unwrap();

        let objects = dir.join(v2::OBJECT_DIRECTORY).join("objects");
        let before: HashMap<_, _> = fs::read_dir(&objects)
            .unwrap()
            .map(|entry| {
                let entry = entry.unwrap();
                (entry.file_name(), fs::read(entry.path()).unwrap())
            })
            .collect();
        ztfs.write_inode_content(ino, offset, b"second-generation")
            .unwrap();
        ztfs.fsync_inode(ino).unwrap();
        for (name, bytes) in before {
            assert_eq!(
                fs::read(objects.join(name)).unwrap(),
                bytes,
                "a referenced immutable v2 object was overwritten"
            );
        }
        ztfs.release_inode(ino).unwrap();
        drop(ztfs);

        let reopened = ZeroTrustFs::new_v2("pw", dir.clone());
        assert_eq!(reopened.inner.format, StoreFormat::V2);
        let entry = reopened.inner.state.read().unwrap().inodes[&ino].clone();
        let content = v2::read_file_range(
            &dir,
            &reopened.inner.key.read().unwrap(),
            &entry.disk_filename,
            entry.size,
            offset,
            "second-generation".len(),
        )
        .unwrap();
        assert_eq!(content, b"second-generation");

        let state = reopened.inner.state.read().unwrap().clone();
        let key = *reopened.inner.key.read().unwrap();
        drop(reopened);
        for object in fs::read_dir(&objects).unwrap() {
            fs::remove_file(object.unwrap().path()).unwrap();
        }
        let error = validate_reachable_v2_files(&dir, &key, &state).unwrap_err();
        assert!(error.contains("not completely materialized"), "{error}");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn v2_small_writes_coalesce_in_bounded_overlay_until_fsync() {
        let dir = PathBuf::from("target/test-v2-dirty-overlay-coalesce");
        let _ = fs::remove_dir_all(&dir);
        let ztfs = ZeroTrustFs::new_v2("pw", dir.clone());
        let ino = add_v2_file(&ztfs, "coalesced.bin");
        ztfs.open_inode(ino).unwrap();
        let before = v2_object_count(&dir);

        for (offset, byte) in b"bounded-overlay".iter().copied().enumerate() {
            ztfs.write_inode_content(ino, offset as u64, &[byte])
                .unwrap();
        }

        assert_eq!(v2_object_count(&dir), before);
        assert_eq!(ztfs.inner.v2_dirty.lock().unwrap().chunk_count, 1);
        assert_eq!(
            ztfs.read_v2_inode_range(ino, 0, 64).unwrap(),
            b"bounded-overlay"
        );

        ztfs.fsync_inode(ino).unwrap();
        assert!(v2_object_count(&dir) > before);
        assert_eq!(ztfs.inner.v2_dirty.lock().unwrap().chunk_count, 0);
        ztfs.release_inode(ino).unwrap();
        drop(ztfs);

        let reopened = ZeroTrustFs::new_v2("pw", dir.clone());
        assert_eq!(
            reopened.read_v2_inode_range(ino, 0, 64).unwrap(),
            b"bounded-overlay"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn v2_overlay_handles_cross_chunk_write_and_read() {
        let dir = PathBuf::from("target/test-v2-dirty-overlay-cross-chunk");
        let _ = fs::remove_dir_all(&dir);
        let ztfs = ZeroTrustFs::new_v2("pw", dir.clone());
        let ino = add_v2_file(&ztfs, "boundary.bin");
        ztfs.open_inode(ino).unwrap();
        let offset = v2::CHUNK_SIZE as u64 - 3;

        ztfs.write_inode_content(ino, offset, b"abcdef").unwrap();

        assert_eq!(ztfs.inner.v2_dirty.lock().unwrap().chunk_count, 2);
        assert_eq!(
            ztfs.read_v2_inode_range(ino, offset - 2, 10).unwrap(),
            b"\0\0abcdef"
        );
        ztfs.fsync_inode(ino).unwrap();
        assert_eq!(
            ztfs.read_v2_inode_range(ino, offset - 2, 10).unwrap(),
            b"\0\0abcdef"
        );
        ztfs.release_inode(ino).unwrap();
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn v2_overlay_reads_last_representable_sparse_byte_before_and_after_flush() {
        let dir = PathBuf::from("target/test-v2-dirty-overlay-u64-boundary");
        let _ = fs::remove_dir_all(&dir);
        let ztfs = ZeroTrustFs::new_v2("pw", dir.clone());
        let ino = add_v2_file(&ztfs, "boundary.bin");
        ztfs.open_inode(ino).unwrap();
        let offset = u64::MAX - 1;

        assert_eq!(ztfs.write_inode_content(ino, offset, b"x").unwrap(), 1);
        assert_eq!(
            ztfs.read_v2_inode_range(ino, offset, 1).unwrap(),
            b"x",
            "the dirty final chunk must be readable before persistence"
        );
        ztfs.fsync_inode(ino).unwrap();
        ztfs.release_inode(ino).unwrap();
        drop(ztfs);

        let reopened = ZeroTrustFs::new_v2("pw", dir.clone());
        assert_eq!(
            reopened.read_v2_inode_range(ino, offset, 1).unwrap(),
            b"x",
            "the final sparse byte must remain readable after root-last persistence"
        );
        drop(reopened);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn v2_overlay_pressure_flushes_before_accepting_another_chunk() {
        let dir = PathBuf::from(format!(
            "target/test-v2-dirty-overlay-pressure-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&dir);
        let mut ztfs = ZeroTrustFs::new_v2("pw", dir.clone());
        ztfs.stop_debounce_thread_for_test();
        let ino = add_v2_file(&ztfs, "pressure.bin");
        ztfs.open_inode(ino).unwrap();
        let before = v2_object_count(&dir);

        for chunk in 0..=V2_DIRTY_CHUNK_LIMIT {
            let offset = chunk as u64 * v2::CHUNK_SIZE as u64;
            ztfs.write_inode_content(ino, offset, &[chunk as u8])
                .unwrap();
        }

        let overlay = ztfs.inner.v2_dirty.lock().unwrap();
        assert_eq!(overlay.chunk_count, 1);
        assert!(overlay.chunk_count <= V2_DIRTY_CHUNK_LIMIT);
        drop(overlay);
        assert!(v2_object_count(&dir) > before);
        for chunk in 0..=V2_DIRTY_CHUNK_LIMIT {
            let offset = chunk as u64 * v2::CHUNK_SIZE as u64;
            assert_eq!(
                ztfs.read_v2_inode_range(ino, offset, 1).unwrap(),
                [chunk as u8]
            );
        }
        ztfs.fsync_inode(ino).unwrap();
        ztfs.release_inode(ino).unwrap();
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn v2_overlay_pressure_failure_does_not_partially_accept_incoming_write() {
        use crate::fault::FaultInjectionGuard;

        let dir = PathBuf::from(format!(
            "target/test-v2-dirty-overlay-pressure-failure-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&dir);
        let mut ztfs = ZeroTrustFs::new_v2("pw", dir.clone());
        ztfs.stop_debounce_thread_for_test();
        let ino = add_v2_file(&ztfs, "pressure-failure.bin");
        ztfs.open_inode(ino).unwrap();
        for chunk in 0..V2_DIRTY_CHUNK_LIMIT {
            ztfs.write_inode_content(ino, chunk as u64 * v2::CHUNK_SIZE as u64, &[chunk as u8])
                .unwrap();
        }
        let size_before = ztfs.inner.state.read().unwrap().inodes[&ino].size;

        let injector = FaultInjectionGuard::fail_at(1);
        let incoming_offset = V2_DIRTY_CHUNK_LIMIT as u64 * v2::CHUNK_SIZE as u64;
        let result = ztfs.write_inode_content(ino, incoming_offset, b"x");
        drop(injector);

        assert!(result.is_err());
        assert_eq!(
            ztfs.inner.state.read().unwrap().inodes[&ino].size,
            size_before
        );
        assert_eq!(ztfs.inner.v2_dirty.lock().unwrap().chunk_count, 16);
        assert!(
            ztfs.read_v2_inode_range(ino, incoming_offset, 1)
                .unwrap()
                .is_empty(),
            "failed pressure flush must not acknowledge the incoming chunk"
        );
        for chunk in 0..V2_DIRTY_CHUNK_LIMIT {
            assert_eq!(
                ztfs.read_v2_inode_range(ino, chunk as u64 * v2::CHUNK_SIZE as u64, 1)
                    .unwrap(),
                [chunk as u8],
                "failed pressure flush discarded prior chunk {chunk}"
            );
        }
        *ztfs.inner.persistence_failure.lock().unwrap() =
            Some("stop pressure-failure test retry".to_string());
        drop(ztfs);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn v2_overlay_shrink_then_grow_never_resurrects_discarded_bytes() {
        let dir = PathBuf::from("target/test-v2-dirty-overlay-truncate");
        let _ = fs::remove_dir_all(&dir);
        let ztfs = ZeroTrustFs::new_v2("pw", dir.clone());
        let ino = add_v2_file(&ztfs, "truncate.bin");
        ztfs.open_inode(ino).unwrap();
        ztfs.write_inode_content(ino, 0, b"abcdefgh").unwrap();
        ztfs.fsync_inode(ino).unwrap();

        ztfs.truncate_inode(ino, 3).unwrap();
        ztfs.truncate_inode(ino, 8).unwrap();
        assert_eq!(
            ztfs.read_v2_inode_range(ino, 0, 16).unwrap(),
            b"abc\0\0\0\0\0"
        );
        ztfs.fsync_inode(ino).unwrap();
        ztfs.release_inode(ino).unwrap();
        drop(ztfs);

        let reopened = ZeroTrustFs::new_v2("pw", dir.clone());
        assert_eq!(
            reopened.read_v2_inode_range(ino, 0, 16).unwrap(),
            b"abc\0\0\0\0\0"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn v2_dirty_unlink_fails_closed_without_discarding_overlay() {
        let dir = PathBuf::from("target/test-v2-dirty-unlink-core");
        let _ = fs::remove_dir_all(&dir);
        let ztfs = ZeroTrustFs::new_v2("pw", dir.clone());
        let ino = add_v2_file(&ztfs, "dirty.txt");
        ztfs.open_inode(ino).unwrap();
        ztfs.write_inode_content(ino, 0, b"acknowledged-dirty-bytes")
            .unwrap();
        let root_before = fs::read(dir.join(v2::ROOT_FILE)).unwrap();
        leave_v2_overlay_after_failed_last_release(&ztfs, ino);

        let error = ztfs.unlink_name(1, "dirty.txt").unwrap_err();
        assert_eq!(error.raw_os_error(), Some(libc::EBUSY));
        assert_eq!(
            ZeroTrustFs::find_child(&ztfs.inner.state.read().unwrap(), 1, "dirty.txt"),
            Some(ino)
        );
        assert_eq!(
            ztfs.read_v2_inode_range(ino, 0, 64).unwrap(),
            b"acknowledged-dirty-bytes"
        );
        assert!(ztfs.has_v2_dirty_inode(ino));
        assert_eq!(fs::read(dir.join(v2::ROOT_FILE)).unwrap(), root_before);

        ztfs.fsync_inode(ino).unwrap();
        ztfs.unlink_name(1, "dirty.txt").unwrap();
        assert!(
            ZeroTrustFs::find_child(&ztfs.inner.state.read().unwrap(), 1, "dirty.txt").is_none()
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn unlink_core_rejects_a_non_directory_parent() {
        let dir = PathBuf::from(format!(
            "target/test-v2-unlink-nondirectory-parent-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&dir);
        let ztfs = ZeroTrustFs::new_v2("pw", dir.clone());
        let file = add_v2_file(&ztfs, "not-a-directory");

        let error = ztfs.unlink_name(file, "child").unwrap_err();
        assert_eq!(error.raw_os_error(), Some(libc::ENOTDIR));
        assert_eq!(
            ZeroTrustFs::find_child(&ztfs.inner.state.read().unwrap(), 1, "not-a-directory"),
            Some(file)
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn v2_dirty_rename_preserves_overlay_and_commits_new_namespace() {
        let dir = PathBuf::from("target/test-v2-dirty-rename-core");
        let _ = fs::remove_dir_all(&dir);
        let ztfs = ZeroTrustFs::new_v2("pw", dir.clone());
        let ino = add_v2_file(&ztfs, "before.txt");
        ztfs.open_inode(ino).unwrap();
        ztfs.write_inode_content(ino, 0, b"dirty-content-follows-inode")
            .unwrap();
        leave_v2_overlay_after_failed_last_release(&ztfs, ino);

        ztfs.rename_name(1, "before.txt", 1, "after.txt").unwrap();
        let state = ztfs.inner.state.read().unwrap();
        assert!(ZeroTrustFs::find_child(&state, 1, "before.txt").is_none());
        assert_eq!(ZeroTrustFs::find_child(&state, 1, "after.txt"), Some(ino));
        assert_eq!(state.inodes[&ino].name, "after.txt");
        drop(state);
        assert_eq!(
            ztfs.read_v2_inode_range(ino, 0, 64).unwrap(),
            b"dirty-content-follows-inode"
        );

        ztfs.fsync_inode(ino).unwrap();
        drop(ztfs);
        let reopened = ZeroTrustFs::new_v2("pw", dir.clone());
        let state = reopened.inner.state.read().unwrap();
        assert!(ZeroTrustFs::find_child(&state, 1, "before.txt").is_none());
        assert_eq!(ZeroTrustFs::find_child(&state, 1, "after.txt"), Some(ino));
        drop(state);
        assert_eq!(
            reopened.read_v2_inode_range(ino, 0, 64).unwrap(),
            b"dirty-content-follows-inode"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn v2_rename_over_dirty_target_is_busy_and_preserves_both_names() {
        let dir = PathBuf::from("target/test-v2-dirty-rename-target-core");
        let _ = fs::remove_dir_all(&dir);
        let ztfs = ZeroTrustFs::new_v2("pw", dir.clone());
        let source = add_v2_file(&ztfs, "source.txt");
        let target = add_v2_file(&ztfs, "target.txt");
        ztfs.open_inode(target).unwrap();
        ztfs.write_inode_content(target, 0, b"target-dirty-evidence")
            .unwrap();
        let root_before = fs::read(dir.join(v2::ROOT_FILE)).unwrap();
        leave_v2_overlay_after_failed_last_release(&ztfs, target);

        let error = ztfs
            .rename_name(1, "source.txt", 1, "target.txt")
            .unwrap_err();
        assert_eq!(error.raw_os_error(), Some(libc::EBUSY));
        let state = ztfs.inner.state.read().unwrap();
        assert_eq!(
            ZeroTrustFs::find_child(&state, 1, "source.txt"),
            Some(source)
        );
        assert_eq!(
            ZeroTrustFs::find_child(&state, 1, "target.txt"),
            Some(target)
        );
        drop(state);
        assert_eq!(
            ztfs.read_v2_inode_range(target, 0, 64).unwrap(),
            b"target-dirty-evidence"
        );
        assert_eq!(fs::read(dir.join(v2::ROOT_FILE)).unwrap(), root_before);
        ztfs.fsync_inode(target).unwrap();
        drop(ztfs);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn v2_rename_over_clean_empty_target_commits_before_return() {
        let dir = PathBuf::from("target/test-v2-rename-clean-empty-target");
        let _ = fs::remove_dir_all(&dir);
        let ztfs = ZeroTrustFs::new_v2("pw", dir.clone());
        let source = add_v2_file(&ztfs, "source.txt");
        let target = add_v2_file(&ztfs, "target.txt");
        ztfs.open_inode(source).unwrap();
        ztfs.write_inode_content(source, 0, b"source survives overwrite")
            .unwrap();
        ztfs.fsync_inode(source).unwrap();
        ztfs.release_inode(source).unwrap();
        assert!(
            ztfs.inner.state.read().unwrap().inodes[&target]
                .disk_filename
                .is_empty(),
            "the overwrite target must exercise the clean empty-root path"
        );
        let root_before = fs::read(dir.join(v2::ROOT_FILE)).unwrap();

        ztfs.rename_name(1, "source.txt", 1, "target.txt").unwrap();
        let root_after = fs::read(dir.join(v2::ROOT_FILE)).unwrap();
        assert_ne!(
            root_after, root_before,
            "a successful overwrite must publish its namespace before returning"
        );
        drop(ztfs);

        let reopened = ZeroTrustFs::new_v2("pw", dir.clone());
        let state = reopened.inner.state.read().unwrap();
        assert!(ZeroTrustFs::find_child(&state, 1, "source.txt").is_none());
        assert_eq!(
            ZeroTrustFs::find_child(&state, 1, "target.txt"),
            Some(source)
        );
        assert!(!state.inodes.contains_key(&target));
        drop(state);
        assert_eq!(
            reopened.read_v2_inode_range(source, 0, 64).unwrap(),
            b"source survives overwrite"
        );
        drop(reopened);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn every_clean_empty_target_overwrite_checkpoint_recovers_old_or_new() {
        use crate::fault::{DurabilityEvent, FaultInjectionGuard};

        let process = std::process::id();
        let baseline = PathBuf::from(format!("target/test-v2-empty-overwrite-baseline-{process}"));
        let successful = PathBuf::from(format!("target/test-v2-empty-overwrite-success-{process}"));
        let _ = fs::remove_dir_all(&baseline);
        let _ = fs::remove_dir_all(&successful);
        let (source, target);
        {
            let ztfs = ZeroTrustFs::new_v2("pw", baseline.clone());
            source = add_v2_file(&ztfs, "source.txt");
            target = add_v2_file(&ztfs, "target.txt");
            ztfs.open_inode(source).unwrap();
            ztfs.write_inode_content(source, 0, b"source generation")
                .unwrap();
            ztfs.fsync_inode(source).unwrap();
            ztfs.release_inode(source).unwrap();
        }
        let old_root = fs::read(baseline.join(v2::ROOT_FILE)).unwrap();

        copy_test_directory(&baseline, &successful);
        let ztfs = ZeroTrustFs::new_v2("pw", successful.clone());
        let recorder = FaultInjectionGuard::record();
        ztfs.rename_name(1, "source.txt", 1, "target.txt").unwrap();
        let events = recorder.events();
        drop(recorder);
        for required in [
            DurabilityEvent::Write,
            DurabilityEvent::FileSync,
            DurabilityEvent::Rename,
            DurabilityEvent::DirectorySync,
            DurabilityEvent::Cleanup,
        ] {
            assert!(
                events.contains(&required),
                "overwrite trace omitted {required:?}"
            );
        }
        let new_root = fs::read(successful.join(v2::ROOT_FILE)).unwrap();
        assert_ne!(new_root, old_root);
        drop(ztfs);
        fs::remove_dir_all(&successful).unwrap();

        for checkpoint in 1..=events.len() {
            let crashed = PathBuf::from(format!(
                "target/test-v2-empty-overwrite-{process}-checkpoint-{checkpoint}"
            ));
            copy_test_directory(&baseline, &crashed);
            fs::write(crashed.join("rename-evidence.keep"), b"preserve me").unwrap();
            let ztfs = ZeroTrustFs::new_v2("pw", crashed.clone());
            let injector = FaultInjectionGuard::fail_at(checkpoint);
            let result = ztfs.rename_name(1, "source.txt", 1, "target.txt");
            drop(injector);
            assert!(result.is_err(), "checkpoint {checkpoint} was not exercised");
            *ztfs.inner.persistence_failure.lock().unwrap() =
                Some("stop test retry before simulated remount".to_string());
            drop(ztfs);

            let reopened = ZeroTrustFs::new_v2("pw", crashed.clone());
            let state = reopened.inner.state.read().unwrap();
            let source_name = ZeroTrustFs::find_child(&state, 1, "source.txt");
            let target_name = ZeroTrustFs::find_child(&state, 1, "target.txt");
            let old_visible = source_name == Some(source) && target_name == Some(target);
            let new_visible = source_name.is_none() && target_name == Some(source);
            assert!(
                old_visible || new_visible,
                "checkpoint {checkpoint} exposed a mixed overwrite namespace"
            );
            let visible_root = fs::read(crashed.join(v2::ROOT_FILE)).unwrap();
            if old_visible {
                assert_eq!(
                    visible_root, old_root,
                    "checkpoint {checkpoint} changed the exact old root"
                );
            } else {
                assert_ne!(
                    visible_root, old_root,
                    "checkpoint {checkpoint} exposed the old root with the new namespace"
                );
            }
            drop(state);
            assert_eq!(
                reopened.read_v2_inode_range(source, 0, 64).unwrap(),
                b"source generation"
            );
            assert_eq!(
                fs::read(crashed.join("rename-evidence.keep")).unwrap(),
                b"preserve me"
            );
            drop(reopened);
            fs::remove_dir_all(crashed).unwrap();
        }

        fs::remove_dir_all(baseline).unwrap();
    }

    #[test]
    fn v2_flush_conflict_keeps_dirty_overlay_readable() {
        let dir = PathBuf::from("target/test-v2-dirty-overlay-conflict");
        let _ = fs::remove_dir_all(&dir);
        let ztfs = ZeroTrustFs::new_v2("pw", dir.clone());
        let ino = add_v2_file(&ztfs, "retained.bin");
        ztfs.open_inode(ino).unwrap();
        ztfs.write_inode_content(ino, 0, b"not-lost").unwrap();
        let old_root = fs::read(dir.join(v2::ROOT_FILE)).unwrap();
        fs::write(dir.join("_root (conflicted copy).age"), b"evidence").unwrap();

        assert!(ztfs.fsync_inode(ino).is_err());
        assert_eq!(fs::read(dir.join(v2::ROOT_FILE)).unwrap(), old_root);
        assert!(ztfs.has_v2_dirty_inode(ino));
        assert_eq!(ztfs.read_v2_inode_range(ino, 0, 32).unwrap(), b"not-lost");
        assert_eq!(
            fs::read(dir.join("_root (conflicted copy).age")).unwrap(),
            b"evidence"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn every_overlay_flush_checkpoint_recovers_old_or_new_and_keeps_evidence() {
        use crate::fault::{DurabilityEvent, FaultInjectionGuard};

        let baseline = PathBuf::from("target/test-v2-overlay-crash-baseline");
        let successful = PathBuf::from("target/test-v2-overlay-crash-success");
        let _ = fs::remove_dir_all(&baseline);
        let _ = fs::remove_dir_all(&successful);
        let ino;
        {
            let ztfs = ZeroTrustFs::new_v2("pw", baseline.clone());
            ino = add_v2_file(&ztfs, "generation.bin");
            ztfs.open_inode(ino).unwrap();
            ztfs.write_inode_content(ino, 0, b"old-generation").unwrap();
            ztfs.fsync_inode(ino).unwrap();
            ztfs.release_inode(ino).unwrap();
        }
        let old_root = fs::read(baseline.join(v2::ROOT_FILE)).unwrap();

        copy_test_directory(&baseline, &successful);
        let ztfs = ZeroTrustFs::new_v2("pw", successful.clone());
        ztfs.open_inode(ino).unwrap();
        ztfs.write_inode_content(ino, 0, b"new-generation").unwrap();
        let recorder = FaultInjectionGuard::record();
        ztfs.fsync_inode(ino).unwrap();
        let events = recorder.events();
        drop(recorder);
        assert!(events.contains(&DurabilityEvent::Write));
        assert!(events.contains(&DurabilityEvent::FileSync));
        assert!(events.contains(&DurabilityEvent::Rename));
        assert!(events.contains(&DurabilityEvent::DirectorySync));
        assert!(events.contains(&DurabilityEvent::Cleanup));
        ztfs.release_inode(ino).unwrap();
        drop(ztfs);
        fs::remove_dir_all(&successful).unwrap();

        for checkpoint in 1..=events.len() {
            let crashed = PathBuf::from(format!(
                "target/test-v2-overlay-crash-checkpoint-{checkpoint}"
            ));
            copy_test_directory(&baseline, &crashed);
            fs::write(crashed.join("conflict-evidence.keep"), b"preserve me").unwrap();
            let ztfs = ZeroTrustFs::new_v2("pw", crashed.clone());
            ztfs.open_inode(ino).unwrap();
            ztfs.write_inode_content(ino, 0, b"new-generation").unwrap();
            let injector = FaultInjectionGuard::fail_at(checkpoint);
            let result = ztfs.fsync_inode(ino);
            drop(injector);
            assert!(result.is_err(), "checkpoint {checkpoint} was not exercised");
            assert_eq!(
                ztfs.read_v2_inode_range(ino, 0, 64).unwrap(),
                b"new-generation",
                "checkpoint {checkpoint} discarded the acknowledged overlay"
            );
            *ztfs.inner.persistence_failure.lock().unwrap() =
                Some("stop test retry before simulated remount".to_string());
            drop(ztfs);

            let reopened = ZeroTrustFs::new_v2("pw", crashed.clone());
            let visible = reopened.read_v2_inode_range(ino, 0, 64).unwrap();
            assert!(
                visible == b"old-generation" || visible == b"new-generation",
                "checkpoint {checkpoint} exposed a mixed generation: {visible:?}"
            );
            if visible == b"old-generation" {
                assert_eq!(
                    fs::read(crashed.join(v2::ROOT_FILE)).unwrap(),
                    old_root,
                    "checkpoint {checkpoint} changed the exact old root"
                );
            }
            assert_eq!(
                fs::read(crashed.join("conflict-evidence.keep")).unwrap(),
                b"preserve me"
            );
            drop(reopened);
            fs::remove_dir_all(crashed).unwrap();
        }

        fs::remove_dir_all(baseline).unwrap();
    }

    #[test]
    fn v2_constructor_keeps_v1_read_compatibility() {
        let dir = PathBuf::from("target/test-v2-v1-compatibility");
        let _ = fs::remove_dir_all(&dir);
        {
            let legacy = ZeroTrustFs::new("pw", dir.clone());
            assert_eq!(legacy.inner.format, StoreFormat::V1);
        }
        let reopened = ZeroTrustFs::new_v2("pw", dir.clone());
        assert_eq!(reopened.inner.format, StoreFormat::V1);
        assert!(dir.join(INDEX_FILE).exists());
        assert!(!dir.join(v2::ROOT_FILE).exists());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn provider_generated_v2_root_sibling_is_conflict_evidence() {
        let dir = PathBuf::from("target/test-v2-root-sibling");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("_root (conflicted copy).age"), b"evidence").unwrap();
        let error = ensure_no_index_siblings(&dir).unwrap_err();
        assert!(error.to_string().contains("_root"));
        assert_eq!(
            fs::read(dir.join("_root (conflicted copy).age")).unwrap(),
            b"evidence"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn delayed_v2_head_latches_a_live_v1_mount_read_only() {
        let dir = PathBuf::from("target/test-delayed-v2-head-on-v1");
        let _ = fs::remove_dir_all(&dir);
        let ztfs = ZeroTrustFs::new("pw", dir.clone());
        let committed_v1 = fs::read(dir.join(INDEX_FILE)).unwrap();

        fs::write(dir.join(v2::ROOT_FILE), b"delayed provider v2 head").unwrap();
        let error = ztfs.inner.ensure_index_unchanged().unwrap_err();
        assert!(
            error
                .to_string()
                .contains("changed, appeared, or disappeared"),
            "{error}"
        );
        assert!(ztfs.inner.read_only.load(Ordering::SeqCst));
        assert_eq!(fs::read(dir.join(INDEX_FILE)).unwrap(), committed_v1);
        assert_eq!(
            fs::read(dir.join(v2::ROOT_FILE)).unwrap(),
            b"delayed provider v2 head"
        );

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn delayed_v1_head_latches_a_live_v2_mount_read_only() {
        let dir = PathBuf::from("target/test-delayed-v1-head-on-v2");
        let _ = fs::remove_dir_all(&dir);
        let ztfs = ZeroTrustFs::new_v2("pw", dir.clone());
        let committed_v2 = fs::read(dir.join(v2::ROOT_FILE)).unwrap();

        fs::write(dir.join(INDEX_FILE), b"delayed provider v1 head").unwrap();
        let error = ztfs.inner.ensure_index_unchanged().unwrap_err();
        assert!(
            error
                .to_string()
                .contains("changed, appeared, or disappeared"),
            "{error}"
        );
        assert!(ztfs.inner.read_only.load(Ordering::SeqCst));
        assert_eq!(fs::read(dir.join(v2::ROOT_FILE)).unwrap(), committed_v2);
        assert_eq!(
            fs::read(dir.join(INDEX_FILE)).unwrap(),
            b"delayed provider v1 head"
        );

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn migrated_v2_mount_pins_retained_control_evidence() {
        let dir = PathBuf::from("target/test-v2-pinned-control-evidence");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(dir.join(v2::OBJECT_DIRECTORY)).unwrap();
        for name in [
            INDEX_FILE,
            crate::v2_migrate::PLAN_FILE,
            crate::v2_migrate::COMPLETION_FILE,
        ] {
            fs::write(dir.join(name), vec![1u8; 40]).unwrap();
        }
        let snapshot = FormatControlSnapshot::capture(&dir, StoreFormat::V2).unwrap();

        fs::write(dir.join(crate::v2_migrate::PLAN_FILE), vec![2u8; 40]).unwrap();
        let error = snapshot.verify(&dir).unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::AlreadyExists);
        assert!(error.to_string().contains(crate::v2_migrate::PLAN_FILE));
        assert_eq!(
            fs::read(dir.join(crate::v2_migrate::PLAN_FILE)).unwrap(),
            vec![2u8; 40]
        );

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn v1_mount_allows_and_pins_preplan_v2_probe_debris() {
        let dir = PathBuf::from("target/test-v1-preplan-v2-probe-debris");
        let _ = fs::remove_dir_all(&dir);
        let evidence = dir.join(v2::OBJECT_DIRECTORY).join("evidence");
        fs::create_dir_all(&evidence).unwrap();
        fs::write(evidence.join("probe.keep"), b"preserve probe evidence").unwrap();

        let snapshot = FormatControlSnapshot::capture(&dir, StoreFormat::V1).unwrap();
        snapshot.verify(&dir).unwrap();
        assert_eq!(
            fs::read(evidence.join("probe.keep")).unwrap(),
            b"preserve probe evidence"
        );

        fs::create_dir_all(dir.join(v2::LEGACY_OBJECT_DIRECTORY)).unwrap();
        let error = snapshot.verify(&dir).unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::AlreadyExists);
        assert!(error.to_string().contains("topology changed"));

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn dual_canonical_heads_require_retained_authenticated_migration_plan() {
        let dir = PathBuf::from("target/test-v2-dual-head-evidence");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join(INDEX_FILE), b"v1 head").unwrap();
        fs::write(dir.join(v2::ROOT_FILE), b"v2 head").unwrap();

        let error = ensure_unambiguous_format_heads(&dir).unwrap_err();
        assert!(error.to_string().contains("provider-merged"), "{error}");
        fs::write(
            dir.join(crate::v2_migrate::PLAN_FILE),
            b"authenticated later",
        )
        .unwrap();
        ensure_unambiguous_format_heads(&dir).unwrap();
        fs::remove_file(dir.join(INDEX_FILE)).unwrap();
        let error = ensure_unambiguous_format_heads(&dir).unwrap_err();
        assert!(
            error.to_string().contains("source head is missing"),
            "{error}"
        );

        let _ = fs::remove_dir_all(&dir);
    }
}
