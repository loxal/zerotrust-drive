// Copyright 2026 Alexander Orlov <alexander.orlov@loxal.net>

//! Version 2 immutable-object storage.
//!
//! V2 never overwrites a referenced data object. Files are sparse radix trees
//! of immutable authenticated chunks; metadata indexes and generation records
//! are immutable objects too. `_root.age` is the only mutable visibility
//! pointer and is atomically switched after every referenced object is durable.

use std::ffi::CString;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use blake2::{Blake2s256, Digest};
use chacha20poly1305::aead::rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};

use crate::crypto::{
    RecoveryFingerprint, V1_CIPHERTEXT_OVERHEAD, ciphertext_bytes_fingerprint, decrypt_bytes_owned,
    encrypt_bytes, exact_fingerprint,
};
use crate::fault::{self, DurabilityEvent};
use crate::fs::{
    DiskIndex, backing_entry_exists, ensure_no_index_siblings, read_bounded_backing_file,
    validate_disk_index_v2, validate_reachable_v2_files,
};

pub(crate) const ROOT_FILE: &str = "_root.age";
pub(crate) const WRITE_MANIFEST: &str = "_write.manifest";
pub(crate) const OBJECT_DIRECTORY: &str = "_zdrive-v2";
pub(crate) const LEGACY_OBJECT_DIRECTORY: &str = ".zdrive-v2";
pub(crate) const CHUNK_SIZE: usize = 4 * 1024 * 1024;
/// Hard cap for one cached FUSE read response. This matches fuser 0.17's
/// maximum request buffer and stays independent of the complete file size.
pub(crate) const MAX_FUSE_READ_SIZE: usize = 16 * 1024 * 1024;
pub(crate) const FORMAT_VERSION: u32 = 2;

pub(crate) const fn platform_supports_atomic_exchange() -> bool {
    cfg!(any(target_os = "linux", target_os = "macos"))
}

pub(crate) fn probe_atomic_exchange(base_path: &Path) -> std::io::Result<()> {
    if !platform_supports_atomic_exchange() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "this platform has no atomic exchange rename",
        ));
    }
    ensure_layout(base_path)?;
    let evidence = selected_object_directory(base_path)?.join(EVIDENCE_DIRECTORY);
    let mut id = [0u8; 16];
    OsRng.fill_bytes(&mut id);
    let prefix = format!("exchange-probe-{}", to_hex(&id));
    let first = evidence.join(format!("{prefix}-a"));
    let second = evidence.join(format!("{prefix}-b"));
    write_new_file(&first, b"first", "stage atomic-exchange capability probe")?;
    write_new_file(&second, b"second", "stage atomic-exchange capability probe")?;
    rename_exchange(&first, &second)?;
    fault::checkpoint(
        DurabilityEvent::Rename,
        "probe backing-directory atomic exchange support",
    )?;
    if read_bounded_regular(&first, 6)? != b"second"
        || read_bounded_regular(&second, 5)? != b"first"
    {
        return Err(io_invalid(
            "backing directory did not preserve both files across atomic exchange",
        ));
    }
    fs::remove_file(&first)?;
    fault::checkpoint(DurabilityEvent::Cleanup, "clean atomic exchange probe")?;
    fs::remove_file(&second)?;
    fault::checkpoint(DurabilityEvent::Cleanup, "clean atomic exchange probe")?;
    File::open(&evidence)?.sync_all()?;
    fault::checkpoint(
        DurabilityEvent::DirectorySync,
        "persist atomic exchange probe cleanup",
    )
}

const OBJECTS_DIRECTORY: &str = "objects";
const EVIDENCE_DIRECTORY: &str = "evidence";
const ROOT_MAGIC: &str = "zerotrust-drive-v2-root";
const ROOT_READY_PREFIX: &str = "_z2-head-";
const MANIFEST_READY_PREFIX: &str = "_z2-manifest-";
const LEGACY_ROOT_READY_PREFIX: &str = "._z2-head-";
const LEGACY_MANIFEST_READY_PREFIX: &str = "._z2-manifest-";
const MANIFEST_VERSION: u32 = 1;
const TREE_FANOUT: u64 = 256;
const MAX_TREE_HEIGHT: u8 = 7;
const MAX_INDEX_CIPHERTEXT: u64 = 64 * 1024 * 1024;
const MAX_METADATA_OBJECT: u64 = 64 * 1024;
pub(crate) const MAX_ROOT_CIPHERTEXT: u64 = MAX_METADATA_OBJECT + V1_CIPHERTEXT_OVERHEAD;
const MAX_MANIFEST_CIPHERTEXT: u64 = 256 * 1024;
const OBJECT_AAD_PREFIX: &[u8] = b"zerotrust-drive\0v2\0object\0";
const ROOT_AAD: &[u8] = b"zerotrust-drive\0v2\0root\0";
const MANIFEST_AAD: &[u8] = b"zerotrust-drive\0v2\0normal-write-manifest\0";

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, Hash)]
pub(crate) struct ObjectRef {
    id: [u8; 16],
    digest: [u8; 32],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ObjectKind {
    Data,
    Tree,
    FileRoot,
    Index,
    Generation,
}

impl ObjectKind {
    fn tag(self) -> &'static [u8] {
        match self {
            Self::Data => b"data",
            Self::Tree => b"tree",
            Self::FileRoot => b"file-root",
            Self::Index => b"index",
            Self::Generation => b"generation",
        }
    }

    fn max_plaintext_len(self) -> u64 {
        match self {
            Self::Data => CHUNK_SIZE as u64,
            Self::Index => MAX_INDEX_CIPHERTEXT - V1_CIPHERTEXT_OVERHEAD,
            Self::Tree | Self::FileRoot | Self::Generation => MAX_METADATA_OBJECT,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RootPointer {
    magic: String,
    format_version: u32,
    generation: ObjectRef,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Generation {
    format_version: u32,
    number: u64,
    lineage_id: [u8; 16],
    index: ObjectRef,
    previous: Option<ObjectRef>,
    origin: Option<ObjectRef>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct FileRoot {
    format_version: u32,
    size: u64,
    height: u8,
    tree: Option<ObjectRef>,
}

impl FileRoot {
    fn empty() -> Self {
        Self {
            format_version: FORMAT_VERSION,
            size: 0,
            height: 0,
            tree: None,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct TreeNode {
    format_version: u32,
    height: u8,
    slots: Vec<TreeSlot>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct TreeSlot {
    slot: u8,
    child: ObjectRef,
}

#[derive(Clone, Debug)]
pub(crate) struct CommitState {
    pub(crate) number: u64,
    pub(crate) generation: ObjectRef,
    pub(crate) parent: Option<ObjectRef>,
    pub(crate) origin: Option<ObjectRef>,
    pub(crate) lineage_id: [u8; 16],
    pub(crate) root_fingerprint: RecoveryFingerprint,
}

#[derive(Debug)]
pub(crate) struct CommitFailure {
    pub(crate) error: std::io::Error,
    pub(crate) recovery_required: bool,
    pub(crate) own_intent_may_be_durable: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct WriteManifest {
    manifest_version: u32,
    transaction_id: [u8; 16],
    kdf_fingerprint: RecoveryFingerprint,
    old_root: Option<RecoveryFingerprint>,
    new_root: RecoveryFingerprint,
    previous_generation: Option<ObjectRef>,
    origin_generation: Option<ObjectRef>,
    new_generation: ObjectRef,
    generation_number: u64,
    lineage_id: [u8; 16],
    root_ready_name: String,
    manifest_ready_name: String,
}

fn io_invalid(message: impl Into<String>) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidData, message.into())
}

fn to_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}

fn from_hex<const N: usize>(value: &str) -> Option<[u8; N]> {
    if value.len() != N * 2 {
        return None;
    }
    let mut result = [0u8; N];
    for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        let nibble = |byte: u8| match byte {
            b'0'..=b'9' => Some(byte - b'0'),
            b'a'..=b'f' => Some(byte - b'a' + 10),
            _ => None,
        };
        result[index] = (nibble(pair[0])? << 4) | nibble(pair[1])?;
    }
    Some(result)
}

fn digest_bytes(bytes: &[u8]) -> [u8; 32] {
    Blake2s256::digest(bytes).into()
}

fn object_name(id: &[u8; 16]) -> String {
    format!("{}.z2", to_hex(id))
}

fn selected_object_directory(base_path: &Path) -> std::io::Result<PathBuf> {
    let current = base_path.join(OBJECT_DIRECTORY);
    let legacy = base_path.join(LEGACY_OBJECT_DIRECTORY);
    match (
        backing_entry_exists(&current)?,
        backing_entry_exists(&legacy)?,
    ) {
        (true, true) => Err(std::io::Error::new(
            std::io::ErrorKind::AlreadyExists,
            format!(
                "both current {} and legacy {} v2 object directories exist; preserve both and reconcile the provider conflict",
                current.display(),
                legacy.display()
            ),
        )),
        (false, true) => Ok(legacy),
        _ => Ok(current),
    }
}

pub(crate) fn ensure_unambiguous_object_directory(base_path: &Path) -> std::io::Result<()> {
    selected_object_directory(base_path).map(|_| ())
}

fn object_path(base_path: &Path, reference: &ObjectRef) -> std::io::Result<PathBuf> {
    Ok(selected_object_directory(base_path)?
        .join(OBJECTS_DIRECTORY)
        .join(object_name(&reference.id)))
}

fn object_aad(kind: ObjectKind, id: &[u8; 16]) -> Vec<u8> {
    let mut aad = Vec::with_capacity(OBJECT_AAD_PREFIX.len() + kind.tag().len() + 1 + id.len());
    aad.extend_from_slice(OBJECT_AAD_PREFIX);
    aad.extend_from_slice(kind.tag());
    aad.push(0);
    aad.extend_from_slice(id);
    aad
}

pub(crate) fn encode_file_root(reference: &ObjectRef) -> String {
    format!("z2:{}:{}", to_hex(&reference.id), to_hex(&reference.digest))
}

pub(crate) fn decode_file_root(value: &str) -> Option<ObjectRef> {
    let mut parts = value.split(':');
    if parts.next()? != "z2" {
        return None;
    }
    let id = from_hex(parts.next()?)?;
    let digest = from_hex(parts.next()?)?;
    if parts.next().is_some() {
        return None;
    }
    Some(ObjectRef { id, digest })
}

fn ensure_directory(path: &Path, parent: &Path) -> std::io::Result<()> {
    match fs::create_dir(path) {
        Ok(()) => {
            fault::checkpoint(DurabilityEvent::Write, "create v2 directory")?;
            File::open(parent)?.sync_all()?;
            fault::checkpoint(DurabilityEvent::DirectorySync, "persist v2 directory")?;
        }
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(error) => return Err(error),
    }
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.file_type().is_dir() || metadata.file_type().is_symlink() {
        return Err(io_invalid(format!(
            "{} is not a real v2 backing directory",
            path.display()
        )));
    }
    Ok(())
}

pub(crate) fn ensure_layout(base_path: &Path) -> std::io::Result<()> {
    let v2 = selected_object_directory(base_path)?;
    ensure_directory(&v2, base_path)?;
    ensure_directory(&v2.join(OBJECTS_DIRECTORY), &v2)?;
    ensure_directory(&v2.join(EVIDENCE_DIRECTORY), &v2)
}

fn open_new_file(path: &Path) -> std::io::Result<File> {
    let mut options = OpenOptions::new();
    options.create_new(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW);
    }
    options.open(path)
}

pub(crate) fn write_new_file(path: &Path, bytes: &[u8], context: &str) -> std::io::Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| io_invalid("v2 target has no parent directory"))?;
    let mut file = open_new_file(path)?;
    file.write_all(bytes)?;
    fault::checkpoint(DurabilityEvent::Write, context)?;
    file.sync_all()?;
    fault::checkpoint(DurabilityEvent::FileSync, context)?;
    drop(file);
    File::open(parent)?.sync_all()?;
    fault::checkpoint(DurabilityEvent::DirectorySync, context)
}

fn read_bounded_regular(path: &Path, max_len: u64) -> std::io::Result<Vec<u8>> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW);
    }
    let file = options.open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.len() > max_len {
        return Err(io_invalid(format!(
            "{} is not a bounded regular file ({} bytes; maximum {max_len})",
            path.display(),
            metadata.len()
        )));
    }
    let capacity = usize::try_from(metadata.len())
        .map_err(|_| std::io::Error::from_raw_os_error(libc::EFBIG))?;
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(capacity)
        .map_err(|_| std::io::Error::from_raw_os_error(libc::ENOMEM))?;
    file.take(max_len.saturating_add(1))
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 != metadata.len() {
        return Err(io_invalid(format!(
            "{} changed size while being read",
            path.display()
        )));
    }
    Ok(bytes)
}

fn write_object(
    base_path: &Path,
    key: &[u8; 32],
    kind: ObjectKind,
    plaintext: &[u8],
) -> std::io::Result<ObjectRef> {
    if plaintext.len() as u64 > kind.max_plaintext_len() {
        return Err(std::io::Error::from_raw_os_error(libc::EFBIG));
    }
    ensure_layout(base_path)?;
    loop {
        let mut id = [0u8; 16];
        OsRng.fill_bytes(&mut id);
        let ciphertext =
            encrypt_bytes(key, plaintext, &object_aad(kind, &id)).map_err(std::io::Error::other)?;
        let reference = ObjectRef {
            id,
            digest: digest_bytes(&ciphertext),
        };
        let path = object_path(base_path, &reference)?;
        match write_new_file(&path, &ciphertext, "publish immutable v2 object") {
            Ok(()) => return Ok(reference),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(error),
        }
    }
}

fn read_object(
    base_path: &Path,
    key: &[u8; 32],
    kind: ObjectKind,
    reference: &ObjectRef,
) -> std::io::Result<Vec<u8>> {
    let max_ciphertext = kind
        .max_plaintext_len()
        .checked_add(V1_CIPHERTEXT_OVERHEAD)
        .ok_or_else(|| std::io::Error::from_raw_os_error(libc::EFBIG))?;
    let path = object_path(base_path, reference)?;
    let ciphertext = read_bounded_regular(&path, max_ciphertext)?;
    if digest_bytes(&ciphertext) != reference.digest {
        return Err(io_invalid(format!(
            "immutable v2 object {} has the wrong complete ciphertext digest",
            path.display()
        )));
    }
    let plaintext = decrypt_bytes_owned(key, ciphertext, &object_aad(kind, &reference.id))
        .map_err(io_invalid)?;
    if plaintext.len() as u64 > kind.max_plaintext_len() {
        return Err(io_invalid("authenticated v2 object exceeds its type bound"));
    }
    Ok(plaintext)
}

fn serialize_metadata<T: Serialize>(value: &T, label: &str) -> std::io::Result<Vec<u8>> {
    let bytes = serde_json::to_vec(value)
        .map_err(|error| io_invalid(format!("serialize v2 {label}: {error}")))?;
    if bytes.len() as u64 > MAX_METADATA_OBJECT {
        return Err(std::io::Error::from_raw_os_error(libc::EFBIG));
    }
    Ok(bytes)
}

fn read_tree(
    base_path: &Path,
    key: &[u8; 32],
    reference: &ObjectRef,
    expected_height: u8,
) -> std::io::Result<TreeNode> {
    let bytes = read_object(base_path, key, ObjectKind::Tree, reference)?;
    let node: TreeNode = serde_json::from_slice(&bytes)
        .map_err(|error| io_invalid(format!("parse authenticated v2 tree node: {error}")))?;
    if node.format_version != FORMAT_VERSION || node.height != expected_height {
        return Err(io_invalid("v2 tree node version/height mismatch"));
    }
    if node.slots.is_empty() || node.slots.len() > TREE_FANOUT as usize {
        return Err(io_invalid("v2 tree node has an invalid fanout"));
    }
    let mut previous = None;
    for entry in &node.slots {
        if previous.is_some_and(|slot| slot >= entry.slot) {
            return Err(io_invalid("v2 tree slots are not strictly ordered"));
        }
        previous = Some(entry.slot);
    }
    Ok(node)
}

fn write_tree(base_path: &Path, key: &[u8; 32], node: &TreeNode) -> std::io::Result<ObjectRef> {
    write_object(
        base_path,
        key,
        ObjectKind::Tree,
        &serialize_metadata(node, "tree node")?,
    )
}

fn digit(chunk_index: u64, height: u8) -> u8 {
    ((chunk_index >> (u32::from(height) * 8)) & 0xff) as u8
}

fn required_height(chunk_index: u64) -> u8 {
    let mut value = chunk_index;
    let mut height = 0u8;
    while value >= TREE_FANOUT {
        value >>= 8;
        height += 1;
    }
    height
}

fn find_child(node: &TreeNode, slot: u8) -> Option<ObjectRef> {
    node.slots
        .binary_search_by_key(&slot, |entry| entry.slot)
        .ok()
        .map(|index| node.slots[index].child)
}

fn get_chunk_ref(
    base_path: &Path,
    key: &[u8; 32],
    mut node_ref: Option<ObjectRef>,
    mut height: u8,
    chunk_index: u64,
) -> std::io::Result<Option<ObjectRef>> {
    // A short tree addresses only 256^(height + 1) chunks. Without this
    // guard, the radix digits of a far sparse read would wrap and could alias
    // a populated low chunk after a truncate-only growth.
    if required_height(chunk_index) > height {
        return Ok(None);
    }
    while let Some(reference) = node_ref {
        let node = read_tree(base_path, key, &reference, height)?;
        node_ref = find_child(&node, digit(chunk_index, height));
        if height == 0 {
            return Ok(node_ref);
        }
        height -= 1;
    }
    Ok(None)
}

fn cow_set_chunk(
    base_path: &Path,
    key: &[u8; 32],
    node_ref: Option<ObjectRef>,
    height: u8,
    chunk_index: u64,
    data_ref: Option<ObjectRef>,
) -> std::io::Result<Option<ObjectRef>> {
    let mut node = match node_ref {
        Some(reference) => read_tree(base_path, key, &reference, height)?,
        None => TreeNode {
            format_version: FORMAT_VERSION,
            height,
            slots: Vec::new(),
        },
    };
    let slot = digit(chunk_index, height);
    let old_child = find_child(&node, slot);
    let child = if height == 0 {
        data_ref
    } else {
        cow_set_chunk(base_path, key, old_child, height - 1, chunk_index, data_ref)?
    };
    match node.slots.binary_search_by_key(&slot, |entry| entry.slot) {
        Ok(index) => match child {
            Some(child) => node.slots[index].child = child,
            None => {
                node.slots.remove(index);
            }
        },
        Err(index) => {
            if let Some(child) = child {
                node.slots.insert(index, TreeSlot { slot, child });
            }
        }
    }
    if node.slots.is_empty() {
        Ok(None)
    } else {
        write_tree(base_path, key, &node).map(Some)
    }
}

fn grow_tree(
    base_path: &Path,
    key: &[u8; 32],
    mut tree: Option<ObjectRef>,
    mut current_height: u8,
    required: u8,
) -> std::io::Result<(Option<ObjectRef>, u8)> {
    if required > MAX_TREE_HEIGHT {
        return Err(std::io::Error::from_raw_os_error(libc::EFBIG));
    }
    while current_height < required {
        if let Some(child) = tree {
            tree = Some(write_tree(
                base_path,
                key,
                &TreeNode {
                    format_version: FORMAT_VERSION,
                    height: current_height + 1,
                    slots: vec![TreeSlot { slot: 0, child }],
                },
            )?);
        }
        current_height += 1;
    }
    Ok((tree, current_height))
}

fn load_file_root(
    base_path: &Path,
    key: &[u8; 32],
    encoded: &str,
    expected_size: u64,
) -> std::io::Result<FileRoot> {
    if encoded.is_empty() {
        if expected_size == 0 {
            return Ok(FileRoot::empty());
        }
        return Err(io_invalid(
            "nonempty v2 file has no authenticated file root",
        ));
    }
    let reference = decode_file_root(encoded)
        .ok_or_else(|| io_invalid("v2 file has an invalid authenticated root reference"))?;
    let bytes = read_object(base_path, key, ObjectKind::FileRoot, &reference)?;
    let root: FileRoot = serde_json::from_slice(&bytes)
        .map_err(|error| io_invalid(format!("parse authenticated v2 file root: {error}")))?;
    if root.format_version != FORMAT_VERSION
        || root.size != expected_size
        || root.height > MAX_TREE_HEIGHT
        || (root.tree.is_none() && root.height != 0)
    {
        return Err(io_invalid("authenticated v2 file root is inconsistent"));
    }
    Ok(root)
}

fn write_file_root(base_path: &Path, key: &[u8; 32], root: &FileRoot) -> std::io::Result<String> {
    let reference = write_object(
        base_path,
        key,
        ObjectKind::FileRoot,
        &serialize_metadata(root, "file root")?,
    )?;
    Ok(encode_file_root(&reference))
}

fn load_chunk(
    base_path: &Path,
    key: &[u8; 32],
    root: &FileRoot,
    chunk_index: u64,
) -> std::io::Result<Vec<u8>> {
    let Some(reference) = get_chunk_ref(base_path, key, root.tree, root.height, chunk_index)?
    else {
        return Ok(Vec::new());
    };
    let bytes = read_object(base_path, key, ObjectKind::Data, &reference)?;
    if bytes.len() > CHUNK_SIZE {
        return Err(io_invalid("authenticated v2 data chunk is oversized"));
    }
    Ok(bytes)
}

pub(crate) fn read_file_range(
    base_path: &Path,
    key: &[u8; 32],
    encoded_root: &str,
    file_size: u64,
    offset: u64,
    requested: usize,
) -> std::io::Result<Vec<u8>> {
    if offset >= file_size || requested == 0 {
        return Ok(Vec::new());
    }
    let root = load_file_root(base_path, key, encoded_root, file_size)?;
    let remaining = file_size - offset;
    // Cached FUSE reads must return the complete requested range except at EOF;
    // otherwise the kernel substitutes zeroes for the missing tail. The
    // negotiated request ceiling bounds this response, while the loop below
    // retains only one decrypted data chunk at a time.
    let result_len = usize::try_from(remaining.min(requested as u64))
        .map_err(|_| std::io::Error::from_raw_os_error(libc::EFBIG))?;
    if result_len > MAX_FUSE_READ_SIZE {
        return Err(std::io::Error::from_raw_os_error(libc::EFBIG));
    }
    let mut result = Vec::new();
    result
        .try_reserve_exact(result_len)
        .map_err(|_| std::io::Error::from_raw_os_error(libc::ENOMEM))?;
    result.resize(result_len, 0);

    let mut result_offset = 0usize;
    while result_offset < result.len() {
        let absolute = offset
            .checked_add(result_offset as u64)
            .ok_or_else(|| std::io::Error::from_raw_os_error(libc::EFBIG))?;
        let chunk_index = absolute / CHUNK_SIZE as u64;
        let within = (absolute % CHUNK_SIZE as u64) as usize;
        let take = (CHUNK_SIZE - within).min(result.len() - result_offset);
        let chunk = load_chunk(base_path, key, &root, chunk_index)?;
        if within < chunk.len() {
            let available = take.min(chunk.len() - within);
            result[result_offset..result_offset + available]
                .copy_from_slice(&chunk[within..within + available]);
        }
        result_offset += take;
    }
    Ok(result)
}

pub(crate) fn write_file_range(
    base_path: &Path,
    key: &[u8; 32],
    encoded_root: &str,
    file_size: u64,
    offset: u64,
    data: &[u8],
) -> std::io::Result<(String, u64)> {
    if data.is_empty() {
        return Ok((encoded_root.to_string(), file_size));
    }
    let end = offset
        .checked_add(data.len() as u64)
        .ok_or_else(|| std::io::Error::from_raw_os_error(libc::EFBIG))?;
    let mut root = load_file_root(base_path, key, encoded_root, file_size)?;
    let last_chunk = (end - 1) / CHUNK_SIZE as u64;
    let (tree, height) = grow_tree(
        base_path,
        key,
        root.tree,
        root.height,
        required_height(last_chunk),
    )?;
    root.tree = tree;
    root.height = height;

    let mut source_offset = 0usize;
    let mut tree_changed = false;
    while source_offset < data.len() {
        let absolute = offset
            .checked_add(source_offset as u64)
            .ok_or_else(|| std::io::Error::from_raw_os_error(libc::EFBIG))?;
        let chunk_index = absolute / CHUNK_SIZE as u64;
        let within = (absolute % CHUNK_SIZE as u64) as usize;
        let take = (CHUNK_SIZE - within).min(data.len() - source_offset);
        let mut chunk = load_chunk(base_path, key, &root, chunk_index)?;
        let needed = within + take;
        let incoming = &data[source_offset..source_offset + take];
        if incoming
            .iter()
            .enumerate()
            .all(|(index, byte)| chunk.get(within + index).copied().unwrap_or(0) == *byte)
        {
            source_offset += take;
            continue;
        }
        if chunk.len() < needed {
            chunk
                .try_reserve(needed - chunk.len())
                .map_err(|_| std::io::Error::from_raw_os_error(libc::ENOMEM))?;
            chunk.resize(needed, 0);
        }
        chunk[within..needed].copy_from_slice(incoming);
        let data_ref = if chunk.iter().all(|byte| *byte == 0) {
            None
        } else {
            Some(write_object(base_path, key, ObjectKind::Data, &chunk)?)
        };
        root.tree = cow_set_chunk(
            base_path,
            key,
            root.tree,
            root.height,
            chunk_index,
            data_ref,
        )?;
        tree_changed = true;
        source_offset += take;
    }
    if root.tree.is_none() {
        root.height = 0;
    }
    let new_size = root.size.max(end);
    if !tree_changed && new_size == root.size {
        return Ok((encoded_root.to_string(), root.size));
    }
    root.size = new_size;
    let encoded = write_file_root(base_path, key, &root)?;
    Ok((encoded, root.size))
}

struct PendingTreeLevel {
    group: Option<u64>,
    slots: Vec<TreeSlot>,
}

struct StreamingTreeBuilder<'a> {
    base_path: &'a Path,
    key: &'a [u8; 32],
    levels: Vec<PendingTreeLevel>,
}

impl<'a> StreamingTreeBuilder<'a> {
    fn new(base_path: &'a Path, key: &'a [u8; 32]) -> Self {
        Self {
            base_path,
            key,
            levels: Vec::new(),
        }
    }

    fn ensure_level(&mut self, height: usize) -> std::io::Result<()> {
        while self.levels.len() <= height {
            self.levels
                .try_reserve(1)
                .map_err(|_| std::io::Error::from_raw_os_error(libc::ENOMEM))?;
            let mut slots = Vec::new();
            slots
                .try_reserve_exact(TREE_FANOUT as usize)
                .map_err(|_| std::io::Error::from_raw_os_error(libc::ENOMEM))?;
            self.levels.push(PendingTreeLevel { group: None, slots });
        }
        Ok(())
    }

    fn flush_level(&mut self, height: usize) -> std::io::Result<(u64, ObjectRef)> {
        let level = &mut self.levels[height];
        let group = level
            .group
            .take()
            .ok_or_else(|| io_invalid("cannot flush an empty streaming v2 tree level"))?;
        let slots = std::mem::take(&mut level.slots);
        let reference = write_tree(
            self.base_path,
            self.key,
            &TreeNode {
                format_version: FORMAT_VERSION,
                height: u8::try_from(height)
                    .map_err(|_| std::io::Error::from_raw_os_error(libc::EFBIG))?,
                slots,
            },
        )?;
        level
            .slots
            .try_reserve_exact(TREE_FANOUT as usize)
            .map_err(|_| std::io::Error::from_raw_os_error(libc::ENOMEM))?;
        Ok((group, reference))
    }

    fn add(&mut self, height: usize, position: u64, child: ObjectRef) -> std::io::Result<()> {
        if height > MAX_TREE_HEIGHT as usize {
            return Err(std::io::Error::from_raw_os_error(libc::EFBIG));
        }
        self.ensure_level(height)?;
        let group = position >> 8;
        if self.levels[height]
            .group
            .is_some_and(|current| current != group)
        {
            let (old_group, reference) = self.flush_level(height)?;
            self.add(height + 1, old_group, reference)?;
        }
        let level = &mut self.levels[height];
        level.group = Some(group);
        level.slots.push(TreeSlot {
            slot: (position & 0xff) as u8,
            child,
        });
        Ok(())
    }

    fn finish(mut self) -> std::io::Result<(Option<ObjectRef>, u8)> {
        if self.levels.is_empty() {
            return Ok((None, 0));
        }
        let mut height = 0usize;
        loop {
            if height >= self.levels.len() {
                return Err(io_invalid("streaming v2 tree lost its root"));
            }
            if self.levels[height].group.is_none() {
                height += 1;
                continue;
            }
            let (group, reference) = self.flush_level(height)?;
            let has_higher = self
                .levels
                .iter()
                .skip(height + 1)
                .any(|level| level.group.is_some());
            if group == 0 && !has_higher {
                return Ok((
                    Some(reference),
                    u8::try_from(height)
                        .map_err(|_| std::io::Error::from_raw_os_error(libc::EFBIG))?,
                ));
            }
            self.add(height + 1, group, reference)?;
            height += 1;
        }
    }
}

/// Convert one already-authenticated legacy plaintext into its final immutable
/// v2 tree without publishing an intermediate file root for every chunk. The
/// builder retains at most one 256-entry node per tree level.
pub(crate) fn import_authenticated_file(
    base_path: &Path,
    key: &[u8; 32],
    plaintext: &[u8],
) -> std::io::Result<String> {
    let mut builder = StreamingTreeBuilder::new(base_path, key);
    for (chunk_index, chunk) in plaintext.chunks(CHUNK_SIZE).enumerate() {
        if chunk.iter().all(|byte| *byte == 0) {
            continue;
        }
        let chunk_index = u64::try_from(chunk_index)
            .map_err(|_| std::io::Error::from_raw_os_error(libc::EFBIG))?;
        let data = write_object(base_path, key, ObjectKind::Data, chunk)?;
        builder.add(0, chunk_index, data)?;
    }
    let (tree, height) = builder.finish()?;
    let size = u64::try_from(plaintext.len())
        .map_err(|_| std::io::Error::from_raw_os_error(libc::EFBIG))?;
    if size == 0 {
        return Ok(String::new());
    }
    write_file_root(
        base_path,
        key,
        &FileRoot {
            format_version: FORMAT_VERSION,
            size,
            height,
            tree,
        },
    )
}

fn prune_after(
    base_path: &Path,
    key: &[u8; 32],
    reference: ObjectRef,
    height: u8,
    max_chunk: u64,
) -> std::io::Result<Option<ObjectRef>> {
    let original = read_tree(base_path, key, &reference, height)?;
    let max_slot = digit(max_chunk, height);
    let mut node = original.clone();
    node.slots.retain(|entry| entry.slot <= max_slot);
    if height > 0
        && let Ok(index) = node
            .slots
            .binary_search_by_key(&max_slot, |entry| entry.slot)
    {
        let child = prune_after(
            base_path,
            key,
            node.slots[index].child,
            height - 1,
            max_chunk,
        )?;
        match child {
            Some(child) => node.slots[index].child = child,
            None => {
                node.slots.remove(index);
            }
        }
    }
    if node.slots.is_empty() {
        Ok(None)
    } else if node == original {
        Ok(Some(reference))
    } else {
        write_tree(base_path, key, &node).map(Some)
    }
}

pub(crate) fn truncate_file(
    base_path: &Path,
    key: &[u8; 32],
    encoded_root: &str,
    old_size: u64,
    new_size: u64,
) -> std::io::Result<String> {
    if old_size == new_size {
        return Ok(encoded_root.to_string());
    }
    let mut root = load_file_root(base_path, key, encoded_root, old_size)?;
    if new_size == 0 {
        root.tree = None;
        root.height = 0;
    } else if new_size < old_size {
        let max_chunk = (new_size - 1) / CHUNK_SIZE as u64;
        if let Some(tree) = root.tree
            && required_height(max_chunk) <= root.height
        {
            root.tree = prune_after(base_path, key, tree, root.height, max_chunk)?;
        }
        let tail_len = (new_size % CHUNK_SIZE as u64) as usize;
        if tail_len != 0 {
            let mut tail = load_chunk(base_path, key, &root, max_chunk)?;
            if tail.len() > tail_len {
                tail.truncate(tail_len);
                let data_ref = if tail.iter().all(|byte| *byte == 0) {
                    None
                } else {
                    Some(write_object(base_path, key, ObjectKind::Data, &tail)?)
                };
                root.tree =
                    cow_set_chunk(base_path, key, root.tree, root.height, max_chunk, data_ref)?;
            }
        }
    }
    if root.tree.is_none() {
        root.height = 0;
    }
    root.size = new_size;
    write_file_root(base_path, key, &root)
}

fn write_generation(
    base_path: &Path,
    key: &[u8; 32],
    index_json: &[u8],
    previous: Option<&CommitState>,
    initial_lineage: Option<[u8; 16]>,
) -> std::io::Result<(ObjectRef, u64, [u8; 16])> {
    if index_json.len() as u64 > ObjectKind::Index.max_plaintext_len() {
        return Err(std::io::Error::from_raw_os_error(libc::EFBIG));
    }
    let index = write_object(base_path, key, ObjectKind::Index, index_json)?;
    let number = previous
        .map_or(Ok(1), |state| state.number.checked_add(1).ok_or(()))
        .map_err(|()| std::io::Error::from_raw_os_error(libc::EOVERFLOW))?;
    if previous.is_some() && initial_lineage.is_some() {
        return Err(io_invalid(
            "an existing v2 lineage cannot be replaced during commit",
        ));
    }
    let lineage_id = previous.map(|state| state.lineage_id).unwrap_or_else(|| {
        let mut lineage = [0u8; 16];
        OsRng.fill_bytes(&mut lineage);
        lineage
    });
    let lineage_id = initial_lineage.unwrap_or(lineage_id);
    let generation = Generation {
        format_version: FORMAT_VERSION,
        number,
        lineage_id,
        index,
        previous: previous.map(|state| state.generation),
        origin: previous.map(|state| state.origin.unwrap_or(state.generation)),
    };
    let reference = write_object(
        base_path,
        key,
        ObjectKind::Generation,
        &serialize_metadata(&generation, "generation")?,
    )?;
    Ok((reference, number, lineage_id))
}

fn prepare_root(
    key: &[u8; 32],
    generation: ObjectRef,
) -> std::io::Result<(Vec<u8>, RecoveryFingerprint)> {
    let pointer = RootPointer {
        magic: ROOT_MAGIC.to_string(),
        format_version: FORMAT_VERSION,
        generation,
    };
    let plaintext = serialize_metadata(&pointer, "root pointer")?;
    let ciphertext = encrypt_bytes(key, &plaintext, ROOT_AAD).map_err(std::io::Error::other)?;
    let fingerprint = ciphertext_bytes_fingerprint(&ciphertext).map_err(std::io::Error::other)?;
    Ok((ciphertext, fingerprint))
}

fn root_fingerprint(base_path: &Path) -> std::io::Result<Option<RecoveryFingerprint>> {
    let path = base_path.join(ROOT_FILE);
    match fs::symlink_metadata(&path) {
        Ok(_) => {
            let bytes = read_bounded_backing_file(&path, MAX_ROOT_CIPHERTEXT)?;
            ciphertext_bytes_fingerprint(&bytes)
                .map(Some)
                .map_err(std::io::Error::other)
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error),
    }
}

fn validate_manifest(manifest: &WriteManifest) -> std::io::Result<()> {
    let transaction_hex = to_hex(&manifest.transaction_id);
    let canonical_ready_names = manifest.root_ready_name
        == format!("{ROOT_READY_PREFIX}{transaction_hex}.ready")
        && manifest.manifest_ready_name
            == format!("{MANIFEST_READY_PREFIX}{transaction_hex}.ready");
    let legacy_ready_names = manifest.root_ready_name
        == format!("{LEGACY_ROOT_READY_PREFIX}{transaction_hex}.ready")
        && manifest.manifest_ready_name
            == format!("{LEGACY_MANIFEST_READY_PREFIX}{transaction_hex}.ready");
    if manifest.manifest_version != MANIFEST_VERSION
        || manifest.generation_number == 0
        || (manifest.generation_number == 1
            && (manifest.previous_generation.is_some() || manifest.origin_generation.is_some()))
        || (manifest.generation_number > 1
            && (manifest.previous_generation.is_none() || manifest.origin_generation.is_none()))
        || !manifest.kdf_fingerprint.is_exact()
        || manifest
            .old_root
            .as_ref()
            .is_some_and(|value| !value.has_full_content_identity())
        || !manifest.new_root.has_full_content_identity()
        || (!canonical_ready_names && !legacy_ready_names)
    {
        return Err(io_invalid("authenticated v2 write manifest is malformed"));
    }
    Ok(())
}

fn decode_manifest_ciphertext(
    key: &[u8; 32],
    ciphertext: Vec<u8>,
) -> std::io::Result<WriteManifest> {
    let plaintext = decrypt_bytes_owned(key, ciphertext, MANIFEST_AAD)
        .map_err(|error| io_invalid(format!("authenticate v2 write manifest: {error}")))?;
    let manifest: WriteManifest = serde_json::from_slice(&plaintext)
        .map_err(|error| io_invalid(format!("parse authenticated v2 write manifest: {error}")))?;
    validate_manifest(&manifest)?;
    Ok(manifest)
}

/// Validate retained normal-write manifests before treating an absent
/// canonical manifest as a completed transaction. This closes the race where
/// a sync provider replaces `_write.manifest` between our byte comparison and
/// namespace move: the raced bytes remain under the transaction-bound
/// retained name and are rejected here on the next mount.
fn audit_manifest_evidence(base_path: &Path, key: &[u8; 32]) -> std::io::Result<()> {
    let evidence = selected_object_directory(base_path)?.join(EVIDENCE_DIRECTORY);
    let entries = match fs::read_dir(&evidence) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error),
    };
    for entry in entries {
        let entry = entry?;
        let Some(name) = entry.file_name().to_str().map(str::to_string) else {
            return Err(io_invalid(
                "v2 evidence directory contains a non-UTF-8 entry",
            ));
        };
        let Some(rest) = name.strip_prefix("normal-") else {
            continue;
        };
        let transaction_hex = rest
            .get(..32)
            .ok_or_else(|| io_invalid("v2 evidence has a truncated transaction name"))?;
        let transaction_id = from_hex::<16>(transaction_hex)
            .ok_or_else(|| io_invalid("v2 manifest evidence has an invalid transaction name"))?;
        let suffix = rest
            .get(32..)
            .ok_or_else(|| io_invalid("v2 evidence has an invalid transaction name"))?;
        let numbered_retained = |value: &str| {
            value.strip_prefix("retained-").is_some_and(|number| {
                !number.is_empty() && number.bytes().all(|byte| byte.is_ascii_digit())
            })
        };
        let manifest_suffix = suffix.strip_prefix("-manifest.");
        let manifest_ready_suffix = suffix.strip_prefix("-manifest-ready.");
        let root_suffix = suffix.strip_prefix("-root.");
        let allowed = manifest_suffix.is_some_and(|value| {
            value == "durable" || value == "retained" || numbered_retained(value)
        }) || manifest_ready_suffix
            .is_some_and(|value| value == "retained" || numbered_retained(value))
            || root_suffix.is_some_and(|value| value == "retained" || numbered_retained(value));
        if !allowed {
            return Err(io_invalid(format!(
                "v2 evidence directory contains an unexpected or provider-conflicted transaction entry {name:?}"
            )));
        }
        let Some(manifest_suffix) = manifest_suffix else {
            if let Some(ready_suffix) = manifest_ready_suffix {
                let ciphertext = read_bounded_regular(&entry.path(), MAX_MANIFEST_CIPHERTEXT)?;
                let manifest = decode_manifest_ciphertext(key, ciphertext).map_err(|error| {
                    io_invalid(format!(
                        "retained v2 manifest-ready evidence {} is not authentic: {error}",
                        entry.path().display()
                    ))
                })?;
                if manifest.transaction_id != transaction_id {
                    return Err(io_invalid(format!(
                        "retained v2 manifest-ready evidence {} is bound to a different transaction",
                        entry.path().display()
                    )));
                }
                debug_assert!(ready_suffix == "retained" || numbered_retained(ready_suffix));
            }
            continue;
        };
        let ciphertext = read_bounded_regular(&entry.path(), MAX_MANIFEST_CIPHERTEXT)?;
        let manifest = decode_manifest_ciphertext(key, ciphertext.clone()).map_err(|error| {
            io_invalid(format!(
                "retained v2 manifest evidence {} is not authentic: {error}",
                entry.path().display()
            ))
        })?;
        if manifest.transaction_id != transaction_id {
            return Err(io_invalid(format!(
                "retained v2 manifest evidence {} is bound to a different transaction",
                entry.path().display()
            )));
        }
        if manifest_suffix != "durable" {
            let durable = evidence.join(format!("normal-{transaction_hex}-manifest.durable"));
            let expected =
                read_bounded_regular(&durable, MAX_MANIFEST_CIPHERTEXT).map_err(|error| {
                    io_invalid(format!(
                        "retained v2 manifest evidence {} has no readable durable anchor: {error}",
                        entry.path().display()
                    ))
                })?;
            if ciphertext != expected {
                return Err(io_invalid(format!(
                    "retained v2 manifest evidence {} differs from its durable transaction anchor",
                    entry.path().display()
                )));
            }
        }
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn rename_noreplace(source: &Path, target: &Path) -> std::io::Result<()> {
    use std::os::unix::ffi::OsStrExt;
    let source = CString::new(source.as_os_str().as_bytes())?;
    let target = CString::new(target.as_os_str().as_bytes())?;
    let result = unsafe {
        libc::renameat2(
            libc::AT_FDCWD,
            source.as_ptr(),
            libc::AT_FDCWD,
            target.as_ptr(),
            libc::RENAME_NOREPLACE,
        )
    };
    if result == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

#[cfg(target_os = "macos")]
fn rename_noreplace(source: &Path, target: &Path) -> std::io::Result<()> {
    use std::os::unix::ffi::OsStrExt;
    let source = CString::new(source.as_os_str().as_bytes())?;
    let target = CString::new(target.as_os_str().as_bytes())?;
    let result = unsafe {
        libc::renameatx_np(
            libc::AT_FDCWD,
            source.as_ptr(),
            libc::AT_FDCWD,
            target.as_ptr(),
            libc::RENAME_EXCL,
        )
    };
    if result == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn rename_noreplace(_source: &Path, _target: &Path) -> std::io::Result<()> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "atomic no-replace rename is unavailable",
    ))
}

#[cfg(target_os = "linux")]
fn rename_exchange(first: &Path, second: &Path) -> std::io::Result<()> {
    use std::os::unix::ffi::OsStrExt;
    let first = CString::new(first.as_os_str().as_bytes())?;
    let second = CString::new(second.as_os_str().as_bytes())?;
    let result = unsafe {
        libc::renameat2(
            libc::AT_FDCWD,
            first.as_ptr(),
            libc::AT_FDCWD,
            second.as_ptr(),
            libc::RENAME_EXCHANGE,
        )
    };
    if result == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

#[cfg(target_os = "macos")]
fn rename_exchange(first: &Path, second: &Path) -> std::io::Result<()> {
    use std::os::unix::ffi::OsStrExt;
    let first = CString::new(first.as_os_str().as_bytes())?;
    let second = CString::new(second.as_os_str().as_bytes())?;
    let result = unsafe {
        libc::renameatx_np(
            libc::AT_FDCWD,
            first.as_ptr(),
            libc::AT_FDCWD,
            second.as_ptr(),
            libc::RENAME_SWAP,
        )
    };
    if result == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn rename_exchange(_first: &Path, _second: &Path) -> std::io::Result<()> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "atomic exchange rename is unavailable",
    ))
}

pub(crate) fn publish_noreplace(source: &Path, target: &Path) -> std::io::Result<bool> {
    match rename_noreplace(source, target) {
        Ok(()) => {
            fault::checkpoint(DurabilityEvent::Rename, "publish authenticated v2 manifest")?;
            Ok(false)
        }
        Err(rename_error) if rename_error.kind() == std::io::ErrorKind::AlreadyExists => {
            Err(rename_error)
        }
        Err(rename_error) => match fs::hard_link(source, target) {
            Ok(()) => {
                fault::checkpoint(DurabilityEvent::Rename, "publish authenticated v2 manifest")?;
                Ok(true)
            }
            Err(link_error) => Err(std::io::Error::other(format!(
                "cannot publish {} without replacement (no-replace rename: {rename_error}; hard link: {link_error})",
                target.display()
            ))),
        },
    }
}

fn fingerprint_file(path: &Path, max_len: u64) -> std::io::Result<RecoveryFingerprint> {
    let bytes = read_bounded_regular(path, max_len)?;
    ciphertext_bytes_fingerprint(&bytes).map_err(std::io::Error::other)
}

/// Publish the staged root without ever overwriting unexamined bytes. Updates
/// exchange the staged and canonical names atomically, leaving the displaced
/// old root at the staging name. An initial generation uses no-replace
/// publication. Thus every namespace state contains either the complete old
/// root, the complete new root, or both.
fn publish_root(
    base_path: &Path,
    root_ready: &Path,
    manifest: &WriteManifest,
) -> std::io::Result<bool> {
    let root_path = base_path.join(ROOT_FILE);
    if root_fingerprint(base_path)? != manifest.old_root
        || fingerprint_file(root_ready, MAX_ROOT_CIPHERTEXT)? != manifest.new_root
    {
        return Err(io_invalid(
            "canonical or staged v2 root changed immediately before atomic publication",
        ));
    }
    let retained_ready = if manifest.old_root.is_some() {
        rename_exchange(root_ready, &root_path)?;
        fault::checkpoint(
            DurabilityEvent::Rename,
            "atomically exchange authenticated v2 root",
        )?;
        true
    } else {
        publish_noreplace(root_ready, &root_path)?
    };
    File::open(base_path)?.sync_all()?;
    fault::checkpoint(
        DurabilityEvent::DirectorySync,
        "persist authenticated v2 root publication",
    )?;

    // Inspect the displaced name first. If it is the exact old root, we can
    // safely restore it even when the new canonical name became unreadable due
    // to a same-path provider race.
    let displaced = if retained_ready {
        fingerprint_file(root_ready, MAX_ROOT_CIPHERTEXT).map(Some)
    } else {
        Ok(None)
    };
    let canonical = root_fingerprint(base_path);
    let expected_displaced = manifest.old_root.as_ref().unwrap_or(&manifest.new_root);
    if canonical
        .as_ref()
        .is_ok_and(|value| value.as_ref() == Some(&manifest.new_root))
        && displaced
            .as_ref()
            .is_ok_and(|value| !retained_ready || value.as_ref() == Some(expected_displaced))
    {
        return Ok(retained_ready);
    }

    // If the atomic exchange displaced the exact authenticated old root, put
    // it back before failing. Whatever raced into the canonical name is moved
    // to the staging name and remains evidence. A crash around either exchange
    // is still recoverable from the durable manifest.
    if manifest.old_root.is_some()
        && displaced
            .as_ref()
            .is_ok_and(|value| value.as_ref() == manifest.old_root.as_ref())
        && backing_entry_exists(root_ready)?
        && backing_entry_exists(&root_path)?
    {
        rename_exchange(root_ready, &root_path)?;
        fault::checkpoint(
            DurabilityEvent::Rename,
            "roll back conflicted authenticated v2 root exchange",
        )?;
        File::open(base_path)?.sync_all()?;
        fault::checkpoint(
            DurabilityEvent::DirectorySync,
            "persist conflicted v2 root rollback",
        )?;
    }
    Err(io_invalid(
        "v2 root publication encountered changed canonical or staging bytes; preserving all generations and transaction evidence",
    ))
}

fn evidence_path(base_path: &Path, stem: &str, suffix: &str) -> std::io::Result<PathBuf> {
    if stem.is_empty()
        || stem.len() > 160
        || !stem
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        return Err(io_invalid("invalid v2 evidence name"));
    }
    Ok(selected_object_directory(base_path)?
        .join(EVIDENCE_DIRECTORY)
        .join(format!("{stem}.{suffix}")))
}

fn retained_fingerprint(
    base_path: &Path,
    evidence_stem: &str,
    max_len: u64,
) -> std::io::Result<Option<RecoveryFingerprint>> {
    let retained = evidence_path(base_path, evidence_stem, "retained")?;
    match read_bounded_regular(&retained, max_len) {
        Ok(bytes) => ciphertext_bytes_fingerprint(&bytes)
            .map(Some)
            .map_err(std::io::Error::other),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error),
    }
}

fn verify_retained(path: &Path, expected: &[u8]) -> std::io::Result<()> {
    let actual = read_bounded_regular(path, expected.len() as u64)?;
    if actual != expected {
        return Err(io_invalid(format!(
            "retained transaction evidence {} differs from its authenticated expected bytes",
            path.display()
        )));
    }
    Ok(())
}

pub(crate) fn retain_known_file(
    base_path: &Path,
    path: &Path,
    expected: &[u8],
    evidence_stem: &str,
    context: &str,
) -> std::io::Result<()> {
    ensure_layout(base_path)?;
    let retained = evidence_path(base_path, evidence_stem, "retained")?;
    match read_bounded_regular(path, expected.len() as u64) {
        Ok(actual) if actual == expected => {}
        Ok(_) => {
            return Err(io_invalid(format!(
                "refusing to retain changed v2 transaction evidence as if it were known {}",
                path.display()
            )));
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return match backing_entry_exists(&retained)? {
                true => verify_retained(&retained, expected),
                false => Ok(()),
            };
        }
        Err(error) => return Err(error),
    }
    // A crash after destination-directory fsync but before source-directory
    // fsync may legitimately replay the old source name while an exact retained
    // name is already durable. Move each replay to a monotonically numbered,
    // transaction-bound duplicate instead of unlinking it. Normal cleanup uses
    // only `.retained`; extra names are created only after such a replay.
    let target = if !backing_entry_exists(&retained)? {
        retained
    } else {
        verify_retained(&retained, expected)?;
        let mut duplicate = None;
        for number in 1..=1024u16 {
            let candidate = evidence_path(base_path, evidence_stem, &format!("retained-{number}"))?;
            if backing_entry_exists(&candidate)? {
                verify_retained(&candidate, expected)?;
            } else {
                duplicate = Some(candidate);
                break;
            }
        }
        duplicate.ok_or_else(|| io_invalid("too many replayed v2 evidence names"))?
    };
    let source_parent = path
        .parent()
        .ok_or_else(|| io_invalid("v2 transaction evidence has no parent directory"))?;
    let evidence = selected_object_directory(base_path)?.join(EVIDENCE_DIRECTORY);
    rename_noreplace(path, &target)?;
    fault::checkpoint(DurabilityEvent::Rename, context)?;
    fault::checkpoint(DurabilityEvent::Cleanup, context)?;
    File::open(&evidence)?.sync_all()?;
    fault::checkpoint(DurabilityEvent::DirectorySync, context)?;
    if source_parent != evidence {
        File::open(source_parent)?.sync_all()?;
        fault::checkpoint(DurabilityEvent::DirectorySync, context)?;
    }
    verify_retained(&target, expected)
}

pub(crate) fn retain_untrusted_file(
    base_path: &Path,
    path: &Path,
    evidence_stem: &str,
    context: &str,
) -> std::io::Result<()> {
    ensure_layout(base_path)?;
    let retained = evidence_path(base_path, evidence_stem, "untrusted")?;
    if !backing_entry_exists(path)? {
        return Ok(());
    }
    let target = if !backing_entry_exists(&retained)? {
        retained
    } else {
        let mut duplicate = None;
        for number in 1..=1024u16 {
            let candidate =
                evidence_path(base_path, evidence_stem, &format!("untrusted-{number}"))?;
            if !backing_entry_exists(&candidate)? {
                duplicate = Some(candidate);
                break;
            }
        }
        duplicate.ok_or_else(|| io_invalid("too many replayed untrusted v2 evidence names"))?
    };
    let source_parent = path
        .parent()
        .ok_or_else(|| io_invalid("untrusted v2 evidence has no parent directory"))?;
    let evidence = selected_object_directory(base_path)?.join(EVIDENCE_DIRECTORY);
    rename_noreplace(path, &target)?;
    fault::checkpoint(DurabilityEvent::Rename, context)?;
    fault::checkpoint(DurabilityEvent::Cleanup, context)?;
    File::open(&evidence)?.sync_all()?;
    fault::checkpoint(DurabilityEvent::DirectorySync, context)?;
    if source_parent != evidence {
        File::open(source_parent)?.sync_all()?;
        fault::checkpoint(DurabilityEvent::DirectorySync, context)?;
    }
    Ok(())
}

fn retain_manifest_last(
    base_path: &Path,
    path: &Path,
    expected: &[u8],
    evidence_stem: &str,
) -> std::io::Result<()> {
    ensure_layout(base_path)?;
    let durable = evidence_path(base_path, evidence_stem, "durable")?;
    match fs::hard_link(path, &durable) {
        Ok(()) => {
            fault::checkpoint(
                DurabilityEvent::Write,
                "create durable v2 manifest evidence link",
            )?;
        }
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            verify_retained(&durable, expected)?;
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            verify_retained(&durable, expected)?;
            return Ok(());
        }
        Err(link_error) => match write_new_file(
            &durable,
            expected,
            "write durable v2 manifest evidence copy",
        ) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                verify_retained(&durable, expected)?;
            }
            Err(error) => {
                return Err(std::io::Error::other(format!(
                    "cannot preserve durable manifest evidence (hard link: {link_error}; copy: {error})"
                )));
            }
        },
    }
    verify_retained(&durable, expected)?;
    File::open(&durable)?.sync_all()?;
    fault::checkpoint(
        DurabilityEvent::FileSync,
        "persist durable v2 manifest evidence link",
    )?;
    let evidence = selected_object_directory(base_path)?.join(EVIDENCE_DIRECTORY);
    File::open(&evidence)?.sync_all()?;
    fault::checkpoint(
        DurabilityEvent::DirectorySync,
        "persist durable v2 manifest evidence name",
    )?;
    retain_known_file(
        base_path,
        path,
        expected,
        evidence_stem,
        "retain committed v2 write manifest last",
    )
}

fn read_manifest(
    base_path: &Path,
    key: &[u8; 32],
) -> std::io::Result<Option<(WriteManifest, Vec<u8>)>> {
    let path = base_path.join(WRITE_MANIFEST);
    let ciphertext = match read_bounded_regular(&path, MAX_MANIFEST_CIPHERTEXT) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    };
    let manifest = decode_manifest_ciphertext(key, ciphertext.clone())?;
    Ok(Some((manifest, ciphertext)))
}

pub(crate) fn authenticate_recovery_intent_before_probe(
    base_path: &Path,
    key: &[u8; 32],
    kdf_fingerprint: &RecoveryFingerprint,
) -> std::io::Result<()> {
    audit_manifest_evidence(base_path, key)?;
    let Some((manifest, _)) = read_manifest(base_path, key)? else {
        return Err(io_invalid(
            "v2 recovery intent disappeared before atomic-exchange preflight",
        ));
    };
    if &manifest.kdf_fingerprint != kdf_fingerprint {
        return Err(io_invalid(
            "KDF metadata differs from the authenticated v2 write manifest",
        ));
    }
    let current = root_fingerprint(base_path)?;
    if current != manifest.old_root && current.as_ref() != Some(&manifest.new_root) {
        return Err(io_invalid(
            "canonical v2 root is neither the authenticated old nor new generation",
        ));
    }
    Ok(())
}

fn read_generation_record(
    base_path: &Path,
    key: &[u8; 32],
    reference: ObjectRef,
) -> std::io::Result<Generation> {
    let generation_bytes = read_object(base_path, key, ObjectKind::Generation, &reference)?;
    let generation: Generation = serde_json::from_slice(&generation_bytes)
        .map_err(|error| io_invalid(format!("parse authenticated v2 generation: {error}")))?;
    if generation.format_version != FORMAT_VERSION || generation.number == 0 {
        return Err(io_invalid("authenticated v2 generation is malformed"));
    }
    if generation.previous == Some(reference) {
        return Err(io_invalid("authenticated v2 generation references itself"));
    }
    if (generation.number == 1 && (generation.previous.is_some() || generation.origin.is_some()))
        || (generation.number > 1 && (generation.previous.is_none() || generation.origin.is_none()))
    {
        return Err(io_invalid(
            "authenticated v2 generation has inconsistent parent/origin metadata",
        ));
    }
    Ok(generation)
}

fn load_generation(
    base_path: &Path,
    key: &[u8; 32],
    reference: ObjectRef,
) -> std::io::Result<(Generation, DiskIndex)> {
    let generation = read_generation_record(base_path, key, reference)?;
    let index_bytes = read_object(base_path, key, ObjectKind::Index, &generation.index)?;
    let index: DiskIndex = serde_json::from_slice(&index_bytes)
        .map_err(|error| io_invalid(format!("parse authenticated v2 index: {error}")))?;
    validate_disk_index_v2(&index).map_err(io_invalid)?;
    Ok((generation, index))
}

fn load_root_bytes(
    base_path: &Path,
    key: &[u8; 32],
    ciphertext: Vec<u8>,
) -> std::io::Result<(DiskIndex, CommitState)> {
    let fingerprint = ciphertext_bytes_fingerprint(&ciphertext).map_err(std::io::Error::other)?;
    let plaintext = decrypt_bytes_owned(key, ciphertext, ROOT_AAD).map_err(io_invalid)?;
    let pointer: RootPointer = serde_json::from_slice(&plaintext)
        .map_err(|error| io_invalid(format!("parse authenticated v2 root: {error}")))?;
    if pointer.magic != ROOT_MAGIC || pointer.format_version != FORMAT_VERSION {
        return Err(io_invalid(
            "authenticated v2 root has an unsupported format",
        ));
    }
    let (generation, index) = load_generation(base_path, key, pointer.generation)?;
    Ok((
        index,
        CommitState {
            number: generation.number,
            generation: pointer.generation,
            parent: generation.previous,
            origin: generation.origin,
            lineage_id: generation.lineage_id,
            root_fingerprint: fingerprint,
        },
    ))
}

pub(crate) fn load(base_path: &Path, key: &[u8; 32]) -> std::io::Result<(DiskIndex, CommitState)> {
    let path = base_path.join(ROOT_FILE);
    let ciphertext = read_bounded_backing_file(&path, MAX_ROOT_CIPHERTEXT)?;
    load_root_bytes(base_path, key, ciphertext)
}

pub(crate) fn validate_lineage_origin(
    base_path: &Path,
    key: &[u8; 32],
    current: &CommitState,
    origin: ObjectRef,
    lineage_id: [u8; 16],
) -> std::io::Result<()> {
    if current.lineage_id != lineage_id || current.number == 0 {
        return Err(io_invalid("current v2 generation has the wrong lineage"));
    }
    let current_origin = current.origin.unwrap_or(current.generation);
    if current_origin != origin {
        return Err(io_invalid(
            "current v2 generation has a different authenticated origin",
        ));
    }
    let origin_generation = read_generation_record(base_path, key, origin)?;
    if origin_generation.number != 1
        || origin_generation.previous.is_some()
        || origin_generation.origin.is_some()
        || origin_generation.lineage_id != lineage_id
    {
        return Err(io_invalid(
            "authenticated migration origin is not a valid first v2 generation",
        ));
    }
    Ok(())
}

pub(crate) fn validate_migration_target(
    base_path: &Path,
    key: &[u8; 32],
    current: &CommitState,
    lineage_id: [u8; 16],
    expected_index: &DiskIndex,
) -> std::io::Result<ObjectRef> {
    let origin = current.origin.unwrap_or(current.generation);
    validate_lineage_origin(base_path, key, current, origin, lineage_id)?;
    let (_, origin_index) = load_generation(base_path, key, origin)?;
    if &origin_index != expected_index {
        return Err(io_invalid(
            "authenticated v2 lineage origin differs from the migration plan and receipts",
        ));
    }
    Ok(origin)
}

fn commit_with_phase_and_lineage(
    base_path: &Path,
    key: &[u8; 32],
    index_json: &[u8],
    previous: Option<&CommitState>,
    kdf_fingerprint: &RecoveryFingerprint,
    initial_lineage: Option<[u8; 16]>,
) -> Result<CommitState, CommitFailure> {
    let mut recovery_required = false;
    let mut own_intent_may_be_durable = false;
    let result = (|| -> std::io::Result<CommitState> {
        match backing_entry_exists(&base_path.join(WRITE_MANIFEST)) {
            Ok(true) => {
                recovery_required = true;
                return Err(io_invalid(
                    "an authenticated v2 write manifest is already pending recovery",
                ));
            }
            Ok(false) => {}
            Err(error) => {
                return Err(error);
            }
        }
        let expected_old = previous.map(|state| state.root_fingerprint.clone());
        if root_fingerprint(base_path)? != expected_old {
            recovery_required = true;
            return Err(io_invalid(
                "v2 root changed before copy-on-write generation preparation",
            ));
        }
        let (generation, number, lineage_id) =
            write_generation(base_path, key, index_json, previous, initial_lineage)?;
        let (root_ciphertext, new_root) = prepare_root(key, generation)?;

        let mut transaction_id = [0u8; 16];
        OsRng.fill_bytes(&mut transaction_id);
        let transaction_hex = to_hex(&transaction_id);
        let root_ready_name = format!("{ROOT_READY_PREFIX}{transaction_hex}.ready");
        let manifest_ready_name = format!("{MANIFEST_READY_PREFIX}{transaction_hex}.ready");
        let root_ready = base_path.join(&root_ready_name);
        write_new_file(&root_ready, &root_ciphertext, "stage authenticated v2 root")?;

        let manifest = WriteManifest {
            manifest_version: MANIFEST_VERSION,
            transaction_id,
            kdf_fingerprint: kdf_fingerprint.clone(),
            old_root: expected_old.clone(),
            new_root: new_root.clone(),
            previous_generation: previous.map(|state| state.generation),
            origin_generation: previous.map(|state| state.origin.unwrap_or(state.generation)),
            new_generation: generation,
            generation_number: number,
            lineage_id,
            root_ready_name,
            manifest_ready_name: manifest_ready_name.clone(),
        };
        let evidence_prefix = format!("normal-{}", to_hex(&manifest.transaction_id));
        validate_manifest(&manifest)?;
        let manifest_json = serde_json::to_vec(&manifest)
            .map_err(|error| io_invalid(format!("serialize v2 write manifest: {error}")))?;
        let manifest_ciphertext =
            encrypt_bytes(key, &manifest_json, MANIFEST_AAD).map_err(std::io::Error::other)?;
        if manifest_ciphertext.len() as u64 > MAX_MANIFEST_CIPHERTEXT {
            return Err(std::io::Error::from_raw_os_error(libc::EFBIG));
        }
        let manifest_ready = base_path.join(&manifest_ready_name);
        write_new_file(
            &manifest_ready,
            &manifest_ciphertext,
            "stage authenticated v2 write manifest",
        )?;
        let manifest_path = base_path.join(WRITE_MANIFEST);
        if root_fingerprint(base_path)? != expected_old {
            recovery_required = true;
            return Err(io_invalid(
                "v2 root changed during generation preparation; refusing to publish write intent",
            ));
        }
        if let Err(error) = ensure_no_index_siblings(base_path) {
            if error.kind() == std::io::ErrorKind::AlreadyExists {
                recovery_required = true;
            }
            return Err(error);
        }
        let pre_intent_kdf = exact_fingerprint(&base_path.join("_kdf.json")).map_err(|error| {
            io_invalid(format!(
                "cannot revalidate KDF immediately before v2 write intent: {error}"
            ))
        })?;
        if &pre_intent_kdf != kdf_fingerprint {
            recovery_required = true;
            return Err(io_invalid(
                "KDF metadata changed during generation preparation; refusing to publish write intent",
            ));
        }
        // From this point onward, even an error returned immediately after a
        // completed namespace operation may have published authenticated intent.
        // The caller must latch read-only and recover before retrying.
        recovery_required = true;
        let retained_ready = match publish_noreplace(&manifest_ready, &manifest_path) {
            Ok(retained) => {
                own_intent_may_be_durable = true;
                retained
            }
            Err(error) => {
                own_intent_may_be_durable =
                    read_bounded_regular(&manifest_path, MAX_MANIFEST_CIPHERTEXT)
                        .is_ok_and(|actual| actual == manifest_ciphertext);
                return Err(error);
            }
        };
        File::open(base_path)?.sync_all()?;
        fault::checkpoint(
            DurabilityEvent::DirectorySync,
            "persist authenticated v2 write manifest",
        )?;
        if retained_ready {
            retain_known_file(
                base_path,
                &manifest_ready,
                &manifest_ciphertext,
                &format!("{evidence_prefix}-manifest-ready"),
                "retain published v2 manifest staging evidence",
            )?;
        }

        if root_fingerprint(base_path)? != expected_old {
            return Err(io_invalid(
                "v2 root changed after manifest publication; preserving all transaction evidence",
            ));
        }
        ensure_no_index_siblings(base_path)?;
        let actual_kdf = exact_fingerprint(&base_path.join("_kdf.json")).map_err(|error| {
            io_invalid(format!(
                "cannot revalidate KDF metadata before v2 root publication: {error}"
            ))
        })?;
        if &actual_kdf != kdf_fingerprint {
            return Err(io_invalid(
                "KDF metadata changed after manifest publication; preserving all transaction evidence",
            ));
        }
        let retained_root_ready = publish_root(base_path, &root_ready, &manifest)?;
        ensure_no_index_siblings(base_path)?;
        let actual_kdf = exact_fingerprint(&base_path.join("_kdf.json")).map_err(|error| {
            io_invalid(format!(
                "cannot revalidate KDF metadata after v2 root publication: {error}"
            ))
        })?;
        if &actual_kdf != kdf_fingerprint {
            return Err(io_invalid(
                "KDF metadata changed across v2 root publication; preserving both roots and all transaction evidence",
            ));
        }
        if retained_root_ready {
            let expected = manifest.old_root.as_ref().unwrap_or(&manifest.new_root);
            let displaced = read_bounded_regular(&root_ready, MAX_ROOT_CIPHERTEXT)?;
            if ciphertext_bytes_fingerprint(&displaced).map_err(std::io::Error::other)? != *expected
            {
                return Err(io_invalid(
                    "displaced v2 root changed before evidence retention; preserving the write manifest",
                ));
            }
            retain_known_file(
                base_path,
                &root_ready,
                &displaced,
                &format!("{evidence_prefix}-root"),
                "retain displaced authenticated v2 root evidence",
            )?;
        }
        if root_fingerprint(base_path)?.as_ref() != Some(&new_root) {
            return Err(io_invalid(
                "canonical v2 root changed before manifest-last completion; preserving transaction evidence",
            ));
        }
        ensure_no_index_siblings(base_path)?;
        if exact_fingerprint(&base_path.join("_kdf.json"))
            .map_err(|error| io_invalid(format!("revalidate KDF before manifest-last: {error}")))?
            != *kdf_fingerprint
        {
            return Err(io_invalid(
                "KDF metadata changed before manifest-last completion; preserving transaction evidence",
            ));
        }
        retain_manifest_last(
            base_path,
            &manifest_path,
            &manifest_ciphertext,
            &format!("{evidence_prefix}-manifest"),
        )?;
        Ok(CommitState {
            number,
            generation,
            parent: previous.map(|state| state.generation),
            origin: manifest.origin_generation,
            lineage_id: manifest.lineage_id,
            root_fingerprint: new_root,
        })
    })();
    result.map_err(|error| CommitFailure {
        error,
        recovery_required,
        own_intent_may_be_durable,
    })
}

pub(crate) fn commit_with_phase(
    base_path: &Path,
    key: &[u8; 32],
    index_json: &[u8],
    previous: Option<&CommitState>,
    kdf_fingerprint: &RecoveryFingerprint,
) -> Result<CommitState, CommitFailure> {
    commit_with_phase_and_lineage(base_path, key, index_json, previous, kdf_fingerprint, None)
}

pub(crate) fn commit_initial_lineage(
    base_path: &Path,
    key: &[u8; 32],
    index_json: &[u8],
    kdf_fingerprint: &RecoveryFingerprint,
    lineage_id: [u8; 16],
) -> std::io::Result<CommitState> {
    commit_with_phase_and_lineage(
        base_path,
        key,
        index_json,
        None,
        kdf_fingerprint,
        Some(lineage_id),
    )
    .map_err(|failure| failure.error)
}

#[cfg(test)]
pub(crate) fn commit(
    base_path: &Path,
    key: &[u8; 32],
    index_json: &[u8],
    previous: Option<&CommitState>,
    kdf_fingerprint: &RecoveryFingerprint,
) -> std::io::Result<CommitState> {
    commit_with_phase(base_path, key, index_json, previous, kdf_fingerprint)
        .map_err(|failure| failure.error)
}

pub(crate) fn recover(
    base_path: &Path,
    key: &[u8; 32],
    kdf_fingerprint: &RecoveryFingerprint,
) -> std::io::Result<bool> {
    audit_manifest_evidence(base_path, key)?;
    let Some((manifest, manifest_ciphertext)) = read_manifest(base_path, key)? else {
        return Ok(false);
    };
    let evidence_prefix = format!("normal-{}", to_hex(&manifest.transaction_id));
    ensure_no_index_siblings(base_path)?;
    fault::checkpoint(DurabilityEvent::Recovery, "authenticate v2 write intent")?;
    if &manifest.kdf_fingerprint != kdf_fingerprint {
        return Err(io_invalid(
            "KDF metadata differs from the authenticated v2 write manifest",
        ));
    }
    let root_ready = base_path.join(&manifest.root_ready_name);
    let manifest_ready = base_path.join(&manifest.manifest_ready_name);
    let root_evidence_stem = format!("{evidence_prefix}-root");
    let current = root_fingerprint(base_path)?;
    let retained_root_ready;
    if current == manifest.old_root {
        match &manifest.old_root {
            Some(_) => {
                let (_old_index, old_state) = load(base_path, key)?;
                if Some(old_state.generation) != manifest.previous_generation
                    || old_state.number.checked_add(1) != Some(manifest.generation_number)
                    || old_state.lineage_id != manifest.lineage_id
                    || Some(old_state.origin.unwrap_or(old_state.generation))
                        != manifest.origin_generation
                {
                    return Err(io_invalid(
                        "authenticated v2 recovery intent is not a direct child of the canonical old generation",
                    ));
                }
            }
            None => {
                if manifest.previous_generation.is_some() || manifest.generation_number != 1 {
                    return Err(io_invalid(
                        "authenticated initial v2 recovery intent has a parent generation",
                    ));
                }
            }
        }
        let ready = read_bounded_regular(&root_ready, MAX_ROOT_CIPHERTEXT)?;
        let ready_fingerprint =
            ciphertext_bytes_fingerprint(&ready).map_err(std::io::Error::other)?;
        if ready_fingerprint != manifest.new_root {
            return Err(io_invalid(
                "staged v2 root differs from authenticated recovery intent",
            ));
        }
        let (ready_index, state) = load_root_bytes(base_path, key, ready)?;
        if state.generation != manifest.new_generation
            || state.number != manifest.generation_number
            || state.parent != manifest.previous_generation
            || state.origin != manifest.origin_generation
            || state.lineage_id != manifest.lineage_id
        {
            return Err(io_invalid(
                "staged v2 root generation differs from authenticated recovery intent",
            ));
        }
        validate_disk_index_v2(&ready_index).map_err(io_invalid)?;
        validate_reachable_v2_files(base_path, key, &ready_index).map_err(|error| {
            io_invalid(format!(
                "staged v2 recovery generation is not completely materialized: {error}"
            ))
        })?;
        fault::checkpoint(DurabilityEvent::Recovery, "validate old v2 generation")?;
        retained_root_ready = publish_root(base_path, &root_ready, &manifest)?;
    } else if current != Some(manifest.new_root.clone()) {
        return Err(io_invalid(
            "canonical v2 root is neither the authenticated old nor new generation; preserving conflict evidence",
        ));
    } else {
        retained_root_ready = backing_entry_exists(&root_ready)?;
        if retained_root_ready {
            let expected = manifest.old_root.as_ref().unwrap_or(&manifest.new_root);
            if fingerprint_file(&root_ready, MAX_ROOT_CIPHERTEXT)? != *expected {
                return Err(io_invalid(
                    "v2 root staging name differs from the authenticated displaced root; preserving all evidence",
                ));
            }
        } else {
            let retained =
                retained_fingerprint(base_path, &root_evidence_stem, MAX_ROOT_CIPHERTEXT)?;
            let expected = manifest.old_root.as_ref().unwrap_or(&manifest.new_root);
            if retained.as_ref().is_some_and(|actual| actual != expected) {
                return Err(io_invalid(
                    "retained v2 root evidence differs from the authenticated write manifest",
                ));
            }
            if manifest.old_root.is_some() && retained.is_none() {
                return Err(io_invalid(
                    "authenticated old v2 root is missing from both its staging and retained evidence names",
                ));
            }
        }
    }
    ensure_no_index_siblings(base_path)?;
    let actual_kdf = exact_fingerprint(&base_path.join("_kdf.json")).map_err(|error| {
        io_invalid(format!(
            "cannot revalidate KDF metadata during v2 recovery: {error}"
        ))
    })?;
    if &actual_kdf != kdf_fingerprint {
        return Err(io_invalid(
            "KDF metadata changed during v2 recovery; preserving both roots and all transaction evidence",
        ));
    }
    fault::checkpoint(DurabilityEvent::Recovery, "validate new v2 generation")?;
    let (index, state) = load(base_path, key)?;
    validate_disk_index_v2(&index).map_err(io_invalid)?;
    validate_reachable_v2_files(base_path, key, &index).map_err(|error| {
        io_invalid(format!(
            "canonical v2 recovery generation is not completely materialized: {error}"
        ))
    })?;
    if state.generation != manifest.new_generation
        || state.number != manifest.generation_number
        || state.lineage_id != manifest.lineage_id
    {
        return Err(io_invalid(
            "canonical v2 root does not name the authenticated recovery generation",
        ));
    }
    if state.parent != manifest.previous_generation {
        return Err(io_invalid(
            "canonical v2 generation parent differs from authenticated recovery intent",
        ));
    }
    if state.origin != manifest.origin_generation {
        return Err(io_invalid(
            "canonical v2 generation origin differs from authenticated recovery intent",
        ));
    }

    if retained_root_ready {
        let expected = manifest.old_root.as_ref().unwrap_or(&manifest.new_root);
        let displaced = read_bounded_regular(&root_ready, MAX_ROOT_CIPHERTEXT)?;
        if ciphertext_bytes_fingerprint(&displaced).map_err(std::io::Error::other)? != *expected {
            return Err(io_invalid(
                "displaced v2 root changed before recovery evidence retention",
            ));
        }
        retain_known_file(
            base_path,
            &root_ready,
            &displaced,
            &root_evidence_stem,
            "retain verified displaced v2 root evidence",
        )?;
    }
    if backing_entry_exists(&manifest_ready)? {
        retain_known_file(
            base_path,
            &manifest_ready,
            &manifest_ciphertext,
            &format!("{evidence_prefix}-manifest-ready"),
            "retain verified duplicate v2 manifest staging evidence",
        )?;
    }
    if root_fingerprint(base_path)?.as_ref() != Some(&manifest.new_root) {
        return Err(io_invalid(
            "canonical v2 root changed before recovery manifest-last completion",
        ));
    }
    ensure_no_index_siblings(base_path)?;
    if exact_fingerprint(&base_path.join("_kdf.json")).map_err(|error| {
        io_invalid(format!(
            "revalidate KDF before recovery manifest-last: {error}"
        ))
    })? != *kdf_fingerprint
    {
        return Err(io_invalid(
            "KDF metadata changed before recovery manifest-last completion",
        ));
    }
    retain_manifest_last(
        base_path,
        &base_path.join(WRITE_MANIFEST),
        &manifest_ciphertext,
        &format!("{evidence_prefix}-manifest"),
    )?;
    fault::checkpoint(DurabilityEvent::Recovery, "finish v2 recovery")?;
    Ok(true)
}

pub(crate) fn validate_reachable_file(
    base_path: &Path,
    key: &[u8; 32],
    encoded_root: &str,
    size: u64,
) -> std::io::Result<()> {
    let root = load_file_root(base_path, key, encoded_root, size)?;
    if size == 0 && root.tree.is_some() {
        return Err(io_invalid("empty v2 file retains a data tree"));
    }
    let Some(last_chunk) = size.checked_sub(1).map(|last| last / CHUNK_SIZE as u64) else {
        return Ok(());
    };
    let tail_len = ((size - 1) % CHUNK_SIZE as u64 + 1) as usize;
    fn visit(
        base_path: &Path,
        key: &[u8; 32],
        reference: ObjectRef,
        height: u8,
        prefix: u64,
        last_chunk: u64,
        tail_len: usize,
    ) -> std::io::Result<()> {
        let node = read_tree(base_path, key, &reference, height)?;
        for slot in node.slots {
            let chunk_prefix = prefix | (u64::from(slot.slot) << (u32::from(height) * 8));
            if chunk_prefix > last_chunk {
                return Err(io_invalid("v2 file tree references data beyond EOF"));
            }
            if height == 0 {
                let chunk = read_object(base_path, key, ObjectKind::Data, &slot.child)?;
                let maximum = if chunk_prefix == last_chunk {
                    tail_len
                } else {
                    CHUNK_SIZE
                };
                if chunk.is_empty() || chunk.len() > maximum || chunk.iter().all(|byte| *byte == 0)
                {
                    return Err(io_invalid(
                        "v2 file tree references a noncanonical or oversized data chunk",
                    ));
                }
            } else {
                visit(
                    base_path,
                    key,
                    slot.child,
                    height - 1,
                    chunk_prefix,
                    last_chunk,
                    tail_len,
                )?;
            }
        }
        Ok(())
    }
    if let Some(tree) = root.tree {
        visit(base_path, key, tree, root.height, 0, last_chunk, tail_len)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{FORMAT_VERSION as KDF_FORMAT_VERSION, KdfParams, SALT_LEN, derive_key};
    use crate::fault::{DurabilityEvent, FaultInjectionGuard};
    use crate::fs::{DirChild, InodeEntry, InodeKind};
    use std::collections::HashMap;
    use std::sync::atomic::{AtomicU64, Ordering};

    static TEST_ID: AtomicU64 = AtomicU64::new(0);

    fn test_directory(label: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "zerotrust-drive-v2-{label}-{}-{}",
            std::process::id(),
            TEST_ID.fetch_add(1, Ordering::Relaxed)
        ))
    }

    fn test_key() -> [u8; 32] {
        derive_key(
            "v2-test-passphrase",
            &KdfParams {
                format_version: KDF_FORMAT_VERSION,
                algorithm: "argon2id".to_string(),
                salt: vec![7; SALT_LEN],
                m_cost: 8,
                t_cost: 1,
                p_cost: 1,
            },
        )
    }

    fn kdf_fingerprint() -> RecoveryFingerprint {
        RecoveryFingerprint::Exact {
            bytes: b"authenticated-test-kdf".to_vec(),
        }
    }

    #[test]
    fn manifest_validation_accepts_legacy_appledouble_staging_names_only_as_a_pair() {
        let transaction_id = [0xabu8; 16];
        let transaction_hex = to_hex(&transaction_id);
        let reference = ObjectRef {
            id: [1; 16],
            digest: [2; 32],
        };
        let root = ciphertext_bytes_fingerprint(&[3; 40]).unwrap();
        let mut manifest = WriteManifest {
            manifest_version: MANIFEST_VERSION,
            transaction_id,
            kdf_fingerprint: kdf_fingerprint(),
            old_root: None,
            new_root: root,
            previous_generation: None,
            origin_generation: None,
            new_generation: reference,
            generation_number: 1,
            lineage_id: [4; 16],
            root_ready_name: format!("{ROOT_READY_PREFIX}{transaction_hex}.ready"),
            manifest_ready_name: format!("{MANIFEST_READY_PREFIX}{transaction_hex}.ready"),
        };
        validate_manifest(&manifest).unwrap();

        manifest.root_ready_name = format!("{LEGACY_ROOT_READY_PREFIX}{transaction_hex}.ready");
        manifest.manifest_ready_name =
            format!("{LEGACY_MANIFEST_READY_PREFIX}{transaction_hex}.ready");
        validate_manifest(&manifest).unwrap();

        manifest.manifest_ready_name = format!("{MANIFEST_READY_PREFIX}{transaction_hex}.ready");
        assert!(validate_manifest(&manifest).is_err());
    }

    #[test]
    fn legacy_dot_object_directory_remains_readable_and_writable() {
        let directory = test_directory("legacy-object-directory");
        fs::create_dir_all(directory.join(LEGACY_OBJECT_DIRECTORY)).unwrap();
        ensure_layout(&directory).unwrap();
        assert_eq!(
            selected_object_directory(&directory).unwrap(),
            directory.join(LEGACY_OBJECT_DIRECTORY)
        );
        assert!(!directory.join(OBJECT_DIRECTORY).exists());

        let key = test_key();
        let (root, size) = write_file_range(&directory, &key, "", 0, 0, b"legacy").unwrap();
        assert_eq!(
            read_file_range(&directory, &key, &root, size, 0, 6).unwrap(),
            b"legacy"
        );
        assert!(
            fs::read_dir(
                directory
                    .join(LEGACY_OBJECT_DIRECTORY)
                    .join(OBJECTS_DIRECTORY)
            )
            .unwrap()
            .next()
            .is_some()
        );

        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn simultaneous_current_and_legacy_object_directories_are_preserved_as_conflict() {
        let directory = test_directory("dual-object-directories");
        fs::create_dir_all(directory.join(OBJECT_DIRECTORY)).unwrap();
        fs::create_dir_all(directory.join(LEGACY_OBJECT_DIRECTORY)).unwrap();

        let error = ensure_layout(&directory).unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::AlreadyExists);
        assert!(directory.join(OBJECT_DIRECTORY).exists());
        assert!(directory.join(LEGACY_OBJECT_DIRECTORY).exists());

        fs::remove_dir_all(directory).unwrap();
    }

    fn index_with_file(name: &str) -> DiskIndex {
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
        let file = InodeEntry {
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
        };
        DiskIndex {
            next_inode: 3,
            next_file_id: 1,
            inodes: HashMap::from([(1, root), (2, file)]),
            children: HashMap::from([(
                1,
                vec![DirChild {
                    name: name.to_string(),
                    inode: 2,
                }],
            )]),
        }
    }

    fn copy_directory(source: &Path, destination: &Path) {
        fs::create_dir_all(destination).unwrap();
        for entry in fs::read_dir(source).unwrap() {
            let entry = entry.unwrap();
            let target = destination.join(entry.file_name());
            if entry.file_type().unwrap().is_dir() {
                copy_directory(&entry.path(), &target);
            } else {
                fs::copy(entry.path(), target).unwrap();
            }
        }
    }

    fn commit_index(
        directory: &Path,
        key: &[u8; 32],
        index: &DiskIndex,
        previous: Option<&CommitState>,
    ) -> std::io::Result<CommitState> {
        let kdf_path = directory.join("_kdf.json");
        if !kdf_path.exists() {
            fs::write(&kdf_path, b"authenticated-test-kdf")?;
        }
        let json = serde_json::to_vec(index).unwrap();
        commit(directory, key, &json, previous, &kdf_fingerprint())
    }

    #[test]
    fn chunk_tree_random_io_and_truncate_are_file_size_independent() {
        let directory = test_directory("chunk-tree");
        fs::create_dir_all(&directory).unwrap();
        let key = test_key();

        let (low_root, low_size) = write_file_range(&directory, &key, "", 0, 0, b"head").unwrap();
        let far_sparse_size = CHUNK_SIZE as u64 * TREE_FANOUT + 4;
        let low_root =
            truncate_file(&directory, &key, &low_root, low_size, far_sparse_size).unwrap();
        assert_eq!(
            read_file_range(
                &directory,
                &key,
                &low_root,
                far_sparse_size,
                CHUNK_SIZE as u64 * TREE_FANOUT,
                4,
            )
            .unwrap(),
            b"\0\0\0\0",
            "sparse growth must not alias chunk zero at the next radix span"
        );
        assert_eq!(
            read_file_range(&directory, &key, &low_root, far_sparse_size, 0, 4).unwrap(),
            b"head"
        );

        let chunk_200 = CHUNK_SIZE as u64 * 200;
        let (short_tree, short_size) =
            write_file_range(&directory, &key, "", 0, chunk_200, b"survives").unwrap();
        let grown_size = CHUNK_SIZE as u64 * 301 + 1;
        let short_tree =
            truncate_file(&directory, &key, &short_tree, short_size, grown_size).unwrap();
        let shrunk_size = CHUNK_SIZE as u64 * 260 + 1;
        let short_tree =
            truncate_file(&directory, &key, &short_tree, grown_size, shrunk_size).unwrap();
        assert_eq!(
            read_file_range(&directory, &key, &short_tree, shrunk_size, chunk_200, 8,).unwrap(),
            b"survives",
            "shrinking above a short radix tree must not wrap the EOF digit and prune live chunks"
        );

        let first = write_object(&directory, &key, ObjectKind::Data, b"a").unwrap();
        let far = write_object(&directory, &key, ObjectKind::Data, b"b").unwrap();
        let mut builder = StreamingTreeBuilder::new(&directory, &key);
        builder.add(0, 0, first).unwrap();
        builder.add(0, 300, far).unwrap();
        let (tree, height) = builder.finish().unwrap();
        assert_eq!(height, 1);
        let streamed_size = CHUNK_SIZE as u64 * 300 + 1;
        let streamed_root = write_file_root(
            &directory,
            &key,
            &FileRoot {
                format_version: FORMAT_VERSION,
                size: streamed_size,
                height,
                tree,
            },
        )
        .unwrap();
        validate_reachable_file(&directory, &key, &streamed_root, streamed_size).unwrap();
        assert_eq!(
            read_file_range(&directory, &key, &streamed_root, streamed_size, 0, 1).unwrap(),
            b"a"
        );
        assert_eq!(
            read_file_range(
                &directory,
                &key,
                &streamed_root,
                streamed_size,
                CHUNK_SIZE as u64 * 300,
                1,
            )
            .unwrap(),
            b"b"
        );

        let zero_offset = CHUNK_SIZE as u64 * TREE_FANOUT;
        let (zero_root, zero_size) =
            write_file_range(&directory, &key, "", 0, zero_offset, b"\0\0\0\0").unwrap();
        validate_reachable_file(&directory, &key, &zero_root, zero_size).unwrap();
        assert_eq!(
            read_file_range(&directory, &key, &zero_root, zero_size, zero_offset, 4).unwrap(),
            b"\0\0\0\0"
        );
        let (populated_root, populated_size) =
            write_file_range(&directory, &key, "", 0, zero_offset, b"data").unwrap();
        let (cleared_root, cleared_size) = write_file_range(
            &directory,
            &key,
            &populated_root,
            populated_size,
            zero_offset,
            b"\0\0\0\0",
        )
        .unwrap();
        validate_reachable_file(&directory, &key, &cleared_root, cleared_size).unwrap();
        assert_eq!(
            read_file_range(
                &directory,
                &key,
                &cleared_root,
                cleared_size,
                zero_offset,
                4,
            )
            .unwrap(),
            b"\0\0\0\0"
        );

        let far_offset = CHUNK_SIZE as u64 * 3 + 17;
        let (root, size) = write_file_range(&directory, &key, "", 0, far_offset, b"tail").unwrap();
        assert_eq!(size, far_offset + 4);
        assert_eq!(
            read_file_range(&directory, &key, &root, size, far_offset - 3, 7).unwrap(),
            b"\0\0\0tail"
        );

        let (root, size) = write_file_range(
            &directory,
            &key,
            &root,
            size,
            CHUNK_SIZE as u64 - 2,
            b"abcdef",
        )
        .unwrap();
        let object_count = fs::read_dir(directory.join(OBJECT_DIRECTORY).join(OBJECTS_DIRECTORY))
            .unwrap()
            .count();
        let (same_root, same_size) = write_file_range(
            &directory,
            &key,
            &root,
            size,
            CHUNK_SIZE as u64 - 2,
            b"abcdef",
        )
        .unwrap();
        assert_eq!((same_root, same_size), (root.clone(), size));
        assert_eq!(
            fs::read_dir(directory.join(OBJECT_DIRECTORY).join(OBJECTS_DIRECTORY),)
                .unwrap()
                .count(),
            object_count,
            "an identical write must not create immutable cloud objects"
        );
        assert_eq!(
            read_file_range(&directory, &key, &root, size, CHUNK_SIZE as u64 - 4, 10,).unwrap(),
            b"\0\0abcdef\0\0"
        );

        let shrunk_size = CHUNK_SIZE as u64 + 1;
        let root = truncate_file(&directory, &key, &root, size, shrunk_size).unwrap();
        let grown_size = far_offset + 4;
        let root = truncate_file(&directory, &key, &root, shrunk_size, grown_size).unwrap();
        assert_eq!(
            read_file_range(&directory, &key, &root, grown_size, far_offset, 4).unwrap(),
            b"\0\0\0\0"
        );
        validate_reachable_file(&directory, &key, &root, grown_size).unwrap();

        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn cached_read_fills_a_complete_request_across_chunk_boundaries() {
        let directory = test_directory("cached-cross-chunk-read");
        fs::create_dir_all(&directory).unwrap();
        let key = test_key();

        let first = vec![0x5a; CHUNK_SIZE];
        let tail = vec![0xa5; 8 * 1024];
        let (root, size) = write_file_range(&directory, &key, "", 0, 0, &first).unwrap();
        let (root, size) =
            write_file_range(&directory, &key, &root, size, CHUNK_SIZE as u64, &tail).unwrap();

        let requested = CHUNK_SIZE + tail.len();
        let data = read_file_range(&directory, &key, &root, size, 0, requested).unwrap();
        assert_eq!(data.len(), requested);
        assert_eq!(&data[..CHUNK_SIZE], first.as_slice());
        assert_eq!(&data[CHUNK_SIZE..], tail.as_slice());

        let oversized = MAX_FUSE_READ_SIZE + 1;
        let sparse_root = truncate_file(&directory, &key, &root, size, oversized as u64).unwrap();
        let error = read_file_range(
            &directory,
            &key,
            &sparse_root,
            oversized as u64,
            0,
            oversized,
        )
        .unwrap_err();
        assert_eq!(error.raw_os_error(), Some(libc::EFBIG));

        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn every_commit_checkpoint_recovers_to_exact_old_or_new_generation() {
        let baseline = test_directory("crash-baseline");
        fs::create_dir_all(&baseline).unwrap();
        let key = test_key();
        let old_index = index_with_file("old.txt");
        let old_state = commit_index(&baseline, &key, &old_index, None).unwrap();
        let old_root_bytes = fs::read(baseline.join(ROOT_FILE)).unwrap();
        let new_index = index_with_file("new.txt");

        let successful = test_directory("crash-success");
        copy_directory(&baseline, &successful);
        let (_, successful_old) = load(&successful, &key).unwrap();
        let recorder = FaultInjectionGuard::record();
        commit_index(&successful, &key, &new_index, Some(&successful_old)).unwrap();
        let events = recorder.events();
        drop(recorder);
        assert!(events.contains(&DurabilityEvent::Write));
        assert!(events.contains(&DurabilityEvent::FileSync));
        assert!(events.contains(&DurabilityEvent::Rename));
        assert!(events.contains(&DurabilityEvent::DirectorySync));
        assert!(events.contains(&DurabilityEvent::Cleanup));
        fs::remove_dir_all(successful).unwrap();

        for checkpoint in 1..=events.len() {
            let crashed = test_directory(&format!("commit-crash-{checkpoint}"));
            copy_directory(&baseline, &crashed);
            fs::write(crashed.join("conflict-evidence.keep"), b"preserve me").unwrap();
            let (_, state) = load(&crashed, &key).unwrap();
            let injector = FaultInjectionGuard::fail_at(checkpoint);
            let result = commit_index(&crashed, &key, &new_index, Some(&state));
            drop(injector);
            assert!(result.is_err(), "checkpoint {checkpoint} was not exercised");

            recover(&crashed, &key, &kdf_fingerprint()).unwrap();
            let (visible, visible_state) = load(&crashed, &key).unwrap();
            assert!(
                visible == old_index || visible == new_index,
                "checkpoint {checkpoint} exposed a mixed/unknown generation"
            );
            if visible == old_index {
                assert_eq!(
                    fs::read(crashed.join(ROOT_FILE)).unwrap(),
                    old_root_bytes,
                    "checkpoint {checkpoint} changed the exact old root bytes"
                );
            } else {
                assert_eq!(visible_state.number, old_state.number + 1);
                assert_eq!(visible_state.parent, Some(old_state.generation));
                assert_eq!(visible_state.origin, Some(old_state.generation));
                assert_eq!(visible_state.lineage_id, old_state.lineage_id);
            }
            assert_eq!(
                fs::read(crashed.join("conflict-evidence.keep")).unwrap(),
                b"preserve me"
            );
            fs::remove_dir_all(crashed).unwrap();
        }

        assert_eq!(old_state.number, 1);
        fs::remove_dir_all(baseline).unwrap();
    }

    #[test]
    fn pre_intent_staging_orphans_are_preserved_without_blocking_retry() {
        let baseline = test_directory("pre-intent-orphan-baseline");
        fs::create_dir_all(&baseline).unwrap();
        let key = test_key();
        let old_index = index_with_file("old.txt");
        let old_state = commit_index(&baseline, &key, &old_index, None).unwrap();
        let new_index = index_with_file("new.txt");

        let trace = test_directory("pre-intent-orphan-trace");
        copy_directory(&baseline, &trace);
        let (_, trace_state) = load(&trace, &key).unwrap();
        let recorder = FaultInjectionGuard::record();
        commit_index(&trace, &key, &new_index, Some(&trace_state)).unwrap();
        let manifest_publish = recorder
            .events()
            .iter()
            .position(|event| *event == DurabilityEvent::Rename)
            .unwrap()
            + 1;
        drop(recorder);
        fs::remove_dir_all(trace).unwrap();

        let injector = FaultInjectionGuard::fail_at(manifest_publish - 1);
        assert!(commit_index(&baseline, &key, &new_index, Some(&old_state)).is_err());
        drop(injector);
        assert!(!baseline.join(WRITE_MANIFEST).exists());
        let orphans: Vec<_> = fs::read_dir(&baseline)
            .unwrap()
            .map(|entry| entry.unwrap())
            .filter(|entry| {
                entry
                    .file_name()
                    .to_str()
                    .is_some_and(|name| name.starts_with("_z2-") && name.ends_with(".ready"))
            })
            .map(|entry| (entry.file_name(), fs::read(entry.path()).unwrap()))
            .collect();
        assert!(orphans.len() >= 2, "root and manifest staging must survive");

        assert!(!recover(&baseline, &key, &kdf_fingerprint()).unwrap());
        commit_index(&baseline, &key, &new_index, Some(&old_state)).unwrap();
        assert_eq!(load(&baseline, &key).unwrap().0, new_index);
        for (name, bytes) in orphans {
            assert_eq!(
                fs::read(baseline.join(name)).unwrap(),
                bytes,
                "pre-intent staging evidence must not be deleted or replaced"
            );
        }

        fs::remove_dir_all(baseline).unwrap();
    }

    #[test]
    fn recovery_is_fault_injected_and_idempotent_without_discarding_evidence() {
        let baseline = test_directory("recovery-baseline");
        fs::create_dir_all(&baseline).unwrap();
        let key = test_key();
        let old_index = index_with_file("old.txt");
        let old_state = commit_index(&baseline, &key, &old_index, None).unwrap();
        let new_index = index_with_file("new.txt");

        // The first namespace event is authenticated manifest publication.
        // Fail immediately afterward to leave a durable roll-forward intent
        // while the old root remains canonical.
        let trace_dir = test_directory("recovery-trace");
        copy_directory(&baseline, &trace_dir);
        let recorder = FaultInjectionGuard::record();
        commit_index(&trace_dir, &key, &new_index, Some(&old_state)).unwrap();
        let commit_events = recorder.events();
        drop(recorder);
        fs::remove_dir_all(trace_dir).unwrap();
        let manifest_publish = commit_events
            .iter()
            .position(|event| *event == DurabilityEvent::Rename)
            .unwrap()
            + 1;

        let pending = test_directory("recovery-pending");
        copy_directory(&baseline, &pending);
        let injector = FaultInjectionGuard::fail_at(manifest_publish);
        assert!(commit_index(&pending, &key, &new_index, Some(&old_state)).is_err());
        drop(injector);
        assert!(pending.join(WRITE_MANIFEST).exists());
        assert_eq!(load(&pending, &key).unwrap().0.inodes[&2].name, "old.txt");

        let recovery_trace = test_directory("recovery-count");
        copy_directory(&pending, &recovery_trace);
        let recorder = FaultInjectionGuard::record();
        recover(&recovery_trace, &key, &kdf_fingerprint()).unwrap();
        let recovery_events = recorder.events();
        drop(recorder);
        assert!(recovery_events.contains(&DurabilityEvent::Recovery));
        fs::remove_dir_all(recovery_trace).unwrap();

        for checkpoint in 1..=recovery_events.len() {
            let crashed = test_directory(&format!("recovery-crash-{checkpoint}"));
            copy_directory(&pending, &crashed);
            fs::write(crashed.join("provider-conflict.keep"), b"evidence").unwrap();
            let injector = FaultInjectionGuard::fail_at(checkpoint);
            let result = recover(&crashed, &key, &kdf_fingerprint());
            drop(injector);
            assert!(
                result.is_err(),
                "recovery checkpoint {checkpoint} was not hit"
            );
            recover(&crashed, &key, &kdf_fingerprint()).unwrap();
            assert!(!recover(&crashed, &key, &kdf_fingerprint()).unwrap());
            assert_eq!(load(&crashed, &key).unwrap().0, new_index);
            assert_eq!(
                fs::read(crashed.join("provider-conflict.keep")).unwrap(),
                b"evidence"
            );
            fs::remove_dir_all(crashed).unwrap();
        }

        fs::remove_dir_all(pending).unwrap();
        fs::remove_dir_all(baseline).unwrap();
    }

    #[test]
    fn recovery_refuses_a_provider_root_sibling_without_discarding_it() {
        let baseline = test_directory("provider-sibling-baseline");
        fs::create_dir_all(&baseline).unwrap();
        let key = test_key();
        let old_index = index_with_file("old.txt");
        let old_state = commit_index(&baseline, &key, &old_index, None).unwrap();
        let new_index = index_with_file("new.txt");

        let trace = test_directory("provider-sibling-trace");
        copy_directory(&baseline, &trace);
        let recorder = FaultInjectionGuard::record();
        commit_index(&trace, &key, &new_index, Some(&old_state)).unwrap();
        let manifest_publish = recorder
            .events()
            .iter()
            .position(|event| *event == DurabilityEvent::Rename)
            .unwrap()
            + 1;
        drop(recorder);
        fs::remove_dir_all(trace).unwrap();

        let injector = FaultInjectionGuard::fail_at(manifest_publish);
        assert!(commit_index(&baseline, &key, &new_index, Some(&old_state)).is_err());
        drop(injector);
        let sibling = baseline.join("_root (conflicted copy).age");
        fs::write(&sibling, b"provider evidence").unwrap();

        let error = recover(&baseline, &key, &kdf_fingerprint()).unwrap_err();
        assert!(error.to_string().contains("cloud-conflict"), "{error}");
        assert_eq!(load(&baseline, &key).unwrap().0, old_index);
        assert_eq!(fs::read(&sibling).unwrap(), b"provider evidence");
        assert!(baseline.join(WRITE_MANIFEST).exists());

        fs::remove_dir_all(baseline).unwrap();
    }

    #[test]
    fn recovery_keeps_old_root_until_every_new_object_is_materialized() {
        let directory = test_directory("partial-new-generation");
        fs::create_dir_all(&directory).unwrap();
        let key = test_key();
        let old_index = index_with_file("old.txt");
        let old_state = commit_index(&directory, &key, &old_index, None).unwrap();
        let old_root = fs::read(directory.join(ROOT_FILE)).unwrap();

        let mut new_index = index_with_file("new.txt");
        let (file_root, size) =
            write_file_range(&directory, &key, "", 0, 0, b"must arrive first").unwrap();
        let root = load_file_root(&directory, &key, &file_root, size).unwrap();
        let data = get_chunk_ref(&directory, &key, root.tree, root.height, 0)
            .unwrap()
            .unwrap();
        let entry = new_index.inodes.get_mut(&2).unwrap();
        entry.disk_filename = file_root;
        entry.size = size;

        let trace = test_directory("partial-new-generation-trace");
        copy_directory(&directory, &trace);
        let recorder = FaultInjectionGuard::record();
        let (_, trace_state) = load(&trace, &key).unwrap();
        commit_index(&trace, &key, &new_index, Some(&trace_state)).unwrap();
        let manifest_publish = recorder
            .events()
            .iter()
            .position(|event| *event == DurabilityEvent::Rename)
            .unwrap()
            + 1;
        drop(recorder);
        fs::remove_dir_all(trace).unwrap();

        let injector = FaultInjectionGuard::fail_at(manifest_publish);
        assert!(commit_index(&directory, &key, &new_index, Some(&old_state)).is_err());
        drop(injector);
        assert!(directory.join(WRITE_MANIFEST).exists());
        fs::remove_file(object_path(&directory, &data).unwrap()).unwrap();

        let error = recover(&directory, &key, &kdf_fingerprint()).unwrap_err();
        assert!(
            error.to_string().contains("not completely materialized"),
            "{error}"
        );
        assert_eq!(
            fs::read(directory.join(ROOT_FILE)).unwrap(),
            old_root,
            "recovery must not publish an incomplete new generation"
        );
        assert!(directory.join(WRITE_MANIFEST).exists());

        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn remount_audits_manifest_evidence_moved_by_a_provider_race() {
        let directory = test_directory("manifest-evidence-audit");
        fs::create_dir_all(&directory).unwrap();
        let key = test_key();
        commit_index(&directory, &key, &index_with_file("committed.txt"), None).unwrap();

        let evidence = directory.join(OBJECT_DIRECTORY).join(EVIDENCE_DIRECTORY);
        let retained = fs::read_dir(&evidence)
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .find(|path| {
                path.file_name()
                    .and_then(|name| name.to_str())
                    .is_some_and(|name| {
                        name.starts_with("normal-") && name.ends_with("-manifest.retained")
                    })
            })
            .expect("successful commit must retain its canonical manifest");
        fs::remove_file(&retained).unwrap();
        fs::write(&retained, b"provider replacement evidence").unwrap();

        let error = recover(&directory, &key, &kdf_fingerprint()).unwrap_err();
        assert!(error.to_string().contains("is not authentic"), "{error}");
        assert_eq!(
            fs::read(&retained).unwrap(),
            b"provider replacement evidence",
            "foreign conflict evidence must remain available for reconciliation"
        );

        fs::remove_dir_all(directory).unwrap();
    }
}
