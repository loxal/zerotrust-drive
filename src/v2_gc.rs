// Copyright 2026 Alexander Orlov <alexander.orlov@loxal.net>

//! Evidence-aware, offline garbage collection for immutable v2 objects.
//!
//! The collector never mutates the authenticated root or an immutable object.
//! A read-only preview authenticates every strong root and the complete object
//! graph first. An explicitly confirmed operation can then move only proven
//! unreachable objects into a plan-bound quarantine. New destructive physical
//! reclaim is disabled because current platforms provide no race-free
//! exclusive-mutation primitive. Purge only validates and completes legacy
//! operations whose authenticated zero-length tombstones already exist.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};

#[cfg(unix)]
use std::os::fd::{AsRawFd, FromRawFd};
#[cfg(unix)]
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};

use serde::{Deserialize, Serialize};

use super::*;
use crate::crypto::{RecoveryFingerprint, load_kdf_with_fingerprint, try_derive_key};
use crate::fs::{InodeKind, backing_entry_exists, validate_disk_index_v2};

const GC_VERSION: u32 = 1;
const GC_DIRECTORY: &str = "gc";
const GC_QUARANTINE_DIRECTORY: &str = "quarantine";
const GC_PURGE_TOMBSTONE_DIRECTORY: &str = "purge-tombstones";
const GC_PURGE_TOMBSTONE_PREFIX: &str = "purge-";
const GC_PURGE_TOMBSTONE_SUFFIX: &str = ".tombstone";
const GC_PLAN_FILE: &str = "plan.age";
const GC_QUARANTINE_COMPLETE_FILE: &str = "quarantine.complete.age";
const GC_RESTORE_COMPLETE_FILE: &str = "restore.complete.age";
const GC_PURGE_INTENT_FILE: &str = "purge.intent.age";
const GC_PURGE_COMPLETE_FILE: &str = "purge.complete.age";
const GC_STAGE_PREFIX: &str = "gc-stage-";
const GC_STAGE_SUFFIX: &str = ".pending";
const GC_PLAN_AAD_PREFIX: &[u8] = b"zerotrust-drive\0v2\0gc-plan\0";
const GC_MARKER_AAD_PREFIX: &[u8] = b"zerotrust-drive\0v2\0gc-marker\0";
const MAX_GC_PLAN_CIPHERTEXT: u64 = 64 * 1024 * 1024;
const MAX_GC_OBJECTS: usize = 250_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum GcControlKind {
    Plan,
    Quarantine,
    Restore,
    PurgeIntent,
    Purge,
}

impl GcControlKind {
    const ALL: [Self; 5] = [
        Self::Plan,
        Self::Quarantine,
        Self::Restore,
        Self::PurgeIntent,
        Self::Purge,
    ];

    fn token(self) -> &'static str {
        match self {
            Self::Plan => "plan",
            Self::Quarantine => "quarantine",
            Self::Restore => "restore",
            Self::PurgeIntent => "purge-intent",
            Self::Purge => "purge",
        }
    }

    fn final_name(self) -> &'static str {
        match self {
            Self::Plan => GC_PLAN_FILE,
            Self::Quarantine => GC_QUARANTINE_COMPLETE_FILE,
            Self::Restore => GC_RESTORE_COMPLETE_FILE,
            Self::PurgeIntent => GC_PURGE_INTENT_FILE,
            Self::Purge => GC_PURGE_COMPLETE_FILE,
        }
    }

    fn maximum_ciphertext_len(self) -> u64 {
        match self {
            Self::Plan => MAX_GC_PLAN_CIPHERTEXT,
            Self::Quarantine | Self::Restore | Self::PurgeIntent | Self::Purge => {
                MAX_METADATA_OBJECT + V1_CIPHERTEXT_OVERHEAD
            }
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct FileIdentity {
    relative_path: String,
    ciphertext_len: u64,
    digest: [u8; 32],
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ObjectIdentity {
    reference: ObjectRef,
    ciphertext_len: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct GcPlanCore {
    format_version: u32,
    /// Legacy plans included the machine-local absolute backing path in their
    /// authenticated identity. Keep accepting that field, but omit it from new
    /// plans so an exact store can be relocated without invalidating GC
    /// evidence.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    canonical_drive_path: Option<String>,
    object_namespace: String,
    kdf_fingerprint: RecoveryFingerprint,
    anchors: Vec<FileIdentity>,
    objects: Vec<ObjectIdentity>,
    candidates: Vec<ObjectIdentity>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct GcPlan {
    gc_version: u32,
    plan_id: String,
    core: GcPlanCore,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct GcMarker {
    gc_version: u32,
    plan_id: String,
    operation: String,
}

#[derive(Clone, Debug)]
pub(crate) struct GcPreview {
    pub(crate) is_v2: bool,
    pub(crate) plan_id: Option<String>,
    pub(crate) reachable_objects: usize,
    pub(crate) candidate_objects: usize,
    pub(crate) candidate_bytes: u64,
    pub(crate) candidate_names: Vec<String>,
}

#[derive(Debug)]
struct Scan {
    plan: GcPlan,
    reachable_objects: usize,
}

struct LiveScan {
    object_namespace: String,
    anchors: Vec<FileIdentity>,
    inventory: BTreeMap<[u8; 16], ObjectIdentity>,
    expectations: HashMap<[u8; 16], (ExpectedObject, [u8; 32])>,
    protected: HashSet<[u8; 16]>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ExpectedObject {
    Data,
    Tree(u8),
    FileRoot(u64),
    Index,
    Generation,
}

struct GraphWalker<'a> {
    base_path: &'a Path,
    key: &'a [u8; 32],
    inventory: &'a BTreeMap<[u8; 16], ObjectIdentity>,
    expectations: HashMap<[u8; 16], (ExpectedObject, [u8; 32])>,
    protected: HashSet<[u8; 16]>,
    validated_orphans: HashSet<[u8; 16]>,
    visiting: HashSet<[u8; 16]>,
}

impl<'a> GraphWalker<'a> {
    fn new(
        base_path: &'a Path,
        key: &'a [u8; 32],
        inventory: &'a BTreeMap<[u8; 16], ObjectIdentity>,
    ) -> Self {
        Self {
            base_path,
            key,
            inventory,
            expectations: HashMap::new(),
            protected: HashSet::new(),
            validated_orphans: HashSet::new(),
            visiting: HashSet::new(),
        }
    }

    fn expect(&mut self, reference: ObjectRef, expected: ExpectedObject) -> std::io::Result<()> {
        let Some(actual) = self.inventory.get(&reference.id) else {
            return Err(io_invalid(format!(
                "authenticated v2 graph references missing object {}",
                object_name(&reference.id)
            )));
        };
        if actual.reference.digest != reference.digest {
            return Err(io_invalid(format!(
                "authenticated v2 graph references {} with a different digest",
                object_name(&reference.id)
            )));
        }
        if let Some((prior_kind, prior_digest)) = self.expectations.get(&reference.id) {
            if *prior_kind != expected || *prior_digest != reference.digest {
                return Err(io_invalid(format!(
                    "v2 object {} is referenced with conflicting kind, size, or digest expectations",
                    object_name(&reference.id)
                )));
            }
        } else {
            self.expectations
                .insert(reference.id, (expected, reference.digest));
        }
        Ok(())
    }

    fn walk_live(&mut self, reference: ObjectRef, expected: ExpectedObject) -> std::io::Result<()> {
        self.walk(reference, expected, true)
    }

    fn walk_orphan(
        &mut self,
        reference: ObjectRef,
        expected: ExpectedObject,
    ) -> std::io::Result<()> {
        self.walk(reference, expected, false)
    }

    fn walk(
        &mut self,
        reference: ObjectRef,
        expected: ExpectedObject,
        protect: bool,
    ) -> std::io::Result<()> {
        if expected == ExpectedObject::Generation {
            return self.walk_generation_chain(reference, protect);
        }
        self.expect(reference, expected)?;
        if protect && self.protected.contains(&reference.id) {
            return Ok(());
        }
        if !protect
            && (self.protected.contains(&reference.id)
                || self.validated_orphans.contains(&reference.id))
        {
            return Ok(());
        }
        if !self.visiting.insert(reference.id) {
            return Err(io_invalid(format!(
                "authenticated v2 object graph contains a cycle at {}",
                object_name(&reference.id)
            )));
        }
        let result = self.walk_children(reference, expected, protect);
        self.visiting.remove(&reference.id);
        result?;
        if protect {
            self.protected.insert(reference.id);
        } else {
            self.validated_orphans.insert(reference.id);
        }
        Ok(())
    }

    fn walk_generation_chain(&mut self, first: ObjectRef, protect: bool) -> std::io::Result<()> {
        let mut current = first;
        let mut chain = Vec::new();
        let mut local = HashSet::new();
        loop {
            self.expect(current, ExpectedObject::Generation)?;
            if (protect && self.protected.contains(&current.id))
                || (!protect
                    && (self.protected.contains(&current.id)
                        || self.validated_orphans.contains(&current.id)))
            {
                break;
            }
            if !local.insert(current.id) {
                return Err(io_invalid(format!(
                    "authenticated v2 generation history contains a cycle at {}",
                    object_name(&current.id)
                )));
            }
            if chain.len() >= MAX_GC_OBJECTS {
                return Err(std::io::Error::from_raw_os_error(libc::EFBIG));
            }
            let generation = read_generation_record(self.base_path, self.key, current)?;
            self.walk(generation.index, ExpectedObject::Index, protect)?;

            if let Some(origin) = generation.origin {
                self.expect(origin, ExpectedObject::Generation)?;
                let origin_record = read_generation_record(self.base_path, self.key, origin)?;
                if origin_record.number != 1
                    || origin_record.previous.is_some()
                    || origin_record.origin.is_some()
                    || origin_record.lineage_id != generation.lineage_id
                {
                    return Err(io_invalid(
                        "authenticated v2 generation names an invalid lineage origin",
                    ));
                }
            }

            chain.push(current.id);
            let Some(previous) = generation.previous else {
                break;
            };
            self.expect(previous, ExpectedObject::Generation)?;
            let previous_record = read_generation_record(self.base_path, self.key, previous)?;
            let expected_origin = previous_record.origin.unwrap_or(previous);
            if previous_record.number.checked_add(1) != Some(generation.number)
                || previous_record.lineage_id != generation.lineage_id
                || generation.origin != Some(expected_origin)
            {
                return Err(io_invalid(
                    "authenticated v2 generation history has inconsistent lineage metadata",
                ));
            }
            current = previous;
        }
        if protect {
            self.protected.extend(chain);
        } else {
            self.validated_orphans.extend(chain);
        }
        Ok(())
    }

    fn walk_children(
        &mut self,
        reference: ObjectRef,
        expected: ExpectedObject,
        protect: bool,
    ) -> std::io::Result<()> {
        match expected {
            ExpectedObject::Data => {
                let bytes = read_object(self.base_path, self.key, ObjectKind::Data, &reference)?;
                if bytes.len() > CHUNK_SIZE {
                    return Err(io_invalid("authenticated v2 data chunk is oversized"));
                }
            }
            ExpectedObject::Tree(height) => {
                let node = read_tree(self.base_path, self.key, &reference, height)?;
                for slot in node.slots {
                    let child = if height == 0 {
                        ExpectedObject::Data
                    } else {
                        ExpectedObject::Tree(height - 1)
                    };
                    self.walk(slot.child, child, protect)?;
                }
            }
            ExpectedObject::FileRoot(expected_size) => {
                let bytes =
                    read_object(self.base_path, self.key, ObjectKind::FileRoot, &reference)?;
                let root: FileRoot = serde_json::from_slice(&bytes).map_err(|error| {
                    io_invalid(format!("parse authenticated v2 file root: {error}"))
                })?;
                if root.format_version != FORMAT_VERSION
                    || root.size != expected_size
                    || root.height > MAX_TREE_HEIGHT
                    || (root.tree.is_none() && root.height != 0)
                {
                    return Err(io_invalid("authenticated v2 file root is inconsistent"));
                }
                if let Some(tree) = root.tree {
                    self.walk(tree, ExpectedObject::Tree(root.height), protect)?;
                }
            }
            ExpectedObject::Index => {
                let bytes = read_object(self.base_path, self.key, ObjectKind::Index, &reference)?;
                let index: DiskIndex = serde_json::from_slice(&bytes).map_err(|error| {
                    io_invalid(format!("parse authenticated v2 index: {error}"))
                })?;
                validate_disk_index_v2(&index).map_err(io_invalid)?;
                for entry in index
                    .inodes
                    .values()
                    .filter(|entry| entry.kind == InodeKind::File)
                {
                    if entry.disk_filename.is_empty() {
                        if entry.size != 0 {
                            return Err(io_invalid(
                                "nonempty v2 index file has no authenticated file root",
                            ));
                        }
                        continue;
                    }
                    let file_root = decode_file_root(&entry.disk_filename).ok_or_else(|| {
                        io_invalid("v2 index contains an invalid file-root reference")
                    })?;
                    self.walk(file_root, ExpectedObject::FileRoot(entry.size), protect)?;
                }
            }
            ExpectedObject::Generation => unreachable!("generation chains are iterative"),
        }
        Ok(())
    }

    fn identify_orphan(&self, identity: &ObjectIdentity) -> std::io::Result<ExpectedObject> {
        let mut authenticated = Vec::new();
        for kind in [
            ObjectKind::Data,
            ObjectKind::Tree,
            ObjectKind::FileRoot,
            ObjectKind::Index,
            ObjectKind::Generation,
        ] {
            if let Ok(bytes) = read_object(self.base_path, self.key, kind, &identity.reference) {
                authenticated.push((kind, bytes));
            }
        }
        if authenticated.len() != 1 {
            return Err(io_invalid(format!(
                "unreachable object {} does not authenticate as exactly one supported v2 object kind; preserving it",
                object_name(&identity.reference.id)
            )));
        }
        let (kind, bytes) = authenticated.pop().expect("one authenticated kind");
        match kind {
            ObjectKind::Data => Ok(ExpectedObject::Data),
            ObjectKind::Tree => {
                let tree: TreeNode = serde_json::from_slice(&bytes).map_err(|error| {
                    io_invalid(format!("parse unreachable authenticated v2 tree: {error}"))
                })?;
                if tree.format_version != FORMAT_VERSION || tree.height > MAX_TREE_HEIGHT {
                    return Err(io_invalid(
                        "unreachable authenticated v2 tree has invalid version/height",
                    ));
                }
                Ok(ExpectedObject::Tree(tree.height))
            }
            ObjectKind::FileRoot => {
                let root: FileRoot = serde_json::from_slice(&bytes).map_err(|error| {
                    io_invalid(format!(
                        "parse unreachable authenticated v2 file root: {error}"
                    ))
                })?;
                if root.format_version != FORMAT_VERSION || root.height > MAX_TREE_HEIGHT {
                    return Err(io_invalid(
                        "unreachable authenticated v2 file root is malformed",
                    ));
                }
                Ok(ExpectedObject::FileRoot(root.size))
            }
            ObjectKind::Index => Ok(ExpectedObject::Index),
            ObjectKind::Generation => Ok(ExpectedObject::Generation),
        }
    }
}

fn checked_relative(base_path: &Path, path: &Path) -> std::io::Result<String> {
    path.strip_prefix(base_path)
        .ok()
        .and_then(Path::to_str)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
        .ok_or_else(|| io_invalid("GC evidence path is not canonical UTF-8 below the drive"))
}

fn file_identity(
    base_path: &Path,
    path: &Path,
    max_len: u64,
) -> std::io::Result<(FileIdentity, Vec<u8>)> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.file_type().is_file() || metadata.file_type().is_symlink() {
        return Err(io_invalid(format!(
            "GC evidence {} is not a real regular file",
            path.display()
        )));
    }
    let bytes = read_bounded_regular(path, max_len)?;
    Ok((
        FileIdentity {
            relative_path: checked_relative(base_path, path)?,
            ciphertext_len: bytes.len() as u64,
            digest: digest_bytes(&bytes),
        },
        bytes,
    ))
}

fn inventory_objects(
    base_path: &Path,
    budget: &mut crate::v2_migrate::GcScanBudget,
) -> std::io::Result<(String, BTreeMap<[u8; 16], ObjectIdentity>)> {
    let namespace = selected_object_directory(base_path)?;
    let namespace_name = namespace
        .file_name()
        .and_then(|value| value.to_str())
        .ok_or_else(|| io_invalid("v2 object namespace has a non-UTF-8 name"))?
        .to_string();
    for directory in [
        &namespace,
        &namespace.join(OBJECTS_DIRECTORY),
        &namespace.join(EVIDENCE_DIRECTORY),
    ] {
        let metadata = fs::symlink_metadata(directory)?;
        if !metadata.file_type().is_dir() || metadata.file_type().is_symlink() {
            return Err(io_invalid(format!(
                "{} is not a real v2 backing directory",
                directory.display()
            )));
        }
    }
    for entry in fs::read_dir(&namespace)? {
        let entry = entry?;
        budget
            .charge("v2 object-namespace inventory")
            .map_err(io_invalid)?;
        let Some(name) = entry.file_name().to_str().map(str::to_string) else {
            return Err(io_invalid(
                "v2 object namespace contains a non-UTF-8 conflict artifact",
            ));
        };
        if !matches!(
            name.as_str(),
            OBJECTS_DIRECTORY | EVIDENCE_DIRECTORY | GC_DIRECTORY
        ) {
            return Err(io_invalid(format!(
                "v2 object namespace contains unexpected entry {name:?}; preserving it"
            )));
        }
    }

    let objects = namespace.join(OBJECTS_DIRECTORY);
    let mut inventory = BTreeMap::new();
    for entry in fs::read_dir(&objects)? {
        let entry = entry?;
        budget
            .charge("immutable v2 object inventory")
            .map_err(io_invalid)?;
        let Some(name) = entry.file_name().to_str().map(str::to_string) else {
            return Err(io_invalid(
                "v2 objects directory contains a non-UTF-8 entry; preserving it",
            ));
        };
        let id_hex = name.strip_suffix(".z2").ok_or_else(|| {
            io_invalid(format!(
                "v2 objects directory contains unexpected entry {name:?}; preserving it"
            ))
        })?;
        let id = from_hex::<16>(id_hex).ok_or_else(|| {
            io_invalid(format!(
                "v2 objects directory contains noncanonical object name {name:?}; preserving it"
            ))
        })?;
        let metadata = fs::symlink_metadata(entry.path())?;
        if !metadata.file_type().is_file() || metadata.file_type().is_symlink() {
            return Err(io_invalid(format!(
                "v2 object {} is not a real regular file; preserving it",
                entry.path().display()
            )));
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            if metadata.nlink() != 1 {
                return Err(io_invalid(format!(
                    "v2 object {} has {} hard links; preserving all possible conflict evidence",
                    entry.path().display(),
                    metadata.nlink()
                )));
            }
        }
        let ciphertext = read_bounded_regular(&entry.path(), MAX_INDEX_CIPHERTEXT)?;
        let identity = ObjectIdentity {
            reference: ObjectRef {
                id,
                digest: digest_bytes(&ciphertext),
            },
            ciphertext_len: ciphertext.len() as u64,
        };
        if inventory.insert(id, identity).is_some() {
            return Err(io_invalid("duplicate immutable v2 object identifier"));
        }
        if inventory.len() > MAX_GC_OBJECTS {
            return Err(std::io::Error::from_raw_os_error(libc::EFBIG));
        }
    }
    Ok((namespace_name, inventory))
}

fn decode_root_bytes(key: &[u8; 32], ciphertext: Vec<u8>) -> std::io::Result<ObjectRef> {
    let plaintext = decrypt_bytes_owned(key, ciphertext, ROOT_AAD).map_err(io_invalid)?;
    let pointer: RootPointer = serde_json::from_slice(&plaintext)
        .map_err(|error| io_invalid(format!("parse authenticated v2 root: {error}")))?;
    if pointer.magic != ROOT_MAGIC || pointer.format_version != FORMAT_VERSION {
        return Err(io_invalid(
            "authenticated v2 GC root has an unsupported format",
        ));
    }
    Ok(pointer.generation)
}

fn valid_transaction_name(name: &str, prefix: &str, suffix: &str) -> bool {
    name.strip_prefix(prefix)
        .and_then(|value| value.strip_suffix(suffix))
        .and_then(from_hex::<16>)
        .is_some()
}

fn push_manifest_roots(manifest: &WriteManifest, roots: &mut Vec<ObjectRef>) {
    roots.push(manifest.new_generation);
    roots.extend(manifest.previous_generation);
    roots.extend(manifest.origin_generation);
}

fn scan_staging_roots(
    base_path: &Path,
    key: &[u8; 32],
    budget: &mut crate::v2_migrate::GcScanBudget,
    anchors: &mut Vec<FileIdentity>,
    generation_roots: &mut Vec<ObjectRef>,
) -> std::io::Result<()> {
    for entry in fs::read_dir(base_path)? {
        let entry = entry?;
        budget
            .charge("top-level v2 ready-control inventory")
            .map_err(io_invalid)?;
        let Some(name) = entry.file_name().to_str().map(str::to_string) else {
            return Err(io_invalid(
                "backing directory contains non-UTF-8 conflict evidence",
            ));
        };
        let root_ready = valid_transaction_name(&name, ROOT_READY_PREFIX, ".ready")
            || valid_transaction_name(&name, LEGACY_ROOT_READY_PREFIX, ".ready");
        let manifest_ready = valid_transaction_name(&name, MANIFEST_READY_PREFIX, ".ready")
            || valid_transaction_name(&name, LEGACY_MANIFEST_READY_PREFIX, ".ready");
        if root_ready {
            let (identity, ciphertext) =
                file_identity(base_path, &entry.path(), MAX_ROOT_CIPHERTEXT)?;
            anchors.push(identity);
            generation_roots.push(decode_root_bytes(key, ciphertext)?);
        } else if manifest_ready {
            let (identity, ciphertext) =
                file_identity(base_path, &entry.path(), MAX_MANIFEST_CIPHERTEXT)?;
            anchors.push(identity);
            let manifest = decode_manifest_ciphertext(key, ciphertext)?;
            push_manifest_roots(&manifest, generation_roots);
        } else if name.starts_with(ROOT_READY_PREFIX)
            || name.starts_with(LEGACY_ROOT_READY_PREFIX)
            || name.starts_with(MANIFEST_READY_PREFIX)
            || name.starts_with(LEGACY_MANIFEST_READY_PREFIX)
            || name.starts_with("_z2-migration-")
            || name.starts_with("._z2-migration-")
        {
            return Err(io_invalid(format!(
                "unsupported or conflicted v2 staging evidence {name:?}; preserving it"
            )));
        }
    }
    Ok(())
}

fn numbered_suffix(value: &str, prefix: &str) -> bool {
    value.strip_prefix(prefix).is_some_and(|number| {
        !number.is_empty() && number.bytes().all(|byte| byte.is_ascii_digit())
    })
}

fn evidence_kind(name: &str) -> Option<&'static str> {
    let rest = name.strip_prefix("normal-")?;
    let transaction = rest.get(..32)?;
    from_hex::<16>(transaction)?;
    let suffix = rest.get(32..)?;
    let valid_retained = |value: &str| value == "retained" || numbered_suffix(value, "retained-");
    if suffix
        .strip_prefix("-manifest.")
        .is_some_and(|value| value == "durable" || valid_retained(value))
        || suffix
            .strip_prefix("-manifest-ready.")
            .is_some_and(valid_retained)
    {
        Some("manifest")
    } else if suffix.strip_prefix("-root.").is_some_and(valid_retained) {
        Some("root")
    } else {
        None
    }
}

fn scan_evidence_roots(
    base_path: &Path,
    key: &[u8; 32],
    budget: &mut crate::v2_migrate::GcScanBudget,
    authenticated_migration_evidence: &HashSet<PathBuf>,
    anchors: &mut Vec<FileIdentity>,
    generation_roots: &mut Vec<ObjectRef>,
) -> std::io::Result<()> {
    let evidence = selected_object_directory(base_path)?.join(EVIDENCE_DIRECTORY);
    for entry in fs::read_dir(&evidence)? {
        let entry = entry?;
        budget
            .charge("normal-write and migration evidence inventory")
            .map_err(io_invalid)?;
        let Some(name) = entry.file_name().to_str().map(str::to_string) else {
            return Err(io_invalid(
                "v2 evidence directory contains a non-UTF-8 entry; preserving it",
            ));
        };
        if name.contains(".untrusted") || name.contains("-untrusted") {
            return Err(io_invalid(format!(
                "v2 evidence contains untrusted artifact {name:?}; preserving every object"
            )));
        }
        if authenticated_migration_evidence.contains(&entry.path()) {
            continue;
        }
        let Some(kind) = evidence_kind(&name) else {
            return Err(io_invalid(format!(
                "v2 evidence contains unsupported or conflicted artifact {name:?}; preserving every object"
            )));
        };
        let max_len = if kind == "root" {
            MAX_ROOT_CIPHERTEXT
        } else {
            MAX_MANIFEST_CIPHERTEXT
        };
        let (identity, ciphertext) = file_identity(base_path, &entry.path(), max_len)?;
        anchors.push(identity);
        if kind == "root" {
            generation_roots.push(decode_root_bytes(key, ciphertext)?);
        } else {
            let rest = name
                .strip_prefix("normal-")
                .ok_or_else(|| io_invalid("v2 manifest evidence has an invalid name"))?;
            let transaction_hex = rest
                .get(..32)
                .ok_or_else(|| io_invalid("v2 manifest evidence has a truncated name"))?;
            let transaction_id = from_hex::<16>(transaction_hex)
                .ok_or_else(|| io_invalid("v2 manifest evidence has an invalid transaction"))?;
            let manifest = decode_manifest_ciphertext(key, ciphertext.clone())?;
            if manifest.transaction_id != transaction_id {
                return Err(io_invalid(format!(
                    "retained v2 manifest evidence {} is bound to a different transaction",
                    entry.path().display()
                )));
            }
            if let Some(retained) = name
                .strip_prefix(&format!("normal-{transaction_hex}-manifest."))
                .filter(|suffix| *suffix != "durable")
            {
                debug_assert!(retained == "retained" || numbered_suffix(retained, "retained-"));
                let durable = evidence.join(format!("normal-{transaction_hex}-manifest.durable"));
                let durable_ciphertext =
                    read_bounded_regular(&durable, MAX_MANIFEST_CIPHERTEXT).map_err(|error| {
                        io_invalid(format!(
                            "retained v2 manifest evidence {} has no readable durable anchor: {error}",
                            entry.path().display()
                        ))
                    })?;
                if ciphertext != durable_ciphertext {
                    return Err(io_invalid(format!(
                        "retained v2 manifest evidence {} differs from its durable transaction anchor",
                        entry.path().display()
                    )));
                }
            }
            push_manifest_roots(&manifest, generation_roots);
        }
    }
    Ok(())
}

fn plan_id(core: &GcPlanCore) -> std::io::Result<String> {
    let bytes = serde_json::to_vec(core)
        .map_err(|error| io_invalid(format!("serialize deterministic v2 GC plan: {error}")))?;
    Ok(to_hex(&digest_bytes(&bytes)))
}

struct GcPlanSizeLimiter {
    written: u64,
    maximum: u64,
}

impl std::io::Write for GcPlanSizeLimiter {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        let total = self
            .written
            .checked_add(bytes.len() as u64)
            .ok_or_else(|| std::io::Error::from_raw_os_error(libc::EFBIG))?;
        if total > self.maximum {
            return Err(std::io::Error::from_raw_os_error(libc::EFBIG));
        }
        self.written = total;
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn ensure_plan_fits(plan: &GcPlan) -> std::io::Result<()> {
    let maximum = MAX_GC_PLAN_CIPHERTEXT
        .checked_sub(V1_CIPHERTEXT_OVERHEAD)
        .ok_or_else(|| std::io::Error::from_raw_os_error(libc::EFBIG))?;
    let mut limiter = GcPlanSizeLimiter {
        written: 0,
        maximum,
    };
    serde_json::to_writer(&mut limiter, plan).map_err(|error| {
        if error.is_io() {
            std::io::Error::from_raw_os_error(libc::EFBIG)
        } else {
            io_invalid(format!("serialize bounded v2 GC plan: {error}"))
        }
    })
}

fn collect_live_scan(
    base_path: &Path,
    key: &[u8; 32],
    kdf_fingerprint: &RecoveryFingerprint,
    resume_plan_id: Option<&str>,
) -> std::io::Result<LiveScan> {
    let mut scan_budget = crate::v2_migrate::GcScanBudget::production();
    collect_live_scan_with_budget(
        base_path,
        key,
        kdf_fingerprint,
        resume_plan_id,
        &mut scan_budget,
    )
}

fn collect_live_scan_with_budget(
    base_path: &Path,
    key: &[u8; 32],
    kdf_fingerprint: &RecoveryFingerprint,
    resume_plan_id: Option<&str>,
    scan_budget: &mut crate::v2_migrate::GcScanBudget,
) -> std::io::Result<LiveScan> {
    if backing_entry_exists(&base_path.join(WRITE_MANIFEST))? {
        return Err(io_invalid(
            "an authenticated normal-write manifest is pending; recover it before GC",
        ));
    }
    let (object_namespace, inventory) = inventory_objects(base_path, scan_budget)?;
    let mut anchors = Vec::new();
    let mut generation_roots = Vec::new();
    let mut migration_file_roots = Vec::new();

    let root_path = base_path.join(ROOT_FILE);
    let (root_identity, root_ciphertext) =
        file_identity(base_path, &root_path, MAX_ROOT_CIPHERTEXT)?;
    anchors.push(root_identity);
    generation_roots.push(decode_root_bytes(key, root_ciphertext)?);
    let (_, current) = load(base_path, key)?;
    let migration = crate::v2_migrate::gc_completed_evidence_roots(
        base_path,
        key,
        kdf_fingerprint,
        &current,
        scan_budget,
    )
    .map_err(io_invalid)?;
    let authenticated_migration_evidence: HashSet<_> =
        migration.anchor_paths.iter().cloned().collect();
    scan_staging_roots(
        base_path,
        key,
        scan_budget,
        &mut anchors,
        &mut generation_roots,
    )?;
    scan_evidence_roots(
        base_path,
        key,
        scan_budget,
        &authenticated_migration_evidence,
        &mut anchors,
        &mut generation_roots,
    )?;
    generation_roots.extend(migration.generations);
    migration_file_roots.extend(migration.file_roots);
    for path in migration.anchor_paths {
        let (identity, _) = file_identity(base_path, &path, MAX_INDEX_CIPHERTEXT)?;
        anchors.push(identity);
    }
    anchors.extend(audit_gc_operations_with_budget(
        base_path,
        key,
        resume_plan_id,
        scan_budget,
    )?);

    anchors.sort_by(|left, right| left.relative_path.cmp(&right.relative_path));
    if anchors
        .windows(2)
        .any(|pair| pair[0].relative_path == pair[1].relative_path)
    {
        return Err(io_invalid("duplicate v2 GC anchor path"));
    }

    let mut walker = GraphWalker::new(base_path, key, &inventory);
    for generation in generation_roots {
        walker.walk_live(generation, ExpectedObject::Generation)?;
    }
    for (file_root, size) in migration_file_roots {
        walker.walk_live(file_root, ExpectedObject::FileRoot(size))?;
    }

    let expectations = std::mem::take(&mut walker.expectations);
    let protected = std::mem::take(&mut walker.protected);
    drop(walker);
    Ok(LiveScan {
        object_namespace,
        anchors,
        inventory,
        expectations,
        protected,
    })
}

fn scan_v2_with_context(
    base_path: &Path,
    key: &[u8; 32],
    kdf_fingerprint: &RecoveryFingerprint,
    resume_plan_id: Option<&str>,
) -> std::io::Result<Scan> {
    let live = collect_live_scan(base_path, key, kdf_fingerprint, resume_plan_id)?;
    let mut walker = GraphWalker::new(base_path, key, &live.inventory);
    walker.expectations = live.expectations.clone();
    walker.protected = live.protected.clone();

    let candidates: Vec<_> = live
        .inventory
        .values()
        .filter(|identity| !walker.protected.contains(&identity.reference.id))
        .cloned()
        .collect();
    for candidate in &candidates {
        let expected = walker.identify_orphan(candidate)?;
        walker.walk_orphan(candidate.reference, expected)?;
    }

    let objects: Vec<_> = live.inventory.values().cloned().collect();
    let reachable_objects = objects.len() - candidates.len();
    let core = GcPlanCore {
        format_version: FORMAT_VERSION,
        canonical_drive_path: None,
        object_namespace: live.object_namespace,
        kdf_fingerprint: kdf_fingerprint.clone(),
        anchors: live.anchors,
        objects,
        candidates,
    };
    let id = plan_id(&core)?;
    let plan = GcPlan {
        gc_version: GC_VERSION,
        plan_id: id,
        core,
    };
    ensure_plan_fits(&plan)?;
    Ok(Scan {
        plan,
        reachable_objects,
    })
}

fn scan_v2(
    base_path: &Path,
    key: &[u8; 32],
    kdf_fingerprint: &RecoveryFingerprint,
) -> std::io::Result<Scan> {
    scan_v2_with_context(base_path, key, kdf_fingerprint, None)
}

fn load_key(base_path: &Path, passphrase: &str) -> Result<([u8; 32], RecoveryFingerprint), String> {
    let (kdf, fingerprint) = load_kdf_with_fingerprint(base_path)?
        .ok_or_else(|| "v2 GC requires Argon2id KDF metadata".to_string())?;
    let key = try_derive_key(passphrase, &kdf)?;
    Ok((key, fingerprint))
}

fn scan_for_command(base_path: &Path, passphrase: &str) -> Result<Option<Scan>, String> {
    crate::fs::ensure_no_index_siblings(base_path).map_err(|error| error.to_string())?;
    crate::fs::ensure_unambiguous_format_heads(base_path).map_err(|error| error.to_string())?;
    let root_exists = backing_entry_exists(&base_path.join(ROOT_FILE))
        .map_err(|error| format!("inspect v2 root: {error}"))?;
    if !root_exists {
        if backing_entry_exists(&base_path.join("_index.age"))
            .map_err(|error| format!("inspect v1 index: {error}"))?
        {
            return Ok(None);
        }
        return Err("no v1 or v2 drive head exists".to_string());
    }
    let (key, kdf_fingerprint) = load_key(base_path, passphrase)?;
    scan_v2(base_path, &key, &kdf_fingerprint)
        .map(Some)
        .map_err(|error| error.to_string())
}

fn preview_from_scan(scan: Scan) -> GcPreview {
    let candidate_bytes = scan
        .plan
        .core
        .candidates
        .iter()
        .map(|candidate| candidate.ciphertext_len)
        .sum();
    let candidate_names: Vec<String> = scan
        .plan
        .core
        .candidates
        .iter()
        .map(|candidate| object_name(&candidate.reference.id))
        .collect();
    GcPreview {
        is_v2: true,
        plan_id: Some(scan.plan.plan_id),
        reachable_objects: scan.reachable_objects,
        candidate_objects: candidate_names.len(),
        candidate_bytes,
        candidate_names,
    }
}

pub(crate) fn gc_preview(base_path: &Path, passphrase: &str) -> Result<GcPreview, String> {
    match scan_for_command(base_path, passphrase)? {
        Some(scan) => Ok(preview_from_scan(scan)),
        None => Ok(GcPreview {
            is_v2: false,
            plan_id: None,
            reachable_objects: 0,
            candidate_objects: 0,
            candidate_bytes: 0,
            candidate_names: Vec::new(),
        }),
    }
}

fn validate_plan_id(value: &str) -> std::io::Result<()> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(io_invalid(
            "v2 GC plan ID must be 64 lowercase hexadecimal digits",
        ));
    }
    Ok(())
}

struct OperationPaths {
    objects: PathBuf,
    gc_root: PathBuf,
    operation: PathBuf,
    quarantine: PathBuf,
    purge_tombstones: PathBuf,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum GcOperationPhase {
    Active,
    Restored,
    Purged,
}

fn operation_paths(base_path: &Path, id: &str) -> std::io::Result<OperationPaths> {
    validate_plan_id(id)?;
    let namespace = selected_object_directory(base_path)?;
    let gc_root = namespace.join(GC_DIRECTORY);
    let operation = gc_root.join(id);
    Ok(OperationPaths {
        objects: namespace.join(OBJECTS_DIRECTORY),
        quarantine: operation.join(GC_QUARANTINE_DIRECTORY),
        purge_tombstones: operation.join(GC_PURGE_TOMBSTONE_DIRECTORY),
        gc_root,
        operation,
    })
}

fn purge_tombstone_name(id: &[u8; 16]) -> String {
    format!(
        "{GC_PURGE_TOMBSTONE_PREFIX}{}{GC_PURGE_TOMBSTONE_SUFFIX}",
        to_hex(id)
    )
}

fn purge_tombstone_id(name: &str) -> Option<[u8; 16]> {
    name.strip_prefix(GC_PURGE_TOMBSTONE_PREFIX)
        .and_then(|value| value.strip_suffix(GC_PURGE_TOMBSTONE_SUFFIX))
        .and_then(from_hex)
}

fn control_stage_name(kind: GcControlKind, nonce: &[u8; 16]) -> String {
    format!(
        "{GC_STAGE_PREFIX}{}-{}{GC_STAGE_SUFFIX}",
        kind.token(),
        to_hex(nonce)
    )
}

fn parse_control_stage_name(name: &str) -> Option<GcControlKind> {
    for kind in GcControlKind::ALL {
        let prefix = format!("{GC_STAGE_PREFIX}{}-", kind.token());
        let nonce = name
            .strip_prefix(&prefix)
            .and_then(|value| value.strip_suffix(GC_STAGE_SUFFIX));
        if nonce.and_then(from_hex::<16>).is_some() {
            return Some(kind);
        }
    }
    None
}

fn control_stage_identity(
    base_path: &Path,
    path: &Path,
    kind: GcControlKind,
) -> std::io::Result<FileIdentity> {
    let before = fs::symlink_metadata(path)?;
    if !before.file_type().is_file()
        || before.file_type().is_symlink()
        || before.len() > kind.maximum_ciphertext_len()
    {
        return Err(io_invalid(format!(
            "staged v2 GC {} control {} is not a bounded real regular file",
            kind.token(),
            path.display()
        )));
    }
    #[cfg(unix)]
    if before.nlink() != 1 {
        return Err(io_invalid(format!(
            "staged v2 GC {} control {} has {} links; preserving every name",
            kind.token(),
            path.display(),
            before.nlink()
        )));
    }
    let bytes = read_bounded_regular(path, kind.maximum_ciphertext_len())?;
    let after = fs::symlink_metadata(path)?;
    if !after.file_type().is_file() || after.len() != before.len() {
        return Err(io_invalid(format!(
            "staged v2 GC {} control {} changed while being inventoried",
            kind.token(),
            path.display()
        )));
    }
    #[cfg(unix)]
    if after.dev() != before.dev() || after.ino() != before.ino() || after.nlink() != 1 {
        return Err(io_invalid(format!(
            "staged v2 GC {} control {} changed identity while being inventoried",
            kind.token(),
            path.display()
        )));
    }
    Ok(FileIdentity {
        relative_path: checked_relative(base_path, path)?,
        ciphertext_len: bytes.len() as u64,
        digest: digest_bytes(&bytes),
    })
}

fn plan_aad(id: &str) -> Vec<u8> {
    let mut aad = Vec::with_capacity(GC_PLAN_AAD_PREFIX.len() + id.len());
    aad.extend_from_slice(GC_PLAN_AAD_PREFIX);
    aad.extend_from_slice(id.as_bytes());
    aad
}

fn marker_aad(id: &str, operation: &str) -> Vec<u8> {
    let mut aad = Vec::with_capacity(GC_MARKER_AAD_PREFIX.len() + id.len() + operation.len() + 1);
    aad.extend_from_slice(GC_MARKER_AAD_PREFIX);
    aad.extend_from_slice(id.as_bytes());
    aad.push(0);
    aad.extend_from_slice(operation.as_bytes());
    aad
}

fn validate_plan(plan: &GcPlan, expected_id: &str, _base_path: &Path) -> std::io::Result<()> {
    if plan.gc_version != GC_VERSION
        || plan.core.format_version != FORMAT_VERSION
        || plan.plan_id != expected_id
        || plan_id(&plan.core)? != expected_id
    {
        return Err(io_invalid("authenticated v2 GC plan is malformed"));
    }
    let mut prior = None;
    let mut object_ids = HashMap::new();
    for object in &plan.core.objects {
        if prior.is_some_and(|id| id >= object.reference.id)
            || object_ids.insert(object.reference.id, object).is_some()
        {
            return Err(io_invalid("v2 GC plan object inventory is not canonical"));
        }
        prior = Some(object.reference.id);
    }
    let mut prior = None;
    let mut candidates = HashSet::new();
    for candidate in &plan.core.candidates {
        if prior.is_some_and(|id| id >= candidate.reference.id)
            || !candidates.insert(candidate.reference.id)
            || object_ids.get(&candidate.reference.id).copied() != Some(candidate)
        {
            return Err(io_invalid("v2 GC candidate inventory is not canonical"));
        }
        prior = Some(candidate.reference.id);
    }
    Ok(())
}

fn read_gc_plan(base_path: &Path, key: &[u8; 32], id: &str) -> std::io::Result<Option<GcPlan>> {
    let paths = operation_paths(base_path, id)?;
    let operation_directory = match open_real_directory(&paths.operation) {
        Ok(directory) => directory,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    };
    verify_open_directory_path(
        &operation_directory,
        &paths.operation,
        "v2 GC operation directory",
    )?;
    let plan = open_authenticated_plan(&operation_directory, base_path, key, id)?
        .map(|(plan, _file)| plan);
    verify_open_directory_path(
        &operation_directory,
        &paths.operation,
        "v2 GC operation directory",
    )?;
    Ok(plan)
}

fn ensure_operation_directories(paths: &OperationPaths) -> std::io::Result<()> {
    let namespace = paths
        .gc_root
        .parent()
        .ok_or_else(|| io_invalid("v2 GC root has no namespace parent"))?;
    ensure_directory(&paths.gc_root, namespace)?;
    ensure_directory(&paths.operation, &paths.gc_root)?;
    ensure_directory(&paths.quarantine, &paths.operation)?;
    for path in [&paths.gc_root, &paths.operation, &paths.quarantine] {
        let metadata = fs::symlink_metadata(path)?;
        if !metadata.file_type().is_dir() || metadata.file_type().is_symlink() {
            return Err(io_invalid(format!(
                "{} is not a real v2 GC directory",
                path.display()
            )));
        }
    }
    sync_directory(namespace, "persist or recover v2 GC root directory")?;
    sync_directory(
        &paths.gc_root,
        "persist or recover v2 GC operation directory",
    )?;
    sync_directory(
        &paths.operation,
        "persist or recover v2 GC quarantine directory",
    )?;
    Ok(())
}

fn persist_gc_plan(base_path: &Path, key: &[u8; 32], plan: &GcPlan) -> std::io::Result<()> {
    let paths = operation_paths(base_path, &plan.plan_id)?;
    ensure_operation_directories(&paths)?;
    let operation_directory = open_real_directory(&paths.operation)?;
    verify_open_directory_path(
        &operation_directory,
        &paths.operation,
        "v2 GC operation directory",
    )?;
    if let Some((existing, file)) =
        open_authenticated_plan(&operation_directory, base_path, key, &plan.plan_id)?
    {
        if existing != *plan {
            return Err(io_invalid(
                "existing authenticated v2 GC plan differs from this preview",
            ));
        }
        sync_open_file(&file, "persist resumed authenticated v2 GC plan")?;
        sync_open_directory(&operation_directory, "persist resumed v2 GC plan name")?;
        verify_open_directory_path(
            &operation_directory,
            &paths.operation,
            "v2 GC operation directory",
        )?;
        fault::checkpoint(DurabilityEvent::Recovery, "resume authenticated v2 GC plan")?;
        return Ok(());
    }
    let plaintext = serde_json::to_vec(plan)
        .map_err(|error| io_invalid(format!("serialize authenticated v2 GC plan: {error}")))?;
    let ciphertext =
        encrypt_bytes(key, &plaintext, &plan_aad(&plan.plan_id)).map_err(std::io::Error::other)?;
    if ciphertext.len() as u64 > MAX_GC_PLAN_CIPHERTEXT {
        return Err(std::io::Error::from_raw_os_error(libc::EFBIG));
    }
    let published = stage_and_publish_control(
        &operation_directory,
        &paths.operation,
        GcControlKind::Plan,
        &ciphertext,
    )?;
    let (existing, file) =
        open_authenticated_plan(&operation_directory, base_path, key, &plan.plan_id)?
            .ok_or_else(|| io_invalid("published v2 GC plan disappeared before authentication"))?;
    if existing != *plan {
        return Err(io_invalid(
            "raced authenticated v2 GC plan differs from this preview",
        ));
    }
    finish_control_publication(
        &operation_directory,
        &paths.operation,
        &file,
        published,
        "v2 GC plan",
    )
}

fn marker_kind(operation: &str) -> std::io::Result<GcControlKind> {
    Ok(match operation {
        "quarantine" => GcControlKind::Quarantine,
        "restore" => GcControlKind::Restore,
        "purge-intent" => GcControlKind::PurgeIntent,
        "purge" => GcControlKind::Purge,
        _ => return Err(io_invalid("unsupported v2 GC marker operation")),
    })
}

fn marker_name(operation: &str) -> std::io::Result<&'static str> {
    Ok(marker_kind(operation)?.final_name())
}

fn read_bounded_open_regular(file: &mut File, max_len: u64) -> std::io::Result<Vec<u8>> {
    let before = file.metadata()?;
    if !before.is_file() || before.len() > max_len {
        return Err(io_invalid(format!(
            "opened v2 GC control file is not a bounded regular file ({} bytes; maximum {max_len})",
            before.len()
        )));
    }
    #[cfg(unix)]
    if before.nlink() != 1 {
        return Err(io_invalid(
            "opened v2 GC control file is not a single-link regular file",
        ));
    }
    let capacity = usize::try_from(before.len())
        .map_err(|_| std::io::Error::from_raw_os_error(libc::EFBIG))?;
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(capacity)
        .map_err(|_| std::io::Error::from_raw_os_error(libc::ENOMEM))?;
    file.take(max_len.saturating_add(1))
        .read_to_end(&mut bytes)?;
    let after = file.metadata()?;
    if bytes.len() as u64 != before.len() || after.len() != before.len() || !after.is_file() {
        return Err(io_invalid(
            "opened v2 GC control file changed while being authenticated",
        ));
    }
    #[cfg(unix)]
    if after.dev() != before.dev() || after.ino() != before.ino() || after.nlink() != 1 {
        return Err(io_invalid(
            "opened v2 GC control file changed identity while being authenticated",
        ));
    }
    Ok(bytes)
}

fn open_authenticated_plan(
    operation_directory: &File,
    base_path: &Path,
    key: &[u8; 32],
    id: &str,
) -> std::io::Result<Option<(GcPlan, File)>> {
    let mut file = match openat_readonly(operation_directory, GC_PLAN_FILE) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    };
    let ciphertext = read_bounded_open_regular(&mut file, MAX_GC_PLAN_CIPHERTEXT)?;
    let plaintext = decrypt_bytes_owned(key, ciphertext, &plan_aad(id))
        .map_err(|error| io_invalid(format!("authenticate v2 GC plan: {error}")))?;
    let plan: GcPlan = serde_json::from_slice(&plaintext)
        .map_err(|error| io_invalid(format!("parse authenticated v2 GC plan: {error}")))?;
    validate_plan(&plan, id, base_path)?;
    Ok(Some((plan, file)))
}

fn open_authenticated_marker(
    operation_directory: &File,
    key: &[u8; 32],
    id: &str,
    operation: &str,
) -> std::io::Result<Option<File>> {
    let mut file = match openat_readonly(operation_directory, marker_name(operation)?) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    };
    let ciphertext =
        read_bounded_open_regular(&mut file, MAX_METADATA_OBJECT + V1_CIPHERTEXT_OVERHEAD)?;
    let plaintext = decrypt_bytes_owned(key, ciphertext, &marker_aad(id, operation))
        .map_err(|error| io_invalid(format!("authenticate v2 GC {operation} marker: {error}")))?;
    let marker: GcMarker = serde_json::from_slice(&plaintext)
        .map_err(|error| io_invalid(format!("parse v2 GC {operation} marker: {error}")))?;
    if marker
        != (GcMarker {
            gc_version: GC_VERSION,
            plan_id: id.to_string(),
            operation: operation.to_string(),
        })
    {
        return Err(io_invalid(format!(
            "authenticated v2 GC {operation} marker is inconsistent"
        )));
    }
    Ok(Some(file))
}

fn read_marker(
    paths: &OperationPaths,
    key: &[u8; 32],
    id: &str,
    operation: &str,
) -> std::io::Result<bool> {
    let operation_directory = open_real_directory(&paths.operation)?;
    verify_open_directory_path(
        &operation_directory,
        &paths.operation,
        "v2 GC operation directory",
    )?;
    let exists = open_authenticated_marker(&operation_directory, key, id, operation)?.is_some();
    verify_open_directory_path(
        &operation_directory,
        &paths.operation,
        "v2 GC operation directory",
    )?;
    Ok(exists)
}

fn validate_quarantine_inventory(
    paths: &OperationPaths,
    plan: &GcPlan,
    budget: &mut crate::v2_migrate::GcScanBudget,
) -> std::io::Result<()> {
    let metadata = fs::symlink_metadata(&paths.quarantine)?;
    if !metadata.file_type().is_dir() || metadata.file_type().is_symlink() {
        return Err(io_invalid(format!(
            "{} is not a real v2 GC quarantine directory",
            paths.quarantine.display()
        )));
    }
    let expected: HashMap<_, _> = plan
        .core
        .candidates
        .iter()
        .map(|candidate| (object_name(&candidate.reference.id), candidate))
        .collect();
    for entry in fs::read_dir(&paths.quarantine)? {
        let entry = entry?;
        budget
            .charge("v2 GC quarantine inventory")
            .map_err(io_invalid)?;
        let Some(name) = entry.file_name().to_str().map(str::to_string) else {
            return Err(io_invalid(
                "v2 GC quarantine contains non-UTF-8 conflict evidence",
            ));
        };
        let Some(candidate) = expected.get(&name) else {
            return Err(io_invalid(format!(
                "v2 GC quarantine contains unexpected entry {name:?}; preserving it"
            )));
        };
        verify_object_at(&entry.path(), candidate)?;
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PurgeTombstoneState {
    Full,
    Reclaimed,
}

#[derive(Clone, Debug)]
struct PurgeTombstoneEvidence {
    state: PurgeTombstoneState,
    identity: FileIdentity,
}

fn verify_reclaimed_tombstone_at(path: &Path) -> std::io::Result<()> {
    let before = fs::symlink_metadata(path)?;
    if !before.file_type().is_file() || before.file_type().is_symlink() || before.len() != 0 {
        return Err(io_invalid(format!(
            "v2 GC purge tombstone {} is not an explicit zero-length regular file",
            path.display()
        )));
    }
    #[cfg(unix)]
    if before.nlink() != 1 {
        return Err(io_invalid(format!(
            "v2 GC purge tombstone {} has {} hard links; preserving every name",
            path.display(),
            before.nlink()
        )));
    }
    let after = fs::symlink_metadata(path)?;
    #[cfg(unix)]
    if after.dev() != before.dev()
        || after.ino() != before.ino()
        || after.nlink() != 1
        || after.len() != 0
    {
        return Err(io_invalid(format!(
            "v2 GC purge tombstone {} changed identity while being inspected",
            path.display()
        )));
    }
    #[cfg(not(unix))]
    if !after.file_type().is_file() || after.file_type().is_symlink() || after.len() != 0 {
        return Err(io_invalid(format!(
            "v2 GC purge tombstone {} changed while being inspected",
            path.display()
        )));
    }
    Ok(())
}

fn inspect_purge_tombstones_with_budget(
    base_path: &Path,
    paths: &OperationPaths,
    plan: &GcPlan,
    budget: &mut crate::v2_migrate::GcScanBudget,
) -> std::io::Result<HashMap<[u8; 16], PurgeTombstoneEvidence>> {
    let metadata = match fs::symlink_metadata(&paths.purge_tombstones) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(HashMap::new()),
        Err(error) => return Err(error),
    };
    if !metadata.file_type().is_dir() || metadata.file_type().is_symlink() {
        return Err(io_invalid(format!(
            "{} is not a real v2 GC purge-tombstone directory",
            paths.purge_tombstones.display()
        )));
    }
    let expected: HashMap<_, _> = plan
        .core
        .candidates
        .iter()
        .map(|candidate| (candidate.reference.id, candidate))
        .collect();
    let mut tombstones = HashMap::new();
    for entry in fs::read_dir(&paths.purge_tombstones)? {
        let entry = entry?;
        budget
            .charge("v2 GC purge-tombstone inventory")
            .map_err(io_invalid)?;
        let Some(name) = entry.file_name().to_str().map(str::to_string) else {
            return Err(io_invalid(
                "v2 GC purge tombstones contain non-UTF-8 conflict evidence",
            ));
        };
        let id = purge_tombstone_id(&name).ok_or_else(|| {
            io_invalid(format!(
                "v2 GC purge tombstones contain unexpected entry {name:?}; preserving it"
            ))
        })?;
        if name != purge_tombstone_name(&id) {
            return Err(io_invalid(format!(
                "v2 GC purge tombstones contain noncanonical entry {name:?}; preserving it"
            )));
        }
        let candidate = expected.get(&id).ok_or_else(|| {
            io_invalid(format!(
                "v2 GC purge tombstone {name:?} is not named by its authenticated plan; preserving it"
            ))
        })?;
        let entry_path = entry.path();
        let entry_metadata = fs::symlink_metadata(&entry_path)?;
        let state = if entry_metadata.len() == 0 {
            verify_reclaimed_tombstone_at(&entry_path)?;
            PurgeTombstoneState::Reclaimed
        } else {
            verify_object_at(&entry_path, candidate)?;
            PurgeTombstoneState::Full
        };
        let identity = FileIdentity {
            relative_path: checked_relative(base_path, &entry_path)?,
            ciphertext_len: match state {
                PurgeTombstoneState::Full => candidate.ciphertext_len,
                PurgeTombstoneState::Reclaimed => 0,
            },
            digest: match state {
                PurgeTombstoneState::Full => candidate.reference.digest,
                PurgeTombstoneState::Reclaimed => digest_bytes(&[]),
            },
        };
        if tombstones
            .insert(id, PurgeTombstoneEvidence { state, identity })
            .is_some()
        {
            return Err(io_invalid(format!(
                "v2 GC purge tombstone {name:?} is duplicated; preserving every name"
            )));
        }
        if tombstones.len() > MAX_GC_OBJECTS {
            return Err(std::io::Error::from_raw_os_error(libc::EFBIG));
        }
    }
    Ok(tombstones)
}

fn inspect_purge_tombstones(
    base_path: &Path,
    paths: &OperationPaths,
    plan: &GcPlan,
) -> std::io::Result<HashMap<[u8; 16], PurgeTombstoneEvidence>> {
    let mut budget = crate::v2_migrate::GcScanBudget::production();
    inspect_purge_tombstones_with_budget(base_path, paths, plan, &mut budget)
}

fn operation_phase(
    base_path: &Path,
    paths: &OperationPaths,
    key: &[u8; 32],
    plan: &GcPlan,
    budget: &mut crate::v2_migrate::GcScanBudget,
) -> std::io::Result<(GcOperationPhase, HashMap<[u8; 16], PurgeTombstoneEvidence>)> {
    validate_quarantine_inventory(paths, plan, budget)?;
    let tombstones = inspect_purge_tombstones_with_budget(base_path, paths, plan, budget)?;
    let quarantine_complete = read_marker(paths, key, &plan.plan_id, "quarantine")?;
    let restore_complete = read_marker(paths, key, &plan.plan_id, "restore")?;
    let purge_intent = read_marker(paths, key, &plan.plan_id, "purge-intent")?;
    let purge_complete = read_marker(paths, key, &plan.plan_id, "purge")?;
    if restore_complete && (purge_intent || purge_complete) {
        return Err(io_invalid(format!(
            "v2 GC operation {} has contradictory restore and purge evidence",
            plan.plan_id
        )));
    }
    if purge_complete && (!purge_intent || !quarantine_complete) {
        return Err(io_invalid(format!(
            "v2 GC operation {} has purge completion without its authenticated prerequisites",
            plan.plan_id
        )));
    }
    if purge_intent && !quarantine_complete {
        return Err(io_invalid(format!(
            "v2 GC operation {} has purge intent without completed quarantine",
            plan.plan_id
        )));
    }
    if !purge_intent && !tombstones.is_empty() {
        return Err(io_invalid(format!(
            "v2 GC operation {} has purge tombstones without durable authenticated purge intent; preserving them",
            plan.plan_id
        )));
    }

    for candidate in &plan.core.candidates {
        let state = candidate_state(paths, candidate)?;
        let tombstone = tombstones
            .get(&candidate.reference.id)
            .map(|evidence| evidence.state);
        let valid = if restore_complete {
            state == QuarantineState::Source && tombstone.is_none()
        } else if purge_complete {
            state == QuarantineState::Missing && tombstone == Some(PurgeTombstoneState::Reclaimed)
        } else if purge_intent {
            matches!(
                (state, tombstone),
                (QuarantineState::Quarantined, None)
                    | (
                        QuarantineState::Missing,
                        Some(PurgeTombstoneState::Full | PurgeTombstoneState::Reclaimed)
                    )
            )
        } else if quarantine_complete {
            tombstone.is_none()
                && matches!(
                    state,
                    QuarantineState::Source | QuarantineState::Quarantined
                )
        } else {
            tombstone.is_none()
                && matches!(
                    state,
                    QuarantineState::Source | QuarantineState::Quarantined
                )
        };
        if !valid {
            return Err(io_invalid(format!(
                "v2 GC operation {} has ambiguous state {:?} for {}; preserving every name",
                plan.plan_id,
                state,
                object_name(&candidate.reference.id)
            )));
        }
    }
    let phase = if restore_complete {
        GcOperationPhase::Restored
    } else if purge_complete {
        GcOperationPhase::Purged
    } else {
        GcOperationPhase::Active
    };
    Ok((phase, tombstones))
}

fn audit_gc_operations_with_budget(
    base_path: &Path,
    key: &[u8; 32],
    resume_plan_id: Option<&str>,
    budget: &mut crate::v2_migrate::GcScanBudget,
) -> std::io::Result<Vec<FileIdentity>> {
    let namespace = selected_object_directory(base_path)?;
    let gc_root = namespace.join(GC_DIRECTORY);
    let metadata = match fs::symlink_metadata(&gc_root) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(error),
    };
    if !metadata.file_type().is_dir() || metadata.file_type().is_symlink() {
        return Err(io_invalid(format!(
            "{} is not a real v2 GC operation directory",
            gc_root.display()
        )));
    }

    let mut entries = Vec::new();
    for entry in fs::read_dir(&gc_root)? {
        let entry = entry?;
        budget
            .charge("v2 GC operation inventory")
            .map_err(io_invalid)?;
        entries.push(entry);
    }
    entries.sort_by_key(|entry| entry.file_name());
    let mut anchors = Vec::new();
    for entry in entries {
        let Some(id) = entry.file_name().to_str().map(str::to_string) else {
            return Err(io_invalid(
                "v2 GC operation namespace contains non-UTF-8 conflict evidence",
            ));
        };
        validate_plan_id(&id).map_err(|_| {
            io_invalid(format!(
                "v2 GC operation namespace contains unexpected entry {id:?}; preserving it"
            ))
        })?;
        let operation_metadata = fs::symlink_metadata(entry.path())?;
        if !operation_metadata.file_type().is_dir() || operation_metadata.file_type().is_symlink() {
            return Err(io_invalid(format!(
                "v2 GC operation {id} is not a real directory"
            )));
        }
        let paths = operation_paths(base_path, &id)?;
        let mut child_names = HashSet::new();
        let mut staged_control_anchors = Vec::new();
        for child in fs::read_dir(&paths.operation)? {
            let child = child?;
            budget
                .charge("v2 GC control inventory")
                .map_err(io_invalid)?;
            let Some(name) = child.file_name().to_str().map(str::to_string) else {
                return Err(io_invalid(format!(
                    "v2 GC operation {id} contains non-UTF-8 conflict evidence"
                )));
            };
            if !child_names.insert(name.clone()) {
                return Err(io_invalid(format!(
                    "v2 GC operation {id} contains unexpected entry {name:?}; preserving it"
                )));
            }
            if matches!(
                name.as_str(),
                GC_PLAN_FILE
                    | GC_QUARANTINE_DIRECTORY
                    | GC_PURGE_TOMBSTONE_DIRECTORY
                    | GC_QUARANTINE_COMPLETE_FILE
                    | GC_RESTORE_COMPLETE_FILE
                    | GC_PURGE_INTENT_FILE
                    | GC_PURGE_COMPLETE_FILE
            ) {
                continue;
            }
            let Some(kind) = parse_control_stage_name(&name) else {
                return Err(io_invalid(format!(
                    "v2 GC operation {id} contains unexpected entry {name:?}; preserving it"
                )));
            };
            staged_control_anchors.push(control_stage_identity(base_path, &child.path(), kind)?);
        }

        let plan = read_gc_plan(base_path, key, &id)?;
        let Some(plan) = plan else {
            if resume_plan_id != Some(id.as_str()) {
                return Err(io_invalid(format!(
                    "v2 GC operation {id} has no authenticated plan; resume the exact operation instead of starting another"
                )));
            }
            if child_names.iter().any(|name| {
                name != GC_QUARANTINE_DIRECTORY
                    && name != GC_PURGE_TOMBSTONE_DIRECTORY
                    && parse_control_stage_name(name).is_none()
            }) {
                return Err(io_invalid(format!(
                    "incomplete v2 GC operation {id} contains unauthenticated control artifacts"
                )));
            }
            if child_names.contains(GC_QUARANTINE_DIRECTORY) {
                let metadata = fs::symlink_metadata(&paths.quarantine)?;
                if !metadata.file_type().is_dir()
                    || metadata.file_type().is_symlink()
                    || fs::read_dir(&paths.quarantine)?.next().is_some()
                {
                    return Err(io_invalid(format!(
                        "incomplete v2 GC operation {id} has an ambiguous quarantine"
                    )));
                }
            }
            if child_names.contains(GC_PURGE_TOMBSTONE_DIRECTORY) {
                let metadata = fs::symlink_metadata(&paths.purge_tombstones)?;
                if !metadata.file_type().is_dir()
                    || metadata.file_type().is_symlink()
                    || fs::read_dir(&paths.purge_tombstones)?.next().is_some()
                {
                    return Err(io_invalid(format!(
                        "incomplete v2 GC operation {id} has ambiguous purge tombstones"
                    )));
                }
            }
            continue;
        };
        if !child_names.contains(GC_QUARANTINE_DIRECTORY) {
            return Err(io_invalid(format!(
                "authenticated v2 GC operation {id} has no quarantine directory"
            )));
        }
        let (phase, tombstones) = operation_phase(base_path, &paths, key, &plan, budget)?;
        if phase == GcOperationPhase::Active && resume_plan_id != Some(id.as_str()) {
            return Err(io_invalid(format!(
                "v2 GC operation {id} is incomplete; resume quarantine, restore, or purge before starting another preview"
            )));
        }
        if resume_plan_id == Some(id.as_str()) {
            continue;
        }
        anchors.extend(staged_control_anchors);
        anchors.extend(tombstones.into_values().map(|evidence| evidence.identity));
        let (plan_identity, _) = file_identity(
            base_path,
            &paths.operation.join(GC_PLAN_FILE),
            MAX_GC_PLAN_CIPHERTEXT,
        )?;
        anchors.push(plan_identity);
        for (name, operation) in [
            (GC_QUARANTINE_COMPLETE_FILE, "quarantine"),
            (GC_RESTORE_COMPLETE_FILE, "restore"),
            (GC_PURGE_INTENT_FILE, "purge-intent"),
            (GC_PURGE_COMPLETE_FILE, "purge"),
        ] {
            if child_names.contains(name) {
                if !read_marker(&paths, key, &id, operation)? {
                    return Err(io_invalid(format!(
                        "v2 GC operation {id} marker {name} disappeared during audit"
                    )));
                }
                let (identity, _) = file_identity(
                    base_path,
                    &paths.operation.join(name),
                    MAX_METADATA_OBJECT + V1_CIPHERTEXT_OVERHEAD,
                )?;
                anchors.push(identity);
            }
        }
    }
    Ok(anchors)
}

fn audit_gc_operations(
    base_path: &Path,
    key: &[u8; 32],
    resume_plan_id: Option<&str>,
) -> std::io::Result<Vec<FileIdentity>> {
    let mut budget = crate::v2_migrate::GcScanBudget::production();
    audit_gc_operations_with_budget(base_path, key, resume_plan_id, &mut budget)
}

fn write_marker(
    paths: &OperationPaths,
    key: &[u8; 32],
    id: &str,
    operation: &str,
) -> std::io::Result<()> {
    let operation_directory = open_real_directory(&paths.operation)?;
    verify_open_directory_path(
        &operation_directory,
        &paths.operation,
        "v2 GC operation directory",
    )?;
    if let Some(file) = open_authenticated_marker(&operation_directory, key, id, operation)? {
        sync_open_file(
            &file,
            "persist resumed authenticated v2 GC operation marker",
        )?;
        sync_open_directory(
            &operation_directory,
            "persist resumed authenticated v2 GC operation marker name",
        )?;
        verify_open_directory_path(
            &operation_directory,
            &paths.operation,
            "v2 GC operation directory",
        )?;
        fault::checkpoint(
            DurabilityEvent::Recovery,
            "resume authenticated v2 GC completion marker",
        )?;
        return Ok(());
    }
    let marker = GcMarker {
        gc_version: GC_VERSION,
        plan_id: id.to_string(),
        operation: operation.to_string(),
    };
    let plaintext = serde_json::to_vec(&marker)
        .map_err(|error| io_invalid(format!("serialize v2 GC {operation} marker: {error}")))?;
    let ciphertext = encrypt_bytes(key, &plaintext, &marker_aad(id, operation))
        .map_err(std::io::Error::other)?;
    let publication = stage_and_publish_control(
        &operation_directory,
        &paths.operation,
        marker_kind(operation)?,
        &ciphertext,
    )?;
    let file = open_authenticated_marker(&operation_directory, key, id, operation)?
        .ok_or_else(|| io_invalid("published v2 GC marker disappeared before authentication"))?;
    finish_control_publication(
        &operation_directory,
        &paths.operation,
        &file,
        publication,
        "v2 GC marker",
    )
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct VerifiedObject {
    #[cfg(unix)]
    device: u64,
    #[cfg(unix)]
    inode: u64,
}

struct OpenedObject {
    file: File,
    verified: VerifiedObject,
}

#[cfg(unix)]
fn open_real_directory(path: &Path) -> std::io::Result<File> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    if !file.metadata()?.is_dir() {
        return Err(io_invalid(format!(
            "{} is not a real GC operation directory",
            path.display()
        )));
    }
    Ok(file)
}

#[cfg(not(unix))]
fn open_real_directory(_path: &Path) -> std::io::Result<File> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "pinned directory operations are unavailable on this platform",
    ))
}

#[cfg(unix)]
fn openat_readonly(directory: &File, name: &str) -> std::io::Result<File> {
    let name = CString::new(name)?;
    let descriptor = unsafe {
        libc::openat(
            directory.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if descriptor < 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(unsafe { File::from_raw_fd(descriptor) })
    }
}

#[cfg(unix)]
fn openat_directory(directory: &File, name: &str) -> std::io::Result<File> {
    let name = CString::new(name)?;
    let descriptor = unsafe {
        libc::openat(
            directory.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if descriptor < 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(unsafe { File::from_raw_fd(descriptor) })
    }
}

#[cfg(all(test, unix))]
fn ensure_purge_tombstone_directory(
    operation_directory: &File,
    paths: &OperationPaths,
) -> std::io::Result<File> {
    let name = CString::new(GC_PURGE_TOMBSTONE_DIRECTORY)?;
    let result = unsafe { libc::mkdirat(operation_directory.as_raw_fd(), name.as_ptr(), 0o700) };
    let created = if result == 0 {
        fault::checkpoint(
            DurabilityEvent::Write,
            "create v2 GC purge-tombstone directory",
        )?;
        true
    } else {
        let error = std::io::Error::last_os_error();
        if error.kind() != std::io::ErrorKind::AlreadyExists {
            return Err(error);
        }
        false
    };
    let directory = openat_directory(operation_directory, GC_PURGE_TOMBSTONE_DIRECTORY)?;
    verify_open_directory_path(
        &directory,
        &paths.purge_tombstones,
        "v2 GC purge-tombstone directory",
    )?;
    sync_open_directory(
        operation_directory,
        "persist v2 GC purge-tombstone directory name",
    )?;
    if !created {
        fault::checkpoint(
            DurabilityEvent::Recovery,
            "resume existing v2 GC purge-tombstone directory",
        )?;
    }
    Ok(directory)
}

#[cfg(all(test, not(unix)))]
fn ensure_purge_tombstone_directory(
    _operation_directory: &File,
    _paths: &OperationPaths,
) -> std::io::Result<File> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "pinned purge-tombstone directory creation is unavailable on this platform",
    ))
}

#[cfg(not(unix))]
fn openat_readonly(_directory: &File, _name: &str) -> std::io::Result<File> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "directory-relative no-follow reads are unavailable on this platform",
    ))
}

#[cfg(not(unix))]
fn openat_directory(_directory: &File, _name: &str) -> std::io::Result<File> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "directory-relative no-follow directory opens are unavailable on this platform",
    ))
}

#[cfg(unix)]
fn openat_new_file(directory: &File, name: &str) -> std::io::Result<File> {
    let name = CString::new(name)?;
    let descriptor = unsafe {
        libc::openat(
            directory.as_raw_fd(),
            name.as_ptr(),
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            0o600,
        )
    };
    if descriptor < 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(unsafe { File::from_raw_fd(descriptor) })
    }
}

#[cfg(not(unix))]
fn openat_new_file(_directory: &File, _name: &str) -> std::io::Result<File> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "directory-relative exclusive writes are unavailable on this platform",
    ))
}

#[cfg(unix)]
fn verify_open_object(
    mut file: File,
    name: &str,
    identity: &ObjectIdentity,
) -> std::io::Result<OpenedObject> {
    let before = file.metadata()?;
    if !before.is_file()
        || before.len() != identity.ciphertext_len
        || before.nlink() != 1
        || before.len() > MAX_INDEX_CIPHERTEXT
    {
        return Err(io_invalid(format!(
            "v2 GC object {name:?} is not the exact planned single-link regular file"
        )));
    }
    let capacity = usize::try_from(before.len())
        .map_err(|_| std::io::Error::from_raw_os_error(libc::EFBIG))?;
    let mut ciphertext = Vec::new();
    ciphertext
        .try_reserve_exact(capacity)
        .map_err(|_| std::io::Error::from_raw_os_error(libc::ENOMEM))?;
    file.read_to_end(&mut ciphertext)?;
    if ciphertext.len() as u64 != identity.ciphertext_len
        || digest_bytes(&ciphertext) != identity.reference.digest
    {
        return Err(io_invalid(format!(
            "v2 GC object {name:?} differs from its authenticated plan"
        )));
    }
    let after = file.metadata()?;
    if after.dev() != before.dev()
        || after.ino() != before.ino()
        || after.nlink() != 1
        || after.len() != before.len()
    {
        return Err(io_invalid(format!(
            "v2 GC object {name:?} changed while being authenticated"
        )));
    }
    Ok(OpenedObject {
        file,
        verified: VerifiedObject {
            device: after.dev(),
            inode: after.ino(),
        },
    })
}

#[cfg(unix)]
fn verify_object_in_directory(
    directory: &File,
    name: &str,
    identity: &ObjectIdentity,
) -> std::io::Result<OpenedObject> {
    verify_open_object(openat_readonly(directory, name)?, name, identity)
}

#[cfg(unix)]
fn verify_reclaimed_tombstone_in_directory(
    directory: &File,
    name: &str,
) -> std::io::Result<OpenedObject> {
    let file = openat_readonly(directory, name)?;
    let before = file.metadata()?;
    if !before.is_file() || before.len() != 0 || before.nlink() != 1 {
        return Err(io_invalid(format!(
            "v2 GC purge tombstone {name:?} is not the exact single-link reclaimed file"
        )));
    }
    let after = file.metadata()?;
    if after.dev() != before.dev()
        || after.ino() != before.ino()
        || after.nlink() != 1
        || after.len() != 0
    {
        return Err(io_invalid(format!(
            "v2 GC purge tombstone {name:?} changed identity while being verified"
        )));
    }
    Ok(OpenedObject {
        file,
        verified: VerifiedObject {
            device: after.dev(),
            inode: after.ino(),
        },
    })
}

#[cfg(not(unix))]
fn verify_reclaimed_tombstone_in_directory(
    _directory: &File,
    _name: &str,
) -> std::io::Result<OpenedObject> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "pinned reclaimed tombstone verification is unavailable on this platform",
    ))
}

#[cfg(not(unix))]
fn verify_object_in_directory(
    _directory: &File,
    _name: &str,
    _identity: &ObjectIdentity,
) -> std::io::Result<OpenedObject> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "pinned object verification is unavailable on this platform",
    ))
}

#[cfg(target_os = "linux")]
fn renameat_noreplace_names(
    source_directory: &File,
    source_name: &str,
    target_directory: &File,
    target_name: &str,
) -> std::io::Result<()> {
    let source_name = CString::new(source_name)?;
    let target_name = CString::new(target_name)?;
    let result = unsafe {
        libc::renameat2(
            source_directory.as_raw_fd(),
            source_name.as_ptr(),
            target_directory.as_raw_fd(),
            target_name.as_ptr(),
            libc::RENAME_NOREPLACE,
        )
    };
    if result == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn renameat_noreplace_names(
    _source_directory: &File,
    _source_name: &str,
    _target_directory: &File,
    _target_name: &str,
) -> std::io::Result<()> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "atomic directory-relative no-replace rename is unavailable on this platform",
    ))
}

#[cfg(target_os = "macos")]
fn renameat_noreplace_names(
    source_directory: &File,
    source_name: &str,
    target_directory: &File,
    target_name: &str,
) -> std::io::Result<()> {
    let source_name = CString::new(source_name)?;
    let target_name = CString::new(target_name)?;
    let result = unsafe {
        libc::renameatx_np(
            source_directory.as_raw_fd(),
            source_name.as_ptr(),
            target_directory.as_raw_fd(),
            target_name.as_ptr(),
            libc::RENAME_EXCL,
        )
    };
    if result == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

fn renameat_noreplace(
    source_directory: &File,
    target_directory: &File,
    name: &str,
) -> std::io::Result<()> {
    renameat_noreplace_names(source_directory, name, target_directory, name)
}

struct StagedControl {
    name: String,
    _file: File,
    verified: VerifiedObject,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ControlPublication {
    Published(VerifiedObject),
    Existing,
}

#[cfg(unix)]
fn verified_control_file(file: &File, expected_len: u64) -> std::io::Result<VerifiedObject> {
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.len() != expected_len || metadata.nlink() != 1 {
        return Err(io_invalid(
            "staged v2 GC control changed before atomic publication",
        ));
    }
    Ok(VerifiedObject {
        device: metadata.dev(),
        inode: metadata.ino(),
    })
}

#[cfg(not(unix))]
fn verified_control_file(_file: &File, _expected_len: u64) -> std::io::Result<VerifiedObject> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "staged GC control identity checks are unavailable on this platform",
    ))
}

fn create_staged_control(
    operation_directory: &File,
    kind: GcControlKind,
    ciphertext: &[u8],
) -> std::io::Result<StagedControl> {
    if ciphertext.len() as u64 > kind.maximum_ciphertext_len() {
        return Err(std::io::Error::from_raw_os_error(libc::EFBIG));
    }
    let (name, mut file) = loop {
        let mut nonce = [0u8; 16];
        OsRng.fill_bytes(&mut nonce);
        let name = control_stage_name(kind, &nonce);
        match openat_new_file(operation_directory, &name) {
            Ok(file) => break (name, file),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(error),
        }
    };
    file.write_all(ciphertext)?;
    fault::checkpoint(
        DurabilityEvent::Write,
        "write fresh staged authenticated v2 GC control",
    )?;
    sync_open_file(&file, "persist fresh staged authenticated v2 GC control")?;
    let verified = verified_control_file(&file, ciphertext.len() as u64)?;
    Ok(StagedControl {
        name,
        _file: file,
        verified,
    })
}

fn publish_staged_control(
    operation_directory: &File,
    staged: StagedControl,
    final_name: &str,
) -> std::io::Result<ControlPublication> {
    match renameat_noreplace_names(
        operation_directory,
        &staged.name,
        operation_directory,
        final_name,
    ) {
        Ok(()) => {
            fault::checkpoint(
                DurabilityEvent::Rename,
                "publish staged authenticated v2 GC control",
            )?;
            sync_open_directory(
                operation_directory,
                "persist authenticated v2 GC control final name",
            )?;
            Ok(ControlPublication::Published(staged.verified))
        }
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            sync_open_directory(
                operation_directory,
                "preserve raced staged v2 GC control evidence",
            )?;
            Ok(ControlPublication::Existing)
        }
        Err(error) => {
            sync_open_directory(
                operation_directory,
                "preserve failed staged v2 GC control evidence",
            )?;
            Err(error)
        }
    }
}

fn stage_and_publish_control(
    operation_directory: &File,
    operation_path: &Path,
    kind: GcControlKind,
    ciphertext: &[u8],
) -> std::io::Result<ControlPublication> {
    verify_open_directory_path(
        operation_directory,
        operation_path,
        "v2 GC operation directory",
    )?;
    let staged = create_staged_control(operation_directory, kind, ciphertext)?;
    let publication = publish_staged_control(operation_directory, staged, kind.final_name())?;
    verify_open_directory_path(
        operation_directory,
        operation_path,
        "v2 GC operation directory",
    )?;
    Ok(publication)
}

fn finish_control_publication(
    operation_directory: &File,
    operation_path: &Path,
    final_file: &File,
    publication: ControlPublication,
    context: &str,
) -> std::io::Result<()> {
    let final_identity = verified_control_file(final_file, final_file.metadata()?.len())?;
    match publication {
        ControlPublication::Published(staged_identity) => {
            if final_identity != staged_identity {
                return Err(io_invalid(format!(
                    "published {context} changed inode at final-name rename; preserving every control file"
                )));
            }
        }
        ControlPublication::Existing => {
            sync_open_file(final_file, "persist raced authenticated v2 GC control")?;
            sync_open_directory(
                operation_directory,
                "persist raced authenticated v2 GC control final name",
            )?;
            fault::checkpoint(
                DurabilityEvent::Recovery,
                "resume raced authenticated v2 GC control publication",
            )?;
        }
    }
    verify_open_directory_path(
        operation_directory,
        operation_path,
        "v2 GC operation directory",
    )
}

fn sync_open_directory(directory: &File, context: &str) -> std::io::Result<()> {
    directory.sync_all()?;
    fault::checkpoint(DurabilityEvent::DirectorySync, context)
}

fn sync_open_file(file: &File, context: &str) -> std::io::Result<()> {
    file.sync_all()?;
    fault::checkpoint(DurabilityEvent::FileSync, context)
}

#[cfg(unix)]
fn verify_open_directory_path(directory: &File, path: &Path, context: &str) -> std::io::Result<()> {
    let opened = directory.metadata()?;
    let current = fs::symlink_metadata(path)?;
    if !opened.is_dir()
        || !current.file_type().is_dir()
        || current.file_type().is_symlink()
        || opened.dev() != current.dev()
        || opened.ino() != current.ino()
    {
        return Err(io_invalid(format!(
            "{context} changed identity while the offline GC operation was running"
        )));
    }
    Ok(())
}

#[cfg(not(unix))]
fn verify_open_directory_path(
    _directory: &File,
    _path: &Path,
    _context: &str,
) -> std::io::Result<()> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "pinned directory identity checks are unavailable on this platform",
    ))
}

fn candidate_state_in_directories(
    objects_directory: &File,
    quarantine_directory: &File,
    candidate: &ObjectIdentity,
) -> std::io::Result<(QuarantineState, Option<OpenedObject>, Option<OpenedObject>)> {
    let name = object_name(&candidate.reference.id);
    let source = match verify_object_in_directory(objects_directory, &name, candidate) {
        Ok(object) => Some(object),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
        Err(error) => return Err(error),
    };
    let quarantined = match verify_object_in_directory(quarantine_directory, &name, candidate) {
        Ok(object) => Some(object),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
        Err(error) => return Err(error),
    };
    let state = match (source.is_some(), quarantined.is_some()) {
        (true, false) => QuarantineState::Source,
        (false, true) => QuarantineState::Quarantined,
        (false, false) => QuarantineState::Missing,
        (true, true) => QuarantineState::Both,
    };
    Ok((state, source, quarantined))
}

fn require_candidate_state_in_directories(
    objects_directory: &File,
    quarantine_directory: &File,
    candidates: &[ObjectIdentity],
    expected: QuarantineState,
    operation: &str,
) -> std::io::Result<()> {
    for candidate in candidates {
        let name = object_name(&candidate.reference.id);
        let (actual, _, _) =
            candidate_state_in_directories(objects_directory, quarantine_directory, candidate)?;
        if actual != expected {
            return Err(io_invalid(format!(
                "v2 GC candidate {name} is {actual:?}, not {expected:?}, before {operation}; preserving the operation evidence"
            )));
        }
    }
    Ok(())
}

fn verify_object_at(path: &Path, identity: &ObjectIdentity) -> std::io::Result<VerifiedObject> {
    let before = fs::symlink_metadata(path)?;
    if !before.file_type().is_file()
        || before.file_type().is_symlink()
        || before.len() != identity.ciphertext_len
    {
        return Err(io_invalid(format!(
            "v2 GC object {} is not the planned regular file",
            path.display()
        )));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if before.nlink() != 1 {
            return Err(io_invalid(format!(
                "v2 GC object {} has {} hard links; preserving every name",
                path.display(),
                before.nlink()
            )));
        }
    }
    let ciphertext = read_bounded_regular(path, identity.ciphertext_len)?;
    if ciphertext.len() as u64 != identity.ciphertext_len
        || digest_bytes(&ciphertext) != identity.reference.digest
    {
        return Err(io_invalid(format!(
            "v2 GC object {} differs from its authenticated plan",
            path.display()
        )));
    }
    let after = fs::symlink_metadata(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if after.dev() != before.dev()
            || after.ino() != before.ino()
            || after.nlink() != 1
            || after.len() != before.len()
        {
            return Err(io_invalid(format!(
                "v2 GC object {} changed identity while being authenticated",
                path.display()
            )));
        }
        Ok(VerifiedObject {
            device: after.dev(),
            inode: after.ino(),
        })
    }
    #[cfg(not(unix))]
    {
        if after.len() != before.len() || !after.file_type().is_file() {
            return Err(io_invalid(format!(
                "v2 GC object {} changed while being authenticated",
                path.display()
            )));
        }
        Ok(VerifiedObject {})
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum QuarantineState {
    Source,
    Quarantined,
    Missing,
    Both,
}

fn candidate_state(
    paths: &OperationPaths,
    candidate: &ObjectIdentity,
) -> std::io::Result<QuarantineState> {
    let name = object_name(&candidate.reference.id);
    let source = paths.objects.join(&name);
    let quarantined = paths.quarantine.join(&name);
    let source_exists = backing_entry_exists(&source)?;
    let quarantined_exists = backing_entry_exists(&quarantined)?;
    if source_exists {
        verify_object_at(&source, candidate)?;
    }
    if quarantined_exists {
        verify_object_at(&quarantined, candidate)?;
    }
    Ok(match (source_exists, quarantined_exists) {
        (true, false) => QuarantineState::Source,
        (false, true) => QuarantineState::Quarantined,
        (false, false) => QuarantineState::Missing,
        (true, true) => QuarantineState::Both,
    })
}

fn validate_resume_snapshot(
    base_path: &Path,
    key: &[u8; 32],
    plan: &GcPlan,
) -> std::io::Result<()> {
    let (_, current_kdf_fingerprint) = load_kdf_with_fingerprint(base_path)
        .map_err(io_invalid)?
        .ok_or_else(|| io_invalid("KDF metadata disappeared during v2 GC"))?;
    if current_kdf_fingerprint != plan.core.kdf_fingerprint {
        return Err(io_invalid(
            "KDF metadata changed after v2 GC preview; preserving the operation",
        ));
    }
    let current = collect_live_scan(
        base_path,
        key,
        &current_kdf_fingerprint,
        Some(&plan.plan_id),
    )?;
    if current.object_namespace != plan.core.object_namespace
        || current.anchors != plan.core.anchors
    {
        return Err(io_invalid(
            "v2 GC anchors changed after preview; preserve the quarantine and create no new mutations",
        ));
    }
    let paths = operation_paths(base_path, &plan.plan_id)?;
    let candidate_ids: HashSet<_> = plan
        .core
        .candidates
        .iter()
        .map(|candidate| candidate.reference.id)
        .collect();
    let mut expected_objects = Vec::new();
    for object in &plan.core.objects {
        if candidate_ids.contains(&object.reference.id) {
            match candidate_state(&paths, object)? {
                QuarantineState::Source => {
                    expected_objects.push(object.clone());
                }
                QuarantineState::Quarantined => {}
                QuarantineState::Missing => {
                    return Err(io_invalid(format!(
                        "planned v2 GC object {} is missing from source and quarantine",
                        object_name(&object.reference.id)
                    )));
                }
                QuarantineState::Both => {
                    return Err(io_invalid(format!(
                        "planned v2 GC object {} exists in source and quarantine; preserving both",
                        object_name(&object.reference.id)
                    )));
                }
            }
        } else {
            expected_objects.push(object.clone());
        }
    }
    let current_objects: Vec<_> = current.inventory.values().cloned().collect();
    let expected_protected: HashSet<_> = plan
        .core
        .objects
        .iter()
        .filter(|object| !candidate_ids.contains(&object.reference.id))
        .map(|object| object.reference.id)
        .collect();
    if current_objects != expected_objects || current.protected != expected_protected {
        return Err(io_invalid(
            "v2 object inventory changed after GC preview; refusing stale or provider-raced plan",
        ));
    }
    Ok(())
}

fn sync_directory(path: &Path, context: &str) -> std::io::Result<()> {
    File::open(path)?.sync_all()?;
    fault::checkpoint(DurabilityEvent::DirectorySync, context)
}

fn quarantine_plan(base_path: &Path, key: &[u8; 32], plan: &GcPlan) -> std::io::Result<()> {
    if plan.core.candidates.is_empty() {
        return Err(io_invalid("v2 GC preview contains no orphan candidates"));
    }
    persist_gc_plan(base_path, key, plan)?;
    let paths = operation_paths(base_path, &plan.plan_id)?;
    if read_marker(&paths, key, &plan.plan_id, "restore")?
        || read_marker(&paths, key, &plan.plan_id, "purge-intent")?
        || read_marker(&paths, key, &plan.plan_id, "purge")?
    {
        return Err(io_invalid(
            "v2 GC plan has already entered restore or purge; it cannot be quarantined again",
        ));
    }
    validate_resume_snapshot(base_path, key, plan)?;
    let objects_directory = open_real_directory(&paths.objects)?;
    let quarantine_directory = open_real_directory(&paths.quarantine)?;
    for candidate in &plan.core.candidates {
        validate_resume_snapshot(base_path, key, plan)?;
        verify_open_directory_path(&objects_directory, &paths.objects, "v2 object namespace")?;
        verify_open_directory_path(
            &quarantine_directory,
            &paths.quarantine,
            "v2 GC quarantine directory",
        )?;
        let name = object_name(&candidate.reference.id);
        let (state, source, quarantined) =
            candidate_state_in_directories(&objects_directory, &quarantine_directory, candidate)?;
        match state {
            QuarantineState::Source => {
                let verified = source.ok_or_else(|| {
                    io_invalid(format!(
                        "v2 GC candidate {name} disappeared before quarantine rename"
                    ))
                })?;
                renameat_noreplace(&objects_directory, &quarantine_directory, &name)?;
                fault::checkpoint(
                    DurabilityEvent::Rename,
                    "move unreachable immutable v2 object into quarantine",
                )?;
                fault::checkpoint(
                    DurabilityEvent::Cleanup,
                    "remove unreachable immutable v2 object from live namespace",
                )?;
                let moved = verify_object_in_directory(&quarantine_directory, &name, candidate)?;
                if moved.verified != verified.verified {
                    return Err(io_invalid(format!(
                        "v2 GC candidate {name} changed identity at quarantine rename; preserving the moved bytes"
                    )));
                }
                sync_open_file(
                    &moved.file,
                    "persist complete immutable v2 quarantine object",
                )?;
                sync_open_directory(&quarantine_directory, "persist v2 GC quarantine object")?;
                sync_open_directory(&objects_directory, "persist v2 GC source removal")?;
            }
            QuarantineState::Quarantined => {
                let quarantined = quarantined.ok_or_else(|| {
                    io_invalid(format!(
                        "v2 GC candidate {name} disappeared during quarantine recovery"
                    ))
                })?;
                sync_open_file(
                    &quarantined.file,
                    "persist resumed immutable v2 quarantine object",
                )?;
                sync_open_directory(&quarantine_directory, "recover v2 GC quarantine object")?;
                sync_open_directory(&objects_directory, "recover v2 GC source removal")?;
                fault::checkpoint(
                    DurabilityEvent::Recovery,
                    "resume already quarantined immutable v2 object",
                )?;
            }
            QuarantineState::Missing => {
                return Err(io_invalid(format!(
                    "v2 GC candidate {name} disappeared from source and quarantine"
                )));
            }
            QuarantineState::Both => {
                return Err(io_invalid(format!(
                    "v2 GC candidate {name} exists in source and quarantine; preserving both"
                )));
            }
        }
    }
    validate_resume_snapshot(base_path, key, plan)?;
    verify_open_directory_path(&objects_directory, &paths.objects, "v2 object namespace")?;
    verify_open_directory_path(
        &quarantine_directory,
        &paths.quarantine,
        "v2 GC quarantine directory",
    )?;
    require_candidate_state_in_directories(
        &objects_directory,
        &quarantine_directory,
        &plan.core.candidates,
        QuarantineState::Quarantined,
        "quarantine completion",
    )?;
    write_marker(&paths, key, &plan.plan_id, "quarantine")?;
    audit_gc_operations(base_path, key, Some(&plan.plan_id))?;
    Ok(())
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn ensure_gc_mutation_supported() -> Result<(), String> {
    Ok(())
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn ensure_gc_mutation_supported() -> Result<(), String> {
    Err(
        "v2 GC mutation requires pinned no-follow directory operations and atomic no-replace rename support available on macOS or Linux"
            .to_string(),
    )
}

pub(crate) fn gc_quarantine(
    base_path: &Path,
    passphrase: &str,
    expected_plan_id: &str,
) -> Result<GcPreview, String> {
    ensure_gc_mutation_supported()?;
    crate::fs::ensure_no_index_siblings(base_path).map_err(|error| error.to_string())?;
    crate::fs::ensure_unambiguous_format_heads(base_path).map_err(|error| error.to_string())?;
    let (key, kdf_fingerprint) = load_key(base_path, passphrase)?;
    validate_plan_id(expected_plan_id).map_err(|error| error.to_string())?;
    audit_gc_operations(base_path, &key, Some(expected_plan_id))
        .map_err(|error| error.to_string())?;
    let plan = match read_gc_plan(base_path, &key, expected_plan_id)
        .map_err(|error| error.to_string())?
    {
        Some(plan) => {
            if plan.core.kdf_fingerprint != kdf_fingerprint {
                return Err(
                        "KDF metadata changed since the authenticated v2 GC plan; preserving the operation"
                            .to_string(),
                    );
            }
            plan
        }
        None => {
            let scan =
                scan_v2_with_context(base_path, &key, &kdf_fingerprint, Some(expected_plan_id))
                    .map_err(|error| error.to_string())?;
            if scan.plan.plan_id != expected_plan_id {
                return Err(format!(
                    "v2 GC preview is stale: expected plan {}, current plan is {}",
                    expected_plan_id, scan.plan.plan_id
                ));
            }
            scan.plan
        }
    };
    quarantine_plan(base_path, &key, &plan).map_err(|error| error.to_string())?;
    let candidate_bytes = plan
        .core
        .candidates
        .iter()
        .map(|candidate| candidate.ciphertext_len)
        .sum();
    Ok(GcPreview {
        is_v2: true,
        plan_id: Some(plan.plan_id),
        reachable_objects: plan.core.objects.len() - plan.core.candidates.len(),
        candidate_objects: plan.core.candidates.len(),
        candidate_bytes,
        candidate_names: plan
            .core
            .candidates
            .iter()
            .map(|candidate| object_name(&candidate.reference.id))
            .collect(),
    })
}

fn load_existing_operation(
    base_path: &Path,
    passphrase: &str,
    plan_id: &str,
    require_exact_kdf: bool,
) -> Result<([u8; 32], RecoveryFingerprint, GcPlan, OperationPaths), String> {
    crate::fs::ensure_no_index_siblings(base_path).map_err(|error| error.to_string())?;
    crate::fs::ensure_unambiguous_format_heads(base_path).map_err(|error| error.to_string())?;
    let (key, kdf_fingerprint) = load_key(base_path, passphrase)?;
    validate_plan_id(plan_id).map_err(|error| error.to_string())?;
    audit_gc_operations(base_path, &key, Some(plan_id)).map_err(|error| error.to_string())?;
    let plan = read_gc_plan(base_path, &key, plan_id)
        .map_err(|error| error.to_string())?
        .ok_or_else(|| format!("no authenticated v2 GC plan {plan_id} exists"))?;
    if require_exact_kdf && plan.core.kdf_fingerprint != kdf_fingerprint {
        return Err(
            "KDF metadata changed since the authenticated v2 GC plan; preserving the operation"
                .to_string(),
        );
    }
    let paths = operation_paths(base_path, plan_id).map_err(|error| error.to_string())?;
    Ok((key, kdf_fingerprint, plan, paths))
}

pub(crate) fn gc_restore(
    base_path: &Path,
    passphrase: &str,
    plan_id: &str,
) -> Result<usize, String> {
    ensure_gc_mutation_supported()?;
    let (key, _, plan, paths) = load_existing_operation(base_path, passphrase, plan_id, false)?;
    if read_marker(&paths, &key, plan_id, "purge-intent").map_err(|error| error.to_string())?
        || read_marker(&paths, &key, plan_id, "purge").map_err(|error| error.to_string())?
    {
        return Err(
            "v2 GC purge has started; restoring an incomplete set would hide deletion evidence"
                .to_string(),
        );
    }
    let objects_directory =
        open_real_directory(&paths.objects).map_err(|error| error.to_string())?;
    let quarantine_directory =
        open_real_directory(&paths.quarantine).map_err(|error| error.to_string())?;
    for candidate in &plan.core.candidates {
        verify_open_directory_path(&objects_directory, &paths.objects, "v2 object namespace")
            .map_err(|error| error.to_string())?;
        verify_open_directory_path(
            &quarantine_directory,
            &paths.quarantine,
            "v2 GC quarantine directory",
        )
        .map_err(|error| error.to_string())?;
        let name = object_name(&candidate.reference.id);
        let (state, source, quarantined) =
            candidate_state_in_directories(&objects_directory, &quarantine_directory, candidate)
                .map_err(|error| error.to_string())?;
        match state {
            QuarantineState::Quarantined => {
                let verified = quarantined.ok_or_else(|| {
                    format!("v2 GC candidate {name} disappeared before restore rename")
                })?;
                renameat_noreplace(&quarantine_directory, &objects_directory, &name)
                    .map_err(|error| error.to_string())?;
                fault::checkpoint(
                    DurabilityEvent::Rename,
                    "restore immutable v2 object from GC quarantine",
                )
                .map_err(|error| error.to_string())?;
                fault::checkpoint(
                    DurabilityEvent::Cleanup,
                    "remove restored immutable v2 object from GC quarantine namespace",
                )
                .map_err(|error| error.to_string())?;
                let moved = verify_object_in_directory(&objects_directory, &name, candidate)
                    .map_err(|error| error.to_string())?;
                if moved.verified != verified.verified {
                    return Err(format!(
                        "v2 GC candidate {name} changed identity at restore rename; preserving the moved bytes"
                    ));
                }
                sync_open_file(&moved.file, "persist complete restored immutable v2 object")
                    .map_err(|error| error.to_string())?;
                sync_open_directory(&objects_directory, "persist restored immutable v2 object")
                    .map_err(|error| error.to_string())?;
                sync_open_directory(&quarantine_directory, "persist v2 GC quarantine restore")
                    .map_err(|error| error.to_string())?;
            }
            QuarantineState::Source => {
                let source = source.ok_or_else(|| {
                    format!("v2 GC candidate {name} disappeared during restore recovery")
                })?;
                sync_open_file(&source.file, "persist resumed restored immutable v2 object")
                    .map_err(|error| error.to_string())?;
                sync_open_directory(&objects_directory, "recover restored immutable v2 object")
                    .map_err(|error| error.to_string())?;
                sync_open_directory(&quarantine_directory, "recover v2 GC quarantine restore")
                    .map_err(|error| error.to_string())?;
                fault::checkpoint(
                    DurabilityEvent::Recovery,
                    "resume already restored immutable v2 object",
                )
                .map_err(|error| error.to_string())?;
            }
            QuarantineState::Missing => {
                return Err(format!(
                    "v2 GC object {name} is missing from source and quarantine; preserving the operation evidence"
                ));
            }
            QuarantineState::Both => {
                return Err(format!(
                    "v2 GC object {name} exists in source and quarantine; preserving both"
                ));
            }
        }
    }
    write_marker(&paths, &key, plan_id, "restore").map_err(|error| error.to_string())?;
    audit_gc_operations(base_path, &key, Some(plan_id)).map_err(|error| error.to_string())?;
    Ok(plan.core.candidates.len())
}

fn validate_purge_snapshot(
    base_path: &Path,
    key: &[u8; 32],
    plan: &GcPlan,
    intent_exists: bool,
) -> std::io::Result<HashMap<[u8; 16], PurgeTombstoneEvidence>> {
    let (_, current_kdf_fingerprint) = load_kdf_with_fingerprint(base_path)
        .map_err(io_invalid)?
        .ok_or_else(|| io_invalid("KDF metadata disappeared during v2 GC purge"))?;
    if current_kdf_fingerprint != plan.core.kdf_fingerprint {
        return Err(io_invalid(
            "KDF metadata changed before v2 GC purge; preserving the quarantine",
        ));
    }
    let current = collect_live_scan(
        base_path,
        key,
        &current_kdf_fingerprint,
        Some(&plan.plan_id),
    )?;
    if current.object_namespace != plan.core.object_namespace
        || current.anchors != plan.core.anchors
    {
        return Err(io_invalid(
            "v2 GC anchors changed before purge; preserving the quarantine",
        ));
    }
    let candidate_ids: HashSet<_> = plan
        .core
        .candidates
        .iter()
        .map(|candidate| candidate.reference.id)
        .collect();
    let expected_objects: Vec<_> = plan
        .core
        .objects
        .iter()
        .filter(|object| !candidate_ids.contains(&object.reference.id))
        .cloned()
        .collect();
    let current_objects: Vec<_> = current.inventory.values().cloned().collect();
    let expected_protected: HashSet<_> = expected_objects
        .iter()
        .map(|object| object.reference.id)
        .collect();
    if current_objects != expected_objects || current.protected != expected_protected {
        return Err(io_invalid(
            "v2 object inventory changed after quarantine; refusing purge",
        ));
    }
    let paths = operation_paths(base_path, &plan.plan_id)?;
    let tombstones = inspect_purge_tombstones(base_path, &paths, plan)?;
    if !intent_exists && !tombstones.is_empty() {
        return Err(io_invalid(
            "v2 GC purge tombstones exist before durable authenticated purge intent; preserving them",
        ));
    }
    for candidate in &plan.core.candidates {
        let state = candidate_state(&paths, candidate)?;
        let tombstone = tombstones
            .get(&candidate.reference.id)
            .map(|evidence| evidence.state);
        match (state, tombstone) {
            (QuarantineState::Quarantined, None) => {}
            (
                QuarantineState::Missing,
                Some(PurgeTombstoneState::Full | PurgeTombstoneState::Reclaimed),
            ) if intent_exists => {}
            (QuarantineState::Missing, None) if !intent_exists => {
                return Err(io_invalid(format!(
                    "v2 GC candidate {} disappeared before durable purge intent",
                    object_name(&candidate.reference.id)
                )));
            }
            (QuarantineState::Source, _) => {
                return Err(io_invalid(format!(
                    "v2 GC candidate {} reappeared in the live object namespace",
                    object_name(&candidate.reference.id)
                )));
            }
            (QuarantineState::Both, _) => {
                return Err(io_invalid(format!(
                    "v2 GC candidate {} exists in source and quarantine; preserving both",
                    object_name(&candidate.reference.id)
                )));
            }
            (state, tombstone) => {
                return Err(io_invalid(format!(
                    "v2 GC candidate {} has ambiguous purge state {state:?} with tombstone {tombstone:?}; preserving every name",
                    object_name(&candidate.reference.id)
                )));
            }
        }
    }
    Ok(tombstones)
}

pub(crate) fn gc_purge(
    base_path: &Path,
    passphrase: &str,
    plan_id: &str,
) -> Result<(usize, u64), String> {
    ensure_gc_mutation_supported()?;
    let (key, _, plan, paths) = load_existing_operation(base_path, passphrase, plan_id, true)?;
    let operation_directory =
        open_real_directory(&paths.operation).map_err(|error| error.to_string())?;
    verify_open_directory_path(
        &operation_directory,
        &paths.operation,
        "v2 GC operation directory",
    )
    .map_err(|error| error.to_string())?;
    if !read_marker(&paths, &key, plan_id, "quarantine").map_err(|error| error.to_string())? {
        return Err("v2 GC quarantine is incomplete; resume it before purge".to_string());
    }
    if read_marker(&paths, &key, plan_id, "restore").map_err(|error| error.to_string())? {
        return Err("v2 GC plan was restored and cannot be purged".to_string());
    }
    let intent_exists =
        read_marker(&paths, &key, plan_id, "purge-intent").map_err(|error| error.to_string())?;
    if !intent_exists {
        return Err(
            "physical v2 GC reclaim is disabled: current platforms provide no primitive which can atomically authenticate an inode and exclude concurrent rename, write, or hard-link mutation; the complete quarantine remains restorable and no purge intent was published"
                .to_string(),
        );
    }
    let tombstones =
        validate_purge_snapshot(base_path, &key, &plan, true).map_err(|error| error.to_string())?;
    for candidate in &plan.core.candidates {
        let state = candidate_state(&paths, candidate).map_err(|error| error.to_string())?;
        let tombstone = tombstones
            .get(&candidate.reference.id)
            .map(|evidence| evidence.state);
        if state != QuarantineState::Missing || tombstone != Some(PurgeTombstoneState::Reclaimed) {
            return Err(format!(
                "physical v2 GC reclaim cannot safely resume candidate {} from state {state:?} with tombstone {tombstone:?}; preserving the complete quarantine or full tombstone",
                object_name(&candidate.reference.id)
            ));
        }
    }
    let quarantine_directory = openat_directory(&operation_directory, GC_QUARANTINE_DIRECTORY)
        .map_err(|error| error.to_string())?;
    let purge_tombstone_directory =
        openat_directory(&operation_directory, GC_PURGE_TOMBSTONE_DIRECTORY)
            .map_err(|error| error.to_string())?;
    write_marker(&paths, &key, plan_id, "quarantine").map_err(|error| error.to_string())?;
    write_marker(&paths, &key, plan_id, "purge-intent").map_err(|error| error.to_string())?;
    fault::checkpoint(
        DurabilityEvent::Recovery,
        "resume durably published authenticated v2 GC purge intent",
    )
    .map_err(|error| error.to_string())?;

    let objects_directory =
        open_real_directory(&paths.objects).map_err(|error| error.to_string())?;
    verify_open_directory_path(
        &operation_directory,
        &paths.operation,
        "v2 GC operation directory",
    )
    .map_err(|error| error.to_string())?;
    for candidate in &plan.core.candidates {
        verify_open_directory_path(
            &operation_directory,
            &paths.operation,
            "v2 GC operation directory",
        )
        .map_err(|error| error.to_string())?;
        verify_open_directory_path(&objects_directory, &paths.objects, "v2 object namespace")
            .map_err(|error| error.to_string())?;
        verify_open_directory_path(
            &quarantine_directory,
            &paths.quarantine,
            "v2 GC quarantine directory",
        )
        .map_err(|error| error.to_string())?;
        verify_open_directory_path(
            &purge_tombstone_directory,
            &paths.purge_tombstones,
            "v2 GC purge-tombstone directory",
        )
        .map_err(|error| error.to_string())?;
        let name = object_name(&candidate.reference.id);
        let tombstone_name = purge_tombstone_name(&candidate.reference.id);
        let (state, _, _) =
            candidate_state_in_directories(&objects_directory, &quarantine_directory, candidate)
                .map_err(|error| error.to_string())?;
        if state != QuarantineState::Missing {
            return Err(format!(
                "v2 GC compatibility recovery observed candidate {name} change to state {state:?}; preserving every name"
            ));
        }
        let reclaimed =
            verify_reclaimed_tombstone_in_directory(&purge_tombstone_directory, &tombstone_name)
                .map_err(|error| error.to_string())?;
        sync_open_file(
            &reclaimed.file,
            "persist resumed reclaimed v2 GC purge tombstone",
        )
        .map_err(|error| error.to_string())?;
        sync_open_directory(
            &purge_tombstone_directory,
            "recover reclaimed v2 GC purge tombstone name",
        )
        .map_err(|error| error.to_string())?;
        sync_open_directory(
            &quarantine_directory,
            "recover empty v2 GC quarantine namespace",
        )
        .map_err(|error| error.to_string())?;
        fault::checkpoint(
            DurabilityEvent::Recovery,
            "resume previously reclaimed v2 GC purge tombstone",
        )
        .map_err(|error| error.to_string())?;
    }
    let tombstones =
        validate_purge_snapshot(base_path, &key, &plan, true).map_err(|error| error.to_string())?;
    verify_open_directory_path(
        &operation_directory,
        &paths.operation,
        "v2 GC operation directory",
    )
    .map_err(|error| error.to_string())?;
    verify_open_directory_path(&objects_directory, &paths.objects, "v2 object namespace")
        .map_err(|error| error.to_string())?;
    verify_open_directory_path(
        &quarantine_directory,
        &paths.quarantine,
        "v2 GC quarantine directory",
    )
    .map_err(|error| error.to_string())?;
    require_candidate_state_in_directories(
        &objects_directory,
        &quarantine_directory,
        &plan.core.candidates,
        QuarantineState::Missing,
        "purge completion",
    )
    .map_err(|error| error.to_string())?;
    verify_open_directory_path(
        &purge_tombstone_directory,
        &paths.purge_tombstones,
        "v2 GC purge-tombstone directory",
    )
    .map_err(|error| error.to_string())?;
    for candidate in &plan.core.candidates {
        if tombstones
            .get(&candidate.reference.id)
            .map(|evidence| evidence.state)
            != Some(PurgeTombstoneState::Reclaimed)
        {
            return Err(format!(
                "v2 GC candidate {} has no exact reclaimed tombstone before purge completion",
                object_name(&candidate.reference.id)
            ));
        }
    }
    write_marker(&paths, &key, plan_id, "purge").map_err(|error| error.to_string())?;
    verify_open_directory_path(
        &operation_directory,
        &paths.operation,
        "v2 GC operation directory",
    )
    .map_err(|error| error.to_string())?;
    audit_gc_operations(base_path, &key, Some(plan_id)).map_err(|error| error.to_string())?;
    let bytes = plan
        .core
        .candidates
        .iter()
        .map(|candidate| candidate.ciphertext_len)
        .sum();
    Ok((plan.core.candidates.len(), bytes))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{
        KdfParams, SALT_LEN, derive_key, encrypt_blob, encrypt_index, kdf_path, save_kdf,
    };
    use crate::fault::FaultInjectionGuard;
    use crate::fs::{DirChild, InodeEntry, durable_write};
    use std::io::Write;
    use std::sync::atomic::{AtomicU64, Ordering};

    static TEST_ID: AtomicU64 = AtomicU64::new(0);
    const PASSPHRASE: &str = "gc-test-passphrase";

    fn test_directory(label: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "zerotrust-drive-v2-gc-{label}-{}-{}",
            std::process::id(),
            TEST_ID.fetch_add(1, Ordering::Relaxed)
        ))
    }

    fn test_index(name: &str) -> DiskIndex {
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

    fn create_store(label: &str) -> (PathBuf, [u8; 32], RecoveryFingerprint, DiskIndex) {
        let directory = test_directory(label);
        fs::create_dir_all(&directory).unwrap();
        let kdf = KdfParams {
            format_version: crate::crypto::FORMAT_VERSION,
            algorithm: "argon2id".to_string(),
            salt: vec![0x5a; SALT_LEN],
            m_cost: 32,
            t_cost: 1,
            p_cost: 1,
        };
        save_kdf(&directory, &kdf).unwrap();
        let key = try_derive_key(PASSPHRASE, &kdf).unwrap();
        let (_, kdf_fingerprint) = load_kdf_with_fingerprint(&directory).unwrap().unwrap();
        let index = test_index("live.txt");
        let json = serde_json::to_vec(&index).unwrap();
        commit(&directory, &key, &json, None, &kdf_fingerprint).unwrap();
        (directory, key, kdf_fingerprint, index)
    }

    fn add_orphan(directory: &Path, key: &[u8; 32], bytes: &[u8]) -> ObjectRef {
        write_object(directory, key, ObjectKind::Data, bytes).unwrap()
    }

    fn add_orphan_graph(directory: &Path, key: &[u8; 32]) -> [ObjectRef; 3] {
        let data = add_orphan(directory, key, b"orphan graph payload");
        let tree = write_tree(
            directory,
            key,
            &TreeNode {
                format_version: FORMAT_VERSION,
                height: 0,
                slots: vec![TreeSlot {
                    slot: 0,
                    child: data,
                }],
            },
        )
        .unwrap();
        let file_root = write_file_root(
            directory,
            key,
            &FileRoot {
                format_version: FORMAT_VERSION,
                size: b"orphan graph payload".len() as u64,
                height: 0,
                tree: Some(tree),
            },
        )
        .unwrap();
        [data, tree, decode_file_root(&file_root).unwrap()]
    }

    fn persist_plan_with_partial_graph(
        directory: &Path,
        key: &[u8; 32],
        kdf_fingerprint: &RecoveryFingerprint,
    ) -> (GcPlan, OperationPaths, [ObjectRef; 3]) {
        let graph = add_orphan_graph(directory, key);
        let scan = scan_v2(directory, key, kdf_fingerprint).unwrap();
        assert_eq!(scan.plan.core.candidates.len(), graph.len());
        persist_gc_plan(directory, key, &scan.plan).unwrap();
        let paths = operation_paths(directory, &scan.plan.plan_id).unwrap();
        let name = object_name(&graph[0].id);
        fs::rename(paths.objects.join(&name), paths.quarantine.join(&name)).unwrap();
        File::open(&paths.quarantine).unwrap().sync_all().unwrap();
        File::open(&paths.objects).unwrap().sync_all().unwrap();
        (scan.plan, paths, graph)
    }

    fn create_v1_migration_store(label: &str, content: &[u8]) -> PathBuf {
        let directory = test_directory(label);
        fs::create_dir_all(&directory).unwrap();
        let kdf = KdfParams {
            format_version: crate::crypto::FORMAT_VERSION,
            algorithm: "argon2id".to_string(),
            salt: vec![0x6b; SALT_LEN],
            m_cost: 8,
            t_cost: 1,
            p_cost: 1,
        };
        save_kdf(&directory, &kdf).unwrap();
        let key = derive_key("migration-passphrase", &kdf);
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
            name: "legacy.bin".to_string(),
            kind: InodeKind::File,
            disk_filename: "000001.age".to_string(),
            size: content.len() as u64,
            perm: 0o600,
            uid: 501,
            gid: 20,
            atime_secs: 1,
            mtime_secs: 1,
            ctime_secs: 1,
            nlink: 1,
            parent: 1,
        };
        let index = DiskIndex {
            next_inode: 3,
            next_file_id: 2,
            inodes: HashMap::from([(1, root), (2, file)]),
            children: HashMap::from([(
                1,
                vec![DirChild {
                    name: "legacy.bin".to_string(),
                    inode: 2,
                }],
            )]),
        };
        durable_write(
            &directory.join("000001.age"),
            &encrypt_blob(&key, "000001.age", content).unwrap(),
        )
        .unwrap();
        durable_write(
            &directory.join("_index.age"),
            &encrypt_index(&key, &serde_json::to_vec(&index).unwrap()).unwrap(),
        )
        .unwrap();
        directory
    }

    fn write_test_object(
        directory: &Path,
        key: &[u8; 32],
        kind: ObjectKind,
        id: [u8; 16],
        plaintext: &[u8],
    ) -> ObjectRef {
        let ciphertext = encrypt_bytes(key, plaintext, &object_aad(kind, &id)).unwrap();
        let reference = ObjectRef {
            id,
            digest: digest_bytes(&ciphertext),
        };
        fs::write(object_path(directory, &reference).unwrap(), ciphertext).unwrap();
        reference
    }

    fn gc_plan_ciphertext(key: &[u8; 32], plan: &GcPlan) -> Vec<u8> {
        let plaintext = serde_json::to_vec(plan).unwrap();
        encrypt_bytes(key, &plaintext, &plan_aad(&plan.plan_id)).unwrap()
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

    fn tree_snapshot(root: &Path) -> Vec<(String, Vec<u8>)> {
        fn visit(base: &Path, path: &Path, output: &mut Vec<(String, Vec<u8>)>) {
            let mut entries: Vec<_> = fs::read_dir(path)
                .unwrap()
                .map(|entry| entry.unwrap())
                .collect();
            entries.sort_by_key(|entry| entry.file_name());
            for entry in entries {
                if entry.file_type().unwrap().is_dir() {
                    visit(base, &entry.path(), output);
                } else {
                    output.push((
                        entry
                            .path()
                            .strip_prefix(base)
                            .unwrap()
                            .to_string_lossy()
                            .into_owned(),
                        fs::read(entry.path()).unwrap(),
                    ));
                }
            }
        }
        let mut output = Vec::new();
        visit(root, root, &mut output);
        output
    }

    #[test]
    fn preview_is_mutation_free_and_v1_preview_is_a_noop() {
        let (directory, key, _, _) = create_store("preview");
        let orphan = add_orphan(&directory, &key, b"orphan");
        let before = tree_snapshot(&directory);

        let first = gc_preview(&directory, PASSPHRASE).unwrap();
        let second = gc_preview(&directory, PASSPHRASE).unwrap();
        assert!(first.is_v2);
        assert_eq!(first.plan_id, second.plan_id);
        assert_eq!(first.candidate_objects, 1);
        assert_eq!(first.candidate_names, vec![object_name(&orphan.id)]);
        assert_eq!(tree_snapshot(&directory), before);
        assert!(
            !selected_object_directory(&directory)
                .unwrap()
                .join(GC_DIRECTORY)
                .exists()
        );

        let v1 = test_directory("v1-preview");
        fs::create_dir_all(&v1).unwrap();
        fs::write(v1.join("_index.age"), b"v1-only").unwrap();
        let v1_before = tree_snapshot(&v1);
        let report = gc_preview(&v1, PASSPHRASE).unwrap();
        assert!(!report.is_v2);
        assert_eq!(tree_snapshot(&v1), v1_before);

        fs::remove_dir_all(directory).unwrap();
        fs::remove_dir_all(v1).unwrap();
    }

    #[test]
    fn quarantine_restore_and_purge_preserve_the_authenticated_root() {
        let (restore_dir, key, _, index) = create_store("restore");
        let orphan = add_orphan(&restore_dir, &key, b"restore-orphan");
        let root_before = fs::read(restore_dir.join(ROOT_FILE)).unwrap();
        let id = gc_preview(&restore_dir, PASSPHRASE)
            .unwrap()
            .plan_id
            .unwrap();
        gc_quarantine(&restore_dir, PASSPHRASE, &id).unwrap();
        let paths = operation_paths(&restore_dir, &id).unwrap();
        assert!(!paths.objects.join(object_name(&orphan.id)).exists());
        assert!(paths.quarantine.join(object_name(&orphan.id)).exists());
        assert_eq!(load(&restore_dir, &key).unwrap().0, index);
        assert_eq!(gc_restore(&restore_dir, PASSPHRASE, &id).unwrap(), 1);
        assert!(paths.objects.join(object_name(&orphan.id)).exists());
        assert!(!paths.quarantine.join(object_name(&orphan.id)).exists());
        assert_eq!(fs::read(restore_dir.join(ROOT_FILE)).unwrap(), root_before);

        let (purge_dir, purge_key, _, purge_index) = create_store("purge");
        let purge_orphan = add_orphan(&purge_dir, &purge_key, b"purge-orphan");
        let purge_root = fs::read(purge_dir.join(ROOT_FILE)).unwrap();
        let purge_id = gc_preview(&purge_dir, PASSPHRASE).unwrap().plan_id.unwrap();
        gc_quarantine(&purge_dir, PASSPHRASE, &purge_id).unwrap();
        let purge_paths = operation_paths(&purge_dir, &purge_id).unwrap();
        let quarantine_path = purge_paths.quarantine.join(object_name(&purge_orphan.id));
        let quarantine_before = fs::read(&quarantine_path).unwrap();
        let purge_before = tree_snapshot(&purge_dir);
        let error = gc_purge(&purge_dir, PASSPHRASE, &purge_id).unwrap_err();
        assert!(
            error.contains("physical v2 GC reclaim is disabled"),
            "{error}"
        );
        assert!(
            !purge_paths
                .objects
                .join(object_name(&purge_orphan.id))
                .exists()
        );
        assert!(purge_paths.operation.join(GC_PLAN_FILE).exists());
        assert_eq!(fs::read(&quarantine_path).unwrap(), quarantine_before);
        assert!(!purge_paths.purge_tombstones.exists());
        assert!(!purge_paths.operation.join(GC_PURGE_INTENT_FILE).exists());
        assert!(!purge_paths.operation.join(GC_PURGE_COMPLETE_FILE).exists());
        assert_eq!(tree_snapshot(&purge_dir), purge_before);
        assert_eq!(load(&purge_dir, &purge_key).unwrap().0, purge_index);
        assert_eq!(fs::read(purge_dir.join(ROOT_FILE)).unwrap(), purge_root);

        fs::remove_dir_all(restore_dir).unwrap();
        fs::remove_dir_all(purge_dir).unwrap();
    }

    #[test]
    fn disabled_fresh_purge_does_not_scan_the_complete_live_store() {
        let (directory, key, _, id) = quarantined_store("purge-disabled-fast");
        let (_, kdf_fingerprint) = load_kdf_with_fingerprint(&directory).unwrap().unwrap();
        let paths = operation_paths(&directory, &id).unwrap();
        let plan = read_gc_plan(&directory, &key, &id).unwrap().unwrap();
        let candidate_ids: HashSet<_> = plan
            .core
            .candidates
            .iter()
            .map(|candidate| candidate.reference.id)
            .collect();
        let protected = plan
            .core
            .objects
            .iter()
            .find(|object| !candidate_ids.contains(&object.reference.id))
            .unwrap();
        fs::remove_file(object_path(&directory, &protected.reference).unwrap()).unwrap();
        assert!(
            collect_live_scan(&directory, &key, &kdf_fingerprint, Some(&id)).is_err(),
            "the fixture must force a complete live-store scan to fail"
        );
        let before = tree_snapshot(&directory);

        let error = gc_purge(&directory, PASSPHRASE, &id).unwrap_err();

        assert!(
            error.contains("physical v2 GC reclaim is disabled"),
            "{error}"
        );
        assert_eq!(tree_snapshot(&directory), before);
        assert!(!paths.operation.join(GC_PURGE_INTENT_FILE).exists());
        assert!(!paths.operation.join(GC_PURGE_COMPLETE_FILE).exists());

        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn untrusted_evidence_and_hardlinked_objects_fail_closed() {
        let (directory, key, kdf_fingerprint, _) = create_store("fail-closed");
        let orphan = add_orphan(&directory, &key, b"evidence");
        let evidence = selected_object_directory(&directory)
            .unwrap()
            .join(EVIDENCE_DIRECTORY)
            .join("provider-conflict.untrusted");
        fs::write(&evidence, b"preserve").unwrap();
        assert!(scan_v2(&directory, &key, &kdf_fingerprint).is_err());
        assert!(object_path(&directory, &orphan).unwrap().exists());
        fs::remove_file(evidence).unwrap();

        let hardlink = directory.join("orphan-hardlink.keep");
        fs::hard_link(object_path(&directory, &orphan).unwrap(), &hardlink).unwrap();
        assert!(scan_v2(&directory, &key, &kdf_fingerprint).is_err());
        assert!(hardlink.exists());
        assert!(object_path(&directory, &orphan).unwrap().exists());

        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn stale_preview_refuses_quarantine_without_creating_gc_state() {
        let (directory, key, kdf_fingerprint, _) = create_store("stale-preview");
        let orphan = add_orphan(&directory, &key, b"stale-orphan");
        let stale_id = gc_preview(&directory, PASSPHRASE).unwrap().plan_id.unwrap();

        let (_, old_state) = load(&directory, &key).unwrap();
        let changed_index = test_index("changed.txt");
        commit(
            &directory,
            &key,
            &serde_json::to_vec(&changed_index).unwrap(),
            Some(&old_state),
            &kdf_fingerprint,
        )
        .unwrap();
        let root_before_attempt = fs::read(directory.join(ROOT_FILE)).unwrap();
        let object_before_attempt = fs::read(object_path(&directory, &orphan).unwrap()).unwrap();

        let error = gc_quarantine(&directory, PASSPHRASE, &stale_id).unwrap_err();
        assert!(error.contains("preview is stale"));
        assert_eq!(
            fs::read(directory.join(ROOT_FILE)).unwrap(),
            root_before_attempt
        );
        assert_eq!(
            fs::read(object_path(&directory, &orphan).unwrap()).unwrap(),
            object_before_attempt
        );
        assert!(
            !selected_object_directory(&directory)
                .unwrap()
                .join(GC_DIRECTORY)
                .exists()
        );

        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn partial_orphan_graph_quarantine_and_pre_marker_restore_resume() {
        let (quarantine_directory, key, kdf_fingerprint, index) =
            create_store("partial-graph-quarantine");
        let (plan, paths, graph) =
            persist_plan_with_partial_graph(&quarantine_directory, &key, &kdf_fingerprint);

        gc_quarantine(&quarantine_directory, PASSPHRASE, &plan.plan_id).unwrap();
        for reference in graph {
            let name = object_name(&reference.id);
            assert!(!paths.objects.join(&name).exists());
            assert!(paths.quarantine.join(&name).exists());
        }
        assert!(read_marker(&paths, &key, &plan.plan_id, "quarantine").unwrap());
        assert_eq!(load(&quarantine_directory, &key).unwrap().0, index);

        let (restore_directory, restore_key, restore_kdf, _) =
            create_store("partial-graph-restore");
        let (restore_plan, restore_paths, restore_graph) =
            persist_plan_with_partial_graph(&restore_directory, &restore_key, &restore_kdf);
        assert!(
            !read_marker(
                &restore_paths,
                &restore_key,
                &restore_plan.plan_id,
                "quarantine"
            )
            .unwrap()
        );

        let (_, previous) = load(&restore_directory, &restore_key).unwrap();
        let changed_index = test_index("root-changed-after-preview.txt");
        commit(
            &restore_directory,
            &restore_key,
            &serde_json::to_vec(&changed_index).unwrap(),
            Some(&previous),
            &restore_kdf,
        )
        .unwrap();
        gc_restore(&restore_directory, PASSPHRASE, &restore_plan.plan_id).unwrap();
        for reference in restore_graph {
            let name = object_name(&reference.id);
            assert!(restore_paths.objects.join(&name).exists());
            assert!(!restore_paths.quarantine.join(&name).exists());
        }
        assert!(
            read_marker(
                &restore_paths,
                &restore_key,
                &restore_plan.plan_id,
                "restore"
            )
            .unwrap()
        );
        assert_eq!(
            load(&restore_directory, &restore_key).unwrap().0,
            changed_index
        );

        fs::remove_dir_all(quarantine_directory).unwrap();
        fs::remove_dir_all(restore_directory).unwrap();
    }

    #[test]
    fn restore_fails_closed_for_both_or_missing_candidate_names() {
        let (both_directory, key, kdf_fingerprint, _) = create_store("restore-both");
        let orphan = add_orphan(&both_directory, &key, b"preserve both");
        let plan = scan_v2(&both_directory, &key, &kdf_fingerprint)
            .unwrap()
            .plan;
        persist_gc_plan(&both_directory, &key, &plan).unwrap();
        let paths = operation_paths(&both_directory, &plan.plan_id).unwrap();
        let name = object_name(&orphan.id);
        fs::copy(paths.objects.join(&name), paths.quarantine.join(&name)).unwrap();
        let error = gc_restore(&both_directory, PASSPHRASE, &plan.plan_id).unwrap_err();
        assert!(error.contains("ambiguous state") || error.contains("exists in source"));
        assert!(paths.objects.join(&name).exists());
        assert!(paths.quarantine.join(&name).exists());

        let (missing_directory, missing_key, missing_kdf, _) = create_store("restore-missing");
        let missing = add_orphan(
            &missing_directory,
            &missing_key,
            b"preserve missing evidence",
        );
        let missing_plan = scan_v2(&missing_directory, &missing_key, &missing_kdf)
            .unwrap()
            .plan;
        persist_gc_plan(&missing_directory, &missing_key, &missing_plan).unwrap();
        let missing_paths = operation_paths(&missing_directory, &missing_plan.plan_id).unwrap();
        fs::remove_file(missing_paths.objects.join(object_name(&missing.id))).unwrap();
        let error = gc_restore(&missing_directory, PASSPHRASE, &missing_plan.plan_id).unwrap_err();
        assert!(error.contains("ambiguous state") || error.contains("missing"));
        assert!(
            !missing_paths
                .operation
                .join(GC_RESTORE_COMPLETE_FILE)
                .exists()
        );

        fs::remove_dir_all(both_directory).unwrap();
        fs::remove_dir_all(missing_directory).unwrap();
    }

    #[test]
    fn active_and_conflicted_gc_names_block_while_completed_records_anchor_new_plans() {
        let (directory, key, kdf_fingerprint, _) = create_store("operation-audit");
        add_orphan(&directory, &key, b"operation audit orphan");
        let first_plan = scan_v2(&directory, &key, &kdf_fingerprint).unwrap().plan;
        persist_gc_plan(&directory, &key, &first_plan).unwrap();
        let active_error = gc_preview(&directory, PASSPHRASE).unwrap_err();
        assert!(active_error.contains("incomplete"), "{active_error}");

        gc_restore(&directory, PASSPHRASE, &first_plan.plan_id).unwrap();
        let second = gc_preview(&directory, PASSPHRASE).unwrap();
        assert_ne!(second.plan_id.as_deref(), Some(first_plan.plan_id.as_str()));
        let namespace = selected_object_directory(&directory).unwrap();

        for conflict_name in ["objects 2", "gc 2"] {
            let conflict = namespace.join(conflict_name);
            fs::create_dir(&conflict).unwrap();
            let error = gc_preview(&directory, PASSPHRASE).unwrap_err();
            assert!(error.contains("unexpected entry"), "{error}");
            assert!(conflict.exists());
            fs::remove_dir(&conflict).unwrap();
        }

        let paths = operation_paths(&directory, &first_plan.plan_id).unwrap();
        let sibling = paths.operation.join("plan 2.age");
        fs::write(&sibling, b"provider conflict").unwrap();
        let error = gc_preview(&directory, PASSPHRASE).unwrap_err();
        assert!(error.contains("unexpected entry"), "{error}");
        assert_eq!(fs::read(&sibling).unwrap(), b"provider conflict");
        fs::remove_file(&sibling).unwrap();

        let extra = paths.quarantine.join("provider-extra.z2");
        fs::write(&extra, b"provider conflict").unwrap();
        let error = gc_preview(&directory, PASSPHRASE).unwrap_err();
        assert!(error.contains("unexpected entry"), "{error}");
        assert_eq!(fs::read(&extra).unwrap(), b"provider conflict");
        fs::remove_file(&extra).unwrap();

        let invalid_operation = paths.gc_root.join("provider operation conflict");
        fs::create_dir(&invalid_operation).unwrap();
        let error = gc_preview(&directory, PASSPHRASE).unwrap_err();
        assert!(error.contains("unexpected entry"), "{error}");
        assert!(invalid_operation.exists());
        fs::remove_dir(&invalid_operation).unwrap();

        let orphan_progress = directory.join(crate::v2_migrate::PROGRESS_DIRECTORY);
        fs::create_dir(&orphan_progress).unwrap();
        let error = gc_preview(&directory, PASSPHRASE).unwrap_err();
        assert!(error.contains("progress exists without an authenticated plan"));
        assert!(orphan_progress.exists());

        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn partial_staged_plan_is_preserved_ignored_and_resume_uses_a_fresh_stage() {
        let (directory, key, _, _) = create_store("partial-staged-plan");
        add_orphan(&directory, &key, b"partial staged plan orphan");
        let preview = gc_preview(&directory, PASSPHRASE).unwrap();
        let id = preview.plan_id.unwrap();
        let paths = operation_paths(&directory, &id).unwrap();
        ensure_operation_directories(&paths).unwrap();
        let partial_name = control_stage_name(GcControlKind::Plan, &[0x41; 16]);
        let partial_path = paths.operation.join(&partial_name);
        fs::write(&partial_path, b"partial ciphertext").unwrap();

        gc_quarantine(&directory, PASSPHRASE, &id).unwrap();
        assert_eq!(fs::read(&partial_path).unwrap(), b"partial ciphertext");
        assert!(paths.operation.join(GC_PLAN_FILE).exists());
        assert!(read_marker(&paths, &key, &id, "quarantine").unwrap());
        let partial_marker_name = control_stage_name(GcControlKind::Restore, &[0x46; 16]);
        let partial_marker_path = paths.operation.join(&partial_marker_name);
        fs::write(&partial_marker_path, b"partial marker ciphertext").unwrap();
        gc_restore(&directory, PASSPHRASE, &id).unwrap();
        assert_eq!(
            fs::read(&partial_marker_path).unwrap(),
            b"partial marker ciphertext"
        );

        let anchored = gc_preview(&directory, PASSPHRASE).unwrap();
        fs::write(&partial_path, b"changed retained stage evidence").unwrap();
        let changed = gc_preview(&directory, PASSPHRASE).unwrap();
        assert_ne!(anchored.plan_id, changed.plan_id);
        assert_eq!(
            fs::read(&partial_path).unwrap(),
            b"changed retained stage evidence"
        );

        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn staged_control_inventory_rejects_conflicts_links_types_and_oversize() {
        let (directory, key, kdf_fingerprint, _) = create_store("staged-control-audit");
        add_orphan(&directory, &key, b"staged control audit orphan");
        let plan = scan_v2(&directory, &key, &kdf_fingerprint).unwrap().plan;
        persist_gc_plan(&directory, &key, &plan).unwrap();
        gc_restore(&directory, PASSPHRASE, &plan.plan_id).unwrap();
        let paths = operation_paths(&directory, &plan.plan_id).unwrap();

        let malformed = paths.operation.join(format!(
            "{} 2",
            control_stage_name(GcControlKind::Plan, &[0x42; 16])
        ));
        fs::write(&malformed, b"provider conflict").unwrap();
        let error = gc_preview(&directory, PASSPHRASE).unwrap_err();
        assert!(error.contains("unexpected entry"), "{error}");
        assert_eq!(fs::read(&malformed).unwrap(), b"provider conflict");
        fs::remove_file(&malformed).unwrap();

        let directory_stage = paths
            .operation
            .join(control_stage_name(GcControlKind::Restore, &[0x43; 16]));
        fs::create_dir(&directory_stage).unwrap();
        let error = gc_preview(&directory, PASSPHRASE).unwrap_err();
        assert!(error.contains("not a bounded real regular file"), "{error}");
        assert!(directory_stage.exists());
        fs::remove_dir(&directory_stage).unwrap();

        let linked_stage = paths
            .operation
            .join(control_stage_name(GcControlKind::Quarantine, &[0x44; 16]));
        fs::write(&linked_stage, b"linked stage evidence").unwrap();
        let second_link = directory.join("retained-stage-hardlink.keep");
        fs::hard_link(&linked_stage, &second_link).unwrap();
        let error = gc_preview(&directory, PASSPHRASE).unwrap_err();
        assert!(error.contains("links; preserving every name"), "{error}");
        assert!(linked_stage.exists());
        assert!(second_link.exists());
        fs::remove_file(&second_link).unwrap();
        fs::remove_file(&linked_stage).unwrap();

        let oversized_stage = paths
            .operation
            .join(control_stage_name(GcControlKind::Plan, &[0x45; 16]));
        let oversized = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&oversized_stage)
            .unwrap();
        oversized.set_len(MAX_GC_PLAN_CIPHERTEXT + 1).unwrap();
        drop(oversized);
        let error = gc_preview(&directory, PASSPHRASE).unwrap_err();
        assert!(error.contains("not a bounded real regular file"), "{error}");
        assert_eq!(
            fs::symlink_metadata(&oversized_stage).unwrap().len(),
            MAX_GC_PLAN_CIPHERTEXT + 1
        );

        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn staged_control_eexist_preserves_fresh_evidence_and_authenticates_final() {
        let (directory, key, kdf_fingerprint, _) = create_store("staged-eexist");
        add_orphan(&directory, &key, b"staged EEXIST orphan");
        let plan = scan_v2(&directory, &key, &kdf_fingerprint).unwrap().plan;
        let paths = operation_paths(&directory, &plan.plan_id).unwrap();
        ensure_operation_directories(&paths).unwrap();
        let operation_directory = open_real_directory(&paths.operation).unwrap();
        let ciphertext = gc_plan_ciphertext(&key, &plan);

        let raced_stage =
            create_staged_control(&operation_directory, GcControlKind::Plan, &ciphertext).unwrap();
        let raced_stage_name = raced_stage.name.clone();
        let winning_stage =
            create_staged_control(&operation_directory, GcControlKind::Plan, &ciphertext).unwrap();
        let winning = publish_staged_control(
            &operation_directory,
            winning_stage,
            GcControlKind::Plan.final_name(),
        )
        .unwrap();
        let (_, winning_file) =
            open_authenticated_plan(&operation_directory, &directory, &key, &plan.plan_id)
                .unwrap()
                .unwrap();
        finish_control_publication(
            &operation_directory,
            &paths.operation,
            &winning_file,
            winning,
            "test winning plan",
        )
        .unwrap();

        let raced = publish_staged_control(
            &operation_directory,
            raced_stage,
            GcControlKind::Plan.final_name(),
        )
        .unwrap();
        assert_eq!(raced, ControlPublication::Existing);
        let (authenticated, raced_file) =
            open_authenticated_plan(&operation_directory, &directory, &key, &plan.plan_id)
                .unwrap()
                .unwrap();
        assert_eq!(authenticated, plan);
        finish_control_publication(
            &operation_directory,
            &paths.operation,
            &raced_file,
            raced,
            "test raced plan",
        )
        .unwrap();
        assert!(paths.operation.join(&raced_stage_name).exists());

        let invalid_directory = test_directory("staged-eexist-invalid");
        copy_directory(&directory, &invalid_directory);
        let invalid_paths = operation_paths(&invalid_directory, &plan.plan_id).unwrap();
        fs::remove_file(invalid_paths.operation.join(GC_PLAN_FILE)).unwrap();
        let invalid_operation = open_real_directory(&invalid_paths.operation).unwrap();
        let retained =
            create_staged_control(&invalid_operation, GcControlKind::Plan, &ciphertext).unwrap();
        let retained_name = retained.name.clone();
        fs::write(invalid_paths.operation.join(GC_PLAN_FILE), b"raced garbage").unwrap();
        let outcome = publish_staged_control(
            &invalid_operation,
            retained,
            GcControlKind::Plan.final_name(),
        )
        .unwrap();
        assert_eq!(outcome, ControlPublication::Existing);
        let error =
            open_authenticated_plan(&invalid_operation, &invalid_directory, &key, &plan.plan_id)
                .unwrap_err();
        assert!(error.to_string().contains("authenticate v2 GC plan"));
        assert!(invalid_paths.operation.join(retained_name).exists());
        assert_eq!(
            fs::read(invalid_paths.operation.join(GC_PLAN_FILE)).unwrap(),
            b"raced garbage"
        );

        fs::remove_dir_all(directory).unwrap();
        fs::remove_dir_all(invalid_directory).unwrap();
    }

    #[test]
    fn relocated_stores_accept_active_completed_and_legacy_path_plans() {
        let (completed_source, key, _, _) = create_store("relocate-completed-source");
        add_orphan(&completed_source, &key, b"completed relocation orphan");
        let completed_id = gc_preview(&completed_source, PASSPHRASE)
            .unwrap()
            .plan_id
            .unwrap();
        gc_quarantine(&completed_source, PASSPHRASE, &completed_id).unwrap();
        gc_restore(&completed_source, PASSPHRASE, &completed_id).unwrap();
        let completed_copy = test_directory("relocate-completed-copy");
        copy_directory(&completed_source, &completed_copy);
        assert!(gc_preview(&completed_copy, PASSPHRASE).unwrap().is_v2);

        let (active_source, active_key, _, _) = create_store("relocate-active-source");
        add_orphan(&active_source, &active_key, b"active relocation orphan");
        let active_id = gc_preview(&active_source, PASSPHRASE)
            .unwrap()
            .plan_id
            .unwrap();
        gc_quarantine(&active_source, PASSPHRASE, &active_id).unwrap();
        let active_copy = test_directory("relocate-active-copy");
        copy_directory(&active_source, &active_copy);
        gc_restore(&active_copy, PASSPHRASE, &active_id).unwrap();

        let (legacy_source, legacy_key, legacy_kdf, _) = create_store("relocate-legacy-source");
        add_orphan(&legacy_source, &legacy_key, b"legacy path plan orphan");
        let mut legacy_plan = scan_v2(&legacy_source, &legacy_key, &legacy_kdf)
            .unwrap()
            .plan;
        legacy_plan.core.canonical_drive_path = Some(
            fs::canonicalize(&legacy_source)
                .unwrap()
                .to_string_lossy()
                .into_owned(),
        );
        legacy_plan.plan_id = plan_id(&legacy_plan.core).unwrap();
        persist_gc_plan(&legacy_source, &legacy_key, &legacy_plan).unwrap();
        let legacy_copy = test_directory("relocate-legacy-copy");
        copy_directory(&legacy_source, &legacy_copy);
        gc_restore(&legacy_copy, PASSPHRASE, &legacy_plan.plan_id).unwrap();

        fs::remove_dir_all(completed_source).unwrap();
        fs::remove_dir_all(completed_copy).unwrap();
        fs::remove_dir_all(active_source).unwrap();
        fs::remove_dir_all(active_copy).unwrap();
        fs::remove_dir_all(legacy_source).unwrap();
        fs::remove_dir_all(legacy_copy).unwrap();
    }

    #[test]
    fn shared_scan_budget_fails_before_unbounded_directory_inventory_growth() {
        let (directory, key, kdf_fingerprint, _) = create_store("shared-scan-budget");
        add_orphan(&directory, &key, b"shared scan budget orphan");
        let plan = scan_v2(&directory, &key, &kdf_fingerprint).unwrap().plan;
        persist_gc_plan(&directory, &key, &plan).unwrap();

        let mut staging_budget = crate::v2_migrate::GcScanBudget::with_limit(0);
        let mut anchors = Vec::new();
        let mut generations = Vec::new();
        let error = scan_staging_roots(
            &directory,
            &key,
            &mut staging_budget,
            &mut anchors,
            &mut generations,
        )
        .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("shared fail-closed GC scan limit")
        );
        assert!(anchors.is_empty());
        assert!(generations.is_empty());

        let mut operation_budget = crate::v2_migrate::GcScanBudget::with_limit(0);
        let error = audit_gc_operations_with_budget(
            &directory,
            &key,
            Some(&plan.plan_id),
            &mut operation_budget,
        )
        .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("shared fail-closed GC scan limit")
        );

        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn shared_scan_budget_combines_object_and_evidence_entries() {
        let (directory, key, _, _) = create_store("combined-object-evidence-budget");
        let namespace = selected_object_directory(&directory).unwrap();
        let evidence = namespace.join(EVIDENCE_DIRECTORY);
        let retained = evidence.join("provider-added-evidence.keep");
        fs::write(&retained, b"retained conflict evidence").unwrap();
        let already_consumed = fs::read_dir(&namespace).unwrap().count()
            + fs::read_dir(namespace.join(OBJECTS_DIRECTORY))
                .unwrap()
                .count();
        let mut budget = crate::v2_migrate::GcScanBudget::with_limit(already_consumed);
        let (_, inventory) = inventory_objects(&directory, &mut budget).unwrap();
        assert!(!inventory.is_empty());

        let mut anchors = Vec::new();
        let mut generations = Vec::new();
        let error = scan_evidence_roots(
            &directory,
            &key,
            &mut budget,
            &HashSet::new(),
            &mut anchors,
            &mut generations,
        )
        .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("shared fail-closed GC scan limit"),
            "{error}"
        );
        assert!(anchors.is_empty());
        assert!(generations.is_empty());
        assert_eq!(fs::read(&retained).unwrap(), b"retained conflict evidence");

        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn kdf_byte_drift_blocks_quarantine_but_not_additive_restore() {
        let (directory, key, kdf_fingerprint, _) = create_store("kdf-byte-drift");
        let orphan = add_orphan(&directory, &key, b"semantic KDF drift");
        let plan = scan_v2(&directory, &key, &kdf_fingerprint).unwrap().plan;
        persist_gc_plan(&directory, &key, &plan).unwrap();
        let paths = operation_paths(&directory, &plan.plan_id).unwrap();
        let name = object_name(&orphan.id);
        fs::rename(paths.objects.join(&name), paths.quarantine.join(&name)).unwrap();
        File::open(&paths.quarantine).unwrap().sync_all().unwrap();
        File::open(&paths.objects).unwrap().sync_all().unwrap();

        let kdf_path = kdf_path(&directory);
        let params: KdfParams = serde_json::from_slice(&fs::read(&kdf_path).unwrap()).unwrap();
        fs::write(&kdf_path, serde_json::to_vec(&params).unwrap()).unwrap();
        let (_, changed_fingerprint) = load_kdf_with_fingerprint(&directory).unwrap().unwrap();
        assert_ne!(changed_fingerprint, kdf_fingerprint);

        let error = gc_quarantine(&directory, PASSPHRASE, &plan.plan_id).unwrap_err();
        assert!(error.contains("KDF metadata changed"), "{error}");
        assert!(paths.quarantine.join(&name).exists());
        gc_restore(&directory, PASSPHRASE, &plan.plan_id).unwrap();
        assert!(paths.objects.join(&name).exists());
        assert!(!paths.quarantine.join(&name).exists());

        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn purge_revalidates_root_after_durable_intent() {
        let (directory, key, _, id) = quarantined_store("purge-root-race");
        let paths = operation_paths(&directory, &id).unwrap();
        write_marker(&paths, &key, &id, "purge-intent").unwrap();
        let quarantined_names: Vec<_> = fs::read_dir(&paths.quarantine)
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect();

        let (mut index, previous) = load(&directory, &key).unwrap();
        index.inodes.get_mut(&2).unwrap().mtime_secs += 1;
        let (_, current_kdf) = load_kdf_with_fingerprint(&directory).unwrap().unwrap();
        commit(
            &directory,
            &key,
            &serde_json::to_vec(&index).unwrap(),
            Some(&previous),
            &current_kdf,
        )
        .unwrap();

        let error = gc_purge(&directory, PASSPHRASE, &id).unwrap_err();
        assert!(error.contains("anchors changed"), "{error}");
        for name in quarantined_names {
            assert!(paths.quarantine.join(name).exists());
        }
        assert!(!paths.operation.join(GC_PURGE_COMPLETE_FILE).exists());

        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn purge_preserves_a_newly_hardlinked_quarantine_candidate() {
        let (directory, key, _, id) = quarantined_store("purge-hardlink-race");
        let paths = operation_paths(&directory, &id).unwrap();
        let plan = read_gc_plan(&directory, &key, &id).unwrap().unwrap();
        let candidate = &plan.core.candidates[0];
        let quarantine = paths.quarantine.join(object_name(&candidate.reference.id));
        let conflict = directory.join("provider-hardlink-conflict.keep");
        if fs::hard_link(&quarantine, &conflict).is_err() {
            fs::remove_dir_all(directory).unwrap();
            return;
        }
        let before = fs::read(&quarantine).unwrap();

        let error = gc_purge(&directory, PASSPHRASE, &id).unwrap_err();
        assert!(error.contains("hard links"), "{error}");
        assert_eq!(fs::read(&quarantine).unwrap(), before);
        assert_eq!(fs::read(&conflict).unwrap(), before);
        assert!(!paths.operation.join(GC_PURGE_INTENT_FILE).exists());
        assert!(!paths.operation.join(GC_PURGE_COMPLETE_FILE).exists());

        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn purge_completion_resumes_from_an_existing_zero_tombstone() {
        let (directory, key, _, id) = quarantined_store("purge-zero-resume");
        let paths = operation_paths(&directory, &id).unwrap();
        let plan = read_gc_plan(&directory, &key, &id).unwrap().unwrap();
        let candidate = &plan.core.candidates[0];
        let source_name = object_name(&candidate.reference.id);
        let tombstone_name = purge_tombstone_name(&candidate.reference.id);
        let operation_directory = open_real_directory(&paths.operation).unwrap();
        let quarantine_directory = open_real_directory(&paths.quarantine).unwrap();
        let tombstone_directory =
            ensure_purge_tombstone_directory(&operation_directory, &paths).unwrap();
        write_marker(&paths, &key, &id, "purge-intent").unwrap();
        renameat_noreplace_names(
            &quarantine_directory,
            &source_name,
            &tombstone_directory,
            &tombstone_name,
        )
        .unwrap();
        verify_object_in_directory(&tombstone_directory, &tombstone_name, candidate).unwrap();
        let tombstone_path = paths.purge_tombstones.join(&tombstone_name);
        let exact = OpenOptions::new()
            .write(true)
            .open(&tombstone_path)
            .unwrap();
        exact.set_len(0).unwrap();
        exact.sync_all().unwrap();
        tombstone_directory.sync_all().unwrap();
        quarantine_directory.sync_all().unwrap();

        assert_eq!(gc_purge(&directory, PASSPHRASE, &id).unwrap().0, 1);
        assert!(read_marker(&paths, &key, &id, "purge").unwrap());
        assert_eq!(
            fs::symlink_metadata(paths.purge_tombstones.join(tombstone_name))
                .unwrap()
                .len(),
            0
        );

        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn purge_preserves_an_existing_full_tombstone() {
        let (directory, key, _, id) = quarantined_store("purge-full-preserved");
        let paths = operation_paths(&directory, &id).unwrap();
        let plan = read_gc_plan(&directory, &key, &id).unwrap().unwrap();
        let candidate = &plan.core.candidates[0];
        let source_name = object_name(&candidate.reference.id);
        let tombstone_name = purge_tombstone_name(&candidate.reference.id);
        let operation_directory = open_real_directory(&paths.operation).unwrap();
        let quarantine_directory = open_real_directory(&paths.quarantine).unwrap();
        let tombstone_directory =
            ensure_purge_tombstone_directory(&operation_directory, &paths).unwrap();
        write_marker(&paths, &key, &id, "purge-intent").unwrap();
        renameat_noreplace_names(
            &quarantine_directory,
            &source_name,
            &tombstone_directory,
            &tombstone_name,
        )
        .unwrap();
        tombstone_directory.sync_all().unwrap();
        quarantine_directory.sync_all().unwrap();
        let tombstone_path = paths.purge_tombstones.join(&tombstone_name);
        let before = fs::read(&tombstone_path).unwrap();

        let error = gc_purge(&directory, PASSPHRASE, &id).unwrap_err();
        assert!(error.contains("cannot safely resume"), "{error}");
        assert_eq!(fs::read(&tombstone_path).unwrap(), before);
        assert!(!paths.operation.join(GC_PURGE_COMPLETE_FILE).exists());

        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn generation_history_beyond_old_recursive_limit_scans_iteratively() {
        const GENERATIONS: u64 = 1_100;
        let (directory, key, kdf_fingerprint, _) = create_store("long-generation-history");
        let mut index_id = [0u8; 16];
        index_id[0] = 0xe0;
        let index = write_test_object(
            &directory,
            &key,
            ObjectKind::Index,
            index_id,
            &serde_json::to_vec(&test_index("long-history.txt")).unwrap(),
        );
        let lineage_id = [0x33; 16];
        let mut previous = None;
        let mut origin = None;
        for number in 1..=GENERATIONS {
            let generation = Generation {
                format_version: FORMAT_VERSION,
                number,
                lineage_id,
                index,
                previous,
                origin,
            };
            let mut id = [0u8; 16];
            id[0] = 0xe1;
            id[8..].copy_from_slice(&number.to_be_bytes());
            let reference = write_test_object(
                &directory,
                &key,
                ObjectKind::Generation,
                id,
                &serialize_metadata(&generation, "test generation").unwrap(),
            );
            if number == 1 {
                origin = Some(reference);
            }
            previous = Some(reference);
        }
        let (root, _) = prepare_root(&key, previous.unwrap()).unwrap();
        fs::write(directory.join(ROOT_FILE), root).unwrap();

        let scan = scan_v2(&directory, &key, &kdf_fingerprint).unwrap();
        assert!(scan.reachable_objects > GENERATIONS as usize);

        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn gc_plan_streaming_limit_fails_before_exceeding_bound() {
        let mut limiter = GcPlanSizeLimiter {
            written: 0,
            maximum: 3,
        };
        assert_eq!(limiter.write(b"abc").unwrap(), 3);
        let error = limiter.write(b"d").unwrap_err();
        assert_eq!(error.raw_os_error(), Some(libc::EFBIG));
    }

    #[test]
    fn completed_migration_evidence_is_accepted_and_anchored_by_gc() {
        let directory = create_v1_migration_store(
            "completed-migration-gc",
            b"authenticated legacy migration content",
        );
        crate::v2_migrate::migrate_v1_to_v2("migration-passphrase", &directory).unwrap();
        let (kdf, _) = load_kdf_with_fingerprint(&directory).unwrap().unwrap();
        let key = derive_key("migration-passphrase", &kdf);
        let orphan = add_orphan(&directory, &key, b"post-migration orphan");

        let preview = gc_preview(&directory, "migration-passphrase").unwrap();
        assert_eq!(preview.candidate_objects, 1);
        assert_eq!(preview.candidate_names, vec![object_name(&orphan.id)]);
        let id = preview.plan_id.unwrap();
        gc_quarantine(&directory, "migration-passphrase", &id).unwrap();
        gc_restore(&directory, "migration-passphrase", &id).unwrap();
        assert!(object_path(&directory, &orphan).unwrap().exists());
        assert!(directory.join(crate::v2_migrate::PLAN_FILE).exists());
        assert!(directory.join(crate::v2_migrate::COMPLETION_FILE).exists());

        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn completed_migration_gc_scan_obeys_the_shared_low_budget() {
        let directory = create_v1_migration_store(
            "completed-migration-low-budget",
            b"bounded completed migration content",
        );
        crate::v2_migrate::migrate_v1_to_v2("migration-passphrase", &directory).unwrap();
        let (kdf, kdf_fingerprint) = load_kdf_with_fingerprint(&directory).unwrap().unwrap();
        let key = derive_key("migration-passphrase", &kdf);
        let (_, current) = load(&directory, &key).unwrap();
        let mut budget = crate::v2_migrate::GcScanBudget::with_limit(0);
        let error = crate::v2_migrate::gc_completed_evidence_roots(
            &directory,
            &key,
            &kdf_fingerprint,
            &current,
            &mut budget,
        )
        .err()
        .unwrap();
        assert!(
            error.contains("shared fail-closed GC scan limit"),
            "{error}"
        );

        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn quarantine_resumes_after_every_durability_checkpoint() {
        let (trace, key, _, _) = create_store("fault-trace");
        add_orphan(&trace, &key, b"checkpoint-orphan");
        let trace_id = gc_preview(&trace, PASSPHRASE).unwrap().plan_id.unwrap();
        let recorder = FaultInjectionGuard::record();
        gc_quarantine(&trace, PASSPHRASE, &trace_id).unwrap();
        let events = recorder.events();
        drop(recorder);
        assert!(events.contains(&DurabilityEvent::Write));
        assert!(events.contains(&DurabilityEvent::FileSync));
        assert!(events.contains(&DurabilityEvent::Rename));
        assert!(events.contains(&DurabilityEvent::DirectorySync));
        assert!(events.contains(&DurabilityEvent::Cleanup));
        fs::remove_dir_all(trace).unwrap();

        for checkpoint in 1..=events.len() {
            let (directory, key, _, index) = create_store(&format!("fault-{checkpoint}"));
            add_orphan(&directory, &key, b"checkpoint-orphan");
            let root_before = fs::read(directory.join(ROOT_FILE)).unwrap();
            let id = gc_preview(&directory, PASSPHRASE).unwrap().plan_id.unwrap();
            let injector = FaultInjectionGuard::fail_at(checkpoint);
            let result = gc_quarantine(&directory, PASSPHRASE, &id);
            drop(injector);
            assert!(result.is_err(), "checkpoint {checkpoint} was not injected");
            gc_quarantine(&directory, PASSPHRASE, &id).unwrap();
            assert_eq!(load(&directory, &key).unwrap().0, index);
            assert_eq!(fs::read(directory.join(ROOT_FILE)).unwrap(), root_before);
            let paths = operation_paths(&directory, &id).unwrap();
            assert!(read_marker(&paths, &key, &id, "quarantine").unwrap());
            fs::remove_dir_all(directory).unwrap();
        }
    }

    fn quarantined_store(label: &str) -> (PathBuf, [u8; 32], DiskIndex, String) {
        let (directory, key, _, index) = create_store(label);
        add_orphan(&directory, &key, b"operation-checkpoint-orphan");
        let id = gc_preview(&directory, PASSPHRASE).unwrap().plan_id.unwrap();
        gc_quarantine(&directory, PASSPHRASE, &id).unwrap();
        (directory, key, index, id)
    }

    #[test]
    fn restore_and_purge_resume_after_every_durability_checkpoint() {
        let (restore_trace, _, _, restore_trace_id) = quarantined_store("restore-trace");
        let recorder = FaultInjectionGuard::record();
        gc_restore(&restore_trace, PASSPHRASE, &restore_trace_id).unwrap();
        let restore_events = recorder.events();
        drop(recorder);
        fs::remove_dir_all(restore_trace).unwrap();

        for checkpoint in 1..=restore_events.len() {
            let (directory, key, index, id) =
                quarantined_store(&format!("restore-fault-{checkpoint}"));
            let root_before = fs::read(directory.join(ROOT_FILE)).unwrap();
            let injector = FaultInjectionGuard::fail_at(checkpoint);
            let result = gc_restore(&directory, PASSPHRASE, &id);
            drop(injector);
            assert!(
                result.is_err(),
                "restore checkpoint {checkpoint} was not injected"
            );
            gc_restore(&directory, PASSPHRASE, &id).unwrap();
            assert_eq!(load(&directory, &key).unwrap().0, index);
            assert_eq!(fs::read(directory.join(ROOT_FILE)).unwrap(), root_before);
            let paths = operation_paths(&directory, &id).unwrap();
            assert!(read_marker(&paths, &key, &id, "restore").unwrap());
            fs::remove_dir_all(directory).unwrap();
        }

        let (purge_trace, _, _, purge_trace_id) = quarantined_store("purge-trace");
        let purge_trace_paths = operation_paths(&purge_trace, &purge_trace_id).unwrap();
        let candidate = fs::read_dir(&purge_trace_paths.quarantine)
            .unwrap()
            .next()
            .unwrap()
            .unwrap()
            .path();
        let before = fs::read(&candidate).unwrap();
        let error = gc_purge(&purge_trace, PASSPHRASE, &purge_trace_id).unwrap_err();
        assert!(
            error.contains("physical v2 GC reclaim is disabled"),
            "{error}"
        );
        assert_eq!(fs::read(candidate).unwrap(), before);
        assert!(!purge_trace_paths.purge_tombstones.exists());
        assert!(
            !purge_trace_paths
                .operation
                .join(GC_PURGE_INTENT_FILE)
                .exists()
        );
        fs::remove_dir_all(purge_trace).unwrap();
    }
}
