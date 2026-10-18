// SPDX-FileCopyrightText: Copyright 2026 Alexander Orlov <info@lifub.com>

//! Replication primitives for remote mirrors of a v2 store.
//!
//! A remote holds exact copies of immutable `.z2` objects and `_root.age`
//! records; it never sees plaintext or the key. These helpers walk the
//! authenticated object graph of every generation in a lineage, read and
//! install exact ciphertext checked against its `ObjectRef` digest, and
//! bootstrap a new local replica. Publishing a pulled generation reuses the
//! local crash-safe manifest protocol through `fast_forward_pinned`.

use std::collections::HashSet;
use std::path::Path;

use super::*;

/// Upper bound for any immutable object's ciphertext.
pub(crate) const MAX_OBJECT_CIPHERTEXT: u64 = MAX_INDEX_CIPHERTEXT;
/// Upper bound for a root record (`_root.age`) ciphertext.
pub(crate) const MAX_ROOT_RECORD: u64 = MAX_ROOT_CIPHERTEXT;
pub(crate) const KDF_FILE_NAME: &str = "_kdf.json";

impl ObjectRef {
    pub(crate) fn id(&self) -> &[u8; 16] {
        &self.id
    }

    pub(crate) fn digest(&self) -> &[u8; 32] {
        &self.digest
    }

    pub(crate) fn from_parts(id: [u8; 16], digest: [u8; 32]) -> Self {
        Self { id, digest }
    }
}

fn max_ciphertext(kind: ObjectKind) -> u64 {
    kind.max_plaintext_len() + V1_CIPHERTEXT_OVERHEAD
}

/// Blake2s-256 of exact ciphertext, the digest an `ObjectRef` commits to.
pub(crate) fn ciphertext_digest(bytes: &[u8]) -> [u8; 32] {
    digest_bytes(bytes)
}

/// Exact `_root.age` bytes, or `None` for a store without a v2 root.
pub(crate) fn read_root_bytes(base_path: &Path) -> std::io::Result<Option<Vec<u8>>> {
    let path = base_path.join(ROOT_FILE);
    if !backing_entry_exists(&path)? {
        return Ok(None);
    }
    read_bounded_regular(&path, MAX_ROOT_CIPHERTEXT).map(Some)
}

/// Authenticates a root record and returns the generation it names.
pub(crate) fn decode_root(key: &[u8; 32], ciphertext: &[u8]) -> std::io::Result<ObjectRef> {
    if ciphertext.len() as u64 > MAX_ROOT_CIPHERTEXT {
        return Err(io_invalid("v2 root record exceeds its size bound"));
    }
    let plaintext = decrypt_bytes_owned(key, ciphertext.to_vec(), ROOT_AAD).map_err(io_invalid)?;
    let pointer: RootPointer = serde_json::from_slice(&plaintext)
        .map_err(|error| io_invalid(format!("parse authenticated v2 root: {error}")))?;
    if pointer.magic != ROOT_MAGIC || pointer.format_version != FORMAT_VERSION {
        return Err(io_invalid(
            "authenticated v2 root has an unsupported format",
        ));
    }
    Ok(pointer.generation)
}

/// The authenticated lineage position of one generation record.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct GenerationInfo {
    pub(crate) reference: ObjectRef,
    pub(crate) number: u64,
    pub(crate) lineage_id: [u8; 16],
    pub(crate) previous: Option<ObjectRef>,
    pub(crate) origin: ObjectRef,
}

/// Where a chain walk must end.
#[derive(Clone, Copy, Debug)]
pub(crate) enum ChainBase {
    /// Walk to generation 1, the lineage origin.
    Origin,
    /// Walk to this exact generation, which must be an ancestor.
    Ancestor { number: u64, reference: ObjectRef },
}

#[derive(Debug)]
pub(crate) enum ChainOutcome {
    /// Generations strictly after the base, ascending, ending at the head.
    Extends(Vec<GenerationInfo>),
    /// The head's lineage does not contain the requested ancestor.
    Diverged,
}

/// Called with each object reference before the walker reads it (and for data
/// chunks, instead of reading them), plus the object's ciphertext size bound.
/// A push records the object; a pull makes it locally present.
pub(crate) type Visit<'v> = dyn FnMut(ObjectRef, u64) -> std::io::Result<()> + 'v;

/// Authenticated walker over the object closure of v2 generations.
pub(crate) struct ClosureWalker<'a> {
    base_path: &'a Path,
    key: &'a [u8; 32],
    pin: &'a V2NamespacePin,
    complete_files: HashSet<(String, u64)>,
    visited_trees: HashSet<ObjectRef>,
    visited_data: HashSet<ObjectRef>,
}

impl<'a> ClosureWalker<'a> {
    pub(crate) fn new(base_path: &'a Path, key: &'a [u8; 32], pin: &'a V2NamespacePin) -> Self {
        Self {
            base_path,
            key,
            pin,
            complete_files: HashSet::new(),
            visited_trees: HashSet::new(),
            visited_data: HashSet::new(),
        }
    }

    pub(crate) fn generation_info(&self, reference: ObjectRef) -> std::io::Result<GenerationInfo> {
        let generation =
            read_generation_record_with_pin(self.base_path, self.key, reference, Some(self.pin))?;
        Ok(GenerationInfo {
            reference,
            number: generation.number,
            lineage_id: generation.lineage_id,
            previous: generation.previous,
            origin: generation.origin.unwrap_or(reference),
        })
    }

    /// Declares that `generation`'s complete closure already exists on the
    /// side being written to, so files it shares are not walked again.
    pub(crate) fn mark_complete(&mut self, generation: ObjectRef) -> std::io::Result<()> {
        let (_, index) =
            load_generation_with_pin(self.base_path, self.key, generation, Some(self.pin))?;
        for entry in index.inodes.values() {
            if entry.kind == crate::fs::InodeKind::File && !entry.disk_filename.is_empty() {
                self.complete_files
                    .insert((entry.disk_filename.clone(), entry.size));
            }
        }
        Ok(())
    }

    /// Walks the `previous` links from `head` down to `base`, visiting each
    /// generation record first, and authenticates the linear lineage.
    pub(crate) fn chain(
        &mut self,
        head: ObjectRef,
        base: ChainBase,
        visit: &mut Visit<'_>,
    ) -> std::io::Result<ChainOutcome> {
        let mut descending = Vec::new();
        let mut reference = head;
        let mut expected: Option<(u64, [u8; 16], ObjectRef)> = None;
        loop {
            if let ChainBase::Ancestor {
                number,
                reference: ancestor,
            } = base
                && let Some((expected_number, lineage_id, origin)) = expected
                && expected_number == number
            {
                if reference != ancestor {
                    return Ok(ChainOutcome::Diverged);
                }
                // The ancestor is already present on the destination side.
                let info = self.generation_info(ancestor)?;
                if info.number != number || info.lineage_id != lineage_id || info.origin != origin {
                    return Err(io_invalid(
                        "replicated v2 generation lineage has an inconsistent parent",
                    ));
                }
                break;
            }
            visit(reference, max_ciphertext(ObjectKind::Generation))?;
            let info = self.generation_info(reference)?;
            if let Some((number, lineage_id, origin)) = expected
                && (info.number != number || info.lineage_id != lineage_id || info.origin != origin)
            {
                return Err(io_invalid(
                    "replicated v2 generation lineage has an inconsistent parent",
                ));
            }
            if let ChainBase::Ancestor {
                number,
                reference: ancestor,
            } = base
            {
                if info.number < number {
                    return Ok(ChainOutcome::Diverged);
                }
                if info.number == number {
                    if reference != ancestor {
                        return Ok(ChainOutcome::Diverged);
                    }
                    break;
                }
            }
            descending.push(info);
            match info.previous {
                Some(previous) => {
                    expected = Some((info.number - 1, info.lineage_id, info.origin));
                    reference = previous;
                }
                None => {
                    if info.number != 1 || info.origin != reference {
                        return Err(io_invalid(
                            "replicated v2 generation lineage does not terminate at its origin",
                        ));
                    }
                    if let ChainBase::Ancestor { .. } = base {
                        return Ok(ChainOutcome::Diverged);
                    }
                    break;
                }
            }
        }
        descending.reverse();
        Ok(ChainOutcome::Extends(descending))
    }

    /// Visits one generation's index and every object of every file it
    /// references that is not already known complete.
    pub(crate) fn generation(
        &mut self,
        info: &GenerationInfo,
        visit: &mut Visit<'_>,
    ) -> std::io::Result<()> {
        let generation = read_generation_record_with_pin(
            self.base_path,
            self.key,
            info.reference,
            Some(self.pin),
        )?;
        visit(generation.index, max_ciphertext(ObjectKind::Index))?;
        let (_, index) =
            load_generation_with_pin(self.base_path, self.key, info.reference, Some(self.pin))?;
        let mut files: Vec<(&str, u64)> = index
            .inodes
            .values()
            .filter(|entry| entry.kind == crate::fs::InodeKind::File)
            .filter(|entry| !entry.disk_filename.is_empty())
            .map(|entry| (entry.disk_filename.as_str(), entry.size))
            .collect();
        // Deterministic order keeps packs and resumed walks reproducible.
        files.sort_unstable();
        for (encoded, size) in files {
            let marker = (encoded.to_string(), size);
            if self.complete_files.contains(&marker) {
                continue;
            }
            self.file(encoded, size, visit)?;
            self.complete_files.insert(marker);
        }
        Ok(())
    }

    fn file(&mut self, encoded: &str, size: u64, visit: &mut Visit<'_>) -> std::io::Result<()> {
        let reference = decode_file_root(encoded)
            .ok_or_else(|| io_invalid("v2 file has an invalid authenticated root reference"))?;
        visit(reference, max_ciphertext(ObjectKind::FileRoot))?;
        let root =
            load_file_root_with_pin(self.base_path, self.key, encoded, size, Some(self.pin))?;
        if let Some(tree) = root.tree {
            self.tree(tree, root.height, visit)?;
        }
        Ok(())
    }

    fn tree(
        &mut self,
        reference: ObjectRef,
        height: u8,
        visit: &mut Visit<'_>,
    ) -> std::io::Result<()> {
        if self.visited_trees.contains(&reference) {
            return Ok(());
        }
        visit(reference, max_ciphertext(ObjectKind::Tree))?;
        let node =
            read_tree_with_pin(self.base_path, self.key, &reference, height, Some(self.pin))?;
        for slot in node.slots {
            if height == 0 {
                if self.visited_data.insert(slot.child) {
                    visit(slot.child, max_ciphertext(ObjectKind::Data))?;
                }
            } else {
                self.tree(slot.child, height - 1, visit)?;
            }
        }
        self.visited_trees.insert(reference);
        Ok(())
    }
}

/// Whether the object file for `reference` exists in the pinned namespace.
pub(crate) fn object_exists(
    base_path: &Path,
    pin: &V2NamespacePin,
    reference: &ObjectRef,
) -> std::io::Result<bool> {
    pin.verify(base_path)?;
    backing_entry_exists(&pin.objects_path.join(object_name(&reference.id)))
}

/// Ciphertext length of a local object, for planning packs before reading.
pub(crate) fn object_len(
    base_path: &Path,
    pin: &V2NamespacePin,
    reference: &ObjectRef,
) -> std::io::Result<u64> {
    pin.object_file_len(base_path, &object_name(&reference.id))
}

/// Exact ciphertext of a local object, verified against its digest.
pub(crate) fn read_ciphertext(
    base_path: &Path,
    pin: &V2NamespacePin,
    reference: &ObjectRef,
    max_len: u64,
) -> std::io::Result<Vec<u8>> {
    let bytes = pin.read_object_file(base_path, &object_name(&reference.id), max_len)?;
    if digest_bytes(&bytes) != reference.digest {
        return Err(io_invalid(format!(
            "local immutable v2 object {} has the wrong complete ciphertext digest",
            object_name(&reference.id)
        )));
    }
    Ok(bytes)
}

/// Installs replicated ciphertext under its object name without replacing
/// anything. Returns whether a new file was created; an existing object must
/// already hold the identical digest.
pub(crate) fn install_ciphertext(
    base_path: &Path,
    pin: &V2NamespacePin,
    reference: &ObjectRef,
    ciphertext: &[u8],
) -> std::io::Result<bool> {
    if digest_bytes(ciphertext) != reference.digest {
        return Err(io_invalid(format!(
            "replicated object {} does not match its authenticated digest",
            object_name(&reference.id)
        )));
    }
    let name = object_name(&reference.id);
    if pin.write_object_file(base_path, &name, ciphertext, "install replicated v2 object")? {
        return Ok(true);
    }
    read_ciphertext(base_path, pin, reference, MAX_OBJECT_CIPHERTEXT).map_err(|error| {
        io_invalid(format!(
            "local object {name} conflicts with its replicated copy; preserving both: {error}"
        ))
    })?;
    Ok(false)
}

/// Validates every file of `index` that is not byte-identical (root and size)
/// to a file of `previous`, whose closure is already validated.
pub(crate) fn validate_generation_delta(
    base_path: &Path,
    key: &[u8; 32],
    pin: &V2NamespacePin,
    previous: Option<ObjectRef>,
    generation: ObjectRef,
) -> std::io::Result<()> {
    let (_, index) = load_generation_with_pin(base_path, key, generation, Some(pin))?;
    let previous_index = match previous {
        Some(previous) => Some(load_generation_with_pin(base_path, key, previous, Some(pin))?.1),
        None => None,
    };
    let unchanged: HashSet<(&str, u64)> = previous_index
        .iter()
        .flat_map(|index| index.inodes.values())
        .filter(|entry| entry.kind == crate::fs::InodeKind::File)
        .map(|entry| (entry.disk_filename.as_str(), entry.size))
        .collect();
    for (&inode, entry) in index
        .inodes
        .iter()
        .filter(|(_, entry)| entry.kind == crate::fs::InodeKind::File)
    {
        if entry.disk_filename.is_empty()
            || unchanged.contains(&(entry.disk_filename.as_str(), entry.size))
        {
            continue;
        }
        validate_reachable_file_with_pin(base_path, key, &entry.disk_filename, entry.size, pin)
            .map_err(|error| {
                io_invalid(format!(
                    "replicated file inode {inode} is not completely materialized and authenticated: {error}"
                ))
            })?;
    }
    Ok(())
}

/// Creates (or resumes) a bootstrap staging store holding the exact remote
/// KDF metadata and the v2 object namespace.
pub(crate) fn prepare_bootstrap(staging: &Path, kdf_bytes: &[u8]) -> std::io::Result<()> {
    match fs::create_dir(staging) {
        Ok(()) => {
            #[cfg(unix)]
            fs::set_permissions(staging, std::os::unix::fs::PermissionsExt::from_mode(0o700))?;
            if let Some(parent) = staging.parent() {
                File::open(parent)?.sync_all()?;
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(error) => return Err(error),
    }
    let metadata = fs::symlink_metadata(staging)?;
    if !metadata.file_type().is_dir() {
        return Err(io_invalid(format!(
            "{} is not a real bootstrap directory",
            staging.display()
        )));
    }
    let kdf_path = staging.join(KDF_FILE_NAME);
    if backing_entry_exists(&kdf_path)? {
        if read_bounded_regular(&kdf_path, 64 * 1024)? != kdf_bytes {
            return Err(io_invalid(format!(
                "{} belongs to a different store; preserving it",
                staging.display()
            )));
        }
    } else {
        write_new_file(&kdf_path, kdf_bytes, "install replicated KDF metadata")?;
    }
    ensure_layout(staging)
}

/// Publishes the exact remote root record into a fully installed and
/// validated bootstrap staging store, then reloads it as a mount would.
pub(crate) fn finish_bootstrap(
    staging: &Path,
    key: &[u8; 32],
    root_bytes: &[u8],
    pin: &V2NamespacePin,
) -> std::io::Result<CommitState> {
    let root_path = staging.join(ROOT_FILE);
    if backing_entry_exists(&root_path)? {
        if read_bounded_regular(&root_path, MAX_ROOT_CIPHERTEXT)? != root_bytes {
            return Err(io_invalid(
                "bootstrap staging already holds a different v2 root; preserving it",
            ));
        }
    } else {
        write_new_file(&root_path, root_bytes, "publish replicated v2 root")?;
    }
    let (index, state) = load_with_pin(staging, key, pin)?;
    validate_reachable_v2_files_with_pin(staging, key, &index, pin).map_err(io_invalid)?;
    Ok(state)
}

/// Current authenticated head of a local store, after the caller ran
/// recovery.
pub(crate) fn local_head(
    base_path: &Path,
    key: &[u8; 32],
    pin: &V2NamespacePin,
) -> std::io::Result<CommitState> {
    load_with_pin(base_path, key, pin).map(|(_, state)| state)
}
