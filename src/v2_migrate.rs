// Copyright 2026 Alexander Orlov <alexander.orlov@loxal.net>

//! Explicit, resumable v1-to-v2 migration.
//!
//! The authenticated plan pins the complete v1 source generation. Per-inode
//! authenticated receipts are the resume journal. V1 ciphertext is never
//! replaced or deleted; `_root.age` is published last through the normal v2
//! transaction, after every receipt and immutable object is durable.

use std::collections::{HashMap, HashSet};
use std::fs::{self, File};
use std::path::{Path, PathBuf};

use chacha20poly1305::aead::rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};

use crate::crypto::{
    RecoveryFingerprint, V1_CIPHERTEXT_OVERHEAD, ciphertext_bytes_fingerprint,
    ciphertext_fingerprint_expected, decrypt_blob_owned, decrypt_bytes_owned, decrypt_index_owned,
    encrypt_bytes, load_kdf_with_fingerprint, try_derive_key,
};
use crate::fault::{self, DurabilityEvent};
use crate::fs::{
    DiskIndex, InodeKind, backing_entry_exists, read_bounded_backing_file, read_index_ciphertext,
    read_v1_blob_ciphertext, serialize_index_bounded_v2, validate_disk_index,
};
use crate::v2;

pub(crate) const PLAN_FILE: &str = "_v2_migrate.plan.age";
pub(crate) const COMPLETION_FILE: &str = "_v2_migrate.complete.age";
pub(crate) const PROGRESS_DIRECTORY: &str = ".v2_migrate_progress";

const PLAN_VERSION: u32 = 1;
const RECEIPT_VERSION: u32 = 1;
const COMPLETION_VERSION: u32 = 1;
const MAX_PLAN_CIPHERTEXT: u64 = 64 * 1024 * 1024;
const MAX_RECEIPT_CIPHERTEXT: u64 = 64 * 1024;
const MAX_COMPLETION_CIPHERTEXT: u64 = 64 * 1024;
const MAX_MIGRATION_FILES: usize = 100_000;
pub(crate) const MAX_GC_SCAN_ENTRIES: usize = 250_000;
const PLAN_AAD: &[u8] = b"zerotrust-drive\0v2\0migration-plan\0";
const COMPLETION_AAD_PREFIX: &[u8] = b"zerotrust-drive\0v2\0migration-completion\0";

pub(crate) struct GcScanBudget {
    consumed: usize,
    maximum: usize,
}

impl GcScanBudget {
    pub(crate) fn production() -> Self {
        Self {
            consumed: 0,
            maximum: MAX_GC_SCAN_ENTRIES,
        }
    }

    #[cfg(test)]
    pub(crate) fn with_limit(maximum: usize) -> Self {
        Self {
            consumed: 0,
            maximum,
        }
    }

    pub(crate) fn charge(&mut self, context: &str) -> Result<(), String> {
        if self.consumed >= self.maximum {
            return Err(format!(
                "{context} exceeds the shared fail-closed GC scan limit of {} entries",
                self.maximum
            ));
        }
        self.consumed += 1;
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct MigrationPlan {
    plan_version: u32,
    transaction_id: [u8; 16],
    source_index: RecoveryFingerprint,
    kdf_fingerprint: RecoveryFingerprint,
    files: Vec<SourceFile>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SourceFile {
    inode: u64,
    disk_filename: String,
    size: u64,
    source: Option<RecoveryFingerprint>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct FileReceipt {
    receipt_version: u32,
    transaction_id: [u8; 16],
    inode: u64,
    source: Option<RecoveryFingerprint>,
    size: u64,
    file_root: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct MigrationCompletion {
    completion_version: u32,
    transaction_id: [u8; 16],
    plan_fingerprint: RecoveryFingerprint,
    source_index: RecoveryFingerprint,
    kdf_fingerprint: RecoveryFingerprint,
    migration_generation: v2::ObjectRef,
    generation_number: u64,
    lineage_id: [u8; 16],
}

fn invalid(message: impl Into<String>) -> String {
    message.into()
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

fn receipt_name(inode: u64) -> String {
    format!("{inode:016x}.done.age")
}

fn receipt_ready_name(inode: u64) -> String {
    format!(".{inode:016x}.done.ready")
}

fn plan_ready_name(transaction_id: &[u8; 16]) -> String {
    format!("_z2-migration-plan-{}.ready", to_hex(transaction_id))
}

fn completion_ready_name(transaction_id: &[u8; 16]) -> String {
    format!("_z2-migration-completion-{}.ready", to_hex(transaction_id))
}

fn legacy_plan_ready_name(transaction_id: &[u8; 16]) -> String {
    format!("._z2-migration-plan-{}.ready", to_hex(transaction_id))
}

fn legacy_completion_ready_name(transaction_id: &[u8; 16]) -> String {
    format!("._z2-migration-completion-{}.ready", to_hex(transaction_id))
}

fn resumable_ready_path(
    base_path: &Path,
    current_name: String,
    legacy_name: String,
) -> Result<PathBuf, String> {
    let current = base_path.join(current_name);
    let legacy = base_path.join(legacy_name);
    let current_exists = backing_entry_exists(&current)
        .map_err(|error| format!("inspect current v2 staging name: {error}"))?;
    let legacy_exists = backing_entry_exists(&legacy)
        .map_err(|error| format!("inspect legacy v2 staging name: {error}"))?;
    if current_exists && legacy_exists {
        return Err(invalid(
            "both current and legacy v2 staging names exist; preserve both as provider conflict evidence",
        ));
    }
    Ok(if legacy_exists { legacy } else { current })
}

fn completion_aad(transaction_id: &[u8; 16]) -> Vec<u8> {
    let mut aad = Vec::with_capacity(COMPLETION_AAD_PREFIX.len() + transaction_id.len());
    aad.extend_from_slice(COMPLETION_AAD_PREFIX);
    aad.extend_from_slice(transaction_id);
    aad
}

fn receipt_aad(transaction_id: &[u8; 16], inode: u64) -> Vec<u8> {
    let mut aad = b"zerotrust-drive\0v2\0migration-receipt\0".to_vec();
    aad.extend_from_slice(transaction_id);
    aad.extend_from_slice(&inode.to_le_bytes());
    aad
}

fn source_files(base_path: &Path, index: &DiskIndex) -> Result<Vec<SourceFile>, String> {
    let mut files: Vec<_> = index
        .inodes
        .iter()
        .filter(|(_, entry)| entry.kind == InodeKind::File)
        .map(|(&inode, entry)| (inode, entry))
        .collect();
    files.sort_by_key(|(inode, _)| *inode);
    if files.len() > MAX_MIGRATION_FILES {
        return Err(format!(
            "v1-to-v2 migration has {} files; maximum is {MAX_MIGRATION_FILES}",
            files.len()
        ));
    }
    files
        .into_iter()
        .map(|(inode, entry)| {
            let path = base_path.join(&entry.disk_filename);
            let source = match backing_entry_exists(&path)
                .map_err(|error| format!("inspect {}: {error}", path.display()))?
            {
                true => {
                    let expected = entry
                        .size
                        .checked_add(V1_CIPHERTEXT_OVERHEAD)
                        .ok_or_else(|| format!("inode {inode} is too large"))?;
                    Some(
                        ciphertext_fingerprint_expected(&path, expected)
                            .map_err(|error| format!("fingerprint {}: {error}", path.display()))?,
                    )
                }
                false if entry.size == 0 => None,
                false => {
                    return Err(format!(
                        "v1 source blob {} is missing for nonempty inode {inode}",
                        entry.disk_filename
                    ));
                }
            };
            Ok(SourceFile {
                inode,
                disk_filename: entry.disk_filename.clone(),
                size: entry.size,
                source,
            })
        })
        .collect()
}

fn validate_plan(plan: &MigrationPlan, index: &DiskIndex) -> Result<(), String> {
    if plan.plan_version != PLAN_VERSION
        || !plan.source_index.has_full_content_identity()
        || !plan.kdf_fingerprint.is_exact()
        || plan.files.len() > MAX_MIGRATION_FILES
    {
        return Err(invalid("authenticated v2 migration plan is malformed"));
    }
    let mut inodes = HashSet::new();
    let mut names = HashSet::new();
    let mut previous = None;
    for source in &plan.files {
        if previous.is_some_and(|inode| inode >= source.inode)
            || !inodes.insert(source.inode)
            || !names.insert(source.disk_filename.as_str())
            || source
                .source
                .as_ref()
                .is_some_and(|fingerprint| !fingerprint.has_full_content_identity())
        {
            return Err(invalid(
                "authenticated v2 migration plan has duplicate or malformed source entries",
            ));
        }
        let entry = index
            .inodes
            .get(&source.inode)
            .ok_or_else(|| format!("migration plan references missing inode {}", source.inode))?;
        if entry.kind != InodeKind::File
            || entry.disk_filename != source.disk_filename
            || entry.size != source.size
            || (source.source.is_none() && source.size != 0)
        {
            return Err(format!(
                "migration plan source inode {} disagrees with the authenticated v1 index",
                source.inode
            ));
        }
        previous = Some(source.inode);
    }
    let live_files = index
        .inodes
        .values()
        .filter(|entry| entry.kind == InodeKind::File)
        .count();
    if live_files != plan.files.len() {
        return Err(invalid(
            "migration plan does not cover every authenticated v1 file",
        ));
    }
    Ok(())
}

fn load_v1_index(
    base_path: &Path,
    key: &[u8; 32],
) -> Result<(DiskIndex, RecoveryFingerprint), String> {
    let path = base_path.join("_index.age");
    let ciphertext = read_index_ciphertext(&path)
        .map_err(|error| format!("read v1 index {}: {error}", path.display()))?;
    let fingerprint = ciphertext_bytes_fingerprint(&ciphertext)
        .map_err(|error| format!("fingerprint v1 index: {error}"))?;
    let plaintext = decrypt_index_owned(key, ciphertext)
        .map_err(|_| "wrong passphrase or corrupted v1 index".to_string())?;
    let index: DiskIndex = serde_json::from_slice(&plaintext)
        .map_err(|error| format!("parse authenticated v1 index: {error}"))?;
    validate_disk_index(&index)
        .map_err(|error| format!("validate authenticated v1 index: {error}"))?;
    Ok((index, fingerprint))
}

fn encrypt_plan(key: &[u8; 32], plan: &MigrationPlan) -> Result<Vec<u8>, String> {
    let json = serde_json::to_vec(plan)
        .map_err(|error| format!("serialize v2 migration plan: {error}"))?;
    let ciphertext = encrypt_bytes(key, &json, PLAN_AAD)
        .map_err(|error| format!("encrypt v2 migration plan: {error}"))?;
    if ciphertext.len() as u64 > MAX_PLAN_CIPHERTEXT {
        return Err(format!(
            "v2 migration plan is too large ({} bytes; maximum {MAX_PLAN_CIPHERTEXT})",
            ciphertext.len()
        ));
    }
    Ok(ciphertext)
}

fn read_plan(base_path: &Path, key: &[u8; 32]) -> Result<Option<(MigrationPlan, Vec<u8>)>, String> {
    let path = base_path.join(PLAN_FILE);
    let ciphertext = match read_bounded_backing_file(&path, MAX_PLAN_CIPHERTEXT) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(format!("read migration plan {}: {error}", path.display())),
    };
    let plaintext = decrypt_bytes_owned(key, ciphertext.clone(), PLAN_AAD)
        .map_err(|error| format!("authenticate v2 migration plan: {error}"))?;
    let plan = serde_json::from_slice(&plaintext)
        .map_err(|error| format!("parse authenticated v2 migration plan: {error}"))?;
    Ok(Some((plan, ciphertext)))
}

fn decode_completion(
    key: &[u8; 32],
    plan: &MigrationPlan,
    plan_ciphertext: &[u8],
    ciphertext: Vec<u8>,
) -> Result<(MigrationCompletion, Vec<u8>), String> {
    let plaintext = decrypt_bytes_owned(
        key,
        ciphertext.clone(),
        &completion_aad(&plan.transaction_id),
    )
    .map_err(|error| format!("authenticate v2 migration completion: {error}"))?;
    let completion: MigrationCompletion = serde_json::from_slice(&plaintext)
        .map_err(|error| format!("parse authenticated v2 migration completion: {error}"))?;
    let plan_fingerprint = ciphertext_bytes_fingerprint(plan_ciphertext)
        .map_err(|error| format!("fingerprint authenticated migration plan: {error}"))?;
    if completion.completion_version != COMPLETION_VERSION
        || completion.transaction_id != plan.transaction_id
        || completion.plan_fingerprint != plan_fingerprint
        || completion.source_index != plan.source_index
        || completion.kdf_fingerprint != plan.kdf_fingerprint
        || completion.generation_number != 1
        || completion.lineage_id != plan.transaction_id
        || !completion.plan_fingerprint.has_full_content_identity()
    {
        return Err(invalid(
            "authenticated v2 migration completion does not match its retained plan",
        ));
    }
    Ok((completion, ciphertext))
}

fn read_completion(
    base_path: &Path,
    key: &[u8; 32],
    plan: &MigrationPlan,
    plan_ciphertext: &[u8],
) -> Result<Option<(MigrationCompletion, Vec<u8>)>, String> {
    let path = base_path.join(COMPLETION_FILE);
    let ciphertext = match read_bounded_backing_file(&path, MAX_COMPLETION_CIPHERTEXT) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(format!(
                "read migration completion {}: {error}",
                path.display()
            ));
        }
    };
    decode_completion(key, plan, plan_ciphertext, ciphertext).map(Some)
}

fn retain_known_evidence(
    base_path: &Path,
    path: &Path,
    expected: &[u8],
    evidence_stem: &str,
    context: &str,
    namespace_pin: Option<&v2::V2NamespacePin>,
) -> std::io::Result<()> {
    match namespace_pin {
        Some(pin) => {
            v2::retain_known_file_with_pin(base_path, path, expected, evidence_stem, context, pin)
        }
        None => v2::retain_known_file(base_path, path, expected, evidence_stem, context),
    }
}

fn retain_untrusted_evidence(
    base_path: &Path,
    path: &Path,
    expected: &[u8],
    evidence_stem: &str,
    context: &str,
    namespace_pin: Option<&v2::V2NamespacePin>,
) -> std::io::Result<()> {
    match namespace_pin {
        Some(pin) => v2::retain_untrusted_file_with_pin(
            base_path,
            path,
            expected,
            evidence_stem,
            context,
            pin,
        ),
        None => v2::retain_untrusted_file(base_path, path, evidence_stem, context),
    }
}

fn publish_completion(
    base_path: &Path,
    key: &[u8; 32],
    plan: &MigrationPlan,
    plan_ciphertext: &[u8],
    migration_generation: v2::ObjectRef,
    namespace_pin: Option<&v2::V2NamespacePin>,
) -> Result<(), String> {
    let expected_completion = MigrationCompletion {
        completion_version: COMPLETION_VERSION,
        transaction_id: plan.transaction_id,
        plan_fingerprint: ciphertext_bytes_fingerprint(plan_ciphertext)
            .map_err(|error| format!("fingerprint migration plan: {error}"))?,
        source_index: plan.source_index.clone(),
        kdf_fingerprint: plan.kdf_fingerprint.clone(),
        migration_generation,
        generation_number: 1,
        lineage_id: plan.transaction_id,
    };
    let ready = resumable_ready_path(
        base_path,
        completion_ready_name(&plan.transaction_id),
        legacy_completion_ready_name(&plan.transaction_id),
    )?;
    let canonical = base_path.join(COMPLETION_FILE);
    let validate_state = |completion: &MigrationCompletion| {
        if completion.migration_generation != migration_generation
            || completion.generation_number != 1
            || completion.lineage_id != plan.transaction_id
        {
            Err(invalid(
                "authenticated migration completion names a different v2 generation",
            ))
        } else {
            Ok(())
        }
    };

    if let Some((completion, _canonical_ciphertext)) =
        read_completion(base_path, key, plan, plan_ciphertext)?
    {
        validate_state(&completion)?;
        File::open(base_path)
            .and_then(|directory| directory.sync_all())
            .map_err(|error| format!("persist resumed migration completion: {error}"))?;
        fault::checkpoint(
            DurabilityEvent::DirectorySync,
            "persist resumed authenticated v2 migration completion",
        )
        .map_err(|error| error.to_string())?;
        match read_bounded_backing_file(&ready, MAX_COMPLETION_CIPHERTEXT) {
            Ok(ready_ciphertext) => {
                let rejected_ciphertext = ready_ciphertext.clone();
                match decode_completion(key, plan, plan_ciphertext, ready_ciphertext) {
                    Ok((ready_completion, ready_ciphertext)) => {
                        validate_state(&ready_completion)?;
                        retain_known_evidence(
                            base_path,
                            &ready,
                            &ready_ciphertext,
                            &format!(
                                "migration-{}-completion-ready",
                                to_hex(&plan.transaction_id)
                            ),
                            "retain duplicate v2 migration completion ready evidence",
                            namespace_pin,
                        )
                        .map_err(|error| error.to_string())?;
                    }
                    Err(error) => {
                        fault::checkpoint(
                            DurabilityEvent::Recovery,
                            "identify invalid duplicate migration completion staging file",
                        )
                        .map_err(|fault| fault.to_string())?;
                        retain_untrusted_evidence(
                            base_path,
                            &ready,
                            &rejected_ciphertext,
                            &format!(
                                "migration-{}-completion-duplicate-invalid",
                                to_hex(&plan.transaction_id)
                            ),
                            "retain invalid duplicate migration completion evidence",
                            namespace_pin,
                        )
                        .map_err(|retain| {
                            format!(
                                "{error}; also failed to retain invalid duplicate completion: {retain}"
                            )
                        })?;
                    }
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(format!("inspect completion ready evidence: {error}")),
        }
        return Ok(());
    }

    let stage_new = || -> Result<Vec<u8>, String> {
        let json = serde_json::to_vec(&expected_completion)
            .map_err(|error| format!("serialize migration completion: {error}"))?;
        let ciphertext = encrypt_bytes(key, &json, &completion_aad(&plan.transaction_id))
            .map_err(|error| format!("encrypt migration completion: {error}"))?;
        if ciphertext.len() as u64 > MAX_COMPLETION_CIPHERTEXT {
            return Err(invalid("authenticated migration completion is too large"));
        }
        v2::write_new_file(
            &ready,
            &ciphertext,
            "stage authenticated v2 migration completion",
        )
        .map_err(|error| format!("stage migration completion: {error}"))?;
        Ok(ciphertext)
    };
    let ciphertext = match read_bounded_backing_file(&ready, MAX_COMPLETION_CIPHERTEXT) {
        Ok(ciphertext) => {
            let rejected_ciphertext = ciphertext.clone();
            match decode_completion(key, plan, plan_ciphertext, ciphertext) {
                Ok((completion, ciphertext)) => {
                    validate_state(&completion)?;
                    ciphertext
                }
                Err(error) => {
                    fault::checkpoint(
                        DurabilityEvent::Recovery,
                        "identify incomplete migration completion staging file",
                    )
                    .map_err(|fault| fault.to_string())?;
                    retain_untrusted_evidence(
                    base_path,
                    &ready,
                    &rejected_ciphertext,
                    &format!(
                        "migration-{}-completion-partial",
                        to_hex(&plan.transaction_id)
                    ),
                    "retain incomplete migration completion staging evidence",
                    namespace_pin,
                )
                .map_err(|retain| {
                    format!(
                        "{error}; also failed to retain incomplete completion evidence: {retain}"
                    )
                })?;
                    eprintln!(
                        "zerotrust-drive: retained incomplete migration-completion staging evidence; rebuilding it from authenticated plan and origin"
                    );
                    stage_new()?
                }
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => stage_new()?,
        Err(error) => return Err(format!("inspect completion ready evidence: {error}")),
    };
    let retained = match v2::publish_noreplace(&ready, &canonical) {
        Ok(retained) => retained,
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            let (completion, _) = read_completion(base_path, key, plan, plan_ciphertext)?
                .ok_or_else(|| format!("completion publication raced and disappeared: {error}"))?;
            validate_state(&completion)?;
            true
        }
        Err(error) => return Err(format!("publish migration completion: {error}")),
    };
    File::open(base_path)
        .and_then(|directory| directory.sync_all())
        .map_err(|error| format!("persist migration completion: {error}"))?;
    fault::checkpoint(
        DurabilityEvent::DirectorySync,
        "persist authenticated v2 migration completion",
    )
    .map_err(|error| error.to_string())?;
    if retained || backing_entry_exists(&ready).map_err(|error| error.to_string())? {
        retain_known_evidence(
            base_path,
            &ready,
            &ciphertext,
            &format!(
                "migration-{}-completion-ready",
                to_hex(&plan.transaction_id)
            ),
            "retain v2 migration completion ready evidence",
            namespace_pin,
        )
        .map_err(|error| error.to_string())?;
    }
    let (observed, _) = read_completion(base_path, key, plan, plan_ciphertext)?
        .ok_or_else(|| invalid("published migration completion disappeared"))?;
    validate_state(&observed)?;
    Ok(())
}

fn publish_plan(
    base_path: &Path,
    key: &[u8; 32],
    source_index: RecoveryFingerprint,
    kdf_fingerprint: RecoveryFingerprint,
    index: &DiskIndex,
    namespace_pin: Option<&v2::V2NamespacePin>,
) -> Result<(MigrationPlan, Vec<u8>), String> {
    let mut transaction_id = [0u8; 16];
    OsRng.fill_bytes(&mut transaction_id);
    let plan = MigrationPlan {
        plan_version: PLAN_VERSION,
        transaction_id,
        source_index,
        kdf_fingerprint,
        files: source_files(base_path, index)?,
    };
    validate_plan(&plan, index)?;
    let ciphertext = encrypt_plan(key, &plan)?;
    let ready = base_path.join(plan_ready_name(&transaction_id));
    v2::write_new_file(&ready, &ciphertext, "stage authenticated v2 migration plan")
        .map_err(|error| format!("stage v2 migration plan: {error}"))?;
    let retained = v2::publish_noreplace(&ready, &base_path.join(PLAN_FILE))
        .map_err(|error| format!("publish v2 migration plan: {error}"))?;
    File::open(base_path)
        .and_then(|directory| directory.sync_all())
        .map_err(|error| format!("persist v2 migration plan: {error}"))?;
    fault::checkpoint(
        DurabilityEvent::DirectorySync,
        "persist authenticated v2 migration plan",
    )
    .map_err(|error| error.to_string())?;
    if retained {
        retain_known_evidence(
            base_path,
            &ready,
            &ciphertext,
            &format!("migration-{}-plan-ready", to_hex(&transaction_id)),
            "retain v2 migration plan ready evidence",
            namespace_pin,
        )
        .map_err(|error| error.to_string())?;
        File::open(base_path)
            .and_then(|directory| directory.sync_all())
            .map_err(|error| format!("persist migration-plan cleanup: {error}"))?;
        fault::checkpoint(
            DurabilityEvent::DirectorySync,
            "persist v2 migration plan ready cleanup",
        )
        .map_err(|error| error.to_string())?;
    }
    Ok((plan, ciphertext))
}

fn ensure_progress_directory(base_path: &Path) -> Result<PathBuf, String> {
    let path = base_path.join(PROGRESS_DIRECTORY);
    match fs::create_dir(&path) {
        Ok(()) => {
            fault::checkpoint(
                DurabilityEvent::Write,
                "create v2 migration progress directory",
            )
            .map_err(|error| error.to_string())?;
            File::open(base_path)
                .and_then(|directory| directory.sync_all())
                .map_err(|error| format!("persist migration progress directory: {error}"))?;
            fault::checkpoint(
                DurabilityEvent::DirectorySync,
                "persist v2 migration progress directory",
            )
            .map_err(|error| error.to_string())?;
        }
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(error) => return Err(format!("create {}: {error}", path.display())),
    }
    let metadata = fs::symlink_metadata(&path)
        .map_err(|error| format!("inspect {}: {error}", path.display()))?;
    if !metadata.file_type().is_dir() || metadata.file_type().is_symlink() {
        return Err(format!(
            "{} is not a real progress directory",
            path.display()
        ));
    }
    Ok(path)
}

fn progress_name_is_planned(name: &str, plan: &MigrationPlan) -> bool {
    let inode_hex = name.strip_suffix(".done.age").or_else(|| {
        name.strip_prefix('.')
            .and_then(|name| name.strip_suffix(".done.ready"))
    });
    let Some(inode_hex) = inode_hex else {
        return false;
    };
    if inode_hex.len() != 16
        || !inode_hex
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return false;
    }
    let Ok(inode) = u64::from_str_radix(inode_hex, 16) else {
        return false;
    };
    plan.files
        .binary_search_by_key(&inode, |source| source.inode)
        .is_ok()
}

fn validate_progress_inventory(
    progress: &Path,
    plan: &MigrationPlan,
    mut budget: Option<&mut GcScanBudget>,
) -> Result<(), String> {
    for entry in fs::read_dir(progress)
        .map_err(|error| format!("inspect migration progress {}: {error}", progress.display()))?
    {
        let entry = entry.map_err(|error| format!("inspect migration progress entry: {error}"))?;
        if let Some(budget) = budget.as_deref_mut() {
            budget.charge("completed migration receipt inventory")?;
        }
        let Some(name) = entry.file_name().to_str().map(str::to_string) else {
            return Err(invalid(
                "migration progress contains a non-UTF-8 conflict artifact; preserving it",
            ));
        };
        if !progress_name_is_planned(&name, plan) {
            return Err(format!(
                "migration progress contains unexpected artifact {name:?}; preserving every entry"
            ));
        }
    }
    Ok(())
}

fn read_receipt(
    path: &Path,
    key: &[u8; 32],
    plan: &MigrationPlan,
    source: &SourceFile,
) -> Result<Option<(FileReceipt, Vec<u8>)>, String> {
    let ciphertext = match read_bounded_backing_file(path, MAX_RECEIPT_CIPHERTEXT) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(format!(
                "read migration receipt {}: {error}",
                path.display()
            ));
        }
    };
    decode_receipt(path, key, plan, source, ciphertext).map(Some)
}

fn decode_receipt(
    path: &Path,
    key: &[u8; 32],
    plan: &MigrationPlan,
    source: &SourceFile,
    ciphertext: Vec<u8>,
) -> Result<(FileReceipt, Vec<u8>), String> {
    let plaintext = decrypt_bytes_owned(
        key,
        ciphertext.clone(),
        &receipt_aad(&plan.transaction_id, source.inode),
    )
    .map_err(|error| format!("authenticate migration receipt {}: {error}", path.display()))?;
    let receipt: FileReceipt = serde_json::from_slice(&plaintext)
        .map_err(|error| format!("parse migration receipt {}: {error}", path.display()))?;
    if receipt.receipt_version != RECEIPT_VERSION
        || receipt.transaction_id != plan.transaction_id
        || receipt.inode != source.inode
        || receipt.source != source.source
        || receipt.size != source.size
        || (receipt.file_root.is_empty() && receipt.size != 0)
        || (!receipt.file_root.is_empty() && v2::decode_file_root(&receipt.file_root).is_none())
    {
        return Err(format!(
            "authenticated migration receipt {} disagrees with its source plan",
            path.display()
        ));
    }
    Ok((receipt, ciphertext))
}

fn read_resumable_ready_receipt(
    base_path: &Path,
    path: &Path,
    key: &[u8; 32],
    plan: &MigrationPlan,
    source: &SourceFile,
    namespace_pin: Option<&v2::V2NamespacePin>,
) -> Result<Option<(FileReceipt, Vec<u8>)>, String> {
    let ciphertext = match read_bounded_backing_file(path, MAX_RECEIPT_CIPHERTEXT) {
        Ok(ciphertext) => ciphertext,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(format!(
                "read migration receipt staging file {}: {error}",
                path.display()
            ));
        }
    };
    let rejected_ciphertext = ciphertext.clone();
    match decode_receipt(path, key, plan, source, ciphertext) {
        Ok(receipt) => Ok(Some(receipt)),
        Err(error) => {
            fault::checkpoint(
                DurabilityEvent::Recovery,
                "identify incomplete migration receipt staging file",
            )
            .map_err(|fault| fault.to_string())?;
            retain_untrusted_evidence(
                base_path,
                path,
                &rejected_ciphertext,
                &format!(
                    "migration-{}-receipt-{}-partial",
                    to_hex(&plan.transaction_id),
                    source.inode
                ),
                "retain incomplete migration receipt staging evidence",
                namespace_pin,
            )
            .map_err(|retain| {
                format!("{error}; also failed to retain incomplete receipt evidence: {retain}")
            })?;
            eprintln!(
                "zerotrust-drive: retained incomplete receipt staging evidence for inode {}; rebuilding it from the authenticated v1 source",
                source.inode
            );
            Ok(None)
        }
    }
}

fn publish_receipt(
    base_path: &Path,
    progress: &Path,
    key: &[u8; 32],
    plan: &MigrationPlan,
    source: &SourceFile,
    receipt: &FileReceipt,
    namespace_pin: Option<&v2::V2NamespacePin>,
) -> Result<(FileReceipt, Vec<u8>), String> {
    let json = serde_json::to_vec(receipt)
        .map_err(|error| format!("serialize migration receipt: {error}"))?;
    let ciphertext = encrypt_bytes(key, &json, &receipt_aad(&plan.transaction_id, source.inode))
        .map_err(|error| format!("encrypt migration receipt: {error}"))?;
    let ready = progress.join(receipt_ready_name(source.inode));
    let canonical = progress.join(receipt_name(source.inode));
    v2::write_new_file(&ready, &ciphertext, "stage authenticated migration receipt")
        .map_err(|error| format!("stage migration receipt: {error}"))?;
    let retained = v2::publish_noreplace(&ready, &canonical)
        .map_err(|error| format!("publish migration receipt: {error}"))?;
    File::open(progress)
        .and_then(|directory| directory.sync_all())
        .map_err(|error| format!("persist migration receipt: {error}"))?;
    fault::checkpoint(
        DurabilityEvent::DirectorySync,
        "persist authenticated migration receipt",
    )
    .map_err(|error| error.to_string())?;
    if retained {
        retain_known_evidence(
            base_path,
            &ready,
            &ciphertext,
            &format!(
                "migration-{}-receipt-{}-ready",
                to_hex(&plan.transaction_id),
                source.inode
            ),
            "retain migration receipt ready evidence",
            namespace_pin,
        )
        .map_err(|error| error.to_string())?;
        File::open(progress)
            .and_then(|directory| directory.sync_all())
            .map_err(|error| format!("persist receipt-ready cleanup: {error}"))?;
        fault::checkpoint(
            DurabilityEvent::DirectorySync,
            "persist migration receipt ready cleanup",
        )
        .map_err(|error| error.to_string())?;
    }
    Ok((receipt.clone(), ciphertext))
}

fn migrate_source(
    base_path: &Path,
    key: &[u8; 32],
    source: &SourceFile,
    namespace_pin: &v2::V2NamespacePin,
) -> Result<String, String> {
    let Some(expected) = &source.source else {
        return Ok(String::new());
    };
    let path = base_path.join(&source.disk_filename);
    let ciphertext = read_v1_blob_ciphertext(&path, source.size)
        .map_err(|error| format!("read pinned v1 blob {}: {error}", path.display()))?;
    let actual = ciphertext_bytes_fingerprint(&ciphertext)
        .map_err(|error| format!("fingerprint pinned v1 blob: {error}"))?;
    if &actual != expected {
        return Err(format!(
            "v1 source blob {} changed after migration planning; preserving every generation",
            source.disk_filename
        ));
    }
    // V1 has one AEAD tag for the complete blob, so authentication inherently
    // requires the legacy whole-object buffer. Once authenticated, conversion
    // emits bounded v2 chunks. Normal v2 reads/writes never use this path.
    let plaintext = decrypt_blob_owned(key, &source.disk_filename, ciphertext)
        .map_err(|error| format!("decrypt pinned v1 blob {}: {error}", source.disk_filename))?;
    if plaintext.len() as u64 != source.size {
        return Err(format!(
            "authenticated v1 blob {} has the wrong plaintext size",
            source.disk_filename
        ));
    }
    v2::import_authenticated_file_with_pin(base_path, key, &plaintext, namespace_pin)
        .map_err(|error| format!("write final v2 tree for inode {}: {error}", source.inode))
}

fn revalidate_sources(base_path: &Path, plan: &MigrationPlan) -> Result<(), String> {
    for source in &plan.files {
        let path = base_path.join(&source.disk_filename);
        let actual = match &source.source {
            Some(_expected) => Some(
                ciphertext_fingerprint_expected(
                    &path,
                    source
                        .size
                        .checked_add(V1_CIPHERTEXT_OVERHEAD)
                        .ok_or_else(|| format!("inode {} is too large", source.inode))?,
                )
                .map_err(|error| format!("revalidate {}: {error}", path.display()))?,
            ),
            None if !backing_entry_exists(&path)
                .map_err(|error| format!("revalidate {}: {error}", path.display()))? =>
            {
                None
            }
            None => {
                return Err(format!(
                    "previously absent empty v1 source {} appeared during migration",
                    source.disk_filename
                ));
            }
        };
        if actual != source.source {
            return Err(format!(
                "v1 source {} changed during migration; preserving plan and objects",
                source.disk_filename
            ));
        }
    }
    Ok(())
}

fn revalidate_plan_inputs(base_path: &Path, plan: &MigrationPlan) -> Result<(), String> {
    let expected_index_len = plan
        .source_index
        .ciphertext_len()
        .ok_or_else(|| invalid("migration plan has a non-ciphertext v1 index fingerprint"))?;
    let current_index =
        ciphertext_fingerprint_expected(&base_path.join("_index.age"), expected_index_len)
            .map_err(|error| format!("revalidate canonical v1 index: {error}"))?;
    if current_index != plan.source_index {
        return Err(invalid(
            "canonical v1 index changed during migration; preserving both format generations",
        ));
    }
    let (_, current_kdf) = load_kdf_with_fingerprint(base_path)?
        .ok_or_else(|| invalid("KDF metadata disappeared during v2 migration"))?;
    if current_kdf != plan.kdf_fingerprint {
        return Err(invalid(
            "KDF metadata changed during v2 migration; preserving all migration evidence",
        ));
    }
    revalidate_sources(base_path, plan)
}

pub(crate) fn validate_completed_migration_evidence(
    base_path: &Path,
    key: &[u8; 32],
    kdf_fingerprint: &RecoveryFingerprint,
    current: &v2::CommitState,
) -> Result<bool, String> {
    validate_completed_migration_evidence_internal(base_path, key, kdf_fingerprint, current, None)
}

pub(crate) fn validate_completed_migration_evidence_with_pin(
    base_path: &Path,
    key: &[u8; 32],
    kdf_fingerprint: &RecoveryFingerprint,
    current: &v2::CommitState,
    namespace_pin: &v2::V2NamespacePin,
) -> Result<bool, String> {
    validate_completed_migration_evidence_internal(
        base_path,
        key,
        kdf_fingerprint,
        current,
        Some(namespace_pin),
    )
}

fn validate_completed_migration_evidence_internal(
    base_path: &Path,
    key: &[u8; 32],
    kdf_fingerprint: &RecoveryFingerprint,
    current: &v2::CommitState,
    namespace_pin: Option<&v2::V2NamespacePin>,
) -> Result<bool, String> {
    let plan_exists = backing_entry_exists(&base_path.join(PLAN_FILE))
        .map_err(|error| format!("inspect retained migration plan: {error}"))?;
    let completion_exists = backing_entry_exists(&base_path.join(COMPLETION_FILE))
        .map_err(|error| format!("inspect migration completion: {error}"))?;
    if !plan_exists && !completion_exists {
        return Ok(false);
    }
    if !plan_exists || !completion_exists {
        return Err(invalid(
            "v1/v2 coexistence is not authorized by both an authenticated migration plan and completion; re-run --migrate-v2",
        ));
    }
    let (index, source_index) = load_v1_index(base_path, key)?;
    let (plan, plan_ciphertext) = read_plan(base_path, key)?
        .ok_or_else(|| invalid("retained migration plan disappeared during validation"))?;
    validate_plan(&plan, &index)?;
    if plan.source_index != source_index || plan.kdf_fingerprint != *kdf_fingerprint {
        return Err(invalid(
            "retained v1 head or KDF differs from the authenticated completed-migration plan",
        ));
    }
    let (completion, _) = read_completion(base_path, key, &plan, &plan_ciphertext)?
        .ok_or_else(|| invalid("authenticated migration completion disappeared"))?;
    match namespace_pin {
        Some(pin) => v2::validate_lineage_origin_with_pin(
            base_path,
            key,
            current,
            completion.migration_generation,
            completion.lineage_id,
            pin,
        ),
        None => v2::validate_lineage_origin(
            base_path,
            key,
            current,
            completion.migration_generation,
            completion.lineage_id,
        ),
    }
    .map_err(|error| format!("validate completed migration lineage: {error}"))?;
    Ok(true)
}

/// Authenticated v2 roots retained by a completed v1-to-v2 migration.
///
/// Offline GC calls this before considering any object unreachable. It keeps
/// the migration generation and every receipt file root strong, and returns
/// the exact canonical evidence files which must remain unchanged throughout
/// a quarantine plan.
pub(crate) struct GcMigrationEvidence {
    pub(crate) generations: Vec<v2::ObjectRef>,
    pub(crate) file_roots: Vec<(v2::ObjectRef, u64)>,
    pub(crate) anchor_paths: Vec<PathBuf>,
}

pub(crate) fn gc_completed_evidence_roots(
    base_path: &Path,
    key: &[u8; 32],
    kdf_fingerprint: &RecoveryFingerprint,
    current: &v2::CommitState,
    budget: &mut GcScanBudget,
) -> Result<GcMigrationEvidence, String> {
    let plan_path = base_path.join(PLAN_FILE);
    let completion_path = base_path.join(COMPLETION_FILE);
    let plan_exists = backing_entry_exists(&plan_path)
        .map_err(|error| format!("inspect retained migration plan: {error}"))?;
    let completion_exists = backing_entry_exists(&completion_path)
        .map_err(|error| format!("inspect migration completion: {error}"))?;
    if !plan_exists && !completion_exists {
        if backing_entry_exists(&base_path.join(PROGRESS_DIRECTORY))
            .map_err(|error| format!("inspect orphan migration progress: {error}"))?
        {
            return Err(invalid(
                "migration progress exists without an authenticated plan; preserving every v2 object",
            ));
        }
        return Ok(GcMigrationEvidence {
            generations: Vec::new(),
            file_roots: Vec::new(),
            anchor_paths: Vec::new(),
        });
    }
    if !validate_completed_migration_evidence(base_path, key, kdf_fingerprint, current)? {
        return Err(invalid(
            "migration evidence disappeared during offline GC validation",
        ));
    }

    let (index, _) = load_v1_index(base_path, key)?;
    let (plan, plan_ciphertext) = read_plan(base_path, key)?
        .ok_or_else(|| invalid("retained migration plan disappeared during GC validation"))?;
    validate_plan(&plan, &index)?;
    let (completion, completion_ciphertext) =
        read_completion(base_path, key, &plan, &plan_ciphertext)?
            .ok_or_else(|| invalid("migration completion disappeared during GC validation"))?;

    let progress = base_path.join(PROGRESS_DIRECTORY);
    let metadata = fs::symlink_metadata(&progress)
        .map_err(|error| format!("inspect completed migration receipts: {error}"))?;
    if !metadata.file_type().is_dir() || metadata.file_type().is_symlink() {
        return Err(invalid(
            "completed migration receipt path is not a real directory",
        ));
    }
    validate_progress_inventory(&progress, &plan, Some(budget))?;

    let mut file_roots = Vec::new();
    let mut anchor_paths = Vec::new();
    budget.charge("completed migration canonical plan anchor")?;
    anchor_paths.push(plan_path);
    budget.charge("completed migration canonical completion anchor")?;
    anchor_paths.push(completion_path);
    let mut retained_expectations = HashMap::new();
    retained_expectations.insert(
        format!("migration-{}-plan-ready", to_hex(&plan.transaction_id)),
        ciphertext_bytes_fingerprint(&plan_ciphertext)
            .map_err(|error| format!("fingerprint migration plan for GC: {error}"))?,
    );
    retained_expectations.insert(
        format!(
            "migration-{}-completion-ready",
            to_hex(&plan.transaction_id)
        ),
        ciphertext_bytes_fingerprint(&completion_ciphertext)
            .map_err(|error| format!("fingerprint migration completion for GC: {error}"))?,
    );
    for source in &plan.files {
        budget.charge("completed migration canonical receipt")?;
        let canonical = progress.join(receipt_name(source.inode));
        let (receipt, canonical_ciphertext) = read_receipt(&canonical, key, &plan, source)?
            .ok_or_else(|| {
                format!(
                    "completed migration receipt {} is missing; preserving every v2 object",
                    canonical.display()
                )
            })?;
        anchor_paths.push(canonical.clone());
        retained_expectations.insert(
            format!(
                "migration-{}-receipt-{}-ready",
                to_hex(&plan.transaction_id),
                source.inode
            ),
            ciphertext_bytes_fingerprint(&canonical_ciphertext).map_err(|error| {
                format!(
                    "fingerprint migration receipt {} for GC: {error}",
                    source.inode
                )
            })?,
        );
        budget.charge("completed migration ready-receipt probe")?;
        let ready = progress.join(receipt_ready_name(source.inode));
        if let Some((ready_receipt, ready_ciphertext)) = read_receipt(&ready, key, &plan, source)? {
            if ready_receipt != receipt || ready_ciphertext != canonical_ciphertext {
                return Err(format!(
                    "completed migration receipt {} has a different ready copy; preserving every v2 object",
                    canonical.display()
                ));
            }
            anchor_paths.push(ready);
        }
        if !receipt.file_root.is_empty() {
            let reference = v2::decode_file_root(&receipt.file_root).ok_or_else(|| {
                format!(
                    "completed migration receipt {} has an invalid file root",
                    canonical.display()
                )
            })?;
            file_roots.push((reference, receipt.size));
        }
    }

    let evidence = v2::selected_object_directory(base_path)
        .map_err(|error| format!("select v2 object directory for GC: {error}"))?
        .join("evidence");
    for entry in fs::read_dir(&evidence)
        .map_err(|error| format!("inspect retained migration evidence: {error}"))?
    {
        let entry = entry.map_err(|error| format!("inspect migration evidence entry: {error}"))?;
        budget.charge("retained migration evidence inventory")?;
        let Some(name) = entry.file_name().to_str().map(str::to_string) else {
            return Err(invalid(
                "migration evidence contains a non-UTF-8 artifact; preserving every object",
            ));
        };
        if !name.starts_with("migration-") {
            continue;
        }
        let stem = name.strip_suffix(".retained").or_else(|| {
            let (stem, number) = name.rsplit_once(".retained-")?;
            (!number.is_empty() && number.bytes().all(|byte| byte.is_ascii_digit())).then_some(stem)
        });
        let Some(expected) = stem.and_then(|stem| retained_expectations.get(stem)) else {
            return Err(format!(
                "unsupported or untrusted migration evidence {name:?}; preserving every object"
            ));
        };
        let actual = read_bounded_backing_file(&entry.path(), MAX_PLAN_CIPHERTEXT)
            .map_err(|error| format!("read retained migration evidence {name:?}: {error}"))?;
        let actual = ciphertext_bytes_fingerprint(&actual).map_err(|error| {
            format!("fingerprint retained migration evidence {name:?}: {error}")
        })?;
        if &actual != expected {
            return Err(format!(
                "retained migration evidence {name:?} differs from its authenticated canonical anchor"
            ));
        }
        anchor_paths.push(entry.path());
    }
    anchor_paths.sort();
    Ok(GcMigrationEvidence {
        generations: vec![completion.migration_generation],
        file_roots,
        anchor_paths,
    })
}

fn ensure_no_provider_head_siblings_with_pin(
    base_path: &Path,
    namespace_pin: &v2::V2NamespacePin,
    context: &'static str,
) -> Result<(), String> {
    namespace_pin
        .verify_at(base_path, context)
        .map_err(|error| format!("immutable v2 namespace changed before conflict scan: {error}"))?;
    crate::fs::ensure_no_index_siblings(base_path).map_err(|error| error.to_string())?;
    namespace_pin
        .verify(base_path)
        .map_err(|error| format!("immutable v2 namespace changed across conflict scan: {error}"))
}

pub(crate) fn migrate_v1_to_v2(passphrase: &str, base_path: &Path) -> Result<(), String> {
    // A completed migration can otherwise take its fast verification path
    // without invoking normal write recovery. Reject provider-created index or
    // root siblings before examining any resumable state so no competing head
    // is silently ignored at any migration phase.
    crate::fs::ensure_no_index_siblings(base_path).map_err(|error| error.to_string())?;
    let (kdf, kdf_fingerprint) = load_kdf_with_fingerprint(base_path)?
        .ok_or_else(|| "v1-to-v2 migration requires existing Argon2id KDF metadata".to_string())?;
    let key = try_derive_key(passphrase, &kdf)?;
    let (index, source_index) = load_v1_index(base_path, &key)?;
    if backing_entry_exists(&base_path.join(PROGRESS_DIRECTORY))
        .map_err(|error| format!("inspect migration progress before namespace pinning: {error}"))?
    {
        let (preflight_plan, _) = read_plan(base_path, &key)?
            .ok_or_else(|| "migration progress exists without an authenticated plan".to_string())?;
        validate_plan(&preflight_plan, &index)?;
        if preflight_plan.source_index != source_index
            || preflight_plan.kdf_fingerprint != kdf_fingerprint
        {
            return Err(invalid(
                "v1 index/KDF changed since the authenticated migration plan was published",
            ));
        }
        validate_progress_inventory(&base_path.join(PROGRESS_DIRECTORY), &preflight_plan, None)?;
    }
    let existing_v2_state = [
        v2::ROOT_FILE,
        v2::WRITE_MANIFEST,
        PLAN_FILE,
        COMPLETION_FILE,
        PROGRESS_DIRECTORY,
    ]
    .iter()
    .try_fold(false, |found, name| {
        backing_entry_exists(&base_path.join(name)).map(|exists| found || exists)
    })
    .map_err(|error| format!("inspect existing v2 migration state: {error}"))?;
    let namespace_pin = if existing_v2_state {
        let pin = v2::V2NamespacePin::capture(base_path).map_err(|error| {
            format!(
                "existing v2 migration state has an incomplete or replaced immutable namespace: {error}"
            )
        })?;
        v2::probe_atomic_exchange_with_pin(base_path, &pin).map_err(|error| {
            format!(
                "backing store cannot provide the atomic exchange required by writable v2: {error}"
            )
        })?;
        pin
    } else {
        v2::probe_atomic_exchange(base_path).map_err(|error| {
            format!(
                "backing store cannot provide the atomic exchange required by writable v2: {error}"
            )
        })?;
        v2::V2NamespacePin::capture(base_path)
            .map_err(|error| format!("pin new immutable v2 migration namespace: {error}"))?
    };
    v2::recover_with_namespace_pin(base_path, &key, &kdf_fingerprint, &namespace_pin)
        .map_err(|error| format!("recover interrupted v2 root commit: {error}"))?;
    let (plan, plan_ciphertext) = match read_plan(base_path, &key)? {
        Some((plan, ciphertext)) => {
            validate_plan(&plan, &index)?;
            if plan.source_index != source_index || plan.kdf_fingerprint != kdf_fingerprint {
                return Err(invalid(
                    "v1 index/KDF changed since the authenticated migration plan was published",
                ));
            }
            let ready = resumable_ready_path(
                base_path,
                plan_ready_name(&plan.transaction_id),
                legacy_plan_ready_name(&plan.transaction_id),
            )?;
            match read_bounded_backing_file(&ready, MAX_PLAN_CIPHERTEXT) {
                Ok(ready_ciphertext) if ready_ciphertext == ciphertext => {
                    retain_known_evidence(
                        base_path,
                        &ready,
                        &ciphertext,
                        &format!("migration-{}-plan-ready", to_hex(&plan.transaction_id)),
                        "retain verified duplicate v2 migration plan ready evidence",
                        Some(&namespace_pin),
                    )
                    .map_err(|error| error.to_string())?;
                    File::open(base_path)
                        .and_then(|directory| directory.sync_all())
                        .map_err(|error| {
                            format!("persist duplicate migration-plan cleanup: {error}")
                        })?;
                    fault::checkpoint(
                        DurabilityEvent::DirectorySync,
                        "persist duplicate v2 migration plan cleanup",
                    )
                    .map_err(|error| error.to_string())?;
                }
                Ok(_) => {
                    return Err(invalid(
                        "authenticated migration plan has a different ready copy; preserving both as conflict evidence",
                    ));
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => {
                    return Err(format!(
                        "inspect migration-plan ready evidence {}: {error}",
                        ready.display()
                    ));
                }
            }
            (plan, ciphertext)
        }
        None => publish_plan(
            base_path,
            &key,
            source_index.clone(),
            kdf_fingerprint.clone(),
            &index,
            Some(&namespace_pin),
        )?,
    };
    if backing_entry_exists(&base_path.join(COMPLETION_FILE))
        .map_err(|error| format!("inspect migration completion: {error}"))?
    {
        let (_, current) = v2::load_with_pin(base_path, &key, &namespace_pin)
            .map_err(|error| format!("load completed v2 migration root: {error}"))?;
        validate_completed_migration_evidence_with_pin(
            base_path,
            &key,
            &kdf_fingerprint,
            &current,
            &namespace_pin,
        )?;
        ensure_no_provider_head_siblings_with_pin(
            base_path,
            &namespace_pin,
            "before completed migration final sibling scan",
        )?;
        return Ok(());
    }
    let progress = ensure_progress_directory(base_path)?;
    validate_progress_inventory(&progress, &plan, None)?;

    let mut target_index = index.clone();
    for source in &plan.files {
        let canonical = progress.join(receipt_name(source.inode));
        let receipt = match read_receipt(&canonical, &key, &plan, source)? {
            Some(receipt) => {
                let ready = progress.join(receipt_ready_name(source.inode));
                if let Some((_ready_receipt, ready_ciphertext)) = read_resumable_ready_receipt(
                    base_path,
                    &ready,
                    &key,
                    &plan,
                    source,
                    Some(&namespace_pin),
                )? {
                    if ready_ciphertext != receipt.1 {
                        return Err(format!(
                            "migration receipt {} has a different valid ready copy; preserving both as conflict evidence",
                            canonical.display()
                        ));
                    }
                    retain_known_evidence(
                        base_path,
                        &ready,
                        &receipt.1,
                        &format!(
                            "migration-{}-receipt-{}-ready",
                            to_hex(&plan.transaction_id),
                            source.inode
                        ),
                        "retain verified duplicate migration receipt ready evidence",
                        Some(&namespace_pin),
                    )
                    .map_err(|error| error.to_string())?;
                    File::open(&progress)
                        .and_then(|directory| directory.sync_all())
                        .map_err(|error| {
                            format!("persist duplicate receipt-ready cleanup: {error}")
                        })?;
                    fault::checkpoint(
                        DurabilityEvent::DirectorySync,
                        "persist duplicate migration receipt cleanup",
                    )
                    .map_err(|error| error.to_string())?;
                }
                receipt
            }
            None => {
                let ready = progress.join(receipt_ready_name(source.inode));
                if let Some((receipt, ciphertext)) = read_resumable_ready_receipt(
                    base_path,
                    &ready,
                    &key,
                    &plan,
                    source,
                    Some(&namespace_pin),
                )? {
                    let retained = v2::publish_noreplace(&ready, &canonical)
                        .map_err(|error| format!("resume receipt publication: {error}"))?;
                    File::open(&progress)
                        .and_then(|directory| directory.sync_all())
                        .map_err(|error| format!("persist resumed receipt: {error}"))?;
                    fault::checkpoint(
                        DurabilityEvent::DirectorySync,
                        "persist resumed migration receipt",
                    )
                    .map_err(|error| error.to_string())?;
                    if retained {
                        retain_known_evidence(
                            base_path,
                            &ready,
                            &ciphertext,
                            &format!(
                                "migration-{}-receipt-{}-ready",
                                to_hex(&plan.transaction_id),
                                source.inode
                            ),
                            "retain resumed migration receipt ready evidence",
                            Some(&namespace_pin),
                        )
                        .map_err(|error| error.to_string())?;
                        File::open(&progress)
                            .and_then(|directory| directory.sync_all())
                            .map_err(|error| format!("persist resumed receipt cleanup: {error}"))?;
                        fault::checkpoint(
                            DurabilityEvent::DirectorySync,
                            "persist resumed migration receipt cleanup",
                        )
                        .map_err(|error| error.to_string())?;
                    }
                    (receipt, ciphertext)
                } else {
                    let file_root = migrate_source(base_path, &key, source, &namespace_pin)?;
                    let receipt = FileReceipt {
                        receipt_version: RECEIPT_VERSION,
                        transaction_id: plan.transaction_id,
                        inode: source.inode,
                        source: source.source.clone(),
                        size: source.size,
                        file_root,
                    };
                    publish_receipt(
                        base_path,
                        &progress,
                        &key,
                        &plan,
                        source,
                        &receipt,
                        Some(&namespace_pin),
                    )?
                }
            }
        };
        let receipt = receipt.0;
        v2::validate_reachable_file_with_pin(
            base_path,
            &key,
            &receipt.file_root,
            receipt.size,
            &namespace_pin,
        )
        .map_err(|error| {
            format!(
                "verify immutable v2 objects for migrated inode {}: {error}",
                source.inode
            )
        })?;
        target_index
            .inodes
            .get_mut(&source.inode)
            .ok_or_else(|| format!("source inode {} disappeared", source.inode))?
            .disk_filename = receipt.file_root.clone();
    }
    let index_json = serialize_index_bounded_v2(&target_index)
        .map_err(|error| format!("serialize v2 migration index: {error}"))?;
    revalidate_plan_inputs(base_path, &plan)?;
    namespace_pin
        .verify(base_path)
        .map_err(|error| format!("immutable v2 namespace changed during migration: {error}"))?;

    let root_exists =
        backing_entry_exists(&base_path.join(v2::ROOT_FILE)).map_err(|error| error.to_string())?;
    if !root_exists {
        v2::commit_initial_lineage_pinned(
            base_path,
            &key,
            &index_json,
            &kdf_fingerprint,
            plan.transaction_id,
            &namespace_pin,
        )
        .map_err(|error| format!("publish migrated v2 generation: {error}"))?;
    }
    namespace_pin.verify(base_path).map_err(|error| {
        format!("immutable v2 namespace changed across migration root publication: {error}")
    })?;
    let (_visible, state) = v2::load_with_pin(base_path, &key, &namespace_pin)
        .map_err(|error| format!("verify committed v2 generation: {error}"))?;
    let origin = v2::validate_migration_target_with_pin(
        base_path,
        &key,
        &state,
        plan.transaction_id,
        &target_index,
        &namespace_pin,
    )
    .map_err(|error| format!("validate v2 migration origin: {error}"))?;
    revalidate_plan_inputs(base_path, &plan)?;
    namespace_pin.verify(base_path).map_err(|error| {
        format!("immutable v2 namespace changed before migration completion: {error}")
    })?;
    ensure_no_provider_head_siblings_with_pin(
        base_path,
        &namespace_pin,
        "before migration completion sibling scan",
    )?;
    publish_completion(
        base_path,
        &key,
        &plan,
        &plan_ciphertext,
        origin,
        Some(&namespace_pin),
    )?;
    namespace_pin.verify(base_path).map_err(|error| {
        format!("immutable v2 namespace changed across migration completion: {error}")
    })?;
    ensure_no_provider_head_siblings_with_pin(
        base_path,
        &namespace_pin,
        "after migration completion publication before sibling scan",
    )?;
    validate_completed_migration_evidence_with_pin(
        base_path,
        &key,
        &kdf_fingerprint,
        &state,
        &namespace_pin,
    )?;
    ensure_no_provider_head_siblings_with_pin(
        base_path,
        &namespace_pin,
        "before migration final sibling scan",
    )?;
    // Retain the authenticated plan, receipts, and v1 source blobs as explicit
    // recovery evidence. Garbage collection is deliberately a separate future
    // operation: a cloud provider acknowledging the new root locally does not
    // prove that every replica has received the immutable objects yet.
    Ok(())
}

pub(crate) fn migration_pending(base_path: &Path) -> Result<bool, String> {
    let plan = migration_plan_exists(base_path)?;
    let completion = backing_entry_exists(&base_path.join(COMPLETION_FILE))
        .map_err(|error| format!("inspect v2 migration completion: {error}"))?;
    Ok(plan && !completion)
}

pub(crate) fn migration_plan_exists(base_path: &Path) -> Result<bool, String> {
    backing_entry_exists(&base_path.join(PLAN_FILE))
        .map_err(|error| format!("inspect v2 migration plan: {error}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{
        FORMAT_VERSION as KDF_FORMAT_VERSION, KdfParams, SALT_LEN, derive_key, encrypt_blob,
        encrypt_index, save_kdf,
    };
    use crate::fault::FaultInjectionGuard;
    use crate::fs::{DirChild, InodeEntry, durable_write};
    use std::collections::HashMap;
    use std::sync::atomic::{AtomicU64, Ordering};

    static TEST_ID: AtomicU64 = AtomicU64::new(0);

    fn directory(label: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "zerotrust-drive-v2-migrate-{label}-{}-{}",
            std::process::id(),
            TEST_ID.fetch_add(1, Ordering::Relaxed)
        ))
    }

    fn fixture(path: &Path, content: &[u8]) {
        fs::create_dir_all(path).unwrap();
        let kdf = KdfParams {
            format_version: KDF_FORMAT_VERSION,
            algorithm: "argon2id".to_string(),
            salt: vec![11; SALT_LEN],
            m_cost: 8,
            t_cost: 1,
            p_cost: 1,
        };
        save_kdf(path, &kdf).unwrap();
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
            &path.join("000001.age"),
            &encrypt_blob(&key, "000001.age", content).unwrap(),
        )
        .unwrap();
        durable_write(
            &path.join("_index.age"),
            &encrypt_index(&key, &serde_json::to_vec(&index).unwrap()).unwrap(),
        )
        .unwrap();
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

    fn read_migrated(path: &Path) -> Vec<u8> {
        let (kdf, _) = load_kdf_with_fingerprint(path).unwrap().unwrap();
        let key = derive_key("migration-passphrase", &kdf);
        let (index, _) = v2::load(path, &key).unwrap();
        let entry = &index.inodes[&2];
        v2::read_file_range(
            path,
            &key,
            &entry.disk_filename,
            entry.size,
            0,
            entry.size as usize,
        )
        .unwrap()
    }

    #[test]
    fn migration_is_explicit_resumable_and_retains_v1_evidence() {
        let path = directory("basic");
        let content = b"authenticated legacy content";
        fixture(&path, content);
        let old_index = fs::read(path.join("_index.age")).unwrap();
        let old_blob = fs::read(path.join("000001.age")).unwrap();

        migrate_v1_to_v2("migration-passphrase", &path).unwrap();

        assert_eq!(read_migrated(&path), content);
        let committed_root = fs::read(path.join(v2::ROOT_FILE)).unwrap();
        migrate_v1_to_v2("migration-passphrase", &path).unwrap();
        assert_eq!(
            fs::read(path.join(v2::ROOT_FILE)).unwrap(),
            committed_root,
            "resuming an already-complete migration must verify, not rewrite, its root"
        );

        let (kdf, kdf_fingerprint) = load_kdf_with_fingerprint(&path).unwrap().unwrap();
        let key = derive_key("migration-passphrase", &kdf);
        let (mut descendant_index, initial_state) = v2::load(&path, &key).unwrap();
        descendant_index.inodes.get_mut(&2).unwrap().mtime_secs += 1;
        let descendant_json = serialize_index_bounded_v2(&descendant_index).unwrap();
        v2::commit(
            &path,
            &key,
            &descendant_json,
            Some(&initial_state),
            &kdf_fingerprint,
        )
        .unwrap();
        let descendant_root = fs::read(path.join(v2::ROOT_FILE)).unwrap();
        migrate_v1_to_v2("migration-passphrase", &path).unwrap();
        assert_eq!(
            fs::read(path.join(v2::ROOT_FILE)).unwrap(),
            descendant_root,
            "a completed migration must accept later authenticated descendants"
        );

        fs::remove_file(path.join(COMPLETION_FILE)).unwrap();
        migrate_v1_to_v2("migration-passphrase", &path).unwrap();
        assert_eq!(
            fs::read(path.join(v2::ROOT_FILE)).unwrap(),
            descendant_root,
            "rebuilding a lost completion anchor must not replace a later descendant root"
        );
        assert!(path.join(COMPLETION_FILE).exists());
        assert_eq!(fs::read(path.join("_index.age")).unwrap(), old_index);
        assert_eq!(fs::read(path.join("000001.age")).unwrap(), old_blob);
        assert!(path.join(PLAN_FILE).exists());
        assert!(path.join(PROGRESS_DIRECTORY).exists());
        assert!(!migration_pending(&path).unwrap());
        fs::remove_dir_all(path).unwrap();
    }

    #[test]
    fn migration_keeps_one_namespace_pin_through_initial_root_publication() {
        let path = directory("namespace-pin");
        let content = b"migration bytes stay in the pinned namespace";
        fixture(&path, content);
        let action_path = path.clone();
        let hook = v2::arm_namespace_test_hook("before v2 root publication", move || {
            let canonical = action_path.join(v2::OBJECT_DIRECTORY);
            fs::rename(
                &canonical,
                action_path.join("provider-displaced-namespace-evidence"),
            )
            .unwrap();
            fs::create_dir(&canonical).unwrap();
            fs::create_dir(canonical.join(v2::OBJECTS_DIRECTORY)).unwrap();
            fs::create_dir(canonical.join(v2::EVIDENCE_DIRECTORY)).unwrap();
        });
        let error = migrate_v1_to_v2("migration-passphrase", &path).unwrap_err();
        drop(hook);
        assert!(error.contains("immutable v2 namespace"), "{error}");
        assert!(!path.join(v2::ROOT_FILE).exists());
        assert!(path.join(PLAN_FILE).exists());
        assert!(path.join(PROGRESS_DIRECTORY).exists());

        let canonical = path.join(v2::OBJECT_DIRECTORY);
        let displaced = path.join("provider-displaced-namespace-evidence");
        let replacement = path.join("provider-replacement-evidence");
        fs::rename(&canonical, &replacement).unwrap();
        fs::rename(&displaced, &canonical).unwrap();
        migrate_v1_to_v2("migration-passphrase", &path).unwrap();
        assert_eq!(read_migrated(&path), content);
        assert!(replacement.is_dir());
        fs::remove_dir_all(path).unwrap();
    }

    #[test]
    fn garbage_plan_cannot_authorize_dual_format_heads() {
        let path = directory("garbage-plan");
        fixture(&path, b"source");
        migrate_v1_to_v2("migration-passphrase", &path).unwrap();
        let root = fs::read(path.join(v2::ROOT_FILE)).unwrap();
        fs::write(path.join(PLAN_FILE), b"provider garbage").unwrap();

        let (kdf, kdf_fingerprint) = load_kdf_with_fingerprint(&path).unwrap().unwrap();
        let key = derive_key("migration-passphrase", &kdf);
        let (_, current) = v2::load(&path, &key).unwrap();
        let error = validate_completed_migration_evidence(&path, &key, &kdf_fingerprint, &current)
            .unwrap_err();
        assert!(error.contains("authenticate v2 migration plan"), "{error}");
        assert_eq!(fs::read(path.join(v2::ROOT_FILE)).unwrap(), root);

        fs::remove_dir_all(path).unwrap();
    }

    #[test]
    fn completed_migration_fast_path_rejects_provider_root_sibling() {
        let path = directory("completed-root-sibling");
        fixture(&path, b"retained source");
        migrate_v1_to_v2("migration-passphrase", &path).unwrap();
        let root_before = fs::read(path.join(v2::ROOT_FILE)).unwrap();
        let sibling = path.join("_root (conflicted copy).age");
        fs::write(&sibling, b"provider conflict evidence").unwrap();

        let error = migrate_v1_to_v2("migration-passphrase", &path).unwrap_err();
        assert!(error.contains("_root"), "{error}");
        assert_eq!(fs::read(path.join(v2::ROOT_FILE)).unwrap(), root_before);
        assert_eq!(fs::read(&sibling).unwrap(), b"provider conflict evidence");
        assert_eq!(read_migrated(&path), b"retained source");
        fs::remove_dir_all(path).unwrap();
    }

    #[test]
    fn completed_migration_fast_path_rechecks_late_provider_root_sibling() {
        let path = directory("completed-late-root-sibling");
        fixture(&path, b"retained source");
        migrate_v1_to_v2("migration-passphrase", &path).unwrap();
        let root_before = fs::read(path.join(v2::ROOT_FILE)).unwrap();
        let sibling = path.join("_root (conflicted copy).age");
        let sibling_for_hook = sibling.clone();
        let hook = v2::arm_namespace_test_hook(
            "before completed migration final sibling scan",
            move || fs::write(sibling_for_hook, b"late provider conflict evidence").unwrap(),
        );

        let error = migrate_v1_to_v2("migration-passphrase", &path).unwrap_err();
        drop(hook);
        assert!(error.contains("_root"), "{error}");
        assert_eq!(fs::read(path.join(v2::ROOT_FILE)).unwrap(), root_before);
        assert_eq!(
            fs::read(&sibling).unwrap(),
            b"late provider conflict evidence"
        );
        assert_eq!(read_migrated(&path), b"retained source");
        fs::remove_dir_all(path).unwrap();
    }

    #[test]
    fn migration_rechecks_provider_root_sibling_after_completion_publication() {
        let path = directory("completion-publication-root-sibling");
        fixture(&path, b"retained source");
        let old_index = fs::read(path.join("_index.age")).unwrap();
        let old_blob = fs::read(path.join("000001.age")).unwrap();
        let sibling = path.join("_root (conflicted copy).age");
        let sibling_for_hook = sibling.clone();
        let hook = v2::arm_namespace_test_hook(
            "after migration completion publication before sibling scan",
            move || fs::write(sibling_for_hook, b"provider conflict during publication").unwrap(),
        );

        let error = migrate_v1_to_v2("migration-passphrase", &path).unwrap_err();
        drop(hook);
        assert!(error.contains("_root"), "{error}");
        assert!(
            path.join(COMPLETION_FILE).exists(),
            "the test hook must run only after completion publication"
        );
        assert_eq!(fs::read(path.join("_index.age")).unwrap(), old_index);
        assert_eq!(fs::read(path.join("000001.age")).unwrap(), old_blob);
        assert_eq!(
            fs::read(&sibling).unwrap(),
            b"provider conflict during publication"
        );
        assert_eq!(read_migrated(&path), b"retained source");

        let retry = migrate_v1_to_v2("migration-passphrase", &path).unwrap_err();
        assert!(retry.contains("_root"), "{retry}");
        fs::remove_file(&sibling).unwrap();
        File::open(&path).unwrap().sync_all().unwrap();
        migrate_v1_to_v2("migration-passphrase", &path).unwrap();
        assert_eq!(read_migrated(&path), b"retained source");
        fs::remove_dir_all(path).unwrap();
    }

    #[test]
    fn migration_resumes_after_every_durability_checkpoint() {
        let baseline = directory("fault-baseline");
        let content = b"small resumable source";
        fixture(&baseline, content);

        let trace = directory("fault-trace");
        copy_directory(&baseline, &trace);
        let recorder = FaultInjectionGuard::record();
        migrate_v1_to_v2("migration-passphrase", &trace).unwrap();
        let events = recorder.events();
        drop(recorder);
        assert!(events.contains(&DurabilityEvent::Write));
        assert!(events.contains(&DurabilityEvent::FileSync));
        assert!(events.contains(&DurabilityEvent::Rename));
        assert!(events.contains(&DurabilityEvent::DirectorySync));
        assert!(events.contains(&DurabilityEvent::Cleanup));
        fs::remove_dir_all(trace).unwrap();

        for checkpoint in 1..=events.len() {
            let crashed = directory(&format!("fault-{checkpoint}"));
            copy_directory(&baseline, &crashed);
            fs::write(crashed.join("provider-evidence.keep"), b"keep").unwrap();
            let injector = FaultInjectionGuard::fail_at(checkpoint);
            let result = migrate_v1_to_v2("migration-passphrase", &crashed);
            drop(injector);
            assert!(
                result.is_err(),
                "migration checkpoint {checkpoint} was not hit"
            );
            migrate_v1_to_v2("migration-passphrase", &crashed).unwrap();
            assert_eq!(read_migrated(&crashed), content);
            assert_eq!(
                fs::read(crashed.join("provider-evidence.keep")).unwrap(),
                b"keep"
            );
            fs::remove_dir_all(crashed).unwrap();
        }

        fs::remove_dir_all(baseline).unwrap();
    }

    #[test]
    fn unexpected_progress_artifact_is_preserved_and_blocks_resume() {
        let path = directory("conflict");
        fixture(&path, b"source");
        let (kdf, kdf_fingerprint) = load_kdf_with_fingerprint(&path).unwrap().unwrap();
        let key = derive_key("migration-passphrase", &kdf);
        let (index, source_index) = load_v1_index(&path, &key).unwrap();
        let _ = publish_plan(&path, &key, source_index, kdf_fingerprint, &index, None).unwrap();
        let progress = ensure_progress_directory(&path).unwrap();
        fs::write(progress.join("provider-conflicted-copy"), b"evidence").unwrap();

        let error = migrate_v1_to_v2("migration-passphrase", &path).unwrap_err();
        assert!(error.contains("unexpected artifact"), "{error}");
        assert_eq!(
            fs::read(progress.join("provider-conflicted-copy")).unwrap(),
            b"evidence"
        );
        assert!(!path.join(v2::ROOT_FILE).exists());
        fs::remove_dir_all(path).unwrap();
    }
}
