// Copyright 2026 Alexander Orlov <alexander.orlov@loxal.net>

use std::collections::HashSet;
use std::sync::atomic::Ordering;

use serde::{Deserialize, Serialize};

use crate::crypto::{
    RecoveryFingerprint, ciphertext_bytes_fingerprint, ciphertext_fingerprint,
    ciphertext_fingerprint_bounded, ciphertext_fingerprint_expected, decrypt_blob_owned,
    decrypt_index_owned, encrypt_blob, encrypt_blob_owned, encrypt_index,
    load_kdf_with_fingerprint, try_derive_existing_key_at, try_derive_key,
};
#[cfg(test)]
use crate::crypto::{decrypt_blob, decrypt_index, exact_fingerprint};
#[cfg(test)]
use crate::fs::{DiskIndex, validate_disk_index};
use crate::fs::{
    FsInner, InodeKind, durable_create_new, durable_write, ensure_index_plaintext_within_limit,
    ensure_no_index_siblings, ensure_real_directory, read_bounded_backing_file,
    read_index_ciphertext, read_v1_blob_ciphertext, serialize_index_bounded,
};
use crate::transaction_lock::{lock_owner_is_active, prepare_lock_owner, write_lock_owner};

const STAGING: &str = ".rekey_staging";
const MANIFEST: &str = "_rekey.manifest";
const LOCK: &str = "_rekey.lock";
const INDEX_FILE: &str = "_index.age";
const MAX_MANIFEST_FILE_LEN: u64 = 64 * 1024 * 1024;
const MAX_INDEX_CIPHERTEXT_LEN: u64 = 64 * 1024 * 1024;
const MAX_MANIFEST_ENTRIES: usize = 100_000;
const MAX_PASSPHRASE_PROBE_LEN: u64 = 64 * 1024 * 1024;

#[derive(Serialize, Deserialize, Clone, Debug)]
struct ManifestEntry {
    filename: String,
    renamed: bool,
    /// Added after the original manifest format shipped. Recovery upgrades
    /// old manifests before it performs another rename.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    fingerprint: Option<RecoveryFingerprint>,
}

#[derive(Clone, Debug)]
struct IndexedBlob {
    filename: String,
    size: u64,
}

fn generated_blob_filename(filename: &str) -> bool {
    let Some(hex) = filename.strip_suffix(".age") else {
        return false;
    };
    if !(6..=16).contains(&hex.len())
        || !hex
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return false;
    }
    let Ok(value) = u64::from_str_radix(hex, 16) else {
        return false;
    };
    value > 0 && format!("{value:06x}.age") == filename
}

fn validate_disk_files(disk_files: &[IndexedBlob]) -> Result<(), String> {
    let mut seen = HashSet::with_capacity(disk_files.len());
    for blob in disk_files {
        if !generated_blob_filename(&blob.filename) {
            return Err(format!(
                "index contains invalid generated filename {:?}",
                blob.filename
            ));
        }
        if !seen.insert(blob.filename.as_str()) {
            return Err(format!(
                "index contains duplicate generated filename {}",
                blob.filename
            ));
        }
    }
    Ok(())
}

fn validate_manifest(entries: &[ManifestEntry]) -> Result<(), String> {
    if entries.len() > MAX_MANIFEST_ENTRIES {
        return Err(format!(
            "rekey manifest has {} entries; maximum is {MAX_MANIFEST_ENTRIES}",
            entries.len()
        ));
    }
    if entries.is_empty() || entries.last().map(|entry| entry.filename.as_str()) != Some(INDEX_FILE)
    {
        return Err("rekey manifest must end with _index.age".to_string());
    }
    let mut seen = HashSet::with_capacity(entries.len());
    for (i, entry) in entries.iter().enumerate() {
        if !seen.insert(entry.filename.as_str()) {
            return Err(format!(
                "rekey manifest contains duplicate {}",
                entry.filename
            ));
        }
        let is_index = i == entries.len() - 1;
        if !is_index && !generated_blob_filename(&entry.filename) {
            return Err(format!(
                "rekey manifest contains invalid blob filename {:?}",
                entry.filename
            ));
        }
        if let Some(fingerprint) = &entry.fingerprint
            && (!fingerprint.is_well_formed() || !fingerprint.is_ciphertext())
        {
            return Err(format!(
                "rekey manifest has invalid fingerprint for {}",
                entry.filename
            ));
        }
        if is_index
            && entry
                .fingerprint
                .as_ref()
                .and_then(RecoveryFingerprint::ciphertext_len)
                .is_some_and(|len| len > MAX_INDEX_CIPHERTEXT_LEN)
        {
            return Err("rekey manifest index exceeds the live index-size limit".to_string());
        }
    }
    Ok(())
}

fn sync_dir(path: &std::path::Path) -> Result<(), String> {
    let dir =
        std::fs::File::open(path).map_err(|e| format!("open directory {}: {e}", path.display()))?;
    dir.sync_all()
        .map_err(|e| format!("sync directory {}: {e}", path.display()))
}

fn checked_exists(path: &std::path::Path) -> Result<bool, String> {
    crate::fs::backing_entry_exists(path).map_err(|e| format!("check {}: {e}", path.display()))
}

fn durable_write_checked(path: &std::path::Path, data: &[u8]) -> Result<(), String> {
    durable_write(path, data).map_err(|e| format!("write {}: {e}", path.display()))
}

fn remove_file_if_exists(path: &std::path::Path) -> Result<(), String> {
    match std::fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(format!("remove {}: {e}", path.display())),
    }
}

fn remove_dir_if_exists(path: &std::path::Path) -> Result<(), String> {
    match std::fs::symlink_metadata(path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(format!("inspect {}: {e}", path.display())),
        Ok(_) => {}
    }
    ensure_real_directory(path).map_err(|e| e.to_string())?;
    std::fs::remove_dir_all(path).map_err(|e| format!("remove {}: {e}", path.display()))
}

fn remove_empty_dir_if_exists(path: &std::path::Path) -> Result<(), String> {
    match std::fs::symlink_metadata(path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(format!("inspect {}: {e}", path.display())),
        Ok(_) => {}
    }
    ensure_real_directory(path).map_err(|e| e.to_string())?;
    std::fs::remove_dir(path).map_err(|e| format!("remove empty {}: {e}", path.display()))
}

fn write_manifest(path: &std::path::Path, entries: &[ManifestEntry]) -> Result<(), String> {
    validate_manifest(entries)?;
    let json = serde_json::to_vec(entries).map_err(|e| format!("serialize rekey manifest: {e}"))?;
    if json.len() as u64 > MAX_MANIFEST_FILE_LEN {
        return Err(format!(
            "rekey manifest is too large ({} bytes; maximum {MAX_MANIFEST_FILE_LEN})",
            json.len()
        ));
    }
    durable_write_checked(path, &json)
}

fn create_manifest(path: &std::path::Path, entries: &[ManifestEntry]) -> Result<(), String> {
    validate_manifest(entries)?;
    let json = serde_json::to_vec(entries).map_err(|e| format!("serialize rekey manifest: {e}"))?;
    if json.len() as u64 > MAX_MANIFEST_FILE_LEN {
        return Err(format!(
            "rekey manifest is too large ({} bytes; maximum {MAX_MANIFEST_FILE_LEN})",
            json.len()
        ));
    }
    durable_create_new(path, &json).map_err(|error| {
        format!(
            "publish new rekey manifest {} without replacement: {error}",
            path.display()
        )
    })
}

fn read_manifest(path: &std::path::Path) -> Result<Vec<ManifestEntry>, String> {
    let json = read_bounded_backing_file(path, MAX_MANIFEST_FILE_LEN)
        .map_err(|e| format!("read {}: {e}", path.display()))?;
    let entries: Vec<ManifestEntry> =
        serde_json::from_slice(&json).map_err(|e| format!("parse rekey manifest: {e}"))?;
    validate_manifest(&entries)?;
    Ok(entries)
}

fn upgrade_manifest_fingerprints(
    base_path: &std::path::Path,
    staging_dir: &std::path::Path,
    manifest_path: &std::path::Path,
    entries: &mut [ManifestEntry],
) -> Result<(), String> {
    let mut changed = false;
    for entry in entries.iter_mut() {
        if entry
            .fingerprint
            .as_ref()
            .is_some_and(RecoveryFingerprint::has_full_content_identity)
        {
            continue;
        }
        let staged = staging_dir.join(&entry.filename);
        let source = if entry.renamed {
            base_path.join(&entry.filename)
        } else if checked_exists(&staged)? {
            staged
        } else if entry.fingerprint.is_some() {
            // Fingerprint-backed manifests are immutable. A matching target
            // can therefore prove a rename that completed immediately before
            // a crash, even though `renamed` was never updated.
            base_path.join(&entry.filename)
        } else {
            return Err(format!(
                "cannot safely recover legacy manifest entry {}: staged file is missing and completion was not recorded",
                entry.filename
            ));
        };
        let upgraded = match entry
            .fingerprint
            .as_ref()
            .and_then(RecoveryFingerprint::ciphertext_len)
        {
            Some(expected_len) => ciphertext_fingerprint_expected(&source, expected_len)?,
            None if entry.filename == INDEX_FILE => {
                ciphertext_fingerprint_bounded(&source, MAX_INDEX_CIPHERTEXT_LEN)?
            }
            None => ciphertext_fingerprint(&source)?,
        };
        if let Some(existing) = &entry.fingerprint
            && !existing.has_same_legacy_identity(&upgraded)
        {
            return Err(format!(
                "cannot upgrade rekey manifest fingerprint for {} because the staged/target identity changed",
                entry.filename
            ));
        }
        entry.fingerprint = Some(upgraded);
        changed = true;
    }
    if changed {
        write_manifest(manifest_path, entries)?;
    }
    Ok(())
}

fn ensure_staging_unambiguous(
    staging_dir: &std::path::Path,
    entries: &[ManifestEntry],
) -> Result<(), String> {
    if !checked_exists(staging_dir)? {
        return Ok(());
    }
    ensure_real_directory(staging_dir).map_err(|e| e.to_string())?;
    let allowed: HashSet<&str> = entries
        .iter()
        .map(|entry| entry.filename.as_str())
        .collect();
    for entry in std::fs::read_dir(staging_dir)
        .map_err(|e| format!("read staging directory {}: {e}", staging_dir.display()))?
    {
        let entry = entry.map_err(|e| format!("read staging entry: {e}"))?;
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            return Err(format!(
                "rekey staging {} contains a non-UTF-8 entry; preserving it for reconciliation",
                staging_dir.display()
            ));
        };
        if !allowed.contains(name) {
            return Err(format!(
                "rekey staging {} contains unexpected provider/interrupted artifact {name:?}; preserving all recovery evidence",
                staging_dir.display()
            ));
        }
    }
    Ok(())
}

fn commit_manifest(
    base_path: &std::path::Path,
    staging_dir: &std::path::Path,
    entries: &[ManifestEntry],
) -> Result<(), String> {
    if checked_exists(staging_dir)? {
        ensure_real_directory(staging_dir).map_err(|e| e.to_string())?;
    }
    ensure_staging_unambiguous(staging_dir, entries)?;
    for entry in entries {
        let expected = entry
            .fingerprint
            .as_ref()
            .ok_or_else(|| format!("rekey manifest entry {} has no fingerprint", entry.filename))?;
        if !expected.has_full_content_identity() {
            return Err(format!(
                "rekey manifest entry {} has no full-content fingerprint",
                entry.filename
            ));
        }
        let expected_len = expected.ciphertext_len().ok_or_else(|| {
            format!(
                "rekey manifest entry {} has a non-ciphertext fingerprint",
                entry.filename
            )
        })?;
        let staged = staging_dir.join(&entry.filename);
        let target = base_path.join(&entry.filename);
        if checked_exists(&staged)? {
            if ciphertext_fingerprint_expected(&staged, expected_len)? != *expected {
                return Err(format!(
                    "staged {} does not match its rekey manifest",
                    entry.filename
                ));
            }
            std::fs::rename(&staged, &target)
                .map_err(|e| format!("rename staging/{}: {e}", entry.filename))?;
            sync_dir(staging_dir)?;
            sync_dir(base_path)?;
        } else {
            let actual = ciphertext_fingerprint_expected(&target, expected_len).map_err(|e| {
                format!(
                    "rekey entry {} is missing from staging and target does not verify: {e}",
                    entry.filename
                )
            })?;
            if actual != *expected {
                return Err(format!(
                    "rekey entry {} is missing from staging and target fingerprint does not match",
                    entry.filename
                ));
            }
        }
    }
    Ok(())
}

fn cleanup_transaction(base_path: &std::path::Path) -> Result<(), String> {
    // Every manifest entry has been moved out. A nonempty staging directory
    // now means a provider/interrupted artifact appeared after the pre-scan;
    // preserve it and the manifest instead of recursively deleting evidence.
    remove_empty_dir_if_exists(&base_path.join(STAGING))?;
    remove_file_if_exists(&base_path.join(LOCK))?;
    // Keep the manifest until every other cleanup step succeeds. If cleanup is
    // interrupted, target fingerprints still prove that the commit completed.
    remove_file_if_exists(&base_path.join(MANIFEST))?;
    sync_dir(base_path)
}

fn acquire_rekey_lock(base_path: &std::path::Path) -> Result<(), String> {
    let lock_path = base_path.join(LOCK);
    let lock_record = prepare_lock_owner("rekey")?;
    if checked_exists(&lock_path)? {
        if lock_owner_is_active(&lock_path, "rekey")? {
            return Err(format!(
                "lock file exists at {} and its owner is still running",
                lock_path.display()
            ));
        }
        eprintln!(
            "zerotrust-drive: replacing stale rekey lock {}",
            lock_path.display()
        );
        remove_file_if_exists(&lock_path)?;
        sync_dir(base_path)?;
    }

    let mut lock_file = std::fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&lock_path)
        .map_err(|e| format!("create rekey lock {}: {e}", lock_path.display()))?;
    if let Err(error) = write_lock_owner(&mut lock_file, &lock_record, &lock_path, "rekey") {
        drop(lock_file);
        let cleanup = remove_file_if_exists(&lock_path).and_then(|()| sync_dir(base_path));
        return match cleanup {
            Ok(()) => Err(error),
            Err(cleanup_error) => Err(format!(
                "{error}; additionally failed to remove the new incomplete lock: {cleanup_error}"
            )),
        };
    }
    lock_file
        .sync_all()
        .map_err(|e| format!("sync rekey lock {}: {e}", lock_path.display()))?;
    sync_dir(base_path)
}

fn cleanup_stale_staging_result(base_path: &std::path::Path) -> Result<(), String> {
    let staging_dir = base_path.join(STAGING);
    if checked_exists(&staging_dir)? && !checked_exists(&base_path.join(MANIFEST))? {
        let lock_path = base_path.join(LOCK);
        if lock_owner_is_active(&lock_path, "rekey")? {
            return Err(format!(
                "refusing to clean staging owned by a live process ({})",
                lock_path.display()
            ));
        }
        eprintln!("zerotrust-drive: removing stale staging directory");
        remove_dir_if_exists(&staging_dir)?;
        sync_dir(base_path)?;
    }
    Ok(())
}

/// Clean up an orphaned pre-commit staging directory.
#[allow(dead_code)]
pub fn cleanup_stale_staging(base_path: &std::path::Path) {
    if let Err(e) = cleanup_stale_staging_result(base_path) {
        eprintln!("zerotrust-drive: ERROR: failed to clean stale rekey staging: {e}");
    }
}

/// Verify that the new passphrase matches the files already in `.rekey_staging/`.
/// Picks the first `.age` file in the staging dir and tries to decrypt it with the new key.
pub fn verify_staged_passphrase(
    new_passphrase: &str,
    base_path: &std::path::Path,
) -> Result<(), String> {
    let staging_dir = base_path.join(STAGING);
    ensure_real_directory(&staging_dir).map_err(|e| e.to_string())?;
    let new_key = try_derive_existing_key_at(base_path, new_passphrase)?;
    let mut staged = Vec::new();
    for entry in std::fs::read_dir(&staging_dir).map_err(|e| e.to_string())? {
        let entry = entry.map_err(|e| e.to_string())?;
        let name = entry.file_name().to_string_lossy().to_string();
        if name == INDEX_FILE || generated_blob_filename(&name) {
            staged.push((name, entry.path()));
        }
    }
    staged.sort_by(|a, b| a.0.cmp(&b.0));
    if staged.is_empty() {
        return Err("no staged files found to verify".to_string());
    }
    let (name, path) = staged
        .iter()
        .find(|(name, _)| name == INDEX_FILE)
        .or_else(|| {
            staged.iter().min_by_key(|(_, path)| {
                path.metadata()
                    .map(|metadata| metadata.len())
                    .unwrap_or(u64::MAX)
            })
        })
        .expect("non-empty staged list");
    let ciphertext = if name == INDEX_FILE {
        read_index_ciphertext(path)
    } else {
        read_bounded_backing_file(path, MAX_PASSPHRASE_PROBE_LEN)
    }
    .map_err(|e| format!("read staged {name}: {e}"))?;
    let result = if name == INDEX_FILE {
        decrypt_index_owned(&new_key, ciphertext)
    } else {
        decrypt_blob_owned(&new_key, name, ciphertext)
    };
    result.map(|_| ()).map_err(|_| {
        format!("staged file {name} was encrypted with a different passphrase or is corrupt")
    })
}

/// Complete an interrupted rekey by finishing the rename pass from the manifest.
/// Returns `true` if recovery was performed.
#[cfg(test)]
pub fn recover_interrupted_rekey(base_path: &std::path::Path) -> bool {
    match recover_interrupted_rekey_result(base_path) {
        Ok(recovered) => recovered,
        Err(e) => {
            eprintln!("zerotrust-drive: ERROR: rekey recovery failed: {e}");
            false
        }
    }
}

pub(crate) fn recover_interrupted_rekey_result(
    base_path: &std::path::Path,
) -> Result<bool, String> {
    ensure_no_index_siblings(base_path)
        .map_err(|e| format!("refuse rekey recovery while control metadata is ambiguous: {e}"))?;
    let manifest_path = base_path.join(MANIFEST);
    if !checked_exists(&manifest_path)? {
        let lock_path = base_path.join(LOCK);
        if checked_exists(&lock_path)? {
            if lock_owner_is_active(&lock_path, "rekey")? {
                return Err(format!(
                    "refusing to clean rekey state owned by a live process ({})",
                    lock_path.display()
                ));
            }
            remove_file_if_exists(&lock_path)?;
            sync_dir(base_path)?;
        }
        return Ok(false);
    }

    let lock_path = base_path.join(LOCK);
    if lock_owner_is_active(&lock_path, "rekey")? {
        return Err(format!(
            "refusing to recover rekey owned by a live process ({})",
            lock_path.display()
        ));
    }
    eprintln!("zerotrust-drive: detected interrupted rekey - completing...");
    let mut entries = read_manifest(&manifest_path)?;
    let staging_dir = base_path.join(STAGING);
    upgrade_manifest_fingerprints(base_path, &staging_dir, &manifest_path, &mut entries)?;
    commit_manifest(base_path, &staging_dir, &entries)?;
    cleanup_transaction(base_path)?;
    eprintln!("zerotrust-drive: interrupted rekey completed successfully");
    Ok(true)
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
#[cfg(test)]
pub fn rekey(
    old_passphrase: &str,
    new_passphrase: &str,
    base_path: &std::path::Path,
    resume: bool,
) {
    if recover_interrupted_rekey_result(base_path).expect("failed to recover interrupted rekey") {
        return;
    }
    if resume {
        let staging_dir = base_path.join(STAGING);
        if checked_exists(&staging_dir).expect("failed to check rekey staging") {
            verify_staged_passphrase(new_passphrase, base_path)
                .unwrap_or_else(|e| panic!("cannot resume rekey: {e}"));
            eprintln!("zerotrust-drive: passphrase verified - resuming interrupted rekey");
        } else {
            eprintln!("zerotrust-drive: nothing to resume - starting fresh");
        }
    } else {
        cleanup_stale_staging_result(base_path).expect("failed to clean stale staging");
    }

    acquire_rekey_lock(base_path).expect("failed to acquire rekey lock");
    let lock_path = base_path.join(LOCK);

    let result = (|| -> Result<(), String> {
        let (kdf, expected_kdf_fingerprint) =
            load_kdf_with_fingerprint(base_path)?.ok_or_else(|| {
                format!(
                    "required KDF metadata {} is missing",
                    base_path.join("_kdf.json").display()
                )
            })?;
        let old_key = try_derive_key(old_passphrase, &kdf)?;
        let new_key = try_derive_key(new_passphrase, &kdf)?;
        let index_path = base_path.join(INDEX_FILE);
        let index_ciphertext =
            read_index_ciphertext(&index_path).map_err(|e| format!("read {INDEX_FILE}: {e}"))?;
        let expected_index_fingerprint = ciphertext_bytes_fingerprint(&index_ciphertext)?;
        let index_json = decrypt_index_owned(&old_key, index_ciphertext)
            .map_err(|_| "failed to decrypt _index.age - wrong passphrase?".to_string())?;
        let index: DiskIndex =
            serde_json::from_slice(&index_json).map_err(|e| format!("parse index: {e}"))?;
        validate_disk_index(&index)
            .map_err(|error| format!("refuse rekey of structurally invalid index: {error}"))?;
        let mut disk_files: Vec<IndexedBlob> = index
            .inodes
            .values()
            .filter(|entry| entry.kind == InodeKind::File && !entry.disk_filename.is_empty())
            .map(|entry| IndexedBlob {
                filename: entry.disk_filename.clone(),
                size: entry.size,
            })
            .collect();
        disk_files.sort_by(|a, b| a.filename.cmp(&b.filename));
        validate_disk_files(&disk_files)?;

        let staging_dir = base_path.join(STAGING);
        std::fs::create_dir_all(&staging_dir)
            .map_err(|e| format!("create {}: {e}", staging_dir.display()))?;
        ensure_real_directory(&staging_dir).map_err(|e| e.to_string())?;
        sync_dir(base_path)?;
        let total = disk_files.len() + 1;
        let mut skipped = 0usize;
        let mut staged_blob_fingerprints = Vec::with_capacity(disk_files.len());
        for (i, blob) in disk_files.iter().enumerate() {
            let filename = &blob.filename;
            let current = match read_v1_blob_ciphertext(&base_path.join(filename), blob.size) {
                Ok(current) => Some(current),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound && blob.size == 0 => None,
                Err(e) => return Err(format!("read {filename}: {e}")),
            };
            let plaintext = match current {
                Some(current) => decrypt_blob_owned(&old_key, filename, current)
                    .map_err(|_| format!("failed to decrypt {filename} - data may be corrupted"))?,
                None => Vec::new(),
            };
            let staged_path = staging_dir.join(filename);
            if resume && checked_exists(&staged_path)? {
                let staged = read_v1_blob_ciphertext(&staged_path, blob.size)
                    .map_err(|e| format!("read staged {filename}: {e}"))?;
                let staged_fingerprint = ciphertext_bytes_fingerprint(&staged)?;
                if decrypt_blob_owned(&new_key, filename, staged)
                    .ok()
                    .as_deref()
                    == Some(plaintext.as_slice())
                {
                    staged_blob_fingerprints.push((filename.clone(), staged_fingerprint));
                    skipped += 1;
                    continue;
                }
            }
            let new_ciphertext = encrypt_blob_owned(&new_key, filename, plaintext)?;
            durable_write_checked(&staged_path, &new_ciphertext)?;
            staged_blob_fingerprints.push((
                filename.clone(),
                ciphertext_bytes_fingerprint(&new_ciphertext)?,
            ));
            eprintln!(
                "zerotrust-drive: [{}/{}] re-encrypted {}",
                i + 1,
                total,
                filename
            );
        }
        if skipped > 0 {
            eprintln!("zerotrust-drive: skipped {skipped} verified staged file(s)");
        }

        let staged_index = staging_dir.join(INDEX_FILE);
        let reuse_staged_index = resume
            && checked_exists(&staged_index)?
            && read_index_ciphertext(&staged_index)
                .ok()
                .and_then(|bytes| decrypt_index_owned(&new_key, bytes).ok())
                .as_deref()
                == Some(index_json.as_slice());
        if !reuse_staged_index {
            durable_write_checked(&staged_index, &encrypt_index(&new_key, &index_json)?)?;
            eprintln!("zerotrust-drive: [{total}/{total}] re-encrypted {INDEX_FILE}");
        }

        let mut manifest: Vec<ManifestEntry> = staged_blob_fingerprints
            .into_iter()
            .map(|(filename, fingerprint)| ManifestEntry {
                filename,
                renamed: false,
                fingerprint: Some(fingerprint),
            })
            .collect();
        manifest.push(ManifestEntry {
            filename: INDEX_FILE.to_string(),
            renamed: false,
            fingerprint: Some(ciphertext_fingerprint_bounded(
                &staging_dir.join(INDEX_FILE),
                MAX_INDEX_CIPHERTEXT_LEN,
            )?),
        });
        validate_manifest(&manifest)?;
        ensure_no_index_siblings(base_path).map_err(|e| format!("refuse rekey commit: {e}"))?;
        if ciphertext_fingerprint_bounded(&index_path, MAX_INDEX_CIPHERTEXT_LEN)?
            != expected_index_fingerprint
        {
            return Err(
                "encrypted index changed during rekey staging; refusing to commit".to_string(),
            );
        }
        if exact_fingerprint(&base_path.join("_kdf.json"))? != expected_kdf_fingerprint {
            return Err(
                "KDF metadata changed during rekey staging; refusing to commit".to_string(),
            );
        }
        create_manifest(&base_path.join(MANIFEST), &manifest)?;
        commit_manifest(base_path, &staging_dir, &manifest)?;
        cleanup_transaction(base_path)?;
        Ok(())
    })();

    if let Err(error) = result {
        let committed = checked_exists(&base_path.join(MANIFEST)).unwrap_or_else(|check_error| {
            eprintln!(
                "zerotrust-drive: ERROR: cannot determine whether rekey committed; preserving recovery state: {check_error}"
            );
            true
        });
        if !committed {
            let _ = if resume {
                remove_file_if_exists(&lock_path).and_then(|()| sync_dir(base_path))
            } else {
                remove_dir_if_exists(&base_path.join(STAGING))
                    .and_then(|()| remove_file_if_exists(&lock_path))
                    .and_then(|()| sync_dir(base_path))
            };
        }
        panic!("rekey failed: {error}");
    }

    eprintln!("zerotrust-drive: re-encryption complete - all files now use the new passphrase");
}

struct RekeySnapshot {
    old_key: [u8; 32],
    new_key: [u8; 32],
    index_json: Vec<u8>,
    disk_files: Vec<IndexedBlob>,
}

fn clean_online_precommit(base_path: &std::path::Path, resume: bool) -> Result<(), String> {
    if !resume {
        remove_dir_if_exists(&base_path.join(STAGING))?;
    }
    remove_file_if_exists(&base_path.join(LOCK))?;
    sync_dir(base_path)
}

fn clean_online_precommit_and_restore_writes(
    base_path: &std::path::Path,
    inner: &FsInner,
    resume: bool,
) {
    match clean_online_precommit(base_path, resume) {
        Ok(()) => inner.restore_writes_if_healthy(),
        Err(e) => eprintln!(
            "zerotrust-drive: ERROR: pre-commit cleanup failed; filesystem remains read-only: {e}"
        ),
    }
}

fn prepare_online_snapshot(
    base_path: &std::path::Path,
    inner: &FsInner,
    old_key: [u8; 32],
    new_key: [u8; 32],
) -> Result<RekeySnapshot, String> {
    inner
        .ensure_index_unchanged()
        .map_err(|e| format!("refuse rekey snapshot: {e}"))?;
    let current_key = *inner
        .key
        .read()
        .map_err(|_| "filesystem key lock is poisoned".to_string())?;
    if current_key != old_key {
        return Err("failed to authenticate current passphrase".to_string());
    }
    let state = inner
        .state
        .read()
        .map_err(|_| "filesystem state lock is poisoned".to_string())?
        .clone();
    let open_files = inner
        .open_files
        .read()
        .map_err(|_| "open-file lock is poisoned".to_string())?;
    let dirty_inodes = inner.dirty_inode_snapshot()?;

    eprintln!("zerotrust-drive: flushing open files before re-encryption...");
    // Validate every open buffer before replacing the first base blob. A
    // later mismatch must not strand an earlier blob under the old index.
    for (ino, content) in open_files.iter() {
        let entry = state
            .inodes
            .get(ino)
            .ok_or_else(|| format!("open inode {ino} is missing from the index"))?;
        if entry.kind != InodeKind::File || entry.disk_filename.is_empty() {
            return Err(format!("open inode {ino} has no valid backing filename"));
        }
        if content.len() as u64 != entry.size {
            return Err(format!(
                "open inode {ino} has {} buffered bytes but records {}",
                content.len(),
                entry.size
            ));
        }
    }
    for ino in &dirty_inodes {
        if !open_files.contains_key(ino) {
            return Err(format!(
                "dirty inode {ino} has no open plaintext buffer during rekey snapshot"
            ));
        }
    }
    let mut disk_files: Vec<IndexedBlob> = state
        .inodes
        .values()
        .filter(|entry| entry.kind == InodeKind::File && !entry.disk_filename.is_empty())
        .map(|entry| IndexedBlob {
            filename: entry.disk_filename.clone(),
            size: entry.size,
        })
        .collect();
    disk_files.sort_by(|a, b| a.filename.cmp(&b.filename));
    validate_disk_files(&disk_files)?;

    // Prepare the matching index before replacing the first open-file blob.
    // Serialization, size bounds, or index encryption must fail while the
    // complete old generation is still intact.
    let index_json =
        serialize_index_bounded(&state).map_err(|e| format!("serialize index: {e}"))?;
    ensure_index_plaintext_within_limit(index_json.len())
        .map_err(|e| format!("refuse rekey snapshot: {e}"))?;
    let encrypted_index = encrypt_index(&current_key, &index_json)?;
    let index_fingerprint = ciphertext_bytes_fingerprint(&encrypted_index)?;

    for (ino, content) in open_files.iter() {
        if !dirty_inodes.contains(ino) {
            continue;
        }
        if let Some(entry) = state.inodes.get(ino)
            && !entry.disk_filename.is_empty()
        {
            let encrypted = encrypt_blob(&current_key, &entry.disk_filename, content)?;
            durable_write_checked(&inner.base_path.join(&entry.disk_filename), &encrypted)?;
        }
    }
    inner
        .ensure_index_unchanged()
        .map_err(|e| format!("refuse rekey snapshot index replacement: {e}"))?;
    durable_write_checked(&inner.base_path.join(INDEX_FILE), &encrypted_index)?;
    *inner
        .index_fingerprint
        .lock()
        .map_err(|_| "index fingerprint lock is poisoned".to_string())? = Some(index_fingerprint);
    if let Ok(metadata) = std::fs::metadata(base_path.join(INDEX_FILE))
        && let Ok(mtime) = metadata.modified()
    {
        *inner
            .index_mtime
            .lock()
            .map_err(|_| "index timestamp lock is poisoned".to_string())? = Some(mtime);
    }
    inner.clear_persisted_maintenance_state()?;

    Ok(RekeySnapshot {
        old_key,
        new_key,
        index_json,
        disk_files,
    })
}

fn stage_online_rekey(
    base_path: &std::path::Path,
    snapshot: &RekeySnapshot,
    resume: bool,
) -> Result<Vec<ManifestEntry>, String> {
    let staging_dir = base_path.join(STAGING);
    std::fs::create_dir_all(&staging_dir)
        .map_err(|e| format!("create {}: {e}", staging_dir.display()))?;
    ensure_real_directory(&staging_dir).map_err(|e| e.to_string())?;
    sync_dir(base_path)?;
    let total = snapshot.disk_files.len() + 1;
    eprintln!(
        "zerotrust-drive: re-encrypting {} file(s) + index with new passphrase...",
        snapshot.disk_files.len()
    );

    let mut skipped = 0usize;
    let mut staged_blob_fingerprints = Vec::with_capacity(snapshot.disk_files.len());
    for (i, blob) in snapshot.disk_files.iter().enumerate() {
        let filename = &blob.filename;
        let ciphertext = match read_v1_blob_ciphertext(&base_path.join(filename), blob.size) {
            Ok(ciphertext) => Some(ciphertext),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound && blob.size == 0 => None,
            Err(e) => return Err(format!("read {filename}: {e}")),
        };
        let plaintext = match ciphertext {
            Some(ciphertext) => decrypt_blob_owned(&snapshot.old_key, filename, ciphertext)
                .map_err(|_| format!("failed to decrypt {filename} - data may be corrupted"))?,
            None => Vec::new(),
        };
        let staged_path = staging_dir.join(filename);
        if resume && checked_exists(&staged_path)? {
            let staged = read_v1_blob_ciphertext(&staged_path, blob.size)
                .map_err(|e| format!("read staged {filename}: {e}"))?;
            let staged_fingerprint = ciphertext_bytes_fingerprint(&staged)?;
            if decrypt_blob_owned(&snapshot.new_key, filename, staged)
                .ok()
                .as_deref()
                == Some(plaintext.as_slice())
            {
                staged_blob_fingerprints.push((filename.clone(), staged_fingerprint));
                skipped += 1;
                continue;
            }
        }
        let encrypted = encrypt_blob_owned(&snapshot.new_key, filename, plaintext)?;
        durable_write_checked(&staged_path, &encrypted)?;
        staged_blob_fingerprints
            .push((filename.clone(), ciphertext_bytes_fingerprint(&encrypted)?));
        eprintln!(
            "zerotrust-drive: [{}/{}] re-encrypted {}",
            i + 1,
            total,
            filename
        );
    }
    if skipped > 0 {
        eprintln!("zerotrust-drive: skipped {skipped} verified staged file(s)");
    }

    let staged_index = staging_dir.join(INDEX_FILE);
    let reuse_staged_index = resume
        && checked_exists(&staged_index)?
        && read_index_ciphertext(&staged_index)
            .ok()
            .and_then(|bytes| decrypt_index_owned(&snapshot.new_key, bytes).ok())
            .as_deref()
            == Some(snapshot.index_json.as_slice());
    if !reuse_staged_index {
        durable_write_checked(
            &staged_index,
            &encrypt_index(&snapshot.new_key, &snapshot.index_json)?,
        )?;
        eprintln!("zerotrust-drive: [{total}/{total}] re-encrypted {INDEX_FILE}");
    }

    let mut manifest: Vec<ManifestEntry> = staged_blob_fingerprints
        .into_iter()
        .map(|(filename, fingerprint)| ManifestEntry {
            filename,
            renamed: false,
            fingerprint: Some(fingerprint),
        })
        .collect();
    manifest.push(ManifestEntry {
        filename: INDEX_FILE.to_string(),
        renamed: false,
        fingerprint: Some(ciphertext_fingerprint_bounded(
            &staging_dir.join(INDEX_FILE),
            MAX_INDEX_CIPHERTEXT_LEN,
        )?),
    });
    validate_manifest(&manifest)?;
    Ok(manifest)
}

/// Re-encrypt all files online while keeping reads available during the
/// expensive staging pass. Writes remain read-only for the full rotation.
pub fn rekey_online(
    old_passphrase: &str,
    new_passphrase: &str,
    base_path: &std::path::Path,
    inner: &FsInner,
    resume: bool,
) {
    match recover_interrupted_rekey_result(base_path) {
        Ok(true) => {
            eprintln!(
                "zerotrust-drive: recovered a committed rekey; remount with the new passphrase before rotating again"
            );
            return;
        }
        Ok(false) => {}
        Err(e) => {
            eprintln!("zerotrust-drive: error: cannot start rekey - {e}");
            return;
        }
    }

    let staging_exists = match checked_exists(&base_path.join(STAGING)) {
        Ok(exists) => exists,
        Err(e) => {
            inner.restore_writes_if_healthy();
            eprintln!("zerotrust-drive: error: cannot inspect rekey staging - {e}");
            return;
        }
    };
    if resume && staging_exists {
        if let Err(e) = verify_staged_passphrase(new_passphrase, base_path) {
            inner.restore_writes_if_healthy();
            eprintln!("zerotrust-drive: error: cannot resume - {e}");
            return;
        }
        eprintln!("zerotrust-drive: passphrase verified - resuming interrupted rekey");
    } else if !resume && let Err(e) = cleanup_stale_staging_result(base_path) {
        eprintln!("zerotrust-drive: error: cannot clean stale rekey staging - {e}");
        return;
    }

    if let Err(e) = acquire_rekey_lock(base_path) {
        eprintln!("zerotrust-drive: error: cannot acquire rekey lock - {e}");
        return;
    }
    let loaded_kdf = match load_kdf_with_fingerprint(base_path) {
        Ok(Some((kdf, _fingerprint))) => kdf,
        Ok(None) => {
            clean_online_precommit_and_restore_writes(base_path, inner, resume);
            eprintln!("zerotrust-drive: error: required KDF metadata is missing");
            return;
        }
        Err(e) => {
            clean_online_precommit_and_restore_writes(base_path, inner, resume);
            eprintln!("zerotrust-drive: error: cannot load KDF metadata - {e}");
            return;
        }
    };
    let old_key = match try_derive_key(old_passphrase, &loaded_kdf) {
        Ok(key) => key,
        Err(e) => {
            clean_online_precommit_and_restore_writes(base_path, inner, resume);
            eprintln!("zerotrust-drive: error: cannot derive current key - {e}");
            return;
        }
    };
    let new_key = match try_derive_key(new_passphrase, &loaded_kdf) {
        Ok(key) => key,
        Err(e) => {
            clean_online_precommit_and_restore_writes(base_path, inner, resume);
            eprintln!("zerotrust-drive: error: cannot derive new key - {e}");
            return;
        }
    };

    inner.read_only.store(true, Ordering::SeqCst);
    eprintln!(
        "zerotrust-drive: filesystem is now read-only - writes return EROFS until re-encryption completes"
    );

    let snapshot = {
        let _persistence = match inner.persistence_mutex.lock() {
            Ok(guard) => guard,
            Err(_) => {
                if let Err(e) = clean_online_precommit(base_path, resume) {
                    eprintln!("zerotrust-drive: ERROR: pre-commit cleanup also failed: {e}");
                }
                eprintln!("zerotrust-drive: ERROR: persistence gate is poisoned");
                return;
            }
        };
        prepare_online_snapshot(base_path, inner, old_key, new_key)
    };
    let snapshot = match snapshot {
        Ok(snapshot) => snapshot,
        Err(e) => {
            clean_online_precommit_and_restore_writes(base_path, inner, resume);
            eprintln!("zerotrust-drive: ERROR: rekey snapshot failed: {e}");
            return;
        }
    };

    // No persistence gate is held here. The old key and target files remain
    // active, so open/release/read operations can continue during staging.
    let manifest = match stage_online_rekey(base_path, &snapshot, resume) {
        Ok(manifest) => manifest,
        Err(e) => {
            clean_online_precommit_and_restore_writes(base_path, inner, resume);
            eprintln!("zerotrust-drive: ERROR: rekey staging failed: {e}");
            return;
        }
    };

    let mut crossed_commit_point = false;
    let result = {
        let _persistence = match inner.persistence_mutex.lock() {
            Ok(guard) => guard,
            Err(_) => {
                if let Err(e) = clean_online_precommit(base_path, resume) {
                    eprintln!("zerotrust-drive: ERROR: pre-commit cleanup also failed: {e}");
                }
                eprintln!("zerotrust-drive: ERROR: persistence gate is poisoned");
                return;
            }
        };
        (|| -> Result<(), String> {
            if *inner
                .key
                .read()
                .map_err(|_| "filesystem key lock is poisoned".to_string())?
                != snapshot.old_key
            {
                return Err("filesystem key changed during rekey staging".to_string());
            }
            let state = inner
                .state
                .read()
                .map_err(|_| "filesystem state lock is poisoned".to_string())?;
            let current_index = serialize_index_bounded(&state)
                .map_err(|e| format!("serialize current index: {e}"))?;
            drop(state);
            if current_index != snapshot.index_json {
                return Err("filesystem state changed during read-only rekey staging".to_string());
            }

            inner
                .ensure_index_unchanged()
                .map_err(|e| format!("refuse rekey commit: {e}"))?;

            create_manifest(&base_path.join(MANIFEST), &manifest)?;
            crossed_commit_point = true;
            commit_manifest(base_path, &base_path.join(STAGING), &manifest)?;
            *inner
                .key
                .write()
                .map_err(|_| "filesystem key lock is poisoned".to_string())? = snapshot.new_key;
            *inner
                .index_fingerprint
                .lock()
                .map_err(|_| "index fingerprint lock is poisoned".to_string())? =
                Some(ciphertext_fingerprint_bounded(
                    &base_path.join(INDEX_FILE),
                    MAX_INDEX_CIPHERTEXT_LEN,
                )?);
            if let Ok(metadata) = std::fs::metadata(base_path.join(INDEX_FILE))
                && let Ok(mtime) = metadata.modified()
            {
                *inner
                    .index_mtime
                    .lock()
                    .map_err(|_| "index timestamp lock is poisoned".to_string())? = Some(mtime);
            }
            cleanup_transaction(base_path)
        })()
    };

    if let Err(e) = result {
        let committed = crossed_commit_point
            || checked_exists(&base_path.join(MANIFEST)).unwrap_or_else(|check_error| {
                eprintln!(
                    "zerotrust-drive: ERROR: cannot determine whether rekey committed; preserving recovery state: {check_error}"
                );
                true
            });
        if !committed {
            clean_online_precommit_and_restore_writes(base_path, inner, resume);
        } else {
            eprintln!(
                "zerotrust-drive: ERROR: rekey crossed its commit point; filesystem remains read-only - unmount and restart so recovery can finish, then use the new passphrase"
            );
        }
        eprintln!("zerotrust-drive: ERROR: rekey failed: {e}");
        return;
    }

    inner.restore_writes_if_healthy();
    eprintln!("zerotrust-drive: passphrase rotation complete - filesystem is read-write again");
    eprintln!("zerotrust-drive: all files are now encrypted with the new passphrase");
    eprintln!("zerotrust-drive: remember to update ZEROTRUST_PASSPHRASE before next mount");
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::derive_key_at;
    use crate::fs::{DirChild, InodeEntry, InodeKind, ZeroTrustFs};
    use crate::transaction_lock::local_lock_record_for_test;
    use std::fs;
    use std::path::PathBuf;
    use std::sync::atomic::Ordering;

    fn legacy_ciphertext_fingerprint(path: &std::path::Path) -> RecoveryFingerprint {
        let mut fingerprint = ciphertext_fingerprint(path).unwrap();
        if let RecoveryFingerprint::Ciphertext { digest, .. } = &mut fingerprint {
            *digest = None;
        }
        fingerprint
    }

    #[test]
    fn rekey_basic() {
        let dir = PathBuf::from("target/test-rekey-basic");
        let _ = fs::remove_dir_all(&dir);
        let old_pw = "old-passphrase";
        let new_pw = "new-passphrase";

        {
            let ztfs = ZeroTrustFs::new(old_pw, dir.clone());
            let mut state = ztfs.inner.state.write().unwrap();
            let ino = ZeroTrustFs::allocate_inode(&mut state);
            let df = ZeroTrustFs::allocate_disk_filename(&mut state);
            state.inodes.insert(
                ino,
                InodeEntry {
                    name: "secret.txt".to_string(),
                    kind: InodeKind::File,
                    disk_filename: df.clone(),
                    size: 11,
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
                name: "secret.txt".to_string(),
                inode: ino,
            });
            drop(state);
            ztfs.write_encrypted_file(&df, b"secret data").unwrap();
            ztfs.flush_state().unwrap();
        }

        rekey(old_pw, new_pw, &dir, false);

        let old_key = derive_key_at(&dir, old_pw);
        let index_ct = fs::read(dir.join("_index.age")).unwrap();
        assert!(decrypt_index(&old_key, &index_ct).is_err());

        let ztfs = ZeroTrustFs::new(new_pw, dir.clone());
        let state = ztfs.inner.state.read().unwrap();
        let ino = ZeroTrustFs::find_child(&state, 1, "secret.txt").expect("file should exist");
        let df = state.inodes.get(&ino).unwrap().disk_filename.clone();
        drop(state);
        let content = ztfs
            .read_encrypted_file(&df)
            .expect("failed to read encrypted file");
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
                ztfs.write_encrypted_file(&df, content).unwrap();
            }
            ztfs.flush_state().unwrap();
        }

        rekey(old_pw, new_pw, &dir, false);

        let ztfs = ZeroTrustFs::new(new_pw, dir.clone());
        let state = ztfs.inner.state.read().unwrap();
        for (name, expected) in &files_data {
            let ino = ZeroTrustFs::find_child(&state, 1, name).expect("file should exist");
            let df = state.inodes.get(&ino).unwrap().disk_filename.clone();
            let content = ztfs
                .read_encrypted_file(&df)
                .expect("failed to read encrypted file");
            assert_eq!(content, *expected, "mismatch for {name}");
        }

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn cleanup_stale_staging_test() {
        let dir = PathBuf::from("target/test-cleanup-stale");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();

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
    fn committed_rekey_refuses_unexpected_staging_artifacts() {
        let dir = PathBuf::from("target/test-rekey-staging-conflict");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(dir.join(STAGING)).unwrap();
        let conflict = dir.join(STAGING).join("000001 (conflicted copy).age");
        fs::write(&conflict, b"provider artifact").unwrap();

        let error = commit_manifest(&dir, &dir.join(STAGING), &[]).unwrap_err();
        assert!(error.contains("unexpected provider/interrupted artifact"));
        assert!(conflict.exists());
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn committed_rekey_cleanup_preserves_late_staging_artifact_and_manifest() {
        let dir = PathBuf::from("target/test-rekey-late-staging-conflict");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(dir.join(STAGING)).unwrap();
        fs::write(dir.join(STAGING).join("late-conflict"), b"evidence").unwrap();
        fs::write(dir.join(MANIFEST), b"manifest evidence").unwrap();
        fs::write(dir.join(LOCK), b"lock evidence").unwrap();

        assert!(cleanup_transaction(&dir).is_err());
        assert!(dir.join(STAGING).join("late-conflict").exists());
        assert!(dir.join(MANIFEST).exists());
        assert!(dir.join(LOCK).exists());
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn recover_interrupted_rekey_test() {
        let dir = PathBuf::from("target/test-recover-rekey");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();

        let staging_dir = dir.join(".rekey_staging");
        fs::create_dir_all(&staging_dir).unwrap();

        let key = derive_key_at(&dir, "new-passphrase");
        let renamed = encrypt_blob(&key, "000001.age", b"already-renamed-new").unwrap();
        let staged = encrypt_blob(&key, "000002.age", b"new-data").unwrap();
        let staged_index = encrypt_index(&key, b"new-index").unwrap();
        fs::write(dir.join("000001.age"), &renamed).unwrap();
        fs::write(staging_dir.join("000002.age"), &staged).unwrap();
        fs::write(staging_dir.join(INDEX_FILE), &staged_index).unwrap();

        // Legacy manifests had mutable `renamed` flags and no fingerprints.
        let manifest = vec![
            ManifestEntry {
                filename: "000001.age".to_string(),
                renamed: true,
                fingerprint: None,
            },
            ManifestEntry {
                filename: "000002.age".to_string(),
                renamed: false,
                fingerprint: None,
            },
            ManifestEntry {
                filename: INDEX_FILE.to_string(),
                renamed: false,
                fingerprint: None,
            },
        ];
        fs::write(
            dir.join("_rekey.manifest"),
            serde_json::to_vec(&manifest).unwrap(),
        )
        .unwrap();
        fs::write(dir.join(LOCK), local_lock_record_for_test(i32::MAX as u32)).unwrap();

        let recovered = recover_interrupted_rekey(&dir);
        assert!(recovered);

        assert_eq!(
            decrypt_blob(
                &key,
                "000001.age",
                &fs::read(dir.join("000001.age")).unwrap()
            )
            .unwrap(),
            b"already-renamed-new"
        );
        assert_eq!(
            decrypt_blob(
                &key,
                "000002.age",
                &fs::read(dir.join("000002.age")).unwrap()
            )
            .unwrap(),
            b"new-data"
        );
        assert_eq!(
            decrypt_index(&key, &fs::read(dir.join(INDEX_FILE)).unwrap()).unwrap(),
            b"new-index"
        );
        assert!(!dir.join("_rekey.manifest").exists());
        assert!(!dir.join("_rekey.lock").exists());
        assert!(!staging_dir.exists());

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn recovery_is_idempotent_after_rename_before_progress_update() {
        let dir = PathBuf::from("target/test-recover-rekey-idempotent");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(dir.join(STAGING)).unwrap();
        let key = derive_key_at(&dir, "new-passphrase");
        let blob = encrypt_blob(&key, "000001.age", b"new-data").unwrap();
        let index = encrypt_index(&key, b"new-index").unwrap();
        fs::write(dir.join("000001.age"), &blob).unwrap();
        fs::write(dir.join(STAGING).join(INDEX_FILE), &index).unwrap();
        let manifest = vec![
            ManifestEntry {
                filename: "000001.age".to_string(),
                renamed: false,
                fingerprint: Some(legacy_ciphertext_fingerprint(&dir.join("000001.age"))),
            },
            ManifestEntry {
                filename: INDEX_FILE.to_string(),
                renamed: false,
                fingerprint: Some(legacy_ciphertext_fingerprint(
                    &dir.join(STAGING).join(INDEX_FILE),
                )),
            },
        ];
        fs::write(dir.join(MANIFEST), serde_json::to_vec(&manifest).unwrap()).unwrap();
        fs::write(dir.join(LOCK), local_lock_record_for_test(i32::MAX as u32)).unwrap();

        assert_eq!(recover_interrupted_rekey_result(&dir), Ok(true));
        assert_eq!(
            decrypt_blob(
                &key,
                "000001.age",
                &fs::read(dir.join("000001.age")).unwrap()
            )
            .unwrap(),
            b"new-data"
        );
        assert_eq!(
            decrypt_index(&key, &fs::read(dir.join(INDEX_FILE)).unwrap()).unwrap(),
            b"new-index"
        );
        assert!(!dir.join(MANIFEST).exists());
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn legacy_renamed_entry_never_prefers_resurrected_staging_content() {
        let dir = PathBuf::from("target/test-rekey-renamed-stale-staging");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(dir.join(STAGING)).unwrap();
        let key = derive_key_at(&dir, "new-passphrase");
        let committed = encrypt_blob(&key, "000001.age", b"committed").unwrap();
        let resurrected = encrypt_blob(&key, "000001.age", b"stale-copy").unwrap();
        let index = encrypt_index(&key, b"new-index").unwrap();
        fs::write(dir.join("000001.age"), &committed).unwrap();
        fs::write(dir.join(STAGING).join("000001.age"), &resurrected).unwrap();
        fs::write(dir.join(STAGING).join(INDEX_FILE), &index).unwrap();
        let manifest = vec![
            ManifestEntry {
                filename: "000001.age".to_string(),
                renamed: true,
                fingerprint: None,
            },
            ManifestEntry {
                filename: INDEX_FILE.to_string(),
                renamed: false,
                fingerprint: None,
            },
        ];
        fs::write(dir.join(MANIFEST), serde_json::to_vec(&manifest).unwrap()).unwrap();
        fs::write(dir.join(LOCK), local_lock_record_for_test(i32::MAX as u32)).unwrap();

        let error = recover_interrupted_rekey_result(&dir).unwrap_err();
        assert!(!error.is_empty());
        assert_eq!(fs::read(dir.join("000001.age")).unwrap(), committed);
        assert!(dir.join(STAGING).join("000001.age").exists());
        assert!(dir.join(MANIFEST).exists());
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn recovery_accepts_fully_committed_manifest_after_staging_cleanup() {
        let dir = PathBuf::from("target/test-rekey-recover-after-staging-cleanup");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let key = derive_key_at(&dir, "new-passphrase");
        let blob = encrypt_blob(&key, "000001.age", b"committed").unwrap();
        let index = encrypt_index(&key, b"committed-index").unwrap();
        fs::write(dir.join("000001.age"), &blob).unwrap();
        fs::write(dir.join(INDEX_FILE), &index).unwrap();
        let manifest = vec![
            ManifestEntry {
                filename: "000001.age".to_string(),
                renamed: false,
                fingerprint: Some(ciphertext_bytes_fingerprint(&blob).unwrap()),
            },
            ManifestEntry {
                filename: INDEX_FILE.to_string(),
                renamed: false,
                fingerprint: Some(ciphertext_bytes_fingerprint(&index).unwrap()),
            },
        ];
        fs::write(dir.join(MANIFEST), serde_json::to_vec(&manifest).unwrap()).unwrap();
        fs::write(dir.join(LOCK), local_lock_record_for_test(i32::MAX as u32)).unwrap();

        assert_eq!(recover_interrupted_rekey_result(&dir), Ok(true));
        assert_eq!(fs::read(dir.join("000001.age")).unwrap(), blob);
        assert_eq!(fs::read(dir.join(INDEX_FILE)).unwrap(), index);
        assert!(!dir.join(MANIFEST).exists());
        assert!(!dir.join(LOCK).exists());
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn rekey_online_basic() {
        let dir = PathBuf::from("target/test-rekey-online");
        let _ = fs::remove_dir_all(&dir);
        let old_pw = "online-old";
        let new_pw = "online-new";

        let ztfs = ZeroTrustFs::new(old_pw, dir.clone());
        {
            let mut state = ztfs.inner.state.write().unwrap();
            let ino = ZeroTrustFs::allocate_inode(&mut state);
            let df = ZeroTrustFs::allocate_disk_filename(&mut state);
            state.inodes.insert(
                ino,
                InodeEntry {
                    name: "online.txt".to_string(),
                    kind: InodeKind::File,
                    disk_filename: df.clone(),
                    size: 12,
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
                name: "online.txt".to_string(),
                inode: ino,
            });
        }
        ztfs.write_encrypted_file("000001.age", b"online data!")
            .unwrap();
        ztfs.flush_state().unwrap();

        ztfs.inner
            .open_files
            .write()
            .unwrap()
            .insert(2, b"online data!".to_vec());

        assert!(!ztfs.inner.read_only.load(Ordering::Relaxed));

        rekey_online(old_pw, new_pw, &dir, &ztfs.inner, false);

        assert!(!ztfs.inner.read_only.load(Ordering::Relaxed));

        let expected_new_key = derive_key_at(&dir, new_pw);
        assert_eq!(*ztfs.inner.key.read().unwrap(), expected_new_key);

        let old_key = derive_key_at(&dir, old_pw);
        let index_ct = fs::read(dir.join("_index.age")).unwrap();
        assert!(decrypt_index(&old_key, &index_ct).is_err());

        let ztfs2 = ZeroTrustFs::new(new_pw, dir.clone());
        let state = ztfs2.inner.state.read().unwrap();
        let ino = ZeroTrustFs::find_child(&state, 1, "online.txt").expect("file should exist");
        let df = state.inodes.get(&ino).unwrap().disk_filename.clone();
        drop(state);
        let content = ztfs2
            .read_encrypted_file(&df)
            .expect("failed to read encrypted file");
        assert_eq!(content, b"online data!");

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
            let mut state = ztfs.inner.state.write().unwrap();
            let ino = ZeroTrustFs::allocate_inode(&mut state);
            let df = ZeroTrustFs::allocate_disk_filename(&mut state);
            state.inodes.insert(
                ino,
                InodeEntry {
                    name: "test.txt".to_string(),
                    kind: InodeKind::File,
                    disk_filename: df.clone(),
                    size: 4,
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
                name: "test.txt".to_string(),
                inode: ino,
            });
        }
        ztfs.write_encrypted_file("000001.age", b"test").unwrap();
        ztfs.flush_state().unwrap();

        ztfs.inner.read_only.store(true, Ordering::SeqCst);
        assert!(ztfs.inner.read_only.load(Ordering::Relaxed));

        rekey_online(old_pw, new_pw, &dir, &ztfs.inner, false);

        assert!(!ztfs.inner.read_only.load(Ordering::Relaxed));

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn online_preflight_failure_restores_cli_preset_read_write_state() {
        let dir = PathBuf::from("target/test-rekey-online-preflight-failure");
        let _ = fs::remove_dir_all(&dir);
        let ztfs = ZeroTrustFs::new("old-passphrase", dir.clone());

        let staging_dir = dir.join(STAGING);
        fs::create_dir_all(&staging_dir).unwrap();
        let unrelated_key = derive_key_at(&dir, "different-new-passphrase");
        let ciphertext = encrypt_blob(&unrelated_key, "000001.age", b"staged").unwrap();
        fs::write(staging_dir.join("000001.age"), ciphertext).unwrap();

        // main sets this before spawning the worker so writes cannot race the
        // thread startup. A safe pre-commit failure must undo that preset.
        ztfs.inner.read_only.store(true, Ordering::SeqCst);
        rekey_online(
            "old-passphrase",
            "requested-new-passphrase",
            &dir,
            &ztfs.inner,
            true,
        );

        assert!(!ztfs.inner.read_only.load(Ordering::SeqCst));
        assert!(!dir.join(MANIFEST).exists());
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn online_rekey_never_recreates_missing_kdf_metadata() {
        let dir = PathBuf::from("target/test-rekey-online-missing-kdf");
        let _ = fs::remove_dir_all(&dir);
        let ztfs = ZeroTrustFs::new("old-passphrase", dir.clone());
        let original_index = fs::read(dir.join(INDEX_FILE)).unwrap();
        fs::remove_file(dir.join("_kdf.json")).unwrap();

        ztfs.inner.read_only.store(true, Ordering::SeqCst);
        rekey_online("old-passphrase", "new-passphrase", &dir, &ztfs.inner, false);

        assert!(!dir.join("_kdf.json").exists());
        assert_eq!(fs::read(dir.join(INDEX_FILE)).unwrap(), original_index);
        assert!(!dir.join(LOCK).exists());
        assert!(!ztfs.inner.read_only.load(Ordering::SeqCst));
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn online_rekey_refuses_externally_changed_index() {
        let dir = PathBuf::from("target/test-rekey-online-index-conflict");
        let _ = fs::remove_dir_all(&dir);
        let old_pw = "old-passphrase";
        let ztfs = ZeroTrustFs::new(old_pw, dir.clone());
        let old_key = derive_key_at(&dir, old_pw);
        let external_index = encrypt_index(&old_key, b"external generation").unwrap();
        fs::write(dir.join(INDEX_FILE), &external_index).unwrap();

        ztfs.inner.read_only.store(true, Ordering::SeqCst);
        rekey_online(old_pw, "new-passphrase", &dir, &ztfs.inner, false);

        assert_eq!(fs::read(dir.join(INDEX_FILE)).unwrap(), external_index);
        assert_eq!(*ztfs.inner.key.read().unwrap(), old_key);
        assert!(!dir.join(MANIFEST).exists());
        assert!(
            ztfs.inner.read_only.load(Ordering::SeqCst),
            "a detected external generation must stay latched read-only until remount"
        );

        // Avoid a noisy conflict retry from Drop after the assertion target is
        // removed; no dirty state is pending.
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn online_rekey_materializes_valid_blobless_empty_file() {
        let dir = PathBuf::from("target/test-rekey-online-empty-file");
        let _ = fs::remove_dir_all(&dir);
        let old_pw = "empty-old";
        let new_pw = "empty-new";
        let ztfs = ZeroTrustFs::new(old_pw, dir.clone());
        {
            let mut state = ztfs.inner.state.write().unwrap();
            let ino = ZeroTrustFs::allocate_inode(&mut state);
            let disk_filename = ZeroTrustFs::allocate_disk_filename(&mut state);
            state.inodes.insert(
                ino,
                InodeEntry {
                    name: "empty.txt".to_string(),
                    kind: InodeKind::File,
                    disk_filename: disk_filename.clone(),
                    size: 0,
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
                name: "empty.txt".to_string(),
                inode: ino,
            });
        }
        ztfs.flush_state().unwrap();
        assert!(!dir.join("000001.age").exists());

        ztfs.inner.read_only.store(true, Ordering::SeqCst);
        rekey_online(old_pw, new_pw, &dir, &ztfs.inner, false);

        let reopened = ZeroTrustFs::new(new_pw, dir.clone());
        assert_eq!(reopened.read_encrypted_file("000001.age").unwrap(), b"");
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn online_staging_has_no_persistence_gate_dependency() {
        let dir = PathBuf::from("target/test-rekey-online-ungated-staging");
        let _ = fs::remove_dir_all(&dir);
        let ztfs = ZeroTrustFs::new("old-passphrase", dir.clone());
        ztfs.flush_state().unwrap();
        let snapshot = RekeySnapshot {
            old_key: derive_key_at(&dir, "old-passphrase"),
            new_key: derive_key_at(&dir, "new-passphrase"),
            index_json: serde_json::to_vec(&*ztfs.inner.state.read().unwrap()).unwrap(),
            disk_files: Vec::new(),
        };

        // Holding the gate while invoking the pure staging phase is safe
        // because that phase has no FsInner access and cannot recursively lock
        // persistence. The production wrapper drops this guard before staging.
        let gate = ztfs.inner.persistence_mutex.lock().unwrap();
        let manifest = stage_online_rekey(&dir, &snapshot, false).unwrap();
        assert_eq!(manifest.len(), 1);
        assert_eq!(manifest[0].filename, INDEX_FILE);
        assert!(dir.join(STAGING).join(INDEX_FILE).exists());
        drop(gate);

        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn resume_rekey_same_passphrase() {
        let dir = PathBuf::from("target/test-resume-same-pw");
        let _ = fs::remove_dir_all(&dir);
        let old_pw = "resume-old";
        let new_pw = "resume-new";

        let ztfs = ZeroTrustFs::new(old_pw, dir.clone());
        {
            let mut state = ztfs.inner.state.write().unwrap();
            for i in 1..=3 {
                let ino = ZeroTrustFs::allocate_inode(&mut state);
                let df = ZeroTrustFs::allocate_disk_filename(&mut state);
                state.inodes.insert(
                    ino,
                    InodeEntry {
                        name: format!("file{i}.txt"),
                        kind: InodeKind::File,
                        disk_filename: df.clone(),
                        size: 3,
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
                    name: format!("file{i}.txt"),
                    inode: ino,
                });
            }
        }
        ztfs.write_encrypted_file("000001.age", b"aaa").unwrap();
        ztfs.write_encrypted_file("000002.age", b"bbb").unwrap();
        ztfs.write_encrypted_file("000003.age", b"ccc").unwrap();
        ztfs.flush_state().unwrap();

        let staging_dir = dir.join(".rekey_staging");
        fs::create_dir_all(&staging_dir).unwrap();
        let new_key = derive_key_at(&dir, new_pw);
        let old_key = derive_key_at(&dir, old_pw);
        let ct = fs::read(dir.join("000001.age")).unwrap();
        let pt = decrypt_blob(&old_key, "000001.age", &ct).unwrap();
        let new_ct = encrypt_blob(&new_key, "000001.age", &pt).unwrap();
        fs::write(staging_dir.join("000001.age"), &new_ct).unwrap();
        fs::write(dir.join(LOCK), local_lock_record_for_test(i32::MAX as u32)).unwrap();

        assert!(verify_staged_passphrase(new_pw, &dir).is_ok());
        assert!(verify_staged_passphrase("wrong-pw", &dir).is_err());

        // Exercise the production online core, including stale-lock repair.
        rekey_online(old_pw, new_pw, &dir, &ztfs.inner, true);

        let ztfs2 = ZeroTrustFs::new(new_pw, dir.clone());
        let state = ztfs2.inner.state.read().unwrap();
        for filename in &["000001.age", "000002.age", "000003.age"] {
            let content = ztfs2
                .read_encrypted_file(filename)
                .expect("failed to read encrypted file");
            assert!(
                !content.is_empty(),
                "{filename} should be readable with new key"
            );
        }
        drop(state);

        let old_key = derive_key_at(&dir, old_pw);
        let index_ct = fs::read(dir.join("_index.age")).unwrap();
        assert!(decrypt_index(&old_key, &index_ct).is_err());

        assert!(!dir.join(".rekey_staging").exists());
        assert!(!dir.join("_rekey.manifest").exists());
        assert!(!dir.join("_rekey.lock").exists());

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn resume_rekey_wrong_passphrase() {
        let dir = PathBuf::from("target/test-resume-wrong-pw");
        let _ = fs::remove_dir_all(&dir);

        let staging_dir = dir.join(".rekey_staging");
        fs::create_dir_all(&staging_dir).unwrap();
        let key_a = derive_key_at(&dir, "passphrase-a");
        let ct = encrypt_blob(&key_a, "000001.age", b"some data").unwrap();
        fs::write(staging_dir.join("000001.age"), ct).unwrap();

        assert!(verify_staged_passphrase("passphrase-a", &dir).is_ok());

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

        let ztfs = ZeroTrustFs::new(old_pw, dir.clone());
        {
            let mut state = ztfs.inner.state.write().unwrap();
            let ino = ZeroTrustFs::allocate_inode(&mut state);
            let df = ZeroTrustFs::allocate_disk_filename(&mut state);
            state.inodes.insert(
                ino,
                InodeEntry {
                    name: "file.txt".to_string(),
                    kind: InodeKind::File,
                    disk_filename: df.clone(),
                    size: 4,
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
                name: "file.txt".to_string(),
                inode: ino,
            });
        }
        ztfs.write_encrypted_file("000001.age", b"data").unwrap();
        ztfs.flush_state().unwrap();

        let staging_dir = dir.join(".rekey_staging");
        fs::create_dir_all(&staging_dir).unwrap();
        let different_key = derive_key_at(&dir, "some-other-passphrase");
        let stale_ct = encrypt_blob(&different_key, "000001.age", b"stale").unwrap();
        fs::write(staging_dir.join("000001.age"), &stale_ct).unwrap();

        rekey(old_pw, new_pw, &dir, false);

        let ztfs2 = ZeroTrustFs::new(new_pw, dir.clone());
        let content = ztfs2
            .read_encrypted_file("000001.age")
            .expect("failed to read encrypted file");
        assert_eq!(content, b"data");

        assert!(!dir.join(".rekey_staging").exists());

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn stale_lock_is_replaced_but_live_lock_is_preserved() {
        let dir = PathBuf::from("target/test-rekey-lock-repair");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let lock = dir.join(LOCK);

        fs::write(&lock, local_lock_record_for_test(i32::MAX as u32)).unwrap();
        acquire_rekey_lock(&dir).unwrap();
        assert_eq!(
            fs::read(&lock).unwrap(),
            local_lock_record_for_test(std::process::id())
        );
        remove_file_if_exists(&lock).unwrap();

        fs::write(&lock, local_lock_record_for_test(std::process::id())).unwrap();
        assert!(
            acquire_rekey_lock(&dir)
                .unwrap_err()
                .contains("still running")
        );
        assert_eq!(
            fs::read(&lock).unwrap(),
            local_lock_record_for_test(std::process::id())
        );
        fs::create_dir_all(dir.join(STAGING)).unwrap();
        fs::write(dir.join(STAGING).join("000001.age"), b"active staging").unwrap();
        assert!(cleanup_stale_staging_result(&dir).is_err());
        assert!(
            dir.join(STAGING).join("000001.age").exists(),
            "a live owner's staging must never be deleted"
        );
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn recovery_rejects_malformed_or_unsafe_manifests_without_cleanup() {
        let cases = [
            vec!["../escape.age", INDEX_FILE],
            vec!["000001.age", "000001.age", INDEX_FILE],
            vec![INDEX_FILE, "000001.age"],
            vec!["00000A.age", INDEX_FILE],
            vec!["_kdf.json", INDEX_FILE],
        ];

        for (i, filenames) in cases.into_iter().enumerate() {
            let dir = PathBuf::from(format!("target/test-rekey-unsafe-{i}"));
            let _ = fs::remove_dir_all(&dir);
            fs::create_dir_all(dir.join(STAGING)).unwrap();
            let manifest: Vec<_> = filenames
                .into_iter()
                .map(|filename| ManifestEntry {
                    filename: filename.to_string(),
                    renamed: false,
                    fingerprint: None,
                })
                .collect();
            fs::write(dir.join(MANIFEST), serde_json::to_vec(&manifest).unwrap()).unwrap();
            let sentinel = dir
                .parent()
                .unwrap()
                .join(format!("rekey-escape-sentinel-{i}"));
            fs::write(&sentinel, b"safe").unwrap();

            assert!(recover_interrupted_rekey_result(&dir).is_err());
            assert_eq!(fs::read(&sentinel).unwrap(), b"safe");
            assert!(
                dir.join(MANIFEST).exists(),
                "invalid transaction evidence must be preserved"
            );

            let _ = fs::remove_file(sentinel);
            let _ = fs::remove_dir_all(dir);
        }

        let dir = PathBuf::from("target/test-rekey-invalid-json");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join(MANIFEST), b"not-json").unwrap();
        assert!(recover_interrupted_rekey_result(&dir).is_err());
        assert!(dir.join(MANIFEST).exists());
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn recovery_manifest_entry_limit_is_bounded_below_byte_limit() {
        // Ciphertext entries contain only a canonical filename, fixed-size
        // byte arrays, and scalar fields. 512 bytes per entry is a
        // conservative serialized upper bound.
        assert!((MAX_MANIFEST_ENTRIES as u64) * 512 < MAX_MANIFEST_FILE_LEN);
        let entry = ManifestEntry {
            filename: INDEX_FILE.to_string(),
            renamed: false,
            fingerprint: None,
        };
        let oversized = vec![entry; MAX_MANIFEST_ENTRIES + 1];
        assert!(validate_manifest(&oversized).is_err());
    }

    #[test]
    fn rekey_recovery_fails_on_missing_staged_file() {
        let dir = PathBuf::from("target/test-recover-missing");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();

        let staging_dir = dir.join(".rekey_staging");
        fs::create_dir_all(&staging_dir).unwrap();

        let key = derive_key_at(&dir, "new-passphrase");
        let renamed = encrypt_blob(&key, "000001.age", b"renamed-new").unwrap();
        let staged = encrypt_blob(&key, "000002.age", b"new-data").unwrap();
        let expected_missing_index = encrypt_index(&key, b"missing-index").unwrap();
        fs::write(dir.join("000001.age"), &renamed).unwrap();
        fs::write(staging_dir.join("000002.age"), &staged).unwrap();

        let manifest = vec![
            ManifestEntry {
                filename: "000001.age".to_string(),
                renamed: false,
                fingerprint: Some(ciphertext_fingerprint(&dir.join("000001.age")).unwrap()),
            },
            ManifestEntry {
                filename: "000002.age".to_string(),
                renamed: false,
                fingerprint: Some(ciphertext_fingerprint(&staging_dir.join("000002.age")).unwrap()),
            },
            ManifestEntry {
                filename: INDEX_FILE.to_string(),
                renamed: false,
                fingerprint: Some(ciphertext_bytes_fingerprint(&expected_missing_index).unwrap()),
            },
        ];
        fs::write(
            dir.join("_rekey.manifest"),
            serde_json::to_vec(&manifest).unwrap(),
        )
        .unwrap();
        fs::write(dir.join(LOCK), local_lock_record_for_test(i32::MAX as u32)).unwrap();

        let recovered = recover_interrupted_rekey(&dir);
        assert!(
            !recovered,
            "recovery should fail when a staged file is missing"
        );

        // 000002.age should have been renamed (it was available)
        assert_eq!(
            decrypt_blob(
                &key,
                "000002.age",
                &fs::read(dir.join("000002.age")).unwrap()
            )
            .unwrap(),
            b"new-data"
        );

        // Manifest and lock should be preserved for investigation
        assert!(
            dir.join("_rekey.manifest").exists(),
            "manifest should be kept for investigation"
        );
        assert!(dir.join("_rekey.lock").exists(), "lock should be kept");

        let _ = fs::remove_dir_all(&dir);
    }
}
