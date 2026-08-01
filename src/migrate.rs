// Copyright 2026 Alexander Orlov <alexander.orlov@loxal.net>

//! One-time on-disk format migration: v0 (pre-0.7) → v1 (0.7+).
//!
//! v0 = homemade KDF + ChaCha20-Poly1305 (12-byte nonce), no salt file.
//! v1 = Argon2id + per-drive salt (`_kdf.json`) + XChaCha20-Poly1305
//! (24-byte nonce). See `crypto.rs` for the rationale.
//!
//! The migration re-encrypts every blob and the index under the new
//! key/cipher. It is crash-safe via the same staged-write + manifest
//! commit pattern as `rekey.rs`:
//!
//! 1. Re-encrypted files (incl. the new `_kdf.json`) are written into
//!    `.migrate_staging/`. Originals are untouched.
//! 2. `_migrate.manifest` is written (the commit point).
//! 3. A rename pass swaps each staged file over its original, with
//!    `_kdf.json` renamed LAST — its presence is the "fully migrated"
//!    marker.
//!
//! Interrupted before the manifest → staging discarded, v0 intact.
//! Interrupted during the rename pass → `recover_interrupted_migration`
//! completes it. Because `_kdf.json` is renamed last, a half-renamed
//! drive is always detectable (manifest present) and recoverable.

use serde::{Deserialize, Serialize};
use std::collections::HashSet;

use crate::crypto::{
    KdfParams, RecoveryFingerprint, ciphertext_fingerprint, ciphertext_fingerprint_bounded,
    ciphertext_fingerprint_expected, decrypt_bytes_legacy, derive_key_legacy,
    derive_key_legacy_tagged, encrypt_blob_owned, encrypt_index, exact_fingerprint, load_kdf,
    try_derive_key,
};
use crate::fs::{
    DiskIndex, InodeKind, backing_entry_exists, durable_create_new, durable_write,
    ensure_index_plaintext_within_limit, ensure_no_index_siblings, ensure_real_directory,
    read_bounded_backing_file, read_index_ciphertext, read_legacy_blob_ciphertext,
    validate_disk_index,
};
use crate::transaction_lock::{lock_owner_is_active, prepare_lock_owner, write_lock_owner};

const STAGING: &str = ".migrate_staging";
const MANIFEST: &str = "_migrate.manifest";
const LOCK: &str = "_migrate.lock";
const KDF_FILE: &str = "_kdf.json";
const INDEX_FILE: &str = "_index.age";
const MAX_MANIFEST_FILE_LEN: u64 = 64 * 1024 * 1024;
const MAX_INDEX_CIPHERTEXT_LEN: u64 = 64 * 1024 * 1024;
const MAX_MANIFEST_ENTRIES: usize = 100_000;

#[derive(PartialEq, Eq)]
struct LegacyIndexFingerprint {
    len: u64,
    nonce: [u8; 12],
    tag: [u8; 16],
}

fn legacy_index_fingerprint(bytes: &[u8]) -> Result<LegacyIndexFingerprint, String> {
    if bytes.len() < 28 {
        return Err("legacy encrypted index is too short".to_string());
    }
    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(&bytes[..12]);
    let mut tag = [0u8; 16];
    tag.copy_from_slice(&bytes[bytes.len() - 16..]);
    Ok(LegacyIndexFingerprint {
        len: bytes.len() as u64,
        nonce,
        tag,
    })
}

#[derive(Serialize, Deserialize, Clone, Debug)]
struct ManifestEntry {
    filename: String,
    renamed: bool,
    /// Added after the original manifest format shipped. `None` keeps old
    /// interrupted manifests readable; recovery upgrades them before renaming.
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
                "legacy index contains invalid generated filename {:?}",
                blob.filename
            ));
        }
        if !seen.insert(blob.filename.as_str()) {
            return Err(format!(
                "legacy index contains duplicate generated filename {}",
                blob.filename
            ));
        }
    }
    Ok(())
}

fn validate_manifest(entries: &[ManifestEntry]) -> Result<(), String> {
    if entries.len() > MAX_MANIFEST_ENTRIES {
        return Err(format!(
            "migration manifest has {} entries; maximum is {MAX_MANIFEST_ENTRIES}",
            entries.len()
        ));
    }
    if entries.len() < 2 {
        return Err("migration manifest must end with _index.age and _kdf.json".to_string());
    }
    if entries[entries.len() - 2].filename != INDEX_FILE
        || entries[entries.len() - 1].filename != KDF_FILE
    {
        return Err("migration manifest has invalid commit order".to_string());
    }

    let mut seen = HashSet::with_capacity(entries.len());
    for (i, entry) in entries.iter().enumerate() {
        if !seen.insert(entry.filename.as_str()) {
            return Err(format!(
                "migration manifest contains duplicate {}",
                entry.filename
            ));
        }
        let is_index = i == entries.len() - 2;
        let is_kdf = i == entries.len() - 1;
        if !is_index && !is_kdf && !generated_blob_filename(&entry.filename) {
            return Err(format!(
                "migration manifest contains invalid blob filename {:?}",
                entry.filename
            ));
        }
        if let Some(fingerprint) = &entry.fingerprint
            && (!fingerprint.is_well_formed()
                || (is_kdf && !fingerprint.is_exact())
                || (!is_kdf && !fingerprint.is_ciphertext()))
        {
            return Err(format!(
                "migration manifest has invalid fingerprint for {}",
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
            return Err("migration manifest index exceeds the live index-size limit".to_string());
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

fn fingerprint_for(filename: &str, path: &std::path::Path) -> Result<RecoveryFingerprint, String> {
    if filename == KDF_FILE {
        exact_fingerprint(path)
    } else {
        ciphertext_fingerprint(path)
    }
}

fn fingerprint_for_expected(
    filename: &str,
    path: &std::path::Path,
    expected: &RecoveryFingerprint,
) -> Result<RecoveryFingerprint, String> {
    if filename == KDF_FILE {
        exact_fingerprint(path)
    } else {
        let expected_len = expected.ciphertext_len().ok_or_else(|| {
            format!("migration entry {filename} has a non-ciphertext fingerprint")
        })?;
        ciphertext_fingerprint_expected(path, expected_len)
    }
}

fn write_manifest(path: &std::path::Path, entries: &[ManifestEntry]) -> Result<(), String> {
    validate_manifest(entries)?;
    let json =
        serde_json::to_vec(entries).map_err(|e| format!("serialize migration manifest: {e}"))?;
    if json.len() as u64 > MAX_MANIFEST_FILE_LEN {
        return Err(format!(
            "migration manifest is too large ({} bytes; maximum {MAX_MANIFEST_FILE_LEN})",
            json.len()
        ));
    }
    durable_write_checked(path, &json)
}

fn create_manifest(path: &std::path::Path, entries: &[ManifestEntry]) -> Result<(), String> {
    validate_manifest(entries)?;
    let json =
        serde_json::to_vec(entries).map_err(|e| format!("serialize migration manifest: {e}"))?;
    if json.len() as u64 > MAX_MANIFEST_FILE_LEN {
        return Err(format!(
            "migration manifest is too large ({} bytes; maximum {MAX_MANIFEST_FILE_LEN})",
            json.len()
        ));
    }
    durable_create_new(path, &json).map_err(|error| {
        format!(
            "publish new migration manifest {} without replacement: {error}",
            path.display()
        )
    })
}

fn read_manifest(path: &std::path::Path) -> Result<Vec<ManifestEntry>, String> {
    let json = read_bounded_backing_file(path, MAX_MANIFEST_FILE_LEN)
        .map_err(|e| format!("read {}: {e}", path.display()))?;
    let entries: Vec<ManifestEntry> =
        serde_json::from_slice(&json).map_err(|e| format!("parse migration manifest: {e}"))?;
    validate_manifest(&entries)?;
    Ok(entries)
}

fn upgrade_manifest_fingerprints(
    base_path: &std::path::Path,
    staging: &std::path::Path,
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
        let staged = staging.join(&entry.filename);
        let source = if entry.renamed {
            base_path.join(&entry.filename)
        } else if backing_entry_exists(&staged)
            .map_err(|e| format!("check {}: {e}", staged.display()))?
        {
            staged
        } else if entry.fingerprint.is_some() {
            // Fingerprint-backed manifests are immutable. A matching target
            // can prove a rename that completed immediately before a crash.
            base_path.join(&entry.filename)
        } else {
            return Err(format!(
                "cannot safely recover legacy manifest entry {}: staged file is missing and completion was not recorded",
                entry.filename
            ));
        };
        let upgraded = match &entry.fingerprint {
            Some(existing) => fingerprint_for_expected(&entry.filename, &source, existing)?,
            None if entry.filename == INDEX_FILE => {
                ciphertext_fingerprint_bounded(&source, MAX_INDEX_CIPHERTEXT_LEN)?
            }
            None => fingerprint_for(&entry.filename, &source)?,
        };
        if let Some(existing) = &entry.fingerprint
            && !existing.has_same_legacy_identity(&upgraded)
        {
            return Err(format!(
                "cannot upgrade migration manifest fingerprint for {} because the staged/target identity changed",
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
    staging: &std::path::Path,
    entries: &[ManifestEntry],
) -> Result<(), String> {
    if !backing_entry_exists(staging).map_err(|e| format!("check {}: {e}", staging.display()))? {
        return Ok(());
    }
    ensure_real_directory(staging).map_err(|e| e.to_string())?;
    let allowed: HashSet<&str> = entries
        .iter()
        .map(|entry| entry.filename.as_str())
        .collect();
    for entry in std::fs::read_dir(staging)
        .map_err(|e| format!("read staging directory {}: {e}", staging.display()))?
    {
        let entry = entry.map_err(|e| format!("read staging entry: {e}"))?;
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            return Err(format!(
                "migration staging {} contains a non-UTF-8 entry; preserving it for reconciliation",
                staging.display()
            ));
        };
        if !allowed.contains(name) {
            return Err(format!(
                "migration staging {} contains unexpected provider/interrupted artifact {name:?}; preserving all recovery evidence",
                staging.display()
            ));
        }
    }
    Ok(())
}

fn commit_manifest(
    base_path: &std::path::Path,
    staging: &std::path::Path,
    entries: &[ManifestEntry],
) -> Result<(), String> {
    if backing_entry_exists(staging).map_err(|e| format!("check {}: {e}", staging.display()))? {
        ensure_real_directory(staging).map_err(|e| e.to_string())?;
    }
    ensure_staging_unambiguous(staging, entries)?;
    for entry in entries {
        let expected = entry.fingerprint.as_ref().ok_or_else(|| {
            format!(
                "migration manifest entry {} has no fingerprint",
                entry.filename
            )
        })?;
        if !expected.has_full_content_identity() {
            return Err(format!(
                "migration manifest entry {} has no full-content fingerprint",
                entry.filename
            ));
        }
        let staged = staging.join(&entry.filename);
        let original = base_path.join(&entry.filename);
        if backing_entry_exists(&staged).map_err(|e| format!("check {}: {e}", staged.display()))? {
            let actual = fingerprint_for_expected(&entry.filename, &staged, expected)?;
            if &actual != expected {
                return Err(format!(
                    "staged {} does not match its migration manifest",
                    entry.filename
                ));
            }
            std::fs::rename(&staged, &original)
                .map_err(|e| format!("rename staging/{}: {e}", entry.filename))?;
            // The rename crosses the staging/base directory boundary. Sync both
            // sides before treating the fingerprint-backed transition as durable.
            sync_dir(staging)?;
            sync_dir(base_path)?;
        } else {
            let actual = fingerprint_for_expected(&entry.filename, &original, expected).map_err(|e| {
                format!(
                    "migration entry {} is missing from staging and target does not verify: {e}",
                    entry.filename
                )
            })?;
            if &actual != expected {
                return Err(format!(
                    "migration entry {} is missing from staging and target fingerprint does not match",
                    entry.filename
                ));
            }
        }
    }
    Ok(())
}

fn cleanup_transaction(base_path: &std::path::Path) -> Result<(), String> {
    // A nonempty directory at this point contains an unexpected artifact that
    // appeared after the commit pre-scan. Preserve it and the manifest.
    remove_empty_dir_if_exists(&base_path.join(STAGING))?;
    remove_file_if_exists(&base_path.join(LOCK))?;
    // Manifest is removed last. If cleanup is interrupted before this point,
    // fingerprint recovery remains able to verify the fully committed target.
    remove_file_if_exists(&base_path.join(MANIFEST))?;
    sync_dir(base_path)
}

/// Returns `Ok(true)` iff `base_path` holds a pre-0.7 drive that needs
/// migration: an `_index.age` exists but no `_kdf.json`. A present but invalid
/// KDF file is an error, never treated as absence. Callers should run
/// [`recover_interrupted_migration`] first so a half-finished
/// migration (manifest present, `_kdf.json` not yet renamed) is
/// completed rather than misclassified.
pub fn needs_migration(base_path: &std::path::Path) -> Result<bool, String> {
    let index_path = base_path.join(INDEX_FILE);
    if !backing_entry_exists(&index_path)
        .map_err(|e| format!("check {}: {e}", index_path.display()))?
    {
        return Ok(false);
    }
    Ok(load_kdf(base_path)?.is_none())
}

/// Complete an interrupted format migration by finishing the rename
/// pass from the manifest. Returns `true` if recovery ran. Mirrors
/// `rekey::recover_interrupted_rekey`.
#[cfg(test)]
pub fn recover_interrupted_migration(base_path: &std::path::Path) -> bool {
    match recover_interrupted_migration_result(base_path) {
        Ok(recovered) => recovered,
        Err(e) => {
            eprintln!("zerotrust-drive: ERROR: migration recovery failed: {e}");
            false
        }
    }
}

pub(crate) fn recover_interrupted_migration_result(
    base_path: &std::path::Path,
) -> Result<bool, String> {
    ensure_no_index_siblings(base_path).map_err(|e| {
        format!("refuse migration recovery while control metadata is ambiguous: {e}")
    })?;
    let manifest_path = base_path.join(MANIFEST);
    if !backing_entry_exists(&manifest_path)
        .map_err(|e| format!("check {}: {e}", manifest_path.display()))?
    {
        // No manifest means the commit point was not crossed. Refuse to touch
        // a live owner's state, otherwise clear both possible pre-commit crash
        // artifacts (the lock can exist before staging is created).
        let staging = base_path.join(STAGING);
        let lock_path = base_path.join(LOCK);
        let staging_exists = backing_entry_exists(&staging)
            .map_err(|e| format!("check {}: {e}", staging.display()))?;
        let lock_exists = backing_entry_exists(&lock_path)
            .map_err(|e| format!("check {}: {e}", lock_path.display()))?;
        if lock_exists && lock_owner_is_active(&lock_path, "migration")? {
            return Err(format!(
                "refusing to clean migration state owned by a live process ({})",
                lock_path.display()
            ));
        }
        if staging_exists {
            eprintln!("zerotrust-drive: removing stale migration staging directory");
            remove_dir_if_exists(&staging)?;
        }
        if lock_exists {
            eprintln!(
                "zerotrust-drive: removing stale migration lock {}",
                lock_path.display()
            );
            remove_file_if_exists(&lock_path)?;
        }
        if staging_exists || lock_exists {
            sync_dir(base_path)?;
        }
        return Ok(false);
    }
    let lock_path = base_path.join(LOCK);
    if lock_owner_is_active(&lock_path, "migration")? {
        return Err(format!(
            "refusing to recover migration owned by a live process ({})",
            lock_path.display()
        ));
    }
    eprintln!("zerotrust-drive: detected interrupted format migration — completing...");
    let mut entries = read_manifest(&manifest_path)?;
    let staging = base_path.join(STAGING);
    upgrade_manifest_fingerprints(base_path, &staging, &manifest_path, &mut entries)?;
    commit_manifest(base_path, &staging, &entries)?;
    cleanup_transaction(base_path)?;
    eprintln!("zerotrust-drive: interrupted format migration completed successfully");
    Ok(true)
}

/// Migrate a v0 drive at `base_path` to v1, in place and crash-safe.
/// Uses the supplied passphrase for both the v0 read key (legacy KDF)
/// and the v1 write key (Argon2id with a freshly generated salt).
///
/// Returns `Err` (leaving the drive untouched) if the passphrase does
/// not decrypt the existing v0 index.
pub fn migrate_v0_to_v1(passphrase: &str, base_path: &std::path::Path) -> Result<(), String> {
    // Finish any prior interrupted migration before starting fresh.
    recover_interrupted_migration_result(base_path)?;
    if !needs_migration(base_path)? {
        return Ok(()); // already v1 (or recovery just finished it)
    }

    // Lock out concurrent mounts/migrations.
    let lock_path = base_path.join(LOCK);
    let lock_record = prepare_lock_owner("migration")?;
    {
        let mut lock_file = std::fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&lock_path)
            .map_err(|_| {
                format!(
                    "lock file exists at {} — another migration/rekey may be in progress",
                    lock_path.display()
                )
            })?;
        if let Err(error) = write_lock_owner(&mut lock_file, &lock_record, &lock_path, "migration")
        {
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
            .map_err(|e| format!("sync migration lock {}: {e}", lock_path.display()))?;
        sync_dir(base_path)?;
    }

    let result = migrate_inner(passphrase, base_path);
    if let Err(original_error) = &result
        && !backing_entry_exists(&base_path.join(MANIFEST))
            .map_err(|e| format!("check migration manifest after failure: {e}"))?
    {
        // Staging never reached the manifest commit point, so the v0
        // originals are intact; just clear our lock + staging.
        let cleanup = remove_dir_if_exists(&base_path.join(STAGING))
            .and_then(|()| remove_file_if_exists(&lock_path))
            .and_then(|()| sync_dir(base_path));
        if let Err(cleanup_error) = cleanup {
            return Err(format!(
                "{}; additionally failed to clean pre-commit migration state: {cleanup_error}",
                original_error
            ));
        }
    }
    result
}

fn decrypt_v0_index(
    passphrase: &str,
    index_ct: &[u8],
) -> Result<([u8; 32], Vec<u8>, DiskIndex), String> {
    let candidates = [
        ("hardened 0.6.1", derive_key_legacy(passphrase)),
        (
            "tagged 0.6.0/early 0.6.1",
            derive_key_legacy_tagged(passphrase),
        ),
    ];
    for (variant, key) in candidates {
        let Ok(index_json) = decrypt_bytes_legacy(&key, index_ct) else {
            continue;
        };
        let index: DiskIndex = serde_json::from_slice(&index_json)
            .map_err(|e| format!("authenticated {variant} index is invalid JSON: {e}"))?;
        validate_disk_index(&index).map_err(|error| {
            format!("authenticated {variant} index is structurally invalid: {error}")
        })?;
        eprintln!("zerotrust-drive: detected {variant} legacy key format");
        return Ok((key, index_json, index));
    }
    Err(
        "failed to decrypt _index.age with either historical v0 key derivation - wrong passphrase?"
            .to_string(),
    )
}

fn migrate_inner(passphrase: &str, base_path: &std::path::Path) -> Result<(), String> {
    // 1. Read + decrypt the v0 index with the legacy key.
    let index_path = base_path.join(INDEX_FILE);
    let index_ct =
        read_index_ciphertext(&index_path).map_err(|e| format!("read {INDEX_FILE}: {e}"))?;
    let expected_index_fingerprint = legacy_index_fingerprint(&index_ct)?;
    let (old_key, index_json, index) = decrypt_v0_index(passphrase, &index_ct)?;

    // 2. New v1 key material.
    let new_kdf = KdfParams::new_random();
    let new_key = try_derive_key(passphrase, &new_kdf)?;

    let mut disk_files: Vec<IndexedBlob> = index
        .inodes
        .values()
        .filter(|e| e.kind == InodeKind::File && !e.disk_filename.is_empty())
        .map(|entry| IndexedBlob {
            filename: entry.disk_filename.clone(),
            size: entry.size,
        })
        .collect();
    disk_files.sort_by(|a, b| a.filename.cmp(&b.filename));
    validate_disk_files(&disk_files)?;

    let staging = base_path.join(STAGING);
    std::fs::create_dir_all(&staging).map_err(|e| format!("create staging: {e}"))?;
    ensure_real_directory(&staging).map_err(|e| e.to_string())?;

    let total = disk_files.len() + 2; // + index + kdf
    eprintln!(
        "zerotrust-drive: migrating {} file(s) + index to v1 (Argon2id + XChaCha20-Poly1305)...",
        disk_files.len()
    );

    // 3. Stage every blob: legacy-decrypt → v1-encrypt.
    let mut staged_blob_fingerprints = Vec::with_capacity(disk_files.len());
    for (i, blob) in disk_files.iter().enumerate() {
        let filename = &blob.filename;
        let ct = match read_legacy_blob_ciphertext(&base_path.join(filename), blob.size) {
            Ok(ct) => Some(ct),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound && blob.size == 0 => None,
            Err(e) => return Err(format!("read {filename}: {e}")),
        };
        let pt = match ct {
            Some(ct) => decrypt_bytes_legacy(&old_key, &ct)
                .map_err(|_| format!("failed to decrypt {filename} — data may be corrupted"))?,
            None => Vec::new(),
        };
        let new_ct = encrypt_blob_owned(&new_key, filename, pt)?;
        durable_write_checked(&staging.join(filename), &new_ct)?;
        staged_blob_fingerprints.push((
            filename.clone(),
            crate::crypto::ciphertext_bytes_fingerprint(&new_ct)?,
        ));
        eprintln!(
            "zerotrust-drive: [{}/{}] migrated {}",
            i + 1,
            total,
            filename
        );
    }

    // 4. Stage the index (v1-encrypted) and the new _kdf.json (plaintext).
    // v1 adds 12 more bytes of nonce overhead than v0. Reject a legacy index
    // at that narrow boundary instead of producing a store the next mount
    // would refuse as oversized.
    ensure_index_plaintext_within_limit(index_json.len())
        .map_err(|e| format!("legacy index cannot be migrated safely: {e}"))?;
    let new_index_ct = encrypt_index(&new_key, &index_json)?;
    durable_write_checked(&staging.join(INDEX_FILE), &new_index_ct)?;
    eprintln!(
        "zerotrust-drive: [{}/{}] migrated {INDEX_FILE}",
        total - 1,
        total
    );

    let kdf_json = serde_json::to_vec_pretty(&new_kdf).map_err(|e| e.to_string())?;
    durable_write_checked(&staging.join(KDF_FILE), &kdf_json)?;
    eprintln!("zerotrust-drive: [{total}/{total}] wrote {KDF_FILE}");

    // 5. Manifest (commit point). Order matters: blobs, then index,
    //    then _kdf.json LAST — its rename is the true completion marker.
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
            &staging.join(INDEX_FILE),
            MAX_INDEX_CIPHERTEXT_LEN,
        )?),
    });
    manifest.push(ManifestEntry {
        filename: KDF_FILE.to_string(),
        renamed: false,
        fingerprint: Some(exact_fingerprint(&staging.join(KDF_FILE))?),
    });
    validate_manifest(&manifest)?;
    ensure_no_index_siblings(base_path).map_err(|e| format!("refuse migration commit: {e}"))?;
    let current_index =
        read_index_ciphertext(&index_path).map_err(|e| format!("re-read {INDEX_FILE}: {e}"))?;
    if legacy_index_fingerprint(&current_index)? != expected_index_fingerprint {
        return Err(
            "encrypted index changed during migration staging; refusing to commit".to_string(),
        );
    }
    match std::fs::symlink_metadata(base_path.join(KDF_FILE)) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => {
            return Err(format!(
                "cannot verify that {KDF_FILE} is still absent before migration commit: {e}"
            ));
        }
        Ok(_) => {
            return Err(format!(
                "{KDF_FILE} appeared during migration staging; refusing to overwrite it"
            ));
        }
    }
    let manifest_path = base_path.join(MANIFEST);
    create_manifest(&manifest_path, &manifest)?;

    // 6. Fingerprint-backed rename pass. The immutable manifest lets
    // recovery infer completed renames without an O(N^2) progress rewrite.
    commit_manifest(base_path, &staging, &manifest)?;

    // 7. Cleanup.
    cleanup_transaction(base_path)?;

    eprintln!(
        "zerotrust-drive: format migration complete — drive is now v1 (Argon2id + XChaCha20-Poly1305)"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{decrypt_index, derive_key_at};
    use crate::fs::{DirChild, InodeEntry, ZeroTrustFs};
    use crate::transaction_lock::local_lock_record_for_test;
    use std::collections::HashMap;
    use std::path::PathBuf;

    #[derive(Clone, Copy, Debug)]
    enum LegacyKdf {
        Tagged,
        Hardened,
    }

    /// Hand-build a v0 drive: legacy KDF + ChaCha20/12-byte blobs +
    /// index, NO `_kdf.json`.
    fn make_v0_drive_with_kdf(
        dir: &std::path::Path,
        pw: &str,
        files: &[(&str, &[u8])],
        legacy_kdf: LegacyKdf,
    ) {
        use chacha20poly1305::{
            ChaCha20Poly1305, Nonce,
            aead::{Aead, KeyInit, OsRng, rand_core::RngCore},
        };
        let _ = std::fs::remove_dir_all(dir);
        std::fs::create_dir_all(dir).unwrap();
        let key = match legacy_kdf {
            LegacyKdf::Tagged => derive_key_legacy_tagged(pw),
            LegacyKdf::Hardened => derive_key_legacy(pw),
        };

        let v0_encrypt = |pt: &[u8]| -> Vec<u8> {
            let cipher = ChaCha20Poly1305::new((&key).into());
            let mut nb = [0u8; 12];
            OsRng.fill_bytes(&mut nb);
            let ct = cipher.encrypt(Nonce::from_slice(&nb), pt).unwrap();
            let mut out = nb.to_vec();
            out.extend_from_slice(&ct);
            out
        };

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
        let mut children: HashMap<u64, Vec<DirChild>> = HashMap::new();
        children.insert(1, Vec::new());
        let mut next_inode = 2u64;
        let mut next_file_id = 1u64;
        for (name, content) in files {
            let ino = next_inode;
            next_inode += 1;
            let df = format!("{next_file_id:06x}.age");
            next_file_id += 1;
            std::fs::write(dir.join(&df), v0_encrypt(content)).unwrap();
            inodes.insert(
                ino,
                InodeEntry {
                    name: name.to_string(),
                    kind: InodeKind::File,
                    disk_filename: df,
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
            children.get_mut(&1).unwrap().push(DirChild {
                name: name.to_string(),
                inode: ino,
            });
        }
        let index = DiskIndex {
            next_inode,
            next_file_id,
            inodes,
            children,
        };
        let index_json = serde_json::to_vec(&index).unwrap();
        std::fs::write(dir.join(INDEX_FILE), v0_encrypt(&index_json)).unwrap();
    }

    fn make_v0_drive(dir: &std::path::Path, pw: &str, files: &[(&str, &[u8])]) {
        make_v0_drive_with_kdf(dir, pw, files, LegacyKdf::Hardened);
    }

    #[test]
    fn detects_v0_and_not_v1() {
        let dir = PathBuf::from("target/test-migrate-detect");
        make_v0_drive(&dir, "pw", &[("a.txt", b"alpha")]);
        assert!(needs_migration(&dir).unwrap(), "v0 drive must be detected");

        migrate_v0_to_v1("pw", &dir).unwrap();
        assert!(!needs_migration(&dir).unwrap(), "after migration it is v1");
        assert!(
            dir.join(KDF_FILE).exists(),
            "_kdf.json must exist post-migration"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn migration_materializes_valid_blobless_empty_file() {
        let dir = PathBuf::from("target/test-migrate-blobless-empty");
        make_v0_drive(&dir, "pw", &[("empty.txt", b"")]);
        std::fs::remove_file(dir.join("000001.age")).unwrap();

        migrate_v0_to_v1("pw", &dir).unwrap();

        let migrated = ZeroTrustFs::new("pw", dir.clone());
        assert_eq!(migrated.read_encrypted_file("000001.age").unwrap(), b"");
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn malformed_kdf_is_not_misclassified_as_absent() {
        let dir = PathBuf::from("target/test-migrate-malformed-kdf");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join(INDEX_FILE), b"index-present").unwrap();
        std::fs::write(dir.join(KDF_FILE), b"not-json").unwrap();

        let error = needs_migration(&dir).unwrap_err();
        assert!(error.contains("parse"), "unexpected error: {error}");
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn pre_staging_stale_lock_is_repaired_but_live_lock_is_preserved() {
        let dir = PathBuf::from("target/test-migrate-lock-repair");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let lock = dir.join(LOCK);

        std::fs::write(&lock, local_lock_record_for_test(i32::MAX as u32)).unwrap();
        assert_eq!(recover_interrupted_migration_result(&dir), Ok(false));
        assert!(
            !lock.exists(),
            "stale lock-only crash state must be cleared"
        );

        std::fs::write(&lock, local_lock_record_for_test(std::process::id())).unwrap();
        assert!(recover_interrupted_migration_result(&dir).is_err());
        assert_eq!(
            std::fs::read(&lock).unwrap(),
            local_lock_record_for_test(std::process::id())
        );
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn committed_migration_refuses_unexpected_staging_artifacts() {
        let dir = PathBuf::from("target/test-migrate-staging-conflict");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join(STAGING)).unwrap();
        let conflict = dir.join(STAGING).join("_index 2.age");
        std::fs::write(&conflict, b"provider artifact").unwrap();

        let error = commit_manifest(&dir, &dir.join(STAGING), &[]).unwrap_err();
        assert!(error.contains("unexpected provider/interrupted artifact"));
        assert!(conflict.exists());
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn committed_migration_cleanup_preserves_late_staging_artifact_and_manifest() {
        let dir = PathBuf::from("target/test-migrate-late-staging-conflict");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join(STAGING)).unwrap();
        std::fs::write(dir.join(STAGING).join("late-conflict"), b"evidence").unwrap();
        std::fs::write(dir.join(MANIFEST), b"manifest evidence").unwrap();
        std::fs::write(dir.join(LOCK), b"lock evidence").unwrap();

        assert!(cleanup_transaction(&dir).is_err());
        assert!(dir.join(STAGING).join("late-conflict").exists());
        assert!(dir.join(MANIFEST).exists());
        assert!(dir.join(LOCK).exists());
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn migrated_data_reads_back_under_v1() {
        let dir = PathBuf::from("target/test-migrate-roundtrip");
        let files: &[(&str, &[u8])] = &[
            ("alpha.txt", b"alpha content"),
            ("beta.txt", b"beta content longer than alpha"),
        ];
        make_v0_drive(&dir, "secret-pw", files);

        migrate_v0_to_v1("secret-pw", &dir).unwrap();

        // Reopen the drive the normal (v1) way and read each file.
        let ztfs = ZeroTrustFs::new("secret-pw", dir.clone());
        let state = ztfs.inner.state.read().unwrap();
        for (name, expected) in files {
            let ino = ZeroTrustFs::find_child(&state, 1, name).expect("file present");
            let df = state.inodes.get(&ino).unwrap().disk_filename.clone();
            let got = ztfs.read_encrypted_file(&df).expect("read v1 blob");
            assert_eq!(&got, expected, "content mismatch for {name}");
        }
        drop(state);

        // The legacy key must no longer decrypt the (now v1) index.
        let old_key = derive_key_legacy("secret-pw");
        let idx_ct = std::fs::read(dir.join(INDEX_FILE)).unwrap();
        assert!(decrypt_bytes_legacy(&old_key, &idx_ct).is_err());
        // The v1 key must.
        let v1_key = derive_key_at(&dir, "secret-pw");
        assert!(decrypt_index(&v1_key, &idx_ct).is_ok());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn migration_supports_both_historical_v0_kdfs() {
        let fixtures: Vec<(String, Vec<u8>)> = (0..11)
            .map(|i| (format!("file-{i}.txt"), format!("content-{i}").into_bytes()))
            .collect();
        let borrowed: Vec<(&str, &[u8])> = fixtures
            .iter()
            .map(|(name, content)| (name.as_str(), content.as_slice()))
            .collect();

        for (suffix, variant) in [
            ("tagged", LegacyKdf::Tagged),
            ("hardened", LegacyKdf::Hardened),
        ] {
            let dir = PathBuf::from(format!("target/test-migrate-{suffix}-kdf"));
            make_v0_drive_with_kdf(&dir, "historical-pw", &borrowed, variant);
            assert!(
                dir.join("00000a.age").exists(),
                "fixture must exercise hexadecimal filenames"
            );

            migrate_v0_to_v1("historical-pw", &dir).unwrap();
            let ztfs = ZeroTrustFs::new("historical-pw", dir.clone());
            let state = ztfs.inner.state.read().unwrap();
            for (name, expected) in &fixtures {
                let ino = ZeroTrustFs::find_child(&state, 1, name).expect("file present");
                let disk_filename = &state.inodes.get(&ino).unwrap().disk_filename;
                assert_eq!(ztfs.read_encrypted_file(disk_filename).unwrap(), *expected);
            }
            drop(state);
            let _ = std::fs::remove_dir_all(&dir);
        }
    }

    #[test]
    fn wrong_passphrase_leaves_drive_untouched() {
        let dir = PathBuf::from("target/test-migrate-wrongpw");
        make_v0_drive(&dir, "right-pw", &[("a.txt", b"data")]);
        let before = std::fs::read(dir.join(INDEX_FILE)).unwrap();

        let err = migrate_v0_to_v1("wrong-pw", &dir).unwrap_err();
        assert!(
            err.contains("wrong passphrase") || err.contains("decrypt"),
            "got: {err}"
        );

        // Drive must be byte-identical and still v0.
        assert_eq!(std::fs::read(dir.join(INDEX_FILE)).unwrap(), before);
        assert!(
            needs_migration(&dir).unwrap(),
            "must still be v0 after a failed migration"
        );
        assert!(!dir.join(LOCK).exists(), "lock must be released on failure");
        assert!(
            !dir.join(STAGING).exists(),
            "staging must be cleaned on failure"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn idempotent_on_already_v1() {
        let dir = PathBuf::from("target/test-migrate-idempotent");
        make_v0_drive(&dir, "pw", &[("a.txt", b"x")]);
        migrate_v0_to_v1("pw", &dir).unwrap();
        // Second call is a no-op (drive already v1).
        migrate_v0_to_v1("pw", &dir).unwrap();
        assert!(!needs_migration(&dir).unwrap());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn recovery_completes_interrupted_rename_pass() {
        // Simulate a crash after the index rename succeeded but before
        // any mutable progress update. The immutable fingerprints let
        // recovery distinguish that state from a missing staged file.
        let dir = PathBuf::from("target/test-migrate-recover");
        make_v0_drive(&dir, "pw", &[]);
        // Run a real migration to produce valid v1 artifacts, then
        // reconstruct the interrupted state from them.
        migrate_v0_to_v1("pw", &dir).unwrap();
        let index_bytes = std::fs::read(dir.join(INDEX_FILE)).unwrap();
        let kdf_bytes = std::fs::read(dir.join(KDF_FILE)).unwrap();

        let staging = dir.join(STAGING);
        std::fs::create_dir_all(&staging).unwrap();
        std::fs::rename(dir.join(KDF_FILE), staging.join(KDF_FILE)).unwrap();
        let manifest = vec![
            ManifestEntry {
                filename: INDEX_FILE.to_string(),
                renamed: false,
                fingerprint: Some(ciphertext_fingerprint(&dir.join(INDEX_FILE)).unwrap()),
            },
            ManifestEntry {
                filename: KDF_FILE.to_string(),
                renamed: false,
                fingerprint: Some(exact_fingerprint(&staging.join(KDF_FILE)).unwrap()),
            },
        ];
        std::fs::write(dir.join(MANIFEST), serde_json::to_vec(&manifest).unwrap()).unwrap();
        std::fs::write(dir.join(LOCK), local_lock_record_for_test(i32::MAX as u32)).unwrap();

        assert!(recover_interrupted_migration(&dir));
        assert_eq!(std::fs::read(dir.join(INDEX_FILE)).unwrap(), index_bytes);
        assert_eq!(std::fs::read(dir.join(KDF_FILE)).unwrap(), kdf_bytes);
        assert!(!dir.join(MANIFEST).exists());
        assert!(!dir.join(LOCK).exists());
        assert!(!staging.exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn recovery_accepts_legacy_manifest_when_every_pending_file_is_staged() {
        let dir = PathBuf::from("target/test-migrate-legacy-manifest");
        make_v0_drive(&dir, "pw", &[]);
        migrate_v0_to_v1("pw", &dir).unwrap();

        let staging = dir.join(STAGING);
        std::fs::create_dir_all(&staging).unwrap();
        for filename in [INDEX_FILE, KDF_FILE] {
            std::fs::rename(dir.join(filename), staging.join(filename)).unwrap();
        }
        let manifest = vec![
            ManifestEntry {
                filename: INDEX_FILE.to_string(),
                renamed: false,
                fingerprint: None,
            },
            ManifestEntry {
                filename: KDF_FILE.to_string(),
                renamed: false,
                fingerprint: None,
            },
        ];
        std::fs::write(dir.join(MANIFEST), serde_json::to_vec(&manifest).unwrap()).unwrap();

        assert_eq!(recover_interrupted_migration_result(&dir), Ok(true));
        assert!(dir.join(INDEX_FILE).exists());
        assert!(dir.join(KDF_FILE).exists());
        assert!(!dir.join(MANIFEST).exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn legacy_renamed_migration_entry_never_prefers_resurrected_staging_content() {
        let dir = PathBuf::from("target/test-migrate-renamed-stale-staging");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join(STAGING)).unwrap();
        let key = derive_key_at(&dir, "pw");
        let committed = encrypt_index(&key, b"committed-index").unwrap();
        let resurrected = encrypt_index(&key, b"stale-index").unwrap();
        std::fs::write(dir.join(INDEX_FILE), &committed).unwrap();
        std::fs::write(dir.join(STAGING).join(INDEX_FILE), &resurrected).unwrap();
        let manifest = vec![
            ManifestEntry {
                filename: INDEX_FILE.to_string(),
                renamed: true,
                fingerprint: None,
            },
            ManifestEntry {
                filename: KDF_FILE.to_string(),
                renamed: true,
                fingerprint: None,
            },
        ];
        std::fs::write(dir.join(MANIFEST), serde_json::to_vec(&manifest).unwrap()).unwrap();
        std::fs::write(dir.join(LOCK), local_lock_record_for_test(i32::MAX as u32)).unwrap();

        let error = recover_interrupted_migration_result(&dir).unwrap_err();
        assert!(!error.is_empty());
        assert_eq!(std::fs::read(dir.join(INDEX_FILE)).unwrap(), committed);
        assert!(dir.join(STAGING).join(INDEX_FILE).exists());
        assert!(dir.join(MANIFEST).exists());
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn recovery_accepts_fully_committed_manifest_after_staging_cleanup() {
        let dir = PathBuf::from("target/test-migrate-recover-after-staging-cleanup");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let key = derive_key_at(&dir, "pw");
        let index = encrypt_index(&key, b"committed-index").unwrap();
        std::fs::write(dir.join(INDEX_FILE), &index).unwrap();
        let manifest = vec![
            ManifestEntry {
                filename: INDEX_FILE.to_string(),
                renamed: false,
                fingerprint: Some(crate::crypto::ciphertext_bytes_fingerprint(&index).unwrap()),
            },
            ManifestEntry {
                filename: KDF_FILE.to_string(),
                renamed: false,
                fingerprint: Some(exact_fingerprint(&dir.join(KDF_FILE)).unwrap()),
            },
        ];
        std::fs::write(dir.join(MANIFEST), serde_json::to_vec(&manifest).unwrap()).unwrap();
        std::fs::write(dir.join(LOCK), local_lock_record_for_test(i32::MAX as u32)).unwrap();

        assert_eq!(recover_interrupted_migration_result(&dir), Ok(true));
        assert_eq!(std::fs::read(dir.join(INDEX_FILE)).unwrap(), index);
        assert!(!dir.join(MANIFEST).exists());
        assert!(!dir.join(LOCK).exists());
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn recovery_rejects_malformed_or_unsafe_manifests_without_cleanup() {
        let cases = [
            vec!["../escape.age", INDEX_FILE, KDF_FILE],
            vec!["000001.age", "000001.age", INDEX_FILE, KDF_FILE],
            vec![INDEX_FILE, "000001.age", KDF_FILE],
            vec!["00000A.age", INDEX_FILE, KDF_FILE],
        ];

        for (i, filenames) in cases.into_iter().enumerate() {
            let dir = PathBuf::from(format!("target/test-migrate-unsafe-{i}"));
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(dir.join(STAGING)).unwrap();
            let manifest: Vec<_> = filenames
                .into_iter()
                .map(|filename| ManifestEntry {
                    filename: filename.to_string(),
                    renamed: false,
                    fingerprint: None,
                })
                .collect();
            std::fs::write(dir.join(MANIFEST), serde_json::to_vec(&manifest).unwrap()).unwrap();
            let sentinel = dir.parent().unwrap().join(format!("escape-sentinel-{i}"));
            std::fs::write(&sentinel, b"safe").unwrap();

            assert!(recover_interrupted_migration_result(&dir).is_err());
            assert_eq!(std::fs::read(&sentinel).unwrap(), b"safe");
            assert!(
                dir.join(MANIFEST).exists(),
                "invalid transaction evidence must be preserved"
            );

            let _ = std::fs::remove_file(sentinel);
            let _ = std::fs::remove_dir_all(dir);
        }

        let dir = PathBuf::from("target/test-migrate-invalid-json");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join(MANIFEST), b"not-json").unwrap();
        assert!(recover_interrupted_migration_result(&dir).is_err());
        assert!(dir.join(MANIFEST).exists());
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn recovery_manifest_entry_limit_is_bounded_below_byte_limit() {
        // Ciphertext entries fit conservatively within 512 bytes. Migration
        // adds one exact KDF fingerprint whose 64 KiB byte vector can occupy
        // at most roughly four JSON bytes per input byte.
        assert!((MAX_MANIFEST_ENTRIES as u64) * 512 + 4 * 64 * 1024 < MAX_MANIFEST_FILE_LEN);
        let entry = ManifestEntry {
            filename: INDEX_FILE.to_string(),
            renamed: false,
            fingerprint: None,
        };
        let oversized = vec![entry; MAX_MANIFEST_ENTRIES + 1];
        assert!(validate_manifest(&oversized).is_err());
    }
}
