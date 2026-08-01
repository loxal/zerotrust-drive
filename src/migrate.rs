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
use std::io::Read;

use crate::crypto::{
    KdfParams, RecoveryFingerprint, ciphertext_fingerprint, decrypt_bytes_legacy,
    derive_key_legacy, derive_key_legacy_tagged, encrypt_blob, encrypt_index, exact_fingerprint,
    load_kdf, try_derive_key,
};
use crate::fs::{DiskIndex, InodeKind, durable_write};

const STAGING: &str = ".migrate_staging";
const MANIFEST: &str = "_migrate.manifest";
const LOCK: &str = "_migrate.lock";
const KDF_FILE: &str = "_kdf.json";
const INDEX_FILE: &str = "_index.age";
const MAX_MANIFEST_FILE_LEN: u64 = 64 * 1024 * 1024;
const MAX_MANIFEST_ENTRIES: usize = 100_000;

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
    match std::fs::remove_dir_all(path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(format!("remove {}: {e}", path.display())),
    }
}

#[cfg(unix)]
fn pid_is_live(pid: u32) -> bool {
    if pid > i32::MAX as u32 {
        return false;
    }
    let result = unsafe { libc::kill(pid as libc::pid_t, 0) };
    result == 0 || std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM)
}

#[cfg(not(unix))]
fn pid_is_live(pid: u32) -> bool {
    pid == std::process::id()
}

fn lock_owner_is_live(lock_path: &std::path::Path) -> Result<bool, String> {
    if !lock_path
        .try_exists()
        .map_err(|e| format!("check {}: {e}", lock_path.display()))?
    {
        return Ok(false);
    }
    let value = std::fs::read_to_string(lock_path)
        .map_err(|e| format!("read migration lock {}: {e}", lock_path.display()))?;
    let Ok(pid) = value.trim().parse::<u32>() else {
        return Ok(false);
    };
    Ok(pid_is_live(pid))
}

fn fingerprint_for(filename: &str, path: &std::path::Path) -> Result<RecoveryFingerprint, String> {
    if filename == KDF_FILE {
        exact_fingerprint(path)
    } else {
        ciphertext_fingerprint(path)
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

fn read_manifest(path: &std::path::Path) -> Result<Vec<ManifestEntry>, String> {
    let file = std::fs::File::open(path).map_err(|e| format!("open {}: {e}", path.display()))?;
    let len = file
        .metadata()
        .map_err(|e| format!("stat {}: {e}", path.display()))?
        .len();
    if len > MAX_MANIFEST_FILE_LEN {
        return Err(format!(
            "{} is too large ({len} bytes; maximum {MAX_MANIFEST_FILE_LEN})",
            path.display()
        ));
    }
    let mut json = Vec::with_capacity(len as usize);
    file.take(MAX_MANIFEST_FILE_LEN + 1)
        .read_to_end(&mut json)
        .map_err(|e| format!("read {}: {e}", path.display()))?;
    if json.len() as u64 > MAX_MANIFEST_FILE_LEN {
        return Err(format!(
            "{} grew beyond the {MAX_MANIFEST_FILE_LEN}-byte maximum while being read",
            path.display()
        ));
    }
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
        if entry.fingerprint.is_some() {
            continue;
        }
        let staged = staging.join(&entry.filename);
        let source = if staged
            .try_exists()
            .map_err(|e| format!("check {}: {e}", staged.display()))?
        {
            staged
        } else if entry.renamed {
            base_path.join(&entry.filename)
        } else {
            return Err(format!(
                "cannot safely recover legacy manifest entry {}: staged file is missing and completion was not recorded",
                entry.filename
            ));
        };
        entry.fingerprint = Some(fingerprint_for(&entry.filename, &source)?);
        changed = true;
    }
    if changed {
        write_manifest(manifest_path, entries)?;
    }
    Ok(())
}

fn commit_manifest(
    base_path: &std::path::Path,
    staging: &std::path::Path,
    entries: &[ManifestEntry],
) -> Result<(), String> {
    for entry in entries {
        let expected = entry.fingerprint.as_ref().ok_or_else(|| {
            format!(
                "migration manifest entry {} has no fingerprint",
                entry.filename
            )
        })?;
        let staged = staging.join(&entry.filename);
        let original = base_path.join(&entry.filename);
        if staged
            .try_exists()
            .map_err(|e| format!("check {}: {e}", staged.display()))?
        {
            let actual = fingerprint_for(&entry.filename, &staged)?;
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
            let actual = fingerprint_for(&entry.filename, &original).map_err(|e| {
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
    remove_dir_if_exists(&base_path.join(STAGING))?;
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
    if !index_path
        .try_exists()
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
    let manifest_path = base_path.join(MANIFEST);
    if !manifest_path
        .try_exists()
        .map_err(|e| format!("check {}: {e}", manifest_path.display()))?
    {
        // No manifest means the commit point was not crossed. Refuse to touch
        // a live owner's state, otherwise clear both possible pre-commit crash
        // artifacts (the lock can exist before staging is created).
        let staging = base_path.join(STAGING);
        let lock_path = base_path.join(LOCK);
        let staging_exists = staging
            .try_exists()
            .map_err(|e| format!("check {}: {e}", staging.display()))?;
        let lock_exists = lock_path
            .try_exists()
            .map_err(|e| format!("check {}: {e}", lock_path.display()))?;
        if lock_exists && lock_owner_is_live(&lock_path)? {
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
    if lock_owner_is_live(&lock_path)? {
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
    {
        use std::io::Write;
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
        write!(lock_file, "{}", std::process::id())
            .map_err(|e| format!("write migration lock {}: {e}", lock_path.display()))?;
        lock_file
            .sync_all()
            .map_err(|e| format!("sync migration lock {}: {e}", lock_path.display()))?;
        sync_dir(base_path)?;
    }

    let result = migrate_inner(passphrase, base_path);
    if let Err(original_error) = &result
        && !base_path
            .join(MANIFEST)
            .try_exists()
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
    let index_ct = std::fs::read(&index_path).map_err(|e| format!("read {INDEX_FILE}: {e}"))?;
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

    let total = disk_files.len() + 2; // + index + kdf
    eprintln!(
        "zerotrust-drive: migrating {} file(s) + index to v1 (Argon2id + XChaCha20-Poly1305)...",
        disk_files.len()
    );

    // 3. Stage every blob: legacy-decrypt → v1-encrypt.
    for (i, blob) in disk_files.iter().enumerate() {
        let filename = &blob.filename;
        let ct = match std::fs::read(base_path.join(filename)) {
            Ok(ct) => Some(ct),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound && blob.size == 0 => None,
            Err(e) => return Err(format!("read {filename}: {e}")),
        };
        let pt = match ct {
            Some(ct) => decrypt_bytes_legacy(&old_key, &ct)
                .map_err(|_| format!("failed to decrypt {filename} — data may be corrupted"))?,
            None => Vec::new(),
        };
        let new_ct = encrypt_blob(&new_key, filename, &pt)?;
        durable_write_checked(&staging.join(filename), &new_ct)?;
        eprintln!(
            "zerotrust-drive: [{}/{}] migrated {}",
            i + 1,
            total,
            filename
        );
    }

    // 4. Stage the index (v1-encrypted) and the new _kdf.json (plaintext).
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
    let manifest: Vec<ManifestEntry> = disk_files
        .iter()
        .map(|blob| blob.filename.clone())
        .chain([INDEX_FILE.to_string(), KDF_FILE.to_string()])
        .map(|filename| {
            let fingerprint = fingerprint_for(&filename, &staging.join(&filename))?;
            Ok(ManifestEntry {
                filename,
                renamed: false,
                fingerprint: Some(fingerprint),
            })
        })
        .collect::<Result<_, String>>()?;
    validate_manifest(&manifest)?;
    let manifest_path = base_path.join(MANIFEST);
    write_manifest(&manifest_path, &manifest)?;

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

        std::fs::write(&lock, u32::MAX.to_string()).unwrap();
        assert_eq!(recover_interrupted_migration_result(&dir), Ok(false));
        assert!(
            !lock.exists(),
            "stale lock-only crash state must be cleared"
        );

        std::fs::write(&lock, std::process::id().to_string()).unwrap();
        assert!(recover_interrupted_migration_result(&dir).is_err());
        assert_eq!(
            std::fs::read_to_string(&lock).unwrap(),
            std::process::id().to_string()
        );
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
        std::fs::write(dir.join(LOCK), u32::MAX.to_string()).unwrap();

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
