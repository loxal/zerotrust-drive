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

use crate::crypto::{
    KdfParams, decrypt_bytes_legacy, derive_key, derive_key_legacy, encrypt_blob, encrypt_index,
    load_kdf,
};
use crate::fs::{DiskIndex, InodeKind, durable_write};

const STAGING: &str = ".migrate_staging";
const MANIFEST: &str = "_migrate.manifest";
const LOCK: &str = "_migrate.lock";
const KDF_FILE: &str = "_kdf.json";
const INDEX_FILE: &str = "_index.age";

#[derive(Serialize, Deserialize, Clone, Debug)]
struct ManifestEntry {
    filename: String,
    renamed: bool,
}

/// True iff `base_path` holds a pre-0.7 drive that needs migration:
/// an `_index.age` exists but no `_kdf.json`. Callers should run
/// [`recover_interrupted_migration`] first so a half-finished
/// migration (manifest present, `_kdf.json` not yet renamed) is
/// completed rather than misclassified.
pub fn needs_migration(base_path: &std::path::Path) -> bool {
    base_path.join(INDEX_FILE).exists()
        && load_kdf(base_path).ok().flatten().is_none()
}

/// Complete an interrupted format migration by finishing the rename
/// pass from the manifest. Returns `true` if recovery ran. Mirrors
/// `rekey::recover_interrupted_rekey`.
pub fn recover_interrupted_migration(base_path: &std::path::Path) -> bool {
    let manifest_path = base_path.join(MANIFEST);
    if !manifest_path.exists() {
        // No manifest: if a staging dir is lying around, the previous
        // attempt died before the commit point — discard it; the v0
        // originals are untouched.
        let staging = base_path.join(STAGING);
        if staging.exists() {
            eprintln!("zerotrust-drive: removing stale migration staging directory");
            let _ = std::fs::remove_dir_all(&staging);
            let _ = std::fs::remove_file(base_path.join(LOCK));
        }
        return false;
    }
    eprintln!("zerotrust-drive: detected interrupted format migration — completing...");
    let manifest_json = std::fs::read(&manifest_path).expect("failed to read migration manifest");
    let mut entries: Vec<ManifestEntry> =
        serde_json::from_slice(&manifest_json).expect("failed to parse migration manifest");
    let staging = base_path.join(STAGING);
    for i in 0..entries.len() {
        if entries[i].renamed {
            continue;
        }
        let staged = staging.join(&entries[i].filename);
        if staged.exists() {
            let original = base_path.join(&entries[i].filename);
            std::fs::rename(&staged, &original).unwrap_or_else(|_| {
                panic!("failed to rename staging/{} -> {}", entries[i].filename, entries[i].filename)
            });
            entries[i].renamed = true;
            let updated = serde_json::to_vec(&entries).expect("failed to serialize manifest");
            durable_write(&manifest_path, &updated).expect("failed to update manifest");
        }
    }
    if entries.iter().any(|e| !e.renamed) {
        eprintln!("zerotrust-drive: ERROR: migration recovery incomplete — some staged files missing");
        eprintln!("zerotrust-drive: manifest kept at {} for investigation", manifest_path.display());
        return false;
    }
    let _ = std::fs::remove_dir_all(&staging);
    let _ = std::fs::remove_file(&manifest_path);
    let _ = std::fs::remove_file(base_path.join(LOCK));
    eprintln!("zerotrust-drive: interrupted format migration completed successfully");
    true
}

/// Migrate a v0 drive at `base_path` to v1, in place and crash-safe.
/// Uses the supplied passphrase for both the v0 read key (legacy KDF)
/// and the v1 write key (Argon2id with a freshly generated salt).
///
/// Returns `Err` (leaving the drive untouched) if the passphrase does
/// not decrypt the existing v0 index.
pub fn migrate_v0_to_v1(passphrase: &str, base_path: &std::path::Path) -> Result<(), String> {
    // Finish any prior interrupted migration before starting fresh.
    recover_interrupted_migration(base_path);
    if !needs_migration(base_path) {
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
        let _ = write!(lock_file, "{}", std::process::id());
    }

    let result = migrate_inner(passphrase, base_path);
    if result.is_err() {
        // Staging never reached the manifest commit point, so the v0
        // originals are intact; just clear our lock + staging.
        let _ = std::fs::remove_dir_all(base_path.join(STAGING));
        let _ = std::fs::remove_file(&lock_path);
    }
    result
}

fn migrate_inner(passphrase: &str, base_path: &std::path::Path) -> Result<(), String> {
    // 1. Read + decrypt the v0 index with the legacy key.
    let old_key = derive_key_legacy(passphrase);
    let index_path = base_path.join(INDEX_FILE);
    let index_ct = std::fs::read(&index_path).map_err(|e| format!("read {INDEX_FILE}: {e}"))?;
    let index_json = decrypt_bytes_legacy(&old_key, &index_ct)
        .map_err(|_| "failed to decrypt _index.age — wrong passphrase?".to_string())?;
    let index: DiskIndex =
        serde_json::from_slice(&index_json).map_err(|e| format!("parse index: {e}"))?;

    // 2. New v1 key material.
    let new_kdf = KdfParams::new_random();
    let new_key = derive_key(passphrase, &new_kdf);

    let disk_files: Vec<String> = index
        .inodes
        .values()
        .filter(|e| e.kind == InodeKind::File && !e.disk_filename.is_empty())
        .map(|e| e.disk_filename.clone())
        .collect();

    let staging = base_path.join(STAGING);
    std::fs::create_dir_all(&staging).map_err(|e| format!("create staging: {e}"))?;

    let total = disk_files.len() + 2; // + index + kdf
    eprintln!(
        "zerotrust-drive: migrating {} file(s) + index to v1 (Argon2id + XChaCha20-Poly1305)...",
        disk_files.len()
    );

    // 3. Stage every blob: legacy-decrypt → v1-encrypt.
    for (i, filename) in disk_files.iter().enumerate() {
        let ct = std::fs::read(base_path.join(filename)).map_err(|e| format!("read {filename}: {e}"))?;
        let pt = decrypt_bytes_legacy(&old_key, &ct)
            .map_err(|_| format!("failed to decrypt {filename} — data may be corrupted"))?;
        let new_ct = encrypt_blob(&new_key, filename, &pt)?;
        durable_write(&staging.join(filename), &new_ct).map_err(|e| format!("stage {filename}: {e}"))?;
        eprintln!("zerotrust-drive: [{}/{}] migrated {}", i + 1, total, filename);
    }

    // 4. Stage the index (v1-encrypted) and the new _kdf.json (plaintext).
    let new_index_ct = encrypt_index(&new_key, &index_json)?;
    durable_write(&staging.join(INDEX_FILE), &new_index_ct).map_err(|e| format!("stage index: {e}"))?;
    eprintln!("zerotrust-drive: [{}/{}] migrated {INDEX_FILE}", total - 1, total);

    let kdf_json = serde_json::to_vec_pretty(&new_kdf).map_err(|e| e.to_string())?;
    durable_write(&staging.join(KDF_FILE), &kdf_json).map_err(|e| format!("stage kdf: {e}"))?;
    eprintln!("zerotrust-drive: [{total}/{total}] wrote {KDF_FILE}");

    // 5. Manifest (commit point). Order matters: blobs, then index,
    //    then _kdf.json LAST — its rename is the true completion marker.
    let mut manifest: Vec<ManifestEntry> = disk_files
        .iter()
        .cloned()
        .chain([INDEX_FILE.to_string(), KDF_FILE.to_string()])
        .map(|f| ManifestEntry { filename: f, renamed: false })
        .collect();
    let manifest_path = base_path.join(MANIFEST);
    durable_write(&manifest_path, &serde_json::to_vec(&manifest).map_err(|e| e.to_string())?)
        .map_err(|e| format!("write manifest: {e}"))?;

    // 6. Rename pass.
    for i in 0..manifest.len() {
        std::fs::rename(staging.join(&manifest[i].filename), base_path.join(&manifest[i].filename))
            .map_err(|e| format!("rename staging/{} : {e}", manifest[i].filename))?;
        manifest[i].renamed = true;
        durable_write(&manifest_path, &serde_json::to_vec(&manifest).map_err(|e| e.to_string())?)
            .map_err(|e| format!("update manifest: {e}"))?;
    }

    // 7. Cleanup.
    let _ = std::fs::remove_dir_all(&staging);
    let _ = std::fs::remove_file(&manifest_path);
    let _ = std::fs::remove_file(base_path.join(LOCK));

    eprintln!("zerotrust-drive: format migration complete — drive is now v1 (Argon2id + XChaCha20-Poly1305)");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{decrypt_index, derive_key_at};
    use crate::fs::{DirChild, InodeEntry, ZeroTrustFs};
    use std::collections::HashMap;
    use std::path::PathBuf;

    /// Hand-build a v0 drive: legacy KDF + ChaCha20/12-byte blobs +
    /// index, NO `_kdf.json`. Returns (dir, passphrase).
    fn make_v0_drive(dir: &std::path::Path, pw: &str, files: &[(&str, &[u8])]) {
        use chacha20poly1305::{
            ChaCha20Poly1305, Nonce,
            aead::{Aead, KeyInit, OsRng, rand_core::RngCore},
        };
        let _ = std::fs::remove_dir_all(dir);
        std::fs::create_dir_all(dir).unwrap();
        let key = derive_key_legacy(pw);

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
        inodes.insert(1, InodeEntry {
            name: String::new(), kind: InodeKind::Directory, disk_filename: String::new(),
            size: 0, perm: 0o755, uid: 501, gid: 20,
            atime_secs: 1000, mtime_secs: 1000, ctime_secs: 1000, nlink: 2, parent: 1,
        });
        let mut children: HashMap<u64, Vec<DirChild>> = HashMap::new();
        children.insert(1, Vec::new());
        let mut next_inode = 2u64;
        let mut next_file_id = 1u64;
        for (name, content) in files {
            let ino = next_inode;
            next_inode += 1;
            let df = format!("{:06}.age", next_file_id);
            next_file_id += 1;
            std::fs::write(dir.join(&df), v0_encrypt(content)).unwrap();
            inodes.insert(ino, InodeEntry {
                name: name.to_string(), kind: InodeKind::File, disk_filename: df,
                size: content.len() as u64, perm: 0o644, uid: 501, gid: 20,
                atime_secs: 1000, mtime_secs: 1000, ctime_secs: 1000, nlink: 1, parent: 1,
            });
            children.get_mut(&1).unwrap().push(DirChild { name: name.to_string(), inode: ino });
        }
        let index = DiskIndex { next_inode, next_file_id, inodes, children };
        let index_json = serde_json::to_vec(&index).unwrap();
        std::fs::write(dir.join(INDEX_FILE), v0_encrypt(&index_json)).unwrap();
    }

    #[test]
    fn detects_v0_and_not_v1() {
        let dir = PathBuf::from("target/test-migrate-detect");
        make_v0_drive(&dir, "pw", &[("a.txt", b"alpha")]);
        assert!(needs_migration(&dir), "v0 drive must be detected");

        migrate_v0_to_v1("pw", &dir).unwrap();
        assert!(!needs_migration(&dir), "after migration it is v1");
        assert!(dir.join(KDF_FILE).exists(), "_kdf.json must exist post-migration");
        let _ = std::fs::remove_dir_all(&dir);
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
    fn wrong_passphrase_leaves_drive_untouched() {
        let dir = PathBuf::from("target/test-migrate-wrongpw");
        make_v0_drive(&dir, "right-pw", &[("a.txt", b"data")]);
        let before = std::fs::read(dir.join(INDEX_FILE)).unwrap();

        let err = migrate_v0_to_v1("wrong-pw", &dir).unwrap_err();
        assert!(err.contains("wrong passphrase") || err.contains("decrypt"), "got: {err}");

        // Drive must be byte-identical and still v0.
        assert_eq!(std::fs::read(dir.join(INDEX_FILE)).unwrap(), before);
        assert!(needs_migration(&dir), "must still be v0 after a failed migration");
        assert!(!dir.join(LOCK).exists(), "lock must be released on failure");
        assert!(!dir.join(STAGING).exists(), "staging must be cleaned on failure");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn idempotent_on_already_v1() {
        let dir = PathBuf::from("target/test-migrate-idempotent");
        make_v0_drive(&dir, "pw", &[("a.txt", b"x")]);
        migrate_v0_to_v1("pw", &dir).unwrap();
        // Second call is a no-op (drive already v1).
        migrate_v0_to_v1("pw", &dir).unwrap();
        assert!(!needs_migration(&dir));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn recovery_completes_interrupted_rename_pass() {
        // Simulate a crash mid-rename: data blobs + index already
        // renamed to v1, but _kdf.json still in staging and manifest
        // says it isn't renamed yet.
        let dir = PathBuf::from("target/test-migrate-recover");
        make_v0_drive(&dir, "pw", &[("a.txt", b"x")]);
        // Run a real migration to produce valid v1 artifacts, then
        // reconstruct the interrupted state from them.
        migrate_v0_to_v1("pw", &dir).unwrap();
        let kdf_bytes = std::fs::read(dir.join(KDF_FILE)).unwrap();

        // Reconstruct: move _kdf.json back into staging, write a
        // manifest marking it not-yet-renamed.
        let staging = dir.join(STAGING);
        std::fs::create_dir_all(&staging).unwrap();
        std::fs::rename(dir.join(KDF_FILE), staging.join(KDF_FILE)).unwrap();
        let manifest = vec![ManifestEntry { filename: KDF_FILE.to_string(), renamed: false }];
        std::fs::write(dir.join(MANIFEST), serde_json::to_vec(&manifest).unwrap()).unwrap();
        std::fs::write(dir.join(LOCK), b"123").unwrap();

        assert!(recover_interrupted_migration(&dir));
        assert_eq!(std::fs::read(dir.join(KDF_FILE)).unwrap(), kdf_bytes);
        assert!(!dir.join(MANIFEST).exists());
        assert!(!dir.join(LOCK).exists());
        assert!(!staging.exists());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
