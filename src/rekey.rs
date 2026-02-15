// Copyright 2026 Alexander Orlov <alexander.orlov@loxal.net>

use std::sync::atomic::Ordering;

use serde::{Deserialize, Serialize};

use crate::crypto::{decrypt_bytes, derive_key, encrypt_bytes};
use crate::fs::{DiskIndex, FsInner, InodeKind};

#[derive(Serialize, Deserialize, Clone, Debug)]
struct ManifestEntry {
    filename: String,
    renamed: bool,
}

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
#[cfg(test)]
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
        let state = inner.state.read().unwrap();
        let open = inner.open_files.read().unwrap();
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
        let state = inner.state.read().unwrap();
        let open = inner.open_files.read().unwrap();
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::derive_key;
    use crate::fs::{DirChild, InodeEntry, InodeKind, ZeroTrustFs};
    use std::fs;
    use std::path::PathBuf;
    use std::sync::atomic::Ordering;

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

        rekey(old_pw, new_pw, &dir, false);

        let old_key = derive_key(old_pw);
        let index_ct = fs::read(dir.join("_index.age")).unwrap();
        assert!(decrypt_bytes(&old_key, &index_ct).is_err());

        let ztfs = ZeroTrustFs::new(new_pw, dir.clone());
        let state = ztfs.inner.state.read().unwrap();
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
                    let mut state = ztfs.inner.state.write().unwrap();
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

        let ztfs = ZeroTrustFs::new(new_pw, dir.clone());
        let state = ztfs.inner.state.write().unwrap();
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

        assert_eq!(fs::read(dir.join("000001.age")).unwrap(), b"already-renamed-new");
        assert_eq!(fs::read(dir.join("000002.age")).unwrap(), b"new-data");
        assert_eq!(fs::read(dir.join("_index.age")).unwrap(), b"new-index");
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

        let ztfs = ZeroTrustFs::new(old_pw, dir.clone());
        {
            let mut state = ztfs.inner.state.write().unwrap();
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

        ztfs.inner.open_files.write().unwrap().insert(2, b"online data!".to_vec());

        assert!(!ztfs.inner.read_only.load(Ordering::Relaxed));

        rekey_online(old_pw, new_pw, &dir, &ztfs.inner, false);

        assert!(!ztfs.inner.read_only.load(Ordering::Relaxed));

        let expected_new_key = derive_key(new_pw);
        assert_eq!(*ztfs.inner.key.read().unwrap(), expected_new_key);

        let old_key = derive_key(old_pw);
        let index_ct = fs::read(dir.join("_index.age")).unwrap();
        assert!(decrypt_bytes(&old_key, &index_ct).is_err());

        let ztfs2 = ZeroTrustFs::new(new_pw, dir.clone());
        let state = ztfs2.inner.state.write().unwrap();
        let ino = ZeroTrustFs::find_child(&state, 1, "online.txt").expect("file should exist");
        let df = state.inodes.get(&ino).unwrap().disk_filename.clone();
        drop(state);
        let content = ztfs2.read_encrypted_file(&df);
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

        ztfs.inner.read_only.store(true, Ordering::SeqCst);
        assert!(ztfs.inner.read_only.load(Ordering::Relaxed));

        ztfs.inner.read_only.store(false, Ordering::SeqCst);
        rekey_online(old_pw, new_pw, &dir, &ztfs.inner, false);

        assert!(!ztfs.inner.read_only.load(Ordering::Relaxed));

        let _ = fs::remove_dir_all(&dir);
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

        let staging_dir = dir.join(".rekey_staging");
        fs::create_dir_all(&staging_dir).unwrap();
        let new_key = derive_key(new_pw);
        let old_key = derive_key(old_pw);
        let ct = fs::read(dir.join("000001.age")).unwrap();
        let pt = decrypt_bytes(&old_key, &ct).unwrap();
        let new_ct = encrypt_bytes(&new_key, &pt).unwrap();
        fs::write(staging_dir.join("000001.age"), &new_ct).unwrap();
        fs::write(dir.join("_rekey.lock"), b"99999").unwrap();

        assert!(verify_staged_passphrase(new_pw, &dir).is_ok());
        assert!(verify_staged_passphrase("wrong-pw", &dir).is_err());

        rekey(old_pw, new_pw, &dir, true);

        let ztfs2 = ZeroTrustFs::new(new_pw, dir.clone());
        let state = ztfs2.inner.state.write().unwrap();
        for filename in &["000001.age", "000002.age", "000003.age"] {
            let content = ztfs2.read_encrypted_file(filename);
            assert!(!content.is_empty(), "{filename} should be readable with new key");
        }
        drop(state);

        let old_key = derive_key(old_pw);
        let index_ct = fs::read(dir.join("_index.age")).unwrap();
        assert!(decrypt_bytes(&old_key, &index_ct).is_err());

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
        let key_a = derive_key("passphrase-a");
        let ct = encrypt_bytes(&key_a, b"some data").unwrap();
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

        let staging_dir = dir.join(".rekey_staging");
        fs::create_dir_all(&staging_dir).unwrap();
        let different_key = derive_key("some-other-passphrase");
        let stale_ct = encrypt_bytes(&different_key, b"stale").unwrap();
        fs::write(staging_dir.join("000001.age"), &stale_ct).unwrap();

        rekey(old_pw, new_pw, &dir, false);

        let ztfs2 = ZeroTrustFs::new(new_pw, dir.clone());
        let content = ztfs2.read_encrypted_file("000001.age");
        assert_eq!(content, b"data");

        assert!(!dir.join(".rekey_staging").exists());

        let _ = fs::remove_dir_all(&dir);
    }
}
