// Copyright 2026 Alexander Orlov <alexander.orlov@loxal.net>

mod crypto;
mod fs;
mod migrate;
mod rekey;

use std::path::{Path, PathBuf};
use std::sync::atomic::Ordering;

#[cfg(unix)]
use std::fs::{File, OpenOptions};
#[cfg(unix)]
use std::os::fd::AsRawFd;
#[cfg(unix)]
use std::os::unix::ffi::OsStrExt;
#[cfg(unix)]
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};

use clap::Parser;
use fuser::{Config, MountOption};

const DEMO_PASSPHRASE: &str = "zerotrust-demo-passphrase";

fn insecure_new_store_passphrase(passphrase: &str) -> bool {
    passphrase.is_empty() || passphrase == DEMO_PASSPHRASE
}

#[derive(Parser)]
#[command(
    name = "zerotrust-drive",
    about = "FUSE-based encrypted overlay filesystem"
)]
struct Cli {
    /// Directory for encrypted .age files (storage backend, auto-managed — do not modify directly)
    #[arg(long, default_value = "~/g.drive/.zerotrust.drive.encrypted")]
    encrypted_dir: PathBuf,

    /// FUSE mount point showing decrypted files
    #[arg(long, default_value = "~/z.drive")]
    decrypted_dir: PathBuf,

    /// Encryption passphrase (can also be set via ZEROTRUST_PASSPHRASE env var)
    #[arg(long)]
    passphrase: Option<String>,

    /// Re-encrypt all files with a new passphrase (mounts read-only during rotation)
    #[arg(long)]
    new_passphrase: Option<String>,

    /// Resume an interrupted rekey instead of starting over (requires --new-passphrase)
    #[arg(long)]
    continue_rekey: bool,

    /// Upgrade a pre-0.7 drive to the v1 on-disk format (Argon2id +
    /// XChaCha20-Poly1305) in place, using the current passphrase, then
    /// exit. Crash-safe; re-run to resume an interrupted migration.
    #[arg(long)]
    migrate_format: bool,

    /// Allow creating a brand-new drive with an empty or built-in demo
    /// passphrase. Refused by default because either is effectively
    /// unencrypted. For tests/demos only.
    #[arg(long)]
    allow_default_passphrase: bool,
}

fn expand_home_path(path: &Path, home: Option<&Path>) -> Result<PathBuf, String> {
    let suffix = match path.strip_prefix(Path::new("~")) {
        Ok(suffix) => suffix,
        Err(_) => return Ok(path.to_path_buf()),
    };
    let home =
        home.ok_or_else(|| format!("cannot expand {} because HOME is not set", path.display()))?;
    Ok(home.join(suffix))
}

fn expand_home_from_env(path: &Path) -> Result<PathBuf, String> {
    let home = std::env::var_os("HOME").map(PathBuf::from);
    expand_home_path(path, home.as_deref())
}

fn create_and_canonicalize(path: &Path, label: &str) -> Result<PathBuf, String> {
    std::fs::create_dir_all(path)
        .map_err(|e| format!("failed to create {label} {}: {e}", path.display()))?;
    std::fs::canonicalize(path)
        .map_err(|e| format!("failed to canonicalize {label} {}: {e}", path.display()))
}

fn ensure_disjoint_paths(encrypted_dir: &Path, decrypted_dir: &Path) -> Result<(), String> {
    if encrypted_dir == decrypted_dir
        || encrypted_dir.starts_with(decrypted_dir)
        || decrypted_dir.starts_with(encrypted_dir)
    {
        return Err(format!(
            "encrypted storage {} and decrypted mount {} must be separate, non-nested directories",
            encrypted_dir.display(),
            decrypted_dir.display()
        ));
    }
    Ok(())
}

fn ensure_recovery_manifest_cleared(base_path: &Path, manifest_name: &str) -> Result<(), String> {
    let manifest = base_path.join(manifest_name);
    match manifest.try_exists() {
        Ok(false) => Ok(()),
        Ok(true) => Err(format!(
            "recovery remains incomplete; refusing to modify {} while {manifest_name} is unresolved",
            base_path.display()
        )),
        Err(e) => Err(format!(
            "cannot verify that recovery completed because {} could not be inspected: {e}",
            manifest.display()
        )),
    }
}

#[cfg(unix)]
fn stable_path_hash(path: &Path) -> u64 {
    // FNV-1a is deliberately implemented here instead of DefaultHasher:
    // its output stays stable across processes and Rust releases.
    let mut hash = 0xcbf29ce484222325u64;
    for byte in path.as_os_str().as_bytes() {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x100000001b3);
    }
    hash
}

#[cfg(unix)]
fn ensure_private_lock_dir(path: &Path) -> std::io::Result<()> {
    let mut builder = std::fs::DirBuilder::new();
    builder.recursive(true).mode(0o700).create(path)?;

    let metadata = std::fs::symlink_metadata(path)?;
    if !metadata.file_type().is_dir() || metadata.file_type().is_symlink() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("{} is not a real directory", path.display()),
        ));
    }
    if metadata.uid() != unsafe { libc::geteuid() } {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            format!("{} is owned by another user", path.display()),
        ));
    }
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
}

#[cfg(unix)]
fn drive_lock_path(encrypted_dir: &Path) -> Result<PathBuf, String> {
    let uid = unsafe { libc::geteuid() };
    let directory_name = format!("zerotrust-drive-locks-{uid}");
    let mut candidates = vec![
        PathBuf::from("/tmp").join(&directory_name),
        PathBuf::from("/var/tmp").join(&directory_name),
        std::env::temp_dir().join(&directory_name),
    ];
    if let Some(home) = std::env::var_os("HOME") {
        candidates.push(
            PathBuf::from(home)
                .join(".cache")
                .join("zerotrust-drive")
                .join("locks"),
        );
    }

    let mut errors = Vec::new();
    for lock_dir in candidates {
        if lock_dir.starts_with(encrypted_dir) {
            continue;
        }
        match ensure_private_lock_dir(&lock_dir) {
            Ok(()) => {
                let canonical_lock_dir = match std::fs::canonicalize(&lock_dir) {
                    Ok(path) => path,
                    Err(e) => {
                        errors.push(format!("{}: {e}", lock_dir.display()));
                        continue;
                    }
                };
                if canonical_lock_dir.starts_with(encrypted_dir) {
                    continue;
                }
                return Ok(canonical_lock_dir
                    .join(format!("{:016x}.lock", stable_path_hash(encrypted_dir))));
            }
            Err(e) => errors.push(format!("{}: {e}", lock_dir.display())),
        }
    }

    Err(format!(
        "failed to create a local lock directory outside {} ({})",
        encrypted_dir.display(),
        errors.join("; ")
    ))
}

#[cfg(unix)]
#[derive(Debug)]
struct DriveOperationLock {
    _file: File,
}

#[cfg(unix)]
impl DriveOperationLock {
    fn acquire(encrypted_dir: &Path) -> Result<Self, String> {
        let lock_path = drive_lock_path(encrypted_dir)?;
        let file = OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .truncate(false)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&lock_path)
            .map_err(|e| format!("failed to open drive lock {}: {e}", lock_path.display()))?;

        let result = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
        if result != 0 {
            let error = std::io::Error::last_os_error();
            if error.kind() == std::io::ErrorKind::WouldBlock {
                return Err(format!(
                    "another zerotrust-drive process is already using {} (local lock {})",
                    encrypted_dir.display(),
                    lock_path.display()
                ));
            }
            return Err(format!(
                "failed to lock {} for {}: {error}",
                lock_path.display(),
                encrypted_dir.display()
            ));
        }

        Ok(Self { _file: file })
    }
}

#[cfg(not(unix))]
struct DriveOperationLock;

#[cfg(not(unix))]
impl DriveOperationLock {
    fn acquire(_encrypted_dir: &Path) -> Result<Self, String> {
        Err("drive-operation locking is supported only on macOS and Linux".to_string())
    }
}

fn exit_with_error(message: impl std::fmt::Display) -> ! {
    eprintln!("zerotrust-drive: error: {message}");
    std::process::exit(1);
}

fn main() {
    let cli = Cli::parse();
    let passphrase_from_env = std::env::var("ZEROTRUST_PASSPHRASE").ok();
    let passphrase_from_cli = cli.passphrase;
    let passphrase = passphrase_from_env
        .or(passphrase_from_cli)
        .unwrap_or_else(|| DEMO_PASSPHRASE.to_string());
    let using_insecure_passphrase = insecure_new_store_passphrase(&passphrase);
    let expanded_base =
        expand_home_from_env(&cli.encrypted_dir).unwrap_or_else(|e| exit_with_error(e));
    let expanded_mountpoint =
        expand_home_from_env(&cli.decrypted_dir).unwrap_or_else(|e| exit_with_error(e));
    if !cli.migrate_format {
        // Catch direct nesting before creating either directory. Canonical
        // validation below repeats the check to cover symlinks and `..`.
        ensure_disjoint_paths(&expanded_base, &expanded_mountpoint)
            .unwrap_or_else(|e| exit_with_error(e));
    }
    let base_path = create_and_canonicalize(&expanded_base, "encrypted storage directory")
        .unwrap_or_else(|e| exit_with_error(e));
    let mountpoint = if cli.migrate_format {
        expanded_mountpoint
    } else {
        let canonical_mountpoint =
            create_and_canonicalize(&expanded_mountpoint, "decrypted mount directory")
                .unwrap_or_else(|e| exit_with_error(e));
        ensure_disjoint_paths(&base_path, &canonical_mountpoint)
            .unwrap_or_else(|e| exit_with_error(e));
        canonical_mountpoint
    };

    // Keep this local advisory lock alive for the full command or mount
    // lifetime. Its stable path is outside the synced encrypted directory,
    // so provider synchronization cannot create a second local lock inode.
    let _drive_operation_lock =
        DriveOperationLock::acquire(&base_path).unwrap_or_else(|e| exit_with_error(e));

    // Footgun guard: refuse to CREATE a brand-new drive under the
    // built-in demo passphrase — that would store data under a
    // publicly-known key (effectively plaintext). Existing drives are
    // left alone (the operator may legitimately be opening a demo drive,
    // and refusing would lock them out).
    let index_exists = base_path
        .join("_index.age")
        .try_exists()
        .unwrap_or_else(|e| exit_with_error(format!("cannot inspect encrypted index: {e}")));
    if using_insecure_passphrase && !index_exists && !cli.allow_default_passphrase {
        eprintln!(
            "zerotrust-drive: error: refusing to create a new drive with an empty or built-in demo passphrase"
        );
        eprintln!("zerotrust-drive: set ZEROTRUST_PASSPHRASE (or --passphrase) to a real secret,");
        eprintln!("zerotrust-drive: or pass --allow-default-passphrase for a throwaway test drive");
        std::process::exit(1);
    }

    // Recover from any interrupted rekey or format migration before
    // doing anything else.
    rekey::recover_interrupted_rekey_result(&base_path)
        .unwrap_or_else(|e| exit_with_error(format!("rekey recovery failed: {e}")));
    ensure_recovery_manifest_cleared(&base_path, "_rekey.manifest")
        .unwrap_or_else(|e| exit_with_error(e));
    migrate::recover_interrupted_migration_result(&base_path)
        .unwrap_or_else(|e| exit_with_error(format!("migration recovery failed: {e}")));
    ensure_recovery_manifest_cleared(&base_path, "_migrate.manifest")
        .unwrap_or_else(|e| exit_with_error(e));

    // Handle --migrate-format (v0 → v1 on-disk upgrade) and exit.
    if cli.migrate_format {
        if cli.new_passphrase.is_some() {
            eprintln!(
                "zerotrust-drive: error: --migrate-format upgrades in place with the current passphrase; do not combine it with --new-passphrase"
            );
            std::process::exit(1);
        }
        if !base_path.join("_index.age").exists() {
            eprintln!(
                "zerotrust-drive: error: no _index.age found in {} — nothing to migrate",
                base_path.display()
            );
            std::process::exit(1);
        }
        if !migrate::needs_migration(&base_path).unwrap_or_else(|e| exit_with_error(e)) {
            eprintln!("zerotrust-drive: drive is already in the v1 on-disk format — nothing to do");
            return;
        }
        eprintln!(
            "zerotrust-drive: migrating {} to v1 (Argon2id + XChaCha20-Poly1305)...",
            base_path.display()
        );
        eprintln!(
            "zerotrust-drive: NOTE: every blob is re-encrypted, so a cloud-sync backend will re-upload the whole drive"
        );
        match migrate::migrate_v0_to_v1(&passphrase, &base_path) {
            Ok(()) => {
                eprintln!("zerotrust-drive: migration complete — mount normally to use the drive");
                return;
            }
            Err(e) => {
                eprintln!("zerotrust-drive: error: migration failed: {e}");
                match base_path.join("_migrate.manifest").try_exists() {
                    Ok(true) => eprintln!(
                        "zerotrust-drive: migration crossed its commit point; keep recovery artifacts and restart the command to complete recovery"
                    ),
                    Ok(false) => eprintln!(
                        "zerotrust-drive: migration failed before its commit point; original data remains authoritative"
                    ),
                    Err(check_error) => eprintln!(
                        "zerotrust-drive: cannot determine migration commit state; preserve all recovery artifacts: {check_error}"
                    ),
                }
                std::process::exit(1);
            }
        }
    }

    // Refuse to operate on a pre-0.7 drive until it is migrated. This
    // guards both the normal mount and the --new-passphrase rekey path
    // (rekey assumes the v1 KDF + cipher).
    if migrate::needs_migration(&base_path).unwrap_or_else(|e| exit_with_error(e)) {
        eprintln!(
            "zerotrust-drive: error: {} uses the pre-0.7 on-disk format (no _kdf.json)",
            base_path.display()
        );
        eprintln!(
            "zerotrust-drive: run `zerotrust-drive --migrate-format` (with the current passphrase) to upgrade it"
        );
        eprintln!(
            "zerotrust-drive: ChaCha20-Poly1305 → XChaCha20-Poly1305 and the homemade KDF → Argon2id"
        );
        std::process::exit(1);
    }

    // Validate --continue-rekey requires --new-passphrase
    let resume = cli.continue_rekey;
    if resume && cli.new_passphrase.is_none() {
        eprintln!("zerotrust-drive: error: --continue-rekey requires --new-passphrase");
        std::process::exit(1);
    }

    // Handle --new-passphrase (online rekey: mount read-only, re-encrypt in background)
    if let Some(new_passphrase) = cli.new_passphrase {
        if new_passphrase == passphrase {
            eprintln!("zerotrust-drive: error: new passphrase is the same as the current one");
            std::process::exit(1);
        }
        let index_path = base_path.join("_index.age");
        if !index_path.exists() {
            eprintln!(
                "zerotrust-drive: error: no _index.age found in {}",
                base_path.display()
            );
            std::process::exit(1);
        }

        let mut ztfs = fs::ZeroTrustFs::new(&passphrase, base_path.clone());
        let inner = ztfs.inner.clone();
        // Make the filesystem read-only before it can be exposed at the
        // mountpoint. rekey_online repeats this store defensively.
        inner.read_only.store(true, Ordering::SeqCst);

        let rekey_base = base_path.clone();
        let old_pw = passphrase.clone();
        let (mount_ready_tx, mount_ready_rx) = std::sync::mpsc::channel();
        ztfs.notify_when_mounted(mount_ready_tx);
        let rekey_worker = std::thread::spawn(move || {
            if mount_ready_rx.recv().is_err() {
                eprintln!("zerotrust-drive: rekey cancelled because the filesystem did not mount");
                return;
            }
            rekey::rekey_online(&old_pw, &new_passphrase, &rekey_base, &inner, resume);
        });

        eprintln!(
            "zerotrust-drive: rotating passphrase — files will be read-only until re-encryption finishes"
        );
        eprintln!("zerotrust-drive: mounting at {}", mountpoint.display());
        eprintln!(
            "zerotrust-drive: encrypted storage at {}",
            base_path.display()
        );
        eprintln!(
            "zerotrust-drive: the filesystem will remain mounted and become read-write when rotation completes"
        );

        let mut config = Config::default();
        config.mount_options = vec![
            MountOption::RW,
            MountOption::FSName("zerotrust-drive".to_string()),
        ];
        let mount_result = fuser::mount2(ztfs, &mountpoint, &config);
        let worker_result = rekey_worker.join();
        if worker_result.is_err() {
            exit_with_error("rekey worker panicked");
        }
        if let Err(e) = mount_result {
            exit_with_error(format!("failed to mount filesystem: {e}"));
        }
        return;
    }

    // Refuse to mount if a rekey is in progress
    let rekey_lock = base_path.join("_rekey.lock");
    if rekey_lock.exists() {
        eprintln!(
            "zerotrust-drive: error: _rekey.lock exists — a rekey operation may be in progress"
        );
        eprintln!(
            "zerotrust-drive: if you are sure no rekey is running, delete {} manually",
            rekey_lock.display()
        );
        std::process::exit(1);
    }

    eprintln!("zerotrust-drive: mounting at {}", mountpoint.display());
    eprintln!(
        "zerotrust-drive: encrypted storage at {}",
        base_path.display()
    );
    if using_insecure_passphrase {
        eprintln!(
            "zerotrust-drive: WARNING: using an empty or built-in demo passphrase - set ZEROTRUST_PASSPHRASE for real security"
        );
    }
    eprintln!(
        "zerotrust-drive: NOTE: in-memory filesystem — all file content is held in RAM while open"
    );
    eprintln!("zerotrust-drive: not recommended for files larger than available memory");
    eprintln!("zerotrust-drive: press Ctrl+C to unmount");

    let mut config = Config::default();
    config.mount_options = vec![
        MountOption::RW,
        MountOption::FSName("zerotrust-drive".to_string()),
    ];
    let ztfs = fs::ZeroTrustFs::new(&passphrase, base_path);
    fuser::mount2(ztfs, &mountpoint, &config)
        .unwrap_or_else(|e| exit_with_error(format!("failed to mount filesystem: {e}")));
}

#[cfg(test)]
mod main_tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    static TEST_DIRECTORY_ID: AtomicU64 = AtomicU64::new(0);

    fn unique_test_directory(label: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "zerotrust-drive-main-{label}-{}-{}",
            std::process::id(),
            TEST_DIRECTORY_ID.fetch_add(1, Ordering::Relaxed)
        ))
    }

    #[test]
    fn expands_only_home_component_paths() {
        let home = Path::new("/home/tester");
        assert_eq!(expand_home_path(Path::new("~"), Some(home)).unwrap(), home);
        assert_eq!(expand_home_path(Path::new("~/"), Some(home)).unwrap(), home);
        assert_eq!(
            expand_home_path(Path::new("~/drive/data"), Some(home)).unwrap(),
            home.join("drive/data")
        );
        assert_eq!(
            expand_home_path(Path::new("~someone/drive"), Some(home)).unwrap(),
            PathBuf::from("~someone/drive")
        );
        assert_eq!(
            expand_home_path(Path::new("relative/~/drive"), Some(home)).unwrap(),
            PathBuf::from("relative/~/drive")
        );
        assert!(expand_home_path(Path::new("~/drive"), None).is_err());
        assert_eq!(
            expand_home_path(Path::new("relative"), None).unwrap(),
            PathBuf::from("relative")
        );
    }

    #[test]
    fn explicit_demo_and_empty_passphrases_are_insecure_for_new_stores() {
        assert!(insecure_new_store_passphrase(DEMO_PASSPHRASE));
        assert!(insecure_new_store_passphrase(""));
        assert!(!insecure_new_store_passphrase("a-real-secret"));
    }

    #[test]
    fn canonical_paths_must_not_overlap() {
        let root = unique_test_directory("overlap");
        let encrypted = create_and_canonicalize(&root.join("encrypted"), "test encrypted").unwrap();
        let nested_mount =
            create_and_canonicalize(&root.join("encrypted/mount"), "test nested mount").unwrap();
        let sibling_mount =
            create_and_canonicalize(&root.join("encrypted-copy"), "test sibling mount").unwrap();

        assert!(ensure_disjoint_paths(&encrypted, &encrypted).is_err());
        assert!(ensure_disjoint_paths(&encrypted, &nested_mount).is_err());
        assert!(ensure_disjoint_paths(&nested_mount, &encrypted).is_err());
        assert!(ensure_disjoint_paths(&encrypted, &sibling_mount).is_ok());

        std::fs::remove_dir_all(&root).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn drive_lock_excludes_then_allows_reacquisition() {
        let root = unique_test_directory("lock");
        let encrypted = create_and_canonicalize(&root, "test encrypted").unwrap();
        let lock_path = drive_lock_path(&encrypted).unwrap();
        assert_eq!(lock_path, drive_lock_path(&encrypted).unwrap());
        assert!(!lock_path.starts_with(&encrypted));

        let first = DriveOperationLock::acquire(&encrypted).unwrap();
        let contention = DriveOperationLock::acquire(&encrypted).unwrap_err();
        assert!(contention.contains("already using"), "{contention}");

        drop(first);
        let reacquired = DriveOperationLock::acquire(&encrypted).unwrap();
        drop(reacquired);

        std::fs::remove_file(lock_path).unwrap();
        std::fs::remove_dir_all(&root).unwrap();
    }
}
