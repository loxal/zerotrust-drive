// Copyright 2026 Alexander Orlov <alexander.orlov@loxal.net>

mod crypto;
mod fault;
mod fs;
mod migrate;
mod rekey;
mod transaction_lock;
mod v2;
mod v2_migrate;

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

    /// Upgrade a v1 drive to the immutable authenticated v2 chunk format and
    /// exit. Source blobs remain untouched. Re-run the same command to resume.
    #[arg(long)]
    migrate_v2: bool,

    /// Authenticate and preview unreachable v2 objects without changing the
    /// backing store. The printed plan ID is required for quarantine.
    #[arg(
        long,
        conflicts_with_all = ["gc_v2_quarantine", "gc_v2_restore", "gc_v2_purge"]
    )]
    gc_v2: bool,

    /// Move only the objects from an exact --gc-v2 preview into a resumable
    /// quarantine. Requires cloud synchronization to be paused on every device.
    #[arg(
        long,
        value_name = "PLAN_ID",
        conflicts_with_all = ["gc_v2", "gc_v2_restore", "gc_v2_purge"]
    )]
    gc_v2_quarantine: Option<String>,

    /// Additively restore every exact object from a partial or completed v2 GC
    /// quarantine before purge intent exists.
    #[arg(
        long,
        value_name = "PLAN_ID",
        conflicts_with_all = ["gc_v2", "gc_v2_quarantine", "gc_v2_purge"]
    )]
    gc_v2_restore: Option<String>,

    /// Resume authenticated compatibility evidence for an already-reclaimed
    /// purge. New physical purge is disabled because it cannot be race-free.
    #[arg(
        long,
        value_name = "PLAN_ID",
        conflicts_with_all = ["gc_v2", "gc_v2_quarantine", "gc_v2_restore"]
    )]
    gc_v2_purge: Option<String>,

    /// Confirm that synchronization is paused on every device for a mutating
    /// v2 GC operation. Preview never requires this acknowledgement.
    #[arg(long)]
    confirm_sync_paused: bool,

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
    match fs::backing_entry_exists(&manifest) {
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
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct BackingDirectoryIdentity {
    device: u64,
    inode: u64,
}

#[cfg(unix)]
impl BackingDirectoryIdentity {
    fn from_metadata(metadata: &std::fs::Metadata) -> std::io::Result<Self> {
        if !metadata.is_dir() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "encrypted storage path is not a directory",
            ));
        }
        if metadata.ino() == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "encrypted storage filesystem does not expose a stable directory inode",
            ));
        }
        Ok(Self {
            device: metadata.dev(),
            inode: metadata.ino(),
        })
    }
}

#[cfg(unix)]
fn drive_identity_lock_file_name(
    encrypted_dir: &Path,
    identity: Option<BackingDirectoryIdentity>,
) -> String {
    match identity {
        Some(identity) => format!("fs-{:016x}-{:016x}.lock", identity.device, identity.inode),
        // This deterministic path identity is reserved for platforms where a
        // stable filesystem object identity is unavailable. Unix acquisition
        // deliberately fails closed instead of taking this aliasable fallback.
        None => format!("path-{:016x}.lock", stable_path_hash(encrypted_dir)),
    }
}

#[cfg(unix)]
fn legacy_drive_lock_file_name(encrypted_dir: &Path) -> String {
    // Preserve the exact pre-filesystem-identity name so a new process still
    // contends with an older zerotrust-drive process using the same path.
    format!("{:016x}.lock", stable_path_hash(encrypted_dir))
}

#[cfg(unix)]
fn open_backing_directory(path: &Path) -> Result<File, String> {
    OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .map_err(|error| {
            format!(
                "failed to pin encrypted storage directory {}: {error}",
                path.display()
            )
        })
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
fn path_is_within_directory_identity(
    path: &Path,
    identity: BackingDirectoryIdentity,
) -> std::io::Result<bool> {
    let mut existing = path;
    while !existing.exists() {
        existing = existing.parent().ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::NotFound,
                format!("{} has no existing ancestor", path.display()),
            )
        })?;
    }

    let canonical_existing = std::fs::canonicalize(existing)?;
    for ancestor in canonical_existing.ancestors() {
        let metadata = std::fs::metadata(ancestor)?;
        if metadata.is_dir()
            && metadata.dev() == identity.device
            && metadata.ino() == identity.inode
        {
            return Ok(true);
        }
    }
    Ok(false)
}

#[cfg(unix)]
fn drive_lock_directory(
    encrypted_dir: &Path,
    identity: BackingDirectoryIdentity,
) -> Result<PathBuf, String> {
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
        match path_is_within_directory_identity(&lock_dir, identity) {
            Ok(true) => {
                errors.push(format!(
                    "{} resolves inside the encrypted storage directory",
                    lock_dir.display()
                ));
                continue;
            }
            Ok(false) => {}
            Err(error) => {
                errors.push(format!(
                    "cannot validate location {}: {error}",
                    lock_dir.display()
                ));
                continue;
            }
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
                if canonical_lock_dir.starts_with(encrypted_dir)
                    || path_is_within_directory_identity(&canonical_lock_dir, identity)
                        .unwrap_or(true)
                {
                    continue;
                }
                return Ok(canonical_lock_dir);
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
fn drive_lock_paths(
    encrypted_dir: &Path,
    identity: BackingDirectoryIdentity,
) -> Result<(PathBuf, PathBuf), String> {
    let lock_dir = drive_lock_directory(encrypted_dir, identity)?;
    Ok((
        lock_dir.join(drive_identity_lock_file_name(encrypted_dir, Some(identity))),
        lock_dir.join(legacy_drive_lock_file_name(encrypted_dir)),
    ))
}

#[cfg(unix)]
fn acquire_lock_file(lock_path: &Path, encrypted_dir: &Path) -> Result<File, String> {
    let file = OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(lock_path)
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

    Ok(file)
}

#[cfg(unix)]
#[derive(Debug)]
struct DriveOperationLock {
    _identity_lock: File,
    _legacy_path_lock: File,
    backing_directory: File,
    backing_path: PathBuf,
    identity: BackingDirectoryIdentity,
}

#[cfg(unix)]
impl DriveOperationLock {
    fn acquire(encrypted_dir: &Path) -> Result<Self, String> {
        let backing_directory = open_backing_directory(encrypted_dir)?;
        let identity = BackingDirectoryIdentity::from_metadata(
            &backing_directory.metadata().map_err(|error| {
                format!(
                    "failed to inspect pinned encrypted storage directory {}: {error}",
                    encrypted_dir.display()
                )
            })?,
        )
        .map_err(|error| {
            format!(
                "cannot derive a safe lock identity for encrypted storage directory {}: {error}",
                encrypted_dir.display()
            )
        })?;
        let (identity_lock_path, legacy_path_lock_path) =
            drive_lock_paths(encrypted_dir, identity)?;

        // Acquire the alias-independent lock first. The legacy path lock then
        // preserves contention with an older binary using this exact path.
        let identity_lock = acquire_lock_file(&identity_lock_path, encrypted_dir)?;
        let legacy_path_lock = acquire_lock_file(&legacy_path_lock_path, encrypted_dir)?;
        let operation_lock = Self {
            _identity_lock: identity_lock,
            _legacy_path_lock: legacy_path_lock,
            backing_directory,
            backing_path: encrypted_dir.to_path_buf(),
            identity,
        };
        operation_lock.revalidate()?;
        Ok(operation_lock)
    }

    fn revalidate(&self) -> Result<(), String> {
        let pinned_identity = BackingDirectoryIdentity::from_metadata(
            &self.backing_directory.metadata().map_err(|error| {
                format!(
                    "failed to re-inspect pinned encrypted storage directory {}: {error}",
                    self.backing_path.display()
                )
            })?,
        )
        .map_err(|error| {
            format!(
                "cannot revalidate pinned encrypted storage directory {}: {error}",
                self.backing_path.display()
            )
        })?;
        let current_directory = open_backing_directory(&self.backing_path)?;
        let current_identity = BackingDirectoryIdentity::from_metadata(
            &current_directory.metadata().map_err(|error| {
                format!(
                    "failed to inspect current encrypted storage directory {}: {error}",
                    self.backing_path.display()
                )
            })?,
        )
        .map_err(|error| {
            format!(
                "cannot revalidate current encrypted storage directory {}: {error}",
                self.backing_path.display()
            )
        })?;

        if pinned_identity != self.identity || current_identity != self.identity {
            return Err(format!(
                "encrypted storage directory {} changed identity after lock acquisition; refusing to continue",
                self.backing_path.display()
            ));
        }
        Ok(())
    }

    fn anchor_process_working_directory(&self) -> Result<(), String> {
        self.revalidate()?;
        let result = unsafe { libc::fchdir(self.backing_directory.as_raw_fd()) };
        if result != 0 {
            return Err(format!(
                "failed to anchor backing-store I/O to pinned encrypted storage directory {}: {}",
                self.backing_path.display(),
                std::io::Error::last_os_error()
            ));
        }

        let anchored_directory = open_backing_directory(Path::new("."))?;
        let anchored_identity = BackingDirectoryIdentity::from_metadata(
            &anchored_directory.metadata().map_err(|error| {
                format!(
                    "failed to inspect anchored encrypted storage directory {}: {error}",
                    self.backing_path.display()
                )
            })?,
        )
        .map_err(|error| {
            format!(
                "cannot validate anchored encrypted storage directory {}: {error}",
                self.backing_path.display()
            )
        })?;
        if anchored_identity != self.identity {
            return Err(format!(
                "process working directory did not anchor to encrypted storage directory {}; refusing to continue",
                self.backing_path.display()
            ));
        }

        // Detect replacement of the user-facing path during fchdir. A later
        // replacement cannot redirect operational `.` I/O, but setup still
        // fails closed so the operator sees the namespace change.
        self.revalidate()
    }
}

#[cfg(not(unix))]
struct DriveOperationLock;

#[cfg(not(unix))]
impl DriveOperationLock {
    fn acquire(_encrypted_dir: &Path) -> Result<Self, String> {
        Err("drive-operation locking is supported only on macOS and Linux".to_string())
    }

    fn revalidate(&self) -> Result<(), String> {
        Err("drive-operation locking is supported only on macOS and Linux".to_string())
    }

    fn anchor_process_working_directory(&self) -> Result<(), String> {
        Err("drive-operation locking is supported only on macOS and Linux".to_string())
    }
}

fn exit_with_error(message: impl std::fmt::Display) -> ! {
    eprintln!("zerotrust-drive: error: {message}");
    std::process::exit(1);
}

fn main() {
    let cli = Cli::parse();
    let gc_mutation_requested =
        cli.gc_v2_quarantine.is_some() || cli.gc_v2_restore.is_some() || cli.gc_v2_purge.is_some();
    let gc_requested = cli.gc_v2 || gc_mutation_requested;
    if cli.confirm_sync_paused && !gc_mutation_requested {
        exit_with_error("--confirm-sync-paused is accepted only with a mutating v2 GC operation");
    }
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
    if !cli.migrate_format && !cli.migrate_v2 && !gc_requested {
        // Catch direct nesting before creating either directory. Canonical
        // validation below repeats the check to cover symlinks and `..`.
        ensure_disjoint_paths(&expanded_base, &expanded_mountpoint)
            .unwrap_or_else(|e| exit_with_error(e));
    }
    let display_base_path = if gc_requested {
        std::fs::canonicalize(&expanded_base).unwrap_or_else(|error| {
            exit_with_error(format!(
                "failed to open existing encrypted storage directory {} for offline GC: {error}",
                expanded_base.display()
            ))
        })
    } else {
        create_and_canonicalize(&expanded_base, "encrypted storage directory")
            .unwrap_or_else(|e| exit_with_error(e))
    };
    let mountpoint = if cli.migrate_format || cli.migrate_v2 || gc_requested {
        expanded_mountpoint
    } else {
        let canonical_mountpoint =
            create_and_canonicalize(&expanded_mountpoint, "decrypted mount directory")
                .unwrap_or_else(|e| exit_with_error(e));
        ensure_disjoint_paths(&display_base_path, &canonical_mountpoint)
            .unwrap_or_else(|e| exit_with_error(e));
        canonical_mountpoint
    };

    // Keep this local advisory lock alive for the full command or mount
    // lifetime. Its stable path is outside the synced encrypted directory,
    // so provider synchronization cannot create a second local lock inode.
    let drive_operation_lock =
        DriveOperationLock::acquire(&display_base_path).unwrap_or_else(|e| exit_with_error(e));
    drive_operation_lock
        .anchor_process_working_directory()
        .unwrap_or_else(|e| exit_with_error(e));

    // All backing-store I/O is relative to the pinned directory now. Renaming
    // or replacing the user-facing absolute path cannot redirect a live mount
    // to a different directory. Keep display_base_path only for diagnostics.
    let base_path = PathBuf::from(".");

    // Cloud providers can preserve conflicting copies under sibling names
    // such as `_index 2.age`. There is no safe automatic merge for an
    // encrypted index, so detect them before recovery or any other write.
    fs::ensure_no_index_siblings(&base_path).unwrap_or_else(|e| exit_with_error(e));
    fs::ensure_unambiguous_format_heads(&base_path).unwrap_or_else(|e| exit_with_error(e));
    fs::ensure_v2_controls_have_kdf(&base_path).unwrap_or_else(|e| exit_with_error(e));

    // Footgun guard: refuse to CREATE a brand-new drive under the
    // built-in demo passphrase — that would store data under a
    // publicly-known key (effectively plaintext). Existing drives are
    // left alone (the operator may legitimately be opening a demo drive,
    // and refusing would lock them out).
    let index_path = base_path.join("_index.age");
    let root_path = base_path.join(v2::ROOT_FILE);
    let index_exists = fs::backing_entry_exists(&index_path)
        .unwrap_or_else(|e| exit_with_error(format!("cannot inspect encrypted index: {e}")));
    let root_exists = fs::backing_entry_exists(&root_path)
        .unwrap_or_else(|e| exit_with_error(format!("cannot inspect encrypted v2 root: {e}")));
    if using_insecure_passphrase && !index_exists && !root_exists && !cli.allow_default_passphrase {
        eprintln!(
            "zerotrust-drive: error: refusing to create a new drive with an empty or built-in demo passphrase"
        );
        eprintln!("zerotrust-drive: set ZEROTRUST_PASSPHRASE (or --passphrase) to a real secret,");
        eprintln!("zerotrust-drive: or pass --allow-default-passphrase for a throwaway test drive");
        std::process::exit(1);
    }

    if gc_requested {
        if cli.migrate_format
            || cli.migrate_v2
            || cli.new_passphrase.is_some()
            || cli.continue_rekey
        {
            exit_with_error(
                "offline v2 GC cannot be combined with migration, mounting, or passphrase rotation",
            );
        }
        ensure_recovery_manifest_cleared(&base_path, "_rekey.manifest")
            .unwrap_or_else(|e| exit_with_error(e));
        ensure_recovery_manifest_cleared(&base_path, "_migrate.manifest")
            .unwrap_or_else(|e| exit_with_error(e));
        for lock_name in ["_rekey.lock", "_migrate.lock"] {
            if fs::backing_entry_exists(&base_path.join(lock_name))
                .unwrap_or_else(|e| exit_with_error(format!("inspect {lock_name}: {e}")))
            {
                exit_with_error(format!(
                    "{lock_name} exists; preserve the possible local or foreign maintenance owner and do not run GC"
                ));
            }
        }
        if v2_migrate::migration_pending(&base_path).unwrap_or_else(|e| exit_with_error(e)) {
            exit_with_error("v1-to-v2 migration is pending; resume it before running offline GC");
        }
        if gc_mutation_requested && !cli.confirm_sync_paused {
            exit_with_error(
                "mutating v2 GC requires --confirm-sync-paused after pausing synchronization on every device",
            );
        }
        drive_operation_lock
            .revalidate()
            .unwrap_or_else(|e| exit_with_error(e));
        if cli.gc_v2 {
            let preview =
                v2::gc_preview(&base_path, &passphrase).unwrap_or_else(|e| exit_with_error(e));
            if !preview.is_v2 {
                eprintln!(
                    "zerotrust-drive: v1 drive detected - preview did not modify the encrypted backing store or persist GC state; v2 GC has nothing to collect"
                );
                return;
            }
            eprintln!(
                "zerotrust-drive: v2 GC preview {}: {} reachable objects; {} quarantine candidates ({} ciphertext bytes)",
                preview.plan_id.as_deref().unwrap_or("unavailable"),
                preview.reachable_objects,
                preview.candidate_objects,
                preview.candidate_bytes
            );
            for name in preview.candidate_names.iter().take(100) {
                eprintln!("zerotrust-drive: candidate {name}");
            }
            if preview.candidate_names.len() > 100 {
                eprintln!(
                    "zerotrust-drive: {} additional candidates omitted from display",
                    preview.candidate_names.len() - 100
                );
            }
            eprintln!(
                "zerotrust-drive: preview did not modify the encrypted backing store or persist a GC plan"
            );
            return;
        }
        if let Some(plan_id) = cli.gc_v2_quarantine.as_deref() {
            let report = v2::gc_quarantine(&base_path, &passphrase, plan_id)
                .unwrap_or_else(|e| exit_with_error(e));
            eprintln!(
                "zerotrust-drive: quarantined {} exact unreachable v2 objects ({} ciphertext bytes) under authenticated plan {plan_id}; object bytes were moved without being unlinked",
                report.candidate_objects, report.candidate_bytes
            );
            return;
        }
        if let Some(plan_id) = cli.gc_v2_restore.as_deref() {
            let count = v2::gc_restore(&base_path, &passphrase, plan_id)
                .unwrap_or_else(|e| exit_with_error(e));
            eprintln!(
                "zerotrust-drive: restored {count} exact immutable v2 objects from quarantine plan {plan_id}"
            );
            return;
        }
        if let Some(plan_id) = cli.gc_v2_purge.as_deref() {
            let (count, bytes) = v2::gc_purge(&base_path, &passphrase, plan_id)
                .unwrap_or_else(|e| exit_with_error(e));
            eprintln!(
                "zerotrust-drive: completed compatibility recovery for {count} already-reclaimed v2 objects ({bytes} prior ciphertext bytes); authenticated plan, completion evidence, and zero-length purge tombstones remain"
            );
            return;
        }
        unreachable!("gc_requested requires one GC action");
    }

    // Recover from any interrupted rekey or format migration before
    // doing anything else.
    drive_operation_lock
        .revalidate()
        .unwrap_or_else(|e| exit_with_error(e));
    fs::ensure_v2_controls_have_kdf(&base_path).unwrap_or_else(|e| exit_with_error(e));
    rekey::recover_interrupted_rekey_result(&base_path)
        .unwrap_or_else(|e| exit_with_error(format!("rekey recovery failed: {e}")));
    fs::ensure_v2_controls_have_kdf(&base_path).unwrap_or_else(|e| exit_with_error(e));
    ensure_recovery_manifest_cleared(&base_path, "_rekey.manifest")
        .unwrap_or_else(|e| exit_with_error(e));
    drive_operation_lock
        .revalidate()
        .unwrap_or_else(|e| exit_with_error(e));
    fs::ensure_v2_controls_have_kdf(&base_path).unwrap_or_else(|e| exit_with_error(e));
    migrate::recover_interrupted_migration_result(&base_path)
        .unwrap_or_else(|e| exit_with_error(format!("migration recovery failed: {e}")));
    fs::ensure_v2_controls_have_kdf(&base_path).unwrap_or_else(|e| exit_with_error(e));
    ensure_recovery_manifest_cleared(&base_path, "_migrate.manifest")
        .unwrap_or_else(|e| exit_with_error(e));

    // Handle --migrate-format (v0 → v1 on-disk upgrade) and exit.
    if cli.migrate_format {
        if cli.migrate_v2 {
            exit_with_error("--migrate-format and --migrate-v2 are mutually exclusive");
        }
        if cli.new_passphrase.is_some() {
            eprintln!(
                "zerotrust-drive: error: --migrate-format upgrades in place with the current passphrase; do not combine it with --new-passphrase"
            );
            std::process::exit(1);
        }
        if !base_path.join("_index.age").exists() {
            eprintln!(
                "zerotrust-drive: error: no _index.age found in {} — nothing to migrate",
                display_base_path.display()
            );
            std::process::exit(1);
        }
        if !migrate::needs_migration(&base_path).unwrap_or_else(|e| exit_with_error(e)) {
            eprintln!("zerotrust-drive: drive is already in the v1 on-disk format — nothing to do");
            return;
        }
        eprintln!(
            "zerotrust-drive: migrating {} to v1 (Argon2id + XChaCha20-Poly1305)...",
            display_base_path.display()
        );
        eprintln!(
            "zerotrust-drive: NOTE: every blob is re-encrypted, so a cloud-sync backend will re-upload the whole drive"
        );
        drive_operation_lock
            .revalidate()
            .unwrap_or_else(|e| exit_with_error(e));
        match migrate::migrate_v0_to_v1(&passphrase, &base_path) {
            Ok(()) => {
                eprintln!("zerotrust-drive: migration complete — mount normally to use the drive");
                return;
            }
            Err(e) => {
                eprintln!("zerotrust-drive: error: migration failed: {e}");
                match fs::backing_entry_exists(&base_path.join("_migrate.manifest")) {
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

    if cli.migrate_v2 {
        if cli.new_passphrase.is_some() || cli.continue_rekey {
            exit_with_error("--migrate-v2 cannot be combined with passphrase-rotation options");
        }
        if !index_exists {
            exit_with_error(format!(
                "no v1 _index.age found in {} - nothing to migrate",
                display_base_path.display()
            ));
        }
        let migration_plan_exists =
            v2_migrate::migration_plan_exists(&base_path).unwrap_or_else(|e| exit_with_error(e));
        if root_exists && !migration_plan_exists {
            eprintln!("zerotrust-drive: drive is already in the v2 on-disk format - nothing to do");
            return;
        }
        if migrate::needs_migration(&base_path).unwrap_or_else(|e| exit_with_error(e)) {
            exit_with_error(
                "pre-0.7 storage must first be upgraded with --migrate-format, then migrated with --migrate-v2",
            );
        }
        eprintln!(
            "zerotrust-drive: migrating {} from v1 whole blobs to v2 immutable authenticated chunks...",
            display_base_path.display()
        );
        eprintln!(
            "zerotrust-drive: v1 source ciphertext is retained; allow temporary space for another complete encrypted copy"
        );
        drive_operation_lock
            .revalidate()
            .unwrap_or_else(|e| exit_with_error(e));
        match v2_migrate::migrate_v1_to_v2(&passphrase, &base_path) {
            Ok(()) => {
                eprintln!(
                    "zerotrust-drive: v2 migration complete - the authenticated root now points only to immutable chunks"
                );
                return;
            }
            Err(error) => {
                exit_with_error(format!(
                    "v1-to-v2 migration stopped safely: {error}; preserve all plan/progress/object evidence and re-run --migrate-v2 to resume"
                ));
            }
        }
    }

    if v2_migrate::migration_pending(&base_path).unwrap_or_else(|e| exit_with_error(e)) {
        exit_with_error(
            "an authenticated v1-to-v2 migration plan is pending; run --migrate-v2 with the same passphrase to resume before mounting or rekeying",
        );
    }

    // Refuse to operate on a pre-0.7 drive until it is migrated. This
    // guards both the normal mount and the --new-passphrase rekey path
    // (rekey assumes the v1 KDF + cipher).
    if migrate::needs_migration(&base_path).unwrap_or_else(|e| exit_with_error(e)) {
        eprintln!(
            "zerotrust-drive: error: {} uses the pre-0.7 on-disk format (no _kdf.json)",
            display_base_path.display()
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
        if root_exists {
            exit_with_error(
                "passphrase rotation for v2 is not implemented yet; preserve the immutable generation and migrate a decrypted export into a new v2 store",
            );
        }
        let index_path = base_path.join("_index.age");
        if !index_path.exists() {
            eprintln!(
                "zerotrust-drive: error: no _index.age found in {}",
                display_base_path.display()
            );
            std::process::exit(1);
        }

        drive_operation_lock
            .revalidate()
            .unwrap_or_else(|e| exit_with_error(e));
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
            display_base_path.display()
        );
        eprintln!(
            "zerotrust-drive: the filesystem will remain mounted and become read-write when rotation completes"
        );

        drive_operation_lock
            .revalidate()
            .unwrap_or_else(|e| exit_with_error(e));

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
            display_base_path.join("_rekey.lock").display()
        );
        std::process::exit(1);
    }

    eprintln!("zerotrust-drive: mounting at {}", mountpoint.display());
    eprintln!(
        "zerotrust-drive: encrypted storage at {}",
        display_base_path.display()
    );
    if using_insecure_passphrase {
        eprintln!(
            "zerotrust-drive: WARNING: using an empty or built-in demo passphrase - set ZEROTRUST_PASSPHRASE for real security"
        );
    }
    drive_operation_lock
        .revalidate()
        .unwrap_or_else(|e| exit_with_error(e));
    let ztfs = fs::ZeroTrustFs::new_v2(&passphrase, base_path);
    match ztfs.inner.format {
        fs::StoreFormat::V2 => eprintln!(
            "zerotrust-drive: v2 immutable chunks enabled - read/write memory is bounded independently of file size"
        ),
        fs::StoreFormat::V1 => {
            eprintln!(
                "zerotrust-drive: WARNING: legacy v1 store - open files remain buffered in RAM"
            );
            eprintln!(
                "zerotrust-drive: run the explicit v1-to-v2 migration before using files larger than available memory"
            );
        }
    }
    eprintln!("zerotrust-drive: press Ctrl+C to unmount");

    let mut config = Config::default();
    config.mount_options = vec![
        MountOption::RW,
        MountOption::FSName("zerotrust-drive".to_string()),
    ];
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
    fn filesystem_identity_lock_name_ignores_path_alias_text() {
        let root = unique_test_directory("identity-name");
        let encrypted = create_and_canonicalize(&root, "test encrypted").unwrap();
        let alias = encrypted.join(".");
        let identity = BackingDirectoryIdentity::from_metadata(
            &open_backing_directory(&encrypted)
                .unwrap()
                .metadata()
                .unwrap(),
        )
        .unwrap();
        let alias_identity = BackingDirectoryIdentity::from_metadata(
            &open_backing_directory(&alias).unwrap().metadata().unwrap(),
        )
        .unwrap();

        assert_eq!(identity, alias_identity);
        assert_eq!(
            drive_identity_lock_file_name(&encrypted, Some(identity)),
            drive_identity_lock_file_name(&alias, Some(alias_identity))
        );
        assert_ne!(
            legacy_drive_lock_file_name(&encrypted),
            legacy_drive_lock_file_name(&alias)
        );
        assert!(
            path_is_within_directory_identity(&alias.join("not-created-yet"), identity).unwrap()
        );
        assert!(
            !path_is_within_directory_identity(
                encrypted
                    .parent()
                    .unwrap()
                    .join("identity-name-sibling")
                    .as_path(),
                identity,
            )
            .unwrap()
        );

        std::fs::remove_dir_all(&root).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn portable_path_lock_name_is_deterministic_and_path_specific() {
        let first = Path::new("/portable/fallback/one");
        let second = Path::new("/portable/fallback/two");

        assert_eq!(
            drive_identity_lock_file_name(first, None),
            drive_identity_lock_file_name(first, None)
        );
        assert_ne!(
            drive_identity_lock_file_name(first, None),
            drive_identity_lock_file_name(second, None)
        );
        assert!(drive_identity_lock_file_name(first, None).starts_with("path-"));
    }

    #[cfg(unix)]
    #[test]
    fn drive_lock_excludes_alias_then_allows_reacquisition() {
        let root = unique_test_directory("lock");
        let encrypted = create_and_canonicalize(&root, "test encrypted").unwrap();
        let alias = encrypted.join(".");
        let identity = BackingDirectoryIdentity::from_metadata(
            &open_backing_directory(&encrypted)
                .unwrap()
                .metadata()
                .unwrap(),
        )
        .unwrap();
        let (identity_lock_path, legacy_lock_path) =
            drive_lock_paths(&encrypted, identity).unwrap();
        assert!(!identity_lock_path.starts_with(&encrypted));
        assert!(!legacy_lock_path.starts_with(&encrypted));

        let first = DriveOperationLock::acquire(&encrypted).unwrap();
        let contention = DriveOperationLock::acquire(&alias).unwrap_err();
        assert!(contention.contains("already using"), "{contention}");
        first.revalidate().unwrap();

        drop(first);
        let reacquired = DriveOperationLock::acquire(&encrypted).unwrap();
        drop(reacquired);

        std::fs::remove_file(identity_lock_path).unwrap();
        std::fs::remove_file(legacy_lock_path).unwrap();
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn drive_lock_contends_with_legacy_path_lock() {
        let root = unique_test_directory("legacy-lock");
        let encrypted = create_and_canonicalize(&root, "test encrypted").unwrap();
        let identity = BackingDirectoryIdentity::from_metadata(
            &open_backing_directory(&encrypted)
                .unwrap()
                .metadata()
                .unwrap(),
        )
        .unwrap();
        let (identity_lock_path, legacy_lock_path) =
            drive_lock_paths(&encrypted, identity).unwrap();
        let legacy_owner = acquire_lock_file(&legacy_lock_path, &encrypted).unwrap();

        let contention = DriveOperationLock::acquire(&encrypted).unwrap_err();
        assert!(contention.contains("already using"), "{contention}");

        drop(legacy_owner);
        std::fs::remove_file(identity_lock_path).unwrap();
        std::fs::remove_file(legacy_lock_path).unwrap();
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn drive_lock_revalidation_rejects_replaced_directory() {
        let root = unique_test_directory("lock-replaced");
        let encrypted = create_and_canonicalize(&root.join("encrypted"), "test encrypted").unwrap();
        let displaced = root.join("displaced");
        let identity = BackingDirectoryIdentity::from_metadata(
            &open_backing_directory(&encrypted)
                .unwrap()
                .metadata()
                .unwrap(),
        )
        .unwrap();
        let (identity_lock_path, legacy_lock_path) =
            drive_lock_paths(&encrypted, identity).unwrap();
        let operation_lock = DriveOperationLock::acquire(&encrypted).unwrap();

        std::fs::rename(&encrypted, &displaced).unwrap();
        std::fs::create_dir(&encrypted).unwrap();
        let error = operation_lock.revalidate().unwrap_err();
        assert!(error.contains("changed identity"), "{error}");

        drop(operation_lock);
        std::fs::remove_file(identity_lock_path).unwrap();
        std::fs::remove_file(legacy_lock_path).unwrap();
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn anchored_backing_io_does_not_follow_replaced_absolute_path() {
        const CHILD_ROOT_ENV: &str = "ZEROTRUST_DRIVE_TEST_ANCHOR_CHILD_ROOT";
        const TEST_NAME: &str =
            "main_tests::anchored_backing_io_does_not_follow_replaced_absolute_path";

        if let Some(root) = std::env::var_os(CHILD_ROOT_ENV).map(PathBuf::from) {
            let original = root.join("original");
            let replacement = root.join("replacement");
            let displaced = root.join("displaced");
            let operation_lock = DriveOperationLock::acquire(&original).unwrap();
            operation_lock.anchor_process_working_directory().unwrap();

            std::fs::rename(&original, &displaced).unwrap();
            std::fs::rename(&replacement, &original).unwrap();
            std::fs::write("anchored-witness", b"pinned directory").unwrap();
            std::fs::write(
                original.join("replacement-witness"),
                b"replacement directory",
            )
            .unwrap();

            assert!(displaced.join("anchored-witness").is_file());
            assert!(!original.join("anchored-witness").exists());
            assert!(operation_lock.revalidate().is_err());
            return;
        }

        let root = unique_test_directory("anchor-subprocess");
        let original = root.join("original");
        let replacement = root.join("replacement");
        let displaced = root.join("displaced");
        std::fs::create_dir_all(&original).unwrap();
        std::fs::create_dir(&replacement).unwrap();
        let identity = BackingDirectoryIdentity::from_metadata(
            &open_backing_directory(&original)
                .unwrap()
                .metadata()
                .unwrap(),
        )
        .unwrap();
        let (identity_lock_path, legacy_lock_path) = drive_lock_paths(&original, identity).unwrap();

        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .arg("--exact")
            .arg(TEST_NAME)
            .arg("--nocapture")
            .arg("--test-threads=1")
            .env(CHILD_ROOT_ENV, &root)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "anchor child failed\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(
            std::fs::read(displaced.join("anchored-witness")).unwrap(),
            b"pinned directory"
        );
        assert_eq!(
            std::fs::read(original.join("replacement-witness")).unwrap(),
            b"replacement directory"
        );

        std::fs::remove_file(identity_lock_path).unwrap();
        std::fs::remove_file(legacy_lock_path).unwrap();
        std::fs::remove_dir_all(&root).unwrap();
    }
}
