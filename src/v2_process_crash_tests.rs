// Copyright 2026 Alexander Orlov <alexander.orlov@loxal.net>

//! Opt-in real-process crash tests for the v2 root-last protocol, offline GC,
//! and explicit v1-to-v2 migration.
//!
//! These tests prove behavior across a userspace process SIGKILL. They do not
//! simulate power loss, torn writes, controller caches, or storage-provider
//! reordering. On macOS they exercise Rust's current `File::sync_all` path, not
//! `F_FULLFSYNC`. Run the ignored platform tests with an explicit path on the
//! filesystem under test:
//!
//! ```fish
//! set -x ZDRIVE_RUN_PROCESS_CRASH_TESTS 1
//! set -x ZDRIVE_CRASH_TEST_ROOT '/path/on/test/filesystem'
//! # macOS/APFS:
//! cargo test --locked 'v2::process_crash_tests::subprocess_sigkill_v2_durability_apfs' -- --exact --ignored --nocapture
//! cargo test --locked 'v2::process_crash_tests::subprocess_sigkill_v2_gc_apfs' -- --exact --ignored --nocapture
//! cargo test --locked 'v2::process_crash_tests::subprocess_sigkill_v1_to_v2_migration_apfs' -- --exact --ignored --nocapture
//! # Linux/ext4:
//! cargo test --locked 'v2::process_crash_tests::subprocess_sigkill_v2_durability_ext4' -- --exact --ignored --nocapture
//! cargo test --locked 'v2::process_crash_tests::subprocess_sigkill_v2_gc_ext4' -- --exact --ignored --nocapture
//! cargo test --locked 'v2::process_crash_tests::subprocess_sigkill_v1_to_v2_migration_ext4' -- --exact --ignored --nocapture
//! ```
//!
//! Each case injects one real process death, verifies recognized provider
//! conflict evidence in another process, then completes in a fresh verifier.
//! Local APFS/ext4 gates remove their synthetic sibling after that proof. The
//! real File Provider mode instead clones the death state, permanently retains
//! the conflict-bearing copy, and recovers only the separate clean copy.
//! The dedicated GC and migration matrices repeat real process deaths from the
//! canonical post-rename and pending-root recovery states. They do not claim a
//! Cartesian matrix of every synthetically malformed recovery artifact;
//! deterministic returned-error tests cover those validation paths. The GC
//! matrices additionally prove that an orphan has exactly one byte-identical
//! live or quarantine name after every injected death. The migration matrix
//! proves that v1 source bytes remain exact and any visible v2 root
//! authenticates a complete migrated generation.

use super::*;
use crate::crypto::{
    FORMAT_VERSION as KDF_FORMAT_VERSION, KdfParams, RecoveryFingerprint, SALT_LEN, derive_key,
    encrypt_blob, encrypt_index, load_kdf_with_fingerprint,
};
use crate::fault::{DurabilityCheckpoint, DurabilityEvent, FaultInjectionGuard};
use crate::fs::{
    DirChild, DiskIndex, InodeEntry, InodeKind, ZeroTrustFs, ensure_no_index_siblings,
    validate_disk_index_v2, validate_reachable_v2_files,
};
use std::collections::{BTreeMap, HashMap};
#[cfg(target_os = "macos")]
use std::ffi::CString;
use std::ffi::OsStr;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
use std::os::unix::process::ExitStatusExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

const RUN_ENV: &str = "ZDRIVE_RUN_PROCESS_CRASH_TESTS";
const ROOT_ENV: &str = "ZDRIVE_CRASH_TEST_ROOT";
const CHILD_MODE_ENV: &str = "ZDRIVE_PROCESS_CRASH_CHILD_MODE";
const CHILD_STORE_ENV: &str = "ZDRIVE_PROCESS_CRASH_CHILD_STORE";
const CHILD_CHECKPOINT_ENV: &str = "ZDRIVE_PROCESS_CRASH_CHILD_CHECKPOINT";
const CHILD_EVENT_ENV: &str = "ZDRIVE_PROCESS_CRASH_CHILD_EVENT";
const CHILD_CONTEXT_ENV: &str = "ZDRIVE_PROCESS_CRASH_CHILD_CONTEXT";
const CHILD_BASELINE_ENV: &str = "ZDRIVE_PROCESS_CRASH_CHILD_BASELINE";
const CHILD_PLAN_ID_ENV: &str = "ZDRIVE_PROCESS_CRASH_CHILD_PLAN_ID";
const CHILD_CANDIDATE_ENV: &str = "ZDRIVE_PROCESS_CRASH_CHILD_CANDIDATE";
const CHILD_TEST_NAME: &str = "v2::process_crash_tests::subprocess_crash_child";
const PASSPHRASE: &str = "v2-process-crash-passphrase";
const MIGRATION_PASSPHRASE: &str = "v2-process-migration-passphrase";
const CONFLICT_SIBLING_NAME: &str = "_root (conflicted copy).age";
const CONFLICT_SIBLING_BYTES: &[u8] =
    b"recognized provider root-sibling evidence must survive fail-closed recovery";
const FILE_NAME: &str = "generation.txt";
const NEW_CONTENT: &[u8] = b"complete authenticated new generation";
const ORPHAN_CONTENT: &[u8] = b"authenticated unreachable object retained across real SIGKILL";
const MIGRATION_FILE_NAME: &str = "legacy.bin";
const MIGRATION_BLOB_NAME: &str = "000001.age";
const MIGRATION_CONTENT: &[u8] = b"complete authenticated v1 source retained across real SIGKILL";
const PASSIVE_EVIDENCE_NAME: &str = "provider-evidence.keep";
const PASSIVE_EVIDENCE_BYTES: &[u8] = b"never discard unrelated provider evidence";
const CHILD_TIMEOUT: Duration = Duration::from_secs(30);
const COPY_TIMEOUT: Duration = Duration::from_secs(300);
const MAX_COPY_ENTRIES: usize = 250_000;
const MAX_COPY_DEPTH: usize = 128;
const MAX_COPY_FILE_BYTES: u64 = 65 * 1024 * 1024;
const MAX_COPY_TOTAL_BYTES: u64 = 4 * 1024 * 1024 * 1024;

static TEST_ID: AtomicU64 = AtomicU64::new(0);

fn test_kdf() -> KdfParams {
    KdfParams {
        format_version: KDF_FORMAT_VERSION,
        algorithm: "argon2id".to_string(),
        salt: vec![23; SALT_LEN],
        m_cost: 8,
        t_cost: 1,
        p_cost: 1,
    }
}

fn kdf_bytes() -> Vec<u8> {
    serde_json::to_vec_pretty(&test_kdf()).expect("serialize process crash test KDF")
}

fn test_key() -> [u8; 32] {
    derive_key(PASSPHRASE, &test_kdf())
}

fn kdf_fingerprint() -> RecoveryFingerprint {
    RecoveryFingerprint::Exact { bytes: kdf_bytes() }
}

fn index_with_empty_file(name: &str) -> DiskIndex {
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

fn commit_index(
    directory: &Path,
    key: &[u8; 32],
    index: &DiskIndex,
    previous: Option<&CommitState>,
) -> std::io::Result<CommitState> {
    let json = serde_json::to_vec(index).expect("serialize process crash test index");
    commit(directory, key, &json, previous, &kdf_fingerprint())
}

fn normal_write_commit(directory: &Path) -> std::io::Result<()> {
    // Exercise the same bounded dirty-chunk overlay and root-last flush that a
    // mounted FUSE write/fsync uses. Calling the lower-level v2 primitives here
    // would leave the overlay's acknowledgment and state-swap behavior outside
    // the real-process crash matrix.
    let mut ztfs = ZeroTrustFs::new_v2(PASSPHRASE, directory.to_path_buf());
    ztfs.stop_debounce_thread_for_test();
    ztfs.open_inode(2)?;
    ztfs.write_inode_content(2, 0, NEW_CONTENT)?;
    ztfs.fsync_inode(2)?;
    ztfs.release_inode(2)
}

fn write_durable(path: &Path, bytes: &[u8]) {
    let mut options = OpenOptions::new();
    options.create_new(true).write(true);
    let mut file = options.open(path).expect("create durable test fixture");
    file.write_all(bytes).expect("write durable test fixture");
    file.sync_all().expect("sync durable test fixture");
    drop(file);
    File::open(path.parent().expect("fixture parent"))
        .expect("open fixture directory")
        .sync_all()
        .expect("sync fixture directory");
}

fn install_provider_conflict_evidence(store: &Path) {
    write_durable(&store.join(CONFLICT_SIBLING_NAME), CONFLICT_SIBLING_BYTES);
}

fn remove_provider_conflict_after_verification(store: &Path) {
    // Test-harness-only reconciliation: production recovery must never remove
    // a provider sibling. The dedicated verifier has already proved the bytes
    // survived unchanged; removing and directory-fsyncing this fixture is what
    // lets the independent old-or-new verifier inspect the underlying crash.
    fs::remove_file(store.join(CONFLICT_SIBLING_NAME))
        .expect("explicitly remove verified conflict fixture before recovery proof");
    File::open(store)
        .expect("open store after removing conflict fixture")
        .sync_all()
        .expect("sync explicit conflict-fixture removal");
}

#[derive(Default)]
struct CopyBudget {
    entries: usize,
    total_bytes: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum CrashCopySnapshotEntry {
    Directory,
    File {
        len: u64,
        links: u64,
        digest: [u8; 32],
    },
}

type CrashCopySnapshot = BTreeMap<PathBuf, CrashCopySnapshotEntry>;

fn ensure_copy_deadline(deadline: Instant) -> io::Result<()> {
    if Instant::now() >= deadline {
        Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "descriptor-rooted crash fixture copy timed out",
        ))
    } else {
        Ok(())
    }
}

fn crash_copy_identity(file: &File) -> io::Result<(u64, u64, bool)> {
    let metadata = file.metadata()?;
    if metadata.ino() == 0 || (!metadata.is_dir() && !metadata.is_file()) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "crash fixture entry has no stable regular-file or directory identity",
        ));
    }
    Ok((metadata.dev(), metadata.ino(), metadata.is_dir()))
}

fn verify_crash_copy_entry(
    parent: &File,
    name: &OsStr,
    retained: &File,
    is_directory: bool,
) -> io::Result<()> {
    let retained_before = crash_copy_identity(retained)?;
    if retained_before.2 != is_directory {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "retained crash fixture entry changed kind",
        ));
    }
    let flags = if is_directory {
        libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NONBLOCK
    } else {
        libc::O_RDONLY | libc::O_NONBLOCK
    };
    let visible = openat_nofollow(parent, name, flags, 0)?;
    if crash_copy_identity(&visible)? != retained_before
        || crash_copy_identity(retained)? != retained_before
    {
        return Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "crash fixture entry changed identity during copy",
        ));
    }
    Ok(())
}

fn create_crash_copy_directory(parent: &File, name: &OsStr) -> io::Result<File> {
    let name_c = c_name(name, "crash fixture destination directory")?;
    let status = unsafe { libc::mkdirat(parent.as_raw_fd(), name_c.as_ptr(), 0o700) };
    if status != 0 {
        return Err(io::Error::last_os_error());
    }
    openat_nofollow(
        parent,
        name,
        libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NONBLOCK,
        0,
    )
}

fn copy_crash_regular_file(
    source_parent: &File,
    destination_parent: &File,
    name: &OsStr,
    deadline: Instant,
    budget: &mut CopyBudget,
) -> io::Result<()> {
    let mut source = openat_nofollow(source_parent, name, libc::O_RDONLY | libc::O_NONBLOCK, 0)?;
    let before = source.metadata()?;
    if !before.is_file() || before.nlink() == 0 || before.len() > MAX_COPY_FILE_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "crash fixture source is not a bounded linked regular file",
        ));
    }
    budget.total_bytes = budget
        .total_bytes
        .checked_add(before.len())
        .ok_or_else(|| io::Error::from_raw_os_error(libc::EFBIG))?;
    if budget.total_bytes > MAX_COPY_TOTAL_BYTES {
        return Err(io::Error::from_raw_os_error(libc::EFBIG));
    }
    let mut destination = openat_nofollow(
        destination_parent,
        name,
        libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL,
        0o600,
    )?;
    let mut copied = 0u64;
    let mut buffer = [0u8; 64 * 1024];
    loop {
        ensure_copy_deadline(deadline)?;
        let read = source.read(&mut buffer)?;
        ensure_copy_deadline(deadline)?;
        if read == 0 {
            break;
        }
        copied = copied
            .checked_add(read as u64)
            .ok_or_else(|| io::Error::from_raw_os_error(libc::EFBIG))?;
        if copied > before.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "crash fixture source grew while being copied",
            ));
        }
        destination.write_all(&buffer[..read])?;
    }
    let after = source.metadata()?;
    if copied != before.len()
        || !after.is_file()
        || after.nlink() != before.nlink()
        || after.len() != before.len()
        || (after.dev(), after.ino()) != (before.dev(), before.ino())
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "crash fixture source changed while being copied",
        ));
    }
    destination.sync_all()?;
    let destination_metadata = destination.metadata()?;
    if !destination_metadata.is_file()
        || destination_metadata.nlink() != 1
        || destination_metadata.len() != copied
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "crash fixture destination changed before its file sync completed",
        ));
    }
    verify_crash_copy_entry(source_parent, name, &source, false)?;
    verify_crash_copy_entry(destination_parent, name, &destination, false)
}

fn snapshot_crash_regular_file(
    parent: &File,
    name: &OsStr,
    deadline: Instant,
    budget: &mut CopyBudget,
) -> io::Result<CrashCopySnapshotEntry> {
    let mut file = openat_nofollow(parent, name, libc::O_RDONLY | libc::O_NONBLOCK, 0)?;
    let before = file.metadata()?;
    if !before.is_file() || before.nlink() == 0 || before.len() > MAX_COPY_FILE_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "crash fixture snapshot encountered an unbounded or unlinked non-regular file",
        ));
    }
    budget.total_bytes = budget
        .total_bytes
        .checked_add(before.len())
        .ok_or_else(|| io::Error::from_raw_os_error(libc::EFBIG))?;
    if budget.total_bytes > MAX_COPY_TOTAL_BYTES {
        return Err(io::Error::from_raw_os_error(libc::EFBIG));
    }

    let mut hasher = Blake2s256::new();
    let mut read_total = 0u64;
    let mut buffer = [0u8; 64 * 1024];
    loop {
        ensure_copy_deadline(deadline)?;
        let read = file.read(&mut buffer)?;
        ensure_copy_deadline(deadline)?;
        if read == 0 {
            break;
        }
        read_total = read_total
            .checked_add(read as u64)
            .ok_or_else(|| io::Error::from_raw_os_error(libc::EFBIG))?;
        if read_total > before.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "crash fixture snapshot source grew while it was read",
            ));
        }
        hasher.update(&buffer[..read]);
    }
    let after = file.metadata()?;
    if read_total != before.len()
        || !after.is_file()
        || after.nlink() != before.nlink()
        || after.len() != before.len()
        || (after.dev(), after.ino()) != (before.dev(), before.ino())
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "crash fixture snapshot file changed while it was read",
        ));
    }
    verify_crash_copy_entry(parent, name, &file, false)?;
    Ok(CrashCopySnapshotEntry::File {
        len: before.len(),
        links: before.nlink(),
        digest: hasher.finalize().into(),
    })
}

fn snapshot_crash_directory_contents(
    source: &File,
    relative: &Path,
    depth: usize,
    deadline: Instant,
    budget: &mut CopyBudget,
    snapshot: &mut CrashCopySnapshot,
) -> io::Result<()> {
    if depth > MAX_COPY_DEPTH {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "crash fixture snapshot exceeded its directory depth limit",
        ));
    }
    ensure_copy_deadline(deadline)?;
    for_each_directory_entry_name(source, |name| {
        ensure_copy_deadline(deadline)?;
        budget.entries = budget
            .entries
            .checked_add(1)
            .ok_or_else(|| io::Error::from_raw_os_error(libc::EFBIG))?;
        if budget.entries > MAX_COPY_ENTRIES {
            return Err(io::Error::from_raw_os_error(libc::EFBIG));
        }
        let child_relative = relative.join(name);
        let entry = match openat_nofollow(
            source,
            name,
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NONBLOCK,
            0,
        ) {
            Ok(source_child) => {
                verify_crash_copy_entry(source, name, &source_child, true)?;
                snapshot_crash_directory_contents(
                    &source_child,
                    &child_relative,
                    depth + 1,
                    deadline,
                    budget,
                    snapshot,
                )?;
                verify_crash_copy_entry(source, name, &source_child, true)?;
                CrashCopySnapshotEntry::Directory
            }
            Err(error) if error.raw_os_error() == Some(libc::ENOTDIR) => {
                snapshot_crash_regular_file(source, name, deadline, budget)?
            }
            Err(error) => return Err(error),
        };
        if snapshot.insert(child_relative, entry).is_some() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "crash fixture snapshot repeated one relative path",
            ));
        }
        Ok(())
    })
}

fn snapshot_crash_directory(source: &File, deadline: Instant) -> io::Result<CrashCopySnapshot> {
    let mut budget = CopyBudget::default();
    let mut snapshot = BTreeMap::new();
    snapshot_crash_directory_contents(
        source,
        Path::new(""),
        0,
        deadline,
        &mut budget,
        &mut snapshot,
    )?;
    Ok(snapshot)
}

fn verify_crash_copy_snapshots(
    source: &CrashCopySnapshot,
    destination: &CrashCopySnapshot,
) -> io::Result<()> {
    if source.len() != destination.len() {
        return Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "crash fixture destination inventory differs from its stable source",
        ));
    }
    for (path, source_entry) in source {
        let Some(destination_entry) = destination.get(path) else {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                format!("crash fixture destination omitted {path:?}"),
            ));
        };
        let matches = match (source_entry, destination_entry) {
            (CrashCopySnapshotEntry::Directory, CrashCopySnapshotEntry::Directory) => true,
            (
                CrashCopySnapshotEntry::File {
                    len: source_len,
                    digest: source_digest,
                    ..
                },
                CrashCopySnapshotEntry::File {
                    len: destination_len,
                    links: 1,
                    digest: destination_digest,
                },
            ) => source_len == destination_len && source_digest == destination_digest,
            _ => false,
        };
        if !matches {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                format!("crash fixture destination changed type or bytes at {path:?}"),
            ));
        }
    }
    Ok(())
}

fn copy_crash_directory_contents(
    source: &File,
    destination: &File,
    depth: usize,
    deadline: Instant,
    budget: &mut CopyBudget,
) -> io::Result<()> {
    if depth > MAX_COPY_DEPTH {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "crash fixture copy exceeded its directory depth limit",
        ));
    }
    ensure_copy_deadline(deadline)?;
    for_each_directory_entry_name(source, |name| {
        ensure_copy_deadline(deadline)?;
        budget.entries = budget
            .entries
            .checked_add(1)
            .ok_or_else(|| io::Error::from_raw_os_error(libc::EFBIG))?;
        if budget.entries > MAX_COPY_ENTRIES {
            return Err(io::Error::from_raw_os_error(libc::EFBIG));
        }
        match openat_nofollow(
            source,
            name,
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NONBLOCK,
            0,
        ) {
            Ok(source_child) => {
                let destination_child = create_crash_copy_directory(destination, name)?;
                verify_crash_copy_entry(source, name, &source_child, true)?;
                verify_crash_copy_entry(destination, name, &destination_child, true)?;
                copy_crash_directory_contents(
                    &source_child,
                    &destination_child,
                    depth + 1,
                    deadline,
                    budget,
                )?;
                destination_child.sync_all()?;
                verify_crash_copy_entry(source, name, &source_child, true)?;
                verify_crash_copy_entry(destination, name, &destination_child, true)
            }
            Err(error) if error.raw_os_error() == Some(libc::ENOTDIR) => {
                copy_crash_regular_file(source, destination, name, deadline, budget)
            }
            Err(error) => Err(error),
        }
    })?;
    destination.sync_all()
}

fn copy_directory_durable_at(
    parent: &File,
    source_name: &OsStr,
    destination_name: &OsStr,
) -> io::Result<()> {
    if source_name == destination_name {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "crash fixture copy requires distinct source and destination names",
        ));
    }
    let deadline = Instant::now()
        .checked_add(COPY_TIMEOUT)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "invalid copy timeout"))?;
    let source_directory = openat_nofollow(
        parent,
        source_name,
        libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NONBLOCK,
        0,
    )?;
    let source_identity = crash_copy_identity(&source_directory)?;
    let source_before = snapshot_crash_directory(&source_directory, deadline)?;
    let destination_directory = create_crash_copy_directory(parent, destination_name)?;
    let mut budget = CopyBudget::default();
    copy_crash_directory_contents(
        &source_directory,
        &destination_directory,
        0,
        deadline,
        &mut budget,
    )?;
    destination_directory.sync_all()?;
    parent.sync_all()?;
    let source_after = snapshot_crash_directory(&source_directory, deadline)?;
    if source_after != source_before {
        return Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "crash fixture source inventory or bytes changed during durable copy",
        ));
    }
    drop(source_after);
    let destination_snapshot = snapshot_crash_directory(&destination_directory, deadline)?;
    verify_crash_copy_snapshots(&source_before, &destination_snapshot)?;
    verify_crash_copy_entry(parent, destination_name, &destination_directory, true)?;
    verify_crash_copy_entry(parent, source_name, &source_directory, true)?;
    if crash_copy_identity(&source_directory)? != source_identity {
        return Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "crash fixture source root changed identity during copy",
        ));
    }
    Ok(())
}

fn copy_directory_durable(source: &Path, destination: &Path) {
    let result = (|| -> io::Result<()> {
        let source_parent = source.parent().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "crash fixture source has no parent",
            )
        })?;
        let destination_parent = destination.parent().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "crash fixture destination has no parent",
            )
        })?;
        if source_parent != destination_parent {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "crash fixture source and destination must share one pinned parent",
            ));
        }
        let source_name = source.file_name().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "crash fixture source has no final component",
            )
        })?;
        let destination_name = destination.file_name().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "crash fixture destination has no final component",
            )
        })?;
        let parent = open_directory_nofollow(source_parent)?;
        copy_directory_durable_at(&parent, source_name, destination_name)
    })();
    result.unwrap_or_else(|error| {
        panic!(
            "descriptor-rooted durable copy {} -> {} failed closed: {error}",
            source.display(),
            destination.display()
        )
    });
}

fn create_baseline(path: &Path) {
    fs::create_dir(path).expect("create process crash baseline");
    write_durable(&path.join("_kdf.json"), &kdf_bytes());
    commit_index(path, &test_key(), &index_with_empty_file(FILE_NAME), None)
        .expect("commit process crash baseline");
}

fn create_gc_baseline(path: &Path) -> (String, String) {
    create_baseline(path);
    let orphan = write_object(path, &test_key(), ObjectKind::Data, ORPHAN_CONTENT)
        .expect("write immutable orphan fixture");
    write_durable(&path.join(PASSIVE_EVIDENCE_NAME), PASSIVE_EVIDENCE_BYTES);
    let candidate = object_name(&orphan.id);
    let preview = gc_preview(path, PASSPHRASE).expect("preview orphan fixture");
    assert_eq!(preview.candidate_objects, 1);
    assert_eq!(preview.candidate_names, std::slice::from_ref(&candidate));
    (preview.plan_id.expect("v2 GC preview plan ID"), candidate)
}

fn migration_kdf() -> KdfParams {
    KdfParams {
        format_version: KDF_FORMAT_VERSION,
        algorithm: "argon2id".to_string(),
        salt: vec![41; SALT_LEN],
        m_cost: 8,
        t_cost: 1,
        p_cost: 1,
    }
}

fn migration_index() -> DiskIndex {
    let mut index = index_with_empty_file(MIGRATION_FILE_NAME);
    let file = index.inodes.get_mut(&2).expect("migration file inode");
    file.disk_filename = MIGRATION_BLOB_NAME.to_string();
    file.size = MIGRATION_CONTENT.len() as u64;
    index.next_file_id = 2;
    index
}

fn create_migration_baseline(path: &Path) {
    fs::create_dir(path).expect("create migration process crash baseline");
    let kdf = migration_kdf();
    let key = derive_key(MIGRATION_PASSPHRASE, &kdf);
    write_durable(
        &path.join("_kdf.json"),
        &serde_json::to_vec_pretty(&kdf).expect("serialize migration KDF"),
    );
    write_durable(
        &path.join(MIGRATION_BLOB_NAME),
        &encrypt_blob(&key, MIGRATION_BLOB_NAME, MIGRATION_CONTENT)
            .expect("encrypt migration source blob"),
    );
    write_durable(
        &path.join("_index.age"),
        &encrypt_index(
            &key,
            &serde_json::to_vec(&migration_index()).expect("serialize migration v1 index"),
        )
        .expect("encrypt migration v1 index"),
    );
    write_durable(&path.join(PASSIVE_EVIDENCE_NAME), PASSIVE_EVIDENCE_BYTES);
}

fn assert_passive_evidence(store: &Path) {
    assert_eq!(
        fs::read(store.join(PASSIVE_EVIDENCE_NAME)).expect("read passive provider evidence"),
        PASSIVE_EVIDENCE_BYTES,
        "an unrelated provider artifact was changed or discarded"
    );
}

fn gc_object_paths(store: &Path, plan_id: &str, candidate: &str) -> (PathBuf, PathBuf) {
    let namespace = store.join(OBJECT_DIRECTORY);
    (
        namespace.join(OBJECTS_DIRECTORY).join(candidate),
        namespace
            .join("gc")
            .join(plan_id)
            .join("quarantine")
            .join(candidate),
    )
}

fn assert_gc_candidate_has_one_complete_copy(
    store: &Path,
    baseline: &Path,
    plan_id: &str,
    candidate: &str,
) -> (bool, bool) {
    assert_eq!(
        fs::read(store.join(ROOT_FILE)).expect("read GC case root"),
        fs::read(baseline.join(ROOT_FILE)).expect("read GC baseline root"),
        "offline GC changed the authenticated root"
    );
    assert_passive_evidence(store);
    let (source, quarantine) = gc_object_paths(store, plan_id, candidate);
    let source_exists = source.exists();
    let quarantine_exists = quarantine.exists();
    assert_ne!(
        source_exists, quarantine_exists,
        "orphan must have exactly one complete namespace name after a crash"
    );
    let visible = if source_exists { &source } else { &quarantine };
    assert_eq!(
        fs::read(visible).expect("read crash-visible orphan bytes"),
        fs::read(
            baseline
                .join(OBJECT_DIRECTORY)
                .join(OBJECTS_DIRECTORY)
                .join(candidate),
        )
        .expect("read baseline orphan bytes"),
        "orphan ciphertext changed across namespace mutation"
    );
    (source_exists, quarantine_exists)
}

fn assert_migration_source_evidence(store: &Path, baseline: &Path) {
    for name in ["_kdf.json", "_index.age", MIGRATION_BLOB_NAME] {
        assert_eq!(
            fs::read(store.join(name)).unwrap_or_else(|error| panic!("read {name}: {error}")),
            fs::read(baseline.join(name))
                .unwrap_or_else(|error| panic!("read baseline {name}: {error}")),
            "migration changed retained v1 evidence {name}"
        );
    }
    assert_passive_evidence(store);
}

fn event_name(event: DurabilityEvent) -> &'static str {
    match event {
        DurabilityEvent::Write => "write",
        DurabilityEvent::FileSync => "file-sync",
        DurabilityEvent::Rename => "rename",
        DurabilityEvent::DirectorySync => "directory-sync",
        DurabilityEvent::Cleanup => "cleanup",
        DurabilityEvent::Recovery => "recovery",
    }
}

fn parse_event(value: &str) -> DurabilityEvent {
    match value {
        "write" => DurabilityEvent::Write,
        "file-sync" => DurabilityEvent::FileSync,
        "rename" => DurabilityEvent::Rename,
        "directory-sync" => DurabilityEvent::DirectorySync,
        "cleanup" => DurabilityEvent::Cleanup,
        "recovery" => DurabilityEvent::Recovery,
        _ => panic!("unknown durability event {value:?}"),
    }
}

fn wait_with_timeout(mut child: Child) -> Output {
    let deadline = Instant::now() + CHILD_TIMEOUT;
    loop {
        match child.try_wait().expect("poll crash-test child") {
            Some(status) => {
                let mut stdout = Vec::new();
                let mut stderr = Vec::new();
                child
                    .stdout
                    .take()
                    .expect("capture crash-test child stdout")
                    .read_to_end(&mut stdout)
                    .expect("read crash-test child stdout");
                child
                    .stderr
                    .take()
                    .expect("capture crash-test child stderr")
                    .read_to_end(&mut stderr)
                    .expect("read crash-test child stderr");
                return Output {
                    status,
                    stdout,
                    stderr,
                };
            }
            None if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(10)),
            None => {
                child.kill().expect("kill hung crash-test child");
                let _ = child.wait();
                panic!("crash-test child exceeded {CHILD_TIMEOUT:?}");
            }
        }
    }
}

fn child_command(mode: &str, store: &Path) -> Command {
    let executable = std::env::current_exe().expect("locate current Rust test executable");
    let mut command = Command::new(executable);
    command
        .arg("--exact")
        .arg(CHILD_TEST_NAME)
        .arg("--nocapture")
        .arg("--test-threads=1")
        .env(CHILD_MODE_ENV, mode)
        .env(CHILD_STORE_ENV, store)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    command
}

fn kill_child(store: &Path, checkpoint: usize, expected: &DurabilityCheckpoint) -> Output {
    let child = child_command("kill-commit", store)
        .env(CHILD_CHECKPOINT_ENV, checkpoint.to_string())
        .env(CHILD_EVENT_ENV, event_name(expected.event))
        .env(CHILD_CONTEXT_ENV, &expected.context)
        .spawn()
        .expect("spawn commit crash-test child");
    wait_with_timeout(child)
}

fn kill_recovery_child(store: &Path, checkpoint: usize, expected: &DurabilityCheckpoint) -> Output {
    let child = child_command("kill-recovery", store)
        .env(CHILD_CHECKPOINT_ENV, checkpoint.to_string())
        .env(CHILD_EVENT_ENV, event_name(expected.event))
        .env(CHILD_CONTEXT_ENV, &expected.context)
        .spawn()
        .expect("spawn recovery crash-test child");
    wait_with_timeout(child)
}

fn kill_named_operation_child(
    mode: &str,
    store: &Path,
    checkpoint: usize,
    expected: &DurabilityCheckpoint,
    plan_id: Option<&str>,
    candidate: Option<&str>,
) -> Output {
    let mut command = child_command(mode, store);
    command
        .env(CHILD_CHECKPOINT_ENV, checkpoint.to_string())
        .env(CHILD_EVENT_ENV, event_name(expected.event))
        .env(CHILD_CONTEXT_ENV, &expected.context);
    if let Some(plan_id) = plan_id {
        command.env(CHILD_PLAN_ID_ENV, plan_id);
    }
    if let Some(candidate) = candidate {
        command.env(CHILD_CANDIDATE_ENV, candidate);
    }
    let child = command.spawn().expect("spawn operation crash-test child");
    wait_with_timeout(child)
}

fn verify_child(store: &Path, baseline: &Path, mode: &str) {
    let child = child_command(mode, store)
        .env(CHILD_BASELINE_ENV, baseline)
        .spawn()
        .expect("spawn fresh crash verifier");
    let output = wait_with_timeout(child);
    assert!(
        output.status.success(),
        "fresh verifier failed: status={} stdout={} stderr={}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn verify_operation_child(
    store: &Path,
    baseline: &Path,
    mode: &str,
    plan_id: Option<&str>,
    candidate: Option<&str>,
) {
    let mut command = child_command(mode, store);
    command.env(CHILD_BASELINE_ENV, baseline);
    if let Some(plan_id) = plan_id {
        command.env(CHILD_PLAN_ID_ENV, plan_id);
    }
    if let Some(candidate) = candidate {
        command.env(CHILD_CANDIDATE_ENV, candidate);
    }
    let output = wait_with_timeout(
        command
            .spawn()
            .expect("spawn fresh operation crash verifier"),
    );
    assert!(
        output.status.success(),
        "fresh {mode} verifier failed: status={} stdout={} stderr={}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn assert_sigkill(output: &Output, checkpoint: usize, expected: &DurabilityCheckpoint) {
    assert_eq!(
        output.status.signal(),
        Some(libc::SIGKILL),
        "checkpoint {checkpoint} did not terminate by SIGKILL: status={} stdout={} stderr={}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let marker = format!(
        "ZDRIVE_SIGKILL_CHECKPOINT\t{checkpoint}\t{:?}\t{}",
        expected.event, expected.context
    );
    assert!(
        String::from_utf8_lossy(&output.stderr).contains(&marker),
        "checkpoint {checkpoint} emitted no exact kill marker: stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
}

fn verify_conflict_evidence(store: &Path) {
    let error = ensure_no_index_siblings(store)
        .expect_err("recognized provider root sibling must make the store ambiguous");
    assert_eq!(error.kind(), std::io::ErrorKind::AlreadyExists);
    assert!(
        error.to_string().contains(CONFLICT_SIBLING_NAME),
        "conflict detector did not identify the provider root sibling: {error}"
    );
    let root_before = fs::read(store.join(ROOT_FILE))
        .expect("read canonical root before fail-closed conflict recovery");
    let had_pending_manifest = store.join(WRITE_MANIFEST).exists();
    match recover(store, &test_key(), &kdf_fingerprint()) {
        Err(error) => assert!(
            error.to_string().contains("cloud-conflict"),
            "recovery failed for an unexpected reason: {error}"
        ),
        Ok(false) if !had_pending_manifest => {}
        Ok(result) => panic!(
            "recovery returned {result} despite recognized conflict evidence and pending={had_pending_manifest}"
        ),
    }
    assert_eq!(
        fs::read(store.join(ROOT_FILE))
            .expect("read canonical root after fail-closed conflict recovery"),
        root_before,
        "recovery changed the canonical root despite recognized provider conflict evidence"
    );
    assert_eq!(
        fs::read(store.join(CONFLICT_SIBLING_NAME))
            .expect("read retained provider root-sibling evidence"),
        CONFLICT_SIBLING_BYTES,
        "provider root-sibling evidence was changed or discarded"
    );
}

fn verify_complete_new_generation(store: &Path, baseline: &Path) {
    let key = test_key();
    let (index, state) = load(store, &key).expect("load authenticated new generation");
    validate_disk_index_v2(&index).expect("validate complete new-generation index structure");
    validate_reachable_v2_files(store, &key, &index)
        .expect("validate every file and immutable object reachable from the new generation");
    let (_old_index, old_state) =
        load(baseline, &key).expect("load authenticated baseline generation");
    assert_eq!(state.number, 2, "new root did not expose generation two");
    assert_eq!(state.parent, Some(old_state.generation));
    assert_eq!(state.origin, Some(old_state.generation));
    assert_eq!(state.lineage_id, old_state.lineage_id);
    let entry = &index.inodes[&2];
    assert_eq!(entry.name, FILE_NAME);
    assert_eq!(index.children[&1][0].name, FILE_NAME);
    assert_eq!(entry.size, NEW_CONTENT.len() as u64);
    validate_reachable_file(store, &key, &entry.disk_filename, entry.size)
        .expect("validate every immutable object in new file generation");
    assert_eq!(
        read_file_range(
            store,
            &key,
            &entry.disk_filename,
            entry.size,
            0,
            entry.size as usize,
        )
        .expect("read complete authenticated new file generation"),
        NEW_CONTENT
    );
}

/// Authenticate the generation selected by the root exactly as it was left by
/// SIGKILL, before recovery is allowed to mutate any name. Returning `false`
/// means the byte-identical old root was visible; `true` means the complete
/// authenticated new generation was visible.
fn verify_crash_visible_generation(store: &Path, baseline: &Path) -> bool {
    let root = fs::read(store.join(ROOT_FILE)).expect("read crash-visible canonical root");
    let old_root =
        fs::read(baseline.join(ROOT_FILE)).expect("read byte-identical expected old root");
    if root == old_root {
        let (index, _state) =
            load(store, &test_key()).expect("authenticate crash-visible old generation");
        assert_eq!(
            index,
            index_with_empty_file(FILE_NAME),
            "byte-identical old root selected unexpected metadata"
        );
        validate_disk_index_v2(&index).expect("validate crash-visible old index structure");
        validate_reachable_v2_files(store, &test_key(), &index)
            .expect("validate every object reachable from the crash-visible old generation");
        false
    } else {
        verify_complete_new_generation(store, baseline);
        true
    }
}

fn child_checkpoint_from_env() -> (usize, DurabilityCheckpoint) {
    let checkpoint = std::env::var(CHILD_CHECKPOINT_ENV)
        .expect("child checkpoint environment")
        .parse()
        .expect("numeric child checkpoint");
    let event = parse_event(&std::env::var(CHILD_EVENT_ENV).expect("child event environment"));
    let context = std::env::var(CHILD_CONTEXT_ENV).expect("child context environment");
    (checkpoint, DurabilityCheckpoint { event, context })
}

fn verify_commit_after_crash(store: &Path, baseline: &Path) {
    let key = test_key();
    verify_crash_visible_generation(store, baseline);
    recover(store, &key, &kdf_fingerprint()).expect("recover commit after process SIGKILL");
    verify_crash_visible_generation(store, baseline);
}

fn verify_recovery_after_crash(store: &Path, baseline: &Path) {
    let key = test_key();
    verify_crash_visible_generation(store, baseline);
    recover(store, &key, &kdf_fingerprint()).expect("resume recovery after process SIGKILL");
    assert!(
        !recover(store, &key, &kdf_fingerprint()).expect("verify idempotent completed recovery"),
        "recovery left a canonical write manifest behind"
    );
    verify_complete_new_generation(store, baseline);
}

fn child_operation_values() -> (String, String) {
    (
        std::env::var(CHILD_PLAN_ID_ENV).expect("child GC plan ID environment"),
        std::env::var(CHILD_CANDIDATE_ENV).expect("child GC candidate environment"),
    )
}

fn assert_gc_store_authenticates(store: &Path) {
    let (index, _) = load(store, &test_key()).expect("load authenticated GC store root");
    validate_disk_index_v2(&index).expect("validate GC store index");
    validate_reachable_v2_files(store, &test_key(), &index)
        .expect("validate every object reachable from the GC store root");
}

fn verify_gc_conflict(
    store: &Path,
    baseline: &Path,
    plan_id: &str,
    candidate: &str,
    operation: &str,
) {
    let root_before = fs::read(store.join(ROOT_FILE)).expect("read root before GC conflict check");
    let error = ensure_no_index_siblings(store)
        .expect_err("recognized provider root sibling must block offline GC");
    assert_eq!(error.kind(), std::io::ErrorKind::AlreadyExists);
    let operation_error = match operation {
        "quarantine" => gc_quarantine(store, PASSPHRASE, plan_id)
            .expect_err("provider conflict must block GC quarantine"),
        "restore" => gc_restore(store, PASSPHRASE, plan_id)
            .expect_err("provider conflict must block GC restore"),
        _ => panic!("unknown GC conflict operation {operation:?}"),
    };
    assert!(
        operation_error.contains(CONFLICT_SIBLING_NAME)
            || operation_error.contains("conflict")
            || operation_error.contains("sibling"),
        "GC failed for an unexpected reason: {operation_error}"
    );
    assert_eq!(
        fs::read(store.join(ROOT_FILE)).expect("read root after GC conflict check"),
        root_before,
        "GC changed the root while conflict evidence was present"
    );
    assert_eq!(
        fs::read(store.join(CONFLICT_SIBLING_NAME)).expect("read GC conflict sibling"),
        CONFLICT_SIBLING_BYTES
    );
    assert_gc_candidate_has_one_complete_copy(store, baseline, plan_id, candidate);
}

fn verify_gc_quarantine_after_crash(store: &Path, baseline: &Path, plan_id: &str, candidate: &str) {
    let report = gc_quarantine(store, PASSPHRASE, plan_id)
        .expect("resume GC quarantine after process SIGKILL");
    assert_eq!(report.candidate_objects, 1);
    assert_eq!(report.candidate_names, [candidate.to_string()]);
    let report = gc_quarantine(store, PASSPHRASE, plan_id)
        .expect("verify idempotent completed GC quarantine");
    assert_eq!(report.candidate_objects, 1);
    let (source, quarantine) =
        assert_gc_candidate_has_one_complete_copy(store, baseline, plan_id, candidate);
    assert!(
        !source && quarantine,
        "completed quarantine left orphan live"
    );
    assert_gc_store_authenticates(store);
}

fn verify_gc_restore_after_crash(store: &Path, baseline: &Path, plan_id: &str, candidate: &str) {
    assert_eq!(
        gc_restore(store, PASSPHRASE, plan_id).expect("resume GC restore after process SIGKILL"),
        1
    );
    assert_eq!(
        gc_restore(store, PASSPHRASE, plan_id).expect("verify idempotent completed GC restore"),
        1
    );
    let (source, quarantine) =
        assert_gc_candidate_has_one_complete_copy(store, baseline, plan_id, candidate);
    assert!(
        source && !quarantine,
        "completed restore left orphan quarantined"
    );
    assert_gc_store_authenticates(store);
}

fn assert_valid_migration_visibility(store: &Path, baseline: &Path) {
    assert_migration_source_evidence(store, baseline);
    if !store.join(ROOT_FILE).exists() {
        return;
    }
    let (kdf, _) = load_kdf_with_fingerprint(store)
        .expect("load migration KDF")
        .expect("migration KDF exists");
    let key = derive_key(MIGRATION_PASSPHRASE, &kdf);
    let (index, _) = load(store, &key).expect("load crash-visible migrated v2 generation");
    validate_disk_index_v2(&index).expect("validate migrated v2 index");
    validate_reachable_v2_files(store, &key, &index)
        .expect("validate complete crash-visible migrated generation");
    let entry = index.inodes.get(&2).expect("migrated file inode");
    assert_eq!(entry.name, MIGRATION_FILE_NAME);
    assert_eq!(entry.size, MIGRATION_CONTENT.len() as u64);
    assert_eq!(
        read_file_range(
            store,
            &key,
            &entry.disk_filename,
            entry.size,
            0,
            entry.size as usize,
        )
        .expect("read complete migrated file"),
        MIGRATION_CONTENT
    );
}

fn verify_migration_conflict(store: &Path, baseline: &Path) {
    let root_before = fs::read(store.join(ROOT_FILE)).ok();
    let error = ensure_no_index_siblings(store)
        .expect_err("recognized provider root sibling must block migration resume");
    assert_eq!(error.kind(), std::io::ErrorKind::AlreadyExists);
    let migration_error = crate::v2_migrate::migrate_v1_to_v2(MIGRATION_PASSPHRASE, store)
        .expect_err("provider conflict must block migration resume");
    assert!(
        migration_error.contains(CONFLICT_SIBLING_NAME)
            || migration_error.contains("conflict")
            || migration_error.contains("sibling"),
        "migration failed for an unexpected reason: {migration_error}"
    );
    assert_eq!(fs::read(store.join(ROOT_FILE)).ok(), root_before);
    assert_eq!(
        fs::read(store.join(CONFLICT_SIBLING_NAME)).expect("read migration conflict sibling"),
        CONFLICT_SIBLING_BYTES
    );
    assert_valid_migration_visibility(store, baseline);
}

fn verify_migration_after_crash(store: &Path, baseline: &Path) {
    assert_valid_migration_visibility(store, baseline);
    crate::v2_migrate::migrate_v1_to_v2(MIGRATION_PASSPHRASE, store)
        .expect("resume v1-to-v2 migration after process SIGKILL");
    assert_valid_migration_visibility(store, baseline);
    assert!(store.join(crate::v2_migrate::PLAN_FILE).exists());
    assert!(store.join(crate::v2_migrate::COMPLETION_FILE).exists());
    assert!(store.join(crate::v2_migrate::PROGRESS_DIRECTORY).is_dir());
    assert!(!crate::v2_migrate::migration_pending(store).expect("inspect migration completion"));
    let root = fs::read(store.join(ROOT_FILE)).expect("read completed migration root");
    crate::v2_migrate::migrate_v1_to_v2(MIGRATION_PASSPHRASE, store)
        .expect("verify idempotent completed migration");
    assert_eq!(
        fs::read(store.join(ROOT_FILE)).expect("read verified migration root"),
        root,
        "completed migration resume rewrote the authenticated root"
    );
    assert_migration_source_evidence(store, baseline);
}

#[test]
fn subprocess_crash_child() {
    let Ok(mode) = std::env::var(CHILD_MODE_ENV) else {
        return;
    };
    let store = PathBuf::from(std::env::var_os(CHILD_STORE_ENV).expect("child store environment"));
    match mode.as_str() {
        "kill-commit" => {
            let (checkpoint, expected) = child_checkpoint_from_env();
            let _guard = FaultInjectionGuard::kill_at(checkpoint, expected);
            normal_write_commit(&store).expect("checkpoint must SIGKILL before commit returns");
            panic!("configured commit checkpoint was not reached");
        }
        "kill-recovery" => {
            let (checkpoint, expected) = child_checkpoint_from_env();
            let _guard = FaultInjectionGuard::kill_at(checkpoint, expected);
            recover(&store, &test_key(), &kdf_fingerprint())
                .expect("checkpoint must SIGKILL before recovery returns");
            panic!("configured recovery checkpoint was not reached");
        }
        "kill-gc-quarantine" => {
            let (checkpoint, expected) = child_checkpoint_from_env();
            let (plan_id, _) = child_operation_values();
            let _guard = FaultInjectionGuard::kill_at(checkpoint, expected);
            gc_quarantine(&store, PASSPHRASE, &plan_id)
                .expect("checkpoint must SIGKILL before GC quarantine returns");
            panic!("configured GC quarantine checkpoint was not reached");
        }
        "kill-gc-restore" => {
            let (checkpoint, expected) = child_checkpoint_from_env();
            let (plan_id, _) = child_operation_values();
            let _guard = FaultInjectionGuard::kill_at(checkpoint, expected);
            gc_restore(&store, PASSPHRASE, &plan_id)
                .expect("checkpoint must SIGKILL before GC restore returns");
            panic!("configured GC restore checkpoint was not reached");
        }
        "kill-migration" => {
            let (checkpoint, expected) = child_checkpoint_from_env();
            let _guard = FaultInjectionGuard::kill_at(checkpoint, expected);
            crate::v2_migrate::migrate_v1_to_v2(MIGRATION_PASSPHRASE, &store)
                .expect("checkpoint must SIGKILL before migration returns");
            panic!("configured migration checkpoint was not reached");
        }
        "verify-commit" => {
            let baseline =
                PathBuf::from(std::env::var_os(CHILD_BASELINE_ENV).expect("baseline environment"));
            verify_commit_after_crash(&store, &baseline);
        }
        "verify-recovery" => {
            let baseline =
                PathBuf::from(std::env::var_os(CHILD_BASELINE_ENV).expect("baseline environment"));
            verify_recovery_after_crash(&store, &baseline);
        }
        "verify-conflict" => verify_conflict_evidence(&store),
        "verify-gc-quarantine-conflict" | "verify-gc-restore-conflict" => {
            let baseline =
                PathBuf::from(std::env::var_os(CHILD_BASELINE_ENV).expect("baseline environment"));
            let (plan_id, candidate) = child_operation_values();
            let operation = if mode == "verify-gc-quarantine-conflict" {
                "quarantine"
            } else {
                "restore"
            };
            verify_gc_conflict(&store, &baseline, &plan_id, &candidate, operation);
        }
        "verify-gc-quarantine" | "verify-gc-restore" => {
            let baseline =
                PathBuf::from(std::env::var_os(CHILD_BASELINE_ENV).expect("baseline environment"));
            let (plan_id, candidate) = child_operation_values();
            if mode == "verify-gc-quarantine" {
                verify_gc_quarantine_after_crash(&store, &baseline, &plan_id, &candidate);
            } else {
                verify_gc_restore_after_crash(&store, &baseline, &plan_id, &candidate);
            }
        }
        "verify-migration-conflict" | "verify-migration" => {
            let baseline =
                PathBuf::from(std::env::var_os(CHILD_BASELINE_ENV).expect("baseline environment"));
            if mode == "verify-migration-conflict" {
                verify_migration_conflict(&store, &baseline);
            } else {
                verify_migration_after_crash(&store, &baseline);
            }
        }
        _ => panic!("unknown process crash child mode {mode:?}"),
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CrashMatrixRetention {
    RemoveLocalFixtures,
    PreserveProviderEvidence,
}

struct CrashMatrixRoot<'a> {
    path: &'a Path,
    capability: Option<&'a File>,
}

impl CrashMatrixRoot<'_> {
    fn copy(&self, source: &Path, destination: &Path) {
        assert_eq!(source.parent(), Some(self.path));
        assert_eq!(destination.parent(), Some(self.path));
        if let Some(capability) = self.capability {
            let source_name = source.file_name().expect("crash copy source name");
            let destination_name = destination
                .file_name()
                .expect("crash copy destination name");
            copy_directory_durable_at(capability, source_name, destination_name).unwrap_or_else(
                |error| {
                    panic!(
                        "capability-rooted durable copy {} -> {} failed closed: {error}",
                        source.display(),
                        destination.display()
                    )
                },
            );
        } else {
            copy_directory_durable(source, destination);
        }
    }
}

fn trace_normal_write(
    matrix: &CrashMatrixRoot<'_>,
    baseline: &Path,
    trace: &Path,
    retention: CrashMatrixRetention,
) -> Vec<DurabilityCheckpoint> {
    matrix.copy(baseline, trace);
    let recorder = FaultInjectionGuard::record();
    normal_write_commit(trace).expect("trace complete normal v2 write");
    let checkpoints = recorder.checkpoints();
    drop(recorder);
    if retention == CrashMatrixRetention::RemoveLocalFixtures {
        fs::remove_dir_all(trace).expect("remove successful normal-write trace");
    }
    checkpoints
}

fn prepare_pending_recovery(
    matrix: &CrashMatrixRoot<'_>,
    baseline: &Path,
    pending: &Path,
    normal_checkpoints: &[DurabilityCheckpoint],
) {
    matrix.copy(baseline, pending);
    let manifest_publish = normal_checkpoints
        .iter()
        .position(|checkpoint| {
            checkpoint.event == DurabilityEvent::Rename
                && checkpoint.context == "publish authenticated v2 manifest"
        })
        .expect("normal write trace includes manifest publication")
        + 1;
    let injector = FaultInjectionGuard::fail_at(manifest_publish);
    assert!(
        normal_write_commit(pending).is_err(),
        "failed to stop after authenticated manifest publication"
    );
    drop(injector);
    assert!(
        pending.join(WRITE_MANIFEST).exists(),
        "pending recovery fixture has no authenticated manifest"
    );
}

fn trace_recovery(
    matrix: &CrashMatrixRoot<'_>,
    pending: &Path,
    trace: &Path,
    retention: CrashMatrixRetention,
) -> Vec<DurabilityCheckpoint> {
    matrix.copy(pending, trace);
    let recorder = FaultInjectionGuard::record();
    assert!(
        recover(trace, &test_key(), &kdf_fingerprint()).expect("trace complete v2 recovery"),
        "pending recovery trace did no recovery work"
    );
    let checkpoints = recorder.checkpoints();
    drop(recorder);
    if retention == CrashMatrixRetention::RemoveLocalFixtures {
        fs::remove_dir_all(trace).expect("remove successful recovery trace");
    }
    checkpoints
}

fn assert_normal_checkpoint_coverage(checkpoints: &[DurabilityCheckpoint]) {
    for event in [
        DurabilityEvent::Write,
        DurabilityEvent::FileSync,
        DurabilityEvent::Rename,
        DurabilityEvent::DirectorySync,
        DurabilityEvent::Cleanup,
    ] {
        assert!(
            checkpoints
                .iter()
                .any(|checkpoint| checkpoint.event == event),
            "trace did not include {event:?}"
        );
    }
}

fn assert_recovery_checkpoint_coverage(checkpoints: &[DurabilityCheckpoint]) {
    assert!(!checkpoints.is_empty(), "recovery trace was empty");
    for event in [
        DurabilityEvent::Recovery,
        DurabilityEvent::Rename,
        DurabilityEvent::DirectorySync,
        DurabilityEvent::Cleanup,
    ] {
        assert!(
            checkpoints
                .iter()
                .any(|checkpoint| checkpoint.event == event),
            "recovery trace did not include {event:?}"
        );
    }
}

fn assert_checkpoint_count(label: &str, checkpoints: &[DurabilityCheckpoint], expected: usize) {
    assert_eq!(
        checkpoints.len(),
        expected,
        "{label} durability inventory changed; audit every added or removed syscall checkpoint before updating the expected count"
    );
}

fn run_process_crash_matrix(
    suite: &Path,
    suite_capability: Option<&File>,
    retention: CrashMatrixRetention,
) {
    let matrix = CrashMatrixRoot {
        path: suite,
        capability: suite_capability,
    };
    let baseline = suite.join("baseline");
    create_baseline(&baseline);

    let normal_checkpoints =
        trace_normal_write(&matrix, &baseline, &suite.join("normal-trace"), retention);
    assert_normal_checkpoint_coverage(&normal_checkpoints);
    assert_checkpoint_count("normal write", &normal_checkpoints, 46);
    checkpoint_with_context(
        &normal_checkpoints,
        DurabilityEvent::Rename,
        "publish authenticated v2 manifest",
    );
    checkpoint_with_context(
        &normal_checkpoints,
        DurabilityEvent::DirectorySync,
        "persist authenticated v2 write manifest",
    );
    checkpoint_with_context(
        &normal_checkpoints,
        DurabilityEvent::Rename,
        "atomically exchange authenticated v2 root",
    );
    checkpoint_with_context(
        &normal_checkpoints,
        DurabilityEvent::DirectorySync,
        "persist authenticated v2 root publication",
    );
    eprintln!(
        "SIGKILL normal-write matrix: {} durability checkpoints",
        normal_checkpoints.len()
    );
    for (offset, expected) in normal_checkpoints.iter().enumerate() {
        let checkpoint = offset + 1;
        let crashed = suite.join(format!("normal-{checkpoint:03}"));
        matrix.copy(&baseline, &crashed);
        let output = kill_child(&crashed, checkpoint, expected);
        assert_sigkill(&output, checkpoint, expected);
        if retention == CrashMatrixRetention::PreserveProviderEvidence {
            let conflicted = suite.join(format!("normal-conflict-{checkpoint:03}"));
            matrix.copy(&crashed, &conflicted);
            install_provider_conflict_evidence(&conflicted);
            verify_child(&conflicted, &baseline, "verify-conflict");
        } else {
            install_provider_conflict_evidence(&crashed);
            verify_child(&crashed, &baseline, "verify-conflict");
            remove_provider_conflict_after_verification(&crashed);
        }
        verify_child(&crashed, &baseline, "verify-commit");
    }

    let pending = suite.join("recovery-pending");
    prepare_pending_recovery(&matrix, &baseline, &pending, &normal_checkpoints);
    let recovery_checkpoints =
        trace_recovery(&matrix, &pending, &suite.join("recovery-trace"), retention);
    assert_recovery_checkpoint_coverage(&recovery_checkpoints);
    assert_checkpoint_count("normal-write recovery", &recovery_checkpoints, 18);
    for context in [
        "authenticate v2 write intent",
        "validate pending v2 manifest lineages",
        "validate old v2 generation",
        "validate new v2 generation",
        "finish v2 recovery",
    ] {
        checkpoint_with_context(&recovery_checkpoints, DurabilityEvent::Recovery, context);
    }
    eprintln!(
        "SIGKILL recovery matrix: {} durability checkpoints",
        recovery_checkpoints.len()
    );
    for (offset, expected) in recovery_checkpoints.iter().enumerate() {
        let checkpoint = offset + 1;
        let crashed = suite.join(format!("recovery-{checkpoint:03}"));
        matrix.copy(&pending, &crashed);
        let output = kill_recovery_child(&crashed, checkpoint, expected);
        assert_sigkill(&output, checkpoint, expected);
        if retention == CrashMatrixRetention::PreserveProviderEvidence {
            let conflicted = suite.join(format!("recovery-conflict-{checkpoint:03}"));
            matrix.copy(&crashed, &conflicted);
            install_provider_conflict_evidence(&conflicted);
            verify_child(&conflicted, &baseline, "verify-conflict");
        } else {
            install_provider_conflict_evidence(&crashed);
            verify_child(&crashed, &baseline, "verify-conflict");
            remove_provider_conflict_after_verification(&crashed);
        }
        verify_child(&crashed, &baseline, "verify-recovery");
    }
}

#[cfg(target_os = "macos")]
fn verify_materialized_process_crash_matrix(suite: &Path) {
    let baseline = suite.join("baseline");
    ensure_no_index_siblings(&baseline)
        .expect("materialized iCloud baseline has no provider conflict sibling");
    let (baseline_index, _) =
        load(&baseline, &test_key()).expect("authenticate materialized iCloud baseline");
    assert_eq!(baseline_index, index_with_empty_file(FILE_NAME));
    validate_reachable_v2_files(&baseline, &test_key(), &baseline_index)
        .expect("authenticate every materialized iCloud baseline object");

    let mut cases = vec![
        suite.join("normal-trace"),
        suite.join("recovery-pending"),
        suite.join("recovery-trace"),
    ];
    cases.extend((1..=46).map(|checkpoint| suite.join(format!("normal-{checkpoint:03}"))));
    cases.extend((1..=18).map(|checkpoint| suite.join(format!("recovery-{checkpoint:03}"))));
    for case in cases {
        ensure_no_index_siblings(&case).unwrap_or_else(|error| {
            panic!(
                "materialized iCloud crash case {} contains provider conflict evidence: {error}",
                case.display()
            )
        });
        verify_crash_visible_generation(&case, &baseline);
    }
    let mut conflict_cases: Vec<_> = (1..=46)
        .map(|checkpoint| suite.join(format!("normal-conflict-{checkpoint:03}")))
        .collect();
    conflict_cases.extend(
        (1..=18).map(|checkpoint| suite.join(format!("recovery-conflict-{checkpoint:03}"))),
    );
    for case in conflict_cases {
        verify_conflict_evidence(&case);
        verify_crash_visible_generation(&case, &baseline);
    }
}

#[test]
fn conflicted_crash_state_authenticates_without_unlinking_evidence() {
    let id = TEST_ID.fetch_add(1, Ordering::Relaxed);
    let suite = PathBuf::from(format!(
        "target/test-v2-retained-conflict-{}-{id}",
        std::process::id()
    ));
    let _ = fs::remove_dir_all(&suite);
    fs::create_dir_all(&suite).unwrap();
    let baseline = suite.join("baseline");
    let conflicted = suite.join("conflicted");
    create_baseline(&baseline);
    copy_directory_durable(&baseline, &conflicted);
    install_provider_conflict_evidence(&conflicted);

    verify_conflict_evidence(&conflicted);
    assert!(!verify_crash_visible_generation(&conflicted, &baseline));
    assert_eq!(
        fs::read(conflicted.join(CONFLICT_SIBLING_NAME)).unwrap(),
        CONFLICT_SIBLING_BYTES
    );
    fs::remove_dir_all(suite).unwrap();
}

#[test]
fn descriptor_rooted_crash_copy_is_byte_exact_and_rejects_symlinks() {
    use std::os::unix::fs::symlink;

    const PAYLOAD: &[u8] = b"descriptor-rooted byte-exact fixture";
    let id = TEST_ID.fetch_add(1, Ordering::Relaxed);
    let suite = PathBuf::from(format!(
        "target/test-v2-descriptor-copy-{}-{id}",
        std::process::id()
    ));
    let _ = fs::remove_dir_all(&suite);
    fs::create_dir_all(suite.join("clean-source/nested")).unwrap();
    fs::write(suite.join("clean-source/nested/payload.bin"), PAYLOAD).unwrap();
    fs::create_dir_all(suite.join("bad-source")).unwrap();
    fs::write(suite.join("outside-secret.bin"), b"must never be followed").unwrap();
    symlink(
        suite.join("outside-secret.bin").canonicalize().unwrap(),
        suite.join("bad-source/provider-link"),
    )
    .unwrap();

    let root = open_directory_nofollow(&suite).unwrap();
    copy_directory_durable_at(&root, OsStr::new("clean-source"), OsStr::new("clean-copy")).unwrap();
    assert_eq!(
        fs::read(suite.join("clean-copy/nested/payload.bin")).unwrap(),
        PAYLOAD
    );
    let deadline = Instant::now() + COPY_TIMEOUT;
    let source = openat_nofollow(
        &root,
        OsStr::new("clean-source"),
        libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NONBLOCK,
        0,
    )
    .unwrap();
    let destination = openat_nofollow(
        &root,
        OsStr::new("clean-copy"),
        libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NONBLOCK,
        0,
    )
    .unwrap();
    let copied_snapshot = snapshot_crash_directory(&destination, deadline).unwrap();
    fs::write(
        suite.join("clean-source/nested/payload.bin"),
        vec![b'x'; PAYLOAD.len()],
    )
    .unwrap();
    let changed_source = snapshot_crash_directory(&source, deadline).unwrap();
    assert!(verify_crash_copy_snapshots(&changed_source, &copied_snapshot).is_err());

    let error = copy_directory_durable_at(&root, OsStr::new("bad-source"), OsStr::new("bad-copy"))
        .unwrap_err();
    assert!(
        matches!(error.raw_os_error(), Some(libc::ELOOP) | Some(libc::EMLINK)),
        "unexpected symlink rejection error: {error}"
    );
    assert!(!suite.join("bad-copy/provider-link").exists());
    assert_eq!(
        fs::read(suite.join("outside-secret.bin")).unwrap(),
        b"must never be followed"
    );
    fs::remove_dir_all(suite).unwrap();
}

fn assert_operation_checkpoint_coverage(label: &str, checkpoints: &[DurabilityCheckpoint]) {
    assert!(!checkpoints.is_empty(), "{label} trace was empty");
    for event in [
        DurabilityEvent::Write,
        DurabilityEvent::FileSync,
        DurabilityEvent::Rename,
        DurabilityEvent::DirectorySync,
        DurabilityEvent::Cleanup,
    ] {
        assert!(
            checkpoints
                .iter()
                .any(|checkpoint| checkpoint.event == event),
            "{label} trace did not include {event:?}"
        );
    }
}

fn assert_recovery_checkpoint_coverage_for(
    label: &str,
    checkpoints: &[DurabilityCheckpoint],
    expected_recovery_context: &str,
) {
    assert!(!checkpoints.is_empty(), "{label} trace was empty");
    for event in [DurabilityEvent::FileSync, DurabilityEvent::DirectorySync] {
        assert!(
            checkpoints
                .iter()
                .any(|checkpoint| checkpoint.event == event),
            "{label} trace did not include {event:?}"
        );
    }
    assert!(
        checkpoints
            .iter()
            .any(|checkpoint| checkpoint.event == DurabilityEvent::Recovery
                && checkpoint.context == expected_recovery_context),
        "{label} trace did not include expected recovery checkpoint {expected_recovery_context:?}"
    );
}

fn checkpoint_with_context(
    checkpoints: &[DurabilityCheckpoint],
    event: DurabilityEvent,
    context: &str,
) -> usize {
    checkpoints
        .iter()
        .position(|checkpoint| checkpoint.event == event && checkpoint.context == context)
        .unwrap_or_else(|| panic!("trace has no {event:?} checkpoint for {context:?}"))
        + 1
}

fn trace_gc_quarantine(baseline: &Path, trace: &Path, plan_id: &str) -> Vec<DurabilityCheckpoint> {
    copy_directory_durable(baseline, trace);
    let recorder = FaultInjectionGuard::record();
    gc_quarantine(trace, PASSPHRASE, plan_id).expect("trace complete GC quarantine");
    let checkpoints = recorder.checkpoints();
    drop(recorder);
    fs::remove_dir_all(trace).expect("remove successful GC quarantine trace");
    checkpoints
}

fn trace_gc_restore(quarantined: &Path, trace: &Path, plan_id: &str) -> Vec<DurabilityCheckpoint> {
    copy_directory_durable(quarantined, trace);
    let recorder = FaultInjectionGuard::record();
    gc_restore(trace, PASSPHRASE, plan_id).expect("trace complete GC restore");
    let checkpoints = recorder.checkpoints();
    drop(recorder);
    fs::remove_dir_all(trace).expect("remove successful GC restore trace");
    checkpoints
}

#[allow(clippy::too_many_arguments)]
fn run_gc_kill_cases(
    suite: &Path,
    fixture: &Path,
    evidence_baseline: &Path,
    prefix: &str,
    checkpoints: &[DurabilityCheckpoint],
    plan_id: &str,
    candidate: &str,
    kill_mode: &str,
    conflict_mode: &str,
    verify_mode: &str,
) {
    for (offset, expected) in checkpoints.iter().enumerate() {
        let checkpoint = offset + 1;
        let crashed = suite.join(format!("{prefix}-{checkpoint:03}"));
        copy_directory_durable(fixture, &crashed);
        let output = kill_named_operation_child(
            kill_mode,
            &crashed,
            checkpoint,
            expected,
            Some(plan_id),
            Some(candidate),
        );
        assert_sigkill(&output, checkpoint, expected);
        assert_gc_candidate_has_one_complete_copy(&crashed, evidence_baseline, plan_id, candidate);
        install_provider_conflict_evidence(&crashed);
        verify_operation_child(
            &crashed,
            evidence_baseline,
            conflict_mode,
            Some(plan_id),
            Some(candidate),
        );
        remove_provider_conflict_after_verification(&crashed);
        verify_operation_child(
            &crashed,
            evidence_baseline,
            verify_mode,
            Some(plan_id),
            Some(candidate),
        );
        fs::remove_dir_all(&crashed).expect("remove successful GC crash case");
    }
}

fn prepare_partial_gc_quarantine(
    baseline: &Path,
    partial: &Path,
    plan_id: &str,
    checkpoints: &[DurabilityCheckpoint],
) {
    copy_directory_durable(baseline, partial);
    let stop = checkpoint_with_context(
        checkpoints,
        DurabilityEvent::Rename,
        "move unreachable immutable v2 object into quarantine",
    );
    let injector = FaultInjectionGuard::fail_at(stop);
    assert!(
        gc_quarantine(partial, PASSPHRASE, plan_id).is_err(),
        "partial quarantine fixture did not stop after its object rename"
    );
    drop(injector);
}

fn prepare_partial_gc_restore(
    quarantined: &Path,
    partial: &Path,
    plan_id: &str,
    checkpoints: &[DurabilityCheckpoint],
) {
    copy_directory_durable(quarantined, partial);
    let stop = checkpoint_with_context(
        checkpoints,
        DurabilityEvent::Rename,
        "restore immutable v2 object from GC quarantine",
    );
    let injector = FaultInjectionGuard::fail_at(stop);
    assert!(
        gc_restore(partial, PASSPHRASE, plan_id).is_err(),
        "partial restore fixture did not stop after its object rename"
    );
    drop(injector);
}

fn run_gc_process_crash_matrix(suite: &Path) {
    let baseline = suite.join("gc-baseline");
    let (plan_id, candidate) = create_gc_baseline(&baseline);

    let quarantine_checkpoints =
        trace_gc_quarantine(&baseline, &suite.join("gc-quarantine-trace"), &plan_id);
    assert_operation_checkpoint_coverage("GC quarantine", &quarantine_checkpoints);
    assert_checkpoint_count("GC quarantine", &quarantine_checkpoints, 22);
    eprintln!(
        "SIGKILL GC quarantine matrix: {} durability checkpoints",
        quarantine_checkpoints.len()
    );
    run_gc_kill_cases(
        suite,
        &baseline,
        &baseline,
        "gc-quarantine",
        &quarantine_checkpoints,
        &plan_id,
        &candidate,
        "kill-gc-quarantine",
        "verify-gc-quarantine-conflict",
        "verify-gc-quarantine",
    );

    let partial_quarantine = suite.join("gc-quarantine-partial");
    prepare_partial_gc_quarantine(
        &baseline,
        &partial_quarantine,
        &plan_id,
        &quarantine_checkpoints,
    );
    let (source, quarantine) = assert_gc_candidate_has_one_complete_copy(
        &partial_quarantine,
        &baseline,
        &plan_id,
        &candidate,
    );
    assert!(!source && quarantine);
    let quarantine_recovery_checkpoints = trace_gc_quarantine(
        &partial_quarantine,
        &suite.join("gc-quarantine-recovery-trace"),
        &plan_id,
    );
    assert_recovery_checkpoint_coverage_for(
        "GC quarantine recovery",
        &quarantine_recovery_checkpoints,
        "resume already quarantined immutable v2 object",
    );
    assert_checkpoint_count(
        "GC quarantine recovery",
        &quarantine_recovery_checkpoints,
        14,
    );
    eprintln!(
        "SIGKILL GC quarantine-recovery matrix: {} durability checkpoints",
        quarantine_recovery_checkpoints.len()
    );
    run_gc_kill_cases(
        suite,
        &partial_quarantine,
        &baseline,
        "gc-quarantine-recovery",
        &quarantine_recovery_checkpoints,
        &plan_id,
        &candidate,
        "kill-gc-quarantine",
        "verify-gc-quarantine-conflict",
        "verify-gc-quarantine",
    );

    let restore_baseline = suite.join("gc-restore-baseline");
    copy_directory_durable(&baseline, &restore_baseline);
    gc_quarantine(&restore_baseline, PASSPHRASE, &plan_id)
        .expect("prepare complete GC quarantine for restore matrix");
    let (source, quarantine) = assert_gc_candidate_has_one_complete_copy(
        &restore_baseline,
        &baseline,
        &plan_id,
        &candidate,
    );
    assert!(!source && quarantine);

    let restore_checkpoints =
        trace_gc_restore(&restore_baseline, &suite.join("gc-restore-trace"), &plan_id);
    assert_operation_checkpoint_coverage("GC restore", &restore_checkpoints);
    assert_checkpoint_count("GC restore", &restore_checkpoints, 9);
    eprintln!(
        "SIGKILL GC restore matrix: {} durability checkpoints",
        restore_checkpoints.len()
    );
    run_gc_kill_cases(
        suite,
        &restore_baseline,
        &baseline,
        "gc-restore",
        &restore_checkpoints,
        &plan_id,
        &candidate,
        "kill-gc-restore",
        "verify-gc-restore-conflict",
        "verify-gc-restore",
    );

    let partial_restore = suite.join("gc-restore-partial");
    prepare_partial_gc_restore(
        &restore_baseline,
        &partial_restore,
        &plan_id,
        &restore_checkpoints,
    );
    let (source, quarantine) = assert_gc_candidate_has_one_complete_copy(
        &partial_restore,
        &baseline,
        &plan_id,
        &candidate,
    );
    assert!(source && !quarantine);
    let restore_recovery_checkpoints = trace_gc_restore(
        &partial_restore,
        &suite.join("gc-restore-recovery-trace"),
        &plan_id,
    );
    assert_recovery_checkpoint_coverage_for(
        "GC restore recovery",
        &restore_recovery_checkpoints,
        "resume already restored immutable v2 object",
    );
    assert_checkpoint_count("GC restore recovery", &restore_recovery_checkpoints, 8);
    eprintln!(
        "SIGKILL GC restore-recovery matrix: {} durability checkpoints",
        restore_recovery_checkpoints.len()
    );
    run_gc_kill_cases(
        suite,
        &partial_restore,
        &baseline,
        "gc-restore-recovery",
        &restore_recovery_checkpoints,
        &plan_id,
        &candidate,
        "kill-gc-restore",
        "verify-gc-restore-conflict",
        "verify-gc-restore",
    );
}

fn trace_migration(baseline: &Path, trace: &Path) -> Vec<DurabilityCheckpoint> {
    copy_directory_durable(baseline, trace);
    let recorder = FaultInjectionGuard::record();
    crate::v2_migrate::migrate_v1_to_v2(MIGRATION_PASSPHRASE, trace)
        .expect("trace complete v1-to-v2 migration");
    let checkpoints = recorder.checkpoints();
    drop(recorder);
    fs::remove_dir_all(trace).expect("remove successful migration trace");
    checkpoints
}

fn prepare_pending_migration_recovery(
    suite: &Path,
    baseline: &Path,
    checkpoints: &[DurabilityCheckpoint],
) -> PathBuf {
    for (offset, expected) in checkpoints.iter().enumerate() {
        if expected.event != DurabilityEvent::Rename
            || expected.context != "publish authenticated v2 manifest"
        {
            continue;
        }
        let checkpoint = offset + 1;
        let candidate = suite.join(format!("migration-partial-candidate-{checkpoint:03}"));
        copy_directory_durable(baseline, &candidate);
        let injector = FaultInjectionGuard::fail_at(checkpoint);
        let result = crate::v2_migrate::migrate_v1_to_v2(MIGRATION_PASSPHRASE, &candidate);
        drop(injector);
        assert!(
            result.is_err(),
            "migration partial candidate {checkpoint} did not inject"
        );
        if candidate.join(WRITE_MANIFEST).exists() {
            return candidate;
        }
        fs::remove_dir_all(&candidate).expect("remove unused migration partial candidate");
    }
    panic!("migration trace produced no pending authenticated v2 write manifest");
}

fn run_migration_kill_cases(
    suite: &Path,
    fixture: &Path,
    baseline: &Path,
    prefix: &str,
    checkpoints: &[DurabilityCheckpoint],
) {
    for (offset, expected) in checkpoints.iter().enumerate() {
        let checkpoint = offset + 1;
        let crashed = suite.join(format!("{prefix}-{checkpoint:03}"));
        copy_directory_durable(fixture, &crashed);
        let output = kill_named_operation_child(
            "kill-migration",
            &crashed,
            checkpoint,
            expected,
            None,
            None,
        );
        assert_sigkill(&output, checkpoint, expected);
        assert_valid_migration_visibility(&crashed, baseline);
        install_provider_conflict_evidence(&crashed);
        verify_operation_child(&crashed, baseline, "verify-migration-conflict", None, None);
        remove_provider_conflict_after_verification(&crashed);
        verify_operation_child(&crashed, baseline, "verify-migration", None, None);
        fs::remove_dir_all(&crashed).expect("remove successful migration crash case");
    }
}

fn run_migration_process_crash_matrix(suite: &Path) {
    let baseline = suite.join("migration-baseline");
    create_migration_baseline(&baseline);
    let checkpoints = trace_migration(&baseline, &suite.join("migration-trace"));
    assert_operation_checkpoint_coverage("v1-to-v2 migration", &checkpoints);
    assert_checkpoint_count("v1-to-v2 migration", &checkpoints, 65);
    eprintln!(
        "SIGKILL v1-to-v2 migration matrix: {} durability checkpoints",
        checkpoints.len()
    );
    run_migration_kill_cases(suite, &baseline, &baseline, "migration", &checkpoints);

    let partial = prepare_pending_migration_recovery(suite, &baseline, &checkpoints);
    assert!(partial.join(WRITE_MANIFEST).exists());
    assert_valid_migration_visibility(&partial, &baseline);
    let recovery_checkpoints = trace_migration(&partial, &suite.join("migration-recovery-trace"));
    assert_recovery_checkpoint_coverage_for(
        "v1-to-v2 migration recovery",
        &recovery_checkpoints,
        "authenticate v2 write intent",
    );
    assert_checkpoint_count("v1-to-v2 migration recovery", &recovery_checkpoints, 29);
    eprintln!(
        "SIGKILL v1-to-v2 migration-recovery matrix: {} durability checkpoints",
        recovery_checkpoints.len()
    );
    run_migration_kill_cases(
        suite,
        &partial,
        &baseline,
        "migration-recovery",
        &recovery_checkpoints,
    );
}

fn configured_suite_root(expected_filesystem: &str) -> PathBuf {
    assert_eq!(
        std::env::var(RUN_ENV).as_deref(),
        Ok("1"),
        "an explicitly selected process-crash gate requires {RUN_ENV}=1 and {ROOT_ENV} to an explicit test filesystem path"
    );
    let configured = PathBuf::from(
        std::env::var_os(ROOT_ENV)
            .unwrap_or_else(|| panic!("{ROOT_ENV} is required when {RUN_ENV}=1")),
    );
    let root = fs::canonicalize(&configured)
        .unwrap_or_else(|error| panic!("canonicalize {}: {error}", configured.display()));
    assert!(root.is_dir(), "{} is not a directory", root.display());
    let actual = filesystem_type(&root)
        .unwrap_or_else(|error| panic!("identify filesystem for {}: {error}", root.display()));
    assert_eq!(
        actual,
        expected_filesystem,
        "{} is on {actual}, not the required {expected_filesystem} filesystem",
        root.display()
    );
    for _ in 0..1024 {
        let id = TEST_ID.fetch_add(1, Ordering::Relaxed);
        let suite = root.join(format!(
            "zerotrust-drive-process-crash-{}-{id}",
            std::process::id()
        ));
        match fs::create_dir(&suite) {
            Ok(()) => {
                File::open(&root)
                    .expect("open crash suite parent")
                    .sync_all()
                    .expect("sync crash suite parent");
                return suite;
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(error) => panic!("create crash suite {}: {error}", suite.display()),
        }
    }
    panic!("could not allocate a unique process crash suite directory");
}

#[cfg(target_os = "macos")]
fn filesystem_type(path: &Path) -> std::io::Result<String> {
    use std::ffi::CStr;
    let path = CString::new(path.as_os_str().as_bytes())?;
    let mut stats = std::mem::MaybeUninit::<libc::statfs>::uninit();
    if unsafe { libc::statfs(path.as_ptr(), stats.as_mut_ptr()) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    let stats = unsafe { stats.assume_init() };
    let name = unsafe { CStr::from_ptr(stats.f_fstypename.as_ptr()) };
    Ok(name.to_string_lossy().into_owned())
}

#[cfg(target_os = "linux")]
fn filesystem_type(path: &Path) -> std::io::Result<String> {
    use std::os::unix::ffi::OsStringExt;
    let mountinfo = fs::read_to_string("/proc/self/mountinfo")?;
    let mut selected: Option<(usize, String)> = None;
    for line in mountinfo.lines() {
        let Some((left, right)) = line.split_once(" - ") else {
            continue;
        };
        let Some(encoded_mount) = left.split_whitespace().nth(4) else {
            continue;
        };
        let Some(filesystem) = right.split_whitespace().next() else {
            continue;
        };
        let mount = PathBuf::from(std::ffi::OsString::from_vec(decode_mountinfo(
            encoded_mount,
        )));
        if path.starts_with(&mount) {
            let specificity = mount.as_os_str().as_bytes().len();
            if selected
                .as_ref()
                .is_none_or(|(previous, _)| specificity > *previous)
            {
                selected = Some((specificity, filesystem.to_string()));
            }
        }
    }
    selected
        .map(|(_, filesystem)| filesystem)
        .ok_or_else(|| std::io::Error::other("no containing mount in /proc/self/mountinfo"))
}

#[cfg(target_os = "linux")]
fn decode_mountinfo(value: &str) -> Vec<u8> {
    let bytes = value.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'\\'
            && index + 3 < bytes.len()
            && bytes[index + 1..index + 4]
                .iter()
                .all(|byte| matches!(byte, b'0'..=b'7'))
        {
            decoded.push(
                (bytes[index + 1] - b'0') * 64
                    + (bytes[index + 2] - b'0') * 8
                    + (bytes[index + 3] - b'0'),
            );
            index += 4;
        } else {
            decoded.push(bytes[index]);
            index += 1;
        }
    }
    decoded
}

#[cfg(target_os = "macos")]
#[test]
#[ignore = "requires explicit opt-in and a real APFS test directory"]
fn subprocess_sigkill_v2_durability_apfs() {
    let suite = configured_suite_root("apfs");
    run_process_crash_matrix(&suite, None, CrashMatrixRetention::RemoveLocalFixtures);
    fs::remove_dir_all(&suite).expect("remove successful APFS process crash suite");
}

#[cfg(target_os = "macos")]
#[test]
#[ignore = "requires explicit opt-in and a real APFS test directory"]
fn subprocess_sigkill_v2_gc_apfs() {
    let suite = configured_suite_root("apfs");
    run_gc_process_crash_matrix(&suite);
    fs::remove_dir_all(&suite).expect("remove successful APFS GC process crash suite");
}

#[cfg(target_os = "macos")]
#[test]
#[ignore = "requires explicit opt-in and a real APFS test directory"]
fn subprocess_sigkill_v1_to_v2_migration_apfs() {
    let suite = configured_suite_root("apfs");
    run_migration_process_crash_matrix(&suite);
    fs::remove_dir_all(&suite).expect("remove successful APFS migration process crash suite");
}

/// Runs the complete normal-write and recovery SIGKILL matrix through a real
/// iCloud Drive File Provider folder. This is still a local process-crash test:
/// waiting for upload completion afterward does not simulate remote-provider
/// reordering or prove atomic visibility on another Mac.
#[cfg(target_os = "macos")]
#[test]
#[ignore = "requires an explicit disposable iCloud folder marked Keep Downloaded"]
fn subprocess_sigkill_v2_durability_icloud() {
    let suite = crate::macos_integration_tests::IcloudTestSuite::create_keep_downloaded("sigkill");
    let filesystem = filesystem_type(suite.path()).unwrap_or_else(|error| {
        panic!(
            "identify filesystem for {}: {error}",
            suite.path().display()
        )
    });
    assert_eq!(
        filesystem, "apfs",
        "real iCloud durability gate requires APFS, found {filesystem}"
    );
    suite.await_materialized_and_uploaded();
    suite.verify_owned_child();
    run_process_crash_matrix(
        suite.path(),
        Some(suite.capability()),
        CrashMatrixRetention::PreserveProviderEvidence,
    );
    let before_provider_settle = suite.capture_tree_snapshot();
    suite.await_materialized_and_uploaded();
    let after_provider_settle = suite.capture_tree_snapshot();
    assert_eq!(
        after_provider_settle, before_provider_settle,
        "iCloud changed an exact name, type, size, link count, or byte digest while the SIGKILL suite settled"
    );
    verify_materialized_process_crash_matrix(suite.path());
    assert_eq!(
        suite.capture_tree_snapshot(),
        before_provider_settle,
        "iCloud changed the exact SIGKILL suite during post-settle authentication"
    );
    suite.finish_and_preserve();
}

#[cfg(target_os = "linux")]
#[test]
#[ignore = "requires explicit opt-in and a real ext4 test directory"]
fn subprocess_sigkill_v2_durability_ext4() {
    let suite = configured_suite_root("ext4");
    run_process_crash_matrix(&suite, None, CrashMatrixRetention::RemoveLocalFixtures);
    fs::remove_dir_all(&suite).expect("remove successful ext4 process crash suite");
}

#[cfg(target_os = "linux")]
#[test]
#[ignore = "requires explicit opt-in and a real ext4 test directory"]
fn subprocess_sigkill_v2_gc_ext4() {
    let suite = configured_suite_root("ext4");
    run_gc_process_crash_matrix(&suite);
    fs::remove_dir_all(&suite).expect("remove successful ext4 GC process crash suite");
}

#[cfg(target_os = "linux")]
#[test]
#[ignore = "requires explicit opt-in and a real ext4 test directory"]
fn subprocess_sigkill_v1_to_v2_migration_ext4() {
    let suite = configured_suite_root("ext4");
    run_migration_process_crash_matrix(&suite);
    fs::remove_dir_all(&suite).expect("remove successful ext4 migration process crash suite");
}
