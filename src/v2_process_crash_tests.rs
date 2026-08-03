// Copyright 2026 Alexander Orlov <alexander.orlov@loxal.net>

//! Opt-in real-process crash tests for the v2 root-last protocol.
//!
//! These tests prove behavior across a userspace process SIGKILL. They do not
//! simulate power loss, torn writes, controller caches, or storage-provider
//! reordering. On macOS they exercise Rust's current `File::sync_all` path, not
//! `F_FULLFSYNC`. Run the ignored platform test with an explicit path on the
//! filesystem under test:
//!
//! ```text
//! ZDRIVE_RUN_PROCESS_CRASH_TESTS=1 \
//! ZDRIVE_CRASH_TEST_ROOT=/path/on/test/filesystem \
//! cargo test subprocess_sigkill_v2_durability -- --ignored --nocapture
//! ```
//!
//! Each recovery case injects one real process death and then completes in a
//! fresh verifier. Repeated process deaths from every already-partial recovery
//! state would be a combinatorial matrix and are not claimed here; the
//! deterministic returned-error recovery tests cover replay idempotence at
//! every individual durability checkpoint.

use super::*;
use crate::crypto::{
    FORMAT_VERSION as KDF_FORMAT_VERSION, KdfParams, RecoveryFingerprint, SALT_LEN, derive_key,
};
use crate::fault::{DurabilityCheckpoint, DurabilityEvent, FaultInjectionGuard};
use crate::fs::{
    DirChild, DiskIndex, InodeEntry, InodeKind, ZeroTrustFs, ensure_no_index_siblings,
    validate_disk_index_v2, validate_reachable_v2_files,
};
use std::collections::HashMap;
#[cfg(target_os = "macos")]
use std::ffi::CString;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::ffi::OsStrExt;
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
const CHILD_TEST_NAME: &str = "v2::process_crash_tests::subprocess_crash_child";
const PASSPHRASE: &str = "v2-process-crash-passphrase";
const CONFLICT_SIBLING_NAME: &str = "_root (conflicted copy).age";
const CONFLICT_SIBLING_BYTES: &[u8] =
    b"recognized provider root-sibling evidence must survive fail-closed recovery";
const FILE_NAME: &str = "generation.txt";
const NEW_CONTENT: &[u8] = b"complete authenticated new generation";
const CHILD_TIMEOUT: Duration = Duration::from_secs(30);

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
    let ztfs = ZeroTrustFs::new_v2(PASSPHRASE, directory.to_path_buf());
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

fn copy_directory_durable(source: &Path, destination: &Path) {
    fs::create_dir(destination).expect("create crash-case directory");
    for entry in fs::read_dir(source).expect("read crash baseline") {
        let entry = entry.expect("read crash baseline entry");
        let target = destination.join(entry.file_name());
        let file_type = entry.file_type().expect("read crash baseline file type");
        if file_type.is_dir() {
            copy_directory_durable(&entry.path(), &target);
        } else if file_type.is_file() {
            fs::copy(entry.path(), &target).expect("copy crash baseline file");
            File::open(&target)
                .expect("open copied crash baseline file")
                .sync_all()
                .expect("sync copied crash baseline file");
        } else {
            panic!("crash baseline contains a non-regular entry");
        }
    }
    File::open(destination)
        .expect("open copied crash baseline directory")
        .sync_all()
        .expect("sync copied crash baseline directory");
}

fn create_baseline(path: &Path) {
    fs::create_dir(path).expect("create process crash baseline");
    write_durable(&path.join("_kdf.json"), &kdf_bytes());
    commit_index(path, &test_key(), &index_with_empty_file(FILE_NAME), None)
        .expect("commit process crash baseline");
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
    recover(store, &key, &kdf_fingerprint()).expect("recover commit after process SIGKILL");
    let (index, _state) = load(store, &key).expect("load root after process SIGKILL recovery");
    if index == index_with_empty_file(FILE_NAME) {
        assert_eq!(
            fs::read(store.join(ROOT_FILE)).expect("read exact old root"),
            fs::read(baseline.join(ROOT_FILE)).expect("read expected exact old root"),
            "old generation root bytes changed"
        );
    } else {
        verify_complete_new_generation(store, baseline);
    }
}

fn verify_recovery_after_crash(store: &Path, baseline: &Path) {
    let key = test_key();
    recover(store, &key, &kdf_fingerprint()).expect("resume recovery after process SIGKILL");
    assert!(
        !recover(store, &key, &kdf_fingerprint()).expect("verify idempotent completed recovery"),
        "recovery left a canonical write manifest behind"
    );
    verify_complete_new_generation(store, baseline);
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
        _ => panic!("unknown process crash child mode {mode:?}"),
    }
}

fn trace_normal_write(baseline: &Path, trace: &Path) -> Vec<DurabilityCheckpoint> {
    copy_directory_durable(baseline, trace);
    let recorder = FaultInjectionGuard::record();
    normal_write_commit(trace).expect("trace complete normal v2 write");
    let checkpoints = recorder.checkpoints();
    drop(recorder);
    fs::remove_dir_all(trace).expect("remove successful normal-write trace");
    checkpoints
}

fn prepare_pending_recovery(
    baseline: &Path,
    pending: &Path,
    normal_checkpoints: &[DurabilityCheckpoint],
) {
    copy_directory_durable(baseline, pending);
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

fn trace_recovery(pending: &Path, trace: &Path) -> Vec<DurabilityCheckpoint> {
    copy_directory_durable(pending, trace);
    let recorder = FaultInjectionGuard::record();
    assert!(
        recover(trace, &test_key(), &kdf_fingerprint()).expect("trace complete v2 recovery"),
        "pending recovery trace did no recovery work"
    );
    let checkpoints = recorder.checkpoints();
    drop(recorder);
    fs::remove_dir_all(trace).expect("remove successful recovery trace");
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

fn run_process_crash_matrix(suite: &Path) {
    let baseline = suite.join("baseline");
    create_baseline(&baseline);

    let normal_checkpoints = trace_normal_write(&baseline, &suite.join("normal-trace"));
    assert_normal_checkpoint_coverage(&normal_checkpoints);
    eprintln!(
        "SIGKILL normal-write matrix: {} durability checkpoints",
        normal_checkpoints.len()
    );
    for (offset, expected) in normal_checkpoints.iter().enumerate() {
        let checkpoint = offset + 1;
        let crashed = suite.join(format!("normal-{checkpoint:03}"));
        copy_directory_durable(&baseline, &crashed);
        let output = kill_child(&crashed, checkpoint, expected);
        assert_sigkill(&output, checkpoint, expected);
        install_provider_conflict_evidence(&crashed);
        verify_child(&crashed, &baseline, "verify-conflict");
        remove_provider_conflict_after_verification(&crashed);
        verify_child(&crashed, &baseline, "verify-commit");
    }

    let pending = suite.join("recovery-pending");
    prepare_pending_recovery(&baseline, &pending, &normal_checkpoints);
    let recovery_checkpoints = trace_recovery(&pending, &suite.join("recovery-trace"));
    assert_recovery_checkpoint_coverage(&recovery_checkpoints);
    eprintln!(
        "SIGKILL recovery matrix: {} durability checkpoints",
        recovery_checkpoints.len()
    );
    for (offset, expected) in recovery_checkpoints.iter().enumerate() {
        let checkpoint = offset + 1;
        let crashed = suite.join(format!("recovery-{checkpoint:03}"));
        copy_directory_durable(&pending, &crashed);
        let output = kill_recovery_child(&crashed, checkpoint, expected);
        assert_sigkill(&output, checkpoint, expected);
        install_provider_conflict_evidence(&crashed);
        verify_child(&crashed, &baseline, "verify-conflict");
        remove_provider_conflict_after_verification(&crashed);
        verify_child(&crashed, &baseline, "verify-recovery");
    }
}

fn configured_suite_root(expected_filesystem: &str) -> Option<PathBuf> {
    if std::env::var(RUN_ENV).as_deref() != Ok("1") {
        eprintln!(
            "skipping opt-in process crash suite; set {RUN_ENV}=1 and {ROOT_ENV} to an explicit test filesystem path"
        );
        return None;
    }
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
                return Some(suite);
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
    let Some(suite) = configured_suite_root("apfs") else {
        return;
    };
    run_process_crash_matrix(&suite);
    fs::remove_dir_all(&suite).expect("remove successful APFS process crash suite");
}

#[cfg(target_os = "linux")]
#[test]
#[ignore = "requires explicit opt-in and a real ext4 test directory"]
fn subprocess_sigkill_v2_durability_ext4() {
    let Some(suite) = configured_suite_root("ext4") else {
        return;
    };
    run_process_crash_matrix(&suite);
    fs::remove_dir_all(&suite).expect("remove successful ext4 process crash suite");
}
