// Copyright 2026 Alexander Orlov <alexander.orlov@loxal.net>

//! Opt-in real-process crash tests for the v2 root-last protocol, offline GC,
//! and explicit v1-to-v2 migration.
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
//! cargo test subprocess_sigkill -- --ignored --nocapture
//! ```
//!
//! Each case injects one real process death, verifies recognized provider
//! conflict evidence in another process, then completes in a fresh verifier.
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

fn assert_checkpoint_count(label: &str, checkpoints: &[DurabilityCheckpoint], expected: usize) {
    assert_eq!(
        checkpoints.len(),
        expected,
        "{label} durability inventory changed; audit every added or removed syscall checkpoint before updating the expected count"
    );
}

fn run_process_crash_matrix(suite: &Path) {
    let baseline = suite.join("baseline");
    create_baseline(&baseline);

    let normal_checkpoints = trace_normal_write(&baseline, &suite.join("normal-trace"));
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
        copy_directory_durable(&pending, &crashed);
        let output = kill_recovery_child(&crashed, checkpoint, expected);
        assert_sigkill(&output, checkpoint, expected);
        install_provider_conflict_evidence(&crashed);
        verify_child(&crashed, &baseline, "verify-conflict");
        remove_provider_conflict_after_verification(&crashed);
        verify_child(&crashed, &baseline, "verify-recovery");
    }
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
    run_process_crash_matrix(&suite);
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

#[cfg(target_os = "linux")]
#[test]
#[ignore = "requires explicit opt-in and a real ext4 test directory"]
fn subprocess_sigkill_v2_durability_ext4() {
    let suite = configured_suite_root("ext4");
    run_process_crash_matrix(&suite);
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
