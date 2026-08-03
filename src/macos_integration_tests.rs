// Copyright 2026 Alex O <info@lifub.com>

//! macOS-only native coordination and opt-in iCloud integration gates.
//!
//! These tests do not enable the production coordinated backend. The iCloud
//! helpers create one randomly named child below an explicitly selected parent
//! and never traverse or mutate siblings. Keep Downloaded and eviction are
//! deliberately separate because a retained-content policy may reject or
//! immediately reverse eviction. Run the persistent-local-copy gates below a
//! folder marked Keep Downloaded in Finder:
//!
//! ```text
//! ZDRIVE_RUN_ICLOUD_TESTS=1 \
//! ZDRIVE_ICLOUD_TEST_ROOT='/absolute/canonical/iCloud/test folder' \
//! ZDRIVE_ICLOUD_TEST_CONFIRM=disposable-keep-downloaded-folder \
//! cargo test --locked 'macos_integration_tests::real_icloud_keep_downloaded_gate' -- --exact --ignored --nocapture
//!
//! ZDRIVE_RUN_ICLOUD_TESTS=1 \
//! ZDRIVE_ICLOUD_TEST_ROOT='/absolute/canonical/iCloud/test folder' \
//! ZDRIVE_ICLOUD_TEST_CONFIRM=disposable-keep-downloaded-folder \
//! cargo test --locked 'v2::process_crash_tests::subprocess_sigkill_v2_durability_icloud' -- --exact --ignored --nocapture
//!
//! To prove a real eviction/download transition, select a second disposable
//! iCloud folder that is not marked Keep Downloaded. Wait until Finder reports
//! it fully downloaded and synchronized before starting the transition:
//!
//! ZDRIVE_RUN_ICLOUD_TESTS=1 \
//! ZDRIVE_ICLOUD_MATERIALIZATION_ROOT='/absolute/canonical/iCloud/test folder' \
//! ZDRIVE_ICLOUD_MATERIALIZATION_CONFIRM=disposable-evictable-folder \
//! cargo test --locked 'macos_integration_tests::real_icloud_materialization_transition_gate' -- --exact --ignored --nocapture
//! ```

use crate::storage::{DownloadStatus, RelativeStorePath, StoreRoot, UbiquityStatus};
use blake2::{Blake2s256, Digest};
use std::collections::BTreeMap;
use std::ffi::{CStr, CString, OsStr, OsString, c_char, c_int, c_void};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

const ERROR_DOMAIN_CAPACITY: usize = 128;
const ERROR_MESSAGE_CAPACITY: usize = 1024;
const ICLOUD_RUN_ENV: &str = "ZDRIVE_RUN_ICLOUD_TESTS";
const ICLOUD_ROOT_ENV: &str = "ZDRIVE_ICLOUD_TEST_ROOT";
const ICLOUD_CONFIRM_ENV: &str = "ZDRIVE_ICLOUD_TEST_CONFIRM";
const ICLOUD_CONFIRM_VALUE: &str = "disposable-keep-downloaded-folder";
const ICLOUD_MATERIALIZATION_ROOT_ENV: &str = "ZDRIVE_ICLOUD_MATERIALIZATION_ROOT";
const ICLOUD_MATERIALIZATION_CONFIRM_ENV: &str = "ZDRIVE_ICLOUD_MATERIALIZATION_CONFIRM";
const ICLOUD_MATERIALIZATION_CONFIRM_VALUE: &str = "disposable-evictable-folder";
const ICLOUD_TIMEOUT_ENV: &str = "ZDRIVE_ICLOUD_TEST_TIMEOUT_SECS";
const FILEPROVIDERCTL_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_FILEPROVIDERCTL_OUTPUT_BYTES: usize = 1024 * 1024;
const MAX_ICLOUD_ENTRIES: usize = 250_000;
const MAX_ICLOUD_DEPTH: usize = 128;
const MAX_ICLOUD_FILE_BYTES: u64 = 65 * 1024 * 1024;
const MAX_ICLOUD_SNAPSHOT_BYTES: u64 = 4 * 1024 * 1024 * 1024;
const OWNER_MARKER: &str = "ztd-test-owner.bin";
const ICLOUD_FIXTURE: &[u8] = b"authenticated disposable iCloud materialization fixture";

static TEST_ID: AtomicU64 = AtomicU64::new(0);

#[repr(C)]
struct NativeError {
    kind: i32,
    code: i64,
    domain: [c_char; ERROR_DOMAIN_CAPACITY],
    message: [c_char; ERROR_MESSAGE_CAPACITY],
}

#[repr(C)]
#[derive(Default)]
struct NativePresenterProbeResult {
    relinquish_writer_count: i32,
    move_count: i32,
    destination_matches: i32,
}

type NativeAccessor = unsafe extern "C" fn(
    context: *mut c_void,
    first_path: *const u8,
    first_path_len: usize,
    second_path: *const u8,
    second_path_len: usize,
) -> c_int;

unsafe extern "C" {
    fn ztd_mac_probe_coordinated_move(
        purpose: *const u8,
        purpose_len: usize,
        source_path: *const u8,
        source_path_len: usize,
        source_is_directory: i32,
        destination_path: *const u8,
        destination_path_len: usize,
        destination_is_directory: i32,
        timeout_millis: u64,
        accessor: NativeAccessor,
        context: *mut c_void,
        result: *mut NativePresenterProbeResult,
        error: *mut NativeError,
    ) -> i32;

    fn ztd_mac_evict_ubiquitous_item(
        path: *const u8,
        path_len: usize,
        is_directory: i32,
        error: *mut NativeError,
    ) -> i32;
}

fn zeroed_native_error() -> NativeError {
    NativeError {
        kind: 0,
        code: 0,
        domain: [0; ERROR_DOMAIN_CAPACITY],
        message: [0; ERROR_MESSAGE_CAPACITY],
    }
}

fn native_error_message(error: &NativeError) -> String {
    let domain = unsafe { CStr::from_ptr(error.domain.as_ptr()) }.to_string_lossy();
    let message = unsafe { CStr::from_ptr(error.message.as_ptr()) }.to_string_lossy();
    format!(
        "native kind {}, {domain} code {}: {message}",
        error.kind, error.code
    )
}

struct ProbeMoveState {
    root: File,
    expected_source: Vec<u8>,
    expected_destination: Vec<u8>,
    source_name: CString,
    destination_name: CString,
}

unsafe extern "C" fn probe_move_accessor(
    context: *mut c_void,
    source_path: *const u8,
    source_path_len: usize,
    destination_path: *const u8,
    destination_path_len: usize,
) -> c_int {
    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        if context.is_null()
            || source_path.is_null()
            || destination_path.is_null()
            || source_path_len == 0
            || destination_path_len == 0
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "native presenter probe supplied an invalid accessor argument",
            ));
        }
        let state = unsafe { &mut *context.cast::<ProbeMoveState>() };
        let source = unsafe { std::slice::from_raw_parts(source_path, source_path_len) };
        let destination =
            unsafe { std::slice::from_raw_parts(destination_path, destination_path_len) };
        if source != state.expected_source || destination != state.expected_destination {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "Foundation adjusted an exact presenter probe path",
            ));
        }
        let status = unsafe {
            libc::renameat(
                state.root.as_raw_fd(),
                state.source_name.as_ptr(),
                state.root.as_raw_fd(),
                state.destination_name.as_ptr(),
            )
        };
        if status == 0 {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    }));
    match outcome {
        Ok(Ok(())) => 0,
        Ok(Err(_)) | Err(_) => 1,
    }
}

fn local_test_directory(label: &str) -> PathBuf {
    for _ in 0..1024 {
        let id = TEST_ID.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "zerotrust-drive-{label}-{}-{id}",
            std::process::id()
        ));
        match fs::create_dir(&path) {
            Ok(()) => return fs::canonicalize(path).expect("canonicalize macOS test directory"),
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(error) => panic!("create macOS test directory: {error}"),
        }
    }
    panic!("could not allocate a unique macOS test directory");
}

fn open_directory(path: &Path) -> io::Result<File> {
    let path = CString::new(path.as_os_str().as_bytes())?;
    let fd = unsafe {
        libc::open(
            path.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(unsafe { File::from_raw_fd(fd) })
    }
}

#[test]
fn ns_file_presenter_probe_observes_exact_descriptor_rooted_move() {
    let directory = local_test_directory("presenter-probe");
    fs::write(directory.join("source"), b"new generation").unwrap();
    fs::write(directory.join("destination"), b"old generation").unwrap();
    let source = directory.join("source");
    let destination = directory.join("destination");
    let source_bytes = source.as_os_str().as_bytes();
    let destination_bytes = destination.as_os_str().as_bytes();
    let mut state = ProbeMoveState {
        root: open_directory(&directory).unwrap(),
        expected_source: source_bytes.to_vec(),
        expected_destination: destination_bytes.to_vec(),
        source_name: CString::new("source").unwrap(),
        destination_name: CString::new("destination").unwrap(),
    };
    let purpose = b"net.lifub.zerotrust-drive.presenter-probe-test";
    let mut result = NativePresenterProbeResult::default();
    let mut error = zeroed_native_error();

    let status = unsafe {
        ztd_mac_probe_coordinated_move(
            purpose.as_ptr(),
            purpose.len(),
            source_bytes.as_ptr(),
            source_bytes.len(),
            0,
            destination_bytes.as_ptr(),
            destination_bytes.len(),
            0,
            10_000,
            probe_move_accessor,
            (&mut state as *mut ProbeMoveState).cast::<c_void>(),
            &mut result,
            &mut error,
        )
    };
    assert_eq!(status, 0, "{}", native_error_message(&error));
    assert!(
        result.relinquish_writer_count >= 1,
        "presenter never relinquished to the coordinated writer: {}",
        result.relinquish_writer_count
    );
    assert_eq!(result.move_count, 1);
    assert_eq!(result.destination_matches, 1);
    assert!(!source.exists());
    assert_eq!(fs::read(destination).unwrap(), b"new generation");

    state.root.sync_all().unwrap();
    drop(state);
    fs::remove_dir_all(directory).unwrap();
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct DirectoryIdentity {
    device: u64,
    inode: u64,
}

impl DirectoryIdentity {
    fn from_file(file: &File) -> io::Result<Self> {
        let metadata = file.metadata()?;
        if !metadata.is_dir() || metadata.ino() == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "iCloud test capability is not a stable directory",
            ));
        }
        Ok(Self {
            device: metadata.dev(),
            inode: metadata.ino(),
        })
    }
}

pub(crate) struct IcloudTestSuite {
    selected_parent: PathBuf,
    path: PathBuf,
    parent: File,
    child: File,
    parent_identity: DirectoryIdentity,
    child_identity: DirectoryIdentity,
    owner_token: Vec<u8>,
    effective_content_policy: String,
    expect_keep_downloaded: bool,
    timeout: Duration,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum SnapshotEntry {
    Directory,
    File {
        len: u64,
        links: u64,
        digest: [u8; 32],
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct IcloudTreeSnapshot {
    entries: BTreeMap<PathBuf, SnapshotEntry>,
}

impl IcloudTestSuite {
    pub(crate) fn create_keep_downloaded(label: &str) -> Self {
        Self::create(
            label,
            ICLOUD_ROOT_ENV,
            ICLOUD_CONFIRM_ENV,
            ICLOUD_CONFIRM_VALUE,
            true,
        )
    }

    fn create_evictable(label: &str) -> Self {
        Self::create(
            label,
            ICLOUD_MATERIALIZATION_ROOT_ENV,
            ICLOUD_MATERIALIZATION_CONFIRM_ENV,
            ICLOUD_MATERIALIZATION_CONFIRM_VALUE,
            false,
        )
    }

    fn create(
        label: &str,
        root_env: &str,
        confirm_env: &str,
        confirm_value: &str,
        expect_keep_downloaded: bool,
    ) -> Self {
        assert_eq!(
            std::env::var(ICLOUD_RUN_ENV).as_deref(),
            Ok("1"),
            "an explicitly selected iCloud gate requires {ICLOUD_RUN_ENV}=1"
        );
        assert_eq!(
            std::env::var(confirm_env).as_deref(),
            Ok(confirm_value),
            "set {confirm_env}={confirm_value} after selecting the required disposable iCloud folder"
        );
        let configured = PathBuf::from(
            std::env::var_os(root_env)
                .unwrap_or_else(|| panic!("{root_env} must name the selected folder")),
        );
        assert!(
            configured.is_absolute(),
            "iCloud test root must be absolute"
        );
        let selected_parent = fs::canonicalize(&configured)
            .unwrap_or_else(|error| panic!("canonicalize {}: {error}", configured.display()));
        assert_eq!(
            configured, selected_parent,
            "iCloud test root must already be canonical and must not be a symlink"
        );
        let metadata = fs::symlink_metadata(&selected_parent)
            .unwrap_or_else(|error| panic!("inspect {}: {error}", selected_parent.display()));
        assert!(metadata.is_dir() && !metadata.file_type().is_symlink());

        let parent_store = StoreRoot::open_macos(&selected_parent)
            .unwrap_or_else(|error| panic!("open selected iCloud folder: {error}"));
        let status = parent_store
            .query_root_ubiquity()
            .unwrap_or_else(|error| panic!("query selected iCloud folder: {error}"));
        assert!(
            status.is_ubiquitous,
            "{} is not managed by iCloud/File Provider",
            selected_parent.display()
        );
        assert_settled_icloud_status(&selected_parent, &status);
        let evaluation = fileprovider_evaluate(&selected_parent);
        assert_eq!(
            evaluated_boolean(&evaluation, "isKeepDownloaded"),
            Some(expect_keep_downloaded),
            "the exact selected folder has the wrong Keep Downloaded policy (expected {expect_keep_downloaded}), or fileproviderctl changed its output:\n{evaluation}"
        );
        assert_eq!(
            evaluated_boolean(&evaluation, "isRecursivelyDownloaded"),
            Some(true),
            "the selected folder is not yet recursively materialized; wait for Finder to finish before running the gate:\n{evaluation}"
        );
        let effective_content_policy =
            evaluated_scalar(&evaluation, "Effective Content Policy:").unwrap_or_else(|| {
                panic!(
                    "fileproviderctl did not report one unambiguous effective content policy for the selected folder:\n{evaluation}"
                )
            });

        let parent = open_directory(&selected_parent).expect("open selected iCloud parent");
        let parent_identity = DirectoryIdentity::from_file(&parent).unwrap();
        let timeout = configured_icloud_timeout();
        let random = random_bytes();
        let random_hex = hex(&random[..8]);
        let mut allocated = None;
        for attempt in 0..1024u64 {
            let name = format!(
                "zerotrust-drive-test-{label}-{}-{random_hex}-{attempt}",
                std::process::id()
            );
            let c_name = CString::new(name.as_bytes()).unwrap();
            let result = unsafe { libc::mkdirat(parent.as_raw_fd(), c_name.as_ptr(), 0o700) };
            if result == 0 {
                allocated = Some((name, c_name));
                break;
            }
            let error = io::Error::last_os_error();
            if error.kind() != io::ErrorKind::AlreadyExists {
                panic!("create disposable iCloud test child: {error}");
            }
        }
        let (name, c_name) = allocated.expect("allocate unique disposable iCloud test child");
        parent.sync_all().expect("sync selected iCloud parent");
        let child_fd = unsafe {
            libc::openat(
                parent.as_raw_fd(),
                c_name.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        assert!(
            child_fd >= 0,
            "open disposable iCloud child: {}",
            io::Error::last_os_error()
        );
        let child = unsafe { File::from_raw_fd(child_fd) };
        let child_identity = DirectoryIdentity::from_file(&child).unwrap();
        let path = selected_parent.join(name);
        assert_eq!(fs::canonicalize(&path).unwrap(), path);

        let owner_token = random_bytes().to_vec();
        write_new_at(&child, OWNER_MARKER, &owner_token).expect("write iCloud owner marker");
        child.sync_all().expect("sync iCloud test child");
        eprintln!(
            "allocated exact disposable iCloud test child {}; any failed gate preserves this complete child for inspection",
            path.display()
        );

        Self {
            selected_parent,
            path,
            parent,
            child,
            parent_identity,
            child_identity,
            owner_token,
            effective_content_policy,
            expect_keep_downloaded,
            timeout,
        }
    }

    pub(crate) fn path(&self) -> &Path {
        &self.path
    }

    pub(crate) fn capability(&self) -> &File {
        &self.child
    }

    pub(crate) fn await_materialized_and_uploaded(&self) {
        let store = StoreRoot::open_macos(&self.path).expect("open disposable iCloud test child");
        let deadline = Instant::now()
            .checked_add(self.timeout)
            .expect("valid iCloud test timeout");
        request_icloud_tree_download(
            &store,
            &self.child,
            deadline.saturating_duration_since(Instant::now()),
        );
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            let mut last_blockers = inspect_icloud_tree(&store, &self.child, &self.path, remaining)
                .unwrap_or_else(|error| {
                    panic!(
                        "descriptor-rooted inspection of {} failed closed: {error}",
                        self.path.display()
                    )
                });
            if last_blockers.is_empty() {
                ensure_before_deadline(deadline, "iCloud settlement polling timed out")
                    .expect("iCloud settlement deadline");
                let evaluation = fileprovider_evaluate_with_timeout(
                    &self.path,
                    FILEPROVIDERCTL_TIMEOUT.min(deadline.saturating_duration_since(Instant::now())),
                );
                let child_policy = evaluated_scalar(&evaluation, "Effective Content Policy:");
                if evaluated_boolean(&evaluation, "isRecursivelyDownloaded") == Some(true)
                    && evaluated_boolean(&evaluation, "isKeepDownloaded")
                        == Some(self.expect_keep_downloaded)
                    && child_policy.as_deref() == Some(self.effective_content_policy.as_str())
                {
                    return;
                }
                last_blockers.push(format!(
                    "fileproviderctl does not report recursive materialization with inherited Keep Downloaded={} and content policy {:?}:\n{evaluation}",
                    self.expect_keep_downloaded, self.effective_content_policy
                ));
            }
            if Instant::now() >= deadline {
                panic!(
                    "iCloud test child did not become completely current, uploaded, conflict-free, and recursively downloaded within {:?}:\n{}",
                    self.timeout,
                    last_blockers.join("\n")
                );
            }
            std::thread::sleep(Duration::from_secs(1));
        }
    }

    pub(crate) fn capture_tree_snapshot(&self) -> IcloudTreeSnapshot {
        snapshot_directory_tree(&self.child, self.timeout)
            .unwrap_or_else(|error| panic!("snapshot {}: {error}", self.path.display()))
    }

    pub(crate) fn verify_owned_child(&self) {
        assert_eq!(
            DirectoryIdentity::from_file(&self.parent).unwrap(),
            self.parent_identity,
            "retained iCloud test parent changed identity"
        );
        assert_eq!(
            DirectoryIdentity::from_file(&open_directory(&self.selected_parent).unwrap()).unwrap(),
            self.parent_identity,
            "visible iCloud test parent changed identity"
        );
        assert_eq!(
            DirectoryIdentity::from_file(&self.child).unwrap(),
            self.child_identity,
            "retained iCloud test child changed identity"
        );
        assert_eq!(
            DirectoryIdentity::from_file(&open_directory(&self.path).unwrap()).unwrap(),
            self.child_identity,
            "visible iCloud test child changed identity"
        );
        assert_eq!(
            read_exact_regular_at(&self.child, OWNER_MARKER, self.owner_token.len())
                .expect("read bounded iCloud owner marker"),
            self.owner_token,
            "iCloud test owner marker changed; preserving the complete child"
        );
    }

    pub(crate) fn finish_and_preserve(self) {
        self.verify_owned_child();
        let snapshot = self.capture_tree_snapshot();
        eprintln!(
            "successful iCloud gate preserved {} with {} exact entries for manual inspection and cleanup",
            self.path.display(),
            snapshot.entries.len()
        );
    }
}

fn random_bytes() -> [u8; 32] {
    let mut random = [0u8; 32];
    let status = unsafe { libc::getentropy(random.as_mut_ptr().cast::<c_void>(), random.len()) };
    assert_eq!(status, 0, "getentropy: {}", io::Error::last_os_error());
    random
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut value = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        value.push(DIGITS[(byte >> 4) as usize] as char);
        value.push(DIGITS[(byte & 0x0f) as usize] as char);
    }
    value
}

fn write_new_at(parent: &File, name: &str, bytes: &[u8]) -> io::Result<()> {
    let name = CString::new(name)?;
    let fd = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            name.as_ptr(),
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            0o600,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    let mut file = unsafe { File::from_raw_fd(fd) };
    file.write_all(bytes)?;
    file.sync_all()
}

fn read_exact_regular_at(parent: &File, name: &str, expected_len: usize) -> io::Result<Vec<u8>> {
    let name = CString::new(name)?;
    let fd = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY | libc::O_NONBLOCK | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    let mut file = unsafe { File::from_raw_fd(fd) };
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.nlink() != 1 || metadata.len() != expected_len as u64 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "iCloud owner marker changed type, link count, or exact length",
        ));
    }
    let mut bytes = Vec::with_capacity(expected_len);
    (&mut file)
        .take(expected_len.saturating_add(1) as u64)
        .read_to_end(&mut bytes)?;
    if bytes.len() != expected_len || file.metadata()?.len() != expected_len as u64 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "iCloud owner marker changed while it was read",
        ));
    }
    verify_visible_item(parent, OsStr::from_bytes(name.as_bytes()), &file, false)?;
    Ok(bytes)
}

fn open_item_at(parent: &File, name: &OsStr, flags: c_int) -> io::Result<File> {
    let name = CString::new(name.as_bytes())?;
    let fd = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            name.as_ptr(),
            flags | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(unsafe { File::from_raw_fd(fd) })
    }
}

fn set_readdir_errno_zero() {
    unsafe {
        *libc::__error() = 0;
    }
}

fn ensure_before_deadline(deadline: Instant, context: &str) -> io::Result<()> {
    if Instant::now() >= deadline {
        Err(io::Error::new(io::ErrorKind::TimedOut, context))
    } else {
        Ok(())
    }
}

fn item_identity(file: &File) -> io::Result<(u64, u64, bool)> {
    let metadata = file.metadata()?;
    if metadata.ino() == 0 || (!metadata.is_dir() && !metadata.is_file()) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "iCloud tree entry has no stable regular-file or directory identity",
        ));
    }
    Ok((metadata.dev(), metadata.ino(), metadata.is_dir()))
}

fn verify_visible_item(
    parent: &File,
    name: &OsStr,
    retained: &File,
    is_directory: bool,
) -> io::Result<()> {
    let retained_before = item_identity(retained)?;
    if retained_before.2 != is_directory {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "retained iCloud item changed kind",
        ));
    }
    let flags = if is_directory {
        libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NONBLOCK
    } else {
        libc::O_RDONLY | libc::O_NONBLOCK
    };
    let visible = open_item_at(parent, name, flags)?;
    let visible_identity = item_identity(&visible)?;
    let retained_after = item_identity(retained)?;
    if retained_before != retained_after || visible_identity != retained_before {
        return Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "iCloud tree entry changed identity during descriptor-rooted traversal",
        ));
    }
    Ok(())
}

fn walk_descriptor_directory<F>(
    directory: &File,
    prefix: &Path,
    depth: usize,
    deadline: Instant,
    visited: &mut usize,
    visitor: &mut F,
) -> io::Result<()>
where
    F: FnMut(&Path, &File, bool) -> io::Result<()>,
{
    if depth > MAX_ICLOUD_DEPTH {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "descriptor-rooted iCloud traversal exceeded its depth limit",
        ));
    }
    ensure_before_deadline(deadline, "descriptor-rooted iCloud traversal timed out")?;
    let dot = CString::new(".").unwrap();
    let fd = unsafe {
        libc::openat(
            directory.as_raw_fd(),
            dot.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    let stream = unsafe { libc::fdopendir(fd) };
    if stream.is_null() {
        let error = io::Error::last_os_error();
        unsafe {
            libc::close(fd);
        }
        return Err(error);
    }
    let result = (|| -> io::Result<()> {
        loop {
            ensure_before_deadline(deadline, "descriptor-rooted iCloud enumeration timed out")?;
            set_readdir_errno_zero();
            let entry = unsafe { libc::readdir(stream) };
            if entry.is_null() {
                let error = io::Error::last_os_error();
                return if error.raw_os_error() == Some(0) {
                    Ok(())
                } else {
                    Err(error)
                };
            }
            ensure_before_deadline(deadline, "descriptor-rooted iCloud enumeration timed out")?;
            let bytes = unsafe { CStr::from_ptr((*entry).d_name.as_ptr()) }.to_bytes();
            if bytes == b"." || bytes == b".." {
                continue;
            }
            *visited = visited
                .checked_add(1)
                .ok_or_else(|| io::Error::from_raw_os_error(libc::EFBIG))?;
            if *visited > MAX_ICLOUD_ENTRIES {
                return Err(io::Error::from_raw_os_error(libc::EFBIG));
            }
            let mut name_bytes = Vec::new();
            name_bytes
                .try_reserve_exact(bytes.len())
                .map_err(|_| io::Error::from_raw_os_error(libc::ENOMEM))?;
            name_bytes.extend_from_slice(bytes);
            let name = OsString::from_vec(name_bytes);
            let relative = prefix.join(&name);
            let (child, is_directory) =
                match open_item_at(directory, &name, libc::O_RDONLY | libc::O_DIRECTORY) {
                    Ok(child) => (child, true),
                    Err(error) if error.raw_os_error() == Some(libc::ENOTDIR) => (
                        open_item_at(directory, &name, libc::O_RDONLY | libc::O_NONBLOCK)?,
                        false,
                    ),
                    Err(error) => return Err(error),
                };
            if item_identity(&child)?.2 != is_directory {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "iCloud traversal encountered a special or unstable item",
                ));
            }
            verify_visible_item(directory, &name, &child, is_directory)?;
            visitor(&relative, &child, is_directory)?;
            if is_directory {
                walk_descriptor_directory(
                    &child,
                    &relative,
                    depth + 1,
                    deadline,
                    visited,
                    visitor,
                )?;
            }
            verify_visible_item(directory, &name, &child, is_directory)?;
        }
    })();
    let close_result = unsafe { libc::closedir(stream) };
    result?;
    if close_result != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn walk_descriptor_tree(
    root: &File,
    timeout: Duration,
    mut visitor: impl FnMut(&Path, &File, bool) -> io::Result<()>,
) -> io::Result<()> {
    let deadline = Instant::now()
        .checked_add(timeout)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "invalid iCloud timeout"))?;
    let mut visited = 0usize;
    walk_descriptor_directory(root, Path::new(""), 0, deadline, &mut visited, &mut visitor)
}

fn fingerprint_regular_file(
    file: &mut File,
    max_len: u64,
    deadline: Instant,
) -> io::Result<(u64, u64, [u8; 32])> {
    ensure_before_deadline(deadline, "iCloud file fingerprint timed out")?;
    let before = file.metadata()?;
    if !before.is_file() || before.len() > max_len {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "iCloud snapshot entry is not a bounded regular file",
        ));
    }
    let expected_identity = (before.dev(), before.ino());
    let mut hasher = Blake2s256::new();
    let mut total = 0u64;
    let mut buffer = [0u8; 64 * 1024];
    loop {
        ensure_before_deadline(deadline, "iCloud file fingerprint timed out")?;
        let read = file.read(&mut buffer)?;
        ensure_before_deadline(deadline, "iCloud file fingerprint timed out")?;
        if read == 0 {
            break;
        }
        total = total
            .checked_add(read as u64)
            .ok_or_else(|| io::Error::from_raw_os_error(libc::EFBIG))?;
        if total > before.len() || total > max_len {
            return Err(io::Error::from_raw_os_error(libc::EFBIG));
        }
        hasher.update(&buffer[..read]);
    }
    let after = file.metadata()?;
    if total != before.len()
        || !after.is_file()
        || (after.dev(), after.ino()) != expected_identity
        || after.len() != before.len()
        || after.nlink() != before.nlink()
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "iCloud snapshot file changed while it was fingerprinted",
        ));
    }
    Ok((total, before.nlink(), hasher.finalize().into()))
}

fn snapshot_directory_tree(root: &File, timeout: Duration) -> io::Result<IcloudTreeSnapshot> {
    let deadline = Instant::now()
        .checked_add(timeout)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "invalid iCloud timeout"))?;
    let mut entries = BTreeMap::new();
    let mut total_bytes = 0u64;
    walk_descriptor_tree(root, timeout, |relative, file, is_directory| {
        let entry = if is_directory {
            SnapshotEntry::Directory
        } else {
            let mut file = file.try_clone()?;
            let (len, links, digest) =
                fingerprint_regular_file(&mut file, MAX_ICLOUD_FILE_BYTES, deadline)?;
            total_bytes = total_bytes
                .checked_add(len)
                .ok_or_else(|| io::Error::from_raw_os_error(libc::EFBIG))?;
            if total_bytes > MAX_ICLOUD_SNAPSHOT_BYTES {
                return Err(io::Error::from_raw_os_error(libc::EFBIG));
            }
            SnapshotEntry::File { len, links, digest }
        };
        if entries.insert(relative.to_path_buf(), entry).is_some() {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "iCloud snapshot repeated one exact relative name",
            ));
        }
        Ok(())
    })?;
    Ok(IcloudTreeSnapshot { entries })
}

fn evict_icloud_item(path: &Path, is_directory: bool) {
    let bytes = path.as_os_str().as_bytes();
    let mut error = zeroed_native_error();
    let status = unsafe {
        ztd_mac_evict_ubiquitous_item(
            bytes.as_ptr(),
            bytes.len(),
            i32::from(is_directory),
            &mut error,
        )
    };
    assert_eq!(
        status,
        0,
        "evict only the local iCloud fixture copy: {}",
        native_error_message(&error)
    );
}

fn configured_icloud_timeout() -> Duration {
    let seconds = match std::env::var(ICLOUD_TIMEOUT_ENV) {
        Ok(value) => value
            .parse::<u64>()
            .unwrap_or_else(|error| panic!("parse {ICLOUD_TIMEOUT_ENV}={value:?}: {error}")),
        Err(std::env::VarError::NotPresent) => 900,
        Err(error) => panic!("read {ICLOUD_TIMEOUT_ENV}: {error}"),
    };
    assert!(
        (30..=3600).contains(&seconds),
        "{ICLOUD_TIMEOUT_ENV} must be between 30 and 3600 seconds"
    );
    Duration::from_secs(seconds)
}

fn read_bounded_to_end(reader: &mut impl Read, max_len: usize) -> io::Result<Vec<u8>> {
    let mut bytes = Vec::with_capacity(max_len.min(8 * 1024));
    let mut buffer = [0u8; 8 * 1024];
    let mut overflowed = false;
    loop {
        let read = reader.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        let remaining = max_len.saturating_sub(bytes.len());
        let retained = read.min(remaining);
        bytes.extend_from_slice(&buffer[..retained]);
        overflowed |= retained != read;
    }
    if overflowed {
        Err(io::Error::from_raw_os_error(libc::EFBIG))
    } else {
        Ok(bytes)
    }
}

fn temporary_output_capture(label: &str) -> (File, PathBuf) {
    for _ in 0..1024 {
        let id = TEST_ID.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "zerotrust-drive-fileproviderctl-{label}-{}-{id}",
            std::process::id()
        ));
        let mut options = OpenOptions::new();
        options.create_new(true).read(true).write(true).mode(0o600);
        match options.open(&path) {
            Ok(file) => return (file, path),
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(error) => panic!("create fileproviderctl {label} capture: {error}"),
        }
    }
    panic!("could not allocate a unique fileproviderctl {label} capture");
}

fn wait_with_timeout(mut child: Child, timeout: Duration) -> std::process::ExitStatus {
    let deadline = Instant::now() + timeout;
    loop {
        match child.try_wait().expect("poll fileproviderctl") {
            Some(status) => return status,
            None if Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(20));
            }
            None => {
                if let Ok(process_id) = i32::try_from(child.id())
                    && let Some(process_group) = process_id.checked_neg()
                {
                    let _ = unsafe { libc::kill(process_group, libc::SIGKILL) };
                }
                let _ = child.kill();
                let _ = child.wait();
                panic!("fileproviderctl exceeded {timeout:?}");
            }
        }
    }
}

#[test]
fn bounded_subprocess_output_reader_drains_and_fails_closed() {
    let mut exact = io::Cursor::new(vec![7u8; 16]);
    assert_eq!(read_bounded_to_end(&mut exact, 16).unwrap(), vec![7u8; 16]);
    assert_eq!(exact.position(), 16);

    let mut oversized = io::Cursor::new(vec![9u8; 65]);
    let error = read_bounded_to_end(&mut oversized, 64).unwrap_err();
    assert_eq!(error.raw_os_error(), Some(libc::EFBIG));
    assert_eq!(
        oversized.position(),
        65,
        "the pipe was not completely drained"
    );
}

fn fileprovider_evaluate(path: &Path) -> String {
    fileprovider_evaluate_with_timeout(path, FILEPROVIDERCTL_TIMEOUT)
}

fn fileprovider_evaluate_with_timeout(path: &Path, timeout: Duration) -> String {
    let (mut stdout, stdout_path) = temporary_output_capture("stdout");
    let (mut stderr, stderr_path) = temporary_output_capture("stderr");
    let mut command = Command::new("/usr/bin/fileproviderctl");
    command
        .arg("evaluate")
        .arg(path)
        .env("LC_ALL", "C")
        .stdin(Stdio::null())
        .stdout(Stdio::from(
            stdout
                .try_clone()
                .expect("clone fileproviderctl stdout capture"),
        ))
        .stderr(Stdio::from(
            stderr
                .try_clone()
                .expect("clone fileproviderctl stderr capture"),
        ))
        .process_group(0);
    unsafe {
        command.pre_exec(|| {
            let limit = libc::rlimit {
                rlim_cur: MAX_FILEPROVIDERCTL_OUTPUT_BYTES as libc::rlim_t,
                rlim_max: MAX_FILEPROVIDERCTL_OUTPUT_BYTES as libc::rlim_t,
            };
            if libc::setrlimit(libc::RLIMIT_FSIZE, &limit) == 0 {
                Ok(())
            } else {
                Err(io::Error::last_os_error())
            }
        });
    }
    let child = command.spawn();
    fs::remove_file(&stdout_path).expect("unlink fileproviderctl stdout capture");
    fs::remove_file(&stderr_path).expect("unlink fileproviderctl stderr capture");
    let child = child.unwrap_or_else(|error| panic!("start fileproviderctl evaluate: {error}"));
    let status = wait_with_timeout(child, timeout);
    stdout
        .seek(SeekFrom::Start(0))
        .expect("rewind fileproviderctl stdout capture");
    stderr
        .seek(SeekFrom::Start(0))
        .expect("rewind fileproviderctl stderr capture");
    let output = Output {
        status,
        stdout: read_bounded_to_end(&mut stdout, MAX_FILEPROVIDERCTL_OUTPUT_BYTES)
            .expect("read bounded fileproviderctl stdout"),
        stderr: read_bounded_to_end(&mut stderr, MAX_FILEPROVIDERCTL_OUTPUT_BYTES)
            .expect("read bounded fileproviderctl stderr"),
    };
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        output.status.success(),
        "fileproviderctl evaluate {} failed with {}:\n{combined}",
        path.display(),
        output.status
    );
    combined
}

fn evaluated_boolean(output: &str, name: &str) -> Option<bool> {
    let prefix = format!("{name} = ");
    let values: Vec<_> = output
        .lines()
        .filter_map(|line| line.trim().strip_prefix(&prefix))
        .collect();
    match values.as_slice() {
        [value] => match value.trim_end_matches(';') {
            "0" => Some(false),
            "1" => Some(true),
            _ => None,
        },
        _ => None,
    }
}

fn evaluated_scalar(output: &str, name: &str) -> Option<String> {
    let values: Vec<_> = output
        .lines()
        .filter_map(|line| line.trim().strip_prefix(name))
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
        .collect();
    match values.as_slice() {
        [value] => Some(value.clone()),
        _ => None,
    }
}

#[test]
fn fileproviderctl_boolean_parser_fails_closed_on_ambiguity() {
    assert_eq!(
        evaluated_boolean("    isKeepDownloaded = 1;\n", "isKeepDownloaded"),
        Some(true)
    );
    assert_eq!(
        evaluated_boolean("isKeepDownloaded = 0;\n", "isKeepDownloaded"),
        Some(false)
    );
    assert_eq!(
        evaluated_boolean(
            "isKeepDownloaded = 1;\nisKeepDownloaded = 0;\n",
            "isKeepDownloaded"
        ),
        None
    );
    assert_eq!(
        evaluated_boolean("isKeepDownloaded = unknown;\n", "isKeepDownloaded"),
        None
    );
    assert_eq!(
        evaluated_boolean(
            "isKeepDownloaded = 1;\nisKeepDownloaded = unknown;\n",
            "isKeepDownloaded"
        ),
        None
    );
    assert_eq!(
        evaluated_scalar("Effective Content Policy: 3\n", "Effective Content Policy:"),
        Some("3".to_string())
    );
    assert_eq!(
        evaluated_scalar(
            "Effective Content Policy: 3\nEffective Content Policy: 1\n",
            "Effective Content Policy:"
        ),
        None
    );
}

#[test]
fn descriptor_rooted_icloud_snapshot_is_byte_exact_and_rejects_symlinks() {
    use std::os::unix::fs::symlink;

    let directory = local_test_directory("icloud-snapshot");
    fs::create_dir(directory.join("nested")).unwrap();
    fs::write(directory.join("first.bin"), b"first bytes").unwrap();
    fs::write(directory.join("nested/second.bin"), b"second bytes").unwrap();
    let root = open_directory(&directory).unwrap();

    let first = snapshot_directory_tree(&root, Duration::from_secs(5)).unwrap();
    let second = snapshot_directory_tree(&root, Duration::from_secs(5)).unwrap();
    assert_eq!(second, first);
    fs::write(directory.join("nested/second.bin"), b"changed-byte").unwrap();
    let changed = snapshot_directory_tree(&root, Duration::from_secs(5)).unwrap();
    assert_ne!(changed, first);

    symlink("first.bin", directory.join("provider-link")).unwrap();
    assert!(snapshot_directory_tree(&root, Duration::from_secs(5)).is_err());
    fs::remove_dir_all(directory).unwrap();
}

#[test]
fn bounded_owner_marker_read_rejects_wrong_length_links_and_symlinks() {
    use std::os::unix::fs::symlink;

    let directory = local_test_directory("icloud-owner-marker");
    let root = open_directory(&directory).unwrap();
    write_new_at(&root, OWNER_MARKER, b"owner").unwrap();
    assert_eq!(
        read_exact_regular_at(&root, OWNER_MARKER, 5).unwrap(),
        b"owner"
    );
    assert!(read_exact_regular_at(&root, OWNER_MARKER, 4).is_err());

    fs::hard_link(
        directory.join(OWNER_MARKER),
        directory.join("owner-hard-link"),
    )
    .unwrap();
    assert!(read_exact_regular_at(&root, OWNER_MARKER, 5).is_err());
    fs::remove_file(directory.join("owner-hard-link")).unwrap();
    fs::remove_file(directory.join(OWNER_MARKER)).unwrap();
    symlink("missing-owner", directory.join(OWNER_MARKER)).unwrap();
    assert!(read_exact_regular_at(&root, OWNER_MARKER, 5).is_err());
    fs::remove_dir_all(directory).unwrap();
}

fn request_icloud_tree_download(store: &StoreRoot, root: &File, timeout: Duration) {
    store
        .start_root_download()
        .unwrap_or_else(|error| panic!("request exact iCloud child download: {error}"));
    walk_descriptor_tree(root, timeout, |relative, _file, is_directory| {
        let entry = store
            .entry(RelativeStorePath::new(relative).unwrap())
            .map_err(|error| {
                io::Error::new(
                    error.kind(),
                    format!("pin descriptor-rooted iCloud entry {relative:?}: {error}"),
                )
            })?;
        store
            .start_entry_download(&entry, is_directory)
            .map_err(|error| {
                io::Error::new(
                    error.kind(),
                    format!("request download for {relative:?}: {error}"),
                )
            })
    })
    .unwrap_or_else(|error| panic!("descriptor-rooted iCloud download walk: {error}"));
}

fn inspect_icloud_tree(
    store: &StoreRoot,
    root: &File,
    display_root: &Path,
    timeout: Duration,
) -> io::Result<Vec<String>> {
    let mut blockers = Vec::new();
    match store.query_root_ubiquity() {
        Ok(status) => inspect_status(
            display_root,
            status,
            || store.start_root_download(),
            &mut blockers,
        ),
        Err(error) => blockers.push(format!("query {}: {error}", display_root.display())),
    }

    walk_descriptor_tree(root, timeout, |relative, _file, is_directory| {
        let child = display_root.join(relative);
        let entry = store.entry(RelativeStorePath::new(relative)?)?;
        match store.query_entry_ubiquity(&entry, is_directory) {
            Ok(status) => inspect_status(
                &child,
                status,
                || store.start_entry_download(&entry, is_directory),
                &mut blockers,
            ),
            Err(error) => blockers.push(format!("query {}: {error}", child.display())),
        }
        Ok(())
    })?;
    Ok(blockers)
}

fn inspect_status(
    path: &Path,
    status: UbiquityStatus,
    start_download: impl FnOnce() -> io::Result<()>,
    blockers: &mut Vec<String>,
) {
    if !status.is_ubiquitous {
        blockers.push(format!("{} is not ubiquitous", path.display()));
    }
    if status.download_status != DownloadStatus::Current {
        if let Err(error) = start_download() {
            blockers.push(format!("request download for {}: {error}", path.display()));
        }
        blockers.push(format!(
            "{} download state is {:?}",
            path.display(),
            status.download_status
        ));
    }
    if status.is_downloading {
        blockers.push(format!("{} is still downloading", path.display()));
    }
    if status.is_uploaded != Some(true) || status.is_uploading {
        blockers.push(format!(
            "{} upload state is uploaded={:?}, uploading={}",
            path.display(),
            status.is_uploaded,
            status.is_uploading
        ));
    }
    if status.has_unresolved_conflicts != Some(false) {
        blockers.push(format!(
            "{} conflict state is {:?}",
            path.display(),
            status.has_unresolved_conflicts
        ));
    }
    if let Some(error) = status.download_error {
        blockers.push(format!("{} download error: {error}", path.display()));
    }
    if let Some(error) = status.upload_error {
        blockers.push(format!("{} upload error: {error}", path.display()));
    }
}

fn assert_settled_icloud_status(path: &Path, status: &UbiquityStatus) {
    assert_eq!(
        status.download_status,
        DownloadStatus::Current,
        "selected iCloud folder is not current: {}: {status:?}",
        path.display()
    );
    assert!(!status.is_downloading, "{path:?} is still downloading");
    assert_eq!(
        status.is_uploaded,
        Some(true),
        "selected iCloud folder upload state is unknown or incomplete: {}: {status:?}",
        path.display()
    );
    assert!(!status.is_uploading, "{path:?} is still uploading");
    assert_eq!(
        status.has_unresolved_conflicts,
        Some(false),
        "selected iCloud folder has unresolved or unknown conflict state: {}: {status:?}",
        path.display()
    );
    assert!(
        status.download_error.is_none() && status.upload_error.is_none(),
        "selected iCloud folder has a provider error: {}: {status:?}",
        path.display()
    );
}

fn write_nested_icloud_fixture(suite: &IcloudTestSuite) -> PathBuf {
    let nested_name = CString::new("nested").unwrap();
    let result = unsafe { libc::mkdirat(suite.child.as_raw_fd(), nested_name.as_ptr(), 0o700) };
    assert_eq!(
        result,
        0,
        "create nested fixture: {}",
        io::Error::last_os_error()
    );
    let nested_path = suite.path().join("nested");
    let nested = open_item_at(
        &suite.child,
        OsStr::new("nested"),
        libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NONBLOCK,
    )
    .expect("open exact descriptor-rooted nested iCloud fixture");
    verify_visible_item(&suite.child, OsStr::new("nested"), &nested, true)
        .expect("verify exact nested iCloud fixture before writing");
    write_new_at(&nested, "materialized.age", ICLOUD_FIXTURE)
        .expect("write iCloud materialization fixture");
    nested.sync_all().expect("sync nested iCloud fixture");
    suite
        .child
        .sync_all()
        .expect("sync iCloud materialization tree");
    verify_visible_item(&suite.child, OsStr::new("nested"), &nested, true)
        .expect("verify exact nested iCloud fixture after writing");
    nested_path
}

fn read_visible_icloud_fixture(suite: &IcloudTestSuite) -> Vec<u8> {
    let nested = open_item_at(
        &suite.child,
        OsStr::new("nested"),
        libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NONBLOCK,
    )
    .expect("reopen exact visible nested iCloud fixture directory");
    read_exact_regular_at(&nested, "materialized.age", ICLOUD_FIXTURE.len())
        .expect("read exact visible iCloud fixture")
}

fn assert_snapshot_contains_icloud_fixture(snapshot: &IcloudTreeSnapshot) {
    assert_eq!(
        snapshot.entries.get(Path::new("nested")),
        Some(&SnapshotEntry::Directory),
        "iCloud snapshot lost the exact visible nested fixture directory"
    );
    let expected_digest: [u8; 32] = Blake2s256::digest(ICLOUD_FIXTURE).into();
    assert_eq!(
        snapshot.entries.get(Path::new("nested/materialized.age")),
        Some(&SnapshotEntry::File {
            len: ICLOUD_FIXTURE.len() as u64,
            links: 1,
            digest: expected_digest,
        }),
        "iCloud snapshot lost or changed the exact visible fixture file"
    );
}

#[test]
#[ignore = "requires an explicit disposable iCloud folder marked Keep Downloaded"]
fn real_icloud_keep_downloaded_gate() {
    let suite = IcloudTestSuite::create_keep_downloaded("keep-downloaded");
    write_nested_icloud_fixture(&suite);
    suite.await_materialized_and_uploaded();
    suite.verify_owned_child();
    assert_eq!(read_visible_icloud_fixture(&suite), ICLOUD_FIXTURE);
    let before_settle = suite.capture_tree_snapshot();
    assert_snapshot_contains_icloud_fixture(&before_settle);
    suite.await_materialized_and_uploaded();
    let after_settle = suite.capture_tree_snapshot();
    assert_snapshot_contains_icloud_fixture(&after_settle);
    assert_eq!(
        after_settle, before_settle,
        "iCloud changed an exact name, type, or regular-file byte fingerprint while the Keep Downloaded fixture settled"
    );
    assert_eq!(read_visible_icloud_fixture(&suite), ICLOUD_FIXTURE);
    suite.finish_and_preserve();
}

#[test]
#[ignore = "requires an explicit disposable iCloud folder not marked Keep Downloaded"]
fn real_icloud_materialization_transition_gate() {
    let suite = IcloudTestSuite::create_evictable("materialization");
    let nested_path = write_nested_icloud_fixture(&suite);
    suite.await_materialized_and_uploaded();
    suite.verify_owned_child();
    assert_eq!(read_visible_icloud_fixture(&suite), ICLOUD_FIXTURE);
    let before_eviction = suite.capture_tree_snapshot();
    assert_snapshot_contains_icloud_fixture(&before_eviction);

    let materialized_path = nested_path.join("materialized.age");
    evict_icloud_item(&materialized_path, false);
    let store = StoreRoot::open_macos(suite.path()).expect("open iCloud materialization store");
    let entry = store
        .entry(RelativeStorePath::new(Path::new("nested/materialized.age")).unwrap())
        .expect("pin exact evicted iCloud fixture");
    let deadline = Instant::now() + suite.timeout;
    loop {
        let status = store
            .query_entry_ubiquity(&entry, false)
            .expect("query exact evicted iCloud fixture");
        if status.download_status == DownloadStatus::NotDownloaded {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "iCloud eviction never exposed a dataless NotDownloaded fixture: {status:?}"
        );
        std::thread::sleep(Duration::from_millis(100));
    }
    store
        .start_entry_download(&entry, false)
        .expect("request exact iCloud fixture materialization");
    suite.await_materialized_and_uploaded();
    let after_materialization = suite.capture_tree_snapshot();
    assert_snapshot_contains_icloud_fixture(&after_materialization);
    assert_eq!(
        after_materialization, before_eviction,
        "iCloud changed an exact name, type, size, link count, or byte digest across eviction and materialization"
    );
    assert_eq!(read_visible_icloud_fixture(&suite), ICLOUD_FIXTURE);
    suite.finish_and_preserve();
}
