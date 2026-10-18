// SPDX-FileCopyrightText: Copyright 2026 Alexander Orlov <info@lifub.com>

//! Live FUSE lifecycle tests for the shipped binary.
//!
//! Each test mounts a fresh drive, writes through the mount without `fsync`,
//! and signals the process at once - well inside the state-flush debounce
//! window - so only a graceful unmount followed by the final flush keeps the
//! acknowledged data. They mount real filesystems, so they are ignored by
//! default and run only on Linux with `/dev/fuse` and an explicit opt-in:
//!
//! ```text
//! ZDRIVE_RUN_LIVE_FUSE_TESTS=1 \
//! cargo test --locked --test live_fuse -- --ignored --test-threads=1 --nocapture
//! ```

#![cfg(target_os = "linux")]

use std::fs::{self, File};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread::sleep;
use std::time::{Duration, Instant};

const RUN_ENV: &str = "ZDRIVE_RUN_LIVE_FUSE_TESTS";
const PASSPHRASE: &str = "live-fuse-test-passphrase";
// Hang guards only; a healthy run finishes each step in well under a second.
const MOUNT_TIMEOUT: Duration = Duration::from_secs(60);
const EXIT_TIMEOUT: Duration = Duration::from_secs(120);
const POLL_INTERVAL: Duration = Duration::from_millis(25);

static NEXT_DRIVE_ID: AtomicU64 = AtomicU64::new(0);

fn opted_in() -> bool {
    if std::env::var(RUN_ENV).as_deref() == Ok("1") {
        return true;
    }
    eprintln!("skipping live FUSE test; set {RUN_ENV}=1 on a Linux host with /dev/fuse");
    false
}

/// A throwaway encrypted store and mountpoint below the temp directory.
struct Drive {
    root: PathBuf,
    store: PathBuf,
    mountpoint: PathBuf,
}

impl Drive {
    fn new(label: &str) -> Self {
        let root = std::env::temp_dir().join(format!(
            "zdrive-live-fuse-{label}-{}-{}",
            std::process::id(),
            NEXT_DRIVE_ID.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(root.join("mnt")).expect("create mountpoint");
        // The binary mounts at the canonical path, so compare against it.
        let root = fs::canonicalize(&root).expect("canonicalize test root");
        Drive {
            store: root.join("store"),
            mountpoint: root.join("mnt"),
            root,
        }
    }
}

impl Drop for Drive {
    fn drop(&mut self) {
        force_unmount(&self.mountpoint);
        let _ = fs::remove_dir_all(&self.root);
    }
}

/// One running `zerotrust-drive` process serving a mount.
struct Mounted {
    child: Child,
    log: PathBuf,
    mountpoint: PathBuf,
}

impl Mounted {
    fn start(drive: &Drive, label: &str) -> Self {
        Self::start_with(drive, label, &[])
    }

    fn start_with(drive: &Drive, label: &str, extra_args: &[&str]) -> Self {
        let log = drive.root.join(format!("{label}.log"));
        let log_file = File::create(&log).expect("create process log");
        let child = Command::new(env!("CARGO_BIN_EXE_zerotrust-drive"))
            .arg("--encrypted-dir")
            .arg(&drive.store)
            .arg("--decrypted-dir")
            .arg(&drive.mountpoint)
            .args(extra_args)
            .env("ZEROTRUST_PASSPHRASE", PASSPHRASE)
            .env_remove("ZEROTRUST_NEW_PASSPHRASE")
            .stdin(Stdio::null())
            .stdout(log_file.try_clone().expect("clone log handle"))
            .stderr(log_file)
            .spawn()
            .expect("spawn zerotrust-drive");
        let mut mounted = Mounted {
            child,
            log,
            mountpoint: drive.mountpoint.clone(),
        };
        let deadline = Instant::now() + MOUNT_TIMEOUT;
        while !is_mounted(&mounted.mountpoint) {
            if let Some(status) = mounted.child.try_wait().expect("poll child") {
                panic!(
                    "zerotrust-drive exited before mounting ({status}); log:\n{}",
                    mounted.log()
                );
            }
            assert!(
                Instant::now() < deadline,
                "mount did not appear within {MOUNT_TIMEOUT:?}; log:\n{}",
                mounted.log()
            );
            sleep(POLL_INTERVAL);
        }
        mounted
    }

    fn signal(&self, signal: libc::c_int) {
        let pid = libc::pid_t::try_from(self.child.id()).expect("pid fits pid_t");
        // SAFETY: kill(2) has no memory-safety preconditions; the pid is our
        // own child, which has not been reaped yet.
        let rc = unsafe { libc::kill(pid, signal) };
        assert_eq!(rc, 0, "kill: {}", std::io::Error::last_os_error());
    }

    fn running(&mut self) -> bool {
        self.child.try_wait().expect("poll child").is_none()
    }

    fn wait_exit(&mut self) -> ExitStatus {
        let deadline = Instant::now() + EXIT_TIMEOUT;
        loop {
            if let Some(status) = self.child.try_wait().expect("poll child") {
                return status;
            }
            assert!(
                Instant::now() < deadline,
                "zerotrust-drive did not exit within {EXIT_TIMEOUT:?}; log:\n{}",
                self.log()
            );
            sleep(POLL_INTERVAL);
        }
    }

    fn wait_for_log(&mut self, needle: &str) {
        let deadline = Instant::now() + EXIT_TIMEOUT;
        while !self.log().contains(needle) {
            if let Some(status) = self.child.try_wait().expect("poll child") {
                panic!(
                    "zerotrust-drive exited ({status}) before logging {needle:?}; log:\n{}",
                    self.log()
                );
            }
            assert!(
                Instant::now() < deadline,
                "no {needle:?} within {EXIT_TIMEOUT:?}; log:\n{}",
                self.log()
            );
            sleep(POLL_INTERVAL);
        }
    }

    fn log(&self) -> String {
        fs::read_to_string(&self.log).unwrap_or_else(|error| format!("<log unreadable: {error}>"))
    }

    /// Stop the process gracefully and require a clean, flushed exit.
    fn stop(self, signal: libc::c_int) {
        self.signal(signal);
        self.expect_clean_exit(&format!("signal {signal}"));
    }

    /// Require a clean, flushed exit without sending anything more.
    fn expect_clean_exit(mut self, after: &str) {
        let status = self.wait_exit();
        assert!(
            status.success(),
            "expected a clean exit after {after}, got {status}; log:\n{}",
            self.log()
        );
        assert!(
            !is_mounted(&self.mountpoint),
            "mount is still present after a clean exit; log:\n{}",
            self.log()
        );
    }
}

impl Drop for Mounted {
    fn drop(&mut self) {
        if self.running() {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
        force_unmount(&self.mountpoint);
    }
}

fn unescape_mountinfo(field: &str) -> String {
    let bytes = field.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'\\'
            && index + 3 < bytes.len()
            && let Ok(value) = u8::from_str_radix(&field[index + 1..index + 4], 8)
        {
            out.push(value);
            index += 4;
            continue;
        }
        out.push(bytes[index]);
        index += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn is_mounted(mountpoint: &Path) -> bool {
    let mountinfo = fs::read_to_string("/proc/self/mountinfo").expect("read mountinfo");
    let wanted = mountpoint.to_string_lossy();
    mountinfo.lines().any(|line| {
        line.split(' ')
            .nth(4)
            .is_some_and(|field| unescape_mountinfo(field) == wanted)
    })
}

fn force_unmount(mountpoint: &Path) {
    if !is_mounted(mountpoint) {
        return;
    }
    for (program, args) in [
        ("fusermount3", &["-u", "-z", "--"][..]),
        ("fusermount", &["-u", "-z", "--"][..]),
        ("umount", &["-l", "--"][..]),
    ] {
        let _ = Command::new(program)
            .args(args)
            .arg(mountpoint)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
        if !is_mounted(mountpoint) {
            return;
        }
    }
}

/// Files spanning several sizes and a nested directory.
fn sample_files(label: &str) -> Vec<(PathBuf, Vec<u8>)> {
    let large: Vec<u8> = (0..(3 * 1024 * 1024 + 4099))
        .map(|index: usize| (index.wrapping_mul(31) ^ (index >> 7)) as u8)
        .collect();
    vec![
        (
            PathBuf::from("hello.txt"),
            format!("written just before {label}\n").into_bytes(),
        ),
        (PathBuf::from("nested/deeper/large.bin"), large),
        (PathBuf::from("nested/empty.txt"), Vec::new()),
    ]
}

fn write_files(mountpoint: &Path, files: &[(PathBuf, Vec<u8>)]) {
    for (relative, content) in files {
        let path = mountpoint.join(relative);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).expect("create directory through the mount");
        }
        fs::write(&path, content).expect("write through the mount");
    }
}

fn assert_files(mountpoint: &Path, files: &[(PathBuf, Vec<u8>)]) {
    for (relative, expected) in files {
        let actual = fs::read(mountpoint.join(relative))
            .unwrap_or_else(|error| panic!("read {} after remount: {error}", relative.display()));
        assert!(
            actual == *expected,
            "{} differs after remount ({} bytes, expected {})",
            relative.display(),
            actual.len(),
            expected.len()
        );
    }
}

fn signal_flushes_and_exits_cleanly(signal: libc::c_int, label: &str) {
    if !opted_in() {
        return;
    }
    let drive = Drive::new(label);
    let files = sample_files(label);

    let mounted = Mounted::start(&drive, "first");
    write_files(&drive.mountpoint, &files);
    mounted.stop(signal);

    let remounted = Mounted::start(&drive, "second");
    assert_files(&drive.mountpoint, &files);
    remounted.stop(libc::SIGTERM);
}

#[test]
#[ignore = "mounts a real FUSE filesystem; set ZDRIVE_RUN_LIVE_FUSE_TESTS=1"]
fn sigint_unmounts_flushes_and_exits_cleanly() {
    signal_flushes_and_exits_cleanly(libc::SIGINT, "sigint");
}

#[test]
#[ignore = "mounts a real FUSE filesystem; set ZDRIVE_RUN_LIVE_FUSE_TESTS=1"]
fn sigterm_unmounts_flushes_and_exits_cleanly() {
    signal_flushes_and_exits_cleanly(libc::SIGTERM, "sigterm");
}

#[test]
#[ignore = "mounts a real FUSE filesystem; set ZDRIVE_RUN_LIVE_FUSE_TESTS=1"]
fn sighup_unmounts_flushes_and_exits_cleanly() {
    signal_flushes_and_exits_cleanly(libc::SIGHUP, "sighup");
}

#[test]
#[ignore = "mounts a real FUSE filesystem; set ZDRIVE_RUN_LIVE_FUSE_TESTS=1"]
fn busy_mount_keeps_serving_until_files_are_closed() {
    if !opted_in() {
        return;
    }
    let drive = Drive::new("busy");
    let files = sample_files("busy");

    let mut mounted = Mounted::start(&drive, "first");
    write_files(&drive.mountpoint, &files);
    let (busy_path, busy_content) = &files[1];
    let mut open_file = File::open(drive.mountpoint.join(busy_path)).expect("open through mount");

    mounted.signal(libc::SIGINT);
    mounted.wait_for_log("cannot unmount");
    assert!(mounted.running(), "a busy mount must keep serving");
    assert!(
        is_mounted(&drive.mountpoint),
        "a busy mount must stay mounted"
    );
    let mut served = Vec::new();
    open_file
        .read_to_end(&mut served)
        .expect("read through the still-mounted drive");
    assert!(served == *busy_content, "busy mount served different bytes");

    drop(open_file);
    mounted.stop(libc::SIGINT);

    let remounted = Mounted::start(&drive, "second");
    assert_files(&drive.mountpoint, &files);
    remounted.stop(libc::SIGTERM);
}

/// systemd and launchd send one stop signal and then wait, so a service must
/// finish a refused unmount by itself once the drive is no longer busy.
#[test]
#[ignore = "mounts a real FUSE filesystem; set ZDRIVE_RUN_LIVE_FUSE_TESTS=1"]
fn a_service_unmounts_a_busy_drive_once_files_close_without_another_signal() {
    if !opted_in() {
        return;
    }
    let drive = Drive::new("service-busy");
    let files = sample_files("service-busy");

    let mut mounted = Mounted::start_with(&drive, "first", &["--service", "--telemetry", "off"]);
    write_files(&drive.mountpoint, &files);
    let (busy_path, busy_content) = &files[1];
    let mut open_file = File::open(drive.mountpoint.join(busy_path)).expect("open through mount");

    mounted.signal(libc::SIGTERM);
    mounted.wait_for_log("retries the unmount every second");
    assert!(mounted.running(), "a busy service mount must keep serving");
    assert!(
        is_mounted(&drive.mountpoint),
        "a busy service mount must stay mounted"
    );
    let mut served = Vec::new();
    open_file
        .read_to_end(&mut served)
        .expect("read through the still-mounted drive");
    assert!(served == *busy_content, "busy mount served different bytes");

    drop(open_file);
    let log = mounted.log.clone();
    mounted.expect_clean_exit("the file closed, with no second signal");
    let log = fs::read_to_string(log).expect("read process log");
    assert!(log.contains("unmounted after"), "log:\n{log}");
    assert!(!log.contains("press Ctrl+C"), "log:\n{log}");

    let remounted = Mounted::start(&drive, "second");
    assert_files(&drive.mountpoint, &files);
    remounted.stop(libc::SIGTERM);
}
