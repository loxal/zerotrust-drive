// SPDX-FileCopyrightText: Copyright 2026 Alexander Orlov <info@lifub.com>

//! Signal-driven graceful shutdown.
//!
//! SIGINT, SIGTERM and SIGHUP are blocked in every thread from the start of
//! `main`, and one dedicated thread receives them with `sigwait(3)`, so no
//! async-signal-safety constraints apply to the handling code. What a signal
//! does depends on the current phase:
//!
//! - **Default** (prompting, migrating, collecting garbage, or mounting): the
//!   terminal is restored and the signal's default action terminates the
//!   process, exactly as without this module.
//! - **Mounted**: the drive is unmounted instead. The FUSE session then ends
//!   on its own, `destroy` flushes every acknowledged write, and the process
//!   exits normally. A busy mount is not detached lazily or forcibly: the
//!   error is reported, the drive keeps serving, and the next signal retries.
//! - **Unmounting**: further signals are reported and ignored until the final
//!   flush completes.
//! - **Finishing** (the final upload of automatic remote sync, after the local
//!   flush): a signal abandons the upload. Local data is already durable and
//!   the next push or mount resumes the upload.
//!
//! A signal the parent process set to be ignored (for example SIGHUP under
//! `nohup`) stays ignored.

use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard, PoisonError};

const HANDLED_SIGNALS: [libc::c_int; 3] = [libc::SIGINT, libc::SIGTERM, libc::SIGHUP];

enum Phase {
    Default,
    Mounted(PathBuf),
    Unmounting,
    Finishing(Box<dyn Fn() + Send>),
}

static PHASE: Mutex<Phase> = Mutex::new(Phase::Default);

fn phase() -> MutexGuard<'static, Phase> {
    PHASE.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Block the handled signals and start the receiving thread. Call this before
/// any other thread exists, so every later thread inherits the blocked mask.
pub(crate) fn install() -> Result<(), String> {
    // SAFETY: the sigset_t values are initialised by sigemptyset before use
    // and the pointers passed to libc refer to live stack values.
    let set = unsafe {
        let mut set: libc::sigset_t = std::mem::zeroed();
        libc::sigemptyset(&mut set);
        for signal in HANDLED_SIGNALS {
            let mut current: libc::sigaction = std::mem::zeroed();
            if libc::sigaction(signal, std::ptr::null(), &mut current) != 0 {
                return Err(format!(
                    "cannot inspect the disposition of {}: {}",
                    signal_name(signal),
                    std::io::Error::last_os_error()
                ));
            }
            if current.sa_sigaction != libc::SIG_IGN {
                libc::sigaddset(&mut set, signal);
            }
        }
        let rc = libc::pthread_sigmask(libc::SIG_BLOCK, &set, std::ptr::null_mut());
        if rc != 0 {
            return Err(format!(
                "cannot block shutdown signals: {}",
                std::io::Error::from_raw_os_error(rc)
            ));
        }
        set
    };
    std::thread::Builder::new()
        .name("zdrive-signals".to_string())
        .spawn(move || receive(set))
        .map(drop)
        .map_err(|error| format!("cannot start the signal thread: {error}"))
}

/// Route later signals to a graceful unmount of `mountpoint`.
pub(crate) fn mounted(mountpoint: &Path) {
    *phase() = Phase::Mounted(mountpoint.to_path_buf());
}

/// Restore the default signal behaviour once the FUSE session has ended.
pub(crate) fn session_ended() {
    *phase() = Phase::Default;
}

/// Route later signals to `abandon` while the final upload runs.
pub(crate) fn finishing(abandon: Box<dyn Fn() + Send>) {
    *phase() = Phase::Finishing(abandon);
}

fn receive(set: libc::sigset_t) {
    loop {
        let mut signal: libc::c_int = 0;
        // SAFETY: set was initialised by install and signal is a live
        // out-parameter.
        let rc = unsafe { libc::sigwait(&set, &mut signal) };
        if rc != 0 {
            // Only an invalid set makes sigwait fail. Without this thread the
            // blocked signals could never stop the process again.
            eprintln!(
                "zerotrust-drive: error: waiting for shutdown signals failed: {}",
                std::io::Error::from_raw_os_error(rc)
            );
            std::process::abort();
        }
        handle(signal);
    }
}

fn handle(signal: libc::c_int) {
    let mut current = phase();
    match &*current {
        Phase::Default => {
            drop(current);
            crate::prompt::restore_terminal_after_signal();
            terminate_with(signal);
        }
        Phase::Unmounting => eprintln!(
            "zerotrust-drive: {} received; already unmounting - waiting for the encrypted state to flush",
            signal_name(signal)
        ),
        Phase::Finishing(abandon) => {
            eprintln!(
                "zerotrust-drive: {} received; leaving the upload unfinished - local data is safe",
                signal_name(signal)
            );
            abandon();
        }
        Phase::Mounted(mountpoint) => {
            let mountpoint = mountpoint.clone();
            *current = Phase::Unmounting;
            drop(current);
            eprintln!(
                "zerotrust-drive: {} received; unmounting {}",
                signal_name(signal),
                mountpoint.display()
            );
            match unmount(&mountpoint) {
                Ok(()) => {}
                Err(error) if error.raw_os_error() == Some(libc::EINVAL) => eprintln!(
                    "zerotrust-drive: {} is no longer mounted; waiting for the encrypted state to flush",
                    mountpoint.display()
                ),
                Err(error) => {
                    let mut current = phase();
                    if matches!(*current, Phase::Unmounting) {
                        *current = Phase::Mounted(mountpoint.clone());
                    }
                    drop(current);
                    eprintln!(
                        "zerotrust-drive: cannot unmount {}: {error}",
                        mountpoint.display()
                    );
                    eprintln!(
                        "zerotrust-drive: the drive stays mounted and keeps serving; close files and programs using it, then press Ctrl+C (or send the signal) again"
                    );
                }
            }
        }
    }
}

/// Terminate through the signal's default action so the exit status still
/// reports the signal to the parent process.
fn terminate_with(signal: libc::c_int) -> ! {
    // SAFETY: plain libc calls on a valid signal number and an initialised
    // sigset_t.
    unsafe {
        libc::signal(signal, libc::SIG_DFL);
        let mut set: libc::sigset_t = std::mem::zeroed();
        libc::sigemptyset(&mut set);
        libc::sigaddset(&mut set, signal);
        libc::pthread_sigmask(libc::SIG_UNBLOCK, &set, std::ptr::null_mut());
        libc::raise(signal);
    }
    std::process::exit(128 + signal);
}

fn signal_name(signal: libc::c_int) -> &'static str {
    match signal {
        libc::SIGINT => "SIGINT",
        libc::SIGTERM => "SIGTERM",
        libc::SIGHUP => "SIGHUP",
        _ => "signal",
    }
}

fn mountpoint_cstring(mountpoint: &Path) -> std::io::Result<std::ffi::CString> {
    use std::os::unix::ffi::OsStrExt;
    std::ffi::CString::new(mountpoint.as_os_str().as_bytes())
        .map_err(|_| std::io::Error::from_raw_os_error(libc::EINVAL))
}

#[cfg(not(target_os = "linux"))]
fn unmount(mountpoint: &Path) -> std::io::Result<()> {
    let path = mountpoint_cstring(mountpoint)?;
    // SAFETY: path is a valid NUL-terminated string for the call's duration.
    if unsafe { libc::unmount(path.as_ptr(), 0) } == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

#[cfg(target_os = "linux")]
fn unmount(mountpoint: &Path) -> std::io::Result<()> {
    let path = mountpoint_cstring(mountpoint)?;
    // SAFETY: path is a valid NUL-terminated string for the call's duration.
    if unsafe { libc::umount2(path.as_ptr(), 0) } == 0 {
        return Ok(());
    }
    let error = std::io::Error::last_os_error();
    if error.raw_os_error() != Some(libc::EPERM) {
        return Err(error);
    }
    // Unprivileged FUSE mounts are removed through the setuid helper. It runs
    // without -z, so a busy mount fails instead of being detached lazily.
    let helpers = match std::env::var_os("FUSERMOUNT_PATH") {
        Some(path) => vec![path],
        None => vec!["fusermount3".into(), "fusermount".into()],
    };
    let mut last_error = error;
    for helper in helpers {
        match std::process::Command::new(&helper)
            .args(["-u", "--"])
            .arg(mountpoint)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::piped())
            .output()
        {
            Ok(output) if output.status.success() => return Ok(()),
            Ok(output) => {
                let stderr = String::from_utf8_lossy(&output.stderr);
                return Err(std::io::Error::other(format!(
                    "{} -u failed ({}): {}",
                    helper.to_string_lossy(),
                    output.status,
                    stderr.trim()
                )));
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => last_error = error,
            Err(error) => return Err(error),
        }
    }
    Err(last_error)
}
