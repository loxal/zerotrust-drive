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
//!   error is reported and the drive keeps serving. Interactively the next
//!   signal retries; under a service manager, which sends a single stop
//!   signal (see [`unattended`]), the drive retries every second by itself.
//! - **Unmounting**: further signals are reported and ignored until the final
//!   flush completes.
//! - **Finishing** (the final upload of automatic remote sync, after the local
//!   flush): a signal abandons the upload. Local data is already durable and
//!   the next push or mount resumes the upload.
//! - **Stoppable** (a plain-mode sync loop, no mount): the first signal only
//!   sets the flag [`stop_requested`] reports, so the loop ends after its
//!   current and one final cycle; a second signal terminates at once.
//!
//! A signal the parent process set to be ignored (for example SIGHUP under
//! `nohup`) stays ignored.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

const HANDLED_SIGNALS: [libc::c_int; 3] = [libc::SIGINT, libc::SIGTERM, libc::SIGHUP];

enum Phase {
    Default,
    Mounted(PathBuf),
    Unmounting,
    Finishing(Box<dyn Fn() + Send>),
    Stoppable,
}

static PHASE: Mutex<Phase> = Mutex::new(Phase::Default);
static STOP: AtomicBool = AtomicBool::new(false);
static UNATTENDED: AtomicBool = AtomicBool::new(false);
static BUSY_RETRY: Mutex<Option<BusyRetry>> = Mutex::new(None);
const BUSY_RETRY_INTERVAL: Duration = Duration::from_secs(1);

/// Progress of the unattended busy-unmount retry. The main thread reports it
/// in [`session_ended`]: the successful attempt ends the FUSE session, so the
/// main thread can flush and exit before the retry thread runs again.
struct BusyRetry {
    mountpoint: PathBuf,
    started: Instant,
    attempts: u64,
}

fn phase() -> MutexGuard<'static, Phase> {
    PHASE.lock().unwrap_or_else(PoisonError::into_inner)
}

fn busy_retry() -> MutexGuard<'static, Option<BusyRetry>> {
    BUSY_RETRY.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Mark this process as run by a service manager. systemd and launchd send
/// one stop signal and then wait for the exit, so a refused unmount is
/// retried until it succeeds instead of waiting for another signal.
pub(crate) fn unattended() {
    UNATTENDED.store(true, Ordering::SeqCst);
}

/// Whether [`unattended`] was called: no terminal, no second signal.
pub(crate) fn is_unattended() -> bool {
    UNATTENDED.load(Ordering::SeqCst)
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

/// Restore the default signal behaviour once the FUSE session has ended, and
/// report a busy unmount that the unattended retry resolved.
pub(crate) fn session_ended() {
    *phase() = Phase::Default;
    let Some(retry) = busy_retry().take() else {
        return;
    };
    let waited = retry.started.elapsed();
    eprintln!(
        "zerotrust-drive: {} unmounted after {} attempts in {} s",
        retry.mountpoint.display(),
        retry.attempts,
        waited.as_secs()
    );
    crate::telemetry::event(
        crate::telemetry::Level::Standard,
        "unmount.retried",
        &[
            ("attempts", crate::telemetry::Field::U64(retry.attempts)),
            (
                "waited_ms",
                crate::telemetry::Field::U64(u64::try_from(waited.as_millis()).unwrap_or(u64::MAX)),
            ),
        ],
    );
}

/// Route later signals to `abandon` while the final upload runs.
pub(crate) fn finishing(abandon: Box<dyn Fn() + Send>) {
    *phase() = Phase::Finishing(abandon);
}

/// Let the first later signal request a stop instead of terminating, for a
/// loop that polls [`stop_requested`]. Never used while a drive is mounted.
pub(crate) fn stoppable() {
    *phase() = Phase::Stoppable;
}

/// Whether a signal arrived since [`stoppable`].
pub(crate) fn stop_requested() -> bool {
    STOP.load(Ordering::SeqCst)
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
            crate::telemetry::stop("signal", 128 + signal);
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
        Phase::Stoppable => {
            if STOP.swap(true, Ordering::SeqCst) {
                drop(current);
                crate::prompt::restore_terminal_after_signal();
                crate::telemetry::stop("signal", 128 + signal);
                terminate_with(signal);
            }
            let _ = crate::service::notify::stopping();
            crate::telemetry::event(
                crate::telemetry::Level::Standard,
                "signal",
                &[("signal", crate::telemetry::Field::Tag(signal_name(signal)))],
            );
            eprintln!(
                "zerotrust-drive: {} received; finishing the current sync cycle (send it again to stop immediately)",
                signal_name(signal)
            );
        }
        Phase::Mounted(mountpoint) => {
            let mountpoint = mountpoint.clone();
            *current = Phase::Unmounting;
            drop(current);
            let _ = crate::service::notify::stopping();
            crate::telemetry::event(
                crate::telemetry::Level::Standard,
                "signal",
                &[("signal", crate::telemetry::Field::Tag(signal_name(signal)))],
            );
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
                    eprintln!(
                        "zerotrust-drive: cannot unmount {}: {error}",
                        mountpoint.display()
                    );
                    crate::telemetry::event(crate::telemetry::Level::Standard, "unmount.busy", &[]);
                    if is_unattended() && retry_busy_unmount(mountpoint.clone()) {
                        return;
                    }
                    let mut current = phase();
                    if matches!(*current, Phase::Unmounting) {
                        *current = Phase::Mounted(mountpoint.clone());
                    }
                    drop(current);
                    eprintln!(
                        "zerotrust-drive: the drive stays mounted and keeps serving; close files and programs using it, then press Ctrl+C (or send the signal) again"
                    );
                }
            }
        }
    }
}

/// Retry a refused unmount every second while the phase stays
/// `Unmounting`, for a service manager that sends no second signal. The
/// drive keeps serving meanwhile; the manager's stop timeout still bounds the
/// wait, and [`session_ended`] reports the outcome. Returns false if the retry
/// thread cannot start.
fn retry_busy_unmount(mountpoint: PathBuf) -> bool {
    *busy_retry() = Some(BusyRetry {
        mountpoint: mountpoint.clone(),
        started: Instant::now(),
        attempts: 1,
    });
    let spawned = std::thread::Builder::new()
        .name("zdrive-unmount-retry".to_string())
        .spawn(move || {
            loop {
                std::thread::sleep(BUSY_RETRY_INTERVAL);
                if !matches!(*phase(), Phase::Unmounting) {
                    return;
                }
                if let Some(retry) = busy_retry().as_mut() {
                    retry.attempts += 1;
                }
                match unmount(&mountpoint) {
                    // The session ends now; session_ended reports it.
                    Ok(()) => return,
                    Err(error) if error.raw_os_error() == Some(libc::EINVAL) => return,
                    Err(_) => {}
                }
            }
        });
    if spawned.is_err() {
        *busy_retry() = None;
        return false;
    }
    eprintln!(
        "zerotrust-drive: the drive keeps serving and retries the unmount every second until the files and programs using it close"
    );
    true
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
