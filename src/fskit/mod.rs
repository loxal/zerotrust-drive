// SPDX-FileCopyrightText: Copyright 2026 Alexander Orlov <info@lifub.com>

//! macFUSE's FSKit backend: mounting without the kernel extension, which
//! Apple silicon Macs load only after reduced security is enabled in
//! recoveryOS.
//!
//! macFUSE delivers FSKit requests through libfuse's channel API instead of
//! `/dev/macfuse`, so fuser cannot mount through it directly. The bridge
//! relays them through a datagram socket that fuser serves like the device
//! (see [`bridge`]). Three things differ from the kernel path, each found by
//! a failing control:
//!
//! - The session must serve before the volume exists: FSKit asks for STATFS
//!   and GETATTR first. Readiness therefore comes from the mount table.
//! - FSKit's own requests carry uid 0, so the session admits root and the
//!   owner instead of the owner alone.
//! - FSKit fails the mount when a reply arrives as one part instead of
//!   libfuse's header and body.

#[cfg(any(target_os = "macos", test))]
pub(crate) mod bridge;
#[cfg(target_os = "macos")]
mod libfuse;

use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};

/// macFUSE's FSKit module, as pluginkit and FSKit's settings name it. The
/// `-local` sibling serves local block devices, not FUSE servers.
pub(crate) const MODULE_ID: &str = "io.macfuse.app.fsmodule.macfuse";
/// The macFUSE bundle and its version.
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
pub(crate) const MACFUSE_BUNDLE: &str = "/Library/Filesystems/macfuse.fs";
/// The first macFUSE release whose FSKit volume survives a killed server
/// (macfuse/macfuse#1201): older ones hang every access until the volume's
/// module process ends.
pub(crate) const RECOVERING_VERSION: (u32, u32, u32) = (5, 5, 0);
/// FSKit sends READ and WRITE of at most 1 MiB; a smaller bridge limit
/// would fail them.
const MIN_TRANSFER: usize = 1 << 20;
/// How often the mount table is read while the volume attaches.
#[cfg(target_os = "macos")]
const ATTACH_POLL: std::time::Duration = std::time::Duration::from_millis(50);
/// When a volume that has not appeared yet is reported as slow.
#[cfg(target_os = "macos")]
const ATTACH_WARNING: std::time::Duration = std::time::Duration::from_secs(30);

/// Set once this process serves through FSKit, for telemetry.
static ACTIVE: AtomicBool = AtomicBool::new(false);

/// `--fuse-backend`: how macOS mounts the drive.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, clap::ValueEnum)]
pub(crate) enum BackendArg {
    /// The kernel extension when it is loaded or FSKit is unavailable, else
    /// FSKit
    #[default]
    Auto,
    /// macFUSE's kernel extension
    Kext,
    /// macFUSE's FSKit module (macOS 15.4 or newer, no kernel extension)
    Fskit,
}

impl BackendArg {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Auto => "auto",
            Self::Kext => "kext",
            Self::Fskit => "fskit",
        }
    }

    pub(crate) fn parse(text: &str) -> Option<Self> {
        [Self::Auto, Self::Kext, Self::Fskit]
            .into_iter()
            .find(|backend| backend.as_str() == text)
    }
}

/// The backend a mount uses.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Backend {
    /// The kernel's FUSE device: Linux, or macFUSE's kernel extension.
    Kernel,
    /// macFUSE's FSKit module through the bridge.
    Fskit,
}

impl Backend {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Kernel => "kext",
            Self::Fskit => "fskit",
        }
    }
}

/// The backend `arg` selects. `auto` keeps the kernel extension wherever it
/// can work: when it is loaded, and when FSKit is not registered, because
/// the extension loads on the first mount once macOS allows it.
pub(crate) fn resolve(arg: BackendArg, kext_loaded: bool, fskit_registered: bool) -> Backend {
    match arg {
        BackendArg::Kext => Backend::Kernel,
        BackendArg::Fskit => Backend::Fskit,
        BackendArg::Auto if kext_loaded || !fskit_registered => Backend::Kernel,
        BackendArg::Auto => Backend::Fskit,
    }
}

/// Whether macFUSE's kernel extension is loaded: it creates the
/// `/dev/macfuse*` devices.
pub(crate) fn kext_loaded(dev: &Path) -> bool {
    std::fs::read_dir(dev).is_ok_and(|entries| {
        entries
            .flatten()
            .any(|entry| entry.file_name().to_string_lossy().starts_with("macfuse"))
    })
}

/// Whether `pluginkit -m -p com.apple.fskit.fsmodule` lists macFUSE's module
/// without the user having set it to be ignored. Lines look like
/// `+    io.macfuse.app.fsmodule.macfuse((null))`.
pub(crate) fn registered_in(pluginkit: &str) -> bool {
    pluginkit.lines().any(|line| {
        let line = line.trim_start();
        if line.starts_with('-') {
            return false;
        }
        let name = line.trim_start_matches(['+', '=', '!', ' ', '\t']);
        name.split('(').next() == Some(MODULE_ID)
    })
}

/// The `CFBundleShortVersionString` of macFUSE's `Info.plist`.
pub(crate) fn bundle_version(plist: &str) -> Option<(u32, u32, u32)> {
    let after_key = plist
        .split("<key>CFBundleShortVersionString</key>")
        .nth(1)?;
    let value = after_key
        .trim_start()
        .strip_prefix("<string>")?
        .split("</string>")
        .next()?;
    parse_version(value)
}

/// `5.4.0`, `5.5` or `5.5.0-beta1` as a comparable triple.
pub(crate) fn parse_version(text: &str) -> Option<(u32, u32, u32)> {
    let mut parts = text
        .trim()
        .split(['.', '-', ' '])
        .map(|part| part.parse::<u32>());
    let major = parts.next()?.ok()?;
    let minor = parts.next().unwrap_or(Ok(0)).ok()?;
    let patch = parts.next().map_or(Some(0), Result::ok).unwrap_or(0);
    Some((major, minor, patch))
}

/// Refuses a backend other than `auto` off macOS, which has only one.
pub(crate) fn check_platform(arg: BackendArg, macos: bool) -> Result<(), String> {
    if macos || arg == BackendArg::Auto {
        Ok(())
    } else {
        Err(format!(
            "--fuse-backend {} applies only to macOS",
            arg.as_str()
        ))
    }
}

/// Pick the backend for a mount and record it for telemetry. Linux has only
/// the kernel path.
pub(crate) fn select(arg: BackendArg) -> Result<Backend, String> {
    if !cfg!(target_os = "macos") {
        check_platform(arg, false)?;
        return Ok(Backend::Kernel);
    }
    let loaded = kext_loaded(Path::new("/dev"));
    // Ask pluginkit only when its answer matters.
    let registered = arg == BackendArg::Auto && !loaded && fskit_registered();
    let backend = resolve(arg, loaded, registered);
    ACTIVE.store(backend == Backend::Fskit, Ordering::SeqCst);
    Ok(backend)
}

/// Whether this process serves through FSKit.
pub(crate) fn active() -> bool {
    ACTIVE.load(Ordering::SeqCst)
}

/// pluginkit's list of FSKit modules. A pluginkit that fails, hangs or is
/// missing counts as no FSKit, which keeps the kernel extension path.
fn fskit_registered() -> bool {
    use std::io::Read;
    use std::process::{Command, Stdio};
    use std::time::{Duration, Instant};
    let Ok(mut child) = Command::new("/usr/bin/pluginkit")
        .args(["-m", "-p", "com.apple.fskit.fsmodule"])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
    else {
        return false;
    };
    let Some(mut stdout) = child.stdout.take() else {
        return false;
    };
    let reader = std::thread::spawn(move || {
        let mut text = String::new();
        stdout.read_to_string(&mut text).map(|_| text)
    });
    let deadline = Instant::now() + Duration::from_secs(5);
    let succeeded = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status.success(),
            Ok(None) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(10)),
            _ => {
                eprintln!(
                    "zerotrust-drive: warning: pluginkit did not answer; using macFUSE's kernel extension"
                );
                let _ = child.kill();
                let _ = child.wait();
                break false;
            }
        }
    };
    let text = reader.join().ok().and_then(Result::ok).unwrap_or_default();
    succeeded && registered_in(&text)
}

/// The bridge limit as the file system's transfer bound, refusing one FSKit
/// would exceed.
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
fn transfer_limit(limit: usize) -> Result<u32, String> {
    if limit < MIN_TRANSFER {
        return Err(format!(
            "the FSKit bridge carries at most {limit} bytes per message, but FSKit sends up to {MIN_TRANSFER}; raise kern.ipc.maxsockbuf"
        ));
    }
    Ok(u32::try_from(limit).unwrap_or(u32::MAX))
}

/// Mount `mountpoint` through FSKit and serve until it is unmounted, by a
/// signal or externally. `destroy` has flushed pending state when this
/// returns.
#[cfg(target_os = "macos")]
pub(crate) fn serve(
    mut filesystem: crate::fs::ZeroTrustFs,
    mountpoint: &Path,
    volume_name: &str,
) -> std::io::Result<()> {
    use std::sync::Arc;
    use std::time::Instant;

    let started = Instant::now();
    // The mount table shows the canonical path; a mount point reached
    // through a symlink (such as /tmp) would otherwise never match.
    let table_path = crate::service::recover::mount_key(mountpoint)
        .map_err(std::io::Error::other)?
        .ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::NotFound,
                format!("the parent of {} does not exist", mountpoint.display()),
            )
        })?;
    let options = format!(
        "backend=fskit,fsname={},volname={volume_name}",
        crate::service::recover::FS_NAME
    );
    let channel = libfuse::FskitChannel::mount(mountpoint, &options)?;
    let (mut bridge, fd) = bridge::start(channel)?;
    let limit = transfer_limit(bridge.limit()).map_err(std::io::Error::other)?;
    filesystem.limit_transfers(limit);

    let abandoned = Arc::new(AtomicBool::new(false));
    let abandon = bridge.abandoner();
    crate::shutdown::attaching(
        mountpoint,
        Box::new({
            let abandoned = Arc::clone(&abandoned);
            move || {
                abandoned.store(true, Ordering::SeqCst);
                abandon();
            }
        }),
    );
    let mut config = fuser::Config::default();
    config.acl = fuser::SessionACL::RootAndOwner;
    let session =
        match fuser::Session::from_fd(filesystem, fd, fuser::SessionACL::RootAndOwner, config) {
            Ok(session) => session,
            Err(error) => {
                bridge.finish();
                crate::shutdown::session_ended();
                if abandoned.load(Ordering::SeqCst) {
                    return Ok(());
                }
                return Err(std::io::Error::other(format!(
                    "the FSKit handshake failed: {error}"
                )));
            }
        };

    let ended = Arc::new(AtomicBool::new(false));
    let appeared = Arc::new(AtomicBool::new(false));
    let watcher = {
        let ended = Arc::clone(&ended);
        let appeared = Arc::clone(&appeared);
        let mountpoint = mountpoint.to_path_buf();
        std::thread::Builder::new()
            .name("zdrive-fskit-attach".to_string())
            .spawn(move || watch_attach(&mountpoint, &table_path, started, &ended, &appeared))?
    };
    let result = session.run();
    ended.store(true, Ordering::SeqCst);
    if watcher.join().is_err() {
        eprintln!("zerotrust-drive: warning: the FSKit attach watcher panicked");
    }
    bridge.finish();
    crate::shutdown::session_ended();
    crate::report_to_service_manager(crate::service::notify::stopping());
    result?;
    if !appeared.load(Ordering::SeqCst) && !abandoned.load(Ordering::SeqCst) {
        return Err(std::io::Error::other(format!(
            "the FSKit volume at {} never appeared; enable macFUSE under System Settings > General > Login Items & Extensions > File System Extensions, or mount with --fuse-backend kext if macOS allows macFUSE's kernel extension",
            mountpoint.display()
        )));
    }
    Ok(())
}

/// Report the volume once it is in the mount table, and route signals to an
/// unmount from then on.
#[cfg(target_os = "macos")]
fn watch_attach(
    mountpoint: &Path,
    table_path: &Path,
    started: std::time::Instant,
    ended: &AtomicBool,
    appeared: &AtomicBool,
) {
    let mut warned = false;
    while !ended.load(Ordering::SeqCst) {
        if attached(table_path) {
            appeared.store(true, Ordering::SeqCst);
            if !crate::shutdown::attached(mountpoint) {
                // A signal abandoned the mount first.
                return;
            }
            let ready_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
            crate::telemetry::event(
                crate::telemetry::Level::Standard,
                "mount.ready",
                &[
                    ("backend", crate::telemetry::Field::Tag("fskit")),
                    ("ready_ms", crate::telemetry::Field::U64(ready_ms)),
                ],
            );
            crate::report_to_service_manager(crate::service::notify::ready());
            crate::report_to_service_manager(crate::service::notify::status(&format!(
                "mounted at {}",
                mountpoint.display()
            )));
            return;
        }
        if !warned && started.elapsed() >= ATTACH_WARNING {
            warned = true;
            eprintln!(
                "zerotrust-drive: warning: the FSKit volume at {} has not appeared after {} s; check System Settings > General > Login Items & Extensions > File System Extensions > macFUSE",
                mountpoint.display(),
                ATTACH_WARNING.as_secs()
            );
        }
        std::thread::sleep(ATTACH_POLL);
    }
}

/// Whether a macFUSE volume is mounted at `table_path`, the mount table's
/// form of the mount point. The table is read without asking each file
/// system, so a hung volume cannot block it.
#[cfg(target_os = "macos")]
fn attached(table_path: &Path) -> bool {
    crate::service::recover::mount_table().is_ok_and(|entries| {
        crate::service::recover::find_entry(&entries, table_path)
            .is_some_and(|entry| entry.fstype.starts_with("macfuse"))
    })
}

#[cfg(not(target_os = "macos"))]
pub(crate) fn serve(
    _filesystem: crate::fs::ZeroTrustFs,
    _mountpoint: &Path,
    _volume_name: &str,
) -> std::io::Result<()> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "the FSKit backend exists only on macOS",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::remote::TestDir;

    #[test]
    fn auto_keeps_the_kernel_extension_wherever_it_can_work() {
        use Backend::{Fskit, Kernel};
        use BackendArg::{Auto, Fskit as WantFskit, Kext};
        for (arg, loaded, registered, expected) in [
            (Auto, true, true, Kernel),
            (Auto, true, false, Kernel),
            (Auto, false, false, Kernel),
            (Auto, false, true, Fskit),
            (Kext, false, true, Kernel),
            (Kext, true, false, Kernel),
            (WantFskit, true, true, Fskit),
            (WantFskit, false, false, Fskit),
        ] {
            assert_eq!(
                resolve(arg, loaded, registered),
                expected,
                "{arg:?} loaded={loaded} registered={registered}"
            );
        }
    }

    #[test]
    fn backend_names_round_trip() {
        for arg in [BackendArg::Auto, BackendArg::Kext, BackendArg::Fskit] {
            assert_eq!(BackendArg::parse(arg.as_str()), Some(arg));
        }
        assert_eq!(BackendArg::parse("kernel"), None);
        assert_eq!(BackendArg::parse("FSKIT"), None);
        assert_eq!(Backend::Kernel.as_str(), "kext");
        assert_eq!(Backend::Fskit.as_str(), "fskit");
    }

    #[test]
    fn pluginkit_listing_counts_only_the_fuse_module_not_ignored() {
        let listed = "     com.apple.fskit.ftp((null))\n\
                      +    io.macfuse.app.fsmodule.macfuse-local((null))\n\
                      +    io.macfuse.app.fsmodule.macfuse((null))\n";
        assert!(registered_in(listed));
        assert!(registered_in(
            "     io.macfuse.app.fsmodule.macfuse(5.5.0)\n"
        ));
        assert!(!registered_in(
            "+    io.macfuse.app.fsmodule.macfuse-local((null))\n     com.apple.fskit.exfat((null))\n"
        ));
        assert!(!registered_in(
            "-    io.macfuse.app.fsmodule.macfuse((null))\n"
        ));
        assert!(!registered_in(""));
    }

    #[test]
    fn versions_compare_as_triples() {
        let info =
            "<dict>\n\t<key>CFBundleShortVersionString</key>\n\t<string>5.4.0</string>\n</dict>";
        assert_eq!(bundle_version(info), Some((5, 4, 0)));
        assert!(bundle_version(info).unwrap() < RECOVERING_VERSION);
        assert_eq!(parse_version("5.5"), Some((5, 5, 0)));
        assert_eq!(parse_version("5.5.0-beta1"), Some((5, 5, 0)));
        assert_eq!(parse_version("5.10.2"), Some((5, 10, 2)));
        assert!(parse_version("5.10.2").unwrap() > RECOVERING_VERSION);
        assert_eq!(parse_version("five"), None);
        assert_eq!(bundle_version("<dict></dict>"), None);
    }

    #[test]
    fn kext_is_loaded_only_with_a_macfuse_device() {
        let dir = TestDir::new("fskit-kext-loaded");
        assert!(!kext_loaded(dir.path()));
        std::fs::write(dir.path().join("fuse"), b"").unwrap();
        assert!(!kext_loaded(dir.path()));
        std::fs::write(dir.path().join("macfuse0"), b"").unwrap();
        assert!(kext_loaded(dir.path()));
        assert!(!kext_loaded(&dir.path().join("missing")));
    }

    #[test]
    fn a_bridge_below_fskit_transfers_is_refused() {
        assert_eq!(transfer_limit(MIN_TRANSFER), Ok(1 << 20));
        assert_eq!(transfer_limit(4 << 20), Ok(4 << 20));
        assert!(
            transfer_limit(MIN_TRANSFER / 2)
                .unwrap_err()
                .contains("kern.ipc.maxsockbuf")
        );
    }

    #[cfg(not(target_os = "macos"))]
    #[test]
    fn other_systems_accept_only_auto() {
        assert_eq!(select(BackendArg::Auto), Ok(Backend::Kernel));
        for arg in [BackendArg::Kext, BackendArg::Fskit] {
            assert!(select(arg).unwrap_err().contains("only to macOS"));
        }
        assert!(!active());
    }
}
