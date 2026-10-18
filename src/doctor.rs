// SPDX-FileCopyrightText: Copyright 2026 Alexander Orlov <info@lifub.com>

//! `zdrive doctor`: a read-only health report of this installation, for
//! users and for later agent sessions that debug it. It never prints a
//! secret: OAuth clients and refresh tokens are reported only as present or
//! missing, and no account address, file name or passphrase is shown.

use std::ffi::OsString;
use std::os::unix::fs::{FileTypeExt, PermissionsExt};
use std::path::{Path, PathBuf};

use serde::Serialize;

use crate::remote::config::{ClientKind, Paths, RemoteConfig, RemoteMode, RemoteName};
use crate::service::{self, Runner};

#[derive(clap::Args, Debug)]
pub(crate) struct DoctorArgs {
    /// Print the report as one JSON object
    #[arg(long)]
    pub(crate) json: bool,
}

#[derive(Debug, Serialize)]
pub(crate) struct Report {
    version: &'static str,
    os: &'static str,
    arch: &'static str,
    kernel: String,
    fuse: Fuse,
    bundled_client: Bundled,
    remotes: Vec<Remote>,
    services: Vec<Service>,
    /// Linux only.
    systemd: Option<Systemd>,
    telemetry: Option<Telemetry>,
    /// Anything that stops zdrive from working; the exit status is 1 then.
    problems: Vec<String>,
    /// Advice that does not make the report fail.
    notes: Vec<String>,
}

#[derive(Debug, Serialize, PartialEq)]
struct Fuse {
    flavour: &'static str,
    ready: bool,
    detail: String,
}

#[derive(Debug, Serialize)]
struct Bundled {
    desktop: bool,
    device: bool,
}

#[derive(Debug, Serialize, PartialEq)]
struct Remote {
    name: String,
    mode: Option<&'static str>,
    client: Option<&'static str>,
    scope: Option<String>,
    signed_in: bool,
    error: Option<String>,
}

#[derive(Debug, Serialize)]
struct Service {
    name: String,
    installed: bool,
    running: bool,
    summary: String,
}

#[derive(Debug, Serialize)]
struct Systemd {
    version: Option<u32>,
    /// `systemd-creds --user` round-trips (systemd 256 or newer).
    user_credentials: Option<bool>,
    /// The user manager survives logout and starts at boot.
    linger: Option<bool>,
    /// How long the system lets the user manager stop (`user@UID.service`),
    /// which bounds a stopping instance at shutdown; `None` when unknown or
    /// unlimited.
    user_stop_timeout_ms: Option<u64>,
}

#[derive(Debug, Serialize)]
struct Telemetry {
    level: &'static str,
    source: &'static str,
    stored_bytes: Option<u64>,
}

pub(crate) fn run(args: DoctorArgs) -> i32 {
    let report = gather(&service::SystemRunner);
    if args.json {
        match serde_json::to_string_pretty(&report) {
            Ok(text) => println!("{text}"),
            Err(error) => {
                eprintln!("zerotrust-drive: error: cannot encode the report: {error}");
                return 1;
            }
        }
    } else {
        print!("{}", report.to_text());
    }
    if report.problems.is_empty() { 0 } else { 1 }
}

fn gather(runner: &dyn Runner) -> Report {
    let (desktop, device) = crate::remote::oauth::bundled_available();
    let mut report = Report {
        version: env!("CARGO_PKG_VERSION"),
        os: std::env::consts::OS,
        arch: std::env::consts::ARCH,
        kernel: crate::telemetry::kernel_release(),
        fuse: host_fuse(runner),
        bundled_client: Bundled { desktop, device },
        remotes: Vec::new(),
        services: Vec::new(),
        systemd: None,
        telemetry: None,
        problems: Vec::new(),
        notes: Vec::new(),
    };
    // An installed but idle FUSE loads on the first mount; only a missing
    // one is a problem. Either way the fuse line already explains it.
    if !report.fuse.ready && report.fuse.flavour != "macfuse" {
        report.problems.push(report.fuse.detail.clone());
    }
    if !(desktop && device) {
        report.notes.push(
            "this build has no bundled Google client; sign in with your own: zdrive remote auth --remote NAME --client-file FILE"
                .to_string(),
        );
    }
    if cfg!(target_os = "linux") {
        let systemd = systemd(runner);
        report.notes.extend(user_stop_note(&systemd));
        report.systemd = Some(systemd);
    }
    match Paths::from_env() {
        Ok(paths) => {
            report.remotes = remotes(&paths);
            for remote in &report.remotes {
                if let Some(problem) = remote_problem(remote, desktop, device) {
                    report.problems.push(problem);
                }
            }
            report.services = service::list(&paths, runner)
                .into_iter()
                .map(|status| Service {
                    summary: status.summary(),
                    name: status.name,
                    installed: status.installed,
                    running: status.running,
                })
                .collect();
            let env = std::env::var(crate::telemetry::ENV_VAR).ok();
            match crate::telemetry::resolve_level(None, env.as_deref(), &paths.config) {
                Ok((level, source)) => {
                    report.telemetry = Some(Telemetry {
                        level: level.as_str(),
                        source: source.describe(),
                        stored_bytes: crate::telemetry::stored_bytes(&paths.state).ok(),
                    });
                }
                Err(error) => report.problems.push(format!("telemetry: {error}")),
            }
        }
        Err(error) => report.problems.push(error.to_string()),
    }
    report
}

/// Whether this host can mount a drive now, and why not.
pub(crate) fn fuse_readiness() -> (bool, String) {
    let fuse = host_fuse(&service::SystemRunner);
    (fuse.ready, fuse.detail)
}

#[cfg(target_os = "linux")]
fn host_fuse(_runner: &dyn Runner) -> Fuse {
    linux_fuse(
        Path::new("/dev/fuse"),
        std::env::var_os("PATH"),
        service::current_uid() == 0,
    )
}

#[cfg(target_os = "macos")]
fn host_fuse(runner: &dyn Runner) -> Fuse {
    let modules = runner
        .run(
            "pluginkit",
            &service::os_args(["-m", "-p", "com.apple.fskit.fsmodule"]),
            None,
        )
        .ok()
        .filter(service::Output::success)
        .map(|output| output.stdout_text());
    macos_fuse(
        Path::new("/Library/Filesystems/macfuse.fs"),
        Path::new("/dev"),
        modules.as_deref(),
    )
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn host_fuse(_runner: &dyn Runner) -> Fuse {
    Fuse {
        flavour: "none",
        ready: false,
        detail: "zdrive mounts only on Linux and macOS".to_string(),
    }
}

/// Linux mounts as an ordinary user through the setuid `fusermount3`.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn linux_fuse(device: &Path, path_var: Option<OsString>, root: bool) -> Fuse {
    let helper = path_var.and_then(|path| {
        std::env::split_paths(&path)
            .map(|dir| dir.join("fusermount3"))
            .find(|candidate| candidate.is_file())
    });
    let Some(helper) = helper else {
        return Fuse {
            flavour: "none",
            ready: false,
            detail: "fusermount3 is not installed: sudo apt install fuse3 (plain sync mode needs no FUSE)"
                .to_string(),
        };
    };
    let device_ok = std::fs::metadata(device).is_ok_and(|meta| meta.file_type().is_char_device());
    if !device_ok {
        return Fuse {
            flavour: "fusermount3",
            ready: false,
            detail: format!(
                "{} is missing: load the module with sudo modprobe fuse; a container needs --device /dev/fuse",
                device.display()
            ),
        };
    }
    let setuid =
        std::fs::metadata(&helper).is_ok_and(|meta| meta.permissions().mode() & 0o4000 != 0);
    if !setuid && !root {
        return Fuse {
            flavour: "fusermount3",
            ready: false,
            detail: format!(
                "{} is not setuid root, so only root can mount: reinstall fuse3",
                helper.display()
            ),
        };
    }
    Fuse {
        flavour: "fusermount3",
        ready: true,
        detail: format!("{} and {}", helper.display(), device.display()),
    }
}

/// macOS mounts through macFUSE. Its kernel extension loads on the first
/// mount once macOS allows it, so "not loaded" is advice, not a failure.
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
fn macos_fuse(bundle: &Path, dev: &Path, fskit_modules: Option<&str>) -> Fuse {
    if !bundle.is_dir() {
        return Fuse {
            flavour: "none",
            ready: false,
            detail: "macFUSE is not installed: get it from https://macfuse.github.io (plain sync mode needs no FUSE)"
                .to_string(),
        };
    }
    let loaded = std::fs::read_dir(dev).is_ok_and(|entries| {
        entries
            .flatten()
            .any(|entry| entry.file_name().to_string_lossy().starts_with("macfuse"))
    });
    let fskit = fskit_modules.is_some_and(|text| text.to_ascii_lowercase().contains("macfuse"));
    let detail = match (loaded, fskit) {
        (true, _) => "macFUSE kernel extension loaded".to_string(),
        (false, true) => "macFUSE FSKit module registered; its kernel extension is not loaded".to_string(),
        (false, false) => "macFUSE is installed but its kernel extension is not loaded: the first mount loads it, which macOS must allow under System Settings > Privacy & Security (on Apple silicon after enabling kernel extensions in recoveryOS)".to_string(),
    };
    Fuse {
        flavour: "macfuse",
        ready: loaded,
        detail,
    }
}

#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn systemd(runner: &dyn Runner) -> Systemd {
    let version = service::systemd::systemd_version(runner);
    let user_credentials = version.map(|version| {
        version >= 256
            && service::custody::probe_systemd_creds(runner, &service::custody::probe_dir()).is_ok()
    });
    Systemd {
        version,
        user_credentials,
        linger: service::systemd::linger_enabled(runner),
        user_stop_timeout_ms: service::systemd::user_stop_timeout_ms(
            runner,
            service::current_uid(),
        ),
    }
}

/// Advice when the system stops the user manager sooner than an instance.
fn user_stop_note(systemd: &Systemd) -> Option<String> {
    systemd
        .user_stop_timeout_ms
        .filter(|&ms| ms < service::definition::STOP_TIMEOUT_SECS * 1000)
        .map(|limit| service::systemd::user_stop_timeout_advice(limit).join("\n  "))
}

/// Every configured remote, without its account or token.
fn remotes(paths: &Paths) -> Vec<Remote> {
    let dir = paths.config.join("remotes");
    let Ok(entries) = std::fs::read_dir(&dir) else {
        return Vec::new();
    };
    let mut names: Vec<String> = entries
        .flatten()
        .filter_map(|entry| {
            let path = PathBuf::from(entry.file_name());
            (path.extension()? == "json")
                .then(|| path.file_stem()?.to_str().map(str::to_string))
                .flatten()
        })
        .collect();
    names.sort();
    names
        .into_iter()
        .map(|name| {
            let loaded = RemoteName::parse(&name).and_then(|parsed| {
                let config = RemoteConfig::load(paths, &parsed)?;
                Ok((parsed, config))
            });
            match loaded {
                Ok((parsed, config)) => Remote {
                    signed_in: match config.mode {
                        RemoteMode::Encrypted => config.token.is_some(),
                        RemoteMode::Plain => paths.remote_token(&parsed).is_file(),
                    },
                    name,
                    mode: Some(config.mode.as_str()),
                    client: Some(client_name(config.client)),
                    scope: Some(config.scope),
                    error: None,
                },
                Err(error) => Remote {
                    name,
                    mode: None,
                    client: None,
                    scope: None,
                    signed_in: false,
                    error: Some(error.to_string()),
                },
            }
        })
        .collect()
}

fn client_name(kind: ClientKind) -> &'static str {
    match kind {
        ClientKind::Byo => "byo",
        ClientKind::BundledDesktop => "bundled-desktop",
        ClientKind::BundledDevice => "bundled-device",
    }
}

fn remote_problem(remote: &Remote, desktop: bool, device: bool) -> Option<String> {
    if let Some(error) = &remote.error {
        return Some(format!("remote {}: {error}", remote.name));
    }
    let missing = match remote.client {
        Some("bundled-desktop") => !desktop,
        Some("bundled-device") => !device,
        _ => false,
    };
    if missing {
        return Some(format!(
            "remote {} was signed in with the bundled Google client, which this build lacks: install a release build",
            remote.name
        ));
    }
    if !remote.signed_in {
        return Some(format!(
            "remote {} is not signed in: zdrive remote auth --remote {}",
            remote.name, remote.name
        ));
    }
    None
}

impl Report {
    fn to_text(&self) -> String {
        let yes = |value: bool| if value { "yes" } else { "no" };
        let mut out = format!(
            "zerotrust-drive {} on {} {} (kernel {})\n",
            self.version, self.os, self.arch, self.kernel
        );
        out.push_str(&format!(
            "fuse: {}, {}: {}\n",
            self.fuse.flavour,
            if self.fuse.ready {
                "ready"
            } else {
                "not ready"
            },
            self.fuse.detail
        ));
        out.push_str(&format!(
            "bundled Google client: desktop {}, device {}\n",
            yes(self.bundled_client.desktop),
            yes(self.bundled_client.device)
        ));
        if self.remotes.is_empty() {
            out.push_str("remotes: none\n");
        } else {
            out.push_str("remotes:\n");
            for remote in &self.remotes {
                match &remote.error {
                    Some(error) => {
                        out.push_str(&format!("  {}: unreadable: {error}\n", remote.name))
                    }
                    None => out.push_str(&format!(
                        "  {}: {}, {} client, scope {}, signed in {}\n",
                        remote.name,
                        remote.mode.unwrap_or("?"),
                        remote.client.unwrap_or("?"),
                        remote.scope.as_deref().unwrap_or("?"),
                        yes(remote.signed_in)
                    )),
                }
            }
        }
        if self.services.is_empty() {
            out.push_str("auto-start services: none\n");
        } else {
            out.push_str("auto-start services:\n");
            for service in &self.services {
                out.push_str(&format!("  {}\n", service.summary));
            }
        }
        if let Some(systemd) = &self.systemd {
            let option = |value: Option<bool>| value.map_or("unknown", yes);
            out.push_str(&format!(
                "systemd: {}, user credentials {}, linger {}, user manager stop timeout {}\n",
                systemd
                    .version
                    .map_or_else(|| "not found".to_string(), |version| version.to_string()),
                option(systemd.user_credentials),
                option(systemd.linger),
                systemd.user_stop_timeout_ms.map_or_else(
                    || "unlimited or unknown".to_string(),
                    service::systemd::human_ms
                )
            ));
        }
        if let Some(telemetry) = &self.telemetry {
            out.push_str(&format!(
                "telemetry: {} (from {}), {} stored locally\n",
                telemetry.level,
                telemetry.source,
                telemetry
                    .stored_bytes
                    .map_or_else(|| "unknown".to_string(), crate::telemetry::human_bytes)
            ));
        }
        if self.problems.is_empty() {
            out.push_str("problems: none\n");
        } else {
            out.push_str("problems:\n");
            for problem in &self.problems {
                out.push_str(&format!("  {problem}\n"));
            }
        }
        for note in &self.notes {
            out.push_str(&format!("note: {note}\n"));
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::remote::TestDir;
    use crate::remote::config::Issuer;

    #[test]
    fn linux_fuse_names_each_missing_piece() {
        let dir = TestDir::new("doctor-linux-fuse");
        let bin = dir.path().join("bin");
        std::fs::create_dir_all(&bin).unwrap();
        let path = Some(bin.clone().into_os_string());

        let missing = linux_fuse(Path::new("/nonexistent/fuse"), path.clone(), false);
        assert_eq!(missing.flavour, "none");
        assert!(missing.detail.contains("apt install fuse3"));

        let helper = bin.join("fusermount3");
        std::fs::write(&helper, b"#!/bin/sh\n").unwrap();
        std::fs::set_permissions(&helper, std::fs::Permissions::from_mode(0o755)).unwrap();
        let no_device = linux_fuse(&dir.path().join("fuse"), path.clone(), false);
        assert!(!no_device.ready);
        assert!(no_device.detail.contains("modprobe fuse"));

        // A regular file is not the FUSE character device.
        std::fs::write(dir.path().join("fuse"), b"").unwrap();
        assert!(!linux_fuse(&dir.path().join("fuse"), path.clone(), false).ready);

        // /dev/null is a character device; the helper is not setuid.
        let not_setuid = linux_fuse(Path::new("/dev/null"), path.clone(), false);
        assert!(!not_setuid.ready);
        assert!(not_setuid.detail.contains("not setuid"));
        assert!(linux_fuse(Path::new("/dev/null"), path, true).ready);
    }

    #[test]
    fn macos_fuse_distinguishes_missing_from_not_loaded() {
        let dir = TestDir::new("doctor-macos-fuse");
        let bundle = dir.path().join("macfuse.fs");
        let dev = dir.path().join("dev");
        std::fs::create_dir_all(&dev).unwrap();

        let missing = macos_fuse(&bundle, &dev, None);
        assert_eq!((missing.flavour, missing.ready), ("none", false));

        std::fs::create_dir_all(&bundle).unwrap();
        let idle = macos_fuse(&bundle, &dev, Some("com.apple.fskit.exfat((null))"));
        assert_eq!((idle.flavour, idle.ready), ("macfuse", false));
        assert!(idle.detail.contains("Privacy & Security"));

        let fskit = macos_fuse(&bundle, &dev, Some("io.macfuse.app.fsmodule(5.3.3)"));
        assert!(!fskit.ready);
        assert!(fskit.detail.contains("FSKit"));

        std::fs::write(dev.join("macfuse0"), b"").unwrap();
        assert!(macos_fuse(&bundle, &dev, None).ready);
    }

    fn paths(dir: &TestDir) -> Paths {
        Paths {
            config: dir.path().join("config"),
            state: dir.path().join("state"),
            data: dir.path().join("data"),
        }
    }

    #[test]
    fn remotes_report_mode_client_and_sign_in_without_secrets() {
        let dir = TestDir::new("doctor-remotes");
        let paths = paths(&dir);
        let remotes_dir = paths.config.join("remotes");
        std::os::unix::fs::DirBuilderExt::mode(std::fs::DirBuilder::new().recursive(true), 0o700)
            .create(&remotes_dir)
            .unwrap();
        let plain = RemoteName::parse("photos").unwrap();
        let config = RemoteConfig::plain(
            &plain,
            "owner@example.com",
            "folder-id",
            "My Drive/ZeroTrust Drive (plain)",
            &Issuer::bundled(ClientKind::BundledDevice),
        );
        config.save(&paths).unwrap();
        std::fs::write(remotes_dir.join("broken.json"), b"{").unwrap();
        std::fs::write(remotes_dir.join("notes.txt"), b"ignored").unwrap();

        let listed = remotes(&paths);
        assert_eq!(
            listed.iter().map(|r| r.name.as_str()).collect::<Vec<_>>(),
            ["broken", "photos"]
        );
        assert!(listed[0].error.is_some());
        let photos = &listed[1];
        assert_eq!(photos.mode, Some("plain"));
        assert_eq!(photos.client, Some("bundled-device"));
        assert!(!photos.signed_in);
        let text = serde_json::to_string(photos).unwrap();
        assert!(!text.contains("owner@example.com"));
        assert!(!text.contains("folder-id"));

        assert!(
            remote_problem(photos, true, true)
                .unwrap()
                .contains("not signed in")
        );
        assert!(
            remote_problem(photos, true, false)
                .unwrap()
                .contains("lacks")
        );
        assert!(
            remote_problem(&listed[0], true, true)
                .unwrap()
                .starts_with("remote broken:")
        );
    }

    #[test]
    fn json_report_carries_the_bundled_client_booleans_ci_checks() {
        let report = Report {
            version: "0.0.0",
            os: "linux",
            arch: "x86_64",
            kernel: "6.8.0".to_string(),
            fuse: Fuse {
                flavour: "fusermount3",
                ready: true,
                detail: String::new(),
            },
            bundled_client: Bundled {
                desktop: true,
                device: false,
            },
            remotes: Vec::new(),
            services: Vec::new(),
            systemd: None,
            telemetry: None,
            problems: Vec::new(),
            notes: Vec::new(),
        };
        let value: serde_json::Value =
            serde_json::from_str(&serde_json::to_string_pretty(&report).unwrap()).unwrap();
        assert_eq!(value["bundled_client"]["desktop"], true);
        assert_eq!(value["bundled_client"]["device"], false);
        let text = report.to_text();
        assert!(text.contains("bundled Google client: desktop yes, device no"));
        assert!(text.contains("problems: none"));
    }

    #[test]
    fn a_user_manager_stop_timeout_below_the_unit_is_reported_with_its_remedy() {
        let systemd = |user_stop_timeout_ms| Systemd {
            version: Some(255),
            user_credentials: Some(false),
            linger: Some(true),
            user_stop_timeout_ms,
        };
        let ubuntu = systemd(Some(5_000));
        let note = user_stop_note(&ubuntu).unwrap();
        assert!(note.contains("stops your user manager after 5 s"), "{note}");
        assert!(note.contains("\n  sudo systemctl daemon-reload"), "{note}");
        for enough in [Some(90_000), Some(120_000), None] {
            assert_eq!(user_stop_note(&systemd(enough)), None);
        }
        let report = Report {
            version: "0.0.0",
            os: "linux",
            arch: "aarch64",
            kernel: "6.8.0".to_string(),
            fuse: Fuse {
                flavour: "fusermount3",
                ready: true,
                detail: String::new(),
            },
            bundled_client: Bundled {
                desktop: true,
                device: true,
            },
            remotes: Vec::new(),
            services: Vec::new(),
            systemd: Some(ubuntu),
            telemetry: None,
            problems: Vec::new(),
            notes: vec![note],
        };
        let text = report.to_text();
        assert!(
            text.contains(
                "systemd: 255, user credentials no, linger yes, user manager stop timeout 5 s\n"
            ),
            "{text}"
        );
        assert!(text.contains("note: at shutdown this system stops your user manager"));
        let value: serde_json::Value =
            serde_json::from_str(&serde_json::to_string(&report).unwrap()).unwrap();
        assert_eq!(value["systemd"]["user_stop_timeout_ms"], 5_000);
        let unlimited = Report {
            systemd: Some(systemd(None)),
            notes: Vec::new(),
            ..report
        };
        assert!(
            unlimited
                .to_text()
                .contains("user manager stop timeout unlimited or unknown")
        );
    }
}
