// SPDX-FileCopyrightText: Copyright 2026 Alexander Orlov <info@lifub.com>

//! Permanent start failures of an unattended drive.
//!
//! A service that cannot start until its operator acts - a wrong passphrase,
//! a revoked sign-in, a binned Drive folder - must not be restarted forever:
//! every restart repeats key derivation and network work and floods the log.
//! Such a failure is a *refusal*. The process records it durably under the
//! state directory, gives telemetry its class (never its message), and exits
//! with a code its service manager does not restart: 78 (`EX_CONFIG`) under
//! systemd, which the unit excludes with `RestartPreventExitStatus=78`, and
//! 0 under launchd, whose `KeepAlive { SuccessfulExit = false }` cannot
//! exclude a single status. `zdrive service status` and `zdrive doctor` show
//! the record; `zdrive service install` clears it and starts the service
//! again. Interactive runs are never armed and keep exiting with 1.
//!
//! Only causes that persist until the operator acts are classed. Anything
//! that may heal by itself (network, a busy mount point, an I/O error) stays
//! transient and keeps the service manager's restarts.

use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use serde::{Deserialize, Serialize};

use crate::remote::RemoteError;
use crate::remote::config::Paths;

/// `EX_CONFIG` from sysexits(3): the systemd unit does not restart it.
pub(crate) const EXIT_CONFIG: i32 = 78;

/// Bound for reading a record; a real one is a few hundred bytes.
const MAX_RECORD_BYTES: u64 = 64 * 1024;

/// Why a service refused to start. The tag is the telemetry value.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Class {
    /// The service definition is missing or invalid.
    Definition,
    /// The passphrase custody (file or systemd credential) is unusable.
    Custody,
    /// The passphrase does not open the store.
    Passphrase,
    /// The remote is missing, of the wrong mode or has no OAuth client.
    Remote,
    /// The provider rejected the credential: sign in again.
    Authorization,
    /// The Drive folder is gone, binned or not marked for this mode.
    DriveFolder,
    /// Local and remote lineages diverged.
    Diverged,
    /// The local store needs an operator step (location, format, recovery).
    Store,
    /// The mount point is invalid.
    MountPoint,
    /// The selected FUSE backend is unavailable.
    Backend,
}

impl Class {
    pub(crate) fn tag(self) -> &'static str {
        match self {
            Self::Definition => "definition",
            Self::Custody => "custody",
            Self::Passphrase => "passphrase",
            Self::Remote => "remote",
            Self::Authorization => "authorization",
            Self::DriveFolder => "drive_folder",
            Self::Diverged => "diverged",
            Self::Store => "store",
            Self::MountPoint => "mount_point",
            Self::Backend => "backend",
        }
    }
}

/// A start failure: refused (classed) or transient.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Failure {
    pub(crate) class: Option<Class>,
    pub(crate) message: String,
}

impl Failure {
    pub(crate) fn refused(class: Class, message: impl Into<String>) -> Self {
        Self {
            class: Some(class),
            message: message.into(),
        }
    }

    /// `message` about `error`, classed by [`remote_class`].
    pub(crate) fn remote(error: &RemoteError, message: impl Into<String>) -> Self {
        Self {
            class: remote_class(error),
            message: message.into(),
        }
    }
}

impl From<String> for Failure {
    fn from(message: String) -> Self {
        Self {
            class: None,
            message,
        }
    }
}

impl std::fmt::Display for Failure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.message)
    }
}

/// The remote failures that persist until the operator acts.
pub(crate) fn remote_class(error: &RemoteError) -> Option<Class> {
    match error {
        RemoteError::Auth(_) => Some(Class::Authorization),
        RemoteError::Diverged(_) => Some(Class::Diverged),
        _ => None,
    }
}

static SERVICE: OnceLock<String> = OnceLock::new();

/// Arms refusals for service instance `name`: from now on a classed failure
/// passed to [`exit`] is recorded and ends with [`exit_code`].
pub(crate) fn arm(name: &str) {
    if crate::service::definition::validate_name(name).is_ok() {
        let _ = SERVICE.set(name.to_string());
    }
}

pub(crate) fn armed() -> bool {
    SERVICE.get().is_some()
}

/// The exit status that keeps the service manager from restarting.
pub(crate) const fn exit_code() -> i32 {
    code_for(cfg!(target_os = "macos"))
}

const fn code_for(macos: bool) -> i32 {
    if macos { 0 } else { EXIT_CONFIG }
}

/// Ends the process with `failure`: a refusal when armed and classed,
/// otherwise the ordinary error exit with status 1.
pub(crate) fn exit(failure: Failure) -> ! {
    let (Some(class), Some(name)) = (failure.class, SERVICE.get()) else {
        crate::exit_with_error(failure.message)
    };
    eprintln!("zerotrust-drive: error: {}", failure.message);
    crate::telemetry::event(
        crate::telemetry::Level::Standard,
        "service.refused",
        &[("class", crate::telemetry::Field::Tag(class.tag()))],
    );
    let code = refuse(
        Paths::from_env().ok().as_ref(),
        name,
        class,
        &failure.message,
    );
    crate::telemetry::stop("refused", code);
    std::process::exit(code);
}

/// Records the refusal of service `name`, logs and reports it to the service
/// manager, and returns the exit status to end with. A record that cannot be
/// written is logged; the refusal stands, since a restart would only fail
/// the same way.
pub(crate) fn refuse(paths: Option<&Paths>, name: &str, class: Class, message: &str) -> i32 {
    let written = match paths {
        Some(paths) => write(paths, name, &Record::new(class, message)),
        None => Err("the state directory is unknown".to_string()),
    };
    if let Err(error) = written {
        eprintln!("zerotrust-drive: service {name}: cannot record the refusal: {error}");
    }
    eprintln!(
        "zerotrust-drive: service {name}: refused ({}); it stays stopped until the cause is fixed and `zdrive service install --name {name}` starts it again",
        class.tag()
    );
    let _ = crate::service::notify::status(&format!(
        "refused ({}): {}",
        class.tag(),
        one_line(message)
    ));
    exit_code()
}

fn one_line(text: &str) -> String {
    text.chars()
        .map(|character| {
            if character.is_control() {
                ' '
            } else {
                character
            }
        })
        .take(200)
        .collect()
}

/// The durable record of the last refusal of one service instance.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Record {
    /// Unix seconds.
    pub(crate) at: u64,
    pub(crate) class: String,
    pub(crate) message: String,
    pub(crate) version: String,
}

impl Record {
    fn new(class: Class, message: &str) -> Self {
        Self {
            at: crate::remote::lease::unix_now(),
            class: class.tag().to_string(),
            message: message.to_string(),
            version: env!("CARGO_PKG_VERSION").to_string(),
        }
    }

    /// One line for `service status` and `doctor`.
    pub(crate) fn describe(&self, name: &str) -> String {
        format!(
            "refused at {} ({}): {}; fix that, then run: zdrive service install --name {name}",
            utc_text(self.at),
            self.class,
            one_line(&self.message)
        )
    }
}

/// `YYYY-MM-DD HH:MM UTC`.
fn utc_text(secs: u64) -> String {
    let secs = i64::try_from(secs).unwrap_or(i64::MAX);
    let (days, rest) = (secs.div_euclid(86_400), secs.rem_euclid(86_400));
    let (year, month, day) = crate::telemetry::system::civil_from_days(days);
    format!(
        "{year:04}-{month:02}-{day:02} {:02}:{:02} UTC",
        rest / 3600,
        rest / 60 % 60
    )
}

fn dir(paths: &Paths) -> PathBuf {
    paths.state.join("services")
}

pub(crate) fn path(paths: &Paths, name: &str) -> PathBuf {
    dir(paths).join(format!("{name}.refusal.json"))
}

fn write(paths: &Paths, name: &str, record: &Record) -> Result<(), String> {
    for dir in [paths.state.clone(), dir(paths)] {
        crate::remote::ensure_private_dir(&dir).map_err(|error| error.to_string())?;
    }
    let bytes = serde_json::to_vec_pretty(record).map_err(|error| error.to_string())?;
    crate::remote::write_private_file(&path(paths, name), &bytes).map_err(|error| error.to_string())
}

/// The refusal record of `name`, if any.
pub(crate) fn read(paths: &Paths, name: &str) -> Result<Option<Record>, String> {
    let path = path(paths, name);
    let Some(bytes) = crate::remote::read_private_file(&path, MAX_RECORD_BYTES)
        .map_err(|error| error.to_string())?
    else {
        return Ok(None);
    };
    serde_json::from_slice(&bytes)
        .map(Some)
        .map_err(|error| format!("{}: {error}", path.display()))
}

/// Removes the refusal record of `name`; `Ok(true)` when one existed.
pub(crate) fn clear(paths: &Paths, name: &str) -> Result<bool, String> {
    remove(&path(paths, name))
}

fn remove(path: &Path) -> Result<bool, String> {
    match std::fs::remove_file(path) {
        Ok(()) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(format!("remove {}: {error}", path.display())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::remote::TestDir;

    fn paths(dir: &TestDir) -> Paths {
        Paths {
            config: dir.path().join("config"),
            state: dir.path().join("state"),
            data: dir.path().join("data"),
        }
    }

    #[test]
    fn refusal_exit_codes_stop_each_service_manager() {
        assert_eq!(code_for(true), 0, "launchd restarts only a failed exit");
        assert_eq!(code_for(false), EXIT_CONFIG);
        assert_eq!(EXIT_CONFIG, 78);
        // Expected failing control: the ordinary error status is restarted
        // by both managers, so it must differ from both refusal codes.
        assert_ne!(code_for(true), 1);
        assert_ne!(code_for(false), 1);
        assert_eq!(exit_code(), if cfg!(target_os = "macos") { 0 } else { 78 });
    }

    #[test]
    fn refusal_classes_only_cover_failures_that_persist() {
        let class = |error: RemoteError| remote_class(&error);
        assert_eq!(
            class(RemoteError::Auth("invalid_grant".into())),
            Some(Class::Authorization)
        );
        assert_eq!(
            class(RemoteError::Diverged("fork".into())),
            Some(Class::Diverged)
        );
        for transient in [
            RemoteError::Network("offline".into()),
            RemoteError::Quota("full".into()),
            RemoteError::NotFound("pack".into()),
            RemoteError::Conflict("id".into()),
            RemoteError::Integrity("digest".into()),
            RemoteError::Protocol("odd".into()),
            RemoteError::Local("io".into()),
        ] {
            assert_eq!(class(transient), None);
        }
        let failure = Failure::from("disk busy".to_string());
        assert_eq!(failure.class, None);
        assert_eq!(failure.to_string(), "disk busy");
        let tags: std::collections::BTreeSet<_> = [
            Class::Definition,
            Class::Custody,
            Class::Passphrase,
            Class::Remote,
            Class::Authorization,
            Class::DriveFolder,
            Class::Diverged,
            Class::Store,
            Class::MountPoint,
            Class::Backend,
        ]
        .iter()
        .map(|class| class.tag())
        .collect();
        assert_eq!(tags.len(), 10, "tags are distinct");
        assert!(
            tags.iter()
                .all(|tag| tag.bytes().all(|b| b.is_ascii_lowercase() || b == b'_'))
        );
    }

    #[test]
    fn refusal_record_round_trips_through_a_private_file() {
        let dir = TestDir::new("refusal-record");
        let paths = paths(&dir);
        assert_eq!(read(&paths, "home").unwrap(), None);
        assert!(!clear(&paths, "home").unwrap());

        let code = refuse(
            Some(&paths),
            "home",
            Class::Passphrase,
            "wrong passphrase:\nit does not open the v2 root",
        );
        assert_eq!(code, exit_code());
        let file = path(&paths, "home");
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(&file).unwrap().permissions().mode() & 0o777,
            0o600
        );
        let record = read(&paths, "home").unwrap().unwrap();
        assert_eq!(record.class, "passphrase");
        assert_eq!(record.version, env!("CARGO_PKG_VERSION"));
        assert!(record.at > 1_700_000_000);
        let line = record.describe("home");
        assert!(
            line.ends_with(
                "(passphrase): wrong passphrase: it does not open the v2 root; fix that, then run: zdrive service install --name home"
            ),
            "{line}"
        );
        assert!(!line.contains('\n'));
        assert_eq!(read(&paths, "other").unwrap(), None);

        // A record others can read is refused rather than trusted.
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(read(&paths, "home").unwrap_err().contains("chmod 600"));
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o600)).unwrap();
        std::fs::write(&file, b"{").unwrap();
        assert!(read(&paths, "home").is_err());

        assert!(clear(&paths, "home").unwrap());
        assert_eq!(read(&paths, "home").unwrap(), None);
    }

    #[test]
    fn refusal_times_are_utc() {
        assert_eq!(utc_text(0), "1970-01-01 00:00 UTC");
        assert_eq!(utc_text(1_760_875_200), "2025-10-19 12:00 UTC");
    }
}
