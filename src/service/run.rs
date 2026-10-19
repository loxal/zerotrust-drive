// SPDX-FileCopyrightText: Copyright 2026 Alexander Orlov <info@lifub.com>

//! `zdrive service run <name>`: what launchd and systemd start. It never
//! prompts; a missing passphrase custody fails fast with one log line and a
//! refusal (see `crate::refusal`), so the manager does not restart it.
//! After the checks it replaces itself with the mount or sync command, so
//! the service manager supervises and signals the real process and
//! systemd's `NotifyAccess=main` accepts its `READY=1`.

use std::ffi::OsString;
use std::path::{Path, PathBuf};

use super::custody::{self, CREDENTIAL_NAME};
use super::definition::{Custody, Definition, Instance};
use super::{Host, SystemRunner, display_command, notify, recover};
use crate::fskit::BackendArg;
use crate::refusal::{self, Class, Failure};

/// The arguments the instance runs `zdrive` with. Under systemd-creds
/// custody the passphrase is the credential file that systemd decrypted
/// into `credentials_directory`.
pub(crate) fn exec_args(def: &Definition, credentials_directory: Option<&Path>) -> Vec<OsString> {
    let mut args: Vec<OsString> = Vec::new();
    let mut push = |values: &[&std::ffi::OsStr]| {
        args.extend(values.iter().map(|value| value.to_os_string()));
    };
    let wait = def.final_push_wait_secs.to_string();
    match &def.instance {
        Instance::Encrypted {
            remote,
            encrypted_dir,
            mount_dir,
            custody,
            fuse_backend,
        } => {
            if let Some(remote) = remote {
                push(&["--remote".as_ref(), remote.as_ref()]);
            }
            push(&["--encrypted-dir".as_ref(), encrypted_dir.as_os_str()]);
            push(&["--decrypted-dir".as_ref(), mount_dir.as_os_str()]);
            if *fuse_backend != BackendArg::Auto {
                push(&["--fuse-backend".as_ref(), fuse_backend.as_str().as_ref()]);
            }
            let passphrase_file = match custody {
                Custody::File(path) => Some(path.clone()),
                Custody::SystemdCreds => credentials_directory.map(|dir| dir.join(CREDENTIAL_NAME)),
            };
            if let Some(path) = &passphrase_file {
                push(&["--passphrase-file".as_ref(), path.as_os_str()]);
            }
            // The final push, and so its wait, exists only with a remote.
            if remote.is_some() {
                push(&["--final-push-wait".as_ref(), wait.as_ref()]);
            }
        }
        Instance::Plain { remote, local_dir } => {
            push(&[
                "sync".as_ref(),
                "--remote".as_ref(),
                remote.as_ref(),
                "--dir".as_ref(),
                local_dir.as_os_str(),
                "--watch".as_ref(),
            ]);
        }
    }
    push(&[
        "--telemetry-instance".as_ref(),
        def.name.as_ref(),
        "--service".as_ref(),
    ]);
    args
}

/// A checked start: the arguments to exec and the lines to log first.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Prepared {
    pub(crate) args: Vec<OsString>,
    pub(crate) log: Vec<String>,
}

/// Loads and checks instance `name`, including its passphrase custody, and
/// recovers a stale mount through `recover`. A definition or custody
/// problem is classed: it persists until the operator acts.
pub(crate) fn prepare(
    host: &Host,
    name: &str,
    credentials_directory: Option<&Path>,
    recover: &mut dyn FnMut(&Path) -> Result<Vec<String>, String>,
) -> Result<Prepared, Failure> {
    let def = Definition::load(&host.paths, name)
        .map_err(|error| Failure::refused(Class::Definition, format!("service {name}: {error}")))?;
    let mut log = Vec::new();
    if let Instance::Encrypted {
        mount_dir, custody, ..
    } = &def.instance
    {
        match custody {
            Custody::File(path) => custody::check_private_secret_file(path).map_err(|error| {
                Failure::refused(Class::Custody, format!("service {name}: {error}"))
            })?,
            Custody::SystemdCreds => {
                let present = credentials_directory
                    .map(|dir| dir.join(CREDENTIAL_NAME))
                    .is_some_and(|file| file.is_file());
                if !present {
                    return Err(Failure::refused(
                        Class::Custody,
                        format!(
                            "service {name}: custody is systemd-creds but $CREDENTIALS_DIRECTORY/{CREDENTIAL_NAME} is missing; run: zdrive service install --name {name}"
                        ),
                    ));
                }
            }
        }
        log.extend(recover(mount_dir).map_err(|error| format!("service {name}: {error}"))?);
    }
    Ok(Prepared {
        args: exec_args(&def, credentials_directory),
        log,
    })
}

/// Runs instance `name` in the foreground. Returns only on failure: with
/// the refusal status for a classed failure, else 1 so the manager retries.
pub(crate) fn run(name: &str) -> i32 {
    let host = match Host::from_env() {
        Ok(host) => host,
        Err(error) => return transient(&format!("service {name}: {error}")),
    };
    let failure = start(&host, name);
    match failure.class {
        Some(class) => {
            eprintln!("zerotrust-drive: error: {}", failure.message);
            refusal::refuse(Some(&host.paths), name, class, &failure.message)
        }
        None => transient(&failure.message),
    }
}

fn transient(message: &str) -> i32 {
    eprintln!("zerotrust-drive: error: {message}");
    let _ = notify::status(message);
    1
}

fn start(host: &Host, name: &str) -> Failure {
    use std::os::unix::process::CommandExt;
    // This attempt replaces the last refusal: a new one is recorded if the
    // cause persists, and a running instance shows none.
    if let Err(error) = refusal::clear(&host.paths, name) {
        eprintln!("zerotrust-drive: service {name}: {error}");
    }
    let credentials_directory = std::env::var_os("CREDENTIALS_DIRECTORY")
        .map(PathBuf::from)
        .filter(|dir| dir.is_absolute());
    let prepared = match prepare(host, name, credentials_directory.as_deref(), &mut |dir| {
        recover::recover(dir, host.platform, &SystemRunner)
    }) {
        Ok(prepared) => prepared,
        Err(failure) => return failure,
    };
    for line in &prepared.log {
        eprintln!("zerotrust-drive: service {name}: {line}");
    }
    let binary = match std::env::current_exe() {
        Ok(binary) => binary,
        Err(error) => {
            return format!("service {name}: cannot locate the zdrive binary: {error}").into();
        }
    };
    eprintln!(
        "zerotrust-drive: service {name}: starting {}",
        display_command(&binary.to_string_lossy(), &prepared.args)
    );
    let _ = notify::status(&format!("starting {name}"));
    let error = std::process::Command::new(&binary)
        .args(&prepared.args)
        .env_remove("ZEROTRUST_PASSPHRASE")
        .stdin(std::process::Stdio::null())
        .exec();
    format!("service {name}: cannot start {}: {error}", binary.display()).into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::remote::TestDir;
    use crate::service::Platform;
    use crate::service::testing::{host, secret_file};
    use std::os::unix::fs::PermissionsExt;

    fn strings(args: &[OsString]) -> Vec<String> {
        args.iter()
            .map(|arg| arg.to_string_lossy().into_owned())
            .collect()
    }

    fn encrypted(remote: Option<&str>, custody: Custody) -> Definition {
        Definition {
            name: "encrypted".to_string(),
            instance: Instance::Encrypted {
                remote: remote.map(str::to_string),
                encrypted_dir: PathBuf::from("/abs/store"),
                mount_dir: PathBuf::from("/abs/mount"),
                custody,
                fuse_backend: BackendArg::Auto,
            },
            final_push_wait_secs: 45,
        }
    }

    #[test]
    fn service_exec_args_pass_only_a_chosen_fuse_backend() {
        let mut def = encrypted(None, Custody::File(PathBuf::from("/abs/secret")));
        assert!(!strings(&exec_args(&def, None)).contains(&"--fuse-backend".to_string()));
        if let Instance::Encrypted { fuse_backend, .. } = &mut def.instance {
            *fuse_backend = BackendArg::Fskit;
        }
        let args = strings(&exec_args(&def, None));
        let at = args.iter().position(|arg| arg == "--fuse-backend").unwrap();
        assert_eq!(args[at + 1], "fskit");
    }

    #[test]
    fn service_exec_args_for_encrypted_instances() {
        let def = encrypted(Some("home"), Custody::File(PathBuf::from("/abs/secret")));
        assert_eq!(
            strings(&exec_args(&def, None)),
            [
                "--remote",
                "home",
                "--encrypted-dir",
                "/abs/store",
                "--decrypted-dir",
                "/abs/mount",
                "--passphrase-file",
                "/abs/secret",
                "--final-push-wait",
                "45",
                "--telemetry-instance",
                "encrypted",
                "--service",
            ]
        );
        let local = encrypted(None, Custody::SystemdCreds);
        assert_eq!(
            strings(&exec_args(
                &local,
                Some(Path::new("/run/user/1000/credentials/u"))
            )),
            [
                "--encrypted-dir",
                "/abs/store",
                "--decrypted-dir",
                "/abs/mount",
                "--passphrase-file",
                "/run/user/1000/credentials/u/zdrive-passphrase",
                "--telemetry-instance",
                "encrypted",
                "--service",
            ]
        );
        assert!(!strings(&exec_args(&local, None)).contains(&"--passphrase-file".to_string()));
    }

    #[test]
    fn service_exec_args_for_plain_instances() {
        let def = Definition {
            name: "photos".to_string(),
            instance: Instance::Plain {
                remote: "home".to_string(),
                local_dir: PathBuf::from("/abs/photos"),
            },
            final_push_wait_secs: 60,
        };
        assert_eq!(
            strings(&exec_args(&def, None)),
            [
                "sync",
                "--remote",
                "home",
                "--dir",
                "/abs/photos",
                "--watch",
                "--telemetry-instance",
                "photos",
                "--service",
            ]
        );
    }

    #[test]
    fn service_run_prepare_checks_custody_and_recovers_the_mount() {
        let dir = TestDir::new("service-run-prepare");
        let host = host(&dir, Platform::Linux);
        let secret = secret_file(&dir);
        let def = encrypted(Some("home"), Custody::File(secret.clone()));
        def.save(&host.paths).unwrap();
        let mut recovered = Vec::new();
        let prepared = prepare(&host, "encrypted", None, &mut |mount| {
            recovered.push(mount.to_path_buf());
            Ok(vec!["unmounted".to_string()])
        })
        .unwrap();
        assert_eq!(recovered, [PathBuf::from("/abs/mount")]);
        assert_eq!(prepared.log, ["unmounted"]);
        assert_eq!(prepared.args, exec_args(&def, None));

        std::fs::set_permissions(&secret, std::fs::Permissions::from_mode(0o640)).unwrap();
        let failure = prepare(&host, "encrypted", None, &mut |_| unreachable!()).unwrap_err();
        assert_eq!(failure.class, Some(Class::Custody));
        let error = failure.message;
        assert!(
            error.starts_with(&format!(
                "service encrypted: passphrase file {}",
                secret.display()
            )),
            "{error}"
        );
        assert!(error.contains("chmod 600"), "{error}");

        std::fs::set_permissions(&secret, std::fs::Permissions::from_mode(0o600)).unwrap();
        let error = prepare(&host, "encrypted", None, &mut |_| {
            Err(
                "/abs/mount is mounted by a zerotrust-drive that is already running; stop it first"
                    .to_string(),
            )
        })
        .unwrap_err();
        // Expected failing control: a busy mount point may heal by itself,
        // so it stays transient and the manager keeps restarting.
        assert_eq!(error.class, None);
        assert!(error.message.contains("already running"), "{error}");

        let missing = prepare(&host, "absent", None, &mut |_| unreachable!()).unwrap_err();
        assert_eq!(missing.class, Some(Class::Definition));
        assert!(
            missing
                .message
                .starts_with("service absent: no service instance named absent")
        );
    }

    #[test]
    fn service_run_prepare_requires_the_systemd_credential() {
        let dir = TestDir::new("service-run-creds");
        let host = host(&dir, Platform::Linux);
        let def = encrypted(Some("home"), Custody::SystemdCreds);
        def.save(&host.paths).unwrap();
        let expected = Failure::refused(
            Class::Custody,
            "service encrypted: custody is systemd-creds but $CREDENTIALS_DIRECTORY/zdrive-passphrase is missing; run: zdrive service install --name encrypted",
        );
        assert_eq!(
            prepare(&host, "encrypted", None, &mut |_| unreachable!()).unwrap_err(),
            expected
        );
        let credentials = dir.path().join("credentials");
        std::fs::create_dir_all(&credentials).unwrap();
        assert_eq!(
            prepare(
                &host,
                "encrypted",
                Some(&credentials),
                &mut |_| unreachable!()
            )
            .unwrap_err(),
            expected
        );
        std::fs::write(credentials.join(CREDENTIAL_NAME), "pass").unwrap();
        let prepared = prepare(&host, "encrypted", Some(&credentials), &mut |_| {
            Ok(Vec::new())
        })
        .unwrap();
        assert!(
            strings(&prepared.args)
                .contains(&credentials.join(CREDENTIAL_NAME).display().to_string())
        );
    }

    #[test]
    fn service_run_prepare_skips_custody_and_recovery_for_plain_instances() {
        let dir = TestDir::new("service-run-plain");
        let host = host(&dir, Platform::MacOs);
        let def = Definition {
            name: "photos".to_string(),
            instance: Instance::Plain {
                remote: "home".to_string(),
                local_dir: dir.path().join("photos"),
            },
            final_push_wait_secs: 60,
        };
        def.save(&host.paths).unwrap();
        let prepared = prepare(&host, "photos", None, &mut |_| unreachable!()).unwrap();
        assert_eq!(prepared.args[0], "sync");
        assert!(prepared.log.is_empty());
    }
}
