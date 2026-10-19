// SPDX-FileCopyrightText: Copyright 2026 Alexander Orlov <info@lifub.com>

//! `zdrive service ...`: define, install, inspect and run auto-started
//! instances.

use std::path::{Path, PathBuf};

use clap::{Args, Subcommand, ValueEnum};

use super::custody;
use super::definition::{
    Custody, DEFAULT_FINAL_PUSH_WAIT_SECS, Definition, Instance, managed_passphrase_path,
    validate_name,
};
use super::{Host, Platform, Runner, SystemRunner, current_binary, systemd};
use crate::fskit::BackendArg;
use crate::prompt::{SecretReader, TerminalReader};

#[derive(Subcommand, Debug)]
pub(crate) enum ServiceCommand {
    /// Install and start auto-start for an instance (macOS LaunchAgent / Linux systemd user unit)
    Install(InstallArgs),
    /// Stop an instance and remove its auto-start entry; the definition is
    /// kept unless --purge is given
    Uninstall {
        /// Instance name
        name: String,
        /// Also delete the definition and the passphrase custody zdrive
        /// manages for it
        #[arg(long)]
        purge: bool,
        /// Confirm --purge
        #[arg(long)]
        yes: bool,
    },
    /// Show the state of one instance, or of every instance
    Status {
        /// Instance name; all instances when omitted
        name: Option<String>,
    },
    /// List every defined instance with its state
    List,
    /// Run an instance in the foreground (used by launchd/systemd)
    Run {
        /// Instance name
        name: String,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
pub(crate) enum ModeArg {
    /// Mount an encrypted store, optionally synced with a remote
    Encrypted,
    /// Keep a plain folder in sync with a remote
    Plain,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
pub(crate) enum CustodyArg {
    /// systemd-creds when `systemd-creds --user` works (Linux, systemd 256
    /// or newer), else a passphrase file
    Auto,
    /// The passphrase encrypted with `systemd-creds --user` (Linux)
    SystemdCreds,
    /// A passphrase file only you can read
    File,
}

#[derive(Args, Debug, Default)]
pub(crate) struct InstallArgs {
    /// Instance name: 1-63 lowercase letters, digits, '-' or '_'
    #[arg(long)]
    pub(crate) name: String,

    /// Create or overwrite the definition with this mode; `plain` when
    /// --local-dir is given, else `encrypted`. Without definition flags an
    /// existing definition is reused
    #[arg(long, value_enum)]
    pub(crate) mode: Option<ModeArg>,

    /// Remote to sync with (configured with `zdrive remote auth`); required
    /// in plain mode
    #[arg(long, value_name = "NAME")]
    pub(crate) remote: Option<String>,

    /// Encrypted store directory (encrypted mode)
    #[arg(long, value_name = "DIR")]
    pub(crate) encrypted_dir: Option<PathBuf>,

    /// Where the decrypted drive is mounted (encrypted mode)
    #[arg(long, value_name = "DIR")]
    pub(crate) mount_dir: Option<PathBuf>,

    /// Plain folder to keep in sync (plain mode)
    #[arg(long, value_name = "DIR")]
    pub(crate) local_dir: Option<PathBuf>,

    /// Where the unattended instance finds its passphrase (encrypted mode)
    #[arg(long, value_enum, value_name = "CUSTODY")]
    pub(crate) custody: Option<CustodyArg>,

    /// Your own passphrase file, readable only by you; without it file
    /// custody stores the passphrase in a zdrive-managed 0600 file
    #[arg(long, value_name = "FILE")]
    pub(crate) passphrase_file: Option<PathBuf>,

    /// Seconds a stopping instance waits for its final upload [default: 60]
    #[arg(long, value_name = "SECS")]
    pub(crate) final_push_wait: Option<u64>,

    /// macOS, encrypted mode: mount through macFUSE's kernel extension
    /// (kext) or its FSKit module (fskit) instead of deciding at every
    /// start (auto)
    #[arg(long, value_enum, value_name = "BACKEND")]
    pub(crate) fuse_backend: Option<BackendArg>,

    /// Store the passphrase again even if the custody already holds one,
    /// for example after a passphrase rotation
    #[arg(long)]
    pub(crate) replace_passphrase: bool,
}

impl InstallArgs {
    fn defines_instance(&self) -> bool {
        self.mode.is_some()
            || self.remote.is_some()
            || self.encrypted_dir.is_some()
            || self.mount_dir.is_some()
            || self.local_dir.is_some()
            || self.final_push_wait.is_some()
            || self.fuse_backend.is_some()
    }

    fn defines_custody(&self) -> bool {
        self.custody.is_some() || self.passphrase_file.is_some()
    }
}

/// What `prepare_install` needs besides the flags.
pub(crate) struct InstallInputs<'a> {
    /// A passphrase already at hand and where it came from, such as
    /// `ZEROTRUST_PASSPHRASE`; the terminal is asked otherwise.
    pub(crate) given_passphrase: Option<(String, &'static str)>,
    /// The terminal to prompt on, when there is one.
    pub(crate) reader: Option<&'a mut dyn SecretReader>,
    /// Where the systemd-creds probe writes its short-lived credential.
    pub(crate) probe_dir: PathBuf,
}

/// Expands `~` and makes `path` absolute. Existing paths are canonicalized;
/// for a mount point only its parent is, so a dead mount is never touched.
fn resolve_path(path: &Path, flag: &str, mount_point: bool) -> Result<PathBuf, String> {
    let expanded = crate::expand_home_from_env(path)?;
    let absolute = std::path::absolute(&expanded)
        .map_err(|error| format!("cannot resolve --{flag} {}: {error}", path.display()))?;
    if !mount_point && let Ok(canonical) = std::fs::canonicalize(&absolute) {
        return Ok(canonical);
    }
    Ok(match (absolute.parent(), absolute.file_name()) {
        (Some(parent), Some(name)) => std::fs::canonicalize(parent)
            .map(|parent| parent.join(name))
            .unwrap_or(absolute),
        _ => absolute,
    })
}

fn only_with(flag: &str, given: bool, mode: &str) -> Result<(), String> {
    if given {
        Err(format!("--{flag} is valid only with --mode {mode}"))
    } else {
        Ok(())
    }
}

/// Chooses the passphrase custody of an encrypted instance from the flags.
fn choose_custody(
    host: &Host,
    args: &InstallArgs,
    probe_dir: &Path,
    runner: &dyn Runner,
    lines: &mut Vec<String>,
) -> Result<Custody, String> {
    let name = &args.name;
    let requested = args.custody.unwrap_or(CustodyArg::Auto);
    if let Some(file) = &args.passphrase_file {
        if requested == CustodyArg::SystemdCreds {
            return Err(
                "--passphrase-file selects file custody; it cannot be combined with --custody systemd-creds"
                    .to_string(),
            );
        }
        let file = resolve_path(file, "passphrase-file", false)?;
        custody::check_private_secret_file(&file)?;
        lines.push(format!("custody: your passphrase file {}", file.display()));
        return Ok(Custody::File(file));
    }
    let managed = managed_passphrase_path(&host.paths, name);
    let file_line = |reason: &str| {
        format!(
            "custody: passphrase file {} (0600, readable only by you){reason}",
            managed.display()
        )
    };
    let unavailable = |error: &str| {
        let version = systemd::systemd_version(runner)
            .map_or("unknown".to_string(), |version| version.to_string());
        format!(
            "systemd-creds --user does not work here ({error}); it needs systemd 256 or newer, this host runs {version}"
        )
    };
    match (requested, host.platform) {
        (CustodyArg::File, _) | (CustodyArg::Auto, Platform::MacOs) => {
            lines.push(file_line(""));
            Ok(Custody::File(managed))
        }
        (CustodyArg::SystemdCreds, Platform::MacOs) => {
            Err("--custody systemd-creds needs Linux; use --custody file".to_string())
        }
        (CustodyArg::SystemdCreds | CustodyArg::Auto, Platform::Linux) => {
            match custody::probe_systemd_creds(runner, probe_dir) {
                Ok(()) => {
                    lines.push(
                        "custody: systemd-creds --user, bound to this user and host".to_string(),
                    );
                    Ok(Custody::SystemdCreds)
                }
                Err(error) if requested == CustodyArg::SystemdCreds => {
                    Err(format!("{}; use --custody file", unavailable(&error)))
                }
                Err(error) => {
                    lines.push(file_line(&format!("; {}", unavailable(&error))));
                    Ok(Custody::File(managed))
                }
            }
        }
    }
}

/// Builds a new definition from the flags.
fn definition_from_flags(
    host: &Host,
    args: &InstallArgs,
    probe_dir: &Path,
    runner: &dyn Runner,
    lines: &mut Vec<String>,
) -> Result<Definition, String> {
    let mode = args.mode.unwrap_or(if args.local_dir.is_some() {
        ModeArg::Plain
    } else {
        ModeArg::Encrypted
    });
    let instance = match mode {
        ModeArg::Encrypted => {
            only_with("local-dir", args.local_dir.is_some(), "plain")?;
            let encrypted_dir = args
                .encrypted_dir
                .as_deref()
                .ok_or("encrypted mode needs --encrypted-dir")?;
            let mount_dir = args
                .mount_dir
                .as_deref()
                .ok_or("encrypted mode needs --mount-dir")?;
            let fuse_backend = args.fuse_backend.unwrap_or_default();
            crate::fskit::check_platform(fuse_backend, host.platform == Platform::MacOs)?;
            Instance::Encrypted {
                remote: args.remote.clone(),
                encrypted_dir: resolve_path(encrypted_dir, "encrypted-dir", false)?,
                mount_dir: resolve_path(mount_dir, "mount-dir", true)?,
                custody: choose_custody(host, args, probe_dir, runner, lines)?,
                fuse_backend,
            }
        }
        ModeArg::Plain => {
            for (flag, given) in [
                ("encrypted-dir", args.encrypted_dir.is_some()),
                ("mount-dir", args.mount_dir.is_some()),
                ("custody", args.custody.is_some()),
                ("passphrase-file", args.passphrase_file.is_some()),
                ("replace-passphrase", args.replace_passphrase),
                ("fuse-backend", args.fuse_backend.is_some()),
            ] {
                only_with(flag, given, "encrypted")?;
            }
            let remote = args.remote.clone().ok_or("plain mode needs --remote")?;
            let local_dir = args
                .local_dir
                .as_deref()
                .ok_or("plain mode needs --local-dir")?;
            Instance::Plain {
                remote,
                local_dir: resolve_path(local_dir, "local-dir", false)?,
            }
        }
    };
    Ok(Definition {
        name: args.name.clone(),
        instance,
        final_push_wait_secs: args.final_push_wait.unwrap_or(DEFAULT_FINAL_PUSH_WAIT_SECS),
    })
}

fn gather_passphrase(name: &str, inputs: InstallInputs<'_>) -> Result<(String, String), String> {
    let (passphrase, source) = match (inputs.given_passphrase, inputs.reader) {
        (Some(given), _) => given,
        (None, Some(reader)) => {
            let mut ask = |prompt: &str| {
                reader.read_secret(prompt).map_err(|error| {
                    format!("cannot read the passphrase from the terminal: {error}")
                })
            };
            let first = ask(&format!(
                "zerotrust-drive: drive passphrase for service {name}: "
            ))?;
            let second = ask("zerotrust-drive: repeat the passphrase: ")?;
            if first != second {
                return Err("the passphrases do not match; nothing was stored".to_string());
            }
            (first, "the terminal")
        }
        (None, None) => {
            return Err(format!(
                "service {name} needs the drive passphrase for unattended starts: set ZEROTRUST_PASSPHRASE or run in a terminal to be prompted"
            ));
        }
    };
    if crate::insecure_new_store_passphrase(&passphrase) {
        return Err(
            "refusing an empty or built-in demo passphrase for an unattended service".to_string(),
        );
    }
    Ok((passphrase, source.to_string()))
}

/// Creates, updates or loads the definition of `args.name`, and stores the
/// passphrase when its custody needs it. Returns the definition, saved, and
/// the lines to show.
pub(crate) fn prepare_install(
    host: &Host,
    args: &InstallArgs,
    inputs: InstallInputs<'_>,
    runner: &dyn Runner,
) -> Result<(Definition, Vec<String>), String> {
    validate_name(&args.name)?;
    let mut lines = Vec::new();
    let def = if args.defines_instance() {
        definition_from_flags(host, args, &inputs.probe_dir, runner, &mut lines)?
    } else {
        let mut def = Definition::load(&host.paths, &args.name)?;
        match &mut def.instance {
            Instance::Encrypted { custody, .. } if args.defines_custody() => {
                *custody = choose_custody(host, args, &inputs.probe_dir, runner, &mut lines)?;
            }
            Instance::Plain { .. } if args.defines_custody() || args.replace_passphrase => {
                return Err(format!(
                    "service {}: a plain instance has no passphrase custody",
                    args.name
                ));
            }
            _ => lines.push(format!("reusing the definition of {}", args.name)),
        }
        def
    };
    if args.defines_instance() || args.defines_custody() {
        let path = def.save(&host.paths)?;
        lines.push(format!("saved {}", path.display()));
    }
    let own_file = matches!(
        &def.instance,
        Instance::Encrypted { custody: Custody::File(path), .. }
            if *path != managed_passphrase_path(&host.paths, &def.name)
    );
    let store = matches!(def.instance, Instance::Encrypted { .. })
        && !own_file
        && (args.replace_passphrase || custody::needs_passphrase(&host.paths, &def));
    if args.replace_passphrase && own_file {
        return Err(format!(
            "service {}: --replace-passphrase does not write your own passphrase file; edit it yourself",
            def.name
        ));
    }
    if store {
        let (passphrase, source) = gather_passphrase(&def.name, inputs)?;
        lines.push(format!("took the passphrase from {source}"));
        lines.extend(custody::store_passphrase(
            &host.paths,
            &def,
            &passphrase,
            runner,
        )?);
    }
    Ok((def, lines))
}

fn print(lines: &[String]) {
    for line in lines {
        println!("{line}");
    }
}

/// Defines (or reuses) an instance, stores its passphrase custody and
/// starts it. `given` is a passphrase already at hand, with its source.
pub(crate) fn install_with(
    host: &Host,
    args: &InstallArgs,
    given: Option<(String, &'static str)>,
    runner: &dyn Runner,
) -> Result<Vec<String>, String> {
    let mut terminal = TerminalReader::open();
    let inputs = InstallInputs {
        given_passphrase: given,
        reader: terminal
            .as_mut()
            .map(|terminal| terminal as &mut dyn SecretReader),
        probe_dir: custody::probe_dir(),
    };
    let (def, lines) = prepare_install(host, args, inputs, runner)?;
    print(&lines);
    super::install_on(host, &def, &current_binary()?, runner)
}

fn execute(command: ServiceCommand) -> Result<Vec<String>, String> {
    let runner = SystemRunner;
    let host = Host::from_env()?;
    match command {
        ServiceCommand::Install(args) => {
            let given = std::env::var("ZEROTRUST_PASSPHRASE")
                .ok()
                .map(|passphrase| (passphrase, "ZEROTRUST_PASSPHRASE"));
            install_with(&host, &args, given, &runner)
        }
        ServiceCommand::Uninstall { name, purge, yes } => {
            check_purge(&name, purge, yes)?;
            super::uninstall(&name, purge, &runner)
        }
        ServiceCommand::Status { name: Some(name) } => {
            Ok(vec![super::status(&name, &runner)?.summary()])
        }
        ServiceCommand::Status { name: None } | ServiceCommand::List => {
            let statuses = super::list(&host.paths, &runner);
            if statuses.is_empty() {
                return Ok(vec![
                    "no service instances; create one with `zdrive service install --name NAME --mode encrypted|plain ...`"
                        .to_string(),
                ]);
            }
            let mut lines: Vec<String> =
                statuses.iter().map(super::ServiceStatus::summary).collect();
            if host.platform == Platform::Linux && systemd::linger_enabled(&runner) == Some(false) {
                lines.push(format!(
                    "linger is off: instances run only while {} is logged in; to start them at boot, run: sudo loginctl enable-linger {}",
                    host.user, host.user
                ));
            }
            Ok(lines)
        }
        ServiceCommand::Run { name } => Err(format!("service {name}: run is handled by run()")),
    }
}

fn check_purge(name: &str, purge: bool, yes: bool) -> Result<(), String> {
    if purge && !yes {
        return Err(format!(
            "--purge deletes the definition of {name} and the passphrase custody zdrive manages for it; add --yes to confirm"
        ));
    }
    Ok(())
}

pub(crate) fn run(command: ServiceCommand) -> i32 {
    if let ServiceCommand::Run { name } = command {
        return super::run::run(&name);
    }
    match execute(command) {
        Ok(lines) => {
            print(&lines);
            0
        }
        Err(error) => {
            eprintln!("zerotrust-drive: error: {error}");
            1
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::remote::TestDir;
    use crate::service::definition::credential_path;
    use crate::service::testing::{FakeRunner, exit, host, ok, secret_file};
    use std::collections::VecDeque;
    use std::sync::{Arc, Mutex};

    struct Scripted {
        answers: VecDeque<String>,
        prompts: Vec<String>,
    }

    impl SecretReader for Scripted {
        fn read_secret(&mut self, prompt: &str) -> std::io::Result<String> {
            self.prompts.push(prompt.to_string());
            self.answers
                .pop_front()
                .ok_or_else(|| std::io::Error::from(std::io::ErrorKind::UnexpectedEof))
        }
    }

    fn scripted(answers: &[&str]) -> Scripted {
        Scripted {
            answers: answers.iter().map(|answer| answer.to_string()).collect(),
            prompts: Vec::new(),
        }
    }

    fn inputs<'a>(
        dir: &TestDir,
        env: Option<&str>,
        reader: Option<&'a mut dyn SecretReader>,
    ) -> InstallInputs<'a> {
        InstallInputs {
            given_passphrase: env.map(|env| (env.to_string(), "ZEROTRUST_PASSPHRASE")),
            reader,
            probe_dir: dir.path().to_path_buf(),
        }
    }

    /// Emulates `systemd-creds --user`: encrypt seals stdin into the file,
    /// decrypt returns it.
    fn working_creds() -> FakeRunner {
        let stored: Arc<Mutex<Vec<u8>>> = Arc::default();
        FakeRunner::new(move |argv, stdin| {
            let words: Vec<&str> = argv.split(' ').collect();
            if words.get(2) == Some(&"encrypt") {
                std::fs::write(words[5], b"sealed")?;
                *stored.lock().unwrap() = stdin.unwrap_or_default().to_vec();
                ok("")
            } else if words.get(2) == Some(&"decrypt") {
                ok(&String::from_utf8_lossy(&stored.lock().unwrap()))
            } else {
                exit(1, "", "unexpected")
            }
        })
    }

    fn encrypted_args(dir: &TestDir) -> InstallArgs {
        InstallArgs {
            name: "enc".to_string(),
            remote: Some("home".to_string()),
            encrypted_dir: Some(dir.path().join("store")),
            mount_dir: Some(dir.path().join("mount")),
            ..InstallArgs::default()
        }
    }

    #[test]
    fn service_install_auto_custody_prefers_systemd_creds_on_linux() {
        let dir = TestDir::new("service-cli-auto-creds");
        let host = host(&dir, Platform::Linux);
        let runner = working_creds();
        let (def, lines) = prepare_install(
            &host,
            &encrypted_args(&dir),
            inputs(&dir, Some("s3cret"), None),
            &runner,
        )
        .unwrap();
        let Instance::Encrypted {
            remote,
            encrypted_dir,
            mount_dir,
            custody,
            fuse_backend,
        } = &def.instance
        else {
            panic!("{def:?}");
        };
        assert_eq!(remote.as_deref(), Some("home"));
        let root = std::fs::canonicalize(dir.path()).unwrap();
        assert_eq!(*encrypted_dir, root.join("store"));
        assert_eq!(*mount_dir, root.join("mount"));
        assert_eq!(*custody, Custody::SystemdCreds);
        assert_eq!(*fuse_backend, BackendArg::Auto);
        assert_eq!(def.final_push_wait_secs, 60);
        assert_eq!(Definition::load(&host.paths, "enc").unwrap(), def);
        let argv = runner.argv();
        assert_eq!(
            argv.len(),
            3,
            "probe encrypt + decrypt, then the store: {argv:?}"
        );
        assert!(argv[2].starts_with("systemd-creds --user encrypt --name=zdrive-passphrase - "));
        assert_eq!(runner.stdin_of(2).unwrap(), b"s3cret");
        assert!(credential_path(&host.paths, "enc").exists());
        assert!(
            lines
                .iter()
                .any(|line| line.contains("ZEROTRUST_PASSPHRASE"))
        );
        assert!(
            !lines.iter().any(|line| line.contains("s3cret")),
            "the passphrase never appears in output"
        );
        assert_eq!(
            std::fs::read_dir(dir.path())
                .unwrap()
                .filter_map(Result::ok)
                .filter(|entry| entry.file_name().to_string_lossy().contains("probe"))
                .count(),
            0,
            "the probe credential is removed"
        );
    }

    #[test]
    fn service_install_auto_custody_falls_back_to_a_managed_file() {
        let dir = TestDir::new("service-cli-auto-file");
        let host = host(&dir, Platform::Linux);
        let runner = FakeRunner::new(|argv, _| {
            if argv == "systemctl --version" {
                ok("systemd 255 (255.4-1ubuntu8)\n+PAM +AUDIT")
            } else {
                exit(1, "", "systemd-creds: unrecognized option '--user'")
            }
        });
        let mut reader = scripted(&["s3cret", "s3cret"]);
        let (def, lines) = prepare_install(
            &host,
            &encrypted_args(&dir),
            inputs(&dir, None, Some(&mut reader)),
            &runner,
        )
        .unwrap();
        let managed = managed_passphrase_path(&host.paths, "enc");
        assert!(matches!(
            &def.instance,
            Instance::Encrypted { custody: Custody::File(path), .. } if *path == managed
        ));
        assert_eq!(std::fs::read(&managed).unwrap(), b"s3cret");
        assert_eq!(reader.prompts.len(), 2);
        let fallback = lines
            .iter()
            .find(|line| line.starts_with("custody: passphrase file"))
            .unwrap();
        assert!(fallback.contains("this host runs 255"), "{fallback}");
        assert!(fallback.contains("unrecognized option"), "{fallback}");

        let mac = super::super::testing::host(&dir, Platform::MacOs);
        let quiet = FakeRunner::succeeding();
        let (def, _) = prepare_install(
            &mac,
            &encrypted_args(&dir),
            inputs(&dir, Some("s3cret"), None),
            &quiet,
        )
        .unwrap();
        assert!(matches!(
            def.instance,
            Instance::Encrypted {
                custody: Custody::File(_),
                ..
            }
        ));
        assert!(quiet.argv().is_empty(), "macOS never probes systemd-creds");
    }

    #[test]
    fn service_install_explicit_custody_choices_and_refusals() {
        let dir = TestDir::new("service-cli-custody");
        let host = host(&dir, Platform::Linux);
        let broken = FakeRunner::new(|_, _| exit(1, "", "no TPM"));
        let creds = InstallArgs {
            custody: Some(CustodyArg::SystemdCreds),
            ..encrypted_args(&dir)
        };
        let error =
            prepare_install(&host, &creds, inputs(&dir, Some("p4ss"), None), &broken).unwrap_err();
        assert!(
            error.contains("no TPM") && error.contains("--custody file"),
            "{error}"
        );
        let mac = super::super::testing::host(&dir, Platform::MacOs);
        let error =
            prepare_install(&mac, &creds, inputs(&dir, Some("p4ss"), None), &broken).unwrap_err();
        assert!(error.contains("needs Linux"), "{error}");

        let secret = secret_file(&dir);
        let own = InstallArgs {
            passphrase_file: Some(secret.clone()),
            ..encrypted_args(&dir)
        };
        let runner = FakeRunner::succeeding();
        let (def, _) = prepare_install(&host, &own, inputs(&dir, None, None), &runner).unwrap();
        assert!(matches!(
            &def.instance,
            Instance::Encrypted { custody: Custody::File(path), .. }
                if *path == std::fs::canonicalize(&secret).unwrap()
        ));
        assert!(runner.argv().is_empty());
        assert!(!managed_passphrase_path(&host.paths, "enc").exists());

        let conflict = InstallArgs {
            custody: Some(CustodyArg::SystemdCreds),
            ..own
        };
        assert!(
            prepare_install(&host, &conflict, inputs(&dir, None, None), &runner)
                .unwrap_err()
                .contains("cannot be combined")
        );

        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&secret, std::fs::Permissions::from_mode(0o644)).unwrap();
        let loose = InstallArgs {
            passphrase_file: Some(secret.clone()),
            ..encrypted_args(&dir)
        };
        let error = prepare_install(&host, &loose, inputs(&dir, None, None), &runner).unwrap_err();
        assert!(error.contains("chmod 600"), "{error}");
    }

    #[test]
    fn service_install_reuses_or_updates_an_existing_definition() {
        let dir = TestDir::new("service-cli-reuse");
        let host = host(&dir, Platform::Linux);
        let file = InstallArgs {
            custody: Some(CustodyArg::File),
            ..encrypted_args(&dir)
        };
        let runner = FakeRunner::succeeding();
        let (created, _) =
            prepare_install(&host, &file, inputs(&dir, Some("s3cret"), None), &runner).unwrap();

        let bare = InstallArgs {
            name: "enc".to_string(),
            ..InstallArgs::default()
        };
        let (reused, lines) =
            prepare_install(&host, &bare, inputs(&dir, None, None), &runner).unwrap();
        assert_eq!(reused, created);
        assert_eq!(lines, ["reusing the definition of enc"]);

        let replace = InstallArgs {
            replace_passphrase: true,
            ..bare
        };
        prepare_install(
            &host,
            &replace,
            inputs(&dir, Some("rotated"), None),
            &runner,
        )
        .unwrap();
        assert_eq!(
            std::fs::read(managed_passphrase_path(&host.paths, "enc")).unwrap(),
            b"rotated"
        );

        let switch = InstallArgs {
            name: "enc".to_string(),
            custody: Some(CustodyArg::SystemdCreds),
            ..InstallArgs::default()
        };
        let creds = working_creds();
        let (switched, _) =
            prepare_install(&host, &switch, inputs(&dir, Some("rotated"), None), &creds).unwrap();
        assert!(matches!(
            switched.instance,
            Instance::Encrypted {
                custody: Custody::SystemdCreds,
                ..
            }
        ));
        assert!(credential_path(&host.paths, "enc").exists());
        assert!(
            !managed_passphrase_path(&host.paths, "enc").exists(),
            "the plaintext copy is gone"
        );

        let missing = InstallArgs {
            name: "absent".to_string(),
            ..InstallArgs::default()
        };
        let error =
            prepare_install(&host, &missing, inputs(&dir, None, None), &runner).unwrap_err();
        assert!(
            error.contains("no service instance named absent"),
            "{error}"
        );
    }

    #[test]
    fn service_install_plain_definitions_and_flag_refusals() {
        let dir = TestDir::new("service-cli-plain");
        let host = host(&dir, Platform::Linux);
        let runner = FakeRunner::succeeding();
        let plain = InstallArgs {
            name: "photos".to_string(),
            remote: Some("home".to_string()),
            local_dir: Some(dir.path().join("photos")),
            final_push_wait: Some(30),
            ..InstallArgs::default()
        };
        let (def, _) = prepare_install(&host, &plain, inputs(&dir, None, None), &runner).unwrap();
        assert_eq!(
            def.instance,
            Instance::Plain {
                remote: "home".to_string(),
                local_dir: std::fs::canonicalize(dir.path()).unwrap().join("photos"),
            }
        );
        assert_eq!(def.final_push_wait_secs, 30);
        assert!(runner.argv().is_empty());

        let refuse = |args: InstallArgs, expected: &str| {
            let error = prepare_install(&host, &args, inputs(&dir, Some("p4ss"), None), &runner)
                .unwrap_err();
            assert!(error.contains(expected), "{error}");
        };
        refuse(
            InstallArgs {
                mount_dir: Some(dir.path().join("mount")),
                ..plain_args(&dir)
            },
            "--mount-dir is valid only with --mode encrypted",
        );
        refuse(
            InstallArgs {
                custody: Some(CustodyArg::File),
                ..plain_args(&dir)
            },
            "--custody is valid only with --mode encrypted",
        );
        refuse(
            InstallArgs {
                remote: None,
                ..plain_args(&dir)
            },
            "plain mode needs --remote",
        );
        refuse(
            InstallArgs {
                mode: Some(ModeArg::Encrypted),
                ..plain_args(&dir)
            },
            "--local-dir is valid only with --mode plain",
        );
        refuse(
            InstallArgs {
                mount_dir: None,
                ..encrypted_args(&dir)
            },
            "needs --mount-dir",
        );
        refuse(
            InstallArgs {
                final_push_wait: Some(600),
                ..plain_args(&dir)
            },
            "exceeds 75",
        );
        refuse(
            InstallArgs {
                name: "Bad Name".to_string(),
                ..plain_args(&dir)
            },
            "invalid service name",
        );
        refuse(
            InstallArgs {
                name: "photos".to_string(),
                custody: Some(CustodyArg::File),
                ..InstallArgs::default()
            },
            "a plain instance has no passphrase custody",
        );
        refuse(
            InstallArgs {
                fuse_backend: Some(BackendArg::Fskit),
                ..plain_args(&dir)
            },
            "--fuse-backend is valid only with --mode encrypted",
        );
        refuse(
            InstallArgs {
                fuse_backend: Some(BackendArg::Kext),
                ..encrypted_args(&dir)
            },
            "--fuse-backend kext applies only to macOS",
        );
    }

    #[test]
    fn service_install_stores_a_chosen_fuse_backend_on_macos() {
        let dir = TestDir::new("service-cli-fuse-backend");
        let host = host(&dir, Platform::MacOs);
        let runner = FakeRunner::succeeding();
        let args = InstallArgs {
            fuse_backend: Some(BackendArg::Fskit),
            ..encrypted_args(&dir)
        };
        let (def, _) =
            prepare_install(&host, &args, inputs(&dir, Some("s3cret"), None), &runner).unwrap();
        assert!(matches!(
            def.instance,
            Instance::Encrypted {
                fuse_backend: BackendArg::Fskit,
                ..
            }
        ));
        assert_eq!(Definition::load(&host.paths, "enc").unwrap(), def);
    }

    fn plain_args(dir: &TestDir) -> InstallArgs {
        InstallArgs {
            name: "photos".to_string(),
            remote: Some("home".to_string()),
            local_dir: Some(dir.path().join("photos")),
            ..InstallArgs::default()
        }
    }

    #[test]
    fn service_install_passphrase_gathering_refusals() {
        let dir = TestDir::new("service-cli-passphrase");
        let host = host(&dir, Platform::MacOs);
        let runner = FakeRunner::succeeding();
        let args = encrypted_args(&dir);
        let error = prepare_install(&host, &args, inputs(&dir, None, None), &runner).unwrap_err();
        assert!(
            error.contains("set ZEROTRUST_PASSPHRASE or run in a terminal"),
            "{error}"
        );
        let mut mismatch = scripted(&["one", "two"]);
        let error = prepare_install(
            &host,
            &args,
            inputs(&dir, None, Some(&mut mismatch)),
            &runner,
        )
        .unwrap_err();
        assert!(error.contains("do not match"), "{error}");
        let error = prepare_install(
            &host,
            &args,
            inputs(&dir, Some(crate::DEMO_PASSPHRASE), None),
            &runner,
        )
        .unwrap_err();
        assert!(error.contains("demo passphrase"), "{error}");
        assert!(!managed_passphrase_path(&host.paths, "enc").exists());
    }

    #[test]
    fn service_uninstall_purge_needs_confirmation() {
        assert!(check_purge("enc", false, false).is_ok());
        assert!(check_purge("enc", true, true).is_ok());
        let error = check_purge("enc", true, false).unwrap_err();
        assert!(error.contains("add --yes"), "{error}");
    }

    #[test]
    fn service_cli_parses_the_documented_flags() {
        use clap::Parser;
        #[derive(Parser)]
        struct Wrapper {
            #[command(subcommand)]
            command: ServiceCommand,
        }
        let parse = |argv: &[&str]| {
            Wrapper::try_parse_from(std::iter::once("zdrive").chain(argv.iter().copied()))
                .map(|wrapper| wrapper.command)
        };
        let Ok(ServiceCommand::Install(args)) = parse(&[
            "install",
            "--name",
            "enc",
            "--mode",
            "encrypted",
            "--encrypted-dir",
            "/s",
            "--mount-dir",
            "/m",
            "--custody",
            "systemd-creds",
            "--final-push-wait",
            "30",
        ]) else {
            panic!("install did not parse");
        };
        assert_eq!(args.mode, Some(ModeArg::Encrypted));
        assert_eq!(args.custody, Some(CustodyArg::SystemdCreds));
        assert_eq!(args.final_push_wait, Some(30));
        assert!(matches!(
            parse(&["uninstall", "enc", "--purge", "--yes"]),
            Ok(ServiceCommand::Uninstall {
                purge: true,
                yes: true,
                ..
            })
        ));
        assert!(matches!(
            parse(&["status"]),
            Ok(ServiceCommand::Status { name: None })
        ));
        assert!(matches!(parse(&["list"]), Ok(ServiceCommand::List)));
        assert!(matches!(
            parse(&["run", "enc"]),
            Ok(ServiceCommand::Run { .. })
        ));
        assert!(parse(&["install"]).is_err(), "--name is required");
        assert!(parse(&["install", "--name", "x", "--custody", "keychain"]).is_err());
    }
}
