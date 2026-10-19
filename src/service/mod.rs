// SPDX-FileCopyrightText: Copyright 2026 Alexander Orlov <info@lifub.com>

//! Auto-start of drive instances: a macOS LaunchAgent or a Linux systemd
//! user unit runs `zdrive service run <name>`, which loads the instance
//! definition, checks the passphrase custody, recovers a stale mount and then
//! replaces itself with the configured mount or sync command.
//!
//! Every external command goes through [`Runner`], so tests assert the exact
//! argument vectors without touching the service manager of the host.

pub(crate) mod cli;
pub(crate) mod custody;
pub(crate) mod definition;
pub(crate) mod launchd;
pub(crate) mod notify;
pub(crate) mod recover;
pub(crate) mod run;
pub(crate) mod systemd;

use std::ffi::{CStr, OsStr, OsString};
use std::io::Write;
use std::path::{Component, Path, PathBuf};
use std::process::Stdio;

use crate::remote::config::Paths;

use definition::Definition;

/// Operating system whose service manager runs the instances.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Platform {
    MacOs,
    Linux,
}

impl Platform {
    pub(crate) fn current() -> Result<Self, String> {
        if cfg!(target_os = "macos") {
            Ok(Self::MacOs)
        } else if cfg!(target_os = "linux") {
            Ok(Self::Linux)
        } else {
            Err("auto-start services are supported only on macOS and Linux".to_string())
        }
    }
}

/// Everything about the current user that install, uninstall and status
/// depend on. Tests construct it to point into a scratch directory.
#[derive(Clone, Debug)]
pub(crate) struct Host {
    pub(crate) platform: Platform,
    pub(crate) paths: Paths,
    pub(crate) home: PathBuf,
    /// `$XDG_CONFIG_HOME/systemd/user`, or `~/.config/systemd/user`.
    pub(crate) systemd_user_dir: PathBuf,
    /// XDG base directories set for this process. launchd and the systemd
    /// user manager do not inherit the login shell, so they are written into
    /// the plist or the unit drop-in to keep definitions and sync state at
    /// the same place.
    pub(crate) xdg_environment: Vec<(String, String)>,
    pub(crate) uid: u32,
    pub(crate) user: String,
}

impl Host {
    pub(crate) fn from_env() -> Result<Self, String> {
        let paths = Paths::from_env().map_err(|error| error.to_string())?;
        Self::with_paths(paths)
    }

    pub(crate) fn with_paths(paths: Paths) -> Result<Self, String> {
        let absolute = |name: &str| {
            std::env::var_os(name)
                .map(PathBuf::from)
                .filter(|path| path.is_absolute())
        };
        let home =
            absolute("HOME").ok_or_else(|| "HOME is not set to an absolute path".to_string())?;
        let config_home = absolute("XDG_CONFIG_HOME").unwrap_or_else(|| home.join(".config"));
        let mut xdg_environment = Vec::new();
        for name in ["XDG_CONFIG_HOME", "XDG_STATE_HOME"] {
            if let Some(path) = absolute(name) {
                let text = path
                    .to_str()
                    .ok_or_else(|| format!("{name} is not valid UTF-8"))?;
                xdg_environment.push((name.to_string(), text.to_string()));
            }
        }
        let uid = current_uid();
        Ok(Self {
            platform: Platform::current()?,
            paths,
            systemd_user_dir: config_home.join("systemd").join("user"),
            home,
            xdg_environment,
            uid,
            user: user_name(uid),
        })
    }
}

pub(crate) fn current_uid() -> u32 {
    // SAFETY: getuid has no preconditions and cannot fail.
    unsafe { libc::getuid() }
}

/// The login name of `uid`, or the number when the account has no name.
pub(crate) fn user_name(uid: u32) -> String {
    let mut buffer = vec![0 as libc::c_char; 16 << 10];
    // SAFETY: passwd is plain old data that getpwuid_r fills in.
    let mut passwd: libc::passwd = unsafe { std::mem::zeroed() };
    let mut result: *mut libc::passwd = std::ptr::null_mut();
    // SAFETY: every pointer refers to live, correctly sized storage for the
    // duration of the call.
    let rc = unsafe {
        libc::getpwuid_r(
            uid,
            &mut passwd,
            buffer.as_mut_ptr(),
            buffer.len(),
            &mut result,
        )
    };
    if rc != 0 || result.is_null() || passwd.pw_name.is_null() {
        return uid.to_string();
    }
    // SAFETY: pw_name points into buffer and is NUL-terminated on success.
    let name = unsafe { CStr::from_ptr(passwd.pw_name) };
    match name.to_str() {
        Ok(name) if !name.is_empty() => name.to_string(),
        _ => uid.to_string(),
    }
}

/// Exit status and captured streams of one external command.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct Output {
    /// `None` when the command was terminated by a signal.
    pub(crate) status: Option<i32>,
    pub(crate) stdout: Vec<u8>,
    pub(crate) stderr: Vec<u8>,
}

impl Output {
    pub(crate) fn success(&self) -> bool {
        self.status == Some(0)
    }

    pub(crate) fn stdout_text(&self) -> String {
        String::from_utf8_lossy(&self.stdout).into_owned()
    }

    pub(crate) fn stderr_text(&self) -> String {
        String::from_utf8_lossy(&self.stderr).trim().to_string()
    }
}

/// Runs external commands. Secrets travel only through `stdin`, never in
/// `args`, so they cannot show up in the process list or in an error.
pub(crate) trait Runner {
    fn run(
        &self,
        program: &str,
        args: &[OsString],
        stdin: Option<&[u8]>,
    ) -> std::io::Result<Output>;
}

/// Runs commands on this host with captured output and a null or piped
/// standard input, so nothing can prompt on the terminal.
pub(crate) struct SystemRunner;

impl Runner for SystemRunner {
    fn run(
        &self,
        program: &str,
        args: &[OsString],
        stdin: Option<&[u8]>,
    ) -> std::io::Result<Output> {
        let mut child = std::process::Command::new(program)
            .args(args)
            .stdin(if stdin.is_some() {
                Stdio::piped()
            } else {
                Stdio::null()
            })
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?;
        let input = child.stdin.take();
        let (output, written) = std::thread::scope(|scope| {
            let writer = scope.spawn(move || -> std::io::Result<()> {
                if let (Some(mut pipe), Some(bytes)) = (input, stdin) {
                    pipe.write_all(bytes)?;
                }
                Ok(())
            });
            let output = child.wait_with_output();
            let written = writer
                .join()
                .unwrap_or_else(|_| Err(std::io::Error::other("stdin writer panicked")));
            (output, written)
        });
        let output = output?;
        // A child that exits without reading its input breaks the pipe; its
        // exit status is the better report then.
        if let Err(error) = written
            && output.status.success()
        {
            return Err(error);
        }
        Ok(Output {
            status: output.status.code(),
            stdout: output.stdout,
            stderr: output.stderr,
        })
    }
}

pub(crate) fn os_args<I, S>(args: I) -> Vec<OsString>
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    args.into_iter()
        .map(|arg| arg.as_ref().to_os_string())
        .collect()
}

/// A command line as the operator would type it.
pub(crate) fn display_command(program: &str, args: &[OsString]) -> String {
    let mut words = vec![shell_word(program)];
    words.extend(args.iter().map(|arg| shell_word(&arg.to_string_lossy())));
    words.join(" ")
}

/// Runs a command and describes a spawn failure.
pub(crate) fn run_command(
    runner: &dyn Runner,
    program: &str,
    args: &[OsString],
    stdin: Option<&[u8]>,
) -> Result<Output, String> {
    runner
        .run(program, args, stdin)
        .map_err(|error| format!("cannot run {}: {error}", display_command(program, args)))
}

pub(crate) fn failure(program: &str, args: &[OsString], output: &Output) -> String {
    let status = match output.status {
        Some(code) => format!("exit status {code}"),
        None => "terminated by a signal".to_string(),
    };
    let stderr = output.stderr_text();
    if stderr.is_empty() {
        format!("{} failed ({status})", display_command(program, args))
    } else {
        format!(
            "{} failed ({status}): {stderr}",
            display_command(program, args)
        )
    }
}

/// Runs a command that must succeed.
pub(crate) fn run_checked(
    runner: &dyn Runner,
    program: &str,
    args: &[OsString],
    stdin: Option<&[u8]>,
) -> Result<Output, String> {
    let output = run_command(runner, program, args, stdin)?;
    if output.success() {
        Ok(output)
    } else {
        Err(failure(program, args, &output))
    }
}

/// Quotes `text` for POSIX shells and fish when it holds anything beyond a
/// conservative set of path characters.
pub(crate) fn shell_word(text: &str) -> String {
    let plain = !text.is_empty()
        && text
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"/._-+@%:,=".contains(&byte));
    if plain {
        text.to_string()
    } else {
        format!("'{}'", text.replace('\'', "'\\''"))
    }
}

pub(crate) fn shell_path(path: &Path) -> String {
    shell_word(&path.to_string_lossy())
}

/// Atomically writes a configuration file that other users may read, such
/// as a LaunchAgent plist or a systemd unit.
pub(crate) fn write_public_file(path: &Path, bytes: &[u8]) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;
    crate::remote::write_private_file(path, bytes).map_err(|error| error.to_string())?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o644))
        .map_err(|error| format!("chmod 644 {}: {error}", path.display()))
}

/// Removes a file; `Ok(false)` when it did not exist.
pub(crate) fn remove_if_present(path: &Path) -> Result<bool, String> {
    match std::fs::remove_file(path) {
        Ok(()) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(format!("cannot remove {}: {error}", path.display())),
    }
}

/// The binary written into the plist or unit must stay where it is.
pub(crate) fn check_binary(binary: &Path) -> Result<String, String> {
    let text = binary
        .to_str()
        .ok_or_else(|| format!("binary path {} is not valid UTF-8", binary.display()))?;
    if !binary.is_absolute() {
        return Err(format!("binary path {text} must be absolute"));
    }
    if text.chars().any(char::is_control) {
        return Err(format!(
            "binary path {text:?} must not contain control characters"
        ));
    }
    Ok(text.to_string())
}

/// Warnings for a binary that a rebuild, `cargo clean` or a temp cleaner
/// would remove under the running service.
pub(crate) fn binary_warnings(binary: &Path, temp_dir: &Path) -> Vec<String> {
    let names: Vec<&OsStr> = binary
        .components()
        .filter_map(|component| match component {
            Component::Normal(name) => Some(name),
            _ => None,
        })
        .collect();
    let profile = |index: usize| {
        names
            .get(index)
            .is_some_and(|name| *name == "debug" || *name == "release")
    };
    let cargo_output = names
        .iter()
        .enumerate()
        .any(|(index, name)| *name == "target" && (profile(index + 1) || profile(index + 2)));
    let temp_roots = [
        temp_dir.to_path_buf(),
        std::fs::canonicalize(temp_dir).unwrap_or_else(|_| temp_dir.to_path_buf()),
        PathBuf::from("/tmp"),
        PathBuf::from("/private/tmp"),
        PathBuf::from("/var/tmp"),
        PathBuf::from("/var/folders"),
        PathBuf::from("/private/var/folders"),
    ];
    let temporary = temp_roots.iter().any(|root| binary.starts_with(root));
    let mut warnings = Vec::new();
    if cargo_output {
        warnings.push(format!(
            "warning: {} is a cargo build output; a rebuild or `cargo clean` breaks the service. Install zdrive (for example `cargo install --path . --locked`) and run `zdrive service install` from the installed binary",
            binary.display()
        ));
    }
    if temporary {
        warnings.push(format!(
            "warning: {} lives in a temporary directory that the system may clean; install zdrive to a permanent location and run `zdrive service install` from there",
            binary.display()
        ));
    }
    warnings
}

/// The canonical path of the running binary, as written into the plist or
/// the unit.
pub(crate) fn current_binary() -> Result<PathBuf, String> {
    let binary = std::env::current_exe()
        .map_err(|error| format!("cannot locate the zdrive binary: {error}"))?;
    std::fs::canonicalize(&binary)
        .map_err(|error| format!("cannot canonicalize {}: {error}", binary.display()))
}

/// State of one instance as its service manager reports it.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct ServiceStatus {
    pub(crate) name: String,
    /// The LaunchAgent plist exists, or the systemd instance is enabled.
    pub(crate) installed: bool,
    /// The job runs (launchd) or the unit is active and running (systemd).
    pub(crate) running: bool,
    /// launchd's `state`, or systemd's `ActiveState (SubState)`.
    pub(crate) state: String,
    pub(crate) pid: Option<u32>,
    pub(crate) last_exit_status: Option<i32>,
    /// launchd: how often the job was started.
    pub(crate) runs: Option<u32>,
    /// systemd: automatic restarts since the unit was started.
    pub(crate) restarts: Option<u32>,
    /// The installed plist or unit template was generated by an older
    /// zdrive; `service install` rewrites it.
    pub(crate) outdated: bool,
    /// The last refusal, or why its record cannot be read: the instance
    /// stays stopped until it is installed again.
    pub(crate) refusal: Option<Result<crate::refusal::Record, String>>,
}

impl ServiceStatus {
    /// What the operator has to do, one line each.
    pub(crate) fn advice(&self) -> Vec<String> {
        let mut lines = Vec::new();
        match &self.refusal {
            Some(Ok(record)) => lines.push(record.describe(&self.name)),
            Some(Err(error)) => lines.push(format!(
                "its last refusal cannot be read ({error}); `zdrive service install --name {}` clears it",
                self.name
            )),
            None => {}
        }
        if self.outdated {
            lines.push(format!(
                "its auto-start entry was generated by an older zdrive; run: zdrive service install --name {}",
                self.name
            ));
        }
        lines
    }

    pub(crate) fn summary(&self) -> String {
        let mut parts = vec![self.state.clone()];
        if let Some(pid) = self.pid {
            parts.push(format!("pid {pid}"));
        }
        if let Some(status) = self.last_exit_status {
            parts.push(format!("last exit status {status}"));
        }
        if let Some(runs) = self.runs {
            parts.push(format!("{runs} runs"));
        }
        if let Some(restarts) = self.restarts {
            parts.push(format!("{restarts} restarts"));
        }
        if !self.installed {
            parts.push("auto-start not installed".to_string());
        }
        format!("{}: {}", self.name, parts.join(", "))
    }
}

/// Installs and (re)starts auto-start for `def` with `binary` as the
/// program. The definition and its passphrase custody must already exist.
/// Returns the lines to show the operator.
pub(crate) fn install_on(
    host: &Host,
    def: &Definition,
    binary: &Path,
    runner: &dyn Runner,
) -> Result<Vec<String>, String> {
    def.validate()?;
    let binary_text = check_binary(binary)?;
    custody::ensure_ready(host, def)?;
    let mut lines = binary_warnings(binary, &std::env::temp_dir());
    lines.extend(cleared_refusal(host, &def.name)?);
    lines.extend(match host.platform {
        Platform::MacOs => launchd::install(host, def, &binary_text, runner)?,
        Platform::Linux => systemd::install(host, def, &binary_text, runner)?,
    });
    Ok(lines)
}

/// Removes the refusal record of `name`: installing or uninstalling is the
/// operator's answer to it.
fn cleared_refusal(host: &Host, name: &str) -> Result<Option<String>, String> {
    Ok(crate::refusal::clear(&host.paths, name)?
        .then(|| format!("cleared the last refusal of {name}")))
}

/// Stops an instance and removes its auto-start entry. `purge` also deletes
/// its definition and the passphrase custody zdrive manages for it; the
/// caller asks for confirmation first.
pub(crate) fn uninstall(
    name: &str,
    purge: bool,
    runner: &dyn Runner,
) -> Result<Vec<String>, String> {
    uninstall_on(&Host::from_env()?, name, purge, runner)
}

pub(crate) fn uninstall_on(
    host: &Host,
    name: &str,
    purge: bool,
    runner: &dyn Runner,
) -> Result<Vec<String>, String> {
    definition::validate_name(name)?;
    let mut lines = match host.platform {
        Platform::MacOs => launchd::uninstall(host, name, runner)?,
        Platform::Linux => systemd::uninstall(host, name, runner)?,
    };
    lines.extend(cleared_refusal(host, name)?);
    if purge {
        let own_passphrase_file = match Definition::load(&host.paths, name) {
            Ok(def) => match def.instance {
                definition::Instance::Encrypted {
                    custody: definition::Custody::File(path),
                    ..
                } if path != definition::managed_passphrase_path(&host.paths, name) => Some(path),
                _ => None,
            },
            Err(_) => None,
        };
        for path in [
            definition::definition_path(&host.paths, name),
            definition::managed_passphrase_path(&host.paths, name),
            definition::credential_path(&host.paths, name),
        ] {
            if remove_if_present(&path)? {
                lines.push(format!("deleted {}", path.display()));
            }
        }
        if let Some(path) = own_passphrase_file {
            lines.push(format!(
                "kept your passphrase file {}; delete it yourself if nothing else uses it",
                path.display()
            ));
        }
    } else {
        lines.push(format!(
            "kept the definition {}; `zdrive service install --name {name}` restores auto-start",
            definition::definition_path(&host.paths, name).display()
        ));
    }
    Ok(lines)
}

/// State of one instance.
pub(crate) fn status(name: &str, runner: &dyn Runner) -> Result<ServiceStatus, String> {
    status_on(&Host::from_env()?, name, runner)
}

pub(crate) fn status_on(
    host: &Host,
    name: &str,
    runner: &dyn Runner,
) -> Result<ServiceStatus, String> {
    definition::validate_name(name)?;
    let mut status = match host.platform {
        Platform::MacOs => launchd::status(host, name, runner),
        Platform::Linux => systemd::status(host, name, runner),
    }?;
    status.refusal = crate::refusal::read(&host.paths, name).transpose();
    Ok(status)
}

/// State of every defined instance, sorted by name. An instance whose state
/// cannot be read is reported as unknown instead of hiding the others.
pub(crate) fn list(paths: &Paths, runner: &dyn Runner) -> Vec<ServiceStatus> {
    match Host::with_paths(paths.clone()) {
        Ok(host) => list_on(&host, runner),
        Err(error) => definition::names(paths)
            .into_iter()
            .map(|name| ServiceStatus {
                name,
                state: format!("unknown ({error})"),
                ..ServiceStatus::default()
            })
            .collect(),
    }
}

pub(crate) fn list_on(host: &Host, runner: &dyn Runner) -> Vec<ServiceStatus> {
    definition::names(&host.paths)
        .into_iter()
        .map(|name| {
            status_on(host, &name, runner).unwrap_or_else(|error| ServiceStatus {
                name,
                state: format!("unknown ({error})"),
                ..ServiceStatus::default()
            })
        })
        .collect()
}

#[cfg(test)]
pub(crate) mod testing {
    use std::cell::RefCell;
    use std::ffi::OsString;
    use std::path::PathBuf;

    use super::{Host, Output, Platform, Runner};
    use crate::remote::TestDir;
    use crate::remote::config::Paths;

    type Respond = Box<dyn Fn(&str, Option<&[u8]>) -> std::io::Result<Output>>;

    /// Records every command and answers from a closure that sees the
    /// space-joined argument vector and the standard input.
    pub(crate) struct FakeRunner {
        calls: RefCell<Vec<(String, Option<Vec<u8>>)>>,
        respond: Respond,
    }

    impl FakeRunner {
        pub(crate) fn new(
            respond: impl Fn(&str, Option<&[u8]>) -> std::io::Result<Output> + 'static,
        ) -> Self {
            Self {
                calls: RefCell::new(Vec::new()),
                respond: Box::new(respond),
            }
        }

        pub(crate) fn succeeding() -> Self {
            Self::new(|_, _| ok(""))
        }

        pub(crate) fn argv(&self) -> Vec<String> {
            self.calls
                .borrow()
                .iter()
                .map(|(argv, _)| argv.clone())
                .collect()
        }

        pub(crate) fn stdin_of(&self, index: usize) -> Option<Vec<u8>> {
            self.calls.borrow()[index].1.clone()
        }
    }

    impl Runner for FakeRunner {
        fn run(
            &self,
            program: &str,
            args: &[OsString],
            stdin: Option<&[u8]>,
        ) -> std::io::Result<Output> {
            let mut argv = program.to_string();
            for arg in args {
                argv.push(' ');
                argv.push_str(&arg.to_string_lossy());
            }
            self.calls
                .borrow_mut()
                .push((argv.clone(), stdin.map(<[u8]>::to_vec)));
            (self.respond)(&argv, stdin)
        }
    }

    pub(crate) fn exit(status: i32, stdout: &str, stderr: &str) -> std::io::Result<Output> {
        Ok(Output {
            status: Some(status),
            stdout: stdout.as_bytes().to_vec(),
            stderr: stderr.as_bytes().to_vec(),
        })
    }

    pub(crate) fn ok(stdout: &str) -> std::io::Result<Output> {
        exit(0, stdout, "")
    }

    /// A host whose home, configuration and units all live in `dir`.
    pub(crate) fn host(dir: &TestDir, platform: Platform) -> Host {
        let root = dir.path().to_path_buf();
        Host {
            platform,
            paths: Paths {
                config: root.join("config").join("zerotrust-drive"),
                state: root.join("state").join("zerotrust-drive"),
                data: root.join("data").join("zerotrust-drive"),
            },
            home: root.join("home"),
            systemd_user_dir: root.join("config").join("systemd").join("user"),
            xdg_environment: Vec::new(),
            uid: 501,
            user: "alex".to_string(),
        }
    }

    pub(crate) fn absolute(dir: &TestDir, relative: &str) -> PathBuf {
        dir.path().join(relative)
    }

    /// A 0600 passphrase file in `dir`.
    pub(crate) fn secret_file(dir: &TestDir) -> PathBuf {
        let path = absolute(dir, "secret");
        crate::remote::write_private_file(&path, b"pass").expect("write the test secret");
        path
    }
}

#[cfg(test)]
mod tests {
    use super::testing::*;
    use super::*;
    use crate::remote::TestDir;
    use crate::service::definition::Instance;

    #[test]
    fn service_shell_words_quote_only_when_needed() {
        assert_eq!(shell_word("/usr/local/bin/zdrive"), "/usr/local/bin/zdrive");
        assert_eq!(shell_word("a b"), "'a b'");
        assert_eq!(shell_word("it's"), "'it'\\''s'");
        assert_eq!(shell_word(""), "''");
    }

    #[test]
    fn service_binary_warnings_flag_cargo_outputs_and_temp_dirs() {
        let temp = Path::new("/scratch/tmp");
        assert!(binary_warnings(Path::new("/usr/local/bin/zdrive"), temp).is_empty());
        assert!(binary_warnings(Path::new("/home/a/.cargo/bin/zdrive"), temp).is_empty());
        let debug = binary_warnings(Path::new("/src/zd/target/debug/zdrive"), temp);
        assert_eq!(debug.len(), 1);
        assert!(debug[0].contains("cargo build output"), "{debug:?}");
        let cross = binary_warnings(
            Path::new("/src/zd/target/x86_64-unknown-linux-gnu/release/zdrive"),
            temp,
        );
        assert_eq!(cross.len(), 1);
        let temporary = binary_warnings(Path::new("/scratch/tmp/zdrive"), temp);
        assert_eq!(temporary.len(), 1);
        assert!(
            temporary[0].contains("temporary directory"),
            "{temporary:?}"
        );
        assert_eq!(binary_warnings(Path::new("/tmp/zdrive"), temp).len(), 1);
    }

    #[test]
    fn service_binary_path_must_be_absolute_utf8_without_controls() {
        assert_eq!(
            check_binary(Path::new("/opt/zdrive")).as_deref(),
            Ok("/opt/zdrive")
        );
        assert!(check_binary(Path::new("zdrive")).is_err());
        assert!(check_binary(Path::new("/opt/z\ndrive")).is_err());
    }

    #[test]
    fn service_status_summary_names_every_known_detail() {
        let status = ServiceStatus {
            name: "home".to_string(),
            installed: true,
            running: true,
            state: "running".to_string(),
            pid: Some(42),
            last_exit_status: Some(0),
            runs: Some(3),
            restarts: None,
            outdated: false,
            refusal: None,
        };
        assert_eq!(
            status.summary(),
            "home: running, pid 42, last exit status 0, 3 runs"
        );
        assert!(status.advice().is_empty());
        let missing = ServiceStatus {
            name: "x".to_string(),
            state: "not loaded".to_string(),
            ..ServiceStatus::default()
        };
        assert_eq!(missing.summary(), "x: not loaded, auto-start not installed");
    }

    #[test]
    fn service_system_runner_pipes_stdin_and_captures_streams() {
        let output = SystemRunner
            .run(
                "/bin/sh",
                &os_args(["-c", "cat; echo err >&2; exit 3"]),
                Some(b"piped"),
            )
            .unwrap();
        assert_eq!(output.status, Some(3));
        assert_eq!(output.stdout, b"piped");
        assert_eq!(output.stderr_text(), "err");
        let missing = SystemRunner.run("/nonexistent/zdrive-test-binary", &[], None);
        assert_eq!(
            missing.unwrap_err().kind(),
            std::io::ErrorKind::NotFound,
            "a missing program is an io error, not an exit status"
        );
    }

    #[test]
    fn service_list_reports_every_definition_sorted() {
        let dir = TestDir::new("service-list");
        let host = host(&dir, Platform::Linux);
        for name in ["beta", "alpha"] {
            Definition {
                name: name.to_string(),
                instance: Instance::Plain {
                    remote: "home".to_string(),
                    local_dir: absolute(&dir, name),
                },
                final_push_wait_secs: 60,
            }
            .save(&host.paths)
            .unwrap();
        }
        let runner = FakeRunner::new(|argv, _| {
            if argv.contains("alpha") {
                ok(
                    "ActiveState=active\nSubState=running\nMainPID=7\nExecMainStatus=0\nNRestarts=1\n",
                )
            } else {
                exit(1, "", "Failed to connect to bus")
            }
        });
        let statuses = list_on(&host, &runner);
        assert_eq!(statuses.len(), 2);
        assert_eq!(statuses[0].name, "alpha");
        assert!(statuses[0].running);
        assert_eq!(statuses[1].name, "beta");
        assert!(
            statuses[1].state.starts_with("unknown ("),
            "{:?}",
            statuses[1]
        );
    }
}
