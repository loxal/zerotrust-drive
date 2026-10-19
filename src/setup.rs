// SPDX-FileCopyrightText: Copyright 2026 Alexander Orlov <info@lifub.com>

//! `zdrive setup`: one guided run from a fresh install to a signed-in,
//! synced drive that starts on its own. It orchestrates the existing
//! commands (`remote auth`, `remote pull|push`, `sync`, `service install`); every
//! question has a flag, so setup also runs unattended.

use std::os::unix::fs::DirBuilderExt;
use std::path::{Path, PathBuf};

use clap::Args;

use crate::fskit::BackendArg;
use crate::prompt::{self, PassphraseSource, Prompter, TerminalReader};
use crate::remote::cli::{self as remote_cli, Action, AuthArgs, RemoteStore, StoreArgs, StoreKind};
use crate::remote::config::{Paths, RemoteMode, RemoteName};
use crate::service::{self, cli as service_cli};
use crate::telemetry;

/// The shortest passphrase setup accepts for a new drive.
pub(crate) const MIN_NEW_PASSPHRASE_CHARS: usize = 12;
const DEFAULT_DIR: &str = "~/zdrive";

#[derive(Args, Debug, Default)]
pub(crate) struct SetupArgs {
    /// Name of the drive, used for its remote and its auto-start instance
    /// [default: "drive", or "plain" with --plain]
    #[arg(long)]
    name: Option<String>,

    /// Google account to sign in with, for example you@gmail.com
    #[arg(long, value_name = "EMAIL")]
    account: Option<String>,

    /// Store plain, unencrypted files that Google can read. The default
    /// encrypts every file on this computer before upload
    #[arg(long)]
    plain: bool,

    /// Where the drive appears: the mount point (encrypted) or the synced
    /// folder (plain) [default: ~/zdrive]
    #[arg(long, visible_alias = "mount", value_name = "DIR")]
    dir: Option<PathBuf>,

    /// Local encrypted store [default:
    /// ~/.local/share/zerotrust-drive/NAME/store]
    #[arg(long, value_name = "DIR", conflicts_with = "plain")]
    store: Option<PathBuf>,

    /// Name of the Drive folder created in My Drive when zdrive has none
    /// yet [default: "ZeroTrust Drive", or "ZeroTrust Drive (plain)"]
    #[arg(long, value_name = "NAME")]
    folder_name: Option<String>,

    /// Your own OAuth Desktop client JSON, for full Drive access instead of
    /// only the files zdrive creates
    #[arg(long, value_name = "FILE")]
    client_file: Option<PathBuf>,

    /// Sign in by entering a short code on Google's device page (the default
    /// over SSH and without a display)
    #[arg(long, conflicts_with = "no_browser")]
    device_code: bool,

    /// Print the consent address and read the redirected address back
    /// instead of opening a local browser
    #[arg(long)]
    no_browser: bool,

    /// Private file (mode 0600) holding the drive passphrase; auto-start
    /// then reads it from there
    #[arg(long, value_name = "FILE", conflicts_with = "plain")]
    passphrase_file: Option<PathBuf>,

    /// macOS: mount through macFUSE's kernel extension (kext) or its FSKit
    /// module (fskit) instead of deciding at every start (auto)
    #[arg(long, value_enum, value_name = "BACKEND", conflicts_with = "plain")]
    fuse_backend: Option<BackendArg>,

    /// Do not start the drive automatically at login (macOS) or boot (Linux)
    #[arg(long)]
    no_autostart: bool,

    /// Accept the shown plan without asking; required without a terminal
    #[arg(long)]
    yes: bool,
}

/// What setup will do, resolved before anything changes.
#[derive(Debug, PartialEq, Eq)]
struct Plan {
    name: RemoteName,
    mode: RemoteMode,
    account: Option<String>,
    /// Mount point (encrypted) or synced folder (plain).
    dir: PathBuf,
    /// Encrypted store; `None` in plain mode.
    store: Option<PathBuf>,
    fuse_backend: BackendArg,
    autostart: bool,
    /// Why auto-start was skipped although it was wanted.
    autostart_skipped: Option<String>,
}

/// The first transfer after sign-in.
#[derive(Debug, PartialEq, Eq)]
enum Initial {
    /// Replicate (or fast-forward to) the drive in Google Drive.
    Pull,
    /// Upload an existing local store into the empty Drive folder.
    Push,
    /// A brand-new drive: its first mount creates the store and uploads it.
    CreateOnMount,
}

pub(crate) fn run(args: SetupArgs) -> i32 {
    match setup(args) {
        Ok(lines) => {
            for line in lines {
                println!("{line}");
            }
            0
        }
        Err(message) => {
            eprintln!("zerotrust-drive: error: {message}");
            1
        }
    }
}

fn setup(args: SetupArgs) -> Result<Vec<String>, String> {
    let paths = Paths::from_env().map_err(|error| error.to_string())?;
    let mut terminal = TerminalReader::open();
    if !args.yes && terminal.is_none() {
        return Err(
            "setup confirms its plan on a terminal; without one, pass --yes (and --account EMAIL)"
                .to_string(),
        );
    }
    let mut plan = resolve_plan(&args, &paths, &|path| crate::expand_home_from_env(path))?;
    if plan.account.is_none()
        && !args.yes
        && let Some(terminal) = terminal.as_mut()
    {
        plan.account = ask_account(terminal)?;
    }
    if plan.mode == RemoteMode::Encrypted && plan.autostart {
        let (ready, detail) = crate::doctor::fuse_readiness();
        if !ready {
            plan.autostart = false;
            plan.autostart_skipped = Some(format!("FUSE is not ready: {detail}"));
        }
    }
    let telemetry = telemetry_notice(&paths);
    for line in describe(&plan, service::Platform::current()?) {
        remote_cli::note(&line);
    }
    if !args.yes {
        let terminal = terminal.as_mut().ok_or("no terminal to confirm on")?;
        if !confirm(terminal)? {
            return Err("setup cancelled; nothing was changed".to_string());
        }
    }

    let passphrase = match plan.mode {
        RemoteMode::Encrypted => Some(read_passphrase(
            args.passphrase_file.as_deref(),
            terminal
                .as_mut()
                .map(|terminal| terminal as &mut dyn Prompter),
        )?),
        RemoteMode::Plain => None,
    };
    create_private_dir(&plan.dir)?;
    if let Some(store) = &plan.store {
        create_private_dir(store)?;
    }
    if plan.mode == RemoteMode::Plain {
        // Refused before signing in rather than after.
        crate::plain::cli::local_folder(&plan.dir, &paths)?;
    }
    let existed = paths.remote_config(&plan.name).exists();

    let authorized = remote_cli::authorize(AuthArgs {
        remote: plan.name.as_str().to_string(),
        account: plan.account.clone(),
        plain: plan.mode == RemoteMode::Plain,
        folder_name: args.folder_name.clone(),
        client_file: args.client_file.clone(),
        device_code: args.device_code,
        no_browser: args.no_browser,
        passphrase: passphrase
            .as_ref()
            .map(|(passphrase, _)| passphrase.clone()),
        ..AuthArgs::default()
    })?;
    let mut lines = authorized.lines;

    if let (Some(store), Some((passphrase, _))) = (&plan.store, &passphrase) {
        let display = store.display().to_string();
        let local = remote_cli::inspect_store(store, &display)?;
        let remote = authorized
            .store
            .ok_or("an encrypted remote reported no store state")?;
        let step = initial_step(&remote, local, &plan.name, &display)?;
        let action = match step {
            Initial::Pull => Some(Action::Pull),
            Initial::Push => Some(Action::Push),
            Initial::CreateOnMount => {
                if let Err(error) = check_new_passphrase(passphrase) {
                    if !existed {
                        forget_remote(&paths, &plan.name);
                    }
                    return Err(error);
                }
                lines.push(
                    "a new drive: its first mount creates the encrypted store and uploads it"
                        .to_string(),
                );
                None
            }
        };
        if let Some(action) = action {
            let summary = remote_cli::store_command(
                StoreArgs {
                    remote: plan.name.as_str().to_string(),
                    encrypted_dir: store.clone(),
                    passphrase: Some(passphrase.clone()),
                    passphrase_file: None,
                },
                action,
            )?;
            lines.extend(summary.lines);
        }
    }
    if plan.mode == RemoteMode::Plain {
        let synced =
            crate::plain::cli::initial_sync(&paths, &plan.name, &plan.dir).map_err(|error| {
                let mut message = format!(
                    "remote {} is signed in, but the first sync failed: {error}",
                    plan.name
                );
                for line in manual_start(&plan) {
                    message.push_str("; ");
                    message.push_str(&line);
                }
                message
            })?;
        lines.extend(synced);
    }

    if plan.autostart {
        let host = service::Host::from_env()?;
        let install = install_args(&plan, args.passphrase_file.as_deref());
        let given = passphrase.map(|(passphrase, source)| (passphrase, source_label(source)));
        lines.extend(service_cli::install_with(
            &host,
            &install,
            given,
            &service::SystemRunner,
        )?);
    } else {
        lines.extend(manual_start(&plan));
    }
    lines.push(telemetry);
    Ok(lines)
}

/// Fills in every default and validates the names and paths.
fn resolve_plan(
    args: &SetupArgs,
    paths: &Paths,
    expand: &dyn Fn(&Path) -> Result<PathBuf, String>,
) -> Result<Plan, String> {
    let mode = if args.plain {
        RemoteMode::Plain
    } else {
        RemoteMode::Encrypted
    };
    let name = args.name.clone().unwrap_or_else(|| {
        match mode {
            RemoteMode::Encrypted => "drive",
            RemoteMode::Plain => "plain",
        }
        .to_string()
    });
    let name = RemoteName::parse(&name).map_err(|error| error.to_string())?;
    let absolute = |path: &Path, flag: &str| -> Result<PathBuf, String> {
        let path = expand(path)?;
        std::path::absolute(&path).map_err(|error| format!("--{flag} {}: {error}", path.display()))
    };
    let dir = absolute(
        args.dir
            .as_deref()
            .unwrap_or_else(|| Path::new(DEFAULT_DIR)),
        "dir",
    )?;
    let store = match mode {
        RemoteMode::Encrypted => {
            let store = match &args.store {
                Some(store) => absolute(store, "store")?,
                None => paths.data.join(name.as_str()).join("store"),
            };
            crate::ensure_disjoint_paths(&store, &dir)?;
            Some(store)
        }
        RemoteMode::Plain => None,
    };
    let account = args
        .account
        .as_deref()
        .map(str::trim)
        .filter(|account| !account.is_empty())
        .map(str::to_string);
    if let Some(account) = &account
        && !account.contains('@')
    {
        return Err(format!(
            "--account {account:?} is not an email address, for example you@gmail.com"
        ));
    }
    let fuse_backend = args.fuse_backend.unwrap_or_default();
    crate::fskit::check_platform(fuse_backend, cfg!(target_os = "macos"))?;
    Ok(Plan {
        name,
        mode,
        account,
        dir,
        store,
        fuse_backend,
        autostart: !args.no_autostart,
        autostart_skipped: None,
    })
}

/// The plan, as shown before anything changes.
fn describe(plan: &Plan, platform: service::Platform) -> Vec<String> {
    let mut lines = vec![format!("setting up drive {}:", plan.name)];
    lines.push(match plan.mode {
        RemoteMode::Encrypted => {
            "  storage:   encrypted on this computer; Google Drive receives only ciphertext"
                .to_string()
        }
        RemoteMode::Plain => {
            "  storage:   PLAIN - files are uploaded unencrypted, and Google can read every one"
                .to_string()
        }
    });
    lines.push(format!(
        "  account:   {}",
        plan.account
            .as_deref()
            .unwrap_or("the one you choose when signing in")
    ));
    match &plan.store {
        Some(store) => {
            lines.push(format!("  mount at:  {}", plan.dir.display()));
            lines.push(format!("  store:     {}", store.display()));
        }
        None => lines.push(format!("  folder:    {}", plan.dir.display())),
    }
    lines.push(format!(
        "  autostart: {}",
        match (&plan.autostart_skipped, plan.autostart) {
            (Some(reason), _) => format!("skipped ({reason})"),
            (None, false) => "no".to_string(),
            (None, true) => match platform {
                service::Platform::MacOs => "at login (LaunchAgent)".to_string(),
                service::Platform::Linux => "at boot (systemd user service)".to_string(),
            },
        }
    ));
    lines
}

fn ask_account(prompter: &mut dyn Prompter) -> Result<Option<String>, String> {
    let answer = prompter
        .read_visible(
            "zerotrust-drive: Google account (for example you@gmail.com; Enter to choose while signing in): ",
        )
        .map_err(|error| format!("cannot read the account: {error}"))?;
    let answer = answer.trim();
    if answer.is_empty() {
        return Ok(None);
    }
    if !answer.contains('@') {
        return Err(format!(
            "{answer:?} is not an email address, for example you@gmail.com"
        ));
    }
    Ok(Some(answer.to_string()))
}

fn confirm(prompter: &mut dyn Prompter) -> Result<bool, String> {
    let answer = prompter
        .read_visible("zerotrust-drive: continue? [Y/n] ")
        .map_err(|error| format!("cannot read the answer: {error}"))?;
    match answer.trim().to_ascii_lowercase().as_str() {
        "" | "y" | "yes" => Ok(true),
        "n" | "no" => Ok(false),
        other => Err(format!("unexpected answer {other:?}; nothing was changed")),
    }
}

/// The drive passphrase: a stored source first (`ZEROTRUST_PASSPHRASE`,
/// the systemd credential, `--passphrase-file`), else asked twice, because
/// a new drive is created with it.
fn read_passphrase(
    passphrase_file: Option<&Path>,
    prompter: Option<&mut dyn Prompter>,
) -> Result<(String, PassphraseSource), String> {
    let passphrase_file = passphrase_file
        .map(crate::expand_home_from_env)
        .transpose()?;
    let (passphrase, source) = match prompt::stored_passphrase(passphrase_file.as_deref())? {
        Some(stored) => stored,
        None => {
            let prompter = prompter.ok_or(
                "setup needs the drive passphrase: set ZEROTRUST_PASSPHRASE, pass --passphrase-file, or run from a terminal",
            )?;
            (ask_passphrase(prompter)?, PassphraseSource::Prompt)
        }
    };
    if crate::insecure_new_store_passphrase(&passphrase) {
        return Err(
            "refusing an empty or built-in demo passphrase: it would leave the drive effectively unencrypted"
                .to_string(),
        );
    }
    Ok((passphrase, source))
}

fn ask_passphrase(prompter: &mut dyn Prompter) -> Result<String, String> {
    let mut ask = |text: &str| {
        prompter
            .read_secret(text)
            .map_err(|error| format!("cannot read the passphrase from the terminal: {error}"))
    };
    let first = ask(&format!(
        "zerotrust-drive: drive passphrase (a new drive: choose one of at least {MIN_NEW_PASSPHRASE_CHARS} characters; an existing drive: its passphrase): "
    ))?;
    let second = ask("zerotrust-drive: repeat the passphrase: ")?;
    if first != second {
        return Err("the passphrases do not match; nothing was changed".to_string());
    }
    Ok(first)
}

fn check_new_passphrase(passphrase: &str) -> Result<(), String> {
    if passphrase.chars().count() < MIN_NEW_PASSPHRASE_CHARS {
        return Err(format!(
            "a new drive needs a passphrase of at least {MIN_NEW_PASSPHRASE_CHARS} characters; run setup again with a longer one"
        ));
    }
    Ok(())
}

/// Decides the first transfer from what Drive and the local store hold.
fn initial_step(
    remote: &RemoteStore,
    local: StoreKind,
    name: &RemoteName,
    display: &str,
) -> Result<Initial, String> {
    match (remote, local) {
        (_, StoreKind::V1) => Err(format!(
            "{display} is a v1 store; migrate it first with `zdrive --migrate-v2 --encrypted-dir {display}`"
        )),
        (RemoteStore::Unknown(error), _) => Err(format!(
            "remote {name} is signed in, but its Drive folder could not be read ({error}); run setup again when Drive is reachable"
        )),
        (RemoteStore::Present, _) => Ok(Initial::Pull),
        (RemoteStore::Absent, StoreKind::V2) => Ok(Initial::Push),
        (RemoteStore::Absent, StoreKind::Absent) => Ok(Initial::CreateOnMount),
        (RemoteStore::Absent, StoreKind::PendingBootstrap) => Err(format!(
            "{display} holds an interrupted first pull, but the Drive folder of remote {name} holds no store; empty {display} or choose another --store"
        )),
    }
}

fn source_label(source: PassphraseSource) -> &'static str {
    match source {
        PassphraseSource::Environment => "ZEROTRUST_PASSPHRASE",
        PassphraseSource::Credential => "the systemd credential",
        PassphraseSource::File => "the passphrase file",
        PassphraseSource::Argument | PassphraseSource::Prompt | PassphraseSource::Default => {
            "the setup prompt"
        }
    }
}

/// The `service install` request that matches the plan.
fn install_args(plan: &Plan, passphrase_file: Option<&Path>) -> service_cli::InstallArgs {
    let remote = Some(plan.name.as_str().to_string());
    match &plan.store {
        Some(store) => service_cli::InstallArgs {
            name: plan.name.as_str().to_string(),
            mode: Some(service_cli::ModeArg::Encrypted),
            remote,
            encrypted_dir: Some(store.clone()),
            mount_dir: Some(plan.dir.clone()),
            passphrase_file: passphrase_file.map(Path::to_path_buf),
            fuse_backend: (plan.fuse_backend != BackendArg::Auto).then_some(plan.fuse_backend),
            ..service_cli::InstallArgs::default()
        },
        None => service_cli::InstallArgs {
            name: plan.name.as_str().to_string(),
            mode: Some(service_cli::ModeArg::Plain),
            remote,
            local_dir: Some(plan.dir.clone()),
            ..service_cli::InstallArgs::default()
        },
    }
}

/// How to start the drive by hand, and how to add auto-start later.
fn manual_start(plan: &Plan) -> Vec<String> {
    let name = &plan.name;
    let dir = plan.dir.display();
    let mut lines = Vec::new();
    if let Some(reason) = &plan.autostart_skipped {
        lines.push(format!("auto-start was skipped: {reason}"));
    }
    match &plan.store {
        Some(store) => {
            let store = store.display();
            let backend = match plan.fuse_backend {
                BackendArg::Auto => String::new(),
                chosen => format!(" --fuse-backend {}", chosen.as_str()),
            };
            lines.push(format!(
                "start the drive with `zdrive --remote {name} --encrypted-dir {store} --decrypted-dir {dir}{backend}`"
            ));
            lines.push(format!(
                "or start it automatically with `zdrive service install --name {name} --mode encrypted --remote {name} --encrypted-dir {store} --mount-dir {dir}{backend}`"
            ));
        }
        None => {
            lines.push(format!(
                "keep the folder in sync with `zdrive sync --remote {name} --dir {dir} --watch`"
            ));
            lines.push(format!(
                "or sync it automatically with `zdrive service install --name {name} --mode plain --remote {name} --local-dir {dir}`"
            ));
        }
    }
    lines
}

fn telemetry_notice(paths: &Paths) -> String {
    let env = std::env::var(telemetry::ENV_VAR).ok();
    let dir = paths.state.join(telemetry::DIR_NAME);
    match telemetry::resolve_level(None, env.as_deref(), &paths.config) {
        Ok((telemetry::Level::Off, _)) => {
            "telemetry: off; turn the local-only diagnostics on with `zdrive telemetry on`"
                .to_string()
        }
        Ok((level, source)) => format!(
            "telemetry: {} ({}); recorded only on this computer in {}, never uploaded; turn it off with `zdrive telemetry off`",
            level.as_str(),
            source.describe(),
            dir.display()
        ),
        Err(error) => format!("telemetry: {error}"),
    }
}

/// Creates `path` and missing parents as 0700; existing directories keep
/// their mode.
fn create_private_dir(path: &Path) -> Result<(), String> {
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(path)
        .map_err(|error| format!("cannot create {}: {error}", path.display()))
}

/// Removes a remote configuration this run created, so a refused setup
/// leaves no half-configured remote behind.
fn forget_remote(paths: &Paths, name: &RemoteName) {
    let path = paths.remote_config(name);
    if let Err(error) = std::fs::remove_file(&path) {
        remote_cli::note(&format!("could not remove {}: {error}", path.display()));
    }
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::io;

    use super::*;
    use crate::prompt::SecretReader;

    struct Scripted(VecDeque<&'static str>);

    impl SecretReader for Scripted {
        fn read_secret(&mut self, _prompt: &str) -> io::Result<String> {
            self.0
                .pop_front()
                .map(str::to_string)
                .ok_or_else(|| io::Error::new(io::ErrorKind::UnexpectedEof, "no more answers"))
        }
    }

    impl Prompter for Scripted {
        fn read_visible(&mut self, prompt: &str) -> io::Result<String> {
            self.read_secret(prompt)
        }
    }

    fn scripted(answers: &[&'static str]) -> Scripted {
        Scripted(answers.iter().copied().collect())
    }

    fn paths() -> Paths {
        Paths {
            config: PathBuf::from("/home/u/.config/zerotrust-drive"),
            state: PathBuf::from("/home/u/.local/state/zerotrust-drive"),
            data: PathBuf::from("/home/u/.local/share/zerotrust-drive"),
        }
    }

    fn expand(path: &Path) -> Result<PathBuf, String> {
        crate::expand_home_path(path, Some(Path::new("/home/u")))
    }

    fn name(text: &str) -> RemoteName {
        RemoteName::parse(text).unwrap()
    }

    #[test]
    fn defaults_mount_encrypted_drive_at_zdrive_with_store_in_xdg_data() {
        let plan = resolve_plan(&SetupArgs::default(), &paths(), &expand).unwrap();
        assert_eq!(
            plan,
            Plan {
                name: name("drive"),
                mode: RemoteMode::Encrypted,
                account: None,
                dir: PathBuf::from("/home/u/zdrive"),
                store: Some(PathBuf::from(
                    "/home/u/.local/share/zerotrust-drive/drive/store"
                )),
                fuse_backend: BackendArg::Auto,
                autostart: true,
                autostart_skipped: None,
            }
        );
    }

    #[test]
    fn plain_defaults_have_no_store_and_their_own_name() {
        let args = SetupArgs {
            plain: true,
            account: Some(" you@example.com ".to_string()),
            no_autostart: true,
            ..SetupArgs::default()
        };
        let plan = resolve_plan(&args, &paths(), &expand).unwrap();
        assert_eq!(plan.name, name("plain"));
        assert_eq!(plan.mode, RemoteMode::Plain);
        assert_eq!(plan.store, None);
        assert_eq!(plan.account.as_deref(), Some("you@example.com"));
        assert!(!plan.autostart);
    }

    #[test]
    fn plan_refuses_bad_names_accounts_and_nested_paths() {
        let bad_name = SetupArgs {
            name: Some("My Drive".to_string()),
            ..SetupArgs::default()
        };
        assert!(resolve_plan(&bad_name, &paths(), &expand).is_err());
        let bad_account = SetupArgs {
            account: Some("nistem".to_string()),
            ..SetupArgs::default()
        };
        let error = resolve_plan(&bad_account, &paths(), &expand).unwrap_err();
        assert!(error.contains("not an email address"), "{error}");
        let nested = SetupArgs {
            dir: Some(PathBuf::from("~/zdrive")),
            store: Some(PathBuf::from("~/zdrive/store")),
            ..SetupArgs::default()
        };
        let error = resolve_plan(&nested, &paths(), &expand).unwrap_err();
        assert!(error.contains("separate, non-nested"), "{error}");
    }

    #[test]
    fn initial_step_pulls_an_existing_drive_and_creates_a_new_one_on_mount() {
        let n = name("drive");
        let step = |remote: RemoteStore, local| initial_step(&remote, local, &n, "/s");
        assert_eq!(
            step(RemoteStore::Present, StoreKind::Absent),
            Ok(Initial::Pull)
        );
        assert_eq!(step(RemoteStore::Present, StoreKind::V2), Ok(Initial::Pull));
        assert_eq!(
            step(RemoteStore::Present, StoreKind::PendingBootstrap),
            Ok(Initial::Pull)
        );
        assert_eq!(step(RemoteStore::Absent, StoreKind::V2), Ok(Initial::Push));
        assert_eq!(
            step(RemoteStore::Absent, StoreKind::Absent),
            Ok(Initial::CreateOnMount)
        );
        assert!(step(RemoteStore::Absent, StoreKind::PendingBootstrap).is_err());
        assert!(step(RemoteStore::Present, StoreKind::V1).is_err());
        let unknown = step(RemoteStore::Unknown("timeout".into()), StoreKind::Absent);
        assert!(unknown.unwrap_err().contains("timeout"));
    }

    #[test]
    fn new_drive_passphrase_needs_twelve_characters() {
        assert!(check_new_passphrase("short pass").is_err());
        assert!(check_new_passphrase("twelve chars").is_ok());
        // Characters, not bytes.
        assert!(check_new_passphrase("ääääääääääää").is_ok());
        assert!(check_new_passphrase("äääääääääää").is_err());
    }

    #[test]
    fn prompts_confirm_and_read_the_account() {
        assert_eq!(confirm(&mut scripted(&[""])), Ok(true));
        assert_eq!(confirm(&mut scripted(&["Yes"])), Ok(true));
        assert_eq!(confirm(&mut scripted(&["n"])), Ok(false));
        assert!(confirm(&mut scripted(&["maybe"])).is_err());
        assert_eq!(ask_account(&mut scripted(&[""])), Ok(None));
        assert_eq!(
            ask_account(&mut scripted(&[" you@example.com "])),
            Ok(Some("you@example.com".to_string()))
        );
        assert!(ask_account(&mut scripted(&["you"])).is_err());
    }

    #[test]
    fn typed_passphrase_must_match() {
        assert_eq!(
            ask_passphrase(&mut scripted(&["correct horse", "correct horse"])),
            Ok("correct horse".to_string())
        );
        let error = ask_passphrase(&mut scripted(&["one", "two"])).unwrap_err();
        assert!(error.contains("do not match"), "{error}");
    }

    #[test]
    fn plan_description_names_the_threat_model() {
        let plan = resolve_plan(&SetupArgs::default(), &paths(), &expand).unwrap();
        let lines = describe(&plan, service::Platform::Linux).join("\n");
        assert!(lines.contains("only ciphertext"), "{lines}");
        assert!(lines.contains("at boot (systemd user service)"), "{lines}");
        let plain = resolve_plan(
            &SetupArgs {
                plain: true,
                ..SetupArgs::default()
            },
            &paths(),
            &expand,
        )
        .unwrap();
        let lines = describe(&plain, service::Platform::MacOs).join("\n");
        assert!(lines.contains("Google can read every one"), "{lines}");
        assert!(lines.contains("at login (LaunchAgent)"), "{lines}");
    }

    #[test]
    fn install_args_match_the_service_contract() {
        let plan = resolve_plan(&SetupArgs::default(), &paths(), &expand).unwrap();
        let args = install_args(&plan, Some(Path::new("/home/u/pass")));
        assert_eq!(args.name, "drive");
        assert_eq!(args.mode, Some(service_cli::ModeArg::Encrypted));
        assert_eq!(args.remote.as_deref(), Some("drive"));
        assert_eq!(args.mount_dir, Some(PathBuf::from("/home/u/zdrive")));
        assert_eq!(args.passphrase_file, Some(PathBuf::from("/home/u/pass")));
        assert_eq!(args.custody, None);
        assert_eq!(args.fuse_backend, None, "auto is decided at every start");
        let pinned = SetupArgs {
            fuse_backend: Some(BackendArg::Fskit),
            ..SetupArgs::default()
        };
        let macos = cfg!(target_os = "macos");
        match resolve_plan(&pinned, &paths(), &expand) {
            Ok(plan) => {
                assert!(macos, "only macOS accepts a pinned backend");
                let args = install_args(&plan, None);
                assert_eq!(args.fuse_backend, Some(BackendArg::Fskit));
                let manual = manual_start(&plan).join("\n");
                assert_eq!(
                    manual.matches("--fuse-backend fskit`").count(),
                    2,
                    "{manual}"
                );
            }
            Err(error) => {
                assert!(!macos, "{error}");
                assert!(error.contains("applies only to macOS"), "{error}");
            }
        }
        let plain = resolve_plan(
            &SetupArgs {
                plain: true,
                ..SetupArgs::default()
            },
            &paths(),
            &expand,
        )
        .unwrap();
        let args = install_args(&plain, None);
        assert_eq!(args.mode, Some(service_cli::ModeArg::Plain));
        assert_eq!(args.local_dir, Some(PathBuf::from("/home/u/zdrive")));
        assert_eq!(args.encrypted_dir, None);
    }
}
