// SPDX-FileCopyrightText: Copyright 2026 Alexander Orlov <info@lifub.com>

//! `zdrive remote ...`: authorize a Google Drive folder, then replicate the
//! local encrypted v2 store to it and back. Google only receives ciphertext.
//!
//! The shell here resolves paths, takes the drive-operation lock, reads the
//! passphrase and builds the client; [`execute`] runs one command against an
//! injected [`Remote`], so tests drive it against the in-process fake.

use std::path::{Path, PathBuf};

use clap::{Args, Subcommand};

use crate::crypto::{KdfParams, RecoveryFingerprint, load_kdf_with_fingerprint, try_derive_key};
use crate::prompt::{self, PassphraseSource, SecretReader, TerminalReader};
use crate::v2::{self, V2NamespacePin, replica};

use super::config::{
    self, ClientKind, Issuer, Paths, RemoteConfig, RemoteMode, RemoteName, SCOPE_DRIVE, SealedToken,
};
use super::gdrive::{self, GoogleDrive, http_agent};
use super::oauth::{self, Consent, Endpoints, OAuthClient, RefreshTokenSource};
use super::state::RemoteState;
use super::sync::{
    self, LocalStore, PullOutcome, PullReport, PushReport, Relation, Remote, StatusReport,
    VerifyReport,
};
use super::{RemoteError, ensure_private_dir};

#[derive(Subcommand, Debug)]
pub(crate) enum RemoteCommand {
    /// Authorize Google Drive access for a remote and choose its folder
    Auth(AuthArgs),
    /// Upload the local head and every encrypted object it needs
    Push(StoreArgs),
    /// Fast-forward the local store to the remote head; an empty directory
    /// becomes a new replica
    Pull(StoreArgs),
    /// Compare the local and remote heads without changing either
    Status(StoreArgs),
    /// Audit the remote copy against the local replica
    Verify(VerifyArgs),
}

#[derive(Args, Debug, Default)]
pub(crate) struct AuthArgs {
    /// Remote name: 1-63 lowercase letters, digits, '-' or '_'
    #[arg(long)]
    pub(crate) remote: String,

    /// Google account to sign in with; zdrive suggests it to Google and
    /// refuses a sign-in with another account
    #[arg(long, value_name = "EMAIL")]
    pub(crate) account: Option<String>,

    /// Store plain, unencrypted files that Google can read. The default
    /// stores only ciphertext
    #[arg(long)]
    pub(crate) plain: bool,

    /// Name of the Drive folder zdrive creates in My Drive when none of its
    /// folders exists yet [default: "ZeroTrust Drive", or "ZeroTrust Drive
    /// (plain)" with --plain]
    #[arg(long, value_name = "NAME")]
    pub(crate) folder_name: Option<String>,

    /// Drive folder that holds the remote, for example a Computers folder.
    /// Defaults to the folder zdrive created, or to the folder of an
    /// already configured remote
    #[arg(long, value_name = "ID")]
    pub(crate) folder_id: Option<String>,

    /// Slash-separated folder path below --folder-id (or My Drive); missing
    /// folders are created and duplicate names are refused
    #[arg(long, value_name = "PATH")]
    pub(crate) folder_path: Option<String>,

    /// Your own OAuth Desktop client JSON from Google Cloud, which grants
    /// full Drive access instead of only the files zdrive creates
    #[arg(long, value_name = "FILE")]
    pub(crate) client_file: Option<PathBuf>,

    /// Sign in by entering a short code on Google's device page from any
    /// phone or computer (the default over SSH and without a display)
    #[arg(long, conflicts_with = "no_browser")]
    pub(crate) device_code: bool,

    /// Print the consent address and read the redirected address back
    /// instead of opening a local browser
    #[arg(long)]
    pub(crate) no_browser: bool,

    /// Store passphrase that seals the Google credential. Prefer the
    /// ZEROTRUST_PASSPHRASE env var, --passphrase-file or the prompt:
    /// arguments are visible in the process list
    #[arg(long)]
    pub(crate) passphrase: Option<String>,

    /// Private file (mode 0600) holding the store passphrase
    #[arg(long, value_name = "FILE")]
    pub(crate) passphrase_file: Option<PathBuf>,
}

#[derive(Args, Debug)]
pub(crate) struct StoreArgs {
    /// Remote name given to `zdrive remote auth`
    #[arg(long)]
    pub(crate) remote: String,

    /// Local encrypted v2 store. Keep it outside folders that a desktop sync
    /// client uploads; the API replication replaces that client
    #[arg(long)]
    pub(crate) encrypted_dir: PathBuf,

    /// Store passphrase. Prefer the ZEROTRUST_PASSPHRASE env var,
    /// --passphrase-file or the prompt: arguments are visible in the
    /// process list
    #[arg(long)]
    pub(crate) passphrase: Option<String>,

    /// Private file (mode 0600) holding the store passphrase
    #[arg(long, value_name = "FILE")]
    pub(crate) passphrase_file: Option<PathBuf>,
}

#[derive(Args, Debug)]
pub(crate) struct VerifyArgs {
    #[command(flatten)]
    store: StoreArgs,

    /// Also download every pack and check each object's digest
    #[arg(long)]
    full: bool,
}

/// One store command, after argument parsing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Action {
    Push,
    Pull,
    Status,
    Verify { full: bool },
}

/// What the local directory holds, judged before any key is derived.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum StoreKind {
    /// No store head: only a first pull may fill it.
    Absent,
    /// An interrupted first pull: only `pull` may continue it.
    PendingBootstrap,
    V1,
    V2,
}

/// Printed result of one command. `healthy` is false when the command ran
/// but found a state the operator must act on.
#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct Summary {
    pub(crate) lines: Vec<String>,
    pub(crate) healthy: bool,
}

/// Runs one `zdrive remote` command and returns the process exit status.
pub(crate) fn run(command: RemoteCommand) -> i32 {
    let outcome = match command {
        RemoteCommand::Auth(args) => auth(args).map(|lines| Summary {
            lines,
            healthy: true,
        }),
        RemoteCommand::Push(args) => store_command(args, Action::Push),
        RemoteCommand::Pull(args) => store_command(args, Action::Pull),
        RemoteCommand::Status(args) => store_command(args, Action::Status),
        RemoteCommand::Verify(args) => {
            store_command(args.store, Action::Verify { full: args.full })
        }
    };
    match outcome {
        Ok(summary) => {
            for line in &summary.lines {
                println!("{line}");
            }
            if summary.healthy { 0 } else { 1 }
        }
        Err(message) => {
            eprintln!("zerotrust-drive: error: {message}");
            1
        }
    }
}

pub(crate) fn note(message: &str) {
    eprintln!("zerotrust-drive: {message}");
}

/// Reads the store passphrase. Remote commands never fall back to the demo
/// passphrase: a credential sealed under it would be readable by anyone.
pub(crate) fn read_passphrase(
    argument: Option<String>,
    passphrase_file: Option<&Path>,
    terminal: Option<&mut TerminalReader>,
    confirm: bool,
) -> Result<String, String> {
    let passphrase_file = passphrase_file
        .map(crate::expand_home_from_env)
        .transpose()?;
    let (passphrase, source) = prompt::resolve_current(
        prompt::stored_passphrase(passphrase_file.as_deref())?,
        argument,
        terminal.map(|terminal| terminal as &mut dyn SecretReader),
        false,
        confirm,
        crate::DEMO_PASSPHRASE,
    )?;
    if source == PassphraseSource::Default {
        return Err(
            "remote commands need the store passphrase: set ZEROTRUST_PASSPHRASE, pass --passphrase-file, or run from a terminal to be prompted"
                .to_string(),
        );
    }
    if crate::insecure_new_store_passphrase(&passphrase) {
        return Err(
            "refusing an empty or built-in demo passphrase: it would leave the store and its Google credential effectively unencrypted"
                .to_string(),
        );
    }
    Ok(passphrase)
}

/// How the user approves access.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Flow {
    /// Loopback redirect to a local browser.
    Browser,
    /// The consent address is printed and the redirected one pasted back.
    Paste,
    /// A short code entered on Google's device page.
    Device,
}

/// What `remote auth` was asked for, before any network access.
#[derive(Debug, Default)]
pub(crate) struct ClientChoice<'a> {
    /// Canonical `--client-file`.
    pub(crate) client_file: Option<PathBuf>,
    /// The issuer of an already configured remote.
    pub(crate) existing: Option<&'a Issuer>,
    pub(crate) device_code: bool,
    pub(crate) no_browser: bool,
    /// No usable local browser (SSH or a Linux host without a display).
    pub(crate) headless: bool,
    /// Bundled (desktop, device) clients in this build.
    pub(crate) bundled: (bool, bool),
    /// The 0.17 default client file, when it exists.
    pub(crate) default_client_file: Option<PathBuf>,
}

/// Picks the OAuth client and the consent flow. A configured remote that
/// uses its own client keeps it, because its folder may lie outside what
/// the bundled `drive.file` client can see.
pub(crate) fn choose_client(choice: ClientChoice<'_>) -> Result<(Issuer, Flow), String> {
    let browser = if choice.no_browser {
        Flow::Paste
    } else {
        Flow::Browser
    };
    let byo_file = choice.client_file.or_else(|| {
        choice
            .existing
            .filter(|issuer| issuer.client == ClientKind::Byo)
            .and_then(|issuer| issuer.client_file.clone())
    });
    if let Some(file) = byo_file {
        if choice.device_code {
            return Err(
                "--device-code signs in with the bundled client; your own OAuth client signs in through a browser (use --no-browser on a host without one)"
                    .to_string(),
            );
        }
        return Ok((Issuer::byo(&file), browser));
    }
    let (desktop, device) = choice.bundled;
    let wants_device = choice.device_code || (choice.headless && !choice.no_browser);
    if wants_device && device {
        return Ok((Issuer::bundled(ClientKind::BundledDevice), Flow::Device));
    }
    if choice.device_code {
        return Err(oauth::missing_bundled_client(ClientKind::BundledDevice).to_string());
    }
    // Without a device client, a headless host pastes the redirect back.
    let flow = if wants_device { Flow::Paste } else { browser };
    if desktop {
        return Ok((Issuer::bundled(ClientKind::BundledDesktop), flow));
    }
    match choice.default_client_file {
        Some(file) => Ok((Issuer::byo(&file), flow)),
        None => Err(oauth::missing_bundled_client(ClientKind::BundledDesktop).to_string()),
    }
}

/// Where the remote lives in Drive.
enum FolderChoice {
    /// The folder zdrive marked, created on first use.
    Marked { marker: &'static str, name: String },
    /// `path` below the folder `parent`.
    Path { parent: String, path: String },
}

/// What the Drive folder of a freshly authorized encrypted remote holds.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum RemoteStore {
    Present,
    Absent,
    /// The folder could not be inspected.
    Unknown(String),
}

/// One completed authorization.
#[derive(Debug)]
pub(crate) struct Authorized {
    pub(crate) lines: Vec<String>,
    /// `None` for a plain remote.
    pub(crate) store: Option<RemoteStore>,
}

/// One `remote auth` run.
fn auth(args: AuthArgs) -> Result<Vec<String>, String> {
    let name = args.remote.clone();
    let mut authorized = authorize(args)?;
    match authorized.store {
        None => authorized.lines.push(format!(
            "sync a local folder with `zdrive sync --remote {name} --dir DIR`"
        )),
        Some(RemoteStore::Present) => authorized.lines.push(format!(
            "the folder holds a zerotrust-drive store: run `zdrive remote pull --remote {name} --encrypted-dir DIR` with an empty DIR to replicate it"
        )),
        Some(RemoteStore::Absent) => authorized.lines.push(format!(
            "the folder holds no store yet: `zdrive remote push --remote {name} --encrypted-dir DIR` creates it"
        )),
        Some(RemoteStore::Unknown(error)) => authorized
            .lines
            .push(format!("could not inspect the folder yet: {error}")),
    }
    Ok(authorized.lines)
}

/// Signs in, chooses the Drive folder and saves the remote configuration.
pub(crate) fn authorize(args: AuthArgs) -> Result<Authorized, String> {
    let paths = Paths::from_env().map_err(|error| error.to_string())?;
    let name = RemoteName::parse(&args.remote).map_err(|error| error.to_string())?;
    let existing = match RemoteConfig::load(&paths, &name) {
        Ok(config) => Some(config),
        Err(RemoteError::NotFound(_)) => None,
        Err(error) => return Err(error.to_string()),
    };
    let mode = if args.plain {
        RemoteMode::Plain
    } else {
        RemoteMode::Encrypted
    };
    if let Some(config) = &existing
        && config.mode != mode
    {
        return Err(match config.mode {
            RemoteMode::Plain => {
                format!("remote {name} is a plain remote; pass --plain to re-authorize it")
            }
            RemoteMode::Encrypted => format!(
                "remote {name} is an encrypted remote; choose another remote name for plain storage"
            ),
        });
    }
    let client_file = args
        .client_file
        .as_deref()
        .map(canonical_client_file)
        .transpose()?;
    let default_client_file = paths.default_client_file();
    let existing_issuer = existing.as_ref().map(RemoteConfig::issuer);
    let (issuer, flow) = choose_client(ClientChoice {
        client_file,
        existing: existing_issuer.as_ref(),
        device_code: args.device_code,
        no_browser: args.no_browser,
        headless: oauth::prefers_device_flow(|name| std::env::var_os(name)),
        bundled: oauth::bundled_available(),
        default_client_file: std::fs::canonicalize(&default_client_file).ok(),
    })?;
    let client = oauth::client_for(&issuer).map_err(|error| error.to_string())?;
    let marker = match mode {
        RemoteMode::Encrypted => gdrive::STORE_MARKER,
        RemoteMode::Plain => gdrive::PLAIN_MARKER,
    };
    let folder_choice = match (args.folder_id, args.folder_path, &existing) {
        (None, None, Some(config)) => FolderChoice::Path {
            parent: config.folder_id.clone(),
            path: String::new(),
        },
        (None, None, None) => FolderChoice::Marked {
            marker,
            name: args.folder_name.unwrap_or_else(|| {
                match mode {
                    RemoteMode::Encrypted => "ZeroTrust Drive",
                    RemoteMode::Plain => "ZeroTrust Drive (plain)",
                }
                .to_string()
            }),
        },
        (id, path, _) => FolderChoice::Path {
            parent: id.unwrap_or_else(|| gdrive::MY_DRIVE.to_string()),
            path: path.unwrap_or_default(),
        },
    };
    if let FolderChoice::Marked { name: folder, .. } = &folder_choice
        && (folder.is_empty() || folder.len() > 255 || folder.contains(['/', '\n', '\r']))
    {
        return Err(format!(
            "--folder-name {folder:?} must be 1-255 characters without '/' or line breaks"
        ));
    }

    let mut terminal = TerminalReader::open();
    let passphrase = match mode {
        RemoteMode::Encrypted => Some(read_passphrase(
            args.passphrase,
            args.passphrase_file.as_deref(),
            terminal.as_mut(),
            true,
        )?),
        RemoteMode::Plain => {
            note("plain mode: files are stored unencrypted, and Google can read every one of them");
            None
        }
    };
    let wanted_account = args
        .account
        .as_deref()
        .map(str::trim)
        .filter(|account| !account.is_empty());
    let login_hint =
        wanted_account.or_else(|| existing.as_ref().map(|config| config.account.as_str()));
    let agent = http_agent();
    let endpoints = Endpoints::google();
    let mut stderr = std::io::stderr();
    let authorization = match flow {
        Flow::Device => oauth::authorize_device(
            &agent,
            &client,
            &endpoints,
            &issuer.scope,
            &mut stderr,
            &std::thread::sleep,
        ),
        Flow::Browser | Flow::Paste => {
            let consent = if flow == Flow::Paste {
                let reader = terminal.as_mut().ok_or(
                    "pasting the redirected address needs a terminal; run from one, or sign in with --device-code",
                )?;
                Consent::Paste(reader)
            } else {
                Consent::Loopback {
                    open: &oauth::open_in_browser,
                    timeout: oauth::CONSENT_TIMEOUT,
                }
            };
            oauth::authorize(
                &agent,
                &client,
                &endpoints,
                &issuer.scope,
                login_hint,
                consent,
                &mut stderr,
            )
        }
    }
    .map_err(|error| error.to_string())?;
    let refresh_token = authorization.refresh_token;
    let drive = GoogleDrive::new(Box::new(RefreshTokenSource::new(
        client,
        refresh_token.clone(),
        &endpoints,
    )));
    let account = drive.about().map_err(|error| error.to_string())?;
    if let Some(wanted) = wanted_account
        && !wanted.eq_ignore_ascii_case(&account.email)
    {
        return Err(format!(
            "you signed in as {}, not {wanted}; run the sign-in again and choose {wanted}",
            account.email
        ));
    }
    if let Some(config) = &existing
        && config.account != account.email
    {
        note(&format!(
            "remote {name} was authorized for {} and is now authorized for {}",
            config.account, account.email
        ));
    }
    let (folder, hint) = choose_folder(&drive, mode, folder_choice, issuer.client.bundled())?;
    if let Some(config) = &existing
        && config.folder_id != folder.id
    {
        note(&format!(
            "remote {name} moves from folder {} to {hint}; its local sync state starts over",
            config.folder_hint
        ));
    }
    let config = match &passphrase {
        Some(passphrase) => {
            let token =
                SealedToken::seal(&name, passphrase, &refresh_token, KdfParams::new_random())
                    .map_err(|error| error.to_string())?;
            RemoteConfig::encrypted(&name, &account.email, &folder.id, &hint, &issuer, token)
        }
        None => {
            config::save_plain_token(&paths, &name, &refresh_token)
                .map_err(|error| error.to_string())?;
            RemoteConfig::plain(&name, &account.email, &folder.id, &hint, &issuer)
        }
    };
    config.save(&paths).map_err(|error| error.to_string())?;

    let mut lines = vec![
        format!(
            "remote {name}: authorized for {} ({}, {})",
            account.email,
            mode.as_str(),
            access_label(&issuer)
        ),
        format!("folder: {hint} (id {})", folder.id),
    ];
    if let (Some(limit), Some(usage)) = (account.limit, account.usage) {
        lines.push(format!("storage: {} used of {}", size(usage), size(limit)));
    }
    if mode == RemoteMode::Plain {
        return Ok(Authorized { lines, store: None });
    }
    let remote = Remote {
        drive: &drive,
        folder_id: &folder.id,
        log: &note,
    };
    let store = match sync::remote_kdf(&remote) {
        Ok(_) => RemoteStore::Present,
        Err(RemoteError::NotFound(_)) => RemoteStore::Absent,
        Err(error) => RemoteStore::Unknown(error.to_string()),
    };
    Ok(Authorized {
        lines,
        store: Some(store),
    })
}

/// Resolves the Drive folder of a remote being authorized; a plain remote
/// always ends in a folder carrying the plain sync marker.
fn choose_folder(
    drive: &GoogleDrive,
    mode: RemoteMode,
    choice: FolderChoice,
    bundled: bool,
) -> Result<(gdrive::DriveFile, String), String> {
    let (folder, hint) = match choice {
        FolderChoice::Marked {
            marker,
            name: folder_name,
        } => {
            let (folder, created) = match mode {
                RemoteMode::Encrypted => drive
                    .find_or_create_marked_folder(marker, &folder_name)
                    .map_err(|error| error.to_string())?,
                RemoteMode::Plain => plain_folder(crate::plain::find_or_create_folder(
                    drive,
                    gdrive::MY_DRIVE,
                    &folder_name,
                ))?,
            };
            note(&if created {
                format!("created the Drive folder \"{}\" in My Drive", folder.name)
            } else {
                format!("joining the existing Drive folder \"{}\"", folder.name)
            });
            let hint = folder.name.clone();
            (folder, hint)
        }
        FolderChoice::Path { parent, path } => {
            let parent_folder = drive.folder(&parent).map_err(|error| match error {
                RemoteError::NotFound(_) if bundled => format!(
                    "Drive folder {parent} is not visible to zdrive: the bundled sign-in sees only folders zdrive created; omit --folder-id, or use your own client with --client-file"
                ),
                error => error.to_string(),
            })?;
            let trimmed = path.trim_matches('/');
            let folder = match mode {
                RemoteMode::Plain if !trimmed.is_empty() => {
                    let (prefix, last) = trimmed.rsplit_once('/').unwrap_or(("", trimmed));
                    let container = drive
                        .resolve_folder_path(&parent, prefix, true)
                        .map_err(|error| error.to_string())?;
                    plain_folder(crate::plain::find_or_create_child_folder(
                        drive,
                        &container.id,
                        last,
                    ))?
                    .0
                }
                _ => drive
                    .resolve_folder_path(&parent, &path, true)
                    .map_err(|error| error.to_string())?,
            };
            if parent_folder.trashed {
                return Err(format!(
                    "the folder {} is in the Drive trash; restore it or choose another",
                    parent_folder.name
                ));
            }
            (folder, folder_hint(&parent_folder.name, &path))
        }
    };
    if folder.trashed {
        return Err(format!(
            "the folder {} is in the Drive trash; restore it or choose another",
            folder.name
        ));
    }
    if mode == RemoteMode::Plain {
        // The sync engine refuses an unmarked folder; never save a remote
        // whose first sync would fail.
        crate::plain::check_marker(&folder).map_err(|error| {
            format!("{error}; pass --folder-path NAME to let zdrive create a plain folder there")
        })?;
    }
    Ok((folder, hint))
}

/// The plain-marked folder chosen by `lookup`; true when it was created.
fn plain_folder(
    lookup: Result<crate::plain::FolderChoice, String>,
) -> Result<(gdrive::DriveFile, bool), String> {
    Ok(match lookup? {
        crate::plain::FolderChoice::Created(folder) => (folder, true),
        crate::plain::FolderChoice::Existing(folder) => (folder, false),
    })
}

fn canonical_client_file(path: &Path) -> Result<PathBuf, String> {
    let path = crate::expand_home_from_env(path)?;
    std::fs::canonicalize(&path).map_err(|error| {
        format!(
            "cannot open the OAuth client file {}: {error}; download the Desktop client JSON from Google Cloud and save it there with mode 0600",
            path.display()
        )
    })
}

/// What the credential can reach, for status lines.
pub(crate) fn access_label(issuer: &Issuer) -> &'static str {
    if issuer.scope == SCOPE_DRIVE {
        "full Drive access"
    } else {
        "access to files zdrive creates"
    }
}

fn folder_hint(parent: &str, path: &str) -> String {
    let path = path.trim_matches('/');
    if path.is_empty() {
        parent.to_string()
    } else {
        format!("{parent}/{path}")
    }
}

pub(crate) fn store_command(args: StoreArgs, action: Action) -> Result<Summary, String> {
    let paths = Paths::from_env().map_err(|error| error.to_string())?;
    let name = RemoteName::parse(&args.remote).map_err(|error| error.to_string())?;
    let expanded = crate::expand_home_from_env(&args.encrypted_dir)?;
    let canonical = if action == Action::Pull {
        crate::create_and_canonicalize(&expanded, "encrypted storage directory")?
    } else {
        std::fs::canonicalize(&expanded).map_err(|error| {
            format!(
                "cannot open the encrypted storage directory {}: {error}",
                expanded.display()
            )
        })?
    };
    // The same lock a mount holds: a mounted store is never replicated
    // underneath its own process.
    let lock = crate::DriveOperationLock::acquire(&canonical)?;
    lock.anchor_process_working_directory()?;
    let base = Path::new(".");
    let display = canonical.display().to_string();
    let kind = inspect_store(base, &display)?;
    admit(action, kind, &name, &display).map_err(|error| error.to_string())?;

    let config = RemoteConfig::load(&paths, &name).map_err(|error| error.to_string())?;
    if config.mode != RemoteMode::Encrypted {
        return Err(format!(
            "remote {name} stores plain files; sync it with `zdrive sync --remote {name} --dir DIR`"
        ));
    }
    let client = oauth::client_for(&config.issuer()).map_err(|error| error.to_string())?;
    let mut terminal = TerminalReader::open();
    let passphrase = read_passphrase(
        args.passphrase,
        args.passphrase_file.as_deref(),
        terminal.as_mut(),
        false,
    )?;
    let drive = open_drive(client, &paths, &config, &name, Some(&passphrase))?;
    let remote = Remote {
        drive: &drive,
        folder_id: &config.folder_id,
        log: &note,
    };
    let state_dir = replica_state(&paths, &name, &canonical)?;
    lock.revalidate()?;
    let mut summary = execute(
        action,
        kind,
        &remote,
        base,
        &display,
        &passphrase,
        &state_dir,
    )
    .map_err(|error| error.to_string())?;
    summary.lines.insert(
        0,
        format!("remote {name}: {} -> {display}", config.folder_hint),
    );
    Ok(summary)
}

/// The Drive client of a configured remote, with its credential unsealed
/// by the store passphrase (encrypted) or read from its token file (plain).
pub(crate) fn open_drive(
    client: OAuthClient,
    paths: &Paths,
    config: &RemoteConfig,
    name: &RemoteName,
    passphrase: Option<&str>,
) -> Result<GoogleDrive, String> {
    let refresh_token = config
        .refresh_token(paths, name, passphrase)
        .map_err(|error| error.to_string())?;
    Ok(GoogleDrive::new(Box::new(RefreshTokenSource::new(
        client,
        refresh_token,
        &Endpoints::google(),
    ))))
}

/// The private sync-state directory of one local replica of `name`.
pub(crate) fn replica_state(
    paths: &Paths,
    name: &RemoteName,
    canonical: &Path,
) -> Result<PathBuf, String> {
    for dir in [
        paths.state.clone(),
        paths.state.join("remotes"),
        paths.remote_state(name),
    ] {
        ensure_private_dir(&dir).map_err(|error| error.to_string())?;
    }
    Ok(paths.replica_state(name, canonical))
}

/// Refuses every directory a remote command must not touch, before any
/// passphrase is read. The local guards match those of offline GC.
pub(crate) fn inspect_store(base: &Path, display: &str) -> Result<StoreKind, String> {
    // A half-filled first pull holds objects but no head; the store guards
    // below would misjudge it.
    if sync::bootstrap_pending(base).map_err(|error| error.to_string())? {
        return Ok(StoreKind::PendingBootstrap);
    }
    crate::fs::ensure_no_index_siblings(base).map_err(|error| error.to_string())?;
    crate::fs::ensure_unambiguous_format_heads(base).map_err(|error| error.to_string())?;
    crate::fs::ensure_v2_controls_have_kdf(base)?;
    crate::ensure_recovery_manifest_cleared(base, "_rekey.manifest")?;
    crate::ensure_recovery_manifest_cleared(base, "_migrate.manifest")?;
    for lock_name in ["_rekey.lock", "_migrate.lock"] {
        if crate::fs::backing_entry_exists(&base.join(lock_name))
            .map_err(|error| format!("inspect {lock_name}: {error}"))?
        {
            return Err(format!(
                "{lock_name} exists in {display}; finish the rekey or migration before replicating"
            ));
        }
    }
    if crate::v2_migrate::migration_pending(base)? {
        return Err(format!(
            "a v1-to-v2 migration of {display} is pending; resume it with --migrate-v2 first"
        ));
    }
    let exists = |name: &str| {
        crate::fs::backing_entry_exists(&base.join(name))
            .map_err(|error| format!("inspect {name}: {error}"))
    };
    if exists(v2::ROOT_FILE)? {
        Ok(StoreKind::V2)
    } else if exists("_index.age")? {
        Ok(StoreKind::V1)
    } else {
        Ok(StoreKind::Absent)
    }
}

fn admit(
    action: Action,
    kind: StoreKind,
    name: &RemoteName,
    display: &str,
) -> Result<(), RemoteError> {
    match (action, kind) {
        (_, StoreKind::V1) => Err(RemoteError::Local(format!(
            "{display} is a v1 store; replication needs v2: run `zdrive --migrate-v2 --encrypted-dir {display}` first"
        ))),
        (Action::Pull, _) | (_, StoreKind::V2) => Ok(()),
        (_, StoreKind::PendingBootstrap) => Err(RemoteError::Local(format!(
            "an interrupted first pull left {display} incomplete; finish it with `zdrive remote pull --remote {name} --encrypted-dir {display}`"
        ))),
        (_, StoreKind::Absent) => Err(RemoteError::Local(format!(
            "{display} holds no v2 store; mount it once to create one, or pull into an empty directory"
        ))),
    }
}

/// Runs one admitted command with the drive-operation lock held.
pub(crate) fn execute(
    action: Action,
    kind: StoreKind,
    remote: &Remote<'_>,
    base: &Path,
    display: &str,
    passphrase: &str,
    state_dir: &Path,
) -> Result<Summary, RemoteError> {
    if kind != StoreKind::V2 {
        if action != Action::Pull {
            return Err(RemoteError::Local(format!("{display} holds no v2 store")));
        }
        return bootstrap(remote, base, display, passphrase, state_dir);
    }
    let (kdf, fingerprint) = load_kdf_with_fingerprint(base)
        .map_err(RemoteError::Local)?
        .ok_or_else(|| RemoteError::Local(format!("{display} has a v2 root but no _kdf.json")))?;
    // The exact bytes the fingerprint authenticated, not a second read.
    let kdf_bytes = match &fingerprint {
        RecoveryFingerprint::Exact { bytes } => bytes.clone(),
        RecoveryFingerprint::Ciphertext { .. } => {
            return Err(RemoteError::Local(
                "_kdf.json has an unexpected fingerprint kind".to_string(),
            ));
        }
    };
    let key = try_derive_key(passphrase, &kdf).map_err(RemoteError::Local)?;
    let root = replica::read_root_bytes(base)?
        .ok_or_else(|| RemoteError::Local(format!("{display} lost its v2 root")))?;
    replica::decode_root(&key, &root).map_err(|_| {
        RemoteError::Auth(format!(
            "wrong passphrase: it does not open the v2 root of {display}"
        ))
    })?;
    let pin = V2NamespacePin::capture(base)?;
    v2::recover_with_namespace_pin(base, &key, &fingerprint, &pin)?;
    let local = LocalStore {
        base,
        key: &key,
        kdf_bytes: &kdf_bytes,
        kdf_fingerprint: &fingerprint,
        pin: &pin,
        display,
    };
    let mut state = RemoteState::open(state_dir, remote.folder_id)?;
    Ok(match action {
        Action::Push => push_summary(&sync::push(remote, &local, &mut state)?),
        Action::Pull => pull_summary(&sync::pull(remote, &local, &mut state)?),
        Action::Status => status_summary(&sync::status(remote, &local, &mut state)?),
        Action::Verify { full } => verify_summary(&sync::verify(remote, &local, &state, full)?),
    })
}

/// Fills an empty directory, or finishes an interrupted fill, from the
/// remote head. The remote key material decides the key.
fn bootstrap(
    remote: &Remote<'_>,
    base: &Path,
    display: &str,
    passphrase: &str,
    state_dir: &Path,
) -> Result<Summary, RemoteError> {
    let remote_kdf = sync::remote_kdf(remote)?;
    let kdf: KdfParams = serde_json::from_slice(&remote_kdf.bytes).map_err(|error| {
        RemoteError::Integrity(format!("the remote _kdf.json is malformed: {error}"))
    })?;
    let key = try_derive_key(passphrase, &kdf).map_err(|error| {
        RemoteError::Integrity(format!("the remote _kdf.json is unusable: {error}"))
    })?;
    let mut state = RemoteState::open(state_dir, remote.folder_id)?;
    let report = sync::bootstrap(remote, base, display, &key, &remote_kdf, &mut state)?;
    Ok(pull_summary(&report))
}

pub(crate) fn size(bytes: u64) -> String {
    const MIB: u64 = 1 << 20;
    const GIB: u64 = 1 << 30;
    if bytes >= GIB {
        format!("{:.2} GiB", bytes as f64 / GIB as f64)
    } else if bytes >= MIB {
        format!("{:.1} MiB", bytes as f64 / MIB as f64)
    } else {
        format!("{bytes} bytes")
    }
}

pub(crate) fn transfer(generations: usize, objects: usize, packs: usize, bytes: u64) -> String {
    format!(
        "{generations} generation(s), {objects} object(s) in {packs} pack(s), {}",
        size(bytes)
    )
}

fn generation(number: Option<u64>) -> String {
    number.map_or_else(|| "none".to_string(), |number| number.to_string())
}

pub(crate) fn push_summary(report: &PushReport) -> Summary {
    let line = if report.up_to_date {
        format!(
            "up to date: the remote already holds generation {}",
            report.number
        )
    } else {
        format!(
            "pushed generation {} (remote was at {}): {}",
            report.number,
            generation(report.previous),
            transfer(
                report.generations,
                report.objects,
                report.packs,
                report.bytes
            )
        )
    };
    Summary {
        lines: vec![line],
        healthy: true,
    }
}

pub(crate) fn pull_summary(report: &PullReport) -> Summary {
    let moved = transfer(
        report.generations,
        report.objects,
        report.packs,
        report.bytes,
    );
    let line = match report.outcome {
        PullOutcome::Advanced => format!(
            "pulled generation {} (local was at {}): {moved}",
            report.number,
            generation(report.previous)
        ),
        PullOutcome::UpToDate => format!("up to date at generation {}", report.number),
        PullOutcome::LocalAhead => format!(
            "local generation {} is ahead of the remote; a mounted drive uploads it by itself, otherwise `zdrive remote push` does",
            report.number
        ),
        PullOutcome::RemoteEmpty => {
            "the remote holds no generation yet; a mounted drive uploads the local store by itself, otherwise `zdrive remote push` does"
                .to_string()
        }
        PullOutcome::Bootstrapped => format!(
            "new replica at generation {}: {moved}; it can be mounted now",
            report.number
        ),
    };
    Summary {
        lines: vec![line],
        healthy: true,
    }
}

pub(crate) fn status_summary(report: &StatusReport) -> Summary {
    let (relation, healthy) = match report.relation {
        Relation::NoRemoteStore => ("the remote folder holds no store; push creates it", true),
        Relation::DifferentStore => (
            "the remote folder holds a different store (other key material)",
            false,
        ),
        Relation::RemoteEmpty => ("the remote store holds no generation yet; push", true),
        Relation::Equal => ("in sync", true),
        Relation::LocalAhead => ("local is ahead; push", true),
        Relation::RemoteAhead => ("remote is ahead; pull", true),
        Relation::Diverged => (
            "DIVERGED: neither head descends from the other; nothing is merged automatically",
            false,
        ),
        Relation::Forked => (
            "FORKED: the remote holds conflicting records for one generation",
            false,
        ),
    };
    let mut lines = vec![
        format!("local generation: {}", report.local),
        format!("remote generation: {}", generation(report.remote)),
        format!("state: {relation}"),
        format!(
            "remote packs: {} ({})",
            report.packs,
            size(report.pack_bytes)
        ),
    ];
    if report.damaged > 0 {
        lines.push(format!(
            "damaged packs: {} (ignored; the next push re-uploads their objects)",
            report.damaged
        ));
    }
    if report.queued > 0 {
        lines.push(format!(
            "packs waiting to upload: {} (the next push resumes them)",
            report.queued
        ));
    }
    if let Some(synced) = &report.synced {
        lines.push(format!(
            "last synced generation: {} (unix time {})",
            synced.number, synced.unix_seconds
        ));
    }
    Summary { lines, healthy }
}

pub(crate) fn verify_summary(report: &VerifyReport) -> Summary {
    let mut lines = vec![format!(
        "remote generation {}: {}",
        generation(report.number),
        transfer(
            report.generations,
            report.objects,
            report.packs,
            report.bytes
        )
    )];
    if report.problems.is_empty() {
        lines.push("verified: every object of the remote head is in an intact pack".to_string());
    } else {
        lines.extend(
            report
                .problems
                .iter()
                .map(|problem| format!("problem: {problem}")),
        );
    }
    Summary {
        lines,
        healthy: report.problems.is_empty(),
    }
}

#[cfg(test)]
#[path = "cli_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "live_tests.rs"]
pub(crate) mod live;
