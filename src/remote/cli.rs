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

use super::config::{Paths, RemoteConfig, RemoteName, SealedToken};
use super::gdrive::{GoogleDrive, http_agent};
use super::oauth::{self, Consent, Endpoints, OAuthClient, RefreshTokenSource};
use super::state::RemoteState;
use super::sync::{
    self, LocalStore, PullOutcome, PullReport, PushReport, Relation, Remote, StatusReport,
    VerifyReport,
};
use super::{RemoteError, ensure_private_dir};

/// Drive's alias for the root of My Drive.
const MY_DRIVE: &str = "root";

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

#[derive(Args, Debug)]
pub(crate) struct AuthArgs {
    /// Remote name: 1-63 lowercase letters, digits, '-' or '_'
    #[arg(long)]
    remote: String,

    /// Drive folder that holds the remote, for example a Computers folder.
    /// Defaults to My Drive, or to the folder of an already configured remote
    #[arg(long, value_name = "ID")]
    folder_id: Option<String>,

    /// Slash-separated folder path below --folder-id (or My Drive); missing
    /// folders are created and duplicate names are refused
    #[arg(long, value_name = "PATH")]
    folder_path: Option<String>,

    /// OAuth Desktop client JSON downloaded from Google Cloud [default:
    /// ~/.config/zerotrust-drive/google-oauth-client.json]
    #[arg(long, value_name = "FILE")]
    client_file: Option<PathBuf>,

    /// Print the consent address and read the redirected address back
    /// instead of opening a local browser (headless hosts)
    #[arg(long)]
    no_browser: bool,

    /// Store passphrase that seals the Google credential. Prefer the
    /// ZEROTRUST_PASSPHRASE env var or the prompt: arguments are visible in
    /// the process list
    #[arg(long)]
    passphrase: Option<String>,
}

#[derive(Args, Debug)]
pub(crate) struct StoreArgs {
    /// Remote name given to `zdrive remote auth`
    #[arg(long)]
    remote: String,

    /// Local encrypted v2 store. Keep it outside folders that a desktop sync
    /// client uploads; the API replication replaces that client
    #[arg(long)]
    encrypted_dir: PathBuf,

    /// Store passphrase. Prefer the ZEROTRUST_PASSPHRASE env var or the
    /// prompt: arguments are visible in the process list
    #[arg(long)]
    passphrase: Option<String>,
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
    terminal: Option<&mut TerminalReader>,
    confirm: bool,
) -> Result<String, String> {
    let (passphrase, source) = prompt::resolve_current(
        std::env::var("ZEROTRUST_PASSPHRASE").ok(),
        argument,
        terminal.map(|terminal| terminal as &mut dyn SecretReader),
        false,
        confirm,
        crate::DEMO_PASSPHRASE,
    )?;
    if source == PassphraseSource::Default {
        return Err(
            "remote commands need the store passphrase: set ZEROTRUST_PASSPHRASE or run from a terminal to be prompted"
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

fn auth(args: AuthArgs) -> Result<Vec<String>, String> {
    let paths = Paths::from_env().map_err(|error| error.to_string())?;
    let name = RemoteName::parse(&args.remote).map_err(|error| error.to_string())?;
    let existing = match RemoteConfig::load(&paths, &name) {
        Ok(config) => Some(config),
        Err(RemoteError::NotFound(_)) => None,
        Err(error) => return Err(error.to_string()),
    };
    let client_file = match &args.client_file {
        Some(path) => crate::expand_home_from_env(path)?,
        None => existing
            .as_ref()
            .map(|config| config.client_file.clone())
            .unwrap_or_else(|| paths.default_client_file()),
    };
    let client_file = std::fs::canonicalize(&client_file).map_err(|error| {
        format!(
            "cannot open the OAuth client file {}: {error}; download the Desktop client JSON from Google Cloud and save it there with mode 0600",
            client_file.display()
        )
    })?;
    let client = OAuthClient::load(&client_file).map_err(|error| error.to_string())?;
    let (parent, folder_path) = match (args.folder_id, args.folder_path, &existing) {
        (None, None, Some(config)) => (config.folder_id.clone(), String::new()),
        (None, None, None) => {
            return Err(
                "choose the remote folder with --folder-id ID and/or --folder-path PATH"
                    .to_string(),
            );
        }
        (id, path, _) => (
            id.unwrap_or_else(|| MY_DRIVE.to_string()),
            path.unwrap_or_default(),
        ),
    };

    let mut terminal = TerminalReader::open();
    let passphrase = read_passphrase(args.passphrase, terminal.as_mut(), true)?;
    let agent = http_agent();
    let endpoints = Endpoints::google();
    let login_hint = existing.as_ref().map(|config| config.account.as_str());
    let mut stderr = std::io::stderr();
    let consent = if args.no_browser {
        let reader = terminal
            .as_mut()
            .ok_or("--no-browser reads the redirected address from a terminal; run it from one")?;
        Consent::Paste(reader)
    } else {
        Consent::Loopback {
            open: &oauth::open_in_browser,
            timeout: oauth::CONSENT_TIMEOUT,
        }
    };
    let authorization = oauth::authorize(
        &agent,
        &client,
        &endpoints,
        login_hint,
        consent,
        &mut stderr,
    )
    .map_err(|error| error.to_string())?;
    let refresh_token = authorization.refresh_token;
    let drive = GoogleDrive::new(Box::new(RefreshTokenSource::new(
        client,
        refresh_token.clone(),
        &endpoints,
    )));
    let account = drive.about().map_err(|error| error.to_string())?;
    if let Some(config) = &existing
        && config.account != account.email
    {
        note(&format!(
            "remote {name} was authorized for {} and is now authorized for {}",
            config.account, account.email
        ));
    }
    let parent_folder = drive.get(&parent).map_err(|error| error.to_string())?;
    let folder = drive
        .resolve_folder_path(&parent, &folder_path, true)
        .map_err(|error| error.to_string())?;
    if parent_folder.trashed || folder.trashed {
        return Err(format!(
            "the folder {} is in the Drive trash; restore it or choose another",
            folder.name
        ));
    }
    let hint = folder_hint(&parent_folder.name, &folder_path);
    if let Some(config) = &existing
        && config.folder_id != folder.id
    {
        note(&format!(
            "remote {name} moves from folder {} to {hint}; its local sync state starts over",
            config.folder_hint
        ));
    }
    let token = SealedToken::seal(&name, &passphrase, &refresh_token, KdfParams::new_random())
        .map_err(|error| error.to_string())?;
    RemoteConfig::new(
        &name,
        &account.email,
        &folder.id,
        &hint,
        &client_file,
        token,
    )
    .save(&paths)
    .map_err(|error| error.to_string())?;

    let mut lines = vec![
        format!("remote {name}: authorized for {}", account.email),
        format!("folder: {hint} (id {})", folder.id),
    ];
    if let (Some(limit), Some(usage)) = (account.limit, account.usage) {
        lines.push(format!("storage: {} used of {}", size(usage), size(limit)));
    }
    let remote = Remote {
        drive: &drive,
        folder_id: &folder.id,
        log: &note,
    };
    lines.push(match sync::remote_kdf(&remote) {
        Ok(_) => format!(
            "the folder holds a zerotrust-drive store: run `zdrive remote pull --remote {name} --encrypted-dir DIR` with an empty DIR to replicate it"
        ),
        Err(RemoteError::NotFound(_)) => format!(
            "the folder holds no store yet: `zdrive remote push --remote {name} --encrypted-dir DIR` creates it"
        ),
        Err(error) => format!("could not inspect the folder yet: {error}"),
    });
    Ok(lines)
}

fn folder_hint(parent: &str, path: &str) -> String {
    let path = path.trim_matches('/');
    if path.is_empty() {
        parent.to_string()
    } else {
        format!("{parent}/{path}")
    }
}

fn store_command(args: StoreArgs, action: Action) -> Result<Summary, String> {
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
    let client = OAuthClient::load(&config.client_file).map_err(|error| error.to_string())?;
    let mut terminal = TerminalReader::open();
    let passphrase = read_passphrase(args.passphrase, terminal.as_mut(), false)?;
    let drive = open_drive(client, &config, &name, &passphrase)?;
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
/// by the store passphrase.
pub(crate) fn open_drive(
    client: OAuthClient,
    config: &RemoteConfig,
    name: &RemoteName,
    passphrase: &str,
) -> Result<GoogleDrive, String> {
    let refresh_token = config
        .token
        .unseal(name, passphrase)
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

fn size(bytes: u64) -> String {
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
            "local generation {} is ahead of the remote; `zdrive remote push` publishes it",
            report.number
        ),
        PullOutcome::RemoteEmpty => {
            "the remote holds no generation yet; `zdrive remote push` publishes the local store"
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
