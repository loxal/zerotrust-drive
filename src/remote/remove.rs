// SPDX-FileCopyrightText: Copyright 2026 Alexander Orlov <info@lifub.com>

//! `zdrive remote remove NAME`: forget a remote on this computer.
//!
//! Removal deletes only what zdrive keeps about the remote here: its
//! configuration, its credential and its sync state. Local stores, a plain
//! folder and its local trash, and everything on Drive stay. It refuses
//! while a service definition uses the remote or a running zdrive holds
//! one of its locks, and holds those locks until it is done. `--revoke`
//! revokes the Google sign-in before anything is deleted; when the
//! revocation fails, nothing is deleted.

use std::fs::File;
use std::path::{Path, PathBuf};

use clap::Args;

use crate::prompt::{Prompter, TerminalReader};
use crate::service::definition::{self, Definition, Instance};

use super::RemoteError;
use super::config::{Paths, RemoteConfig, RemoteMode, RemoteName};
use super::gdrive::http_agent;
use super::oauth::{self, Revocation};
use super::state;

/// Where a Google account lists and revokes the apps it signed in to.
const PERMISSIONS_URL: &str = "https://myaccount.google.com/permissions";
const NO_TERMINAL: &str =
    "remote remove asks for confirmation on a terminal; add --yes to remove without asking";

#[derive(Args, Debug)]
pub(crate) struct RemoveArgs {
    /// Remote name given to `zdrive remote auth` or `zdrive setup`
    pub(crate) name: String,

    /// Also revoke the Google sign-in. This signs out every zdrive install
    /// that uses the same Google account, on every computer
    #[arg(long)]
    pub(crate) revoke: bool,

    /// Remove without asking; required without a terminal
    #[arg(long)]
    pub(crate) yes: bool,

    /// Private file (mode 0600) holding the store passphrase, which
    /// --revoke needs to open the credential of an encrypted remote.
    /// ZEROTRUST_PASSPHRASE and the prompt work as well
    #[arg(long, value_name = "FILE")]
    pub(crate) passphrase_file: Option<PathBuf>,
}

/// The answers a removal needs from whoever runs it.
pub(crate) trait Operator {
    /// The last question before anything changes.
    fn confirm(&mut self, question: &str) -> Result<bool, String>;
    /// The store passphrase that opens an encrypted remote's credential.
    fn passphrase(&mut self) -> Result<String, String>;
}

struct TerminalOperator {
    terminal: Option<TerminalReader>,
    yes: bool,
    passphrase_file: Option<PathBuf>,
}

impl TerminalOperator {
    /// Refuses up front when nobody could answer the confirmation.
    fn new(
        terminal: Option<TerminalReader>,
        yes: bool,
        passphrase_file: Option<PathBuf>,
    ) -> Result<Self, String> {
        if !yes && terminal.is_none() {
            return Err(NO_TERMINAL.to_string());
        }
        Ok(Self {
            terminal,
            yes,
            passphrase_file,
        })
    }
}

impl Operator for TerminalOperator {
    fn confirm(&mut self, question: &str) -> Result<bool, String> {
        if self.yes {
            return Ok(true);
        }
        let terminal = self.terminal.as_mut().ok_or(NO_TERMINAL)?;
        ask(terminal, question)
    }

    fn passphrase(&mut self) -> Result<String, String> {
        super::cli::read_passphrase(
            None,
            self.passphrase_file.as_deref(),
            self.terminal.as_mut(),
            false,
        )
    }
}

/// A yes/no question whose default is no.
fn ask(prompter: &mut dyn Prompter, question: &str) -> Result<bool, String> {
    crate::prompt::ask_yes_no(prompter, question, "nothing was removed")
}

/// Revokes one refresh token.
type Revoke<'a> = &'a dyn Fn(&str) -> Result<Revocation, RemoteError>;

pub(crate) fn remove(args: RemoveArgs) -> Result<Vec<String>, String> {
    let name = RemoteName::parse(&args.name).map_err(|error| error.to_string())?;
    let paths = Paths::from_env().map_err(|error| error.to_string())?;
    let mut operator =
        TerminalOperator::new(TerminalReader::open(), args.yes, args.passphrase_file)?;
    let agent = http_agent();
    let revoke = |token: &str| oauth::revoke(&agent, oauth::REVOKE_URL, token);
    remove_with(
        &paths,
        &name,
        args.revoke.then_some(&revoke as Revoke),
        &mut operator,
        &mut |line| super::cli::note(line),
    )
}

/// The configuration of the remote as found on disk.
enum Config {
    Missing,
    Invalid(String),
    Valid(Box<RemoteConfig>),
}

/// Everything zdrive keeps about one remote on this computer.
struct Found {
    config: Config,
    /// Existing files, deleted in this order: the configuration first, so
    /// nothing new starts on a half-removed remote.
    files: Vec<PathBuf>,
    /// The per-remote sync state directory, with one directory per local
    /// replica.
    state_dir: Option<PathBuf>,
    replica_locks: Vec<PathBuf>,
    plain_lock: Option<PathBuf>,
    /// Sealed packs that never reached Drive.
    unsent_packs: usize,
    plain_trash: Option<PathBuf>,
}

fn exists(path: &Path) -> bool {
    std::fs::symlink_metadata(path).is_ok()
}

fn is_real_dir(path: &Path) -> bool {
    std::fs::symlink_metadata(path).is_ok_and(|metadata| metadata.file_type().is_dir())
}

impl Found {
    fn inspect(paths: &Paths, name: &RemoteName) -> Result<Self, String> {
        let config = match RemoteConfig::load(paths, name) {
            Ok(config) => Config::Valid(Box::new(config)),
            Err(RemoteError::NotFound(_)) => Config::Missing,
            Err(error) => Config::Invalid(error.to_string()),
        };
        let plain_state = crate::plain::cli::state_file(paths, name);
        let plain_lock = crate::plain::lock_path(&plain_state);
        let files: Vec<PathBuf> = [
            paths.remote_config(name),
            paths.remote_token(name),
            plain_state,
            plain_lock.clone(),
        ]
        .into_iter()
        .filter(|path| exists(path))
        .collect();
        let dir = paths.remote_state(name);
        let state_dir = match std::fs::symlink_metadata(&dir) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
            Ok(metadata) if metadata.file_type().is_dir() => Some(dir),
            Ok(_) => {
                return Err(format!(
                    "{} is not a real directory; nothing was removed",
                    dir.display()
                ));
            }
            Err(error) => return Err(format!("{}: {error}; nothing was removed", dir.display())),
        };
        let (mut replica_locks, mut unsent_packs) = (Vec::new(), 0);
        if let Some(dir) = &state_dir {
            let entries = std::fs::read_dir(dir)
                .map_err(|error| format!("{}: {error}; nothing was removed", dir.display()))?;
            for entry in entries {
                let replica = entry
                    .map_err(|error| format!("{}: {error}; nothing was removed", dir.display()))?
                    .path();
                if !is_real_dir(&replica) {
                    continue;
                }
                let lock = replica.join(state::LOCK_FILE);
                if exists(&lock) {
                    replica_locks.push(lock);
                }
                unsent_packs += count_packs(&replica.join(state::OUTGOING_DIR));
            }
        }
        let trash = crate::plain::cli::trash_dir(paths, name);
        Ok(Self {
            config,
            files,
            state_dir,
            replica_locks,
            plain_lock: exists(&plain_lock).then_some(plain_lock),
            unsent_packs,
            plain_trash: is_real_dir(&trash).then_some(trash),
        })
    }

    fn is_empty(&self) -> bool {
        matches!(self.config, Config::Missing) && self.files.is_empty() && self.state_dir.is_none()
    }

    /// Takes every lock a running mount, sync, push or pull holds.
    fn lock(&self, name: &RemoteName) -> Result<Vec<File>, String> {
        let mut locks = Vec::new();
        for path in &self.replica_locks {
            locks.push(state::lock_existing(path).map_err(|error| match error {
                RemoteError::Conflict(_) => format!(
                    "remote {name} is in use by a running zdrive (a mount, push or pull); stop it first; nothing was removed"
                ),
                other => format!("{other}; nothing was removed"),
            })?);
        }
        if let Some(path) = &self.plain_lock {
            locks.push(
                crate::plain::lock_existing(path)
                    .map_err(|error| format!("{error}; nothing was removed"))?,
            );
        }
        Ok(locks)
    }

    fn describe(&self, paths: &Paths, name: &RemoteName, revoke: bool) -> Vec<String> {
        let mut lines = Vec::new();
        match &self.config {
            Config::Valid(config) => {
                lines.push(format!(
                    "remote {name}: {} Google Drive folder {:?} of {}, https://drive.google.com/drive/folders/{}",
                    config.mode.as_str(),
                    config.folder_hint,
                    config.account,
                    config.folder_id
                ));
            }
            Config::Invalid(error) => lines.push(format!("remote {name}: {error}")),
            Config::Missing => lines.push(format!(
                "remote {name} is not configured, but zdrive files of it remain"
            )),
        }
        lines.push("this deletes from this computer:".to_string());
        for path in &self.files {
            lines.push(format!("  {}", path.display()));
        }
        if let Some(dir) = &self.state_dir {
            lines.push(format!("  {} (sync state)", dir.display()));
        }
        if self.unsent_packs > 0 {
            lines.push(format!(
                "{} sealed pack(s) never reached Drive; the local store keeps their data, and a push to a remote uploads it again",
                self.unsent_packs
            ));
        }
        lines.push(
            "it keeps every local store and plain folder, and everything on Google Drive; move the Drive folder to the Drive bin yourself once you no longer need it"
                .to_string(),
        );
        if let Some(trash) = &self.plain_trash {
            lines.push(format!(
                "it keeps the local trash of remote {name} at {}; delete it yourself once you no longer need it",
                trash.display()
            ));
        }
        if revoke {
            if let Config::Valid(config) = &self.config {
                let mut warning = format!(
                    "--revoke first revokes the Google sign-in. That signs out every zdrive install that uses {}, on every computer",
                    config.account
                );
                let others = sharing_account(paths, name, config);
                if !others.is_empty() {
                    warning.push_str(&format!(
                        ", including remote(s) {} on this one",
                        others.join(", ")
                    ));
                }
                lines.push(warning);
            }
        } else {
            lines.push(format!(
                "the Google sign-in stays valid: revoke zdrive at {PERMISSIONS_URL}, or remove with --revoke"
            ));
        }
        lines
    }

    /// Deletes in order; reports what was deleted before a failure.
    fn delete(&self, note: &mut dyn FnMut(&str)) -> Result<Vec<String>, String> {
        let mut lines = Vec::new();
        let failed = |lines: &[String], note: &mut dyn FnMut(&str), error: String| {
            for line in lines {
                note(line);
            }
            Err(error)
        };
        for path in &self.files {
            match std::fs::remove_file(path) {
                Ok(()) => lines.push(format!("deleted {}", path.display())),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => {
                    return failed(
                        &lines,
                        note,
                        format!("cannot delete {}: {error}", path.display()),
                    );
                }
            }
        }
        if let Some(dir) = &self.state_dir {
            if let Err(error) = state::remove_tree(dir) {
                return failed(
                    &lines,
                    note,
                    format!("cannot delete {}: {error}", dir.display()),
                );
            }
            lines.push(format!("deleted {}", dir.display()));
        }
        Ok(lines)
    }
}

fn count_packs(outgoing: &Path) -> usize {
    std::fs::read_dir(outgoing).map_or(0, |entries| {
        entries
            .filter_map(Result::ok)
            .filter(|entry| {
                entry
                    .file_name()
                    .to_str()
                    .is_some_and(|name| name.ends_with(".zpk"))
            })
            .count()
    })
}

/// Other remotes here whose sign-in a revocation also ends: the same
/// account through zdrive's bundled clients (observed 2026-10-18: one
/// revocation ended both), or through the same own client file.
fn sharing_account(paths: &Paths, name: &RemoteName, config: &RemoteConfig) -> Vec<String> {
    let Ok(entries) = std::fs::read_dir(paths.config.join("remotes")) else {
        return Vec::new();
    };
    let mut names: Vec<String> = entries
        .filter_map(Result::ok)
        .filter_map(|entry| {
            let file_name = entry.file_name();
            let other = RemoteName::parse(file_name.to_str()?.strip_suffix(".json")?).ok()?;
            if other == *name {
                return None;
            }
            let theirs = RemoteConfig::load(paths, &other).ok()?;
            let same_client = (config.client.bundled() && theirs.client.bundled())
                || (config.client == theirs.client && config.client_file == theirs.client_file);
            (!config.account.is_empty()
                && theirs.account.eq_ignore_ascii_case(&config.account)
                && same_client)
                .then(|| other.as_str().to_string())
        })
        .collect();
    names.sort();
    names
}

/// Service instances whose definition uses the remote.
fn services_using(paths: &Paths, name: &RemoteName) -> Result<Vec<String>, String> {
    let mut users = Vec::new();
    for service in definition::names(paths) {
        let loaded = Definition::load(paths, &service).map_err(|error| {
            format!(
                "cannot tell whether service instance {service} uses remote {name}: {error}; nothing was removed"
            )
        })?;
        let remote = match &loaded.instance {
            Instance::Encrypted { remote, .. } => remote.as_deref(),
            Instance::Plain { remote, .. } => Some(remote.as_str()),
        };
        if remote == Some(name.as_str()) {
            users.push(service);
        }
    }
    Ok(users)
}

/// The refresh token to revoke; nothing has changed when this fails.
fn credential(
    found: &Found,
    paths: &Paths,
    name: &RemoteName,
    operator: &mut dyn Operator,
) -> Result<String, String> {
    let cannot = |reason: String| {
        format!(
            "cannot revoke the Google sign-in of remote {name}: {reason}; nothing was removed. Remove it without --revoke, then revoke zdrive at {PERMISSIONS_URL}"
        )
    };
    let config = match &found.config {
        Config::Valid(config) => config,
        Config::Invalid(error) => return Err(cannot(error.clone())),
        Config::Missing => return Err(cannot("it is not configured".to_string())),
    };
    let passphrase = match config.mode {
        RemoteMode::Encrypted => Some(operator.passphrase().map_err(cannot)?),
        RemoteMode::Plain => None,
    };
    config
        .refresh_token(paths, name, passphrase.as_deref())
        .map_err(|error| match error {
            RemoteError::Auth(_) if passphrase.is_some() => {
                cannot("this passphrase does not open its credential".to_string())
            }
            other => cannot(other.to_string()),
        })
}

fn remove_with(
    paths: &Paths,
    name: &RemoteName,
    revoke: Option<Revoke>,
    operator: &mut dyn Operator,
    note: &mut dyn FnMut(&str),
) -> Result<Vec<String>, String> {
    let found = Found::inspect(paths, name)?;
    if found.is_empty() {
        return Err(format!(
            "remote {name} is not configured; nothing was removed"
        ));
    }
    let users = services_using(paths, name)?;
    if let Some(first) = users.first() {
        return Err(format!(
            "remote {name} is used by service instance(s) {}; uninstall them first, for example `zdrive service uninstall {first} --purge`; nothing was removed",
            users.join(", ")
        ));
    }
    // Held until the deletion is done, so nothing starts syncing meanwhile.
    let _locks = found.lock(name)?;
    // Opened before the question, so a wrong passphrase ends the removal
    // before anyone answers yes.
    let token = match revoke {
        Some(_) => Some(credential(&found, paths, name, operator)?),
        None => None,
    };
    for line in found.describe(paths, name, revoke.is_some()) {
        note(&line);
    }
    if !operator.confirm(&format!("remove remote {name} from this computer?"))? {
        return Err(format!("kept remote {name}; nothing was removed"));
    }
    let mut lines = Vec::new();
    if let (Some(revoke), Some(token)) = (revoke, token) {
        match revoke(&token).map_err(|error| format!("{error}; nothing was removed"))? {
            Revocation::Revoked => {
                lines.push(format!("revoked the Google sign-in of remote {name}"))
            }
            Revocation::AlreadyInvalid => lines.push(format!(
                "the Google sign-in of remote {name} was already revoked or expired"
            )),
        }
    }
    let revoked = !lines.is_empty();
    match found.delete(note) {
        Ok(deleted) => lines.extend(deleted),
        Err(error) => {
            for line in &lines {
                note(line);
            }
            let rest = if revoked {
                format!(
                    "; run `zdrive remote remove {name}` again, without --revoke, to delete the rest"
                )
            } else {
                format!("; run `zdrive remote remove {name}` again to delete the rest")
            };
            return Err(format!("{error}{rest}"));
        }
    }
    lines.push(format!(
        "removed remote {name} from this computer; its Drive folder is unchanged"
    ));
    Ok(lines)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::prompt::SecretReader;
    use crate::remote::TestDir;
    use crate::remote::config::{self, ClientKind, Issuer, SealedToken};
    use crate::remote::fake::{self, FakeDrive, Fault, Op};
    use crate::remote::state::RemoteState;
    use std::collections::VecDeque;
    use std::io;

    const PASSPHRASE: &str = "correct horse battery staple";
    const FOLDER: &str = "folder0000000000000000000001";

    struct Scripted {
        answers: VecDeque<bool>,
        passphrase: Option<&'static str>,
        asked: usize,
        passphrase_reads: usize,
    }

    impl Scripted {
        fn new(answers: &[bool], passphrase: Option<&'static str>) -> Self {
            Self {
                answers: answers.iter().copied().collect(),
                passphrase,
                asked: 0,
                passphrase_reads: 0,
            }
        }
    }

    impl Operator for Scripted {
        fn confirm(&mut self, _question: &str) -> Result<bool, String> {
            self.asked += 1;
            self.answers
                .pop_front()
                .ok_or_else(|| "no scripted answer".to_string())
        }

        fn passphrase(&mut self) -> Result<String, String> {
            self.passphrase_reads += 1;
            self.passphrase
                .map(str::to_string)
                .ok_or_else(|| "no passphrase".to_string())
        }
    }

    struct Fixture {
        _dir: TestDir,
        paths: Paths,
    }

    impl Fixture {
        fn new(label: &str) -> Self {
            let dir = TestDir::new(label);
            let paths = Paths {
                config: dir.path().join("config"),
                state: dir.path().join("state"),
                data: dir.path().join("data"),
            };
            Self { _dir: dir, paths }
        }

        fn encrypted(&self, remote: &str, account: &str, refresh_token: &str) -> RemoteName {
            let name = RemoteName::parse(remote).unwrap();
            let token =
                SealedToken::seal(&name, PASSPHRASE, refresh_token, config::test_kdf()).unwrap();
            RemoteConfig::encrypted(
                &name,
                account,
                FOLDER,
                "My Drive/ZeroTrust Drive",
                &Issuer::bundled(ClientKind::BundledDesktop),
                token,
            )
            .save(&self.paths)
            .unwrap();
            name
        }

        fn plain(&self, remote: &str, account: &str) -> RemoteName {
            let name = RemoteName::parse(remote).unwrap();
            RemoteConfig::plain(
                &name,
                account,
                FOLDER,
                "My Drive/ZeroTrust Drive (plain)",
                &Issuer::bundled(ClientKind::BundledDevice),
            )
            .save(&self.paths)
            .unwrap();
            config::save_plain_token(&self.paths, &name, fake::REFRESH_TOKEN).unwrap();
            name
        }

        /// A replica's sync state, as a push leaves it, plus one sealed
        /// pack that never reached Drive.
        fn replica(&self, name: &RemoteName, store: &str) -> PathBuf {
            let dir = self.paths.replica_state(name, Path::new(store));
            drop(RemoteState::open(&dir, FOLDER).unwrap());
            std::fs::write(dir.join(state::OUTGOING_DIR).join("p1.zpk"), b"sealed").unwrap();
            dir
        }

        fn remove(
            &self,
            name: &RemoteName,
            revoke: Option<Revoke>,
            operator: &mut dyn Operator,
        ) -> (Result<Vec<String>, String>, Vec<String>) {
            let mut notes = Vec::new();
            let result = remove_with(&self.paths, name, revoke, operator, &mut |line| {
                notes.push(line.to_string())
            });
            (result, notes)
        }
    }

    fn revoker(fake: &FakeDrive) -> impl Fn(&str) -> Result<Revocation, RemoteError> {
        let url = format!("{}/revoke", fake.base_url());
        move |token| oauth::revoke(&http_agent(), &url, token)
    }

    fn untouched(fixture: &Fixture, name: &RemoteName) {
        assert!(fixture.paths.remote_config(name).exists());
        assert!(fixture.paths.remote_state(name).exists());
    }

    #[test]
    fn removal_deletes_only_this_computers_records_of_the_remote() {
        let fixture = Fixture::new("remove-files");
        let name = fixture.encrypted("drive", "a@example.com", fake::REFRESH_TOKEN);
        fixture.replica(&name, "/stores/one");
        fixture.replica(&name, "/stores/two");
        let other = fixture.encrypted("other", "b@example.com", fake::REFRESH_TOKEN);
        let other_state = fixture.replica(&other, "/stores/three");
        let store = fixture.paths.data.join("drive").join("store");
        std::fs::create_dir_all(&store).unwrap();
        std::fs::write(store.join("v2-root"), b"keep").unwrap();

        let mut operator = Scripted::new(&[true], None);
        let (result, notes) = fixture.remove(&name, None, &mut operator);
        let lines = result.unwrap();

        assert!(!fixture.paths.remote_config(&name).exists());
        assert!(!fixture.paths.remote_state(&name).exists());
        assert_eq!(std::fs::read(store.join("v2-root")).unwrap(), b"keep");
        assert!(fixture.paths.remote_config(&other).exists());
        assert!(other_state.join(state::LOCK_FILE).exists());
        assert_eq!((operator.asked, operator.passphrase_reads), (1, 0));
        assert!(
            lines
                .iter()
                .any(|line| line.starts_with("deleted ") && line.ends_with("remotes/drive.json"))
        );
        assert!(lines.last().unwrap().contains("Drive folder is unchanged"));
        let notes = notes.join("\n");
        assert!(
            notes.contains(&format!("drive/folders/{FOLDER}")),
            "{notes}"
        );
        assert!(
            notes.contains("2 sealed pack(s) never reached Drive"),
            "{notes}"
        );
        assert!(notes.contains(PERMISSIONS_URL), "{notes}");
    }

    #[test]
    fn plain_removal_deletes_the_token_and_index_but_keeps_the_local_trash() {
        let fixture = Fixture::new("remove-plain");
        let name = fixture.plain("notes", "a@example.com");
        let index = crate::plain::cli::state_file(&fixture.paths, &name);
        std::fs::create_dir_all(index.parent().unwrap()).unwrap();
        std::fs::write(&index, b"{}").unwrap();
        let lock = crate::plain::lock_path(&index);
        std::fs::write(&lock, b"").unwrap();
        let trash = crate::plain::cli::trash_dir(&fixture.paths, &name);
        std::fs::create_dir_all(&trash).unwrap();
        std::fs::write(trash.join("old.txt"), b"user data").unwrap();

        let (result, notes) = fixture.remove(&name, None, &mut Scripted::new(&[true], None));
        result.unwrap();

        for gone in [
            fixture.paths.remote_config(&name),
            fixture.paths.remote_token(&name),
            index,
            lock,
        ] {
            assert!(!gone.exists(), "{}", gone.display());
        }
        assert_eq!(std::fs::read(trash.join("old.txt")).unwrap(), b"user data");
        assert!(
            notes
                .iter()
                .any(|line| line.contains(&trash.display().to_string()))
        );
    }

    #[test]
    fn revoke_ends_the_grant_before_deleting() {
        let fake = FakeDrive::start();
        let fixture = Fixture::new("remove-revoke");
        let name = fixture.encrypted("drive", "a@example.com", fake::REFRESH_TOKEN);
        fixture.replica(&name, "/stores/one");
        let shared = fixture.plain("notes", "A@example.com");
        let revoke = revoker(&fake);
        let mut operator = Scripted::new(&[true], Some(PASSPHRASE));

        let (result, notes) = fixture.remove(&name, Some(&revoke), &mut operator);
        let lines = result.unwrap();

        assert!(fake.refresh_revoked());
        assert_eq!(fake.count(Op::Revoke), 1);
        assert_eq!(lines[0], "revoked the Google sign-in of remote drive");
        assert!(!fixture.paths.remote_config(&name).exists());
        assert!(fixture.paths.remote_config(&shared).exists());
        let notes = notes.join("\n");
        assert!(
            notes.contains("every zdrive install that uses a@example.com"),
            "{notes}"
        );
        assert!(
            notes.contains("including remote(s) notes on this one"),
            "{notes}"
        );
    }

    #[test]
    fn an_already_revoked_sign_in_still_removes_the_remote() {
        let fake = FakeDrive::start();
        let fixture = Fixture::new("remove-revoked");
        let name = fixture.plain("notes", "a@example.com");
        config::save_plain_token(&fixture.paths, &name, "long-gone-token").unwrap();
        let revoke = revoker(&fake);

        let (result, _) = fixture.remove(&name, Some(&revoke), &mut Scripted::new(&[true], None));
        let lines = result.unwrap();

        assert_eq!(
            lines[0],
            "the Google sign-in of remote notes was already revoked or expired"
        );
        assert!(!fixture.paths.remote_config(&name).exists());
        assert!(!fake.refresh_revoked());
    }

    #[test]
    fn a_failed_revocation_removes_nothing() {
        let fake = FakeDrive::start();
        let fixture = Fixture::new("remove-revoke-fails");
        let name = fixture.encrypted("drive", "a@example.com", fake::REFRESH_TOKEN);
        fixture.replica(&name, "/stores/one");
        let revoke = revoker(&fake);
        for fault in [
            Fault::Status(503, "backendError"),
            Fault::Drop,
            Fault::Status(401, "unauthorized_client"),
        ] {
            fake.fault(Op::Revoke, fault);
            let (result, _) = fixture.remove(
                &name,
                Some(&revoke),
                &mut Scripted::new(&[true], Some(PASSPHRASE)),
            );
            let error = result.unwrap_err();
            assert!(error.ends_with("nothing was removed"), "{error}");
            untouched(&fixture, &name);
        }
        assert!(!fake.refresh_revoked());
    }

    #[test]
    fn a_wrong_passphrase_stops_before_the_question_and_the_revocation() {
        let fake = FakeDrive::start();
        let fixture = Fixture::new("remove-wrong-passphrase");
        let name = fixture.encrypted("drive", "a@example.com", fake::REFRESH_TOKEN);
        fixture.replica(&name, "/stores/one");
        let revoke = revoker(&fake);
        let mut operator = Scripted::new(&[true], Some("not the passphrase"));

        let (result, notes) = fixture.remove(&name, Some(&revoke), &mut operator);
        let error = result.unwrap_err();

        assert!(
            error.contains("this passphrase does not open its credential"),
            "{error}"
        );
        assert!(error.contains(PERMISSIONS_URL), "{error}");
        assert!(!error.contains(PASSPHRASE) && !error.contains(fake::REFRESH_TOKEN));
        assert_eq!(operator.asked, 0);
        assert!(notes.is_empty());
        assert_eq!(fake.count(Op::Revoke), 0);
        untouched(&fixture, &name);
    }

    #[test]
    fn a_service_definition_that_uses_the_remote_refuses_removal() {
        let fixture = Fixture::new("remove-service");
        let name = fixture.encrypted("drive", "a@example.com", fake::REFRESH_TOKEN);
        fixture.replica(&name, "/stores/one");
        Definition {
            name: "photos".to_string(),
            instance: Instance::Plain {
                remote: "drive".to_string(),
                local_dir: PathBuf::from("/abs/photos"),
            },
            final_push_wait_secs: 60,
        }
        .save(&fixture.paths)
        .unwrap();
        let mut operator = Scripted::new(&[true], None);

        let (result, _) = fixture.remove(&name, None, &mut operator);
        let error = result.unwrap_err();

        assert!(error.contains("service instance(s) photos"), "{error}");
        assert!(
            error.contains("zdrive service uninstall photos --purge"),
            "{error}"
        );
        assert_eq!(operator.asked, 0);
        untouched(&fixture, &name);
    }

    #[test]
    fn an_unreadable_service_definition_refuses_removal() {
        let fixture = Fixture::new("remove-bad-service");
        let name = fixture.encrypted("drive", "a@example.com", fake::REFRESH_TOKEN);
        fixture.replica(&name, "/stores/one");
        let path = definition::definition_path(&fixture.paths, "broken");
        definition::ensure_services_dir(&fixture.paths).unwrap();
        crate::remote::write_private_file(&path, b"{").unwrap();

        let (result, _) = fixture.remove(&name, None, &mut Scripted::new(&[true], None));
        let error = result.unwrap_err();

        assert!(error.contains("service instance broken"), "{error}");
        untouched(&fixture, &name);
    }

    #[test]
    fn a_running_sync_refuses_removal() {
        let fixture = Fixture::new("remove-locked");
        let name = fixture.encrypted("drive", "a@example.com", fake::REFRESH_TOKEN);
        let replica = fixture.replica(&name, "/stores/one");
        let held = RemoteState::open(&replica, FOLDER).unwrap();
        let mut operator = Scripted::new(&[true], None);

        let (result, _) = fixture.remove(&name, None, &mut operator);
        let error = result.unwrap_err();

        assert!(error.contains("in use by a running zdrive"), "{error}");
        assert_eq!(operator.asked, 0);
        untouched(&fixture, &name);
        drop(held);
        let (result, _) = fixture.remove(&name, None, &mut operator);
        result.unwrap();
    }

    #[test]
    fn a_running_plain_sync_refuses_removal() {
        let fixture = Fixture::new("remove-plain-locked");
        let name = fixture.plain("notes", "a@example.com");
        let index = crate::plain::cli::state_file(&fixture.paths, &name);
        std::fs::create_dir_all(index.parent().unwrap()).unwrap();
        let lock = crate::plain::lock_path(&index);
        std::fs::write(&lock, b"").unwrap();
        let held = crate::plain::lock_existing(&lock).unwrap();

        let (result, _) = fixture.remove(&name, None, &mut Scripted::new(&[true], None));
        let error = result.unwrap_err();

        assert!(error.contains("already syncing"), "{error}");
        assert!(fixture.paths.remote_config(&name).exists());
        assert!(fixture.paths.remote_token(&name).exists());
        drop(held);
    }

    #[test]
    fn declining_keeps_everything() {
        let fixture = Fixture::new("remove-declined");
        let name = fixture.encrypted("drive", "a@example.com", fake::REFRESH_TOKEN);
        fixture.replica(&name, "/stores/one");

        let (result, notes) = fixture.remove(&name, None, &mut Scripted::new(&[false], None));

        assert_eq!(
            result.unwrap_err(),
            "kept remote drive; nothing was removed"
        );
        assert!(!notes.is_empty());
        untouched(&fixture, &name);
    }

    #[test]
    fn an_unknown_remote_is_an_error() {
        let fixture = Fixture::new("remove-unknown");
        let name = RemoteName::parse("nothing").unwrap();
        let mut operator = Scripted::new(&[true], None);
        let (result, _) = fixture.remove(&name, None, &mut operator);
        assert_eq!(
            result.unwrap_err(),
            "remote nothing is not configured; nothing was removed"
        );
        assert_eq!(operator.asked, 0);
    }

    #[test]
    fn leftovers_of_an_unconfigured_remote_are_removed() {
        let fixture = Fixture::new("remove-leftovers");
        let name = fixture.encrypted("drive", "a@example.com", fake::REFRESH_TOKEN);
        fixture.replica(&name, "/stores/one");
        std::fs::remove_file(fixture.paths.remote_config(&name)).unwrap();

        let (result, notes) = fixture.remove(&name, None, &mut Scripted::new(&[true], None));
        result.unwrap();

        assert!(!fixture.paths.remote_state(&name).exists());
        assert!(notes[0].contains("not configured"), "{notes:?}");
        // --revoke has no credential to revoke for leftovers.
        fixture.replica(&name, "/stores/one");
        let fake = FakeDrive::start();
        let revoke = revoker(&fake);
        let (result, _) = fixture.remove(&name, Some(&revoke), &mut Scripted::new(&[true], None));
        assert!(result.unwrap_err().contains("it is not configured"));
        assert!(fixture.paths.remote_state(&name).exists());
    }

    #[test]
    fn an_invalid_configuration_is_removable_but_not_revocable() {
        let fixture = Fixture::new("remove-invalid");
        let name = fixture.encrypted("drive", "a@example.com", fake::REFRESH_TOKEN);
        crate::remote::write_private_file(&fixture.paths.remote_config(&name), b"{").unwrap();
        let fake = FakeDrive::start();
        let revoke = revoker(&fake);

        let (result, _) = fixture.remove(&name, Some(&revoke), &mut Scripted::new(&[true], None));
        let error = result.unwrap_err();
        assert!(error.contains("invalid remote configuration"), "{error}");
        assert!(fixture.paths.remote_config(&name).exists());

        let (result, notes) = fixture.remove(&name, None, &mut Scripted::new(&[true], None));
        result.unwrap();
        assert!(
            notes[0].contains("invalid remote configuration"),
            "{notes:?}"
        );
        assert!(!fixture.paths.remote_config(&name).exists());
    }

    #[test]
    fn a_state_directory_symlink_is_refused() {
        let fixture = Fixture::new("remove-symlink");
        let name = fixture.encrypted("drive", "a@example.com", fake::REFRESH_TOKEN);
        let target = fixture.paths.data.join("elsewhere");
        std::fs::create_dir_all(&target).unwrap();
        std::fs::create_dir_all(fixture.paths.state.join("remotes")).unwrap();
        std::os::unix::fs::symlink(&target, fixture.paths.remote_state(&name)).unwrap();

        let (result, _) = fixture.remove(&name, None, &mut Scripted::new(&[true], None));

        assert!(result.unwrap_err().contains("is not a real directory"));
        assert!(target.exists());
        assert!(fixture.paths.remote_config(&name).exists());
    }

    struct Answers(VecDeque<&'static str>);

    impl SecretReader for Answers {
        fn read_secret(&mut self, _prompt: &str) -> io::Result<String> {
            self.0
                .pop_front()
                .map(str::to_string)
                .ok_or_else(|| io::Error::new(io::ErrorKind::UnexpectedEof, "no more answers"))
        }
    }

    impl Prompter for Answers {
        fn read_visible(&mut self, prompt: &str) -> io::Result<String> {
            self.read_secret(prompt)
        }
    }

    #[test]
    fn the_question_defaults_to_no() {
        let mut answers = Answers(["", "n", "No", "y", " YES ", "maybe"].into_iter().collect());
        let mut next = || ask(&mut answers, "remove?");
        assert_eq!(next(), Ok(false));
        assert_eq!(next(), Ok(false));
        assert_eq!(next(), Ok(false));
        assert_eq!(next(), Ok(true));
        assert_eq!(next(), Ok(true));
        assert!(next().unwrap_err().contains("nothing was removed"));
        assert!(next().unwrap_err().contains("cannot read the answer"));
    }

    #[test]
    fn without_a_terminal_removal_needs_yes() {
        assert_eq!(
            TerminalOperator::new(None, false, None).err().as_deref(),
            Some(NO_TERMINAL)
        );
        let mut operator = TerminalOperator::new(None, true, None).unwrap();
        assert_eq!(operator.confirm("remove?"), Ok(true));
    }
}
