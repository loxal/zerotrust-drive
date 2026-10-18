// SPDX-FileCopyrightText: Copyright 2026 Alexander Orlov <info@lifub.com>

//! Live Google Drive checks through the same admission and execution path as
//! `zdrive remote`. They need a remote that `zdrive remote auth` configured
//! and the passphrase that sealed its credential. Each test works in a fresh
//! folder below that remote's folder and moves it to the Drive bin afterwards
//! (`ZDRIVE_GDRIVE_KEEP=1` keeps it for inspection):
//!
//! ```fish
//! set -x ZDRIVE_RUN_GDRIVE_TESTS 1
//! set -x ZDRIVE_GDRIVE_REMOTE gdrive-test
//! read -s -x ZEROTRUST_PASSPHRASE
//! cargo test --locked remote::cli::live -- --ignored --test-threads=1 --nocapture
//! ```
//!
//! `live_scratch_folder` with `ZDRIVE_GDRIVE_KEEP=1` only creates and keeps an
//! empty run folder. A copy of the remote's configuration pointing at it lets
//! a kernel mount with `--remote` start a fresh store there without touching
//! the remote's own folder.

use std::time::Instant;

use super::*;
use crate::remote::TestDir;
use crate::remote::gdrive::DriveFile;
use crate::remote::sync::tests::{CANARY, PASSPHRASE, Store, content};

const RUN_ENV: &str = "ZDRIVE_RUN_GDRIVE_TESTS";

pub(crate) struct Live {
    pub(crate) drive: GoogleDrive,
    pub(crate) folder: String,
    /// The run folder's name below the remote's folder.
    pub(crate) run: String,
    hint: String,
    keep: bool,
    client: OAuthClient,
    refresh_token: String,
}

/// The configured live remote and a client for its account.
pub(crate) struct Account {
    pub(crate) config: RemoteConfig,
    client: OAuthClient,
    refresh_token: String,
    pub(crate) drive: GoogleDrive,
}

impl Account {
    pub(crate) fn open() -> Self {
        assert_eq!(
            std::env::var(RUN_ENV).as_deref(),
            Ok("1"),
            "set {RUN_ENV}=1 for the live Google Drive checks"
        );
        let name = std::env::var("ZDRIVE_GDRIVE_REMOTE")
            .expect("set ZDRIVE_GDRIVE_REMOTE to a remote configured by `zdrive remote auth`");
        let name = RemoteName::parse(&name).unwrap();
        let passphrase = std::env::var("ZEROTRUST_PASSPHRASE")
            .expect("set ZEROTRUST_PASSPHRASE to the passphrase that sealed the remote");
        let paths = Paths::from_env().unwrap();
        let config = RemoteConfig::load(&paths, &name).unwrap();
        let client = OAuthClient::load(&config.client_file).unwrap();
        let refresh_token = config.token.unseal(&name, &passphrase).unwrap();
        let drive = GoogleDrive::new(Box::new(RefreshTokenSource::new(
            client.clone(),
            refresh_token.clone(),
            &Endpoints::google(),
        )));
        Self {
            config,
            client,
            refresh_token,
            drive,
        }
    }

    /// A second client for the same account, for a thread that owns one.
    pub(crate) fn client(&self) -> GoogleDrive {
        GoogleDrive::new(Box::new(RefreshTokenSource::new(
            self.client.clone(),
            self.refresh_token.clone(),
            &Endpoints::google(),
        )))
    }
}

impl Live {
    pub(crate) fn start(label: &str) -> Self {
        let Account {
            config,
            client,
            refresh_token,
            drive,
        } = Account::open();
        let mut nonce = [0u8; 4];
        crate::crypto::fill_random(&mut nonce);
        let run = format!("live-{label}-{}", crate::remote::hex(&nonce));
        let id = drive.generate_ids(1).unwrap().remove(0);
        let folder = drive
            .create_folder(&config.folder_id, &run, &id)
            .unwrap()
            .id;
        let hint = format!("{}/{run}", config.folder_hint);
        eprintln!("live run folder: {hint} (id {folder})");
        Self {
            drive,
            folder,
            run,
            hint,
            keep: std::env::var("ZDRIVE_GDRIVE_KEEP").as_deref() == Ok("1"),
            client,
            refresh_token,
        }
    }

    /// A second client for the same account, for a component that owns one.
    pub(crate) fn client(&self) -> GoogleDrive {
        GoogleDrive::new(Box::new(RefreshTokenSource::new(
            self.client.clone(),
            self.refresh_token.clone(),
            &Endpoints::google(),
        )))
    }

    fn remote(&self) -> Remote<'_> {
        Remote {
            drive: &self.drive,
            folder_id: &self.folder,
            log: &progress,
        }
    }

    /// One command as `store_command` runs it after its lock and credential
    /// steps, timed.
    pub(crate) fn run(
        &self,
        action: Action,
        base: &Path,
        state: &Path,
    ) -> Result<Summary, RemoteError> {
        let started = Instant::now();
        let kind = inspect_store(base, "store").map_err(RemoteError::Local)?;
        admit(action, kind, &RemoteName::parse("live").unwrap(), "store")?;
        let outcome = execute(
            action,
            kind,
            &self.remote(),
            base,
            "store",
            PASSPHRASE,
            state,
        );
        eprintln!("{action:?} took {:.2?}", started.elapsed());
        if let Ok(summary) = &outcome {
            for line in &summary.lines {
                eprintln!("  {line}");
            }
        }
        outcome
    }

    /// Every file and folder below the run folder.
    pub(crate) fn files(&self) -> Vec<DriveFile> {
        let mut pending = vec![self.folder.clone()];
        let mut files = Vec::new();
        while let Some(parent) = pending.pop() {
            for file in self.drive.list(&parent, false).unwrap() {
                if file.is_folder() {
                    pending.push(file.id.clone());
                }
                files.push(file);
            }
        }
        files
    }
}

impl Drop for Live {
    fn drop(&mut self) {
        if self.keep {
            eprintln!("kept {} (id {})", self.hint, self.folder);
        } else if let Err(error) = self.drive.trash(&self.folder) {
            eprintln!("could not move {} to the Drive bin: {error}", self.hint);
        }
    }
}

fn progress(line: &str) {
    eprintln!("  .. {line}");
}

/// An empty directory for a first pull, and the sync state beside it.
pub(crate) fn empty_replica(label: &str) -> (TestDir, PathBuf, PathBuf) {
    let dir = TestDir::new(label);
    let base = dir.path().join("store");
    std::fs::create_dir_all(&base).unwrap();
    let state = dir.path().join("cli-state");
    (dir, base, state)
}

/// What [`check_mirror`] found.
pub(crate) struct Mirrored {
    pub(crate) identical: usize,
    pub(crate) absent: usize,
    pub(crate) bytes: u64,
}

/// Compares the local copy that Drive for desktop keeps of a Drive folder
/// with the folder itself: every mirrored file must equal its Drive file
/// byte for byte and hold no plaintext canary. Files not mirrored yet are
/// counted, not failed.
pub(crate) fn check_mirror(drive: &GoogleDrive, folder: &str, mirror: &Path) -> Mirrored {
    let mut pending = vec![(folder.to_string(), mirror.to_path_buf())];
    let mut found = Mirrored {
        identical: 0,
        absent: 0,
        bytes: 0,
    };
    while let Some((parent, dir)) = pending.pop() {
        for file in drive.list(&parent, false).unwrap() {
            let local = dir.join(&file.name);
            if file.is_folder() {
                pending.push((file.id.clone(), local));
                continue;
            }
            let Ok(content) = std::fs::read(&local) else {
                found.absent += 1;
                continue;
            };
            assert_eq!(
                Some(content.len() as u64),
                file.size(),
                "{}",
                local.display()
            );
            assert_eq!(
                Some(crate::remote::md5_bytes(&content)),
                file.md5(),
                "{}",
                local.display()
            );
            assert!(
                !content.windows(CANARY.len()).any(|window| window == CANARY),
                "plaintext canary in {}",
                local.display()
            );
            found.identical += 1;
            found.bytes += content.len() as u64;
        }
    }
    found
}

/// With `ZDRIVE_GDRIVE_MIRROR` naming the local copy that Drive for desktop
/// keeps of the remote's folder, everything mirrored equals the remote.
#[test]
#[ignore = "requires ZDRIVE_RUN_GDRIVE_TESTS=1, a configured remote and ZDRIVE_GDRIVE_MIRROR"]
fn live_mirror_holds_exactly_the_remote_ciphertext() {
    let mirror = PathBuf::from(
        std::env::var("ZDRIVE_GDRIVE_MIRROR")
            .expect("set ZDRIVE_GDRIVE_MIRROR to the local mirror of the remote's folder"),
    );
    let account = Account::open();
    let found = check_mirror(&account.drive, &account.config.folder_id, &mirror);
    eprintln!(
        "mirror: {} files ({} bytes) identical, {} not mirrored",
        found.identical, found.bytes, found.absent
    );
    assert!(found.identical > 0, "nothing mirrored yet");
}

#[test]
#[ignore = "requires ZDRIVE_RUN_GDRIVE_TESTS=1 and a remote configured by `zdrive remote auth`"]
fn live_round_trip_leaves_google_only_ciphertext() {
    let live = Live::start("round-trip");
    let mut origin = Store::origin("live-origin");
    // Larger than the multipart limit, so the pack travels in a resumable
    // session.
    origin.write("large.bin", content(3, 12 << 20));
    let origin_state = origin.dir.path().join("cli-state");
    assert!(
        live.run(Action::Push, &origin.base, &origin_state)
            .unwrap()
            .healthy
    );
    assert!(
        live.run(Action::Status, &origin.base, &origin_state)
            .unwrap()
            .healthy
    );
    assert!(
        live.run(Action::Verify { full: true }, &origin.base, &origin_state)
            .unwrap()
            .healthy
    );

    origin.write("a.txt", content(4, 200));
    assert!(
        live.run(Action::Push, &origin.base, &origin_state)
            .unwrap()
            .healthy
    );

    let (dir, base, state) = empty_replica("live-replica");
    assert!(live.run(Action::Pull, &base, &state).unwrap().healthy);
    let replica = Store::open(dir, origin.key);
    assert_eq!(replica.contents(), origin.contents());
    assert!(live.run(Action::Pull, &base, &state).unwrap().healthy);

    let files = live.files();
    assert_eq!(
        files
            .iter()
            .filter(|file| file.name.ends_with(".zr"))
            .count(),
        2
    );
    assert!(files.iter().any(|file| file.name.ends_with(".zpk")));
    let downloads = TestDir::new("live-download");
    for file in files.iter().filter(|file| !file.is_folder()) {
        let dest = downloads.path().join(&file.id);
        live.drive.download_to(file, &dest).unwrap();
        let bytes = std::fs::read(&dest).unwrap();
        assert!(
            !bytes.windows(CANARY.len()).any(|window| window == CANARY),
            "{} holds plaintext",
            file.name
        );
    }
}

#[test]
#[ignore = "requires ZDRIVE_RUN_GDRIVE_TESTS=1 and a remote configured by `zdrive remote auth`"]
fn live_diverged_writer_is_refused_and_records_survive() {
    let live = Live::start("writers");
    let mut origin = Store::origin("live-writers-origin");
    let origin_state = origin.dir.path().join("cli-state");
    live.run(Action::Push, &origin.base, &origin_state).unwrap();
    let (dir, base, state) = empty_replica("live-writers-replica");
    live.run(Action::Pull, &base, &state).unwrap();
    let mut replica = Store::open(dir, origin.key);

    origin.write("a.txt", content(6, 10));
    replica.write("a.txt", content(7, 10));
    live.run(Action::Push, &origin.base, &origin_state).unwrap();

    let refused = live.run(Action::Push, &base, &state);
    assert!(
        matches!(
            refused,
            Err(RemoteError::Diverged(_) | RemoteError::Conflict(_))
        ),
        "{refused:?}"
    );
    let pulled = live.run(Action::Pull, &base, &state);
    assert!(
        matches!(pulled, Err(RemoteError::Diverged(_))),
        "{pulled:?}"
    );
    assert!(!live.run(Action::Status, &base, &state).unwrap().healthy);
    let roots = live
        .files()
        .into_iter()
        .filter(|file| file.name.ends_with(".zr"))
        .count();
    assert_eq!(roots, 2);
    assert_eq!(replica.contents()["a.txt"], content(7, 10));
}

#[test]
#[ignore = "requires ZDRIVE_RUN_GDRIVE_TESTS=1, ZDRIVE_GDRIVE_KEEP=1 and a configured remote"]
fn live_scratch_folder() {
    let live = Live::start("scratch");
    assert!(
        live.keep,
        "set ZDRIVE_GDRIVE_KEEP=1, or the folder goes to the Drive bin at once"
    );
    assert!(live.files().is_empty());
}
