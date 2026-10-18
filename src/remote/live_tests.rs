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

use std::time::Instant;

use super::*;
use crate::remote::TestDir;
use crate::remote::gdrive::DriveFile;
use crate::remote::sync::tests::{CANARY, PASSPHRASE, Store, content};

const RUN_ENV: &str = "ZDRIVE_RUN_GDRIVE_TESTS";

struct Live {
    drive: GoogleDrive,
    folder: String,
    hint: String,
    keep: bool,
}

impl Live {
    fn start(label: &str) -> Self {
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
            client,
            refresh_token,
            &Endpoints::google(),
        )));
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
            hint,
            keep: std::env::var("ZDRIVE_GDRIVE_KEEP").as_deref() == Ok("1"),
        }
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
    fn run(&self, action: Action, base: &Path, state: &Path) -> Result<Summary, RemoteError> {
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
    fn files(&self) -> Vec<DriveFile> {
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
fn empty_replica(label: &str) -> (TestDir, PathBuf, PathBuf) {
    let dir = TestDir::new(label);
    let base = dir.path().join("store");
    std::fs::create_dir_all(&base).unwrap();
    let state = dir.path().join("cli-state");
    (dir, base, state)
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
