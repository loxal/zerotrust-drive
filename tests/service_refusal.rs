// SPDX-FileCopyrightText: Copyright 2026 Alexander Orlov <info@lifub.com>

//! A service instance that can never start must not be restarted forever.
//!
//! Runs the shipped binary the way `zdrive service run` execs it, against a
//! copy of the committed v2 format fixture with a wrong passphrase. The
//! passphrase is checked before anything is mounted, so this needs no FUSE.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

const NAME: &str = "home";

struct Sandbox(PathBuf);

impl Sandbox {
    fn new(label: &str) -> Self {
        let root = std::env::temp_dir().join(format!(
            "zdrive-service-refusal-{label}-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&root);
        copy_tree(
            &Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/format/v2"),
            &root.join("store"),
        );
        fs::create_dir_all(root.join("home")).unwrap();
        Self(root)
    }

    fn run(&self, armed: bool) -> Output {
        let mut command = Command::new(env!("CARGO_BIN_EXE_zerotrust-drive"));
        command
            .arg("--encrypted-dir")
            .arg(self.0.join("store"))
            .arg("--decrypted-dir")
            .arg(self.0.join("mnt"));
        if armed {
            command.args(["--telemetry-instance", NAME, "--service"]);
        }
        command
            .env("HOME", self.0.join("home"))
            .env("XDG_CONFIG_HOME", self.0.join("config"))
            .env("XDG_STATE_HOME", self.0.join("state"))
            .env("XDG_DATA_HOME", self.0.join("data"))
            .env("ZEROTRUST_PASSPHRASE", "not-the-fixture-passphrase")
            .env("ZDRIVE_TELEMETRY", "standard")
            .env_remove("NOTIFY_SOCKET")
            .env_remove("CREDENTIALS_DIRECTORY")
            .output()
            .unwrap()
    }

    fn record(&self) -> PathBuf {
        self.0
            .join("state/zerotrust-drive/services")
            .join(format!("{NAME}.refusal.json"))
    }

    fn telemetry(&self) -> String {
        let dir = self.0.join("state/zerotrust-drive/telemetry").join(NAME);
        let Ok(entries) = fs::read_dir(&dir) else {
            return String::new();
        };
        entries
            .map(|entry| fs::read_to_string(entry.unwrap().path()).unwrap())
            .collect()
    }
}

impl Drop for Sandbox {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn copy_tree(source: &Path, target: &Path) {
    fs::create_dir_all(target).unwrap();
    for entry in fs::read_dir(source).unwrap() {
        let entry = entry.unwrap();
        let destination = target.join(entry.file_name());
        if entry.file_type().unwrap().is_dir() {
            copy_tree(&entry.path(), &destination);
        } else {
            fs::copy(entry.path(), destination).unwrap();
        }
    }
}

#[test]
fn a_service_with_a_wrong_passphrase_is_refused_and_recorded() {
    let sandbox = Sandbox::new("armed");
    let output = sandbox.run(true);
    let stderr = String::from_utf8_lossy(&output.stderr);
    // launchd restarts only a failed exit; systemd skips exit status 78.
    let expected = if cfg!(target_os = "macos") { 0 } else { 78 };
    assert_eq!(output.status.code(), Some(expected), "{stderr}");
    assert!(stderr.contains("refused (passphrase)"), "{stderr}");
    // The drive runs relative to its store; the refusal names the store.
    let store = fs::canonicalize(sandbox.0.join("store")).unwrap();
    let message = format!(
        "wrong passphrase: it does not open the v2 root of {}",
        store.display()
    );
    assert!(stderr.contains(&message), "{stderr}");

    let record = fs::read_to_string(sandbox.record()).unwrap();
    assert!(record.contains("\"class\": \"passphrase\""), "{record}");
    assert!(record.contains(&message), "{record}");
    assert!(record.contains(env!("CARGO_PKG_VERSION")), "{record}");
    assert!(!record.contains("not-the-fixture-passphrase"));

    let telemetry = sandbox.telemetry();
    assert!(telemetry.contains("service.refused"), "{telemetry}");
    assert!(telemetry.contains("\"refused\""), "{telemetry}");
    assert!(!telemetry.contains("not-the-fixture-passphrase"));
    assert!(!telemetry.contains(sandbox.0.to_str().unwrap()));
}

#[test]
fn an_interactive_mount_with_a_wrong_passphrase_is_an_ordinary_error() {
    // Expected failing control: without `--service` nothing is armed, so the
    // same failure keeps exit status 1 and leaves no record.
    let sandbox = Sandbox::new("unarmed");
    let output = sandbox.run(false);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(1), "{stderr}");
    assert!(stderr.contains("wrong passphrase"), "{stderr}");
    assert!(!stderr.contains("refused"), "{stderr}");
    assert!(!sandbox.record().exists());
}
