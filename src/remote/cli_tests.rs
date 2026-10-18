// SPDX-FileCopyrightText: Copyright 2026 Alexander Orlov <info@lifub.com>

use clap::Parser;

use super::*;
use crate::remote::TestDir;
use crate::remote::sync::tests::{Env, PASSPHRASE, Store, content, only_pack};

fn parse(arguments: &[&str]) -> Result<crate::Cli, clap::Error> {
    crate::Cli::try_parse_from(std::iter::once("zerotrust-drive").chain(arguments.iter().copied()))
}

fn remote_command(arguments: &[&str]) -> RemoteCommand {
    match parse(arguments) {
        Ok(cli) => match cli.command {
            Some(crate::Command::Remote(command)) => command,
            Some(_) => panic!("{arguments:?} parsed as another command"),
            None => panic!("{arguments:?} parsed without a command"),
        },
        Err(error) => panic!("{arguments:?}: {error}"),
    }
}

/// Runs one command the way `store_command` does after its lock and
/// credential steps.
fn run_command(
    env: &Env,
    action: Action,
    base: &Path,
    state: &Path,
) -> Result<Summary, RemoteError> {
    let kind = inspect_store(base, "store").map_err(RemoteError::Local)?;
    admit(action, kind, &RemoteName::parse("test").unwrap(), "store")?;
    execute(
        action,
        kind,
        &env.remote(),
        base,
        "store",
        PASSPHRASE,
        state,
    )
}

#[test]
fn remote_commands_parse_and_leave_the_mount_default_alone() {
    match remote_command(&["remote", "push", "--remote", "gd", "--encrypted-dir", "/s"]) {
        RemoteCommand::Push(args) => {
            assert_eq!(args.remote, "gd");
            assert_eq!(args.encrypted_dir, Path::new("/s"));
            assert!(args.passphrase.is_none());
        }
        other => panic!("{other:?}"),
    }
    match remote_command(&[
        "remote",
        "verify",
        "--remote",
        "gd",
        "--encrypted-dir",
        "/s",
        "--full",
    ]) {
        RemoteCommand::Verify(args) => assert!(args.full),
        other => panic!("{other:?}"),
    }
    match remote_command(&[
        "remote",
        "auth",
        "--remote",
        "gd",
        "--folder-id",
        "abc",
        "--folder-path",
        "a/b",
        "--no-browser",
    ]) {
        RemoteCommand::Auth(args) => {
            assert_eq!(args.folder_id.as_deref(), Some("abc"));
            assert_eq!(args.folder_path.as_deref(), Some("a/b"));
            assert!(args.no_browser);
        }
        other => panic!("{other:?}"),
    }
    let mount = parse(&["--encrypted-dir", "/e", "--decrypted-dir", "/m"]).unwrap();
    assert!(mount.command.is_none());
    assert_eq!(mount.encrypted_dir.as_deref(), Some(Path::new("/e")));

    // Mount flags never silently combine with a remote command, and a
    // store command never falls back to the default encrypted directory.
    assert!(
        parse(&[
            "--rekey",
            "remote",
            "push",
            "--remote",
            "gd",
            "--encrypted-dir",
            "/s"
        ])
        .is_err()
    );
    assert!(parse(&["remote", "push", "--remote", "gd"]).is_err());
    assert!(parse(&["remote", "pull", "--encrypted-dir", "/s"]).is_err());
}

#[test]
fn push_bootstrap_pull_status_and_verify_run_through_execute() {
    let env = Env::new();
    let mut origin = Store::origin("cli-origin");
    let origin_state = origin.dir.path().join("cli-state");
    let pushed = run_command(&env, Action::Push, &origin.base, &origin_state).unwrap();
    assert!(pushed.healthy);
    assert!(
        pushed.lines[0].starts_with("pushed generation"),
        "{pushed:?}"
    );

    let dir = TestDir::new("cli-replica");
    let base = dir.path().join("store");
    std::fs::create_dir_all(&base).unwrap();
    let replica_state = dir.path().join("cli-state");
    assert_eq!(inspect_store(&base, "replica").unwrap(), StoreKind::Absent);
    let cloned = run_command(&env, Action::Pull, &base, &replica_state).unwrap();
    assert!(
        cloned.lines[0].starts_with("new replica at generation"),
        "{cloned:?}"
    );
    assert_eq!(inspect_store(&base, "replica").unwrap(), StoreKind::V2);
    let status = run_command(&env, Action::Status, &base, &replica_state).unwrap();
    assert!(status.healthy);
    assert!(
        status.lines.contains(&"state: in sync".to_string()),
        "{status:?}"
    );

    origin.write("later.txt", content(9, 5_000));
    run_command(&env, Action::Push, &origin.base, &origin_state).unwrap();
    let behind = run_command(&env, Action::Status, &base, &replica_state).unwrap();
    assert!(
        behind
            .lines
            .contains(&"state: remote is ahead; pull".to_string()),
        "{behind:?}"
    );
    let pulled = run_command(&env, Action::Pull, &base, &replica_state).unwrap();
    assert!(
        pulled.lines[0].starts_with("pulled generation"),
        "{pulled:?}"
    );
    let again = run_command(&env, Action::Push, &base, &replica_state).unwrap();
    assert!(again.lines[0].starts_with("up to date"), "{again:?}");

    let verified = run_command(&env, Action::Verify { full: true }, &base, &replica_state).unwrap();
    assert!(verified.healthy, "{verified:?}");
    let replica = Store::open(dir, origin.key);
    assert_eq!(replica.contents(), origin.contents());
}

#[test]
fn a_wrong_passphrase_is_named_and_touches_no_sync_state() {
    let env = Env::new();
    let origin = Store::origin("cli-wrong");
    let state = origin.dir.path().join("cli-state");
    let kind = inspect_store(&origin.base, "store").unwrap();
    let error = execute(
        Action::Push,
        kind,
        &env.remote(),
        &origin.base,
        "store",
        "not the passphrase",
        &state,
    )
    .unwrap_err();
    assert!(
        matches!(&error, RemoteError::Auth(message) if message.contains("wrong passphrase")),
        "{error}"
    );
    assert!(!state.exists());
    assert!(
        env.fake
            .files()
            .iter()
            .all(|file| file.name == "zdrive-test")
    );
}

#[test]
fn only_pull_may_enter_an_unfinished_or_missing_store() {
    let name = RemoteName::parse("gd").unwrap();
    let dir = TestDir::new("cli-kinds");
    let base = dir.path();
    std::fs::write(base.join(sync::PULL_PENDING_FILE), b"").unwrap();
    assert_eq!(
        inspect_store(base, "d").unwrap(),
        StoreKind::PendingBootstrap
    );
    for action in [Action::Push, Action::Status, Action::Verify { full: false }] {
        let error = admit(action, StoreKind::PendingBootstrap, &name, "d").unwrap_err();
        assert!(
            error.to_string().contains("remote pull --remote gd"),
            "{error}"
        );
        assert!(admit(action, StoreKind::Absent, &name, "d").is_err());
    }
    admit(Action::Pull, StoreKind::PendingBootstrap, &name, "d").unwrap();
    admit(Action::Pull, StoreKind::Absent, &name, "d").unwrap();

    std::fs::remove_file(base.join(sync::PULL_PENDING_FILE)).unwrap();
    std::fs::write(base.join("_index.age"), b"v1").unwrap();
    assert_eq!(inspect_store(base, "d").unwrap(), StoreKind::V1);
    for action in [Action::Push, Action::Pull] {
        let error = admit(action, StoreKind::V1, &name, "d").unwrap_err();
        assert!(error.to_string().contains("--migrate-v2"), "{error}");
    }

    std::fs::write(base.join("_rekey.lock"), b"").unwrap();
    assert!(
        inspect_store(base, "d")
            .unwrap_err()
            .contains("_rekey.lock")
    );
}

#[test]
fn an_interrupted_first_pull_resumes_through_execute() {
    let env = Env::new();
    let origin = Store::origin("cli-resume-origin");
    let origin_state = origin.dir.path().join("cli-state");
    run_command(&env, Action::Push, &origin.base, &origin_state).unwrap();
    let pack = only_pack(&env);
    let mut damaged = pack.content.clone();
    damaged[100] ^= 0xff;
    env.fake.overwrite(&pack.id, &damaged);

    let dir = TestDir::new("cli-resume");
    let base = dir.path().join("store");
    std::fs::create_dir_all(&base).unwrap();
    let state = dir.path().join("cli-state");
    assert!(run_command(&env, Action::Pull, &base, &state).is_err());
    assert_eq!(
        inspect_store(&base, "replica").unwrap(),
        StoreKind::PendingBootstrap
    );
    assert!(run_command(&env, Action::Push, &base, &state).is_err());

    env.fake.overwrite(&pack.id, &pack.content);
    let resumed = run_command(&env, Action::Pull, &base, &state).unwrap();
    assert!(resumed.lines[0].starts_with("new replica"), "{resumed:?}");
    let replica = Store::open(dir, origin.key);
    assert_eq!(replica.contents(), origin.contents());
}

#[test]
fn summaries_flag_states_that_need_the_operator() {
    let status = |relation| StatusReport {
        local: 3,
        remote: Some(4),
        relation,
        packs: 2,
        pack_bytes: 3 << 20,
        damaged: 1,
        queued: 0,
        synced: None,
    };
    for relation in [
        Relation::Diverged,
        Relation::Forked,
        Relation::DifferentStore,
    ] {
        assert!(!status_summary(&status(relation)).healthy);
    }
    let ahead = status_summary(&status(Relation::RemoteAhead));
    assert!(ahead.healthy);
    assert!(
        ahead
            .lines
            .contains(&"remote packs: 2 (3.0 MiB)".to_string()),
        "{ahead:?}"
    );
    assert!(
        ahead
            .lines
            .iter()
            .any(|line| line.starts_with("damaged packs: 1"))
    );

    let clean = VerifyReport::default();
    assert!(verify_summary(&clean).healthy);
    let broken = VerifyReport {
        problems: vec!["pack x is damaged".to_string()],
        ..VerifyReport::default()
    };
    let summary = verify_summary(&broken);
    assert!(!summary.healthy);
    assert!(
        summary
            .lines
            .contains(&"problem: pack x is damaged".to_string())
    );
    assert_eq!(size(5 << 30), "5.00 GiB");
    assert_eq!(size(512), "512 bytes");
    assert_eq!(folder_hint("My Drive", "/a/b/"), "My Drive/a/b");
    assert_eq!(folder_hint("g.drive", ""), "g.drive");
}

fn choice<'a>() -> ClientChoice<'a> {
    ClientChoice {
        client_file: None,
        existing: None,
        device_code: false,
        no_browser: false,
        headless: false,
        bundled: (true, true),
        default_client_file: None,
    }
}

#[test]
fn client_choice_keeps_own_clients_and_prefers_the_device_flow_without_a_browser() {
    let desktop = Issuer::bundled(ClientKind::BundledDesktop);
    let device = Issuer::bundled(ClientKind::BundledDevice);
    let own = PathBuf::from("/c/client.json");

    assert_eq!(
        choose_client(choice()).unwrap(),
        (desktop.clone(), Flow::Browser)
    );
    assert_eq!(
        choose_client(ClientChoice {
            no_browser: true,
            ..choice()
        })
        .unwrap(),
        (desktop.clone(), Flow::Paste)
    );
    assert_eq!(
        choose_client(ClientChoice {
            headless: true,
            ..choice()
        })
        .unwrap(),
        (device.clone(), Flow::Device)
    );
    assert_eq!(
        choose_client(ClientChoice {
            device_code: true,
            ..choice()
        })
        .unwrap(),
        (device, Flow::Device)
    );

    // An explicit or already configured own client wins over bundled ones.
    assert_eq!(
        choose_client(ClientChoice {
            client_file: Some(own.clone()),
            headless: true,
            ..choice()
        })
        .unwrap(),
        (Issuer::byo(&own), Flow::Browser)
    );
    let configured = Issuer::byo(&own);
    assert_eq!(
        choose_client(ClientChoice {
            existing: Some(&configured),
            no_browser: true,
            ..choice()
        })
        .unwrap(),
        (Issuer::byo(&own), Flow::Paste)
    );
    let error = choose_client(ClientChoice {
        existing: Some(&configured),
        device_code: true,
        ..choice()
    })
    .unwrap_err();
    assert!(error.contains("--device-code"), "{error}");

    // A configured bundled remote follows the current host's flow.
    let bundled_remote = Issuer::bundled(ClientKind::BundledDesktop);
    assert_eq!(
        choose_client(ClientChoice {
            existing: Some(&bundled_remote),
            headless: true,
            ..choice()
        })
        .unwrap()
        .1,
        Flow::Device
    );
}

#[test]
fn client_choice_without_bundled_clients_falls_back_or_names_the_fix() {
    let desktop_only = ClientChoice {
        bundled: (true, false),
        ..choice()
    };
    assert_eq!(
        choose_client(ClientChoice {
            headless: true,
            ..desktop_only
        })
        .unwrap(),
        (Issuer::bundled(ClientKind::BundledDesktop), Flow::Paste)
    );
    let error = choose_client(ClientChoice {
        device_code: true,
        bundled: (true, false),
        ..choice()
    })
    .unwrap_err();
    assert!(error.contains("--client-file"), "{error}");

    let source_build = ClientChoice {
        bundled: (false, false),
        ..choice()
    };
    let legacy = PathBuf::from("/c/legacy.json");
    assert_eq!(
        choose_client(ClientChoice {
            default_client_file: Some(legacy.clone()),
            ..source_build
        })
        .unwrap(),
        (Issuer::byo(&legacy), Flow::Browser)
    );
    let error = choose_client(ClientChoice {
        bundled: (false, false),
        ..choice()
    })
    .unwrap_err();
    assert!(error.contains("--client-file"), "{error}");
}

#[test]
fn plain_remotes_always_end_in_a_marked_folder() {
    use crate::remote::fake::{FakeDrive, ROOT_ID};
    use crate::remote::gdrive::{FOLDER_MIME, MARKER_KEY, PLAIN_MARKER};

    let fake = FakeDrive::start();
    let drive = fake.client();
    let marker = |id: &str| {
        fake.file(id)
            .expect("folder exists")
            .app_properties
            .get(MARKER_KEY)
            .cloned()
    };
    let default = || FolderChoice::Marked {
        marker: PLAIN_MARKER,
        name: "ZeroTrust Drive (plain)".to_string(),
    };
    let path = |parent: &str, path: &str| FolderChoice::Path {
        parent: parent.to_string(),
        path: path.to_string(),
    };

    // The default folder is created marked in My Drive and joined again.
    let (first, hint) = choose_folder(&drive, RemoteMode::Plain, default(), true).unwrap();
    assert_eq!(hint, "ZeroTrust Drive (plain)");
    assert_eq!(marker(&first.id).as_deref(), Some(PLAIN_MARKER));
    let (again, _) = choose_folder(&drive, RemoteMode::Plain, default(), true).unwrap();
    assert_eq!(again.id, first.id);

    // An explicit path creates and marks exactly its last component, even
    // directly in My Drive, and is joined again by the same path.
    let (nested, _) = choose_folder(
        &drive,
        RemoteMode::Plain,
        path(ROOT_ID, "/Work/Sync/"),
        false,
    )
    .unwrap();
    assert_eq!(nested.name, "Sync");
    assert_eq!(marker(&nested.id).as_deref(), Some(PLAIN_MARKER));
    let work = fake.file(&nested.parents[0]).unwrap();
    assert_eq!(work.name, "Work");
    assert!(work.app_properties.is_empty(), "{work:?}");
    let (rejoined, _) =
        choose_folder(&drive, RemoteMode::Plain, path(ROOT_ID, "Work/Sync"), false).unwrap();
    assert_eq!(rejoined.id, nested.id);
    let (top, _) = choose_folder(&drive, RemoteMode::Plain, path(ROOT_ID, "Top"), false).unwrap();
    assert_eq!(top.name, "Top");
    assert_ne!(top.id, first.id);
    assert_eq!(marker(&top.id).as_deref(), Some(PLAIN_MARKER));

    // A configured remote re-authorizes onto its own marked folder.
    let (same, _) = choose_folder(&drive, RemoteMode::Plain, path(&first.id, ""), false).unwrap();
    assert_eq!(same.id, first.id);

    // A folder zdrive did not mark is never adopted, by path or by id, and
    // stays unmarked.
    let foreign = fake.insert(ROOT_ID, "Mine", Some(FOLDER_MIME), b"");
    let error = choose_folder(&drive, RemoteMode::Plain, path(ROOT_ID, "Mine"), false).unwrap_err();
    assert!(error.contains(&foreign), "{error}");
    let error = choose_folder(&drive, RemoteMode::Plain, path(&foreign, ""), false).unwrap_err();
    assert!(error.contains("not marked for plain sync"), "{error}");
    assert!(error.contains("--folder-path"), "{error}");
    assert_eq!(marker(&foreign), None);

    // Encrypted path folders stay unmarked, as before.
    let (vault, _) =
        choose_folder(&drive, RemoteMode::Encrypted, path(ROOT_ID, "Vault"), false).unwrap();
    assert_eq!(marker(&vault.id), None);
}

#[test]
fn bundled_folder_paths_work_although_drive_file_hides_my_drive() {
    use crate::remote::fake::{FakeDrive, ROOT_REAL_ID};
    use crate::remote::gdrive::MY_DRIVE;

    let fake = FakeDrive::start();
    fake.hide_my_drive_root(true);
    let drive = fake.client();
    let path = |parent: &str, path: &str| FolderChoice::Path {
        parent: parent.to_string(),
        path: path.to_string(),
    };
    let choose =
        |mode, parent: &str, folder: &str| choose_folder(&drive, mode, path(parent, folder), true);

    let (vault, hint) = choose(RemoteMode::Encrypted, MY_DRIVE, "zdrive-tests/enc").unwrap();
    assert_eq!(hint, "My Drive/zdrive-tests/enc");
    let (nested, _) = choose(RemoteMode::Plain, MY_DRIVE, "zdrive-tests/plain").unwrap();
    let (top, _) = choose(RemoteMode::Plain, MY_DRIVE, "Top").unwrap();
    assert_eq!(fake.file(&top.id).unwrap().parents, [ROOT_REAL_ID]);

    // A second machine joins every folder instead of creating a duplicate,
    // although Drive reports My Drive's real id, not the alias, as parent.
    assert_eq!(
        choose(RemoteMode::Encrypted, MY_DRIVE, "zdrive-tests/enc")
            .unwrap()
            .0
            .id,
        vault.id
    );
    assert_eq!(
        choose(RemoteMode::Plain, MY_DRIVE, "zdrive-tests/plain")
            .unwrap()
            .0
            .id,
        nested.id
    );
    assert_eq!(
        choose(RemoteMode::Plain, MY_DRIVE, "Top").unwrap().0.id,
        top.id
    );
    let mut names: Vec<String> = fake
        .children(MY_DRIVE)
        .into_iter()
        .map(|f| f.name)
        .collect();
    names.sort();
    assert_eq!(names, ["Top", "zdrive-tests"]);

    // A folder id the bundled client cannot see keeps its guidance.
    let error = choose(RemoteMode::Encrypted, "invisible", "").unwrap_err();
    assert!(
        error.contains("bundled sign-in sees only folders zdrive created"),
        "{error}"
    );
}
