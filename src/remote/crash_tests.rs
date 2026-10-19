// SPDX-FileCopyrightText: Copyright 2026 Alexander Orlov <info@lifub.com>

//! Subprocess SIGKILL matrix. A re-executed copy of this test binary runs
//! a real `push` or `pull` against the fake server, which withholds the
//! answer to one request at a chosen checkpoint, and the parent kills the
//! child there. A new replica must then see exactly the old or the new
//! generation, and the next command must finish what the killed one began
//! without duplicating anything on the remote.

use std::collections::BTreeMap;
use std::os::unix::process::ExitStatusExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use super::cli::{Action, StoreKind, execute, inspect_store};
use super::fake::{FakeDrive, Hold, Op, REFRESH_TOKEN};
use super::gdrive::GoogleDrive;
use super::oauth::{Endpoints, RefreshTokenSource, test_client};
use super::sync::Remote;
use super::sync::tests::{
    Env, PASSPHRASE, Store, content, damaged_evidence, object_files, quiet, tear,
};
use super::{RemoteError, TestDir};
use crate::fault::{DurabilityCheckpoint, DurabilityEvent, FaultInjectionGuard};
use crate::v2::replica::{INSTALL_CONTEXT, SYNC_INSTALLED_CONTEXT};

const CHILD: &str = "ZDRIVE_CRASH_CHILD";
/// The upload sizes of [`Env::resumable`].
const RESUMABLE: u64 = 256 << 10;

type Files = BTreeMap<String, Vec<u8>>;

/// The child half: runs one command the way the CLI does and must be
/// killed before it returns. Without [`CHILD`] it is an empty test.
#[test]
fn crash_child() {
    let Ok(spec) = std::env::var(CHILD) else {
        return;
    };
    let fields: Vec<&str> = spec.split('\n').collect();
    let [
        action,
        base_url,
        folder,
        store,
        state,
        resumable,
        checkpoint,
    ] = fields[..]
    else {
        panic!("malformed child spec {spec:?}");
    };
    let _armed = (!checkpoint.is_empty()).then(|| {
        let parts: Vec<&str> = checkpoint.split('\t').collect();
        let [event, context, occurrence] = parts[..] else {
            panic!("malformed checkpoint spec {checkpoint:?}");
        };
        let event = match event {
            "FileSync" => DurabilityEvent::FileSync,
            "DirectorySync" => DurabilityEvent::DirectorySync,
            other => panic!("unsupported checkpoint event {other}"),
        };
        FaultInjectionGuard::kill_at_matching(
            DurabilityCheckpoint::new(event, context),
            occurrence.parse().expect("checkpoint occurrence"),
        )
    });
    let endpoints = Endpoints {
        auth: format!("{base_url}/auth"),
        token: format!("{base_url}/token"),
        device: format!("{base_url}/device/code"),
    };
    let tokens = RefreshTokenSource::new(test_client(), REFRESH_TOKEN.to_string(), &endpoints);
    let mut drive =
        GoogleDrive::with_endpoint(base_url, Box::new(tokens), FakeDrive::fast_policy());
    if resumable == "1" {
        drive = drive.with_upload_sizes(RESUMABLE, RESUMABLE);
    }
    let remote = Remote {
        drive: &drive,
        folder_id: folder,
        log: &quiet,
    };
    let action = match action {
        "push" => Action::Push,
        "pull" => Action::Pull,
        other => panic!("unknown action {other}"),
    };
    let store = Path::new(store);
    let kind = inspect_store(store, "store").expect("inspect store");
    let result = execute(
        action,
        kind,
        &remote,
        store,
        "store",
        PASSPHRASE,
        Path::new(state),
    );
    eprintln!("the crash child was never held and finished with {result:?}");
    std::process::exit(3);
}

/// Starts `action` on `store` in a child process; a non-empty `checkpoint`
/// (event, context and occurrence, tab-separated) makes the child SIGKILL
/// itself there.
fn spawn_child(
    env: &Env,
    resumable: bool,
    action: &str,
    store: &Path,
    state: &Path,
    checkpoint: &str,
) -> Child {
    let module = module_path!()
        .split_once("::")
        .map_or(module_path!(), |(_, path)| path);
    let spec = [
        action,
        env.fake.base_url(),
        &env.folder,
        store.to_str().expect("utf-8 store path"),
        state.to_str().expect("utf-8 state path"),
        if resumable { "1" } else { "0" },
        checkpoint,
    ]
    .join("\n");
    Command::new(std::env::current_exe().expect("test binary"))
        .args([
            "--exact",
            &format!("{module}::crash_child"),
            "--nocapture",
            "--test-threads=1",
        ])
        .env(CHILD, spec)
        .env_remove("ZEROTRUST_PASSPHRASE")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn the crash child")
}

/// Runs `action` on `store` in a child process and SIGKILLs it as soon as
/// the server holds the request `hold` describes.
fn kill_at(env: &Env, resumable: bool, action: &str, store: &Path, state: &Path, hold: Hold) {
    let before = env.fake.held();
    env.fake.hold(hold.clone());
    let mut child = spawn_child(env, resumable, action, store, state, "");
    let deadline = Instant::now() + Duration::from_secs(60);
    while env.fake.held() == before {
        if child.try_wait().expect("poll the child").is_some() {
            let output = child.wait_with_output().expect("child output");
            panic!(
                "the child ended ({}) before {hold:?}: {}",
                output.status,
                String::from_utf8_lossy(&output.stderr)
            );
        }
        if Instant::now() > deadline {
            let _ = child.kill();
            panic!("{hold:?} was never reached");
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    child.kill().expect("SIGKILL the child");
    let status = child.wait().expect("reap the child");
    assert_eq!(status.signal(), Some(9), "{status}");
}

/// Runs `action` on `store` in a child process that SIGKILLs itself at the
/// `occurrence`th durability checkpoint of `event` in `context`.
fn kill_at_checkpoint(
    env: &Env,
    action: &str,
    store: &Path,
    state: &Path,
    event: DurabilityEvent,
    context: &str,
    occurrence: usize,
) {
    let checkpoint = format!("{event:?}\t{context}\t{occurrence}");
    let mut child = spawn_child(env, false, action, store, state, &checkpoint);
    let deadline = Instant::now() + Duration::from_secs(60);
    while child.try_wait().expect("poll the child").is_none() {
        if Instant::now() > deadline {
            let _ = child.kill();
            panic!("the child never reached {checkpoint:?}");
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    let output = child.wait_with_output().expect("child output");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(
        output.status.signal(),
        Some(9),
        "{}: {stderr}",
        output.status
    );
    assert!(
        stderr.contains(&format!("\t{event:?}\t{context}\n")),
        "killed elsewhere: {stderr}"
    );
}

fn command(env: &Env, action: Action, base: &Path, state: &Path) -> Result<(), RemoteError> {
    let kind = inspect_store(base, "store").map_err(RemoteError::Local)?;
    execute(
        action,
        kind,
        &env.remote(),
        base,
        "store",
        PASSPHRASE,
        state,
    )
    .map(drop)
}

/// What a new replica authenticates from the remote.
fn fresh_pull(env: &Env, key: [u8; 32]) -> (u64, Files) {
    let dir = TestDir::new("crash-fresh");
    let base = dir.path().join("store");
    std::fs::create_dir_all(&base).unwrap();
    command(env, Action::Pull, &base, &dir.path().join("state")).unwrap();
    let replica = Store::open(dir, key);
    (replica.head.number, replica.contents())
}

/// An origin whose first generation is on the remote and whose second is
/// committed locally only, with a new file of `extra` bytes.
struct OneAhead {
    origin: Store,
    state: PathBuf,
    old: (u64, Files),
}

impl OneAhead {
    fn new(env: &Env, label: &str, extra: usize) -> Self {
        let mut origin = Store::origin(label);
        let state = origin.dir.path().join("cli-state");
        command(env, Action::Push, &origin.base, &state).unwrap();
        let old = (origin.head.number, origin.contents());
        origin.write("c.bin", content(3, extra));
        Self { origin, state, old }
    }

    fn new_generation(&self) -> (u64, Files) {
        (self.origin.head.number, self.origin.contents())
    }
}

/// Kills a push at `hold`, then proves the remote and the resumed push.
fn push_killed_at(env: &Env, resumable: bool, extra: usize, hold: Hold, root_committed: bool) {
    let ahead = OneAhead::new(env, "crash-push", extra);
    kill_at(
        env,
        resumable,
        "push",
        &ahead.origin.base,
        &ahead.state,
        hold,
    );
    let expected = if root_committed {
        ahead.new_generation()
    } else {
        ahead.old.clone()
    };
    assert_eq!(
        fresh_pull(env, ahead.origin.key),
        expected,
        "after the kill"
    );

    command(env, Action::Push, &ahead.origin.base, &ahead.state).unwrap();
    assert_eq!(
        fresh_pull(env, ahead.origin.key),
        ahead.new_generation(),
        "after the resumed push"
    );
    assert_eq!(env.named(".zpk").len(), 2, "one pack per generation");
    assert_eq!(env.named(".zr").len(), 2, "one root record per generation");
}

fn hold(op: Op, suffix: &'static str, skip: usize, commit: bool) -> Hold {
    Hold {
        op,
        suffix,
        skip,
        commit,
    }
}

#[test]
fn a_push_killed_before_its_pack_exists_resumes() {
    let env = Env::new();
    push_killed_at(
        &env,
        false,
        1_000,
        hold(Op::Multipart, ".zpk", 0, false),
        false,
    );
}

#[test]
fn a_push_killed_after_its_pack_committed_adopts_that_pack() {
    let env = Env::new();
    push_killed_at(
        &env,
        false,
        1_000,
        hold(Op::Multipart, ".zpk", 0, true),
        false,
    );
}

#[test]
fn a_push_killed_mid_upload_resumes_its_persisted_session() {
    let env = Env::resumable();
    push_killed_at(
        &env,
        true,
        700_000,
        hold(Op::Chunk, ".zpk", 1, false),
        false,
    );
    // One session per pack, the first generation's and the killed push's:
    // the resumed push continues the latter instead of starting another.
    assert_eq!(env.fake.count(Op::StartSession), 2);
    assert!(env.fake.count(Op::QuerySession) > 0);
}

#[test]
fn a_push_killed_before_its_root_record_exists_keeps_the_old_generation() {
    let env = Env::new();
    push_killed_at(
        &env,
        false,
        1_000,
        hold(Op::Multipart, ".zr", 0, false),
        false,
    );
}

#[test]
fn a_push_killed_after_its_root_record_committed_converges() {
    let env = Env::new();
    push_killed_at(
        &env,
        false,
        1_000,
        hold(Op::Multipart, ".zr", 0, true),
        true,
    );
}

#[test]
fn a_pull_killed_mid_download_keeps_the_old_generation_and_resumes() {
    let env = Env::new();
    let ahead = OneAhead::new(&env, "crash-pull-origin", 1_000);
    let replica = TestDir::new("crash-pull");
    let base = replica.path().join("store");
    std::fs::create_dir_all(&base).unwrap();
    let state = replica.path().join("cli-state");
    command(&env, Action::Pull, &base, &state).unwrap();
    command(&env, Action::Push, &ahead.origin.base, &ahead.state).unwrap();

    kill_at(
        &env,
        false,
        "pull",
        &base,
        &state,
        hold(Op::Media, ".zpk", 0, false),
    );
    let killed = Store::open(replica, ahead.origin.key);
    assert_eq!((killed.head.number, killed.contents()), ahead.old);

    let Store { dir: replica, .. } = killed;
    command(&env, Action::Pull, &base, &state).unwrap();
    let resumed = Store::open(replica, ahead.origin.key);
    assert_eq!(
        (resumed.head.number, resumed.contents()),
        ahead.new_generation()
    );
}

#[test]
fn a_first_pull_killed_mid_download_resumes_the_bootstrap() {
    let env = Env::new();
    let ahead = OneAhead::new(&env, "crash-bootstrap-origin", 1_000);
    command(&env, Action::Push, &ahead.origin.base, &ahead.state).unwrap();
    let replica = TestDir::new("crash-bootstrap");
    let base = replica.path().join("store");
    std::fs::create_dir_all(&base).unwrap();
    let state = replica.path().join("cli-state");

    kill_at(
        &env,
        false,
        "pull",
        &base,
        &state,
        hold(Op::Media, ".zpk", 0, false),
    );
    assert_eq!(
        inspect_store(&base, "replica").unwrap(),
        StoreKind::PendingBootstrap
    );

    command(&env, Action::Pull, &base, &state).unwrap();
    let resumed = Store::open(replica, ahead.origin.key);
    assert_eq!(
        (resumed.head.number, resumed.contents()),
        ahead.new_generation()
    );
}

/// A replica one generation behind the origin's remote, both through the CLI.
fn behind(env: &Env, label: &str) -> (OneAhead, TestDir, PathBuf, PathBuf) {
    let ahead = OneAhead::new(env, label, 200_000);
    let replica = TestDir::new(label);
    let base = replica.path().join("store");
    std::fs::create_dir_all(&base).unwrap();
    let state = replica.path().join("cli-state");
    command(env, Action::Pull, &base, &state).unwrap();
    command(env, Action::Push, &ahead.origin.base, &ahead.state).unwrap();
    (ahead, replica, base, state)
}

#[test]
fn a_pull_killed_before_its_barrier_replaces_torn_objects_when_resumed() {
    let env = Env::new();
    let (ahead, replica, base, state) = behind(&env, "crash-pull-installs");
    let before = object_files(&base);

    kill_at_checkpoint(
        &env,
        "pull",
        &base,
        &state,
        DurabilityEvent::FileSync,
        INSTALL_CONTEXT,
        2,
    );
    let installed: Vec<_> = object_files(&base).difference(&before).cloned().collect();
    assert_eq!(installed.len(), 2, "{installed:?}");
    // SIGKILL keeps the page cache; power loss before the barrier may not.
    let torn = tear(&installed[0], true);
    let killed = Store::open(replica, ahead.origin.key);
    assert_eq!((killed.head.number, killed.contents()), ahead.old);

    let Store { dir: replica, .. } = killed;
    command(&env, Action::Pull, &base, &state).unwrap();
    let resumed = Store::open(replica, ahead.origin.key);
    assert_eq!(
        (resumed.head.number, resumed.contents()),
        ahead.new_generation()
    );
    assert_eq!(damaged_evidence(&state), vec![torn]);
}

#[test]
fn a_pull_killed_at_its_barrier_has_published_nothing_and_resumes() {
    let env = Env::new();
    let (ahead, replica, base, state) = behind(&env, "crash-pull-barrier");

    kill_at_checkpoint(
        &env,
        "pull",
        &base,
        &state,
        DurabilityEvent::DirectorySync,
        SYNC_INSTALLED_CONTEXT,
        1,
    );
    let killed = Store::open(replica, ahead.origin.key);
    assert_eq!((killed.head.number, killed.contents()), ahead.old);

    let Store { dir: replica, .. } = killed;
    command(&env, Action::Pull, &base, &state).unwrap();
    let resumed = Store::open(replica, ahead.origin.key);
    assert_eq!(
        (resumed.head.number, resumed.contents()),
        ahead.new_generation()
    );
    assert!(damaged_evidence(&state).is_empty());
}

#[test]
fn a_first_pull_killed_before_its_barrier_resumes_with_torn_objects() {
    let env = Env::new();
    let ahead = OneAhead::new(&env, "crash-bootstrap-installs", 200_000);
    command(&env, Action::Push, &ahead.origin.base, &ahead.state).unwrap();
    let replica = TestDir::new("crash-bootstrap-installs");
    let base = replica.path().join("store");
    std::fs::create_dir_all(&base).unwrap();
    let state = replica.path().join("cli-state");

    kill_at_checkpoint(
        &env,
        "pull",
        &base,
        &state,
        DurabilityEvent::FileSync,
        INSTALL_CONTEXT,
        3,
    );
    assert_eq!(
        inspect_store(&base, "replica").unwrap(),
        StoreKind::PendingBootstrap
    );
    let installed: Vec<_> = object_files(&base).into_iter().collect();
    assert_eq!(installed.len(), 3, "{installed:?}");
    let mut torn = vec![tear(&installed[0], false), tear(&installed[2], true)];
    torn.sort();

    command(&env, Action::Pull, &base, &state).unwrap();
    let resumed = Store::open(replica, ahead.origin.key);
    assert_eq!(
        (resumed.head.number, resumed.contents()),
        ahead.new_generation()
    );
    assert_eq!(damaged_evidence(&state), torn);
}

#[test]
fn a_first_pull_killed_at_its_barrier_resumes_the_bootstrap() {
    let env = Env::new();
    let ahead = OneAhead::new(&env, "crash-bootstrap-barrier", 1_000);
    command(&env, Action::Push, &ahead.origin.base, &ahead.state).unwrap();
    let replica = TestDir::new("crash-bootstrap-barrier");
    let base = replica.path().join("store");
    std::fs::create_dir_all(&base).unwrap();
    let state = replica.path().join("cli-state");

    kill_at_checkpoint(
        &env,
        "pull",
        &base,
        &state,
        DurabilityEvent::DirectorySync,
        SYNC_INSTALLED_CONTEXT,
        1,
    );
    assert_eq!(
        inspect_store(&base, "replica").unwrap(),
        StoreKind::PendingBootstrap
    );

    command(&env, Action::Pull, &base, &state).unwrap();
    let resumed = Store::open(replica, ahead.origin.key);
    assert_eq!(
        (resumed.head.number, resumed.contents()),
        ahead.new_generation()
    );
}
