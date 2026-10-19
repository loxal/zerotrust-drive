// SPDX-FileCopyrightText: Copyright 2026 Alexander Orlov <info@lifub.com>

//! Subprocess SIGKILL tests. A re-executed copy of this test binary runs
//! one plain sync cycle against the fake server, which withholds the answer
//! to one request (after applying it, where the test says so), and the
//! parent kills the child there. A temporary file must never have replaced
//! a real one, and a cycle in the parent must converge without losing or
//! duplicating anything.

use std::os::unix::process::ExitStatusExt;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use super::tests::{Env, Replica, Tree, assert_converged, conflicts, settle, tree};
use super::{PlainOptions, sync_once};
use crate::remote::fake::{FakeDrive, Fault, Hold, Op, REFRESH_TOKEN};
use crate::remote::gdrive::GoogleDrive;
use crate::remote::oauth::{Endpoints, RefreshTokenSource, test_client};

const CHILD: &str = "ZDRIVE_PLAIN_CRASH_CHILD";

/// The child half: runs one cycle and must be killed before it returns.
/// Without [`CHILD`] it is an empty test.
#[test]
fn crash_child() {
    let Ok(spec) = std::env::var(CHILD) else {
        return;
    };
    let fields: Vec<&str> = spec.split('\n').collect();
    let [
        base_url,
        folder,
        local_dir,
        state_file,
        trash_dir,
        resumable,
        mirror,
    ] = fields[..]
    else {
        panic!("malformed child spec {spec:?}");
    };
    let endpoints = Endpoints {
        auth: format!("{base_url}/auth"),
        token: format!("{base_url}/token"),
        device: format!("{base_url}/device/code"),
    };
    let tokens = RefreshTokenSource::new(test_client(), REFRESH_TOKEN.to_string(), &endpoints);
    let mut drive =
        GoogleDrive::with_endpoint(base_url, Box::new(tokens), FakeDrive::fast_policy());
    if resumable == "1" {
        drive = drive.with_upload_sizes(1024, 256 << 10);
    }
    let options = PlainOptions {
        local_dir: local_dir.into(),
        folder_id: folder.to_string(),
        state_file: state_file.into(),
        trash_dir: trash_dir.into(),
        host: "child".to_string(),
        stable_age: Duration::ZERO,
        mirror: mirror == "1",
        allow_deletions: None,
        progress: None,
    };
    let result = sync_once(&drive, &options);
    eprintln!("the crash child was never held and finished with {result:?}");
    std::process::exit(3);
}

/// Runs a cycle of `replica` in a child process and SIGKILLs it as soon
/// as the server holds the request `hold` describes.
fn kill_at(env: &Env, replica: &Replica, resumable: bool, hold: Hold) {
    let before = env.fake.held();
    env.fake.hold(hold.clone());
    let module = module_path!()
        .split_once("::")
        .map_or(module_path!(), |(_, path)| path);
    let path = |path: &std::path::Path| path.to_str().expect("utf-8 test path").to_string();
    let spec = [
        env.fake.base_url().to_string(),
        replica.options.folder_id.clone(),
        path(&replica.options.local_dir),
        path(&replica.options.state_file),
        path(&replica.options.trash_dir),
        if resumable { "1" } else { "0" }.to_string(),
        if replica.options.mirror { "1" } else { "0" }.to_string(),
    ]
    .join("\n");
    let mut child = Command::new(std::env::current_exe().expect("test binary"))
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
        .expect("spawn the crash child");
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
    env.fake.release_held();
}

fn hold(op: Op, suffix: &'static str, skip: usize, commit: bool) -> Hold {
    Hold {
        op,
        suffix,
        skip,
        commit,
    }
}

/// Converges after the kill, without conflict copies or duplicates.
fn recover(env: &Env, replica: &Replica, expected: &Tree) {
    settle(replica, &env.drive);
    let local = assert_converged(&env.fake, &env.drive, replica);
    assert_eq!(conflicts(&local), Vec::new());
    assert_eq!(&local, expected);
    let live = env
        .fake
        .files()
        .into_iter()
        .filter(|file| !file.trashed)
        .count();
    assert_eq!(live, expected.len() + 1, "no duplicate on Drive");
}

#[test]
fn killed_mid_download_the_local_file_stays_intact() {
    let env = Env::new();
    let a = env.replica("kill-download-a");
    let b = env.replica("kill-download-b");
    let old = vec![b'o'; 4096];
    let new = vec![b'n'; 8192];
    a.write("f.bin", &old);
    a.sync(&env.drive);
    b.sync(&env.drive);
    a.write("f.bin", &new);
    a.sync(&env.drive);
    // The first answer is cut short; the child resumes and is held there.
    env.fake.fault(Op::Media, Fault::TruncateBody(1000));
    kill_at(&env, &b, false, hold(Op::Media, "f.bin", 1, false));
    assert_eq!(b.read("f.bin"), old, "a partial download replaced the file");
    let partial: Vec<String> = b.debris();
    assert_eq!(partial.len(), 1, "{partial:?}");
    assert!(partial[0].starts_with(".zdrive-tmp-"), "{partial:?}");
    recover(&env, &b, &tree(&[("f.bin", Some(&new))]));
    assert!(b.trash().contains(&("f.bin".to_string(), old)));
}

#[test]
fn killed_after_a_create_was_applied_the_file_is_adopted() {
    let env = Env::new();
    let replica = env.replica("kill-create");
    replica.write("keep.txt", b"keep");
    replica.sync(&env.drive);
    replica.write("new/created.txt", b"created");
    kill_at(
        &env,
        &replica,
        false,
        hold(Op::CreateFolder, "new", 0, true),
    );
    replica.write("new/created.txt", b"created");
    kill_at(
        &env,
        &replica,
        false,
        hold(Op::Multipart, "created.txt", 0, true),
    );
    recover(
        &env,
        &replica,
        &tree(&[
            ("keep.txt", Some(b"keep")),
            ("new", None),
            ("new/created.txt", Some(b"created")),
        ]),
    );
}

#[test]
fn killed_after_an_edit_was_uploaded_nothing_conflicts() {
    let env = Env::new();
    let replica = env.replica("kill-update");
    replica.write("edit.txt", b"v1");
    replica.sync(&env.drive);
    let id = env.id("edit.txt");
    replica.write("edit.txt", b"v2, longer");
    kill_at(
        &env,
        &replica,
        false,
        hold(Op::UpdateMedia, "edit.txt", 0, true),
    );
    assert_eq!(env.fake.file(&id).unwrap().content, b"v2, longer");
    recover(&env, &replica, &tree(&[("edit.txt", Some(b"v2, longer"))]));
    assert_eq!(env.id("edit.txt"), id);
}

#[test]
fn killed_after_a_move_or_trash_was_applied_both_complete() {
    let env = Env::new();
    let replica = env.replica("kill-move");
    replica.write("move.txt", b"move");
    replica.write("delete.txt", b"delete");
    replica.write("dir/x.txt", b"x");
    replica.sync(&env.drive);
    let moved = env.id("move.txt");
    let deleted = env.id("delete.txt");
    std::fs::rename(replica.path("move.txt"), replica.path("dir/moved.txt")).unwrap();
    kill_at(&env, &replica, false, hold(Op::Patch, "move.txt", 0, true));
    std::fs::remove_file(replica.path("delete.txt")).unwrap();
    kill_at(
        &env,
        &replica,
        false,
        hold(Op::Patch, "delete.txt", 0, true),
    );
    assert!(env.fake.file(&deleted).unwrap().trashed);
    recover(
        &env,
        &replica,
        &tree(&[
            ("dir", None),
            ("dir/moved.txt", Some(b"move")),
            ("dir/x.txt", Some(b"x")),
        ]),
    );
    assert_eq!(env.id("dir/moved.txt"), moved);
}

#[test]
fn killed_mid_resumable_upload_the_next_cycle_uploads_once() {
    let env = Env::resumable();
    let replica = env.replica("kill-resumable");
    let big: Vec<u8> = (0..(700u32 << 10))
        .map(|index| (index % 251) as u8)
        .collect();
    replica.write("big.bin", &big);
    kill_at(&env, &replica, true, hold(Op::Chunk, "big.bin", 1, false));
    recover(&env, &replica, &tree(&[("big.bin", Some(&big))]));
}

#[test]
fn killed_while_applying_remote_changes_the_next_cycle_finishes() {
    let env = Env::new();
    let a = env.replica("kill-pull-a");
    let b = env.replica("kill-pull-b");
    a.write("one.txt", b"one");
    a.write("two.txt", b"two");
    a.write("three.txt", b"three");
    a.sync(&env.drive);
    b.sync(&env.drive);
    a.write("one.txt", b"one, edited");
    std::fs::rename(a.path("two.txt"), a.path("two-renamed.txt")).unwrap();
    std::fs::remove_file(a.path("three.txt")).unwrap();
    a.write("four.txt", b"four");
    a.sync(&env.drive);
    // The cycle on b is killed while downloading the second new version.
    kill_at(&env, &b, false, hold(Op::Media, ".txt", 1, false));
    recover(&env, &b, &a.tree());
}

#[test]
fn a_mirror_killed_between_duplicates_converges_without_renames() {
    let env = Env::mirror();
    env.fake
        .insert(crate::remote::fake::ROOT_ID, "dup.txt", None, b"one");
    env.fake
        .insert(crate::remote::fake::ROOT_ID, "dup.txt", None, b"two");
    let replica = env.mirror_replica("kill-mirror");
    // Killed while the second of the two is downloading.
    kill_at(&env, &replica, false, hold(Op::Media, "dup.txt", 1, false));
    settle(&replica, &env.drive);
    let local = replica.tree();
    let mut contents: Vec<Vec<u8>> = local.values().flatten().cloned().collect();
    contents.sort();
    assert_eq!(
        local.keys().cloned().collect::<Vec<_>>(),
        ["dup (2).txt", "dup.txt"]
    );
    assert_eq!(contents, [b"one".to_vec(), b"two".to_vec()]);
    assert_eq!(replica.debris(), Vec::<String>::new());
    assert_eq!(env.fake.count(Op::Patch), 0, "nothing renamed on Drive");
}
