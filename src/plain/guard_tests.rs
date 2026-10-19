// SPDX-FileCopyrightText: Copyright 2026 Alexander Orlov <info@lifub.com>

//! The guards that keep a plain sync from emptying Drive, parked items and
//! a stop during a long cycle, against the in-process fake Drive.

use std::cell::RefCell;
use std::time::Duration;

use super::engine::watch_with_grace;
use super::tests::{Env, Replica, assert_converged, assert_quiet, tree};
use super::{CycleReport, local, sync_once};
use crate::remote::fake::Op;

/// `count` synced top-level files `fNNN.txt`.
fn synced_files(env: &Env, replica: &Replica, count: usize) {
    for n in 0..count {
        replica.write(&format!("f{n:03}.txt"), format!("file {n}").as_bytes());
    }
    replica.sync(&env.drive);
}

fn remove(replica: &Replica, range: std::ops::Range<usize>) {
    for n in range {
        std::fs::remove_file(replica.path(&format!("f{n:03}.txt"))).expect("remove a file");
    }
}

/// One cycle with `--allow-deletions allowed`.
fn sync_allowing(env: &Env, replica: &Replica, allowed: u64) -> CycleReport {
    let mut options = replica.options.clone();
    options.allow_deletions = Some(allowed);
    sync_once(&env.drive, &options).expect("sync")
}

fn reason(report: &CycleReport) -> &str {
    report.held_reason.as_deref().unwrap_or_default()
}

#[test]
fn an_emptied_local_folder_bins_nothing_until_allowed() {
    let env = Env::new();
    let replica = env.replica("emptied");
    synced_files(&env, &replica, 12);
    let before = env.remote();
    remove(&replica, 0..12);

    let report = replica.sync(&env.drive);
    assert_eq!((report.held_deletions, report.remote_trashed), (12, 0));
    assert!(
        reason(&report).contains("every synced item is missing"),
        "{report:?}"
    );
    assert_eq!(env.remote(), before);
    // Held on every cycle, never applied by itself.
    assert_eq!(replica.sync(&env.drive).held_deletions, 12);
    assert_eq!(env.fake.count(Op::Patch), 0);

    // Fewer than the missing items are not a review of them.
    assert_eq!(sync_allowing(&env, &replica, 11).held_deletions, 12);
    let report = sync_allowing(&env, &replica, 12);
    assert_eq!((report.held_deletions, report.remote_trashed), (0, 12));
    assert_eq!(env.remote(), tree(&[]));
    assert_converged(&env.fake, &env.drive, &replica);
}

#[test]
fn a_mass_deletion_is_held_but_a_few_deletions_are_not() {
    let env = Env::new();
    let replica = env.replica("mass");
    synced_files(&env, &replica, 100);
    remove(&replica, 0..5);
    let report = replica.sync(&env.drive);
    assert_eq!((report.held_deletions, report.remote_trashed), (0, 5));

    remove(&replica, 5..65);
    let report = replica.sync(&env.drive);
    assert_eq!((report.held_deletions, report.remote_trashed), (60, 0));
    assert!(
        reason(&report).contains("60 of 95 synced items are missing at once"),
        "{report:?}"
    );
    assert_eq!(env.remote().len(), 95);
}

#[test]
fn a_big_folder_may_go_when_it_is_a_small_part_of_the_index() {
    let env = Env::new();
    let replica = env.replica("big-folder");
    for n in 0..60 {
        replica.write(&format!("big/b{n:02}.txt"), b"big");
    }
    synced_files(&env, &replica, 600);
    // 61 synced items (the folder counts with its contents) of 661.
    std::fs::remove_dir_all(replica.path("big")).expect("remove the folder");
    let report = replica.sync(&env.drive);
    assert_eq!((report.held_deletions, report.remote_trashed), (0, 1));
    assert_eq!(env.remote().len(), 600);
}

#[test]
fn a_folder_without_its_root_id_holds_every_deletion() {
    let env = Env::new();
    let replica = env.replica("root-id");
    synced_files(&env, &replica, 3);
    let marker = replica.path(local::ROOT_ID_FILE);
    let first = std::fs::read_to_string(&marker).expect("the root id is written");

    // Nothing is missing, so a lost root id is simply written again.
    std::fs::remove_file(&marker).expect("remove the root id");
    assert_quiet(&replica.sync(&env.drive));
    let second = std::fs::read_to_string(&marker).expect("written again");
    assert_ne!(second, first);

    // With an item missing the folder may be another one: nothing is binned.
    std::fs::remove_file(&marker).expect("remove the root id");
    remove(&replica, 0..1);
    let report = replica.sync(&env.drive);
    assert_eq!((report.held_deletions, report.remote_trashed), (1, 0));
    assert!(
        reason(&report).contains("it has no .zdrive-root-id"),
        "{report:?}"
    );
    assert!(!marker.exists());
    std::fs::write(&marker, "someone else\n").expect("a foreign root id");
    let report = replica.sync(&env.drive);
    assert!(
        reason(&report).contains("belongs to another sync"),
        "{report:?}"
    );
    assert_eq!(env.remote().len(), 3);

    // A reviewed run binds the folder again and applies the deletion.
    let report = sync_allowing(&env, &replica, 1);
    assert_eq!(report.remote_trashed, 1);
    let bound = std::fs::read_to_string(&marker).expect("bound again");
    assert_ne!(bound.trim(), "someone else");
    assert_converged(&env.fake, &env.drive, &replica);
}

#[test]
fn an_index_of_an_older_zdrive_is_upgraded_and_bound() {
    let env = Env::new();
    let replica = env.replica("upgrade");
    synced_files(&env, &replica, 2);
    // As zdrive 0.18 left it: version 1, no root id in the folder or state.
    let state_file = &replica.options.state_file;
    let read_state = || -> serde_json::Value {
        serde_json::from_slice(&std::fs::read(state_file).expect("read the state")).expect("json")
    };
    let mut old = read_state();
    old["version"] = 1.into();
    old.as_object_mut().expect("object").remove("root_id");
    std::fs::write(state_file, serde_json::to_vec(&old).expect("encode")).expect("write");
    std::fs::remove_file(replica.path(local::ROOT_ID_FILE)).expect("remove the root id");
    remove(&replica, 0..1);

    let report = replica.sync(&env.drive);
    assert_eq!((report.held_deletions, report.remote_trashed), (0, 1));
    let upgraded = read_state();
    assert_eq!(upgraded["version"], 2);
    assert_eq!(
        upgraded["root_id"].as_str().map(str::to_string),
        local::read_root_id(replica.root()).expect("read the root id")
    );

    let mut newer = upgraded;
    newer["version"] = 3.into();
    std::fs::write(state_file, serde_json::to_vec(&newer).expect("encode")).expect("write");
    let error = replica.try_sync(&env.drive).unwrap_err();
    assert!(error.contains("versions 1 to 2"), "{error}");
}

#[test]
fn a_drive_folder_holding_unsynced_items_is_kept() {
    let env = Env::new();
    let replica = env.replica("kept");
    replica.write("docs/a.txt", b"a");
    replica.write("docs/sub/b.txt", b"b");
    replica.sync(&env.drive);
    let docs = env.id("docs");
    let sub = env.id("docs/sub");
    env.fake.insert(
        &docs,
        "Notes",
        Some("application/vnd.google-apps.document"),
        b"",
    );
    assert_eq!(replica.sync(&env.drive).skipped_special, 1);

    std::fs::remove_dir_all(replica.path("docs")).expect("remove the folder");
    let report = replica.sync(&env.drive);
    // a.txt one by one, docs/sub in one step; docs stays for its document.
    assert_eq!((report.remote_trashed, report.kept_folders), (2, 1));
    let files = env.fake.files();
    let live = |id: &str| files.iter().any(|file| file.id == id && !file.trashed);
    assert!(live(&docs));
    assert!(!live(&sub));
    let left: Vec<String> = env
        .fake
        .children(&docs)
        .into_iter()
        .filter(|child| !child.trashed)
        .map(|child| child.name)
        .collect();
    assert_eq!(left, ["Notes"]);
    assert_quiet(&replica.sync(&env.drive));
    assert!(!replica.path("docs").exists());
}

#[test]
fn a_download_drive_refuses_is_parked_until_a_new_version() {
    let env = Env::new();
    let replica = env.replica("parked-download");
    let locked = env.remote_file("", "locked.txt", b"no download");
    env.fake.set_capabilities(&locked, true, true, false);
    let report = replica.try_sync(&env.drive).expect("sync");
    assert_eq!(report.parked, 1);
    assert!(
        report
            .errors
            .iter()
            .any(|error| error.contains("locked.txt is not downloaded")),
        "{report:?}"
    );
    // Parked: later cycles neither ask Drive again nor report it.
    assert_eq!(replica.sync(&env.drive).parked, 0);
    assert_eq!(env.fake.count(Op::Media), 0);

    env.fake.set_capabilities(&locked, true, true, true);
    env.fake.update_foreign(&locked, b"now allowed");
    let report = replica.sync(&env.drive);
    assert_eq!(report.downloaded, 1);
    assert_eq!(replica.read("locked.txt"), b"now allowed");
}

#[test]
fn an_edit_or_deletion_drive_refuses_is_parked() {
    let env = Env::new();
    let replica = env.replica("parked-push");
    replica.write("theirs.txt", b"v1");
    replica.write("gone.txt", b"gone");
    replica.sync(&env.drive);
    let theirs = env.id("theirs.txt");
    let gone = env.id("gone.txt");
    env.fake.set_capabilities(&theirs, false, true, true);
    env.fake.set_capabilities(&gone, true, false, true);
    let patches = env.fake.count(Op::Patch);

    replica.write("theirs.txt", b"v2 here");
    std::fs::remove_file(replica.path("gone.txt")).expect("remove a file");
    let report = replica.try_sync(&env.drive).expect("sync");
    assert_eq!((report.parked, report.errors.len()), (2, 2), "{report:?}");
    let uploads = env.fake.count(Op::UpdateMedia) + env.fake.count(Op::UpdateSession);
    assert_eq!(uploads, 0);
    assert_eq!(env.fake.count(Op::Patch), patches);
    let report = replica.sync(&env.drive);
    assert_eq!(report.parked, 0);
    let files = env.fake.files();
    let file = |id: &str| files.iter().find(|file| file.id == id).expect("on Drive");
    assert_eq!(file(&theirs).content, b"v1");
    assert!(!file(&gone).trashed);
}

#[test]
fn a_stop_ends_a_long_cycle_after_its_grace_and_keeps_the_work() {
    let env = Env::new();
    let replica = env.replica("stop");
    for n in 0..30 {
        env.remote_file("", &format!("r{n:02}.txt"), b"remote");
    }
    let results: RefCell<Vec<Result<CycleReport, String>>> = RefCell::new(Vec::new());
    watch_with_grace(
        &env.drive,
        &replica.options,
        Duration::from_millis(10),
        Duration::ZERO,
        &|| true,
        &mut |result| results.borrow_mut().push(result.clone()),
    )
    .expect("watch");
    let results = results.into_inner();
    assert_eq!(results.len(), 1, "no final cycle after an overdue stop");
    let error = results[0].as_ref().unwrap_err();
    assert!(
        error.contains("stopped before the cycle finished"),
        "{error}"
    );
    assert_eq!(replica.tree().len(), 1, "the first download is kept");

    replica.sync(&env.drive);
    assert_eq!(replica.tree().len(), 30);
    assert_converged(&env.fake, &env.drive, &replica);
}
