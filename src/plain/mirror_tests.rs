// SPDX-FileCopyrightText: Copyright 2026 Alexander Orlov <info@lifub.com>

//! A mirror of all of My Drive against the in-process fake Drive: what it
//! leaves out, the local names it gives Drive names, and that it never
//! renames anything on Drive.

use std::cell::RefCell;
use std::time::{Duration, Instant};

use super::engine::watch_with_grace;
use super::tests::{Env, Replica, assert_quiet, conflicts, tree};
use super::{CycleReport, FolderChoice, find_or_create_folder, local};
use crate::remote::fake::{FakeFile, Hold, Op, ROOT_ID, ROOT_REAL_ID};
use crate::remote::gdrive::{FOLDER_MIME, MY_DRIVE};

fn file(env: &Env, id: &str) -> FakeFile {
    env.fake
        .files()
        .into_iter()
        .find(|file| file.id == id)
        .unwrap_or_else(|| panic!("{id} is not on Drive"))
}

/// The live Drive items named `name` directly in `parent`.
fn named(env: &Env, parent: &str, name: &str) -> Vec<FakeFile> {
    env.fake
        .children(parent)
        .into_iter()
        .filter(|child| !child.trashed && child.name == name)
        .collect()
}

#[test]
fn a_mirror_syncs_my_drive_and_leaves_zdrive_folders_and_docs_out() {
    let env = Env::mirror();
    let fake = &env.fake;
    let photos = fake.insert(ROOT_ID, "Photos", Some(FOLDER_MIME), b"");
    fake.insert(&photos, "beach.jpg", None, b"jpeg");
    let year = fake.insert(&photos, "2026", Some(FOLDER_MIME), b"");
    fake.insert(&year, "day.jpg", None, b"day");
    fake.insert(ROOT_ID, "notes.txt", None, b"notes");
    fake.insert(
        ROOT_ID,
        "Plan",
        Some("application/vnd.google-apps.document"),
        b"",
    );
    fake.insert(
        ROOT_ID,
        "Link",
        Some("application/vnd.google-apps.shortcut"),
        b"",
    );
    // zdrive's own folders: a marked plain folder, and an encrypted store
    // whose marker an own OAuth client could not see.
    let plain = match find_or_create_folder(&env.drive, MY_DRIVE, "ZeroTrust Drive (plain)") {
        Ok(FolderChoice::Created(folder)) => folder.id,
        other => panic!("expected a new folder, got {other:?}"),
    };
    fake.insert(&plain, "synced elsewhere.txt", None, b"plain");
    let store = fake.insert(ROOT_ID, "ZeroTrust Drive", Some(FOLDER_MIME), b"");
    fake.insert(&store, "zdrive-remote.json", None, b"{}");
    let packs = fake.insert(&store, "packs", Some(FOLDER_MIME), b"");
    fake.insert(&packs, "a.zpk", None, b"ciphertext");
    // Shared with the user, but not in their My Drive.
    let shared = fake.insert(ROOT_ID, "Shared", Some(FOLDER_MIME), b"");
    fake.insert(&shared, "theirs.txt", None, b"theirs");
    fake.detach(&shared);

    let replica = env.mirror_replica("all");
    let report = replica.sync(&env.drive);
    assert_eq!(report.skipped_special, 2, "{report:?}");
    let expected = tree(&[
        ("Photos", None),
        ("Photos/2026", None),
        ("Photos/2026/day.jpg", Some(b"day")),
        ("Photos/beach.jpg", Some(b"jpeg")),
        ("notes.txt", Some(b"notes")),
    ]);
    assert_eq!(replica.tree(), expected);
    assert_quiet(&replica.sync(&env.drive));

    // Local changes reach My Drive itself.
    replica.write("Photos/new.jpg", b"new");
    replica.write("top.txt", b"top");
    assert_eq!(replica.sync(&env.drive).uploaded, 2);
    let top = named(&env, ROOT_REAL_ID, "top.txt");
    assert_eq!(top.len(), 1);
    assert_eq!(top[0].content, b"top");
    assert_eq!(named(&env, &photos, "new.jpg").len(), 1);

    // A folder that turns out to hold a store leaves the mirror, and its
    // local copy goes to the local trash.
    let later = fake.insert(ROOT_ID, "Later", Some(FOLDER_MIME), b"");
    fake.insert(&later, "early.zpk", None, b"early");
    replica.sync(&env.drive);
    assert!(replica.path("Later/early.zpk").exists());
    fake.insert(&later, "zdrive-remote.json", None, b"{}");
    replica.sync(&env.drive);
    assert!(!replica.path("Later").exists());
    assert!(
        replica
            .trash()
            .contains(&("Later/early.zpk".to_string(), b"early".to_vec()))
    );
    assert!(!file(&env, &later).trashed, "Drive keeps the store");
    assert_quiet(&replica.sync(&env.drive));
}

#[test]
fn a_mirror_maps_names_and_never_renames_on_drive() {
    let env = Env::mirror();
    let fake = &env.fake;
    let slash = fake.insert(ROOT_ID, "Q1/Q2 report.txt", None, b"slash");
    let first = fake.insert(ROOT_ID, "dup.txt", None, b"first");
    let second = fake.insert(ROOT_ID, "dup.txt", None, b"second");
    let long_name = format!("{}.txt", "x".repeat(300));
    let long = fake.insert(ROOT_ID, &long_name, None, b"long");
    let replica = env.mirror_replica("names");

    let report = replica.sync(&env.drive);
    assert_eq!(report.downloaded, 4, "{report:?}");
    assert_eq!(fake.count(Op::Patch), 0, "nothing is renamed on Drive");
    let local = replica.tree();
    let mapped_long = local::mirror_name(&long_name).expect("a local name");
    assert!(mapped_long.len() <= local::NAME_MAX && mapped_long.ends_with(".txt"));
    assert_eq!(
        local.keys().cloned().collect::<Vec<_>>(),
        vec![
            "Q1\u{FF0F}Q2 report.txt".to_string(),
            "dup (2).txt".to_string(),
            "dup.txt".to_string(),
            mapped_long.clone(),
        ]
    );
    assert_eq!(local[&mapped_long], Some(b"long".to_vec()));
    let mut dups = [local["dup.txt"].clone(), local["dup (2).txt"].clone()];
    dups.sort();
    assert_eq!(dups, [Some(b"first".to_vec()), Some(b"second".to_vec())]);
    assert_quiet(&replica.sync(&env.drive));

    // An edit travels to the right Drive file, which keeps its name.
    let apart = if local["dup (2).txt"] == Some(b"second".to_vec()) {
        &second
    } else {
        &first
    };
    replica.write("dup (2).txt", b"edited");
    assert_eq!(replica.sync(&env.drive).uploaded, 1);
    let edited = file(&env, apart);
    assert_eq!(
        (edited.name.as_str(), edited.content.as_slice()),
        ("dup.txt", &b"edited"[..])
    );

    // A move keeps the Drive name; a local rename gives a new one.
    std::fs::create_dir(replica.path("sub")).expect("create a folder");
    std::fs::rename(replica.path("dup (2).txt"), replica.path("sub/dup (2).txt")).expect("move");
    std::fs::rename(
        replica.path("Q1\u{FF0F}Q2 report.txt"),
        replica.path("report.txt"),
    )
    .expect("rename");
    let report = replica.sync(&env.drive);
    assert_eq!(report.moved, 2, "{report:?}");
    let moved = file(&env, apart);
    let sub = named(&env, ROOT_REAL_ID, "sub");
    assert_eq!(moved.name, "dup.txt");
    assert_eq!(moved.parents, [sub[0].id.clone()]);
    assert_eq!(file(&env, &slash).name, "report.txt");
    assert_quiet(&replica.sync(&env.drive));

    // Deleting a locally mapped item bins its Drive file.
    std::fs::remove_file(replica.path(&mapped_long)).expect("remove");
    assert_eq!(replica.sync(&env.drive).remote_trashed, 1);
    assert!(file(&env, &long).trashed);
    assert_quiet(&replica.sync(&env.drive));
}

#[test]
fn a_mirror_keeps_a_local_edit_beside_a_drive_edit() {
    let env = Env::mirror();
    let id = env.fake.insert(ROOT_ID, "plan.txt", None, b"v1");
    let replica = env.mirror_replica("conflict");
    replica.sync(&env.drive);
    replica.write("plan.txt", b"local v2");
    env.fake.update_foreign(&id, b"drive v2");

    let report = replica.sync(&env.drive);
    assert_eq!((report.conflicts, report.uploaded), (1, 1), "{report:?}");
    let local = replica.tree();
    assert_eq!(local["plan.txt"], Some(b"drive v2".to_vec()));
    let kept = conflicts(&local);
    assert_eq!(kept.len(), 1, "{kept:?}");
    assert_eq!(kept[0].1, Some(b"local v2".to_vec()));
    // The Drive file keeps its name; the local edit is a new Drive file.
    let original = file(&env, &id);
    assert_eq!(
        (original.name.as_str(), original.content.as_slice()),
        ("plan.txt", &b"drive v2"[..])
    );
    let copy = named(&env, ROOT_REAL_ID, &kept[0].0);
    assert_eq!(copy.len(), 1);
    assert_eq!(copy[0].content, b"local v2");
    assert_quiet(&replica.sync(&env.drive));
}

#[test]
fn a_mirror_needs_its_own_my_drive_and_full_access() {
    let env = Env::mirror();
    let mut alias = Replica::new(ROOT_ID, "alias");
    alias.options.mirror = true;
    let error = alias.try_sync(&env.drive).unwrap_err();
    assert!(error.contains("belongs to the My Drive root"), "{error}");

    let replica = env.mirror_replica("hidden");
    env.fake.hide_my_drive_root(true);
    let error = replica.try_sync(&env.drive).unwrap_err();
    assert!(error.contains("needs full Drive access"), "{error}");
}

#[test]
fn a_mirror_lists_many_folders_per_request() {
    let env = Env::mirror();
    // 120 folders on one level, each with a file and a subfolder.
    for n in 0..120 {
        let folder = env
            .fake
            .insert(ROOT_ID, &format!("d{n:03}"), Some(FOLDER_MIME), b"");
        env.fake.insert(&folder, "f.txt", None, b"f");
        env.fake.insert(&folder, "sub", Some(FOLDER_MIME), b"");
    }
    let replica = env.mirror_replica("fast-list");
    let before = env.fake.count(Op::List);
    assert_eq!(replica.sync(&env.drive).downloaded, 120);
    // My Drive, then 120 folders in three requests of up to 50, then
    // their 120 subfolders in three more: 7, not 241.
    assert_eq!(env.fake.count(Op::List) - before, 7);
    assert_eq!(replica.tree().len(), 360);
}

#[test]
fn mirror_names_fit_a_local_file_name() {
    assert_eq!(
        local::mirror_name("plain.txt").as_deref(),
        Some("plain.txt")
    );
    assert_eq!(local::mirror_name("a/b").as_deref(), Some("a\u{FF0F}b"));
    assert_eq!(local::mirror_name(".").as_deref(), Some("\u{FF0E}"));
    assert_eq!(
        local::mirror_name("..").as_deref(),
        Some("\u{FF0E}\u{FF0E}")
    );
    assert_eq!(local::mirror_name(""), None);
    let one = local::mirror_name(&format!("{}a.pdf", "é".repeat(200))).expect("a name");
    let two = local::mirror_name(&format!("{}b.pdf", "é".repeat(200))).expect("a name");
    assert!(
        one.len() <= local::NAME_MAX && one.ends_with(".pdf"),
        "{one}"
    );
    assert_ne!(one, two, "long names stay apart");
    assert!(local::valid_name(&one));
}

#[test]
fn a_mirror_downloads_in_parallel_and_leaves_no_staged_files() {
    let env = Env::mirror();
    for n in 0..12 {
        env.fake.insert(
            ROOT_ID,
            &format!("f{n:02}.txt"),
            None,
            format!("{n}").as_bytes(),
        );
    }
    let replica = env.mirror_replica("parallel");
    // The first file's download hangs; the others go on meanwhile.
    env.fake.hold(Hold {
        op: Op::Media,
        suffix: "f00.txt",
        skip: 0,
        commit: false,
    });
    std::thread::scope(|scope| {
        let syncing = scope.spawn(|| replica.try_sync(&env.drive));
        let deadline = Instant::now() + Duration::from_secs(30);
        while env.fake.held() == 0 || env.fake.count(Op::Media) < 4 {
            assert!(Instant::now() < deadline, "no parallel downloads");
            std::thread::sleep(Duration::from_millis(5));
        }
        env.fake.release_held();
        let report = syncing.join().expect("sync thread").expect("sync");
        assert_eq!(report.downloaded, 12, "{report:?}");
    });
    assert_eq!(replica.tree().len(), 12);
    assert_eq!(replica.debris(), Vec::<String>::new());
    assert_quiet(&replica.sync(&env.drive));

    // A stop during the pass removes what was staged but not installed.
    for n in 0..12 {
        env.fake
            .insert(ROOT_ID, &format!("g{n:02}.txt"), None, b"more");
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
    assert!(results.into_inner()[0].is_err());
    assert_eq!(replica.debris(), Vec::<String>::new());
    assert_eq!(replica.sync(&env.drive).downloaded, 11);
    assert_eq!(replica.tree().len(), 24);
}

#[test]
fn my_drive_size_counts_what_a_mirror_downloads() {
    let env = Env::mirror();
    let fake = &env.fake;
    let folder = fake.insert(ROOT_ID, "Docs", Some(FOLDER_MIME), b"");
    fake.insert(&folder, "a.txt", None, b"12345");
    fake.insert(ROOT_ID, "b.bin", None, b"123");
    fake.insert(
        &folder,
        "Plan",
        Some("application/vnd.google-apps.document"),
        b"",
    );
    let store = fake.insert(ROOT_ID, "Store", Some(FOLDER_MIME), b"");
    fake.insert(&store, "zdrive-remote.json", None, b"{}");
    fake.insert(&store, "pack.zpk", None, b"ciphertext");
    let shared = fake.insert(ROOT_ID, "Shared", Some(FOLDER_MIME), b"");
    fake.insert(&shared, "theirs.txt", None, b"theirs");
    fake.detach(&shared);
    let size = super::my_drive_size(&env.drive, ROOT_REAL_ID).expect("size");
    assert_eq!(
        size,
        super::MyDriveSize {
            files: 2,
            bytes: 8,
            without_content: 1,
        }
    );
}
