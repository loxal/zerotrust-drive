// SPDX-FileCopyrightText: Copyright 2026 Alexander Orlov <info@lifub.com>

//! Hermetic plain sync tests against the in-process fake Drive.

use std::cell::{Cell, RefCell};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use super::engine::watch;
use super::local;
use super::state;
use super::*;
use crate::remote::TestDir;
use crate::remote::fake::{FakeDrive, Fault, Hold, Op, ROOT_ID};
use crate::remote::gdrive::FOLDER_MIME;

/// Relative path => content, `None` for a folder.
pub(super) type Tree = BTreeMap<String, Option<Vec<u8>>>;

pub(super) struct Replica {
    _dir: TestDir,
    pub(super) options: PlainOptions,
}

impl Replica {
    pub(super) fn new(folder_id: &str, label: &str) -> Self {
        let dir = TestDir::new(&format!("plain-{label}"));
        let base = dir.path().canonicalize().expect("canonical test dir");
        let root = base.join("sync");
        std::fs::create_dir(&root).expect("create the local folder");
        let options = PlainOptions {
            local_dir: root,
            folder_id: folder_id.to_string(),
            state_file: base.join("state").join("plain.json"),
            trash_dir: base.join("data").join("trash"),
            host: "testhost.example".to_string(),
            stable_age: Duration::ZERO,
        };
        Self { _dir: dir, options }
    }

    pub(super) fn root(&self) -> &Path {
        &self.options.local_dir
    }

    pub(super) fn path(&self, rel: &str) -> PathBuf {
        self.root().join(rel)
    }

    pub(super) fn write(&self, rel: &str, content: &[u8]) {
        let path = self.path(rel);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).expect("create parent folders");
        }
        std::fs::write(path, content).expect("write a local file");
    }

    pub(super) fn read(&self, rel: &str) -> Vec<u8> {
        std::fs::read(self.path(rel)).unwrap_or_else(|error| panic!("read {rel}: {error}"))
    }

    pub(super) fn try_sync(&self, drive: &GoogleDrive) -> Result<CycleReport, String> {
        sync_once(drive, &self.options)
    }

    /// One cycle that must succeed without per-item errors.
    pub(super) fn sync(&self, drive: &GoogleDrive) -> CycleReport {
        let report = self
            .try_sync(drive)
            .unwrap_or_else(|error| panic!("sync failed: {error}"));
        assert!(report.errors.is_empty(), "sync errors: {:?}", report.errors);
        report
    }

    pub(super) fn tree(&self) -> Tree {
        local_tree(self.root())
    }

    /// Every file in the local trash: path below its time bucket => content.
    pub(super) fn trash(&self) -> Vec<(String, Vec<u8>)> {
        let mut found = Vec::new();
        let Ok(buckets) = std::fs::read_dir(&self.options.trash_dir) else {
            return found;
        };
        for bucket in buckets.flatten() {
            for (rel, content) in local_tree(&bucket.path()) {
                if let Some(content) = content {
                    found.push((rel, content));
                }
            }
        }
        found.sort();
        found
    }

    /// Leftover temporary or set-aside files anywhere below the root.
    pub(super) fn debris(&self) -> Vec<String> {
        let mut found = Vec::new();
        walk(self.root(), "", &mut |rel, name, _| {
            if name.starts_with(local::OWN_PREFIX) {
                found.push(rel.to_string());
            }
        });
        found
    }
}

/// Visits every entry below `dir` (without following symlinks).
fn walk(dir: &Path, prefix: &str, visit: &mut dyn FnMut(&str, &str, &std::fs::Metadata)) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        let rel = if prefix.is_empty() {
            name.clone()
        } else {
            format!("{prefix}/{name}")
        };
        let Ok(metadata) = std::fs::symlink_metadata(entry.path()) else {
            continue;
        };
        visit(&rel, &name, &metadata);
        if metadata.is_dir() {
            walk(&entry.path(), &rel, visit);
        }
    }
}

/// Synced items below `root`: regular files and folders, without ignored
/// names.
pub(super) fn local_tree(root: &Path) -> Tree {
    let mut tree = Tree::new();
    let mut skip: Vec<String> = Vec::new();
    walk(root, "", &mut |rel, name, metadata| {
        if skip.iter().any(|top| local::within(rel, top)) {
            return;
        }
        if local::ignored(name) {
            skip.push(rel.to_string());
            return;
        }
        if metadata.is_dir() {
            tree.insert(rel.to_string(), None);
        } else if metadata.is_file() {
            let content = std::fs::read(root.join(rel)).expect("read a local file");
            tree.insert(rel.to_string(), Some(content));
        }
    });
    tree
}

/// The non-trashed items below the Drive folder `folder`.
pub(super) fn remote_tree(fake: &FakeDrive, folder: &str) -> Tree {
    fn visit(fake: &FakeDrive, id: &str, prefix: &str, tree: &mut Tree) {
        for child in fake.children(id) {
            if child.trashed {
                continue;
            }
            let rel = if prefix.is_empty() {
                child.name.clone()
            } else {
                format!("{prefix}/{}", child.name)
            };
            assert!(
                !tree.contains_key(&rel),
                "two Drive items share the path {rel}"
            );
            if child.mime == FOLDER_MIME {
                tree.insert(rel.clone(), None);
                visit(fake, &child.id, &rel, tree);
            } else {
                tree.insert(rel, Some(child.content.clone()));
            }
        }
    }
    let mut tree = Tree::new();
    visit(fake, folder, "", &mut tree);
    tree
}

/// The Drive id of the non-trashed item at `rel` below `folder`.
pub(super) fn remote_id(fake: &FakeDrive, folder: &str, rel: &str) -> Option<String> {
    let mut current = folder.to_string();
    for name in rel.split('/') {
        current = fake
            .children(&current)
            .into_iter()
            .find(|child| !child.trashed && child.name == name)?
            .id;
    }
    Some(current)
}

pub(super) fn tree(items: &[(&str, Option<&[u8]>)]) -> Tree {
    items
        .iter()
        .map(|(rel, content)| (rel.to_string(), content.map(<[u8]>::to_vec)))
        .collect()
}

pub(super) fn is_conflict(rel: &str) -> bool {
    rel.contains("(conflict ")
}

pub(super) fn conflicts(tree: &Tree) -> Vec<(String, Option<Vec<u8>>)> {
    tree.iter()
        .filter(|(rel, _)| is_conflict(rel))
        .map(|(rel, content)| (rel.clone(), content.clone()))
        .collect()
}

/// A cycle that found nothing to do.
pub(super) fn assert_quiet(report: &CycleReport) {
    let changes = (
        report.uploaded,
        report.downloaded,
        report.moved,
        report.remote_trashed,
        report.local_trashed,
        report.conflicts,
        report.folders_created,
        report.skipped_unstable,
    );
    assert_eq!(changes, (0, 0, 0, 0, 0, 0, 0, 0), "{report:?}");
    assert!(report.errors.is_empty(), "{:?}", report.errors);
}

/// Local and Drive hold exactly the same items, nothing is left behind,
/// and another cycle changes nothing.
pub(super) fn assert_converged(fake: &FakeDrive, drive: &GoogleDrive, replica: &Replica) -> Tree {
    let local = replica.tree();
    assert_eq!(local, remote_tree(fake, &replica.options.folder_id));
    assert_eq!(replica.debris(), Vec::<String>::new());
    assert_quiet(&replica.sync(drive));
    assert_eq!(replica.tree(), local);
    local
}

pub(super) struct Env {
    pub(super) fake: FakeDrive,
    pub(super) drive: GoogleDrive,
    pub(super) folder: String,
}

impl Env {
    pub(super) fn new() -> Self {
        Self::with(|fake| fake.client())
    }

    /// Uploads above 1 KiB are resumable, in 256 KiB chunks.
    pub(super) fn resumable() -> Self {
        Self::with(|fake| fake.client().with_upload_sizes(1024, 256 << 10))
    }

    fn with(client: impl Fn(&FakeDrive) -> GoogleDrive) -> Self {
        let fake = FakeDrive::start();
        let drive = client(&fake);
        let folder = match find_or_create_folder(&drive, MY_DRIVE, "Plain") {
            Ok(FolderChoice::Created(folder)) => folder.id,
            other => panic!("expected a new folder, got {other:?}"),
        };
        Self {
            fake,
            drive,
            folder,
        }
    }

    pub(super) fn replica(&self, label: &str) -> Replica {
        Replica::new(&self.folder, label)
    }

    pub(super) fn remote(&self) -> Tree {
        remote_tree(&self.fake, &self.folder)
    }

    pub(super) fn id(&self, rel: &str) -> String {
        remote_id(&self.fake, &self.folder, rel).unwrap_or_else(|| panic!("{rel} is not on Drive"))
    }

    /// A folder below the sync folder, created as another client would.
    pub(super) fn remote_dir(&self, parent_rel: &str, name: &str) -> String {
        let parent = self.parent_id(parent_rel);
        self.fake.insert(&parent, name, Some(FOLDER_MIME), b"")
    }

    pub(super) fn remote_file(&self, parent_rel: &str, name: &str, content: &[u8]) -> String {
        let parent = self.parent_id(parent_rel);
        self.fake.insert(&parent, name, None, content)
    }

    fn parent_id(&self, rel: &str) -> String {
        if rel.is_empty() {
            self.folder.clone()
        } else {
            self.id(rel)
        }
    }

    /// Waits until the fake parks `count` requests in total.
    pub(super) fn wait_held(&self, count: usize) {
        let deadline = Instant::now() + Duration::from_secs(30);
        while self.fake.held() < count {
            assert!(Instant::now() < deadline, "the request was never held");
            std::thread::sleep(Duration::from_millis(5));
        }
    }
}

fn pattern(len: usize, seed: u8) -> Vec<u8> {
    (0..len)
        .map(|index| (index as u8).wrapping_mul(31).wrapping_add(seed))
        .collect()
}

#[test]
fn first_cycle_links_uploads_downloads_and_keeps_both_on_conflict() {
    let env = Env::new();
    let replica = env.replica("first");
    replica.write("same.txt", b"identical");
    replica.write("local/only.txt", b"local only");
    replica.write("both.txt", b"local version");
    env.remote_file("", "same.txt", b"identical");
    let remote_dir = env.remote_dir("", "remote");
    env.fake
        .insert(&remote_dir, "only.txt", None, b"remote only");
    let both = env.remote_file("", "both.txt", b"remote version");
    let same = env.id("same.txt");

    let report = replica.sync(&env.drive);
    assert_eq!(report.conflicts, 1, "{report:?}");
    assert_eq!(report.downloaded, 2, "{report:?}");
    assert_eq!(report.uploaded, 2, "{report:?}");
    assert_eq!(report.folders_created, 2, "{report:?}");

    let local = assert_converged(&env.fake, &env.drive, &replica);
    assert_eq!(local["same.txt"], Some(b"identical".to_vec()));
    assert_eq!(local["local/only.txt"], Some(b"local only".to_vec()));
    assert_eq!(local["remote/only.txt"], Some(b"remote only".to_vec()));
    assert_eq!(local["both.txt"], Some(b"local version".to_vec()));
    let copies = conflicts(&local);
    assert_eq!(copies.len(), 1, "{local:?}");
    assert!(copies[0].0.starts_with("both (conflict "), "{copies:?}");
    assert!(copies[0].0.ends_with(" testhost).txt"), "{copies:?}");
    assert_eq!(copies[0].1, Some(b"remote version".to_vec()));
    // Linking keeps the Drive item; the conflicting one lives on under
    // its conflict name.
    assert_eq!(env.id("same.txt"), same);
    assert_eq!(env.id(&copies[0].0), both);
}

#[test]
fn local_creates_edits_renames_and_deletes_reach_drive() {
    let env = Env::new();
    let replica = env.replica("local");
    replica.write("docs/a.txt", b"a1");
    replica.write("docs/deep/b.txt", b"b1");
    replica.write("c.txt", b"c1");
    replica.write("gone/d.txt", b"d1");
    let report = replica.sync(&env.drive);
    assert_eq!(
        (report.uploaded, report.folders_created),
        (4, 3),
        "{report:?}"
    );
    assert_eq!(report.upload_bytes, 8);
    assert_converged(&env.fake, &env.drive, &replica);
    let a = env.id("docs/a.txt");
    let deep = env.id("docs/deep");
    let b = env.id("docs/deep/b.txt");
    let c = env.id("c.txt");
    let d = env.id("gone/d.txt");

    replica.write("docs/a.txt", b"a2, longer");
    let report = replica.sync(&env.drive);
    assert_eq!(report.uploaded, 1, "{report:?}");
    assert_eq!(env.id("docs/a.txt"), a, "an edit keeps the Drive id");
    assert_eq!(env.fake.file(&a).unwrap().content, b"a2, longer");

    std::fs::rename(replica.path("c.txt"), replica.path("docs/c-renamed.txt")).unwrap();
    std::fs::rename(replica.path("docs/deep"), replica.path("moved-deep")).unwrap();
    let report = replica.sync(&env.drive);
    assert_eq!(report.moved, 2, "{report:?}");
    assert_eq!(report.uploaded, 0, "{report:?}");
    assert_eq!(env.id("docs/c-renamed.txt"), c);
    assert_eq!(env.id("moved-deep"), deep);
    assert_eq!(env.id("moved-deep/b.txt"), b);
    assert_converged(&env.fake, &env.drive, &replica);

    std::fs::remove_file(replica.path("docs/c-renamed.txt")).unwrap();
    std::fs::remove_dir_all(replica.path("gone")).unwrap();
    let report = replica.sync(&env.drive);
    assert_eq!(report.remote_trashed, 2, "{report:?}");
    assert!(
        env.fake.file(&c).unwrap().trashed,
        "deleted files go to the Drive bin"
    );
    let gone = env.fake.file(&d).unwrap();
    assert!(env.fake.file(&gone.parents[0]).unwrap().trashed);
    let local = assert_converged(&env.fake, &env.drive, &replica);
    assert_eq!(
        local,
        tree(&[
            ("docs", None),
            ("docs/a.txt", Some(b"a2, longer")),
            ("moved-deep", None),
            ("moved-deep/b.txt", Some(b"b1")),
        ])
    );
}

#[test]
fn remote_creates_edits_moves_and_deletes_reach_the_local_folder() {
    let env = Env::new();
    let replica = env.replica("remote");
    replica.sync(&env.drive);
    let docs = env.remote_dir("", "docs");
    let a = env.fake.insert(&docs, "a.txt", None, b"a1");
    let b = env.remote_file("", "b.txt", b"b1");
    let c = env.remote_file("", "c.txt", b"c1");
    let report = replica.sync(&env.drive);
    assert_eq!(
        (report.downloaded, report.download_bytes),
        (3, 6),
        "{report:?}"
    );
    assert_eq!(report.folders_created, 1, "{report:?}");
    assert_converged(&env.fake, &env.drive, &replica);

    env.fake.update_foreign(&a, b"a2 edited");
    let report = replica.sync(&env.drive);
    assert_eq!(report.downloaded, 1, "{report:?}");
    assert_eq!(replica.read("docs/a.txt"), b"a2 edited");
    // The replaced version is kept in the local trash.
    assert_eq!(
        replica.trash(),
        vec![("docs/a.txt".to_string(), b"a1".to_vec())]
    );

    env.fake.rename_foreign(&b, "b-renamed.txt");
    env.fake.move_foreign(&b, &docs);
    env.fake.rename_foreign(&docs, "documents");
    let report = replica.sync(&env.drive);
    assert_eq!(report.downloaded, 0, "{report:?}");
    assert!(report.moved >= 2, "{report:?}");
    assert_eq!(replica.read("documents/b-renamed.txt"), b"b1");
    assert_converged(&env.fake, &env.drive, &replica);

    env.fake.trash_foreign(&c, true);
    env.fake.delete_foreign(&a);
    let report = replica.sync(&env.drive);
    assert_eq!(report.local_trashed, 2, "{report:?}");
    let trash = replica.trash();
    assert!(
        trash.contains(&("c.txt".to_string(), b"c1".to_vec())),
        "{trash:?}"
    );
    assert!(
        trash.contains(&("documents/a.txt".to_string(), b"a2 edited".to_vec())),
        "{trash:?}"
    );
    let local = assert_converged(&env.fake, &env.drive, &replica);
    assert_eq!(
        local,
        tree(&[
            ("documents", None),
            ("documents/b-renamed.txt", Some(b"b1"))
        ])
    );

    env.fake.trash_foreign(&docs, true);
    let report = replica.sync(&env.drive);
    // The file, then its emptied folder.
    assert_eq!(report.local_trashed, 2, "{report:?}");
    assert_eq!(replica.tree(), Tree::new());
    assert!(
        replica
            .trash()
            .contains(&("documents/b-renamed.txt".to_string(), b"b1".to_vec()))
    );
    assert_converged(&env.fake, &env.drive, &replica);
}

#[test]
fn edits_on_both_sides_keep_both_versions() {
    let env = Env::new();
    let replica = env.replica("both");
    replica.write("notes.md", b"base");
    replica.sync(&env.drive);
    let id = env.id("notes.md");
    replica.write("notes.md", b"local edit");
    env.fake.update_foreign(&id, b"remote edit");
    let report = replica.sync(&env.drive);
    assert_eq!(report.conflicts, 1, "{report:?}");
    let local = assert_converged(&env.fake, &env.drive, &replica);
    assert_eq!(local["notes.md"], Some(b"local edit".to_vec()));
    let copies = conflicts(&local);
    assert_eq!(copies.len(), 1, "{local:?}");
    assert!(copies[0].0.starts_with("notes (conflict "), "{copies:?}");
    assert!(copies[0].0.ends_with(".md"), "{copies:?}");
    assert_eq!(copies[0].1, Some(b"remote edit".to_vec()));
}

#[test]
fn an_edit_wins_over_a_deletion_on_the_other_side() {
    let env = Env::new();
    let replica = env.replica("edit-delete");
    replica.write("kept-local.txt", b"v1");
    replica.write("kept-remote.txt", b"v1");
    replica.sync(&env.drive);
    let local_kept = env.id("kept-local.txt");
    let remote_kept = env.id("kept-remote.txt");

    // Edited here, trashed on Drive: the local edit is uploaded again.
    replica.write("kept-local.txt", b"v2 local");
    env.fake.trash_foreign(&local_kept, true);
    // Deleted here, edited on Drive: the remote edit comes back.
    std::fs::remove_file(replica.path("kept-remote.txt")).unwrap();
    env.fake.update_foreign(&remote_kept, b"v2 remote");

    replica.sync(&env.drive);
    let local = assert_converged(&env.fake, &env.drive, &replica);
    assert_eq!(
        local,
        tree(&[
            ("kept-local.txt", Some(b"v2 local")),
            ("kept-remote.txt", Some(b"v2 remote")),
        ])
    );
    assert!(env.fake.file(&local_kept).unwrap().trashed);
    assert_eq!(env.id("kept-remote.txt"), remote_kept);
}

#[test]
fn a_file_changed_during_its_upload_is_uploaded_next_cycle() {
    let env = Env::resumable();
    let replica = env.replica("unstable");
    let first = pattern(1 << 20, 1);
    replica.write("big.bin", &first);
    replica.sync(&env.drive);
    let id = env.id("big.bin");

    let second = pattern(1 << 20, 2);
    replica.write("big.bin", &second);
    env.fake.hold(Hold {
        op: Op::Chunk,
        suffix: "big.bin",
        skip: 1,
        commit: false,
    });
    let third = pattern(1 << 20, 3);
    let report = std::thread::scope(|scope| {
        let cycle = scope.spawn(|| replica.try_sync(&env.drive));
        env.wait_held(1);
        std::thread::sleep(Duration::from_millis(20));
        std::fs::write(replica.path("big.bin"), &third).unwrap();
        env.fake.release_held();
        cycle.join().unwrap()
    })
    .expect("the cycle itself succeeds");
    assert_eq!(report.skipped_unstable, 1, "{report:?}");
    assert_eq!(report.uploaded, 0, "{report:?}");
    assert_eq!(
        env.fake.file(&id).unwrap().content,
        first,
        "Drive keeps a whole version"
    );
    assert_eq!(replica.read("big.bin"), third);

    let report = replica.sync(&env.drive);
    assert_eq!(report.uploaded, 1, "{report:?}");
    assert_eq!(env.fake.file(&id).unwrap().content, third);
    assert_converged(&env.fake, &env.drive, &replica);
}

#[test]
fn recently_modified_files_wait_until_they_are_stable() {
    let env = Env::new();
    let mut replica = env.replica("stable-age");
    replica.options.stable_age = Duration::from_secs(3600);
    replica.write("fresh.txt", b"still being written");
    let report = replica.sync(&env.drive);
    assert_eq!(
        (report.uploaded, report.skipped_unstable),
        (0, 1),
        "{report:?}"
    );
    assert_eq!(env.remote(), Tree::new());
    replica.options.stable_age = Duration::ZERO;
    let report = replica.sync(&env.drive);
    assert_eq!(report.uploaded, 1, "{report:?}");
    assert_converged(&env.fake, &env.drive, &replica);
}

#[test]
fn symlinks_and_special_files_are_skipped_and_counted() {
    let env = Env::new();
    let replica = env.replica("special");
    replica.write("real.txt", b"real");
    std::os::unix::fs::symlink("real.txt", replica.path("link.txt")).unwrap();
    std::os::unix::fs::symlink("/", replica.path("escape")).unwrap();
    let fifo = std::ffi::CString::new(replica.path("pipe").to_str().unwrap()).unwrap();
    // SAFETY: a valid NUL-terminated path.
    assert_eq!(unsafe { libc::mkfifo(fifo.as_ptr(), 0o600) }, 0);
    replica.write(".DS_Store", b"finder");
    replica.write("._real.txt", b"resource fork");
    let report = replica.sync(&env.drive);
    assert_eq!(report.skipped_special, 3, "{report:?}");
    assert_eq!(report.uploaded, 1, "{report:?}");
    assert_eq!(env.remote(), tree(&[("real.txt", Some(b"real"))]));
    let report = replica.sync(&env.drive);
    assert_eq!(report.skipped_special, 3, "{report:?}");
    assert_quiet(&report);
}

#[test]
fn drive_items_without_content_are_skipped() {
    let env = Env::new();
    let replica = env.replica("gdoc");
    env.fake.insert(
        &env.folder,
        "Doc",
        Some("application/vnd.google-apps.document"),
        b"",
    );
    env.remote_file("", "plain.txt", b"plain");
    let report = replica.sync(&env.drive);
    assert_eq!(report.skipped_special, 1, "{report:?}");
    assert_eq!(replica.tree(), tree(&[("plain.txt", Some(b"plain"))]));
    assert_quiet(&replica.sync(&env.drive));
}

#[test]
fn unicode_names_round_trip_in_both_directions() {
    let env = Env::new();
    let first = env.replica("unicode-a");
    let second = env.replica("unicode-b");
    // Precomposed (NFC) and decomposed (NFD) spellings, as different
    // clients produce them.
    first.write("Gr\u{fc}\u{df}e/\u{65e5}\u{672c}\u{8a9e}.txt", b"nfc");
    first.write("Cafe\u{301} \u{1f600}.md", b"nfd");
    let remote_dir = env.remote_dir("", "\u{c5}ngstr\u{f6}m");
    env.fake
        .insert(&remote_dir, "Re\u{301}sume\u{301}.txt", None, b"remote nfd");
    first.sync(&env.drive);
    let local = assert_converged(&env.fake, &env.drive, &first);
    assert_eq!(local.len(), 5, "{local:?}");
    second.sync(&env.drive);
    assert_eq!(assert_converged(&env.fake, &env.drive, &second), local);
}

#[test]
fn names_that_alias_on_this_file_system_never_overwrite_each_other() {
    let env = Env::new();
    let replica = env.replica("alias");
    replica.write("Readme.txt", b"local");
    replica.write("e\u{301}.txt", b"local nfd");
    replica.sync(&env.drive);
    env.remote_file("", "README.txt", b"remote");
    env.remote_file("", "\u{e9}.txt", b"remote nfc");
    replica.sync(&env.drive);
    let local = assert_converged(&env.fake, &env.drive, &replica);
    let mut contents: Vec<Vec<u8>> = local.values().flatten().cloned().collect();
    contents.sort();
    assert_eq!(
        contents,
        vec![
            b"local".to_vec(),
            b"local nfd".to_vec(),
            b"remote".to_vec(),
            b"remote nfc".to_vec(),
        ]
    );
}

#[test]
fn an_offline_cycle_fails_cleanly_and_the_next_one_converges() {
    let env = Env::new();
    let replica = env.replica("offline");
    replica.write("a.txt", b"a");
    replica.sync(&env.drive);
    replica.write("a.txt", b"a, edited offline");
    replica.write("b.txt", b"created offline");
    env.remote_file("", "c.txt", b"remote while offline");
    env.fake.set_offline(true);
    let error = replica.try_sync(&env.drive).unwrap_err();
    assert!(
        error.contains("offline") || error.contains("503"),
        "{error}"
    );
    assert_eq!(replica.read("a.txt"), b"a, edited offline");
    env.fake.set_offline(false);
    replica.sync(&env.drive);
    let local = assert_converged(&env.fake, &env.drive, &replica);
    assert_eq!(
        local,
        tree(&[
            ("a.txt", Some(b"a, edited offline")),
            ("b.txt", Some(b"created offline")),
            ("c.txt", Some(b"remote while offline")),
        ])
    );
}

#[test]
fn watch_retries_failed_cycles_and_finishes_with_a_final_cycle() {
    let env = Env::new();
    let replica = env.replica("watch");
    replica.write("a.txt", b"a");
    env.fake.set_offline(true);
    let results: RefCell<Vec<Result<CycleReport, String>>> = RefCell::new(Vec::new());
    let stop = || results.borrow().len() >= 3;
    let mut on_cycle = |result: &Result<CycleReport, String>| {
        let mut results = results.borrow_mut();
        results.push(result.clone());
        if results.len() == 2 {
            env.fake.set_offline(false);
            replica.write("b.txt", b"b");
        }
    };
    watch(
        &env.drive,
        &replica.options,
        Duration::from_millis(10),
        &stop,
        &mut on_cycle,
    )
    .unwrap();
    let results = results.into_inner();
    assert_eq!(results.len(), 4, "{results:?}");
    assert!(results[0].is_err() && results[1].is_err(), "{results:?}");
    assert_eq!(results[2].as_ref().unwrap().uploaded, 2);
    assert_quiet(results[3].as_ref().unwrap());
    assert_converged(&env.fake, &env.drive, &replica);
}

#[test]
fn watch_stops_at_once_on_a_refused_folder() {
    let env = Env::new();
    let unmarked = env.fake.insert(ROOT_ID, "Unmarked", Some(FOLDER_MIME), b"");
    let replica = Replica::new(&unmarked, "watch-refused");
    let calls = Cell::new(0);
    let result = watch(
        &env.drive,
        &replica.options,
        Duration::from_millis(10),
        &|| false,
        &mut |_| calls.set(calls.get() + 1),
    );
    let error = result.unwrap_err();
    assert!(
        error.message.contains("not marked for plain sync"),
        "{error}"
    );
    assert_eq!(error.class, Some(crate::refusal::Class::DriveFolder));
    assert_eq!(calls.get(), 1);
}

#[test]
fn two_replicas_converge_in_both_directions() {
    let env = Env::new();
    let a = env.replica("two-a");
    let b = env.replica("two-b");
    a.write("shared/one.txt", b"one");
    a.write("shared/two.txt", b"two");
    a.write("three.txt", b"three");
    a.sync(&env.drive);
    b.sync(&env.drive);
    assert_eq!(b.tree(), a.tree());

    b.write("shared/one.txt", b"one, edited on b");
    std::fs::rename(b.path("shared/two.txt"), b.path("two-moved.txt")).unwrap();
    std::fs::remove_file(b.path("three.txt")).unwrap();
    b.write("new/four.txt", b"four");
    b.sync(&env.drive);
    let report = a.sync(&env.drive);
    assert_eq!(report.local_trashed, 1, "{report:?}");
    // The deleted file and the version the edit replaced.
    assert_eq!(
        a.trash(),
        vec![
            ("shared/one.txt".to_string(), b"one".to_vec()),
            ("three.txt".to_string(), b"three".to_vec()),
        ]
    );
    let expected = tree(&[
        ("new", None),
        ("new/four.txt", Some(b"four")),
        ("shared", None),
        ("shared/one.txt", Some(b"one, edited on b")),
        ("two-moved.txt", Some(b"two")),
    ]);
    assert_eq!(assert_converged(&env.fake, &env.drive, &a), expected);
    assert_eq!(assert_converged(&env.fake, &env.drive, &b), expected);

    // Both edit the same file: each side ends with both versions.
    a.write("shared/one.txt", b"a wins the name");
    b.write("shared/one.txt", b"b keeps a copy");
    a.sync(&env.drive);
    let report = b.sync(&env.drive);
    assert_eq!(report.conflicts, 1, "{report:?}");
    a.sync(&env.drive);
    let final_a = assert_converged(&env.fake, &env.drive, &a);
    assert_eq!(assert_converged(&env.fake, &env.drive, &b), final_a);
    let mut versions: Vec<Vec<u8>> = final_a
        .iter()
        .filter(|(rel, _)| rel.starts_with("shared/one"))
        .filter_map(|(_, content)| content.clone())
        .collect();
    versions.sort();
    assert_eq!(
        versions,
        vec![b"a wins the name".to_vec(), b"b keeps a copy".to_vec()]
    );
}

#[test]
fn large_files_use_resumable_uploads_updates_and_downloads() {
    let env = Env::resumable();
    let a = env.replica("large-a");
    let b = env.replica("large-b");
    let first = pattern(700 << 10, 7);
    a.write("big.bin", &first);
    let report = a.sync(&env.drive);
    assert_eq!(report.upload_bytes, 700 << 10);
    assert!(env.fake.count(Op::StartSession) >= 1);
    assert!(env.fake.count(Op::Multipart) == 0);
    b.sync(&env.drive);
    assert_eq!(b.read("big.bin"), first);

    let second = pattern(900 << 10, 9);
    b.write("big.bin", &second);
    b.sync(&env.drive);
    assert!(env.fake.count(Op::UpdateSession) >= 1);
    let report = a.sync(&env.drive);
    assert_eq!(report.download_bytes, 900 << 10);
    assert_eq!(a.read("big.bin"), second);
    assert_converged(&env.fake, &env.drive, &a);
}

/// Cycles until one finds nothing to do (a failed cycle counts too).
pub(super) fn settle(replica: &Replica, drive: &GoogleDrive) {
    let mut last = None;
    for _ in 0..5 {
        match replica.try_sync(drive) {
            Ok(report)
                if report.errors.is_empty()
                    && report.uploaded + report.downloaded + report.moved == 0
                    && report.remote_trashed + report.local_trashed + report.conflicts == 0
                    && report.folders_created + report.skipped_unstable == 0 =>
            {
                return;
            }
            other => last = Some(other),
        }
    }
    panic!("no quiet cycle; the last was {last:?}");
}

#[test]
fn corrupt_or_cut_downloads_never_replace_the_local_file() {
    for fault in [Fault::CorruptBody, Fault::TruncateBody(5)] {
        let env = Env::new();
        let a = env.replica("download-a");
        let b = env.replica("download-b");
        a.write("f.txt", b"version one");
        a.sync(&env.drive);
        b.sync(&env.drive);
        a.write("f.txt", b"version two, longer");
        a.sync(&env.drive);
        for _ in 0..8 {
            env.fake.fault(Op::Media, fault.clone());
        }
        // A cut body is resumed within the cycle; a corrupt one fails the
        // download until the faults are used up.
        let mut results = Vec::new();
        while b.read("f.txt") != b"version two, longer" {
            assert!(results.len() < 10, "{fault:?}: {results:?}");
            results.push(b.try_sync(&env.drive));
            let content = b.read("f.txt");
            assert!(
                content == b"version one" || content == b"version two, longer",
                "{fault:?} left {content:?} after {results:?}"
            );
            assert_eq!(b.debris(), Vec::<String>::new(), "{fault:?}");
        }
        settle(&b, &env.drive);
        assert_eq!(b.read("f.txt"), b"version two, longer");
        assert_converged(&env.fake, &env.drive, &b);
    }
}

#[test]
fn lost_responses_after_remote_steps_never_duplicate_anything() {
    let env = Env::new();
    let replica = env.replica("lost-responses");
    replica.write("edit.txt", b"v1");
    replica.write("rename.txt", b"r");
    replica.write("delete.txt", b"d");
    replica.sync(&env.drive);
    let rename = env.id("rename.txt");
    let edit = env.id("edit.txt");

    replica.write("new/n.txt", b"new file");
    replica.write("edit.txt", b"v2, edited");
    std::fs::rename(replica.path("rename.txt"), replica.path("renamed.txt")).unwrap();
    std::fs::remove_file(replica.path("delete.txt")).unwrap();
    for op in [
        Op::CreateFolder,
        Op::Multipart,
        Op::UpdateMedia,
        Op::Patch,
        Op::Patch,
    ] {
        env.fake.fault(op, Fault::CommitThenDrop);
    }
    let _ = replica.try_sync(&env.drive);
    settle(&replica, &env.drive);
    let local = assert_converged(&env.fake, &env.drive, &replica);
    assert_eq!(
        local,
        tree(&[
            ("edit.txt", Some(b"v2, edited")),
            ("new", None),
            ("new/n.txt", Some(b"new file")),
            ("renamed.txt", Some(b"r")),
        ])
    );
    assert_eq!(env.id("renamed.txt"), rename);
    assert_eq!(env.id("edit.txt"), edit);
    let live: Vec<_> = env
        .fake
        .files()
        .into_iter()
        .filter(|file| !file.trashed)
        .collect();
    // The sync folder plus four items.
    assert_eq!(live.len(), 5, "{live:?}");
}

#[test]
fn refused_remote_steps_are_reported_and_retried_next_cycle() {
    let env = Env::new();
    let replica = env.replica("refused-steps");
    replica.write("rename.txt", b"r");
    replica.write("delete.txt", b"d");
    replica.write("edit.txt", b"e1");
    replica.sync(&env.drive);
    let rename = env.id("rename.txt");
    let delete = env.id("delete.txt");

    std::fs::rename(replica.path("rename.txt"), replica.path("renamed.txt")).unwrap();
    std::fs::remove_file(replica.path("delete.txt")).unwrap();
    replica.write("edit.txt", b"e2 edited");
    replica.write("new.txt", b"new");
    env.fake.fault(Op::Patch, Fault::Status(400, "badRequest"));
    env.fake.fault(Op::Patch, Fault::Status(400, "badRequest"));
    env.fake
        .fault(Op::UpdateMedia, Fault::Status(400, "badRequest"));
    env.fake
        .fault(Op::Multipart, Fault::Status(400, "badRequest"));
    let report = replica.try_sync(&env.drive).unwrap();
    assert_eq!(report.errors.len(), 4, "{report:?}");
    assert_eq!(
        (report.moved, report.remote_trashed, report.uploaded),
        (0, 0, 0),
        "{report:?}"
    );
    assert!(!env.fake.file(&delete).unwrap().trashed);
    assert_eq!(env.fake.file(&rename).unwrap().name, "rename.txt");

    let report = replica.sync(&env.drive);
    assert_eq!(
        (report.moved, report.remote_trashed, report.uploaded),
        (1, 1, 2),
        "{report:?}"
    );
    assert_eq!(env.id("renamed.txt"), rename);
    assert!(env.fake.file(&delete).unwrap().trashed);
    assert_converged(&env.fake, &env.drive, &replica);
}

/// Changes on both sides that every crash point below must carry through.
fn crash_scenario(env: &Env, replica: &Replica) -> Tree {
    replica.write("keep.txt", b"keep");
    replica.write("edit.txt", b"edit v1");
    replica.write("rename.txt", b"rename");
    replica.write("delete.txt", b"delete");
    replica.write("dir/inner.txt", b"inner");
    replica.write("remote-edit.txt", b"remote v1");
    replica.write("remote-trash.txt", b"remote trash");
    replica.sync(&env.drive);
    replica.write("new.txt", b"new");
    replica.write("newdir/n.txt", b"n");
    replica.write("edit.txt", b"edit v2, longer");
    std::fs::rename(replica.path("rename.txt"), replica.path("dir/renamed.txt")).unwrap();
    std::fs::remove_file(replica.path("delete.txt")).unwrap();
    env.fake
        .update_foreign(&env.id("remote-edit.txt"), b"remote v2 edited");
    env.fake.trash_foreign(&env.id("remote-trash.txt"), true);
    env.remote_file("dir", "from-remote.txt", b"from remote");
    tree(&[
        ("dir", None),
        ("dir/from-remote.txt", Some(b"from remote")),
        ("dir/inner.txt", Some(b"inner")),
        ("dir/renamed.txt", Some(b"rename")),
        ("edit.txt", Some(b"edit v2, longer")),
        ("keep.txt", Some(b"keep")),
        ("new.txt", Some(b"new")),
        ("newdir", None),
        ("newdir/n.txt", Some(b"n")),
        ("remote-edit.txt", Some(b"remote v2 edited")),
    ])
}

#[test]
fn a_failed_state_write_at_any_point_loses_nothing() {
    for failing in 0u32.. {
        let env = Env::new();
        let replica = env.replica("state-write");
        let expected = crash_scenario(&env, &replica);
        state::fail_save_after(Some(failing));
        let first = replica.try_sync(&env.drive);
        state::fail_save_after(None);
        settle(&replica, &env.drive);
        let local = assert_converged(&env.fake, &env.drive, &replica);
        assert_eq!(local, expected, "state write {failing} failed: {first:?}");
        let trash = replica.trash();
        assert!(
            trash.contains(&("remote-trash.txt".to_string(), b"remote trash".to_vec())),
            "{failing}: {trash:?}"
        );
        if first.is_ok() {
            assert!(failing > 0);
            break;
        }
        assert!(failing < 100, "the cycle never completed");
    }
}

#[test]
fn refuses_unmarked_store_and_binned_folders() {
    let env = Env::new();
    let unmarked = env.fake.insert(ROOT_ID, "Plain", Some(FOLDER_MIME), b"");
    let error = Replica::new(&unmarked, "unmarked")
        .try_sync(&env.drive)
        .unwrap_err();
    assert!(error.contains("not marked for plain sync"), "{error}");

    let id = env.drive.generate_ids(1).unwrap().remove(0);
    let props = BTreeMap::from([(
        MARKER_KEY.to_string(),
        crate::remote::gdrive::STORE_MARKER.to_string(),
    )]);
    let store = env
        .drive
        .create_folder_with(ROOT_ID, "Store", &id, &props)
        .unwrap();
    let error = Replica::new(&store.id, "store")
        .try_sync(&env.drive)
        .unwrap_err();
    assert!(error.contains("encrypted zerotrust-drive store"), "{error}");

    let replica = env.replica("binned");
    replica.write("a.txt", b"a");
    replica.sync(&env.drive);
    env.fake.trash_foreign(&env.folder, true);
    let error = replica.try_sync(&env.drive).unwrap_err();
    assert!(error.contains("Drive bin"), "{error}");
    assert_eq!(
        replica.read("a.txt"),
        b"a",
        "a binned folder deletes nothing"
    );
    assert_eq!(replica.trash(), Vec::new());
}

#[test]
fn a_state_file_stays_bound_to_its_folders() {
    let env = Env::new();
    let replica = env.replica("bound");
    replica.write("a.txt", b"a");
    replica.sync(&env.drive);
    let other = env.replica("bound-other");

    let mut options = replica.options.clone();
    options.local_dir = other.options.local_dir.clone();
    let error = sync_once(&env.drive, &options).unwrap_err();
    assert_eq!(
        error,
        format!(
            "{} belongs to the local folder {}, not {}; remove {} to bind it from scratch",
            replica.options.state_file.display(),
            replica.options.local_dir.display(),
            other.options.local_dir.display(),
            replica.options.state_file.display(),
        )
    );

    let mut options = replica.options.clone();
    options.folder_id = "another-folder".to_string();
    let error = sync_once(&env.drive, &options).unwrap_err();
    assert!(error.contains("belongs to the Drive folder"), "{error}");

    // A replaced local folder (say, an unmounted volume) must not read as
    // "everything was deleted".
    std::fs::rename(replica.root(), replica.root().with_extension("moved")).unwrap();
    std::fs::create_dir(replica.root()).unwrap();
    let error = replica.try_sync(&env.drive).unwrap_err();
    assert!(
        error.contains("no longer the folder that was synced"),
        "{error}"
    );
    assert!(!env.fake.file(&env.id("a.txt")).unwrap().trashed);
}

#[test]
fn a_second_process_cannot_sync_the_same_instance() {
    let env = Env::new();
    let replica = env.replica("locked");
    replica.sync(&env.drive);
    let held = state::open(&replica.options).unwrap();
    let error = replica.try_sync(&env.drive).unwrap_err();
    assert!(
        error.contains("another zdrive process is already syncing"),
        "{error}"
    );
    drop(held);
    replica.sync(&env.drive);
}

#[test]
fn find_or_create_folder_joins_only_marked_folders() {
    let fake = FakeDrive::start();
    let drive = fake.client();
    let created = match find_or_create_folder(&drive, MY_DRIVE, "Sync") {
        Ok(FolderChoice::Created(folder)) => folder,
        other => panic!("{other:?}"),
    };
    assert_eq!(
        created.app_properties.get(MARKER_KEY).map(String::as_str),
        Some(PLAIN_MARKER)
    );
    match find_or_create_folder(&drive, MY_DRIVE, "Sync") {
        Ok(FolderChoice::Existing(folder)) => assert_eq!(folder.id, created.id),
        other => panic!("{other:?}"),
    }

    // Below another folder: an unmarked namesake is refused, not adopted.
    let parent = fake.insert(ROOT_ID, "Parent", Some(FOLDER_MIME), b"");
    let namesake = fake.insert(&parent, "Mine", Some(FOLDER_MIME), b"");
    let error = find_or_create_folder(&drive, &parent, "Mine").unwrap_err();
    assert!(error.contains(&namesake), "{error}");
    let fresh = match find_or_create_folder(&drive, &parent, "Other") {
        Ok(FolderChoice::Created(folder)) => folder,
        other => panic!("{other:?}"),
    };
    assert_eq!(fresh.parents, vec![parent.clone()]);
    match find_or_create_folder(&drive, &parent, "Other") {
        Ok(FolderChoice::Existing(folder)) => assert_eq!(folder.id, fresh.id),
        other => panic!("{other:?}"),
    }
    let props = BTreeMap::from([(MARKER_KEY.to_string(), PLAIN_MARKER.to_string())]);
    let id = drive.generate_ids(1).unwrap().remove(0);
    let twin = drive
        .create_folder_with(&parent, "Other", &id, &props)
        .unwrap();
    let error = find_or_create_folder(&drive, &parent, "Other").unwrap_err();
    assert!(
        error.contains(&fresh.id) && error.contains(&twin.id),
        "{error}"
    );
    assert!(find_or_create_folder(&drive, MY_DRIVE, "a/b").is_err());
    assert!(find_or_create_folder(&drive, MY_DRIVE, ".zdrive-x").is_err());
}

#[test]
fn find_or_create_folder_refuses_an_unmarked_namesake_in_my_drive() {
    let fake = FakeDrive::start();
    let drive = fake.client();
    let namesake = fake.insert(ROOT_ID, "Sync", Some(FOLDER_MIME), b"");
    let error = find_or_create_folder(&drive, MY_DRIVE, "Sync").unwrap_err();
    assert!(error.contains(&namesake), "{error}");
    assert_eq!(fake.files().len(), 1, "nothing was created");
}

#[test]
fn trash_older_than_thirty_days_is_purged_at_cycle_start() {
    use std::os::unix::fs::PermissionsExt;
    let env = Env::new();
    let replica = env.replica("purge");
    let trash = &replica.options.trash_dir;
    let now = local::now_secs();
    let old = trash.join(local::utc_bucket(now - 31 * 86_400));
    let recent = trash.join(local::utc_bucket(now - 29 * 86_400));
    let foreign = trash.join("not a bucket");
    for dir in [&old, &recent, &foreign] {
        std::fs::create_dir_all(dir.join("sub")).unwrap();
        std::fs::write(dir.join("sub/f.txt"), b"x").unwrap();
    }
    std::fs::set_permissions(trash, std::fs::Permissions::from_mode(0o700)).unwrap();
    replica.sync(&env.drive);
    assert!(!old.exists(), "a bucket past the retention is purged");
    assert!(recent.join("sub/f.txt").exists());
    assert!(
        foreign.join("sub/f.txt").exists(),
        "only zdrive's buckets are purged"
    );
}

#[test]
fn leftovers_of_an_interrupted_cycle_are_cleared_without_losing_data() {
    let env = Env::new();
    let replica = env.replica("debris");
    replica.write("free.txt", b"free v1");
    replica.write("taken.txt", b"taken v1");
    replica.sync(&env.drive);
    // As left by a crash while replacing files: `free.txt` was set aside
    // before its download was placed, `taken.txt` after.
    std::fs::rename(
        replica.path("free.txt"),
        replica.path(".zdrive-old-77.1-free.txt"),
    )
    .unwrap();
    replica.write(".zdrive-old-77.2-taken.txt", b"taken v0");
    replica.write(".zdrive-tmp-77.3", b"partial download");
    replica.write("sub/.zdrive-tmp-77.4", b"partial download");
    // Look-alikes that zdrive did not write stay where they are.
    replica.write(".zdrive-tmp-mine", b"user data");
    replica.write(".zdrive-old-x-free.txt", b"user data");

    let mut report = replica.sync(&env.drive);
    // Only the folder `sub`, empty once its partial download is gone, is new.
    assert_eq!(report.folders_created, 1, "{report:?}");
    report.folders_created = 0;
    assert_quiet(&report);
    assert_eq!(replica.read("free.txt"), b"free v1");
    assert_eq!(replica.read("taken.txt"), b"taken v1");
    assert_eq!(
        replica.trash(),
        vec![("taken.txt".to_string(), b"taken v0".to_vec())]
    );
    assert!(!replica.path("sub/.zdrive-tmp-77.4").exists());
    let mut debris = replica.debris();
    debris.sort();
    assert_eq!(debris, vec![".zdrive-old-x-free.txt", ".zdrive-tmp-mine"]);
    assert_eq!(replica.read(".zdrive-tmp-mine"), b"user data");
    assert_eq!(
        remote_tree(&env.fake, &env.folder),
        tree(&[
            ("free.txt", Some(b"free v1")),
            ("sub", None),
            ("taken.txt", Some(b"taken v1")),
        ])
    );
    assert_quiet(&replica.sync(&env.drive));
}

#[test]
fn moving_items_out_of_or_into_the_folder_on_drive_removes_or_adds_them() {
    let env = Env::new();
    let replica = env.replica("subtree");
    replica.write("leaves.txt", b"leaving");
    replica.write("dir/inner.txt", b"inner");
    replica.sync(&env.drive);
    let outside = env.fake.insert(ROOT_ID, "Outside", Some(FOLDER_MIME), b"");
    let incoming = env.fake.insert(&outside, "incoming.txt", None, b"incoming");
    env.fake.move_foreign(&env.id("leaves.txt"), &outside);
    env.fake.move_foreign(&env.id("dir"), &outside);
    env.fake.move_foreign(&incoming, &env.folder);
    let report = replica.sync(&env.drive);
    assert_eq!(report.downloaded, 1, "{report:?}");
    // Two files to the trash, then the emptied folder.
    assert_eq!(report.local_trashed, 3, "{report:?}");
    let local = assert_converged(&env.fake, &env.drive, &replica);
    assert_eq!(local, tree(&[("incoming.txt", Some(b"incoming"))]));
    let trash = replica.trash();
    assert!(trash.contains(&("leaves.txt".to_string(), b"leaving".to_vec())));
    assert!(trash.contains(&("dir/inner.txt".to_string(), b"inner".to_vec())));
}

#[test]
fn the_changes_token_is_recorded_after_each_cycle() {
    let env = Env::new();
    let replica = env.replica("token");
    replica.write("a.txt", b"a");
    replica.sync(&env.drive);
    let stored = || -> String {
        let bytes = std::fs::read(&replica.options.state_file).unwrap();
        let value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        value["start_page_token"].as_str().unwrap().to_string()
    };
    let first: u64 = stored().parse().unwrap();
    assert!(first <= env.fake.change_token());
    env.remote_file("", "b.txt", b"b");
    replica.sync(&env.drive);
    let second: u64 = stored().parse().unwrap();
    assert!(second > first && second <= env.fake.change_token());
    assert_quiet(&replica.sync(&env.drive));
    assert_eq!(stored().parse::<u64>().unwrap(), env.fake.change_token());
}

#[test]
fn conflict_and_trash_names() {
    assert_eq!(
        local::conflict_name("report.txt", false, "2026-03-04 050607", "mac", 1),
        "report (conflict 2026-03-04 050607 mac).txt"
    );
    assert_eq!(
        local::conflict_name("archive.tar.gz", false, "2026-03-04 050607", "mac", 2),
        "archive.tar (conflict 2026-03-04 050607 mac 2).gz"
    );
    assert_eq!(
        local::conflict_name("v1.2 notes", true, "2026-03-04 050607", "mac", 1),
        "v1.2 notes (conflict 2026-03-04 050607 mac)"
    );
    assert_eq!(
        local::conflict_name(".bashrc", false, "2026-03-04 050607", "mac", 1),
        ".bashrc (conflict 2026-03-04 050607 mac)"
    );
    let long = "x".repeat(300);
    let tagged = local::conflict_name(&format!("{long}.txt"), false, "s", "h", 1);
    assert!(tagged.len() <= local::NAME_MAX && tagged.ends_with(" (conflict s h).txt"));
    assert_eq!(local::host_tag("Alexs-MacBook.local"), "Alexs-MacBook");
    assert_eq!(local::host_tag("a b/c"), "a-b-c");
    for secs in [0, 1_772_000_000, 4_102_444_800] {
        let bucket = local::utc_bucket(secs);
        assert_eq!(local::parse_bucket(&bucket), Some(secs), "{bucket}");
    }
    assert_eq!(local::parse_bucket("2026-13-01T000000Z"), None);
    assert!(local::is_own_temp(".zdrive-tmp-123.4"));
    assert!(!local::is_own_temp(".zdrive-tmp-123"));
    assert!(!local::is_own_temp(".zdrive-tmp-a.4"));
    assert_eq!(
        local::aside_original(".zdrive-old-1.2-a-b.txt"),
        Some("a-b.txt")
    );
    assert_eq!(local::aside_original(".zdrive-old-x-a.txt"), None);
    assert_eq!(local::aside_original(".zdrive-old-1.2-.DS_Store"), None);
    for ignored in [".DS_Store", "._x", ".zdrive-anything"] {
        assert!(local::ignored(ignored));
    }
    assert!(!local::ignored(".zshrc"));
}
