// SPDX-FileCopyrightText: Copyright 2026 Alexander Orlov <info@lifub.com>

use super::*;
use crate::crypto::{KdfParams, load_kdf_with_fingerprint, save_kdf, try_derive_key};
use crate::fault::{DurabilityCheckpoint, DurabilityEvent, FaultInjectionGuard};
use crate::fs::{DirChild, DiskIndex, InodeEntry, InodeKind};
use crate::remote::TestDir;
use crate::remote::config::test_kdf;
use crate::remote::fake::{FakeDrive, Fault, Op, ROOT_ID};
use crate::remote::gdrive::FOLDER_MIME;

pub(crate) const PASSPHRASE: &str = "sync-test-passphrase";
pub(crate) const CANARY: &[u8] = b"PLAINTEXT-CANARY-7f3a";

pub(crate) fn quiet(_: &str) {}

/// Distinct, incompressible-looking content with a plaintext canary.
pub(crate) fn content(seed: u8, len: usize) -> Vec<u8> {
    let mut bytes = CANARY.to_vec();
    let mut state = u32::from(seed).wrapping_mul(2_654_435_761).wrapping_add(1);
    while bytes.len() < len {
        state ^= state << 13;
        state ^= state >> 17;
        state ^= state << 5;
        bytes.push(state as u8);
    }
    bytes.truncate(len.max(CANARY.len()));
    bytes
}

pub(crate) struct Env {
    pub(crate) fake: FakeDrive,
    pub(crate) drive: GoogleDrive,
    pub(crate) folder: String,
}

impl Env {
    pub(crate) fn new() -> Self {
        let fake = FakeDrive::start();
        let drive = fake.client();
        Self::with(fake, drive)
    }

    /// Packs above 256 KiB travel through resumable sessions.
    pub(crate) fn resumable() -> Self {
        let fake = FakeDrive::start();
        let drive = fake.client().with_upload_sizes(256 << 10, 256 << 10);
        Self::with(fake, drive)
    }

    fn with(fake: FakeDrive, drive: GoogleDrive) -> Self {
        let folder = fake.insert(ROOT_ID, "zdrive-test", Some(FOLDER_MIME), b"");
        Self {
            fake,
            drive,
            folder,
        }
    }

    pub(crate) fn remote(&self) -> Remote<'_> {
        Remote {
            drive: &self.drive,
            folder_id: &self.folder,
            log: &quiet,
        }
    }

    pub(crate) fn named(&self, suffix: &str) -> Vec<crate::remote::fake::FakeFile> {
        self.fake
            .files()
            .into_iter()
            .filter(|file| file.name.ends_with(suffix))
            .collect()
    }

    fn drain_faults(&self) {
        while self.fake.pending_faults() > 0 {
            self.drive.list(&self.folder, false).unwrap();
        }
    }

    pub(crate) fn push(&self, store: &Store) -> Result<PushReport, RemoteError> {
        push(
            &self.remote(),
            &store.local(),
            &mut store.state(&self.folder),
        )
    }

    fn pull(&self, store: &mut Store) -> Result<PullReport, RemoteError> {
        let report = pull(
            &self.remote(),
            &store.local(),
            &mut store.state(&self.folder),
        );
        store.reload();
        report
    }

    fn status(&self, store: &Store) -> StatusReport {
        status(
            &self.remote(),
            &store.local(),
            &mut store.state(&self.folder),
        )
        .unwrap()
    }

    fn verify(&self, store: &Store, full: bool) -> VerifyReport {
        verify(
            &self.remote(),
            &store.local(),
            &store.state(&self.folder),
            full,
        )
        .unwrap()
    }

    /// Fills a new empty directory from the remote, as a first pull does.
    fn bootstrap_into(
        &self,
        dir: TestDir,
        passphrase: &str,
    ) -> Result<Store, (TestDir, RemoteError)> {
        let base = dir.path().join("store");
        std::fs::create_dir_all(&base).unwrap();
        let remote_kdf = remote_kdf(&self.remote()).unwrap();
        let kdf: KdfParams = serde_json::from_slice(&remote_kdf.bytes).unwrap();
        let key = try_derive_key(passphrase, &kdf).unwrap();
        let mut state = RemoteState::open(&dir.path().join("state"), &self.folder).unwrap();
        match bootstrap(
            &self.remote(),
            &base,
            "replica",
            &key,
            &remote_kdf,
            &mut state,
        ) {
            Ok(report) => {
                assert_eq!(report.outcome, PullOutcome::Bootstrapped);
                drop(state);
                Ok(Store::open(dir, key))
            }
            Err(error) => Err((dir, error)),
        }
    }

    pub(crate) fn clone_store(&self, label: &str) -> Store {
        self.bootstrap_into(TestDir::new(label), PASSPHRASE)
            .map_err(|(_, error)| error)
            .unwrap()
    }
}

pub(crate) struct Store {
    pub(crate) dir: TestDir,
    pub(crate) base: PathBuf,
    pub(crate) key: [u8; 32],
    kdf_bytes: Vec<u8>,
    fingerprint: RecoveryFingerprint,
    pin: V2NamespacePin,
    pub(crate) head: CommitState,
    /// Name => (plaintext, encoded file root).
    files: BTreeMap<String, (Vec<u8>, String)>,
}

impl Store {
    fn create(label: &str, kdf: KdfParams, files: &[(&str, Vec<u8>)]) -> Self {
        Self::create_in(TestDir::new(label), kdf, files)
    }

    /// Creates the store in `dir/store`; `dir` must exist.
    pub(crate) fn create_in(dir: TestDir, kdf: KdfParams, files: &[(&str, Vec<u8>)]) -> Self {
        let base = dir.path().join("store");
        std::fs::create_dir_all(&base).unwrap();
        save_kdf(&base, &kdf).unwrap();
        let key = try_derive_key(PASSPHRASE, &kdf).unwrap();
        let (_, fingerprint) = load_kdf_with_fingerprint(&base).unwrap().unwrap();
        let mut entries = BTreeMap::new();
        for (name, plaintext) in files {
            let root = v2::import_authenticated_file(&base, &key, plaintext).unwrap();
            entries.insert(name.to_string(), (plaintext.clone(), root));
        }
        let head = v2::commit(&base, &key, &index_json(&entries), None, &fingerprint).unwrap();
        let pin = V2NamespacePin::capture(&base).unwrap();
        Self {
            kdf_bytes: std::fs::read(base.join("_kdf.json")).unwrap(),
            dir,
            base,
            key,
            fingerprint,
            pin,
            head,
            files: entries,
        }
    }

    pub(crate) fn origin(label: &str) -> Self {
        Self::create(
            label,
            test_kdf(),
            &[("a.txt", content(1, 100)), ("big.bin", content(2, 300_000))],
        )
    }

    /// Opens a replica the way the CLI does after a bootstrap.
    pub(crate) fn open(dir: TestDir, key: [u8; 32]) -> Self {
        let base = dir.path().join("store");
        let (_, fingerprint) = load_kdf_with_fingerprint(&base).unwrap().unwrap();
        let pin = V2NamespacePin::capture(&base).unwrap();
        v2::recover_with_namespace_pin(&base, &key, &fingerprint, &pin).unwrap();
        let (head, _) = replica::local_head(&base, &key, &pin).unwrap();
        let mut store = Self {
            kdf_bytes: std::fs::read(base.join("_kdf.json")).unwrap(),
            dir,
            base,
            key,
            fingerprint,
            pin,
            head,
            files: BTreeMap::new(),
        };
        store.reload();
        store
    }

    /// Re-reads the head and files after a pull.
    fn reload(&mut self) {
        let (index, head) = v2::load(&self.base, &self.key).unwrap();
        self.head = head;
        self.files = index
            .inodes
            .values()
            .filter(|inode| matches!(inode.kind, InodeKind::File))
            .map(|inode| {
                let plaintext = v2::read_file_range(
                    &self.base,
                    &self.key,
                    &inode.disk_filename,
                    inode.size,
                    0,
                    inode.size as usize,
                )
                .unwrap();
                (inode.name.clone(), (plaintext, inode.disk_filename.clone()))
            })
            .collect();
    }

    pub(crate) fn write(&mut self, name: &str, plaintext: Vec<u8>) {
        let root = v2::import_authenticated_file(&self.base, &self.key, &plaintext).unwrap();
        self.files.insert(name.to_string(), (plaintext, root));
        self.head = v2::commit(
            &self.base,
            &self.key,
            &index_json(&self.files),
            Some(&self.head),
            &self.fingerprint,
        )
        .unwrap();
    }

    pub(crate) fn contents(&self) -> BTreeMap<String, Vec<u8>> {
        self.files
            .iter()
            .map(|(name, (plaintext, _))| (name.clone(), plaintext.clone()))
            .collect()
    }

    pub(crate) fn local(&self) -> LocalStore<'_> {
        LocalStore {
            base: &self.base,
            key: &self.key,
            kdf_bytes: &self.kdf_bytes,
            kdf_fingerprint: &self.fingerprint,
            pin: &self.pin,
            display: "test-store",
        }
    }

    pub(crate) fn state(&self, folder: &str) -> RemoteState {
        RemoteState::open(&self.dir.path().join("state"), folder).unwrap()
    }
}

fn index_json(files: &BTreeMap<String, (Vec<u8>, String)>) -> Vec<u8> {
    let directory = |name: &str, parent| InodeEntry {
        name: name.to_string(),
        kind: InodeKind::Directory,
        disk_filename: String::new(),
        size: 0,
        perm: 0o755,
        uid: 501,
        gid: 20,
        atime_secs: 1,
        mtime_secs: 1,
        ctime_secs: 1,
        nlink: 2,
        parent,
    };
    let mut inodes = HashMap::from([(1, directory("", 1))]);
    let mut children = Vec::new();
    for (position, (name, (plaintext, root))) in files.iter().enumerate() {
        let inode = position as u64 + 2;
        inodes.insert(
            inode,
            InodeEntry {
                name: name.clone(),
                kind: InodeKind::File,
                disk_filename: root.clone(),
                size: plaintext.len() as u64,
                perm: 0o600,
                uid: 501,
                gid: 20,
                atime_secs: 1,
                mtime_secs: 1,
                ctime_secs: 1,
                nlink: 1,
                parent: 1,
            },
        );
        children.push(DirChild {
            name: name.clone(),
            inode,
        });
    }
    serde_json::to_vec(&DiskIndex {
        next_inode: files.len() as u64 + 2,
        next_file_id: 1,
        inodes,
        children: HashMap::from([(1, children)]),
    })
    .unwrap()
}

/// Times a first pull of many small files from the fake Drive, the local
/// install path without network latency. Release build, one run per call:
///
/// ```fish
/// set -x ZDRIVE_PULL_BENCH_FILES 2000
/// set -x ZDRIVE_BENCH_OUT ~/pull-bench.jsonl
/// cargo test --release --locked bench_first_pull -- --ignored --nocapture
/// ```
#[test]
#[ignore = "benchmark; run explicitly with --ignored in a release build"]
fn bench_first_pull_of_many_small_files() {
    let count: usize = std::env::var("ZDRIVE_PULL_BENCH_FILES")
        .map_or(2_000, |value| value.parse().expect("a file count"));
    let files: Vec<(String, Vec<u8>)> = (0..count)
        .map(|number| {
            // 4-64 KiB, unique per file, like the W2 workload.
            let len = 4096 + (number * 7_919) % (60 * 1024);
            let mut bytes = content((number % 251) as u8, len);
            bytes[CANARY.len()..CANARY.len() + 8].copy_from_slice(&(number as u64).to_le_bytes());
            (format!("f{number:05}.bin"), bytes)
        })
        .collect();
    let named: Vec<(&str, Vec<u8>)> = files
        .iter()
        .map(|(name, bytes)| (name.as_str(), bytes.clone()))
        .collect();
    let env = Env::new();
    let origin = Store::create("bench-pull-origin", test_kdf(), &named);
    env.push(&origin).unwrap();
    let dir = TestDir::new("bench-pull");
    let base = dir.path().join("store");
    std::fs::create_dir_all(&base).unwrap();
    let remote_kdf = remote_kdf(&env.remote()).unwrap();
    let mut state = RemoteState::open(&dir.path().join("state"), &env.folder).unwrap();
    let mut load = [0f64; 3];
    // SAFETY: getloadavg writes at most three values into the array.
    unsafe { libc::getloadavg(load.as_mut_ptr(), 3) };
    let started = std::time::Instant::now();
    let report = bootstrap(
        &env.remote(),
        &base,
        "replica",
        &origin.key,
        &remote_kdf,
        &mut state,
    )
    .unwrap();
    let elapsed = started.elapsed();
    assert_eq!(report.outcome, PullOutcome::Bootstrapped);
    let line = serde_json::json!({
        "version": env!("CARGO_PKG_VERSION"),
        "files": count,
        "objects": report.objects,
        "packs": report.packs,
        "bytes": report.bytes,
        "elapsed_ms": elapsed.as_secs_f64() * 1000.0,
        "per_object_us": elapsed.as_secs_f64() * 1e6 / report.objects.max(1) as f64,
        "loadavg_1m": load[0],
        "temp_dir": std::env::temp_dir(),
    })
    .to_string();
    eprintln!("{line}");
    if let Ok(out) = std::env::var("ZDRIVE_BENCH_OUT") {
        use std::io::Write as _;
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(out)
            .unwrap();
        writeln!(file, "{line}").unwrap();
    }
}

fn root_records(env: &Env, number: u64) -> usize {
    env.named(".zr")
        .iter()
        .filter(|file| parse_root_record_name(&file.name).is_some_and(|(n, _)| n == number))
        .count()
}

pub(crate) fn only_pack(env: &Env) -> crate::remote::fake::FakeFile {
    let packs = env.named(".zpk");
    assert_eq!(packs.len(), 1, "expected exactly one pack");
    packs.into_iter().next().unwrap()
}

#[test]
fn push_then_bootstrap_round_trips_every_file_as_ciphertext_only() {
    let env = Env::new();
    let origin = Store::origin("round-trip-origin");
    let report = env.push(&origin).unwrap();
    assert_eq!(report.number, origin.head.number);
    assert_eq!(report.previous, None);
    assert_eq!((report.packs, report.up_to_date), (1, false));
    assert!(report.objects >= 4, "{report:?}");

    let replica = env.clone_store("round-trip-replica");
    assert_eq!(replica.contents(), origin.contents());
    assert_eq!(replica.head.generation, origin.head.generation);
    assert!(!bootstrap_pending(&replica.base).unwrap());
    for file in env.fake.files() {
        assert!(
            !file
                .content
                .windows(CANARY.len())
                .any(|window| window == CANARY),
            "{} holds plaintext",
            file.name
        );
    }

    assert!(env.push(&origin).unwrap().up_to_date);
    let mut replica = replica;
    assert_eq!(
        env.pull(&mut replica).unwrap().outcome,
        PullOutcome::UpToDate
    );
    assert_eq!(env.status(&replica).relation, Relation::Equal);
    assert_eq!(root_records(&env, origin.head.number), 1);
}

#[test]
fn incremental_push_and_pull_fast_forward_several_generations_both_ways() {
    let env = Env::new();
    let mut origin = Store::origin("incremental-origin");
    env.push(&origin).unwrap();
    let mut replica = env.clone_store("incremental-replica");
    let first = origin.head.number;

    origin.write("b.txt", content(3, 5_000));
    origin.write("a.txt", content(4, 70_000));
    let pushed = env.push(&origin).unwrap();
    assert_eq!(
        (pushed.previous, pushed.generations, pushed.packs),
        (Some(first), 2, 1)
    );

    let pulled = env.pull(&mut replica).unwrap();
    assert_eq!(pulled.outcome, PullOutcome::Advanced);
    assert_eq!(
        (pulled.generations, pulled.packs),
        (2, 1),
        "only the new pack is fetched"
    );
    assert_eq!(pulled.number, origin.head.number);
    assert_eq!(replica.contents(), origin.contents());

    replica.write("c.txt", content(5, 1));
    env.push(&replica).unwrap();
    let back = env.pull(&mut origin).unwrap();
    assert_eq!((back.outcome, back.generations), (PullOutcome::Advanced, 1));
    assert_eq!(origin.contents(), replica.contents());
    assert_eq!(env.status(&origin).relation, Relation::Equal);
    assert!(env.verify(&origin, true).problems.is_empty());
}

#[test]
fn diverged_histories_are_refused_and_every_record_is_preserved() {
    let env = Env::new();
    let mut origin = Store::origin("diverge-origin");
    env.push(&origin).unwrap();
    let mut replica = env.clone_store("diverge-replica");
    origin.write("a.txt", content(6, 10));
    replica.write("a.txt", content(7, 10));
    env.push(&origin).unwrap();

    assert!(matches!(
        env.pull(&mut replica),
        Err(RemoteError::Diverged(_))
    ));
    assert!(matches!(env.push(&replica), Err(RemoteError::Diverged(_))));
    assert_eq!(env.status(&replica).relation, Relation::Diverged);
    replica.write("b.txt", content(8, 10));
    assert!(matches!(env.push(&replica), Err(RemoteError::Diverged(_))));
    assert_eq!(env.named(".zr").len(), 2);
    assert_eq!(replica.contents()["a.txt"], content(7, 10));
}

#[test]
fn push_requires_a_pull_when_the_remote_is_newer() {
    let env = Env::new();
    let mut origin = Store::origin("newer-origin");
    env.push(&origin).unwrap();
    let mut replica = env.clone_store("newer-replica");
    origin.write("a.txt", content(9, 10));
    env.push(&origin).unwrap();
    assert_eq!(env.status(&replica).relation, Relation::RemoteAhead);
    let refused = env.push(&replica);
    assert!(
        matches!(refused, Err(RemoteError::Conflict(_))),
        "{refused:?}"
    );
    env.pull(&mut replica).unwrap();
    replica.write("b.txt", content(10, 10));
    env.push(&replica).unwrap();

    origin.write("c.txt", content(11, 10));
    let mut ahead = env.clone_store("newer-ahead");
    ahead.write("d.txt", content(12, 10));
    assert_eq!(
        env.pull(&mut ahead).unwrap().outcome,
        PullOutcome::LocalAhead
    );
    assert_eq!(env.status(&ahead).relation, Relation::LocalAhead);
}

#[test]
fn bootstrap_with_the_wrong_passphrase_writes_nothing() {
    let env = Env::new();
    env.push(&Store::origin("wrong-key-origin")).unwrap();
    let (dir, error) = match env.bootstrap_into(TestDir::new("wrong-key"), "not the passphrase") {
        Ok(_) => panic!("a wrong passphrase bootstrapped"),
        Err(failure) => failure,
    };
    assert!(matches!(error, RemoteError::Auth(_)), "{error}");
    assert_eq!(
        std::fs::read_dir(dir.path().join("store")).unwrap().count(),
        0
    );
}

#[test]
fn a_different_store_cannot_push_into_the_folder() {
    let env = Env::new();
    env.push(&Store::origin("foreign-store-origin")).unwrap();
    let mut kdf = test_kdf();
    kdf.salt = vec![7; kdf.salt.len()];
    let other = Store::create("foreign-store-other", kdf, &[("x", content(13, 10))]);
    assert!(matches!(env.push(&other), Err(RemoteError::Diverged(_))));
    assert_eq!(env.status(&other).relation, Relation::DifferentStore);
}

#[test]
fn pull_without_a_remote_store_is_not_found() {
    let env = Env::new();
    let mut origin = Store::origin("empty-remote");
    assert!(matches!(
        env.pull(&mut origin),
        Err(RemoteError::NotFound(_))
    ));
    assert_eq!(env.status(&origin).relation, Relation::NoRemoteStore);
}

#[test]
fn a_damaged_pack_is_reported_and_its_objects_are_uploaded_again() {
    let env = Env::new();
    let mut origin = Store::origin("damaged-origin");
    let first = env.push(&origin).unwrap();
    let pack = only_pack(&env);
    let mut damaged = pack.content.clone();
    damaged[100] ^= 0xff;
    env.fake.overwrite(&pack.id, &damaged);

    let report = env.verify(&origin, false);
    assert!(
        report
            .problems
            .iter()
            .any(|problem| problem.contains("damaged")),
        "{report:?}"
    );
    assert!(
        report
            .problems
            .iter()
            .any(|problem| problem.contains("no intact pack")),
        "{report:?}"
    );

    origin.write("b.txt", content(14, 10));
    let repaired = env.push(&origin).unwrap();
    assert!(
        repaired.objects > first.objects,
        "{repaired:?} vs {first:?}"
    );
    let replica = env.clone_store("damaged-replica");
    assert_eq!(replica.contents(), origin.contents());
    let report = env.verify(&origin, true);
    assert_eq!(report.problems.len(), 1, "{report:?}");
}

#[test]
fn a_bootstrap_without_an_intact_copy_fails_closed_and_resumes() {
    let env = Env::new();
    let origin = Store::origin("closed-origin");
    env.push(&origin).unwrap();
    let pack = only_pack(&env);
    let mut damaged = pack.content.clone();
    damaged[100] ^= 0xff;
    env.fake.overwrite(&pack.id, &damaged);

    let (dir, error) = match env.bootstrap_into(TestDir::new("closed-replica"), PASSPHRASE) {
        Ok(_) => panic!("bootstrapped without the objects"),
        Err(failure) => failure,
    };
    assert!(matches!(error, RemoteError::NotFound(_)), "{error}");
    let base = dir.path().join("store");
    assert!(bootstrap_pending(&base).unwrap());
    assert!(replica::read_root_bytes(&base).unwrap().is_none());

    env.fake.overwrite(&pack.id, &pack.content);
    let replica = env
        .bootstrap_into(dir, PASSPHRASE)
        .map_err(|(_, error)| error)
        .unwrap();
    assert_eq!(replica.contents(), origin.contents());
    assert!(!bootstrap_pending(&replica.base).unwrap());
}

/// The local object files of the store at `base`.
pub(crate) fn object_files(base: &Path) -> std::collections::BTreeSet<PathBuf> {
    let objects = v2::selected_object_directory(base)
        .unwrap()
        .join(v2::OBJECTS_DIRECTORY);
    std::fs::read_dir(objects)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .collect()
}

/// Leaves the object file at `path` as power loss before its barrier can:
/// cut short, or at full length but zeroed. Its torn bytes.
pub(crate) fn tear(path: &Path, cut: bool) -> Vec<u8> {
    use std::os::unix::fs::FileExt as _;
    let len = std::fs::metadata(path).unwrap().len();
    let file = OpenOptions::new().write(true).open(path).unwrap();
    if cut {
        file.set_len(len / 2).unwrap();
    } else {
        file.write_all_at(&vec![0; len as usize], 0).unwrap();
    }
    std::fs::read(path).unwrap()
}

/// The bytes kept under `state/damaged`, sorted.
pub(crate) fn damaged_evidence(state: &Path) -> Vec<Vec<u8>> {
    let dir = state.join("damaged");
    let Ok(entries) = std::fs::read_dir(&dir) else {
        return Vec::new();
    };
    let mut kept: Vec<Vec<u8>> = entries
        .map(|entry| {
            use std::os::unix::fs::PermissionsExt as _;
            let path = entry.unwrap().path();
            let mode = std::fs::metadata(&path).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600, "{}", path.display());
            std::fs::read(path).unwrap()
        })
        .collect();
    kept.sort();
    kept
}

/// Every replicated object is installed before the one barrier, and the
/// barrier precedes the publication `published` names.
fn assert_one_barrier_before(checkpoints: &[DurabilityCheckpoint], published: &str) {
    let position = |context: &str| -> Vec<(usize, DurabilityEvent)> {
        checkpoints
            .iter()
            .enumerate()
            .filter(|(_, checkpoint)| checkpoint.context == context)
            .map(|(index, checkpoint)| (index, checkpoint.event))
            .collect()
    };
    let installs = position(replica::INSTALL_CONTEXT);
    assert!(!installs.is_empty(), "{checkpoints:?}");
    assert!(
        installs
            .iter()
            .all(|(_, event)| *event != DurabilityEvent::DirectorySync),
        "an install syncs its directory: {checkpoints:?}"
    );
    let barriers = position(replica::SYNC_INSTALLED_CONTEXT);
    assert_eq!(
        barriers,
        vec![(barriers[0].0, DurabilityEvent::DirectorySync)],
        "{checkpoints:?}"
    );
    let barrier = barriers[0].0;
    assert!(installs.iter().all(|(index, _)| *index < barrier));
    let publication = *position(published)
        .first()
        .unwrap_or_else(|| panic!("no {published:?} in {checkpoints:?}"));
    assert!(barrier < publication.0, "{checkpoints:?}");
}

#[test]
fn a_pull_makes_its_objects_durable_with_one_barrier_before_publishing() {
    let env = Env::new();
    let mut origin = Store::origin("barrier-origin");
    env.push(&origin).unwrap();

    let recorder = FaultInjectionGuard::record();
    let mut replica = env.clone_store("barrier-replica");
    assert_one_barrier_before(&recorder.checkpoints(), "publish replicated v2 root");

    origin.write("b.txt", content(3, 5_000));
    origin.write("c.txt", content(4, 90_000));
    env.push(&origin).unwrap();
    let recorder = FaultInjectionGuard::record();
    assert_eq!(
        env.pull(&mut replica).unwrap().outcome,
        PullOutcome::Advanced
    );
    assert_one_barrier_before(&recorder.checkpoints(), "publish authenticated v2 manifest");
    drop(recorder);
    assert_eq!(replica.contents(), origin.contents());
}

#[test]
fn torn_objects_of_an_interrupted_pull_are_kept_as_evidence_and_replaced() {
    let env = Env::new();
    let mut origin = Store::origin("torn-pull-origin");
    env.push(&origin).unwrap();
    let mut replica = env.clone_store("torn-pull-replica");
    let old = replica.contents();
    let before = object_files(&replica.base);
    origin.write("b.txt", content(3, 5_000));
    origin.write("c.txt", content(4, 90_000));
    env.push(&origin).unwrap();

    let failing = FaultInjectionGuard::fail_at_matching(
        DurabilityCheckpoint::new(DurabilityEvent::FileSync, replica::INSTALL_CONTEXT),
        3,
    );
    let error = env.pull(&mut replica).unwrap_err();
    drop(failing);
    assert!(error.to_string().contains("injected crash"), "{error}");
    assert_eq!(replica.contents(), old, "nothing was published");
    let installed: Vec<_> = object_files(&replica.base)
        .difference(&before)
        .cloned()
        .collect();
    assert_eq!(installed.len(), 3, "{installed:?}");
    let mut torn = vec![tear(&installed[0], true), tear(&installed[1], false)];
    torn.sort();

    assert_eq!(
        env.pull(&mut replica).unwrap().outcome,
        PullOutcome::Advanced
    );
    assert_eq!(replica.contents(), origin.contents());
    assert_eq!(
        damaged_evidence(&replica.dir.path().join("state")),
        torn,
        "exactly the torn objects are kept; the intact one is reused"
    );
    assert!(env.verify(&replica, true).problems.is_empty());
}

#[test]
fn torn_objects_of_an_interrupted_bootstrap_are_replaced_when_it_resumes() {
    let env = Env::new();
    let origin = Store::origin("torn-bootstrap-origin");
    env.push(&origin).unwrap();

    let failing = FaultInjectionGuard::fail_at_matching(
        DurabilityCheckpoint::new(DurabilityEvent::FileSync, replica::INSTALL_CONTEXT),
        2,
    );
    let (dir, error) = match env.bootstrap_into(TestDir::new("torn-bootstrap"), PASSPHRASE) {
        Ok(_) => panic!("the bootstrap ignored its injected failure"),
        Err(failure) => failure,
    };
    drop(failing);
    assert!(error.to_string().contains("injected crash"), "{error}");
    let base = dir.path().join("store");
    assert!(bootstrap_pending(&base).unwrap());
    assert!(replica::read_root_bytes(&base).unwrap().is_none());
    let installed: Vec<_> = object_files(&base).into_iter().collect();
    assert_eq!(installed.len(), 2, "{installed:?}");
    let torn = tear(&installed[1], true);

    let state = dir.path().join("state");
    let replica = env
        .bootstrap_into(dir, PASSPHRASE)
        .map_err(|(_, error)| error)
        .unwrap();
    assert_eq!(replica.contents(), origin.contents());
    assert!(!bootstrap_pending(&replica.base).unwrap());
    assert_eq!(damaged_evidence(&state), vec![torn]);
}

#[test]
fn object_digests_reject_a_consistently_named_but_corrupted_pack() {
    let env = Env::new();
    let origin = Store::origin("forged-origin");
    env.push(&origin).unwrap();
    let pack = only_pack(&env);
    let mut forged = pack.content.clone();
    *forged.last_mut().unwrap() ^= 0xff;
    let name = pack_name(&md5_bytes(&forged), forged.len() as u64);
    env.fake.insert(&pack.parents[0], &name, None, &forged);

    let report = env.verify(&origin, true);
    assert_eq!(report.problems.len(), 1, "{report:?}");
    assert!(report.problems[0].contains("damaged copy"), "{report:?}");
    let replica = env.clone_store("forged-alternate");
    assert_eq!(replica.contents(), origin.contents());

    env.fake.remove(&pack.id);
    match env.bootstrap_into(TestDir::new("forged-only"), PASSPHRASE) {
        Ok(_) => panic!("installed a corrupted object"),
        Err((_, error)) => assert!(matches!(error, RemoteError::Integrity(_)), "{error}"),
    }
}

#[test]
fn foreign_and_misnamed_files_are_ignored() {
    let env = Env::new();
    let mut origin = Store::origin("foreign-origin");
    env.push(&origin).unwrap();
    let packs = only_pack(&env).parents[0].clone();
    let roots = env.named(".zr")[0].parents[0].clone();
    env.fake.insert(&packs, "notes.txt", None, b"hello");
    env.fake.insert(&packs, "deadbeef.zpk", None, b"junk");
    env.fake.insert(&roots, "readme.md", None, b"hello");
    env.fake.insert(&env.folder, "photo.jpg", None, b"jpeg");
    env.fake
        .insert(&env.folder, "packs", Some(FOLDER_MIME), b"");

    let replica = env.clone_store("foreign-replica");
    assert_eq!(replica.contents(), origin.contents());
    origin.write("b.txt", content(15, 10));
    env.push(&origin).unwrap();
    assert!(env.verify(&origin, false).problems.is_empty());
}

#[test]
fn listing_lag_neither_breaks_nor_duplicates_publication() {
    let env = Env::new();
    for _ in 0..40 {
        env.fake.fault(Op::List, Fault::ListLag);
    }
    let mut origin = Store::origin("lag-origin");
    env.push(&origin).unwrap();
    assert!(env.push(&origin).unwrap().up_to_date);
    origin.write("b.txt", content(16, 10));
    env.push(&origin).unwrap();
    env.drain_faults();
    assert_eq!(root_records(&env, origin.head.number - 1), 1);
    assert_eq!(root_records(&env, origin.head.number), 1);
    assert_eq!(env.named("zdrive-remote.json").len(), 1);
    let replica = env.clone_store("lag-replica");
    assert_eq!(replica.contents(), origin.contents());
}

#[test]
fn an_ambiguous_root_create_converges_on_its_saved_id() {
    let env = Env::resumable();
    let mut origin = Store::origin("ambiguous-origin");
    env.push(&origin).unwrap();
    // A pack above the multipart limit, so the faults below hit the root record.
    origin.write("b.bin", content(17, 300_000));
    env.fake.fault(Op::Multipart, Fault::CommitThenDrop);
    env.fake
        .fault(Op::Multipart, Fault::Status(400, "badRequest"));
    let failed = env.push(&origin);
    assert!(
        matches!(failed, Err(RemoteError::Protocol(_))),
        "{failed:?}"
    );
    let pending = origin
        .state(&env.folder)
        .record
        .pending_root
        .clone()
        .unwrap();
    assert_eq!(root_records(&env, origin.head.number), 1);

    for _ in 0..10 {
        env.fake.fault(Op::List, Fault::ListLag);
    }
    assert!(env.push(&origin).unwrap().up_to_date);
    env.drain_faults();
    assert_eq!(root_records(&env, origin.head.number), 1);
    let state = origin.state(&env.folder).record;
    assert!(state.pending_root.is_none());
    assert_eq!(state.synced.unwrap().record, pending.file_id);
    assert_eq!(
        env.clone_store("ambiguous-replica").contents(),
        origin.contents()
    );
}

#[test]
fn a_quota_failure_is_typed_and_the_sealed_pack_is_resumed() {
    let env = Env::new();
    let origin = Store::origin("quota-origin");
    env.fake.set_quota(Some(16 << 10));
    assert!(matches!(env.push(&origin), Err(RemoteError::Quota(_))));
    assert_eq!(origin.state(&env.folder).outgoing_packs().unwrap().len(), 1);
    assert_eq!(env.named(".zr").len(), 0);

    env.fake.set_quota(None);
    let report = env.push(&origin).unwrap();
    assert_eq!(report.packs, 1);
    assert!(report.objects >= 4, "{report:?}");
    assert_eq!(env.named(".zpk").len(), 1);
    assert!(
        origin
            .state(&env.folder)
            .outgoing_packs()
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        env.clone_store("quota-replica").contents(),
        origin.contents()
    );
}

#[test]
fn an_interrupted_resumable_upload_resumes_its_session() {
    let env = Env::resumable();
    let origin = Store::create(
        "session-origin",
        test_kdf(),
        &[("big.bin", content(18, 1 << 20))],
    );
    env.fake.fault(Op::Chunk, Fault::Status(400, "badRequest"));
    assert!(matches!(env.push(&origin), Err(RemoteError::Protocol(_))));
    let queued = origin.state(&env.folder).outgoing_packs().unwrap();
    assert_eq!(queued.len(), 1);
    assert!(queued[0].checkpoint.as_ref().unwrap().session_uri.is_some());
    assert_eq!(env.fake.count(Op::StartSession), 1);

    env.push(&origin).unwrap();
    assert_eq!(env.fake.count(Op::StartSession), 1);
    assert!(env.fake.count(Op::QuerySession) >= 1);
    assert_eq!(
        env.clone_store("session-replica").contents(),
        origin.contents()
    );
}

struct RevokedGrant;

impl crate::remote::gdrive::TokenSource for RevokedGrant {
    fn fetch(&self, _agent: &ureq::Agent) -> Result<(String, std::time::Duration), RemoteError> {
        Err(RemoteError::Auth(
            "Google refused the refresh token (invalid_grant)".to_string(),
        ))
    }
}

#[test]
fn a_revoked_grant_fails_as_auth_and_changes_nothing() {
    let env = Env::new();
    let mut origin = Store::origin("auth-origin");
    env.push(&origin).unwrap();
    let before = origin.state(&env.folder).record;
    origin.write("b.txt", content(20, 10));
    // Access tokens alone are refreshed transparently.
    env.fake.revoke_tokens();
    let revoked = GoogleDrive::with_endpoint(
        env.fake.base_url(),
        Box::new(RevokedGrant),
        FakeDrive::fast_policy(),
    );
    let remote = Remote {
        drive: &revoked,
        folder_id: &env.folder,
        log: &quiet,
    };
    let refused = push(&remote, &origin.local(), &mut origin.state(&env.folder));
    assert!(matches!(refused, Err(RemoteError::Auth(_))), "{refused:?}");
    assert_eq!(origin.state(&env.folder).record, before);
    assert_eq!(env.push(&origin).unwrap().number, origin.head.number);
}

#[test]
fn verify_walks_the_complete_remote_closure() {
    let env = Env::new();
    let mut origin = Store::origin("verify-origin");
    env.push(&origin).unwrap();
    origin.write("b.txt", content(19, 10));
    env.push(&origin).unwrap();
    let report = env.verify(&origin, true);
    assert!(report.problems.is_empty(), "{report:?}");
    assert_eq!(report.number, Some(origin.head.number));
    assert_eq!((report.generations, report.packs), (2, 2));
    assert!(report.objects >= 6, "{report:?}");
}

/// Requests `action` sends, by endpoint, without token refreshes.
fn requests<T>(env: &Env, action: impl FnOnce() -> T) -> (T, HashMap<Op, usize>) {
    const OPS: [Op; 11] = [
        Op::About,
        Op::List,
        Op::Get,
        Op::Media,
        Op::GenerateIds,
        Op::CreateFolder,
        Op::Multipart,
        Op::StartSession,
        Op::Chunk,
        Op::QuerySession,
        Op::Patch,
    ];
    let before = OPS.map(|op| env.fake.count(op));
    let result = action();
    let sent = OPS
        .into_iter()
        .zip(before)
        .map(|(op, count)| (op, env.fake.count(op) - count))
        .filter(|(_, count)| *count > 0)
        .collect();
    (result, sent)
}

#[test]
fn steady_state_sync_reads_neither_the_layout_nor_known_records_again() {
    let env = Env::new();
    let mut origin = Store::origin("steady-origin");
    let (_, sent) = requests(&env, || env.push(&origin).unwrap());
    assert_eq!(sent[&Op::CreateFolder], 3);
    assert_eq!(sent[&Op::GenerateIds], 2);

    origin.write("b.txt", content(20, 10));
    let (report, sent) = requests(&env, || env.push(&origin).unwrap());
    assert!(!report.up_to_date);
    // Folder, roots and packs at once; roots before and after publication.
    assert_eq!(
        sent,
        HashMap::from([(Op::List, 5), (Op::GenerateIds, 1), (Op::Multipart, 2)])
    );
    let (report, sent) = requests(&env, || env.push(&origin).unwrap());
    assert!(report.up_to_date);
    assert_eq!(sent, HashMap::from([(Op::List, 3)]));
    let (report, sent) = requests(&env, || env.status(&origin));
    assert_eq!(report.relation, Relation::Equal);
    assert_eq!(sent, HashMap::from([(Op::List, 3)]));
    let mut origin = origin;
    let (report, sent) = requests(&env, || env.pull(&mut origin).unwrap());
    assert_eq!(report.outcome, PullOutcome::UpToDate);
    assert_eq!(sent, HashMap::from([(Op::List, 2)]));

    // A replica authenticates a record it has not seen yet, once.
    let mut replica = env.clone_store("steady-replica");
    origin.write("c.txt", content(21, 10));
    env.push(&origin).unwrap();
    let (report, sent) = requests(&env, || env.pull(&mut replica).unwrap());
    assert_eq!(report.outcome, PullOutcome::Advanced);
    assert_eq!(sent[&Op::List], 3);
    assert!(!sent.contains_key(&Op::Get), "{sent:?}");
    assert_eq!(replica.contents(), origin.contents());
    let (_, sent) = requests(&env, || env.pull(&mut replica).unwrap());
    assert_eq!(sent, HashMap::from([(Op::List, 2)]));
}

#[test]
fn verify_authenticates_every_record_again() {
    let env = Env::new();
    let origin = Store::origin("verify-fresh-origin");
    env.push(&origin).unwrap();
    let (report, sent) = requests(&env, || env.verify(&origin, false));
    assert!(report.problems.is_empty(), "{:?}", report.problems);
    // The marker, the root record and the pack header, read again.
    assert_eq!(sent[&Op::Media], 3, "{sent:?}");
}

#[test]
fn a_new_marker_or_changed_key_material_replaces_the_cached_layout() {
    let env = Env::new();
    let mut origin = Store::origin("relayout-origin");
    env.push(&origin).unwrap();
    let ours = env.named("zdrive-remote.json").remove(0);

    // A concurrent initializer's marker with a smaller id wins over ours.
    let theirs = env
        .fake
        .insert(&env.folder, "zdrive-remote.json", None, &ours.content);
    assert!(theirs < ours.id);
    origin.write("b.txt", content(22, 10));
    let (_, sent) = requests(&env, || env.push(&origin).unwrap());
    assert_eq!(sent[&Op::Media], 1, "the new marker is read once: {sent:?}");
    let layout = origin.state(&env.folder).record.layout.unwrap();
    assert_eq!(layout.marker, theirs);

    // An unreadable winning marker is refused rather than masked.
    env.fake.overwrite(&theirs, b"not a marker");
    assert!(matches!(env.push(&origin), Err(RemoteError::Protocol(_))));
    env.fake.overwrite(&theirs, &ours.content);
    assert!(env.push(&origin).unwrap().up_to_date);

    // Key material changed under the cached layout is refused as well.
    let kdf = env.named("_kdf.json").remove(0);
    env.fake.overwrite(&kdf.id, b"{}");
    assert!(matches!(
        status(
            &env.remote(),
            &origin.local(),
            &mut origin.state(&env.folder)
        ),
        Err(RemoteError::Integrity(_))
    ));
    assert!(matches!(env.push(&origin), Err(RemoteError::Integrity(_))));
    assert!(matches!(
        env.pull(&mut origin),
        Err(RemoteError::Integrity(_))
    ));
}

#[test]
fn a_known_record_never_hides_a_rival_generation() {
    let env = Env::new();
    let mut origin = Store::origin("rival-origin");
    env.push(&origin).unwrap();
    let mut replica = env.clone_store("rival-replica");
    origin.write("a.txt", content(23, 10));
    replica.write("a.txt", content(24, 10));
    env.push(&origin).unwrap();
    assert_eq!(env.status(&origin).relation, Relation::Equal);

    // The replica's generation of the same number, published beside it.
    let rival = replica::read_root_bytes(&replica.base).unwrap().unwrap();
    let roots = env.named(".zr")[0].parents[0].clone();
    env.fake.insert(
        &roots,
        &root_record_name(replica.head.number, &md5_bytes(&rival)),
        None,
        &rival,
    );
    assert_eq!(replica.head.number, origin.head.number);
    assert_eq!(env.status(&origin).relation, Relation::Forked);
    assert!(matches!(env.push(&origin), Err(RemoteError::Diverged(_))));
    assert!(matches!(
        env.pull(&mut origin),
        Err(RemoteError::Diverged(_))
    ));
}
