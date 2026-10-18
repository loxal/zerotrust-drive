// SPDX-FileCopyrightText: Copyright 2026 Alexander Orlov <info@lifub.com>

//! Drive for desktop against `zdrive` replication of identical encrypted
//! stores, on the live account of a remote that `zdrive remote auth`
//! configured. Only the replication path differs between the arms:
//!
//! - native: the store directory moves into the folder Drive for desktop
//!   syncs (`native`, a sibling of the remote folder's local mirror), and
//!   the Drive API is polled until every file matches by size and md5;
//! - ours: the same bytes, kept outside any synced folder, are pushed into a
//!   fresh folder below the remote's folder.
//!
//! The clock starts once the store is durable locally. The native poller
//! also records how long Drive showed a `_root.age` whose objects it did
//! not hold yet: the window in which another machine would read a broken
//! store. Each workload appends one JSON line per arm to
//! `ZDRIVE_BENCH_OUT`. Drive for desktop itself is never touched.
//!
//! ```fish
//! set -x ZDRIVE_RUN_GDRIVE_TESTS 1
//! set -x ZDRIVE_GDRIVE_REMOTE gdrive-test
//! set -x ZDRIVE_GDRIVE_MIRROR ~/g.drive/zerotrust-drive-test/api
//! set -x ZDRIVE_BENCH_OUT ~/bench.jsonl
//! read -s -x ZEROTRUST_PASSPHRASE
//! cargo test --release --locked remote::mount::bench -- --ignored --test-threads=1 --nocapture
//! ```
//!
//! `ZDRIVE_BENCH_REPEAT` (the repetition number; odd runs push first),
//! `ZDRIVE_BENCH_LOCAL` (default `~/zerotrust.drive/test`),
//! `ZDRIVE_BENCH_CALIBRATE_MIB`, `ZDRIVE_BENCH_LARGE_MIB`,
//! `ZDRIVE_BENCH_SMALL_FILES`, `ZDRIVE_BENCH_EDITS`, `ZDRIVE_BENCH_POLL_MS`
//! and `ZDRIVE_BENCH_TIMEOUT_MIN` adjust a run.

use std::collections::BTreeMap;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use super::*;
use crate::fs::ZeroTrustFs;
use crate::remote::TestDir;
use crate::remote::cli::Action;
use crate::remote::cli::live::{Account, Live, check_mirror, empty_replica};
use crate::remote::config::test_kdf;
use crate::remote::sync::tests::{PASSPHRASE, Store, content};
use crate::v2;

const MIB: usize = 1 << 20;
/// The store's chunk size: each edit below rewrites one chunk.
const CHUNK: usize = 4 * MIB;
/// The only file of a single-file store.
const ONLY_FILE: u64 = 2;
const ROOT: &str = "_root.age";
const OBJECTS: &str = "_zdrive-v2/objects";

/// Relative path to size and md5 of every file below a directory.
type Manifest = BTreeMap<String, (u64, [u8; 16])>;
/// Relative path to size and md5 as Drive reports them.
type Tree = BTreeMap<String, (Option<u64>, Option<[u8; 16]>)>;

fn env_number(name: &str, default: u64) -> u64 {
    std::env::var(name).map_or(default, |value| {
        value
            .parse()
            .unwrap_or_else(|_| panic!("{name} must be a number"))
    })
}

fn home() -> PathBuf {
    PathBuf::from(std::env::var("HOME").expect("HOME"))
}

fn manifest(dir: &Path) -> Manifest {
    let mut files = Manifest::new();
    let mut pending = vec![(dir.to_path_buf(), String::new())];
    while let Some((path, prefix)) = pending.pop() {
        for entry in std::fs::read_dir(&path).unwrap() {
            let entry = entry.unwrap();
            let name = entry.file_name().into_string().unwrap();
            let relative = format!("{prefix}{name}");
            if entry.file_type().unwrap().is_dir() {
                pending.push((entry.path(), format!("{relative}/")));
            } else {
                let bytes = std::fs::read(entry.path()).unwrap();
                files.insert(
                    relative,
                    (bytes.len() as u64, crate::remote::md5_bytes(&bytes)),
                );
            }
        }
    }
    files
}

fn tree(drive: &GoogleDrive, folder: &str) -> Tree {
    let mut files = Tree::new();
    let mut pending = vec![(folder.to_string(), String::new())];
    while let Some((parent, prefix)) = pending.pop() {
        for file in drive.list(&parent, false).unwrap() {
            let relative = format!("{prefix}{}", file.name);
            if file.is_folder() {
                pending.push((file.id.clone(), format!("{relative}/")));
            } else {
                files.insert(relative, (file.size(), file.md5()));
            }
        }
    }
    files
}

fn child_folder(drive: &GoogleDrive, parent: &str, name: &str) -> Option<String> {
    drive
        .list(parent, true)
        .unwrap()
        .into_iter()
        .find(|file| file.name == name)
        .map(|file| file.id)
}

/// The root a store published and every file another machine needs to
/// open it: the key material and the objects present when it was
/// published. Objects are immutable, so their size identifies them.
struct Generation {
    root: [u8; 16],
    needs: BTreeMap<String, u64>,
}

impl Generation {
    fn capture(base: &Path) -> Self {
        let root = crate::remote::md5_bytes(&std::fs::read(base.join(ROOT)).unwrap());
        let mut needs = BTreeMap::new();
        for entry in std::fs::read_dir(base.join(OBJECTS)).unwrap() {
            let entry = entry.unwrap();
            let name = entry.file_name().into_string().unwrap();
            needs.insert(format!("{OBJECTS}/{name}"), entry.metadata().unwrap().len());
        }
        let kdf = std::fs::metadata(base.join("_kdf.json")).unwrap().len();
        needs.insert("_kdf.json".to_string(), kdf);
        Self { root, needs }
    }
}

/// What the native poller saw.
#[derive(Default)]
struct Observed {
    /// The first poll at which Drive held every file of the final store.
    complete: Option<Instant>,
    /// The first poll at which Drive held the final root, the key material
    /// and every object: what another machine needs to open the store, and
    /// what `zdrive` uploads. Drive for desktop also uploads the store's
    /// local evidence files, which `zdrive` does not replicate.
    replicated: Option<Instant>,
    polls: u64,
    /// Polls that showed a known root with objects of it missing.
    broken_polls: u64,
    most_missing: usize,
    first_broken: Option<Instant>,
    last_broken: Option<Instant>,
    /// Polls that showed a root no local generation published.
    unknown_roots: u64,
    remote_files: usize,
    missing_at_end: usize,
    /// Up to ten files of the final store Drive lacked when polling ended.
    missing_paths: Vec<String>,
}

/// Polls Drive until the folder `run` below `parent` holds `last` once it
/// is known.
fn observe_native(
    drive: &GoogleDrive,
    parent: String,
    run: String,
    generations: Arc<Mutex<Vec<Generation>>>,
    last: Arc<Mutex<Option<Manifest>>>,
    poll: Duration,
    timeout: Duration,
) -> Observed {
    let deadline = Instant::now() + timeout;
    let mut seen = Observed::default();
    let mut folder = None;
    loop {
        let started = Instant::now();
        if folder.is_none() {
            folder = child_folder(drive, &parent, &run);
        }
        let remote = folder
            .as_deref()
            .map(|id| tree(drive, id))
            .unwrap_or_default();
        let at = Instant::now();
        seen.polls += 1;
        if let Some((_, Some(root))) = remote.get(ROOT) {
            let generations = generations.lock().unwrap();
            match generations
                .iter()
                .find(|generation| generation.root == *root)
            {
                Some(generation) => {
                    let missing = generation
                        .needs
                        .iter()
                        .filter(|(path, size)| {
                            remote.get(*path).map(|(remote, _)| *remote) != Some(Some(**size))
                        })
                        .count();
                    if missing > 0 {
                        seen.broken_polls += 1;
                        seen.most_missing = seen.most_missing.max(missing);
                        seen.first_broken.get_or_insert(at);
                        seen.last_broken = Some(at);
                    }
                }
                None => seen.unknown_roots += 1,
            }
        }
        if let Some(last) = last.lock().unwrap().as_ref() {
            seen.remote_files = remote.len();
            let missing: Vec<&String> = last
                .iter()
                .filter(|(path, (size, md5))| remote.get(*path) != Some(&(Some(*size), Some(*md5))))
                .map(|(path, _)| path)
                .collect();
            seen.missing_at_end = missing.len();
            seen.missing_paths = missing
                .iter()
                .take(10)
                .map(|path| path.to_string())
                .collect();
            if seen.replicated.is_none() && !missing.iter().any(|path| is_replicated(path)) {
                seen.replicated = Some(at);
            }
            if missing.is_empty() {
                seen.complete = Some(at);
                break;
            }
        }
        if Instant::now() >= deadline {
            break;
        }
        std::thread::sleep(poll.saturating_sub(started.elapsed()));
    }
    seen
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Arm {
    Native,
    Ours,
}

struct Bench {
    account: Account,
    local: PathBuf,
    native: PathBuf,
    native_id: String,
    mirror: PathBuf,
    poll: Duration,
    timeout: Duration,
    repeat: u64,
    out: Option<PathBuf>,
}

impl Bench {
    fn open() -> Self {
        let account = Account::open();
        let mirror = PathBuf::from(
            std::env::var("ZDRIVE_GDRIVE_MIRROR")
                .expect("set ZDRIVE_GDRIVE_MIRROR to the local mirror of the remote's folder"),
        );
        let native = mirror
            .parent()
            .expect("the mirror has a parent")
            .join("native");
        let local = std::env::var("ZDRIVE_BENCH_LOCAL")
            .map_or_else(|_| home().join("zerotrust.drive/test"), PathBuf::from);
        std::fs::create_dir_all(&native).unwrap();
        std::fs::create_dir_all(&local).unwrap();
        let drive = &account.drive;
        let info = drive.about().unwrap();
        let gib = |bytes: Option<u64>| bytes.map(|bytes| bytes as f64 / f64::from(1 << 30));
        eprintln!(
            "quota: {:?} GiB used of {:?} GiB",
            gib(info.usage),
            gib(info.limit)
        );
        let parent = drive.get(&account.config.folder_id).unwrap().parents[0].clone();
        let deadline = Instant::now() + Duration::from_secs(300);
        let native_id = loop {
            if let Some(id) = child_folder(drive, &parent, "native") {
                break id;
            }
            assert!(
                Instant::now() < deadline,
                "Drive for desktop did not upload {}",
                native.display()
            );
            std::thread::sleep(Duration::from_secs(5));
        };
        Self {
            account,
            local,
            native,
            native_id,
            mirror,
            poll: Duration::from_millis(env_number("ZDRIVE_BENCH_POLL_MS", 2_000)),
            timeout: Duration::from_secs(60 * env_number("ZDRIVE_BENCH_TIMEOUT_MIN", 180)),
            repeat: env_number("ZDRIVE_BENCH_REPEAT", 0),
            out: std::env::var("ZDRIVE_BENCH_OUT").ok().map(PathBuf::from),
        }
    }

    fn drive(&self) -> &GoogleDrive {
        &self.account.drive
    }

    fn arms(&self) -> [Arm; 2] {
        if self.repeat.is_multiple_of(2) {
            [Arm::Native, Arm::Ours]
        } else {
            [Arm::Ours, Arm::Native]
        }
    }

    fn run_name(&self, workload: &str) -> String {
        let mut nonce = [0u8; 4];
        crate::crypto::fill_random(&mut nonce);
        format!(
            "bench-{workload}-r{}-{}",
            self.repeat,
            crate::remote::hex(&nonce)
        )
    }

    /// A store at `local/run/store`, and its byte-identical clone staged
    /// beside it for the native arm.
    fn create(&self, run: &str, files: &[(&str, Vec<u8>)]) -> (Store, PathBuf) {
        let dir = self.local.join(run);
        std::fs::create_dir_all(&dir).unwrap();
        let started = Instant::now();
        let store = Store::create_in(TestDir(dir), test_kdf(), files);
        let stage = self.local.join(format!("{run}-native"));
        let status = std::process::Command::new("cp")
            .arg("-cR")
            .arg(&store.base)
            .arg(&stage)
            .status()
            .unwrap();
        assert!(status.success(), "clone the store for the native arm");
        assert_eq!(manifest(&stage), manifest(&store.base));
        eprintln!("built {run} in {:.2?}", started.elapsed());
        (store, stage)
    }

    fn record(&self, values: serde_json::Value) {
        eprintln!("RESULT {values}");
        if let Some(out) = &self.out {
            let mut file = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(out)
                .unwrap();
            writeln!(file, "{values}").unwrap();
        }
    }

    /// Starts the native poller for `run`; `last` stays open until known.
    fn watch_native(
        &self,
        run: &str,
        generations: Arc<Mutex<Vec<Generation>>>,
        last: Arc<Mutex<Option<Manifest>>>,
    ) -> std::thread::JoinHandle<Observed> {
        let drive = self.account.client();
        let (parent, run) = (self.native_id.clone(), run.to_string());
        let (poll, timeout) = (self.poll, self.timeout);
        std::thread::spawn(move || {
            observe_native(&drive, parent, run, generations, last, poll, timeout)
        })
    }

    /// Moves a staged store into the native folder, then waits until Drive
    /// holds all of it. Returns the time until then, or until polling gave
    /// up, and the time until Drive held what a replica needs.
    fn native_bulk(&self, run: &str, stage: &Path) -> (Duration, Option<Duration>, Observed) {
        let generations = Arc::new(Mutex::new(vec![Generation::capture(stage)]));
        let last = Arc::new(Mutex::new(Some(manifest(stage))));
        let target = self.native.join(run);
        let watcher = self.watch_native(run, generations, last);
        let started = Instant::now();
        std::fs::rename(stage, &target).unwrap();
        let seen = watcher.join().unwrap();
        let took = seen
            .complete
            .map_or_else(|| started.elapsed(), |at| at - started);
        let replicated = seen.replicated.map(|at| at - started);
        (took, replicated, seen)
    }

    /// Waits until Drive for desktop mirrored everything a push uploaded,
    /// so its downloads do not overlap the next measurement, and checks the
    /// mirrored bytes.
    fn settle(&self, live: &Live) {
        let mirror = self.mirror.join(&live.run);
        let started = Instant::now();
        loop {
            let found = check_mirror(self.drive(), &live.folder, &mirror);
            if found.absent == 0 {
                eprintln!(
                    "mirror identical after {:.2?}: {} files, {} bytes",
                    started.elapsed(),
                    found.identical,
                    found.bytes
                );
                return;
            }
            assert!(
                started.elapsed() < Duration::from_secs(1_800),
                "Drive for desktop did not mirror {} files",
                found.absent
            );
            std::thread::sleep(Duration::from_secs(5));
        }
    }

    fn remove_native(&self, run: &str) {
        if std::env::var("ZDRIVE_GDRIVE_KEEP").as_deref() != Ok("1") {
            std::fs::remove_dir_all(self.native.join(run)).unwrap();
        }
    }
}

/// The bytes a replica shares with its origin: the root, the key material
/// and every object. Each was authenticated on the way in.
fn is_replicated(path: &str) -> bool {
    path == ROOT
        || path == "_kdf.json"
        || path
            .strip_prefix(OBJECTS)
            .is_some_and(|rest| rest.starts_with('/'))
}

fn replicated(base: &Path) -> Manifest {
    let mut files = manifest(base);
    files.retain(|path, _| is_replicated(path));
    files
}

fn remote_size(live: &Live) -> (usize, u64) {
    let files: Vec<_> = live
        .files()
        .into_iter()
        .filter(|file| !file.is_folder())
        .collect();
    let bytes = files.iter().filter_map(|file| file.size()).sum();
    (files.len(), bytes)
}

fn local_size(manifest: &Manifest) -> (usize, u64) {
    (
        manifest.len(),
        manifest.values().map(|(size, _)| size).sum(),
    )
}

/// Times both arms on one store created in one piece, then a first pull
/// of what the push uploaded.
fn bulk(workload: &str, files: Vec<(String, Vec<u8>)>) {
    let bench = Bench::open();
    let run = bench.run_name(workload);
    let (names, contents): (Vec<String>, Vec<Vec<u8>>) = files.into_iter().unzip();
    let files: Vec<(&str, Vec<u8>)> = names.iter().map(String::as_str).zip(contents).collect();
    let (store, stage) = bench.create(&run, &files);
    drop(files);
    let (local_files, local_bytes) = local_size(&manifest(&store.base));
    // A native arm that never finishes is recorded and fails the test only
    // after the other arm ran and the native folder was removed.
    let mut native_finished = true;
    for arm in bench.arms() {
        match arm {
            Arm::Native => {
                let (took, replicated, seen) = bench.native_bulk(&run, &stage);
                bench.record(serde_json::json!({
                    "workload": workload, "arm": "native", "repeat": bench.repeat,
                    "local_files": local_files, "local_bytes": local_bytes,
                    "complete": seen.complete.is_some(), "seconds": took.as_secs_f64(),
                    "replicated_seconds": replicated.map(|took| took.as_secs_f64()),
                    "remote_files": seen.remote_files, "missing_at_end": seen.missing_at_end,
                    "missing_paths": seen.missing_paths,
                    "polls": seen.polls, "poll_ms": bench.poll.as_millis() as u64,
                    "broken_polls": seen.broken_polls, "most_missing": seen.most_missing,
                    "broken_seconds": seen.first_broken.zip(seen.last_broken)
                        .map(|(first, last)| (last - first).as_secs_f64()),
                    "unknown_roots": seen.unknown_roots,
                }));
                native_finished &= seen.complete.is_some();
                std::thread::sleep(Duration::from_secs(30));
            }
            Arm::Ours => {
                let live = Live::start(&run);
                let state = store.dir.path().join("state");
                let started = Instant::now();
                assert!(live.run(Action::Push, &store.base, &state).unwrap().healthy);
                let took = started.elapsed();
                let (remote_files, remote_bytes) = remote_size(&live);
                let (dir, base, pull_state) = empty_replica(&format!("{run}-pull"));
                let started = Instant::now();
                assert!(live.run(Action::Pull, &base, &pull_state).unwrap().healthy);
                let pulled = started.elapsed();
                assert_eq!(replicated(&base), replicated(&store.base));
                drop(dir);
                bench.record(serde_json::json!({
                    "workload": workload, "arm": "ours", "repeat": bench.repeat,
                    "local_files": local_files, "local_bytes": local_bytes,
                    "complete": true, "seconds": took.as_secs_f64(),
                    "remote_files": remote_files, "remote_bytes": remote_bytes,
                    "pull_seconds": pulled.as_secs_f64(),
                }));
                bench.settle(&live);
            }
        }
    }
    bench.remove_native(&run);
    assert!(native_finished, "the native upload did not finish");
}

/// Rewrites a few bytes in one chunk of the only file, like a mounted
/// write and fsync do.
fn edit(ztfs: &ZeroTrustFs, number: usize, file_len: usize) {
    let chunks = file_len / CHUNK;
    let offset = (number * 7) % chunks * CHUNK + (number * 4_096) % (CHUNK - 4_096);
    ztfs.open_inode(ONLY_FILE).unwrap();
    ztfs.write_inode_content(
        ONLY_FILE,
        offset as u64,
        &content((number % 251) as u8, 4_096),
    )
    .unwrap();
    ztfs.fsync_inode(ONLY_FILE).unwrap();
    ztfs.release_inode(ONLY_FILE).unwrap();
}

fn mount(base: &Path) -> ZeroTrustFs {
    let mut ztfs = ZeroTrustFs::new_v2(PASSPHRASE, base.to_path_buf());
    ztfs.stop_debounce_thread_for_test();
    ztfs
}

#[test]
#[ignore = "requires ZDRIVE_RUN_GDRIVE_TESTS=1, a configured remote and ZDRIVE_GDRIVE_MIRROR"]
fn bench_calibrate_uplink() {
    let bench = Bench::open();
    let size = env_number("ZDRIVE_BENCH_CALIBRATE_MIB", 128) as usize * MIB;
    let run = bench.run_name("calibrate");
    let (store, stage) = bench.create(&run, &[("calibrate.bin", content(1, size))]);
    std::fs::remove_dir_all(stage).unwrap();
    let live = Live::start(&run);
    let started = Instant::now();
    let state = store.dir.path().join("state");
    assert!(live.run(Action::Push, &store.base, &state).unwrap().healthy);
    let took = started.elapsed();
    let (_, bytes) = remote_size(&live);
    bench.record(serde_json::json!({
        "workload": "calibrate", "arm": "ours", "remote_bytes": bytes,
        "seconds": took.as_secs_f64(),
        "mib_per_second": bytes as f64 / MIB as f64 / took.as_secs_f64(),
    }));
    bench.settle(&live);
}

#[test]
#[ignore = "requires ZDRIVE_RUN_GDRIVE_TESTS=1, a configured remote and ZDRIVE_GDRIVE_MIRROR"]
fn bench_large_file() {
    let size = env_number("ZDRIVE_BENCH_LARGE_MIB", 1_024) as usize * MIB;
    bulk("large", vec![("large.bin".to_string(), content(2, size))]);
}

#[test]
#[ignore = "requires ZDRIVE_RUN_GDRIVE_TESTS=1, a configured remote and ZDRIVE_GDRIVE_MIRROR"]
fn bench_small_files() {
    let count = env_number("ZDRIVE_BENCH_SMALL_FILES", 2_000) as usize;
    let files = (0..count)
        .map(|number| {
            let size = 4_096 + (number * 7_919) % (60 * 1_024);
            (
                format!("small-{number:05}.bin"),
                content((number % 251) as u8, size),
            )
        })
        .collect();
    bulk("small", files);
}

/// Repeated fsync'd edits while each arm replicates as it goes: Drive for
/// desktop syncs the mounted store's directory, `zdrive` runs its mount
/// replicator. The clock runs from the last edit's fsync.
#[test]
#[ignore = "requires ZDRIVE_RUN_GDRIVE_TESTS=1, a configured remote and ZDRIVE_GDRIVE_MIRROR"]
fn bench_edits() {
    let bench = Bench::open();
    let edits = env_number("ZDRIVE_BENCH_EDITS", 200) as usize;
    let file_len = 64 * MIB;
    let run = bench.run_name("edits");
    let (store, stage) = bench.create(&run, &[("edited.bin", content(3, file_len))]);
    let mut native_finished = true;
    for arm in bench.arms() {
        match arm {
            Arm::Native => {
                let (initial, _, initial_seen) = bench.native_bulk(&run, &stage);
                eprintln!("native initial upload took {initial:.2?}");
                native_finished &= initial_seen.complete.is_some();
                std::thread::sleep(Duration::from_secs(30));
                let base = bench.native.join(&run);
                let generations = Arc::new(Mutex::new(vec![Generation::capture(&base)]));
                let last = Arc::new(Mutex::new(None));
                let watcher = bench.watch_native(&run, generations.clone(), last.clone());
                let ztfs = mount(&base);
                let first = Instant::now();
                for number in 0..edits {
                    edit(&ztfs, number, file_len);
                    generations.lock().unwrap().push(Generation::capture(&base));
                }
                let durable = Instant::now();
                drop(ztfs);
                let (local_files, local_bytes) = {
                    let final_manifest = manifest(&base);
                    let size = local_size(&final_manifest);
                    *last.lock().unwrap() = Some(final_manifest);
                    size
                };
                let seen = watcher.join().unwrap();
                bench.record(serde_json::json!({
                    "workload": "edits", "arm": "native", "repeat": bench.repeat,
                    "edits": edits, "edit_seconds": (durable - first).as_secs_f64(),
                    "local_files": local_files, "local_bytes": local_bytes,
                    "initial_complete": initial_seen.complete.is_some(),
                    "complete": seen.complete.is_some(),
                    "seconds": seen.complete.map(|at| (at - durable).as_secs_f64()),
                    "replicated_seconds": seen.replicated.map(|at| (at - durable).as_secs_f64()),
                    "remote_files": seen.remote_files, "missing_at_end": seen.missing_at_end,
                    "missing_paths": seen.missing_paths,
                    "polls": seen.polls, "poll_ms": bench.poll.as_millis() as u64,
                    "broken_polls": seen.broken_polls, "most_missing": seen.most_missing,
                    "broken_seconds": seen.first_broken.zip(seen.last_broken)
                        .map(|(first, last)| (last - first).as_secs_f64()),
                    "unknown_roots": seen.unknown_roots,
                }));
                native_finished &= seen.complete.is_some();
                std::thread::sleep(Duration::from_secs(30));
            }
            Arm::Ours => {
                let live = Live::start(&run);
                let state_dir = store.dir.path().join("state");
                assert!(
                    live.run(Action::Push, &store.base, &state_dir)
                        .unwrap()
                        .healthy
                );
                let state = store.state(&live.folder);
                let name = RemoteName::parse("bench").unwrap();
                assert_eq!(foreign_lease(&live.drive, &state, &name), None);
                let prepared = Prepared {
                    name,
                    display: "bench-store".to_string(),
                    drive: live.client(),
                    folder_id: live.folder.clone(),
                    state,
                    passphrase: PASSPHRASE.to_string(),
                    read_only: None,
                };
                let ztfs = mount(&store.base);
                let mut replicator = prepared
                    .start_with(ztfs.inner.clone(), Timing::MOUNT)
                    .unwrap();
                let first = Instant::now();
                for number in 0..edits {
                    edit(&ztfs, number, file_len);
                }
                let durable = Instant::now();
                let generation = v2::load(&store.base, &store.key).unwrap().1.number;
                let outcome = replicator.finish(Duration::from_secs(3_600));
                let took = durable.elapsed();
                assert_eq!(outcome, Outcome::Synced(generation));
                drop(ztfs);
                let (local_files, local_bytes) = local_size(&manifest(&store.base));
                let (remote_files, remote_bytes) = remote_size(&live);
                bench.record(serde_json::json!({
                    "workload": "edits", "arm": "ours", "repeat": bench.repeat,
                    "edits": edits, "edit_seconds": (durable - first).as_secs_f64(),
                    "local_files": local_files, "local_bytes": local_bytes,
                    "complete": true, "seconds": took.as_secs_f64(),
                    "remote_files": remote_files, "remote_bytes": remote_bytes,
                }));
                bench.settle(&live);
            }
        }
    }
    bench.remove_native(&run);
    assert!(native_finished, "the native upload did not finish");
}
