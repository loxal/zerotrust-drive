// SPDX-FileCopyrightText: Copyright 2026 Alexander Orlov <info@lifub.com>

use std::sync::atomic::Ordering;

use super::*;
use crate::fs::ZeroTrustFs;
use crate::remote::fake::FakeDrive;
use crate::remote::gdrive::TokenSource;
use crate::remote::sync::tests::{Env, PASSPHRASE, Store, content};
use crate::v2;

const FAST: Timing = Timing {
    watch: Duration::from_millis(40),
    first_retry: Duration::from_millis(10),
    max_retry: Duration::from_millis(80),
    max_final_retry: Duration::from_millis(40),
    heartbeat: Duration::from_millis(80),
};
const LIMIT: Duration = Duration::from_secs(60);
/// `a.txt`, the first file of [`Store::origin`].
const EDITED: u64 = 2;

fn name() -> RemoteName {
    RemoteName::parse("test").unwrap()
}

fn mount(store: &Store) -> ZeroTrustFs {
    let mut ztfs = ZeroTrustFs::new_v2(PASSPHRASE, store.base.clone());
    ztfs.stop_debounce_thread_for_test();
    ztfs
}

fn prepared_with(env: &Env, store: &Store, drive: GoogleDrive) -> Prepared {
    let state = store.state(&env.folder);
    let read_only = foreign_lease(&drive, &state, &name());
    Prepared {
        name: name(),
        display: "test-store".to_string(),
        drive,
        folder_id: env.folder.clone(),
        state,
        passphrase: PASSPHRASE.to_string(),
        read_only,
    }
}

fn prepared(env: &Env, store: &Store) -> Prepared {
    prepared_with(env, store, env.fake.client())
}

/// Rewrites `a.txt` the way a mounted write and fsync do.
fn edit(ztfs: &ZeroTrustFs, bytes: &[u8]) {
    ztfs.open_inode(EDITED).unwrap();
    ztfs.write_inode_content(EDITED, 0, bytes).unwrap();
    ztfs.fsync_inode(EDITED).unwrap();
    ztfs.release_inode(EDITED).unwrap();
}

fn local_number(store: &Store) -> u64 {
    v2::load(&store.base, &store.key).unwrap().1.number
}

fn remote_has(env: &Env, number: u64) -> bool {
    let prefix = format!("{number:020}-");
    env.fake
        .files()
        .iter()
        .any(|file| file.name.starts_with(&prefix) && file.name.ends_with(".zr"))
}

fn lease_states(env: &Env) -> Vec<String> {
    env.fake
        .files()
        .into_iter()
        .filter_map(|file| file.app_properties.get("state").cloned())
        .collect()
}

fn wait_until(what: &str, mut condition: impl FnMut() -> bool) {
    let deadline = Instant::now() + LIMIT;
    while !condition() {
        assert!(Instant::now() < deadline, "timed out waiting for {what}");
        std::thread::sleep(Duration::from_millis(5));
    }
}

fn blocked(ztfs: &ZeroTrustFs) -> bool {
    ztfs.inner.read_only.load(Ordering::SeqCst)
}

#[test]
fn uploads_each_commit_and_the_final_generation_and_releases_the_lease() {
    let env = Env::new();
    let store = Store::origin("mount-upload");
    let ztfs = mount(&store);
    let mut replicator = prepared(&env, &store)
        .start_with(ztfs.inner.clone(), FAST)
        .unwrap();
    let first = local_number(&store);
    wait_until("the initial upload", || remote_has(&env, first));
    wait_until("the lease", || lease_states(&env) == ["active"]);

    edit(&ztfs, &content(9, 200));
    let second = local_number(&store);
    assert!(second > first);
    wait_until("the commit upload", || remote_has(&env, second));

    // Unmounted right after a commit: the final push carries it.
    let last_bytes = content(10, 300);
    edit(&ztfs, &last_bytes);
    let last = local_number(&store);
    let outcome = replicator.finish(LIMIT);
    assert_eq!(outcome, Outcome::Synced(last));
    assert_eq!(replicator.report(&outcome), 0);
    assert_eq!(lease_states(&env), ["released"]);
    assert!(!blocked(&ztfs));
    drop(ztfs);

    let mut expected = store.contents();
    expected.insert("a.txt".to_string(), last_bytes);
    assert_eq!(env.clone_store("mount-upload-clone").contents(), expected);
}

#[test]
fn a_burst_of_commits_becomes_one_push() {
    let shared = Shared::default();
    let later = Instant::now() + Duration::from_secs(3600);
    let mut plan = Plan {
        pending: false,
        retry_at: None,
        delay: FAST.first_retry,
        failing: false,
        next_watch: later,
        next_beat: later,
        synced: Some(1),
    };
    for _ in 0..3 {
        shared.mark_dirty();
    }
    assert!(matches!(next_event(&shared, &mut plan), Event::Push));
    plan.pending = false;
    shared.lock().stop = true;
    assert!(matches!(next_event(&shared, &mut plan), Event::Stop));

    // A failed push waits for its retry even when new commits arrive.
    let shared = Shared::default();
    plan.pending = true;
    plan.retry_at = Some(later);
    shared.mark_dirty();
    shared.lock().stop = true;
    assert!(matches!(next_event(&shared, &mut plan), Event::Stop));
}

#[test]
fn an_outage_delays_uploads_without_blocking_writes() {
    let env = Env::new();
    let store = Store::origin("mount-offline");
    env.push(&store).unwrap();
    let ztfs = mount(&store);
    let prepared = prepared(&env, &store);
    env.fake.set_offline(true);
    let mut replicator = prepared.start_with(ztfs.inner.clone(), FAST).unwrap();

    edit(&ztfs, &content(9, 200));
    let number = local_number(&store);
    std::thread::sleep(FAST.max_retry * 2);
    assert!(!remote_has(&env, number));
    assert!(!blocked(&ztfs));

    env.fake.set_offline(false);
    wait_until("the upload after the outage", || remote_has(&env, number));
    assert_eq!(replicator.finish(LIMIT), Outcome::Synced(number));
}

#[test]
fn an_offline_unmount_without_new_generations_is_synced() {
    let env = Env::new();
    let store = Store::origin("mount-offline-clean");
    let number = env.push(&store).unwrap().number;
    let ztfs = mount(&store);
    let prepared = prepared(&env, &store);
    env.fake.set_offline(true);
    let mut replicator = prepared.start_with(ztfs.inner.clone(), FAST).unwrap();
    assert_eq!(replicator.finish(LIMIT), Outcome::Synced(number));
}

#[test]
fn an_unfinished_final_upload_exits_unsynced() {
    let env = Env::new();
    let store = Store::origin("mount-unfinished");
    env.push(&store).unwrap();
    let ztfs = mount(&store);
    let prepared = prepared(&env, &store);
    env.fake.set_offline(true);
    let mut replicator = prepared.start_with(ztfs.inner.clone(), FAST).unwrap();
    edit(&ztfs, &content(9, 200));

    let outcome = replicator.finish(Duration::from_millis(300));
    assert!(
        matches!(&outcome, Outcome::Unfinished(reason) if reason.contains("within")),
        "{outcome:?}"
    );
    assert_eq!(replicator.report(&outcome), EXIT_UNSYNCED);
}

#[test]
fn a_signal_leaves_the_final_upload_for_later() {
    let env = Env::new();
    let store = Store::origin("mount-signal");
    env.push(&store).unwrap();
    let ztfs = mount(&store);
    let prepared = prepared(&env, &store);
    env.fake.set_offline(true);
    let mut replicator = prepared.start_with(ztfs.inner.clone(), FAST).unwrap();
    edit(&ztfs, &content(9, 200));
    let shared = Arc::clone(&replicator.shared);
    let signal = std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(100));
        shared.abandon();
    });
    let outcome = replicator.finish(LIMIT);
    signal.join().unwrap();
    assert!(matches!(outcome, Outcome::Unfinished(_)), "{outcome:?}");
}

#[test]
fn a_foreign_root_seen_while_idle_blocks_writes_until_remount() {
    let env = Env::new();
    let store = Store::origin("mount-watch");
    env.push(&store).unwrap();
    let ztfs = mount(&store);
    let mut replicator = prepared(&env, &store)
        .start_with(ztfs.inner.clone(), FAST)
        .unwrap();
    wait_until("the lease", || lease_states(&env) == ["active"]);

    let mut other = env.clone_store("mount-watch-other");
    other.write("b.txt", content(5, 50));
    env.push(&other).unwrap();
    wait_until("the write block", || blocked(&ztfs));
    // Restoring writes after a healthy flush keeps the remote block.
    ztfs.inner.restore_writes_if_healthy();
    assert!(blocked(&ztfs));

    let outcome = replicator.finish(LIMIT);
    assert!(
        matches!(&outcome, Outcome::Blocked(reason) if reason.contains("mount again to fast-forward")),
        "{outcome:?}"
    );
    assert_eq!(replicator.report(&outcome), EXIT_UNSYNCED);
}

#[test]
fn a_diverged_remote_blocks_writes_and_names_the_way_out() {
    let env = Env::new();
    let store = Store::origin("mount-diverged");
    env.push(&store).unwrap();
    let mut other = env.clone_store("mount-diverged-other");
    other.write("b.txt", content(5, 50));
    env.push(&other).unwrap();

    // The same generation number with different contents.
    let ztfs = mount(&store);
    edit(&ztfs, &content(9, 200));
    assert_eq!(local_number(&store), other.head.number);
    let mut replicator = prepared(&env, &store)
        .start_with(ztfs.inner.clone(), FAST)
        .unwrap();
    let outcome = replicator.finish(LIMIT);
    assert!(
        matches!(&outcome, Outcome::Blocked(reason) if reason.contains("move test-store aside")),
        "{outcome:?}"
    );
    assert!(blocked(&ztfs));
    assert_eq!(
        env.clone_store("mount-diverged-check").contents(),
        other.contents()
    );
}

struct RevokedGrant;

impl TokenSource for RevokedGrant {
    fn fetch(&self, _agent: &ureq::Agent) -> Result<(String, Duration), RemoteError> {
        Err(RemoteError::Auth(
            "Google refused the refresh token (invalid_grant)".to_string(),
        ))
    }
}

#[test]
fn a_revoked_grant_stops_sync_but_not_local_writes() {
    let env = Env::new();
    let store = Store::origin("mount-revoked");
    env.push(&store).unwrap();
    let ztfs = mount(&store);
    let revoked = GoogleDrive::with_endpoint(
        env.fake.base_url(),
        Box::new(RevokedGrant),
        FakeDrive::fast_policy(),
    );
    let mut replicator = prepared_with(&env, &store, revoked)
        .start_with(ztfs.inner.clone(), FAST)
        .unwrap();
    edit(&ztfs, &content(9, 200));
    let outcome = replicator.finish(LIMIT);
    assert!(
        matches!(&outcome, Outcome::Failed(reason) if reason.contains("invalid_grant")),
        "{outcome:?}"
    );
    assert!(!blocked(&ztfs));
    assert_eq!(replicator.report(&outcome), EXIT_UNSYNCED);
}

#[test]
fn only_a_fresh_lease_of_another_replica_mounts_read_only() {
    let env = Env::new();
    let store = Store::origin("mount-lease");
    env.push(&store).unwrap();
    let leases = store
        .state(&env.folder)
        .record
        .layout
        .clone()
        .unwrap()
        .leases;
    let now = lease::unix_now();
    // Our own lease, a stale one and a released one never block.
    lease::acquire(&env.drive, &leases, &mut store.state(&env.folder), now).unwrap();
    let stale = env.clone_store("mount-lease-stale");
    lease::acquire(
        &env.drive,
        &leases,
        &mut stale.state(&env.folder),
        now - lease::FRESH.as_secs() - 1,
    )
    .unwrap();
    let released = env.clone_store("mount-lease-released");
    {
        let mut state = released.state(&env.folder);
        lease::acquire(&env.drive, &leases, &mut state, now).unwrap();
        lease::release(&env.drive, state.record.lease.as_ref().unwrap(), now).unwrap();
    }
    assert_eq!(prepared(&env, &store).read_only, None);

    let active = env.clone_store("mount-lease-active");
    lease::acquire(&env.drive, &leases, &mut active.state(&env.folder), now).unwrap();
    let prepared = prepared(&env, &store);
    assert!(
        prepared
            .read_only
            .as_deref()
            .is_some_and(|reason| reason.contains("read-only")),
        "{:?}",
        prepared.read_only
    );
    let ztfs = mount(&store);
    let mut replicator = prepared.start_with(ztfs.inner.clone(), FAST).unwrap();
    assert!(blocked(&ztfs));
    assert_eq!(replicator.finish(LIMIT), Outcome::ReadOnly);
    assert_eq!(replicator.report(&Outcome::ReadOnly), 0);
}

/// Real Google Drive pacing: a commit reaches the server within seconds,
/// so these bounds only keep a slow run from hanging.
const LIVE: Timing = Timing {
    watch: Duration::from_secs(3),
    first_retry: Duration::from_secs(1),
    max_retry: Duration::from_secs(10),
    max_final_retry: Duration::from_secs(5),
    heartbeat: Duration::from_secs(5),
};

#[test]
#[ignore = "requires ZDRIVE_RUN_GDRIVE_TESTS=1 and a remote configured by `zdrive remote auth`"]
fn live_mount_replicates_each_commit_and_releases_its_lease() {
    use crate::remote::cli::Action;
    use crate::remote::cli::live::{Live, empty_replica};

    let live = Live::start("mount");
    let store = Store::origin("live-mount");
    let ztfs = mount(&store);
    let state = store.state(&live.folder);
    let read_only = foreign_lease(&live.drive, &state, &name());
    assert_eq!(read_only, None);
    let prepared = Prepared {
        name: name(),
        display: "test-store".to_string(),
        drive: live.client(),
        folder_id: live.folder.clone(),
        state,
        passphrase: PASSPHRASE.to_string(),
        read_only,
    };
    let root_visible = |number: u64| {
        let prefix = format!("{number:020}-");
        live.files()
            .iter()
            .any(|file| file.name.starts_with(&prefix) && file.name.ends_with(".zr"))
    };
    let lease_states = || {
        live.files()
            .into_iter()
            .filter_map(|file| file.app_properties.get("state").cloned())
            .collect::<Vec<_>>()
    };

    let started = Instant::now();
    let mut replicator = prepared.start_with(ztfs.inner.clone(), LIVE).unwrap();
    let first = local_number(&store);
    wait_until("the initial upload", || root_visible(first));
    eprintln!("initial store visible after {:.2?}", started.elapsed());
    wait_until("the lease", || lease_states() == ["active"]);

    edit(&ztfs, &content(9, 200));
    let second = local_number(&store);
    let committed = Instant::now();
    wait_until("the commit upload", || root_visible(second));
    eprintln!("commit visible after {:.2?}", committed.elapsed());

    let last_bytes = content(10, 300);
    edit(&ztfs, &last_bytes);
    let last = local_number(&store);
    let unmounted = Instant::now();
    let outcome = replicator.finish(LIMIT);
    eprintln!("final upload took {:.2?}", unmounted.elapsed());
    assert_eq!(outcome, Outcome::Synced(last));
    assert_eq!(lease_states(), ["released"]);
    let mut expected = store.contents();
    expected.insert("a.txt".to_string(), last_bytes);
    drop(ztfs);

    let (dir, base, pull_state) = empty_replica("live-mount-replica");
    assert!(live.run(Action::Pull, &base, &pull_state).unwrap().healthy);
    assert_eq!(Store::open(dir, store.key).contents(), expected);
}
