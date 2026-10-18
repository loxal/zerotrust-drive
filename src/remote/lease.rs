// SPDX-FileCopyrightText: Copyright 2026 Alexander Orlov <info@lifub.com>

//! Advisory writer leases.
//!
//! A replica mounted with automatic sync keeps one file in the remote
//! `leases/` folder and refreshes its `heartbeat` app property while it runs.
//! Before a writable mount, a fresh active lease of another replica makes the
//! mount read-only. Leases depend on clocks and on listings that may lag, so
//! they only avoid surprises; fork detection on every push stays the actual
//! guarantee. A lease names a random replica id, never a host or user.

use std::collections::BTreeMap;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use super::gdrive::{DriveFile, GoogleDrive};
use super::state::{LeaseRecord, RemoteState};
use super::{RemoteError, hex};

/// How often a mounted replica refreshes its lease.
pub(crate) const HEARTBEAT: Duration = Duration::from_secs(120);
/// How long a heartbeat keeps a lease fresh.
pub(crate) const FRESH: Duration = Duration::from_secs(600);
const STATE: &str = "state";
const BEAT: &str = "heartbeat";
const ACTIVE: &str = "active";
const RELEASED: &str = "released";
const FORMAT: &str = "zerotrust-drive-lease";

pub(crate) fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs())
}

/// Another replica whose active lease is fresh.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Peer {
    pub(crate) replica: String,
    /// Seconds since its last heartbeat; zero for one from the future.
    pub(crate) age: u64,
}

/// The fresh active leases in `folder` other than this replica's own.
pub(crate) fn fresh_peers(
    drive: &GoogleDrive,
    folder: &str,
    own: Option<&LeaseRecord>,
    now: u64,
) -> Result<Vec<Peer>, RemoteError> {
    let own = own.map(|lease| lease.file_id.as_str());
    Ok(drive
        .list(folder, false)?
        .iter()
        .filter(|file| Some(file.id.as_str()) != own)
        .filter_map(|file| peer(file, now))
        .collect())
}

fn peer(file: &DriveFile, now: u64) -> Option<Peer> {
    if file.app_properties.get(STATE).map(String::as_str) != Some(ACTIVE) {
        return None;
    }
    let beat: u64 = file.app_properties.get(BEAT)?.parse().ok()?;
    let fresh = FRESH.as_secs();
    // Clocks drift, so a heartbeat slightly in the future still counts; one
    // far ahead is implausible and must not lock other replicas out.
    if beat > now.saturating_add(fresh) || now.saturating_sub(beat) >= fresh {
        return None;
    }
    let replica = file.name.strip_suffix(".json").unwrap_or(&file.name);
    Some(Peer {
        replica: replica.to_string(),
        age: now.saturating_sub(beat),
    })
}

fn properties(state: &str, now: u64) -> BTreeMap<String, String> {
    BTreeMap::from([
        (STATE.to_string(), state.to_string()),
        (BEAT.to_string(), now.to_string()),
    ])
}

/// Creates this replica's lease in `folder`, or renews the existing one, as
/// active.
pub(crate) fn acquire(
    drive: &GoogleDrive,
    folder: &str,
    state: &mut RemoteState,
    now: u64,
) -> Result<(), RemoteError> {
    let current = state
        .record
        .lease
        .clone()
        .filter(|lease| lease.folder == folder);
    if let Some(lease) = &current
        && lease.created
    {
        match heartbeat(drive, lease, now) {
            // Someone removed it: a new lease replaces it below.
            Err(RemoteError::NotFound(_)) => {}
            other => return other,
        }
    }
    let lease = match current.filter(|lease| !lease.created) {
        Some(pending) => pending,
        None => {
            let mut random = [0u8; 16];
            crate::crypto::fill_random(&mut random);
            let file_id =
                drive.generate_ids(1)?.into_iter().next().ok_or_else(|| {
                    RemoteError::Protocol("Drive generated no file id".to_string())
                })?;
            let lease = LeaseRecord {
                replica: hex(&random),
                file_id,
                folder: folder.to_string(),
                created: false,
            };
            state.record.lease = Some(lease.clone());
            state.save()?;
            lease
        }
    };
    let body = serde_json::to_vec(&serde_json::json!({
        "format": FORMAT,
        "version": 1,
        "replica": lease.replica,
    }))
    .map_err(|error| RemoteError::Local(error.to_string()))?;
    drive.create_small(
        folder,
        &format!("{}.json", lease.replica),
        &lease.file_id,
        &body,
        &properties(ACTIVE, now),
    )?;
    if let Some(saved) = state.record.lease.as_mut() {
        saved.created = true;
    }
    state.save()
}

/// Refreshes an acquired lease's heartbeat.
pub(crate) fn heartbeat(
    drive: &GoogleDrive,
    lease: &LeaseRecord,
    now: u64,
) -> Result<(), RemoteError> {
    drive
        .set_app_properties(&lease.file_id, &properties(ACTIVE, now))
        .map(drop)
}

/// Marks an acquired lease released. The file stays: nothing remote is
/// ever deleted.
pub(crate) fn release(
    drive: &GoogleDrive,
    lease: &LeaseRecord,
    now: u64,
) -> Result<(), RemoteError> {
    drive
        .set_app_properties(&lease.file_id, &properties(RELEASED, now))
        .map(drop)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn file(name: &str, props: &[(&str, &str)]) -> DriveFile {
        serde_json::from_value(serde_json::json!({
            "id": "lease-id",
            "name": name,
            "appProperties": props.iter().copied().collect::<BTreeMap<_, _>>(),
        }))
        .unwrap()
    }

    #[test]
    fn only_recent_active_heartbeats_are_fresh() {
        let now = 1_000_000;
        let beat = |offset: i64| (now as i64 + offset).to_string();
        let fresh = file("ab.json", &[("state", "active"), ("heartbeat", &beat(-30))]);
        assert_eq!(
            peer(&fresh, now),
            Some(Peer {
                replica: "ab".to_string(),
                age: 30
            })
        );
        let ahead = file("ab.json", &[("state", "active"), ("heartbeat", &beat(60))]);
        assert_eq!(peer(&ahead, now).map(|peer| peer.age), Some(0));
        for stale in [
            file(
                "ab.json",
                &[("state", "active"), ("heartbeat", &beat(-600))],
            ),
            file("ab.json", &[("state", "active"), ("heartbeat", &beat(601))]),
            file("ab.json", &[("state", "released"), ("heartbeat", &beat(0))]),
            file("ab.json", &[("state", "active"), ("heartbeat", "soon")]),
            file("ab.json", &[("state", "active")]),
            file("ab.json", &[]),
        ] {
            assert_eq!(peer(&stale, now), None, "{stale:?}");
        }
    }
}
