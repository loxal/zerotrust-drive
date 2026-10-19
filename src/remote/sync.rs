// SPDX-FileCopyrightText: Copyright 2026 Alexander Orlov <info@lifub.com>

//! Push and pull of a v2 store against a remote folder.
//!
//! Remote layout, format 1, inside the configured folder:
//!
//! ```text
//! zdrive-remote.json        marker naming the subfolders and _kdf.json
//! _kdf.json                 exact copy of the store's KDF metadata
//! packs/<md5>-<size>.zpk    immutable object packs, named by content
//! roots/<number>-<md5>.zr   exact `_root.age` records, one per push
//! leases/                   advisory writer leases of automatic sync
//! ```
//!
//! Nothing remote is replaced or deleted. A root record is created only after
//! every pack holding its closure is verified complete, so a reader sees the
//! previous head or the new one, never a root without its objects. A pull
//! installs each object only after checking it against the digest its
//! authenticated parent commits to, and advances the local root through the
//! crash-safe manifest protocol one generation at a time.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::fs::{File, OpenOptions};
use std::io::{BufWriter, Read, Write};
use std::os::unix::fs::{FileExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Mutex, MutexGuard, mpsc};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use md5::Digest;

use crate::crypto::RecoveryFingerprint;
use crate::v2::replica::{
    self, ChainBase, ChainOutcome, ClosureWalker, GenerationInfo, MAX_OBJECT_CIPHERTEXT,
    MAX_ROOT_RECORD,
};
use crate::v2::{self, ChildFiles, CommitState, ObjectRef, V2NamespacePin};

use super::format::{
    KDF_NAME, LEASES_DIR, MARKER_NAME, MAX_PACK_OBJECTS, MAX_SMALL_FILE, Marker, PACK_PREFIX_LEN,
    PACKS_DIR, PackEntry, ROOTS_DIR, TARGET_PACK_BYTES, encode_pack_header, pack_header_len,
    pack_name, parse_pack_header, parse_pack_name, parse_pack_prefix, parse_root_record_name,
    root_record_name,
};
use super::gdrive::{DriveFile, GoogleDrive, UploadCheckpoint};
use super::state::{KnownLayout, PendingLayout, PendingRoot, RemoteState, SyncedHead};
use super::{RemoteError, ensure_private_dir, hex, md5_bytes, md5_file, unhex, write_private_file};
use crate::telemetry::{self, Field, Level};

/// Present while a bootstrap pull is filling an empty directory. Mounting
/// refuses such a directory; `zdrive remote pull` finishes it.
pub(crate) const PULL_PENDING_FILE: &str = "_zdrive-pull.pending";
/// Concurrent pack uploads. A 1 GiB push measured 42 s with 3, 35-36 s with
/// 6 and no further gain with 8; chunk PUTs are not write-paced.
const UPLOAD_PARALLELISM: usize = 6;
const DOWNLOAD_PARALLELISM: usize = 4;
/// Sealed packs waiting for an upload worker; bounds outgoing disk use.
const PIPELINE_DEPTH: usize = 2;
/// First read of a pack header; covers about 1,100 entries.
const HEADER_PROBE: u64 = 64 << 10;
const MAX_ID_BATCH: usize = 1000;

/// The provider folder a store replicates into.
pub(crate) struct Remote<'a> {
    pub(crate) drive: &'a GoogleDrive,
    pub(crate) folder_id: &'a str,
    /// Progress and warnings for the operator; never receives secrets.
    pub(crate) log: &'a (dyn Fn(&str) + Sync),
}

impl Remote<'_> {
    fn note(&self, message: &str) {
        (self.log)(message);
    }
}

/// An unlocked local store, after crash recovery ran under the drive lock.
pub(crate) struct LocalStore<'a> {
    pub(crate) base: &'a Path,
    pub(crate) key: &'a [u8; 32],
    /// Exact `_kdf.json` bytes.
    pub(crate) kdf_bytes: &'a [u8],
    pub(crate) kdf_fingerprint: &'a RecoveryFingerprint,
    pub(crate) pin: &'a V2NamespacePin,
    /// Canonical encrypted directory, recorded in the sync state.
    pub(crate) display: &'a str,
}

struct LocalHead {
    state: CommitState,
    root_bytes: Vec<u8>,
}

impl LocalStore<'_> {
    fn head(&self) -> Result<LocalHead, RemoteError> {
        let (state, root_bytes) = replica::local_head(self.base, self.key, self.pin)?;
        Ok(LocalHead { state, root_bytes })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Layout {
    marker: String,
    marker_md5: [u8; 16],
    kdf_file: String,
    kdf_md5: [u8; 16],
    packs: String,
    roots: String,
    leases: String,
}

impl Layout {
    fn from_known(known: &KnownLayout) -> Option<Self> {
        Some(Self {
            marker: known.marker.clone(),
            marker_md5: unhex(&known.marker_md5)?,
            kdf_file: known.kdf.clone(),
            kdf_md5: unhex(&known.kdf_md5)?,
            packs: known.packs.clone(),
            roots: known.roots.clone(),
            leases: known.leases.clone(),
        })
    }

    fn known(&self) -> KnownLayout {
        KnownLayout {
            marker: self.marker.clone(),
            marker_md5: hex(&self.marker_md5),
            kdf: self.kdf_file.clone(),
            kdf_md5: hex(&self.kdf_md5),
            packs: self.packs.clone(),
            roots: self.roots.clone(),
            leases: self.leases.clone(),
        }
    }

    /// Whether `listing` of the remote folder still chooses this layout's
    /// marker and holds its `_kdf.json`, both unchanged.
    fn listed_in(&self, listing: &[DriveFile]) -> bool {
        chosen_marker(listing)
            .is_some_and(|marker| marker.id == self.marker && marker.md5() == Some(self.marker_md5))
            && listing.iter().any(|file| {
                file.id == self.kdf_file && !file.is_folder() && file.md5() == Some(self.kdf_md5)
            })
    }

    fn holds_kdf(&self, kdf_bytes: &[u8]) -> bool {
        self.kdf_md5 == md5_bytes(kdf_bytes)
    }
}

/// Concurrent initializations can leave several markers; every client
/// picks the smallest id.
fn chosen_marker(listing: &[DriveFile]) -> Option<&DriveFile> {
    listing
        .iter()
        .filter(|file| file.name == MARKER_NAME && !file.is_folder())
        .min_by(|left, right| left.id.cmp(&right.id))
}

/// Reads the layout the chosen marker in `listing` commits to.
fn read_layout(remote: &Remote<'_>, listing: &[DriveFile]) -> Result<Option<Layout>, RemoteError> {
    let Some(chosen) = chosen_marker(listing) else {
        return Ok(None);
    };
    let markers = listing
        .iter()
        .filter(|file| file.name == MARKER_NAME && !file.is_folder())
        .count();
    if markers > 1 {
        remote.note(&format!(
            "warning: {markers} remote markers exist; using the one with the smallest id"
        ));
    }
    let bytes = remote.drive.read_small(chosen, MAX_SMALL_FILE)?;
    let marker = Marker::decode(&bytes).map_err(RemoteError::Protocol)?;
    let kdf_md5 = unhex::<16>(&marker.kdf_md5)
        .ok_or_else(|| RemoteError::Protocol("marker names an invalid kdf md5".to_string()))?;
    let kdf_file = match listing.iter().find(|file| file.id == marker.kdf_file_id) {
        Some(file) => file.clone(),
        None => remote.drive.get(&marker.kdf_file_id)?,
    };
    if kdf_file.trashed || kdf_file.md5() != Some(kdf_md5) {
        return Err(RemoteError::Integrity(format!(
            "the remote {KDF_NAME} does not match its marker"
        )));
    }
    Ok(Some(Layout {
        marker: chosen.id.clone(),
        marker_md5: md5_bytes(&bytes),
        kdf_file: marker.kdf_file_id,
        kdf_md5,
        packs: marker.packs_folder_id,
        roots: marker.roots_folder_id,
        leases: marker.leases_folder_id,
    }))
}

/// The remote layout with listings of its `roots/` and, when asked for,
/// `packs/`.
struct Snapshot {
    layout: Layout,
    roots: Vec<DriveFile>,
    packs: Option<Vec<DriveFile>>,
}

/// Lists folders on one thread each. Drive answers independent listings
/// concurrently, so several cost about one round trip.
fn list_folders<const N: usize>(
    drive: &GoogleDrive,
    folders: [&str; N],
) -> [Result<Vec<DriveFile>, RemoteError>; N] {
    std::thread::scope(|scope| {
        folders
            .map(|folder| scope.spawn(move || drive.list(folder, false)))
            .map(join)
    })
}

/// Joins a scoped worker, re-raising its panic.
fn join<T>(handle: std::thread::ScopedJoinHandle<'_, T>) -> T {
    handle
        .join()
        .unwrap_or_else(|panic| std::panic::resume_unwind(panic))
}

/// Reads the remote layout. A cached layout is trusted only while the
/// listing of the remote folder still chooses its marker and holds its
/// `_kdf.json` unchanged; that listing then runs concurrently with the
/// layout's own listings. Any mismatch reads the marker again.
fn snapshot(
    remote: &Remote<'_>,
    state: &mut RemoteState,
    with_packs: bool,
) -> Result<Option<Snapshot>, RemoteError> {
    let cached = state.record.layout.as_ref().and_then(Layout::from_known);
    let listing = match cached {
        Some(layout) => {
            let (listing, roots, packs) = if with_packs {
                let [listing, roots, packs] = list_folders(
                    remote.drive,
                    [remote.folder_id, &layout.roots, &layout.packs],
                );
                (listing?, roots, Some(packs))
            } else {
                let [listing, roots] =
                    list_folders(remote.drive, [remote.folder_id, &layout.roots]);
                (listing?, roots, None)
            };
            if layout.listed_in(&listing) {
                return Ok(Some(Snapshot {
                    roots: roots?,
                    packs: packs.transpose()?,
                    layout,
                }));
            }
            listing
        }
        None => remote.drive.list(remote.folder_id, false)?,
    };
    let layout = read_layout(remote, &listing)?;
    remember_layout(state, layout.as_ref())?;
    layout
        .map(|layout| list_layout(remote, layout, with_packs))
        .transpose()
}

fn list_layout(
    remote: &Remote<'_>,
    layout: Layout,
    with_packs: bool,
) -> Result<Snapshot, RemoteError> {
    let (roots, packs) = if with_packs {
        let [roots, packs] = list_folders(remote.drive, [&layout.roots, &layout.packs]);
        (roots?, Some(packs?))
    } else {
        (remote.drive.list(&layout.roots, false)?, None)
    };
    Ok(Snapshot {
        layout,
        roots,
        packs,
    })
}

/// The `packs/` listing of a snapshot, or a fresh one.
fn packs_listing(
    remote: &Remote<'_>,
    layout: &Layout,
    packs: Option<Vec<DriveFile>>,
) -> Result<Vec<DriveFile>, RemoteError> {
    match packs {
        Some(packs) => Ok(packs),
        None => remote.drive.list(&layout.packs, false),
    }
}

fn remember_layout(state: &mut RemoteState, layout: Option<&Layout>) -> Result<(), RemoteError> {
    let known = layout.map(Layout::known);
    if state.record.layout != known {
        state.record.layout = known;
        state.save()?;
    }
    Ok(())
}

/// The layout a push writes into, created on first use, with its listings.
fn push_snapshot(
    remote: &Remote<'_>,
    state: &mut RemoteState,
    kdf_bytes: &[u8],
) -> Result<Snapshot, RemoteError> {
    let snapshot = match snapshot(remote, state, true)? {
        Some(snapshot) => {
            if state.record.pending_layout.take().is_some() {
                state.save()?;
            }
            snapshot
        }
        None => {
            confirm_remote_absent(remote, state)?;
            let layout = init_layout(remote, state, kdf_bytes)?;
            list_layout(remote, layout, true)?
        }
    };
    if !snapshot.layout.holds_kdf(kdf_bytes) {
        return Err(RemoteError::Diverged(
            "the remote folder holds a store with different key material".to_string(),
        ));
    }
    Ok(snapshot)
}

/// A missing marker after this replica confirmed a push is listing lag,
/// unless the synced root record itself is gone.
fn confirm_remote_absent(remote: &Remote<'_>, state: &RemoteState) -> Result<(), RemoteError> {
    let Some(synced) = &state.record.synced else {
        return Ok(());
    };
    if record_present(remote, &synced.record)? {
        return Err(RemoteError::Network(
            "Drive does not list the remote marker yet, although this replica synced it; retry shortly"
                .to_string(),
        ));
    }
    Ok(())
}

/// Whether a root record still exists intact, read by id rather than
/// through a listing that may lag.
fn record_present(remote: &Remote<'_>, id: &str) -> Result<bool, RemoteError> {
    match remote.drive.get(id) {
        Ok(file) => Ok(!file.trashed
            && parse_root_record_name(&file.name).is_some_and(|(_, md5)| file.md5() == Some(md5))),
        Err(RemoteError::NotFound(_)) => Ok(false),
        Err(error) => Err(error),
    }
}

/// Creates the folders and `_kdf.json` concurrently, and finally the
/// marker, all under ids saved beforehand so a retried initialization
/// converges on the same files.
fn init_layout(
    remote: &Remote<'_>,
    state: &mut RemoteState,
    kdf_bytes: &[u8],
) -> Result<Layout, RemoteError> {
    let pending = match state.record.pending_layout.clone() {
        Some(pending) => pending,
        None => {
            let ids = generate_ids(remote.drive, 5)?;
            let pending = PendingLayout {
                packs: ids[0].clone(),
                roots: ids[1].clone(),
                leases: ids[2].clone(),
                kdf: ids[3].clone(),
                marker: ids[4].clone(),
            };
            state.record.pending_layout = Some(pending.clone());
            state.save()?;
            pending
        }
    };
    remote.note("initializing the remote layout");
    let none = BTreeMap::new();
    let created = std::thread::scope(|scope| {
        let mut handles: Vec<_> = [
            (&pending.packs, PACKS_DIR),
            (&pending.roots, ROOTS_DIR),
            (&pending.leases, LEASES_DIR),
        ]
        .into_iter()
        .map(|(id, name)| {
            scope.spawn(move || remote.drive.create_folder(remote.folder_id, name, id))
        })
        .collect();
        handles.push(scope.spawn(|| {
            remote
                .drive
                .create_small(remote.folder_id, KDF_NAME, &pending.kdf, kdf_bytes, &none)
        }));
        handles.into_iter().map(join).collect::<Vec<_>>()
    });
    for result in created {
        result?;
    }
    let marker = Marker::new(
        &pending.packs,
        &pending.roots,
        &pending.leases,
        &pending.kdf,
        &md5_bytes(kdf_bytes),
    )
    .encode();
    remote.drive.create_small(
        remote.folder_id,
        MARKER_NAME,
        &pending.marker,
        &marker,
        &none,
    )?;
    state.record.pending_layout = None;
    state.save()?;
    let ours = Layout {
        marker: pending.marker,
        marker_md5: md5_bytes(&marker),
        kdf_file: pending.kdf,
        kdf_md5: md5_bytes(kdf_bytes),
        packs: pending.packs,
        roots: pending.roots,
        leases: pending.leases,
    };
    // A concurrent initializer's marker with a smaller id wins. Ours counts
    // even while a lagging listing omits it.
    let listing = remote.drive.list(remote.folder_id, false)?;
    let layout = match chosen_marker(&listing) {
        Some(chosen) if chosen.id < ours.marker => read_layout(remote, &listing)?.unwrap_or(ours),
        _ => ours,
    };
    remember_layout(state, Some(&layout))?;
    Ok(layout)
}

fn generate_ids(drive: &GoogleDrive, count: usize) -> Result<Vec<String>, RemoteError> {
    let mut ids = Vec::with_capacity(count);
    while ids.len() < count {
        let batch = drive.generate_ids((count - ids.len()).min(MAX_ID_BATCH))?;
        if batch.is_empty() {
            return Err(RemoteError::Protocol(
                "Drive generated no file ids".to_string(),
            ));
        }
        ids.extend(batch);
    }
    ids.truncate(count);
    Ok(ids)
}

/// The newest authenticated root record.
#[derive(Debug)]
struct RemoteHead {
    number: u64,
    generation: ObjectRef,
    record: DriveFile,
    /// Exact record bytes, unless the generation was already known.
    bytes: Option<Vec<u8>>,
    /// Other generations published under the same number: a fork.
    rivals: usize,
}

/// A root record this replica created or confirmed. Drive may list a
/// recent create late, but answers a read by id at once. A record whose
/// generation this replica authenticated before needs no download: its
/// listed md5 must still equal the md5 in its name.
#[derive(Clone, Debug)]
struct KnownRecord {
    id: String,
    authenticated: Option<Authenticated>,
}

/// What an earlier read of a root record established.
#[derive(Clone, Copy, Debug)]
struct Authenticated {
    number: u64,
    generation: ObjectRef,
    md5: [u8; 16],
}

impl KnownRecord {
    fn of(head: &RemoteHead) -> Self {
        Self {
            id: head.record.id.clone(),
            authenticated: head.record.md5().map(|md5| Authenticated {
                number: head.number,
                generation: head.generation,
                md5,
            }),
        }
    }
}

fn known_records(state: &RemoteState) -> Vec<KnownRecord> {
    let mut known = Vec::new();
    if let Some(synced) = &state.record.synced {
        let md5 = synced.record_md5.as_deref().and_then(unhex::<16>);
        known.push(KnownRecord {
            id: synced.record.clone(),
            authenticated: parse_generation(&synced.generation).zip(md5).map(
                |(generation, md5)| Authenticated {
                    number: synced.number,
                    generation,
                    md5,
                },
            ),
        });
    }
    if let Some(pending) = &state.record.pending_root {
        known.push(KnownRecord {
            id: pending.file_id.clone(),
            authenticated: None,
        });
    }
    known
}

/// Inverse of [`object_hex`].
fn parse_generation(text: &str) -> Option<ObjectRef> {
    if text.len() != 96 || !text.is_ascii() {
        return None;
    }
    let (id, digest) = text.split_at(32);
    Some(ObjectRef::from_parts(unhex(id)?, unhex(digest)?))
}

/// Finds the highest-numbered root records in the `roots/` listing `files`
/// and authenticates each of them. `known` record ids missing from a
/// lagging listing are read by id, so this replica never mistakes its own
/// last record for an absent or rival one. `unreadable` classifies a record
/// the key cannot open: corruption for an unlocked replica, most likely a
/// wrong passphrase for a bootstrap.
fn remote_head(
    remote: &Remote<'_>,
    layout: &Layout,
    mut files: Vec<DriveFile>,
    key: &[u8; 32],
    known: &[KnownRecord],
    unreadable: fn(String) -> RemoteError,
) -> Result<Option<RemoteHead>, RemoteError> {
    for record in known {
        if files.iter().any(|file| file.id == record.id) {
            continue;
        }
        match remote.drive.get(&record.id) {
            Ok(file) if !file.trashed && file.parents.contains(&layout.roots) => {
                files.push(file);
            }
            Ok(_) | Err(RemoteError::NotFound(_)) => {}
            Err(error) => return Err(error),
        }
    }
    let mut candidates = Vec::new();
    for file in files {
        if file.is_folder() {
            continue;
        }
        let Some((number, md5)) = parse_root_record_name(&file.name) else {
            continue;
        };
        let size = file.size().unwrap_or(0);
        if file.md5() != Some(md5) || size == 0 || size > MAX_ROOT_RECORD {
            remote.note(&format!(
                "warning: ignoring damaged root record {}",
                file.name
            ));
            continue;
        }
        candidates.push((number, file));
    }
    let Some(top) = candidates.iter().map(|(number, _)| *number).max() else {
        return Ok(None);
    };
    let mut newest: Vec<DriveFile> = candidates
        .into_iter()
        .filter(|(number, _)| *number == top)
        .map(|(_, file)| file)
        .collect();
    newest.sort_by(|left, right| (&left.name, &left.id).cmp(&(&right.name, &right.id)));
    let mut head: Option<RemoteHead> = None;
    let mut generations = HashSet::new();
    for file in newest {
        let authenticated = known
            .iter()
            .find(|record| record.id == file.id)
            .and_then(|record| record.authenticated)
            .filter(|known| known.number == top && file.md5() == Some(known.md5));
        let (generation, bytes) = match authenticated {
            Some(known) => (known.generation, None),
            None => {
                let bytes = remote.drive.read_small(&file, MAX_ROOT_RECORD)?;
                let generation = replica::decode_root(key, &bytes).map_err(|error| {
                    unreadable(format!(
                        "root record {} does not authenticate: {error}",
                        file.name
                    ))
                })?;
                (generation, Some(bytes))
            }
        };
        generations.insert(generation);
        if head.is_none() {
            head = Some(RemoteHead {
                number: top,
                generation,
                record: file,
                bytes,
                rivals: 0,
            });
        }
    }
    Ok(head.map(|head| RemoteHead {
        rivals: generations.len() - 1,
        ..head
    }))
}

fn refuse_forks(head: &RemoteHead) -> Result<(), RemoteError> {
    if head.rivals == 0 {
        return Ok(());
    }
    Err(RemoteError::Diverged(format!(
        "the remote holds {} different generations numbered {}; every record is preserved, \
         but push and pull refuse until one replica's history is chosen",
        head.rivals + 1,
        head.number
    )))
}

#[derive(Debug)]
struct RemotePack {
    file: DriveFile,
    entries: Vec<PackEntry>,
}

/// Every object held by an intact remote pack.
#[derive(Debug, Default)]
struct RemoteIndex {
    packs: Vec<RemotePack>,
    /// Pack and entry positions of each object; duplicates are alternates.
    locations: HashMap<ObjectRef, Vec<(usize, usize)>>,
    /// Packs whose metadata contradicts their name or whose header is bad.
    damaged: Vec<String>,
    names: HashSet<String>,
    bytes: u64,
}

impl RemoteIndex {
    fn contains(&self, reference: &ObjectRef) -> bool {
        self.locations.contains_key(reference)
    }
}

/// Reads the header of every pack in the `packs/` listing `listing`, from
/// the content-keyed cache unless `fresh`. Damaged packs are skipped, so a
/// push uploads their objects again.
fn remote_index(
    remote: &Remote<'_>,
    listing: Vec<DriveFile>,
    state: &RemoteState,
    fresh: bool,
) -> Result<RemoteIndex, RemoteError> {
    let mut index = RemoteIndex::default();
    let mut files = Vec::new();
    for file in listing {
        let Some((md5, size)) = parse_pack_name(&file.name) else {
            continue;
        };
        if file.is_folder() || file.md5() != Some(md5) || file.size() != Some(size) {
            remote.note(&format!(
                "warning: pack {} does not match its name; ignoring it",
                file.name
            ));
            index.damaged.push(file.name);
            continue;
        }
        files.push((file, size));
    }
    files.sort_by(|(left, _), (right, _)| (&left.name, &left.id).cmp(&(&right.name, &right.id)));
    let headers = parallel_map(&files, DOWNLOAD_PARALLELISM, &|(file, size)| {
        pack_entries(remote.drive, state, file, *size, fresh)
    });
    first_fatal(&headers)?;
    for ((file, size), result) in files.into_iter().zip(headers) {
        let entries = match result {
            Some(Ok(entries)) => entries,
            Some(Err(error)) => {
                remote.note(&format!("warning: {error}"));
                index.damaged.push(file.name);
                continue;
            }
            None => continue,
        };
        let pack = index.packs.len();
        for (slot, entry) in entries.iter().enumerate() {
            index
                .locations
                .entry(entry.reference)
                .or_default()
                .push((pack, slot));
        }
        index.names.insert(file.name.clone());
        index.bytes += size;
        index.packs.push(RemotePack { file, entries });
    }
    Ok(index)
}

fn pack_entries(
    drive: &GoogleDrive,
    state: &RemoteState,
    file: &DriveFile,
    size: u64,
    fresh: bool,
) -> Result<Vec<PackEntry>, RemoteError> {
    if !fresh
        && let Some(cached) = state.cached_header(&file.name)?
        && let Ok(entries) = parse_pack_header(&cached, size)
    {
        return Ok(entries);
    }
    let damaged = |error: String| RemoteError::Integrity(format!("pack {}: {error}", file.name));
    let mut header = drive.read_range(&file.id, 0, size.min(HEADER_PROBE))?;
    let header_len = pack_header_len(parse_pack_prefix(&header).map_err(damaged)?);
    if header_len > size {
        return Err(damaged("header is longer than the pack".to_string()));
    }
    let probed = header.len() as u64;
    if probed < header_len {
        header.extend(drive.read_range(&file.id, probed, header_len - probed)?);
    }
    header.truncate(header_len as usize);
    let entries = parse_pack_header(&header, size).map_err(damaged)?;
    state.store_header(&file.name, &header)?;
    Ok(entries)
}

/// Runs `work` for each item on up to `threads` threads. Integrity failures
/// are per item; any other failure stops items not yet started (`None`).
fn parallel_map<T: Sync, R: Send>(
    items: &[T],
    threads: usize,
    work: &(dyn Fn(&T) -> Result<R, RemoteError> + Sync),
) -> Vec<Option<Result<R, RemoteError>>> {
    let next = AtomicUsize::new(0);
    let stop = AtomicBool::new(false);
    let results: Vec<Mutex<Option<Result<R, RemoteError>>>> =
        items.iter().map(|_| Mutex::new(None)).collect();
    std::thread::scope(|scope| {
        for _ in 0..threads.min(items.len()) {
            scope.spawn(|| {
                while !stop.load(Ordering::SeqCst) {
                    let position = next.fetch_add(1, Ordering::SeqCst);
                    let Some(item) = items.get(position) else {
                        break;
                    };
                    let result = work(item);
                    if matches!(&result, Err(error) if !matches!(error, RemoteError::Integrity(_)))
                    {
                        stop.store(true, Ordering::SeqCst);
                    }
                    *lock(&results[position]) = Some(result);
                }
            });
        }
    });
    results
        .into_iter()
        .map(|cell| {
            cell.into_inner()
                .unwrap_or_else(|poison| poison.into_inner())
        })
        .collect()
}

/// The first failure other than a per-item integrity failure.
fn first_fatal<R>(results: &[Option<Result<R, RemoteError>>]) -> Result<(), RemoteError> {
    for result in results.iter().flatten() {
        if let Err(error) = result
            && !matches!(error, RemoteError::Integrity(_))
        {
            return Err(clone_error(error));
        }
    }
    Ok(())
}

fn clone_error(error: &RemoteError) -> RemoteError {
    match error {
        RemoteError::Auth(message) => RemoteError::Auth(message.clone()),
        RemoteError::Quota(message) => RemoteError::Quota(message.clone()),
        RemoteError::NotFound(message) => RemoteError::NotFound(message.clone()),
        RemoteError::Conflict(message) => RemoteError::Conflict(message.clone()),
        RemoteError::Integrity(message) => RemoteError::Integrity(message.clone()),
        RemoteError::Diverged(message) => RemoteError::Diverged(message.clone()),
        RemoteError::Network(message) => RemoteError::Network(message.clone()),
        RemoteError::Protocol(message) => RemoteError::Protocol(message.clone()),
        RemoteError::Denied(message) => RemoteError::Denied(message.clone()),
        RemoteError::Local(message) => RemoteError::Local(message.clone()),
    }
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(|poison| poison.into_inner())
}

fn object_hex(reference: &ObjectRef) -> String {
    format!("{}{}", hex(reference.id()), hex(reference.digest()))
}

fn record_synced(
    state: &mut RemoteState,
    display: &str,
    number: u64,
    generation: &ObjectRef,
    record: &DriveFile,
) -> Result<(), RemoteError> {
    let unix_seconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs())
        .unwrap_or(0);
    state.record.synced = Some(SyncedHead {
        number,
        generation: object_hex(generation),
        record: record.id.clone(),
        record_md5: record.md5().map(|md5| hex(&md5)),
        encrypted_dir: display.to_string(),
        unix_seconds,
    });
    state.record.pending_root = None;
    state.save()
}

/// The local head's number when the remote last held exactly it, so there
/// is nothing to upload; answers without the network.
pub(crate) fn synced_head(
    local: &LocalStore<'_>,
    state: &RemoteState,
) -> Result<Option<u64>, RemoteError> {
    let head = local.head()?.state;
    Ok(state
        .record
        .synced
        .as_ref()
        .filter(|synced| {
            synced.number == head.number && synced.generation == object_hex(&head.generation)
        })
        .map(|synced| synced.number))
}

/// Outcome of one push.
#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct PushReport {
    /// Local generation now published.
    pub(crate) number: u64,
    /// Remote generation before the push.
    pub(crate) previous: Option<u64>,
    pub(crate) generations: usize,
    pub(crate) objects: usize,
    pub(crate) packs: usize,
    pub(crate) bytes: u64,
    pub(crate) up_to_date: bool,
}

/// A sealed pack on its way to the remote.
struct Job {
    name: String,
    path: PathBuf,
    header: Vec<u8>,
    checkpoint: UploadCheckpoint,
    size: u64,
}

/// A pack left in `outgoing/` by an interrupted push.
struct Queued {
    name: String,
    path: PathBuf,
    header: Vec<u8>,
    entries: Vec<PackEntry>,
    checkpoint: Option<UploadCheckpoint>,
    size: u64,
}

/// Telemetry names of one transfer direction; they never carry a name, id or
/// path.
struct Transfer {
    op: &'static str,
    duration: &'static str,
    failed: &'static str,
    bytes: &'static str,
    objects: &'static str,
    packs: &'static str,
}

const PUSH: Transfer = Transfer {
    op: "push",
    duration: "remote.push",
    failed: "remote.push.failed",
    bytes: "remote.push.bytes",
    objects: "remote.push.objects",
    packs: "remote.push.packs",
};

const PULL: Transfer = Transfer {
    op: "pull",
    duration: "remote.pull",
    failed: "remote.pull.failed",
    bytes: "remote.pull.bytes",
    objects: "remote.pull.objects",
    packs: "remote.pull.packs",
};

const BOOTSTRAP: Transfer = Transfer {
    op: "bootstrap",
    duration: "remote.bootstrap",
    failed: "remote.bootstrap.failed",
    bytes: "remote.bootstrap.bytes",
    objects: "remote.bootstrap.objects",
    packs: "remote.bootstrap.packs",
};

fn pulled(result: &Result<PullReport, RemoteError>) -> Result<(u64, usize, usize), &RemoteError> {
    result
        .as_ref()
        .map(|report| (report.bytes, report.objects, report.packs))
}

/// Records one transfer: its duration, and what it moved or why it failed.
fn record_transfer(
    transfer: &Transfer,
    started: Instant,
    moved: Result<(u64, usize, usize), &RemoteError>,
) {
    telemetry::duration(transfer.duration, started.elapsed());
    match moved {
        Ok((bytes, objects, packs)) => {
            telemetry::counter(transfer.bytes, bytes);
            telemetry::counter(transfer.objects, objects as u64);
            telemetry::counter(transfer.packs, packs as u64);
        }
        Err(error) => {
            telemetry::counter(transfer.failed, 1);
            telemetry::event(
                Level::Standard,
                "remote.sync_failed",
                &[
                    ("op", Field::Tag(transfer.op)),
                    ("error", Field::Tag(error_kind(error))),
                ],
            );
        }
    }
}

fn error_kind(error: &RemoteError) -> &'static str {
    match error {
        RemoteError::Auth(_) => "auth",
        RemoteError::Quota(_) => "quota",
        RemoteError::NotFound(_) => "not_found",
        RemoteError::Conflict(_) => "conflict",
        RemoteError::Integrity(_) => "integrity",
        RemoteError::Diverged(_) => "diverged",
        RemoteError::Network(_) => "network",
        RemoteError::Protocol(_) => "protocol",
        RemoteError::Denied(_) => "denied",
        RemoteError::Local(_) => "local",
    }
}

/// Publishes the local head: uploads every object of its closure the remote
/// lacks, then creates its root record. The remote head must be an ancestor
/// of the local head.
pub(crate) fn push(
    remote: &Remote<'_>,
    local: &LocalStore<'_>,
    state: &mut RemoteState,
) -> Result<PushReport, RemoteError> {
    let started = Instant::now();
    let result = push_unrecorded(remote, local, state);
    let moved = result
        .as_ref()
        .map(|report| (report.bytes, report.objects, report.packs));
    record_transfer(&PUSH, started, moved);
    result
}

fn push_unrecorded(
    remote: &Remote<'_>,
    local: &LocalStore<'_>,
    state: &mut RemoteState,
) -> Result<PushReport, RemoteError> {
    let head = local.head()?;
    let Snapshot {
        layout,
        roots,
        packs,
    } = push_snapshot(remote, state, local.kdf_bytes)?;
    let before = remote_head(
        remote,
        &layout,
        roots,
        local.key,
        &known_records(state),
        RemoteError::Integrity,
    )?;
    let mut walker = ClosureWalker::new(local.base, local.key, local.pin);
    let base = match &before {
        None => ChainBase::Origin,
        Some(found) => {
            refuse_forks(found)?;
            if found.generation == head.state.generation {
                for queued in state.outgoing_packs()? {
                    state.finish_outgoing(&queued.name)?;
                }
                record_synced(
                    state,
                    local.display,
                    found.number,
                    &found.generation,
                    &found.record,
                )?;
                return Ok(PushReport {
                    number: found.number,
                    previous: Some(found.number),
                    up_to_date: true,
                    ..PushReport::default()
                });
            }
            if found.number >= head.state.number {
                return Err(remote_not_behind(found, &head.state));
            }
            if !replica::object_exists(local.base, local.pin, &found.generation)? {
                return Err(diverged(found.number, head.state.number));
            }
            let info = walker.generation_info(found.generation)?;
            if info.number != found.number {
                return Err(RemoteError::Integrity(format!(
                    "root record {} holds generation {}",
                    found.record.name, info.number
                )));
            }
            ChainBase::Ancestor {
                number: found.number,
                reference: found.generation,
            }
        }
    };

    let index = remote_index(remote, packs_listing(remote, &layout, packs)?, state, false)?;
    let queued = queued_packs(remote, state)?;
    let pending: HashSet<ObjectRef> = queued
        .iter()
        .flat_map(|pack| pack.entries.iter().map(|entry| entry.reference))
        .collect();
    let mut needed = Vec::new();
    let mut seen = HashSet::new();
    let mut visit = |reference: ObjectRef, _bound: u64| -> std::io::Result<()> {
        if !index.contains(&reference) && !pending.contains(&reference) && seen.insert(reference) {
            needed.push(reference);
        }
        Ok(())
    };
    let generations = match walker.chain(head.state.generation, base, &mut visit)? {
        ChainOutcome::Extends(generations) => generations,
        ChainOutcome::Diverged => {
            return Err(diverged(
                before.as_ref().map_or(0, |found| found.number),
                head.state.number,
            ));
        }
    };
    let walk: Vec<GenerationInfo> = match base {
        ChainBase::Ancestor { reference, .. } if index.damaged.is_empty() => {
            walker.mark_complete(reference)?;
            generations.clone()
        }
        ChainBase::Ancestor { .. } => {
            remote.note("re-uploading the objects of damaged remote packs");
            match walker.chain(head.state.generation, ChainBase::Origin, &mut visit)? {
                ChainOutcome::Extends(all) => all,
                ChainOutcome::Diverged => {
                    return Err(RemoteError::Local(
                        "the local lineage does not reach its origin".to_string(),
                    ));
                }
            }
        }
        ChainBase::Origin => generations.clone(),
    };
    for info in &walk {
        walker.generation(info, &mut visit)?;
    }
    drop(walker);

    let plans = plan_packs(local, &needed)?;
    let record_name = root_record_name(head.state.number, &md5_bytes(&head.root_bytes));
    let record_id_needed = state
        .record
        .pending_root
        .as_ref()
        .is_none_or(|pending| pending.name != record_name);
    let fresh_ids = plans.len()
        + queued
            .iter()
            .filter(|pack| pack.checkpoint.is_none())
            .count()
        + usize::from(record_id_needed);
    let mut ids = generate_ids(remote.drive, fresh_ids)?;
    let record_id = if record_id_needed { ids.pop() } else { None };
    let mut ids = ids.into_iter();
    let mut resumed = Vec::with_capacity(queued.len());
    for pack in queued {
        let checkpoint = match pack.checkpoint {
            Some(checkpoint) => checkpoint,
            None => {
                let checkpoint = UploadCheckpoint {
                    file_id: next_id(&mut ids)?,
                    session_uri: None,
                };
                state.save_checkpoint(&pack.name, &checkpoint)?;
                checkpoint
            }
        };
        resumed.push(Job {
            name: pack.name,
            path: pack.path,
            header: pack.header,
            checkpoint,
            size: pack.size,
        });
    }
    if !needed.is_empty() || !resumed.is_empty() {
        remote.note(&format!(
            "uploading {} object(s) in {} pack(s)",
            needed.len() + pending.len(),
            plans.len() + resumed.len()
        ));
    }
    let (packs, bytes) = upload_packs(remote, &layout, state, &index, local, resumed, &plans, ids)?;

    let mut known = known_records(state);
    known.extend(before.as_ref().map(KnownRecord::of));
    let current = remote_head(
        remote,
        &layout,
        remote.drive.list(&layout.roots, false)?,
        local.key,
        &known,
        RemoteError::Integrity,
    )?;
    let current_generation = current.as_ref().map(|found| found.generation);
    if current_generation != before.as_ref().map(|found| found.generation)
        && current_generation != Some(head.state.generation)
    {
        return Err(RemoteError::Conflict(
            "another replica published a root during this push; pull, then push again".to_string(),
        ));
    }
    let record = publish_root(remote, &layout, state, &head, record_id)?;
    confirm_root(remote, &layout, local.key, &head.state, &record)?;
    record_synced(
        state,
        local.display,
        head.state.number,
        &head.state.generation,
        &record,
    )?;
    Ok(PushReport {
        number: head.state.number,
        previous: before.map(|found| found.number),
        generations: generations.len(),
        objects: needed.len() + pending.len(),
        packs,
        bytes,
        up_to_date: false,
    })
}

fn next_id(ids: &mut impl Iterator<Item = String>) -> Result<String, RemoteError> {
    ids.next()
        .ok_or_else(|| RemoteError::Protocol("Drive generated too few file ids".to_string()))
}

fn remote_not_behind(found: &RemoteHead, local: &CommitState) -> RemoteError {
    if found.number == local.number {
        return diverged(found.number, local.number);
    }
    RemoteError::Conflict(format!(
        "the remote holds generation {}, newer than local generation {}; run `zdrive remote pull` first",
        found.number, local.number
    ))
}

fn diverged(remote: u64, local: u64) -> RemoteError {
    RemoteError::Diverged(format!(
        "remote generation {remote} and local generation {local} are on different histories; \
         both are preserved and neither is overwritten"
    ))
}

/// Packs left in `outgoing/` whose content still matches their name.
fn queued_packs(remote: &Remote<'_>, state: &RemoteState) -> Result<Vec<Queued>, RemoteError> {
    let mut queued = Vec::new();
    for pack in state.outgoing_packs()? {
        let Some((md5, size)) = parse_pack_name(&pack.name) else {
            continue;
        };
        let intact = md5_file(&pack.path)? == (md5, size);
        match intact.then(|| read_local_header(&pack.path, size)) {
            Some(Ok((header, entries))) => queued.push(Queued {
                name: pack.name,
                path: pack.path,
                header,
                entries,
                checkpoint: pack.checkpoint,
                size,
            }),
            _ => {
                remote.note(&format!(
                    "warning: discarding damaged queued pack {}",
                    pack.name
                ));
                state.finish_outgoing(&pack.name)?;
            }
        }
    }
    Ok(queued)
}

fn read_local_header(path: &Path, size: u64) -> Result<(Vec<u8>, Vec<PackEntry>), RemoteError> {
    let mut file = File::open(path)?;
    let mut header = vec![0u8; PACK_PREFIX_LEN as usize];
    file.read_exact(&mut header)?;
    let header_len = pack_header_len(parse_pack_prefix(&header).map_err(RemoteError::Local)?);
    if header_len > size {
        return Err(RemoteError::Local(
            "queued pack header is too long".to_string(),
        ));
    }
    header.resize(header_len as usize, 0);
    file.read_exact(&mut header[PACK_PREFIX_LEN as usize..])?;
    let entries = parse_pack_header(&header, size).map_err(RemoteError::Local)?;
    Ok((header, entries))
}

/// Groups objects into packs of about `TARGET_PACK_BYTES`, in walk order.
fn plan_packs(
    local: &LocalStore<'_>,
    needed: &[ObjectRef],
) -> Result<Vec<Vec<(ObjectRef, u64)>>, RemoteError> {
    let mut plans = Vec::new();
    let mut current = Vec::new();
    let mut bytes = 0u64;
    for reference in needed {
        let len = replica::object_len(local.base, local.pin, reference)?;
        if len == 0 || len > MAX_OBJECT_CIPHERTEXT {
            return Err(RemoteError::Local(format!(
                "local object {} has an invalid length {len}",
                hex(reference.id())
            )));
        }
        if !current.is_empty()
            && (bytes + len > TARGET_PACK_BYTES || current.len() >= MAX_PACK_OBJECTS as usize)
        {
            plans.push(std::mem::take(&mut current));
            bytes = 0;
        }
        current.push((*reference, len));
        bytes += len;
    }
    if !current.is_empty() {
        plans.push(current);
    }
    Ok(plans)
}

/// Seals packs on this thread while workers upload earlier ones. On the
/// first failure no new pack is sealed or started; sealed packs stay queued
/// with their checkpoints for the next push.
#[allow(clippy::too_many_arguments)]
fn upload_packs(
    remote: &Remote<'_>,
    layout: &Layout,
    state: &RemoteState,
    index: &RemoteIndex,
    local: &LocalStore<'_>,
    resumed: Vec<Job>,
    plans: &[Vec<(ObjectRef, u64)>],
    mut ids: impl Iterator<Item = String>,
) -> Result<(usize, u64), RemoteError> {
    let failed = AtomicBool::new(false);
    let first_error: Mutex<Option<RemoteError>> = Mutex::new(None);
    let totals = Mutex::new((0usize, 0u64));
    let fail = |error: RemoteError| {
        failed.store(true, Ordering::SeqCst);
        lock(&first_error).get_or_insert(error);
    };
    let (sender, receiver) = mpsc::sync_channel::<Job>(PIPELINE_DEPTH);
    let receiver = Mutex::new(receiver);
    std::thread::scope(|scope| {
        for _ in 0..UPLOAD_PARALLELISM {
            scope.spawn(|| {
                loop {
                    let next = lock(&receiver).recv();
                    let Ok(job) = next else {
                        break;
                    };
                    if failed.load(Ordering::SeqCst) {
                        continue;
                    }
                    match upload_pack(remote, layout, state, index, job) {
                        Ok(Some(size)) => {
                            let mut totals = lock(&totals);
                            totals.0 += 1;
                            totals.1 += size;
                        }
                        Ok(None) => {}
                        Err(error) => fail(error),
                    }
                }
            });
        }
        let sender = sender;
        for job in resumed {
            if failed.load(Ordering::SeqCst) || sender.send(job).is_err() {
                return;
            }
        }
        for (sequence, plan) in plans.iter().enumerate() {
            if failed.load(Ordering::SeqCst) {
                return;
            }
            let job = next_id(&mut ids).and_then(|id| seal_pack(local, state, plan, sequence, id));
            match job {
                Ok(job) => {
                    if sender.send(job).is_err() {
                        return;
                    }
                }
                Err(error) => {
                    fail(error);
                    return;
                }
            }
        }
    });
    if let Some(error) = first_error
        .into_inner()
        .unwrap_or_else(|poison| poison.into_inner())
    {
        return Err(error);
    }
    Ok(totals
        .into_inner()
        .unwrap_or_else(|poison| poison.into_inner()))
}

/// Uploads one pack unless an intact remote copy exists, then retires it
/// from the queue. Returns the uploaded size.
fn upload_pack(
    remote: &Remote<'_>,
    layout: &Layout,
    state: &RemoteState,
    index: &RemoteIndex,
    job: Job,
) -> Result<Option<u64>, RemoteError> {
    let mut uploaded = None;
    if !index.names.contains(&job.name) {
        let mut checkpoint = job.checkpoint;
        let mut persist =
            |checkpoint: &UploadCheckpoint| state.save_checkpoint(&job.name, checkpoint);
        let file = remote.drive.upload_file(
            &layout.packs,
            &job.name,
            &job.path,
            &mut checkpoint,
            &mut persist,
        )?;
        if parse_pack_name(&job.name).map(|(md5, size)| (Some(md5), Some(size)))
            != Some((file.md5(), file.size()))
        {
            state.finish_outgoing(&job.name)?;
            return Err(RemoteError::Integrity(format!(
                "queued pack {} changed on local disk; it is discarded and resealed by the next push",
                job.name
            )));
        }
        uploaded = Some(job.size);
    }
    state.store_header(&job.name, &job.header)?;
    state.finish_outgoing(&job.name)?;
    Ok(uploaded)
}

/// Writes one pack into `outgoing/`, durably, named by its content.
fn seal_pack(
    local: &LocalStore<'_>,
    state: &RemoteState,
    plan: &[(ObjectRef, u64)],
    sequence: usize,
    file_id: String,
) -> Result<Job, RemoteError> {
    let header = encode_pack_header(plan).map_err(RemoteError::Local)?;
    let dir = state.outgoing_dir();
    let temporary = dir.join(format!(".pack.{}.{sequence}.tmp", std::process::id()));
    let result = (|| -> Result<Job, RemoteError> {
        let file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&temporary)?;
        let mut writer = BufWriter::with_capacity(1 << 20, file);
        let mut hasher = md5::Md5::new();
        writer.write_all(&header)?;
        hasher.update(&header);
        let mut size = header.len() as u64;
        for (reference, len) in plan {
            let bytes =
                replica::read_ciphertext(local.base, local.pin, reference, MAX_OBJECT_CIPHERTEXT)?;
            if bytes.len() as u64 != *len {
                return Err(RemoteError::Local(format!(
                    "local object {} changed size while packing",
                    hex(reference.id())
                )));
            }
            writer.write_all(&bytes)?;
            hasher.update(&bytes);
            size += len;
        }
        writer
            .into_inner()
            .map_err(|error| error.into_error())?
            .sync_all()?;
        let md5: [u8; 16] = hasher.finalize().into();
        let name = pack_name(&md5, size);
        let path = dir.join(&name);
        std::fs::rename(&temporary, &path)?;
        File::open(&dir)?.sync_all()?;
        let checkpoint = UploadCheckpoint {
            file_id,
            session_uri: None,
        };
        state.save_checkpoint(&name, &checkpoint)?;
        Ok(Job {
            name,
            path,
            header,
            checkpoint,
            size,
        })
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&temporary);
    }
    result
}

/// Creates the root record under an id saved beforehand, so an ambiguous
/// failure is retried as the same file rather than a duplicate. `fresh` is
/// a generated id to use when no matching record is pending.
fn publish_root(
    remote: &Remote<'_>,
    layout: &Layout,
    state: &mut RemoteState,
    head: &LocalHead,
    fresh: Option<String>,
) -> Result<DriveFile, RemoteError> {
    let name = root_record_name(head.state.number, &md5_bytes(&head.root_bytes));
    let file_id = match &state.record.pending_root {
        Some(pending) if pending.name == name => pending.file_id.clone(),
        _ => {
            let id = match fresh {
                Some(id) => id,
                None => next_id(&mut generate_ids(remote.drive, 1)?.into_iter())?,
            };
            state.record.pending_root = Some(PendingRoot {
                name: name.clone(),
                file_id: id.clone(),
            });
            state.save()?;
            id
        }
    };
    let record = remote.drive.create_small(
        &layout.roots,
        &name,
        &file_id,
        &head.root_bytes,
        &BTreeMap::new(),
    )?;
    state.record.pending_root = None;
    state.save()?;
    Ok(record)
}

/// Re-reads the remote head after publishing: a rival record at the same or
/// a higher number is a fork; an absent one is listing lag, confirmed by id.
fn confirm_root(
    remote: &Remote<'_>,
    layout: &Layout,
    key: &[u8; 32],
    head: &CommitState,
    record: &DriveFile,
) -> Result<(), RemoteError> {
    let ours = KnownRecord {
        id: record.id.clone(),
        authenticated: record.md5().map(|md5| Authenticated {
            number: head.number,
            generation: head.generation,
            md5,
        }),
    };
    match remote_head(
        remote,
        layout,
        remote.drive.list(&layout.roots, false)?,
        key,
        std::slice::from_ref(&ours),
        RemoteError::Integrity,
    )? {
        Some(found)
            if found.number == head.number
                && found.generation == head.generation
                && found.rivals == 0 =>
        {
            Ok(())
        }
        Some(found) if found.number >= head.number => Err(RemoteError::Diverged(format!(
            "another replica published generation {} concurrently; both histories are preserved, \
             but push and pull refuse until one is chosen",
            found.number
        ))),
        _ => {
            let fetched = remote.drive.get(&record.id)?;
            if fetched.trashed || fetched.md5() != record.md5() {
                return Err(RemoteError::Integrity(
                    "the new root record is missing after it was created".to_string(),
                ));
            }
            remote.note("Drive does not list the new root record yet; it is confirmed by id");
            Ok(())
        }
    }
}

/// Outcome of one pull.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) enum PullOutcome {
    Advanced,
    #[default]
    UpToDate,
    /// The local head descends from the remote head; push publishes it.
    LocalAhead,
    /// The remote layout exists but holds no root record yet.
    RemoteEmpty,
    Bootstrapped,
}

#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct PullReport {
    pub(crate) outcome: PullOutcome,
    /// Local generation after the pull.
    pub(crate) number: u64,
    pub(crate) previous: Option<u64>,
    pub(crate) generations: usize,
    pub(crate) objects: usize,
    pub(crate) packs: usize,
    pub(crate) bytes: u64,
}

/// Fast-forwards the local store to the remote head.
pub(crate) fn pull(
    remote: &Remote<'_>,
    local: &LocalStore<'_>,
    state: &mut RemoteState,
) -> Result<PullReport, RemoteError> {
    let started = Instant::now();
    let result = pull_unrecorded(remote, local, state);
    record_transfer(&PULL, started, pulled(&result));
    result
}

fn pull_unrecorded(
    remote: &Remote<'_>,
    local: &LocalStore<'_>,
    state: &mut RemoteState,
) -> Result<PullReport, RemoteError> {
    // `packs/` is listed only once the head is known: a listing taken
    // before `roots/` could miss the packs of a root published between them.
    let Snapshot { layout, roots, .. } =
        snapshot(remote, state, false)?.ok_or_else(no_remote_store)?;
    if !layout.holds_kdf(local.kdf_bytes) {
        return Err(RemoteError::Diverged(
            "the remote folder holds a store with different key material".to_string(),
        ));
    }
    let head = local.head()?.state;
    let mut report = PullReport {
        number: head.number,
        previous: Some(head.number),
        ..PullReport::default()
    };
    let Some(found) = remote_head(
        remote,
        &layout,
        roots,
        local.key,
        &known_records(state),
        RemoteError::Integrity,
    )?
    else {
        report.outcome = PullOutcome::RemoteEmpty;
        return Ok(report);
    };
    refuse_forks(&found)?;
    if found.generation == head.generation {
        record_synced(
            state,
            local.display,
            found.number,
            &found.generation,
            &found.record,
        )?;
        return Ok(report);
    }
    let mut walker = ClosureWalker::new(local.base, local.key, local.pin);
    if found.number <= head.number {
        if replica::object_exists(local.base, local.pin, &found.generation)?
            && let ChainOutcome::Extends(_) = walker.chain(
                head.generation,
                ChainBase::Ancestor {
                    number: found.number,
                    reference: found.generation,
                },
                &mut |_, _| Ok(()),
            )?
        {
            report.outcome = PullOutcome::LocalAhead;
            return Ok(report);
        }
        return Err(diverged(found.number, head.number));
    }

    let index = remote_index(
        remote,
        remote.drive.list(&layout.packs, false)?,
        state,
        false,
    )?;
    let mut fetcher = Fetcher::new(
        remote,
        &index,
        state.incoming_dir(),
        state.damaged_dir(),
        local.base,
        local.pin,
    );
    let mut wanted = Vec::new();
    for (position, pack) in index.packs.iter().enumerate() {
        for entry in &pack.entries {
            if !replica::object_exists(local.base, local.pin, &entry.reference)? {
                wanted.push(position);
                break;
            }
        }
    }
    fetcher.prefetch(&wanted)?;
    let mut ensure =
        |reference: ObjectRef, _bound: u64| fetcher.ensure(reference).map_err(std::io::Error::from);
    let generations = match walker.chain(
        found.generation,
        ChainBase::Ancestor {
            number: head.number,
            reference: head.generation,
        },
        &mut ensure,
    )? {
        ChainOutcome::Extends(generations) => generations,
        ChainOutcome::Diverged => return Err(diverged(found.number, head.number)),
    };
    check_chain_head(&generations, &found)?;
    walker.mark_complete(head.generation)?;
    for info in &generations {
        walker.generation(info, &mut ensure)?;
    }
    drop(walker);
    // One authentication of every changed file of the final generation
    // replaces a per-generation pass over files later generations replace.
    replica::validate_generation_delta(
        local.base,
        local.key,
        local.pin,
        Some(head.generation),
        found.generation,
    )?;
    // Unconditional: an interrupted earlier pull may have installed objects
    // this one found intact but that no barrier made durable yet.
    replica::sync_installed(local.base, local.pin)?;
    let mut current = head;
    for info in &generations {
        current = v2::fast_forward_pinned(
            local.base,
            local.key,
            &current,
            info.reference,
            local.kdf_fingerprint,
            local.pin,
            ChildFiles::ValidatedChain,
        )
        .map_err(|failure| {
            let advice = if failure.recovery_required {
                "; open the store again to run crash recovery"
            } else {
                ""
            };
            RemoteError::Local(format!(
                "fast-forward to generation {}: {}{advice}",
                info.number, failure.error
            ))
        })?;
    }
    report.objects = fetcher.installed;
    report.packs = fetcher.downloaded;
    report.bytes = fetcher.downloaded_bytes;
    state.clear_incoming()?;
    record_synced(
        state,
        local.display,
        current.number,
        &current.generation,
        &found.record,
    )?;
    report.outcome = PullOutcome::Advanced;
    report.number = current.number;
    report.generations = generations.len();
    Ok(report)
}

fn no_remote_store() -> RemoteError {
    RemoteError::NotFound("the remote folder holds no zdrive store; push one first".to_string())
}

/// The walked chain must end at the record's generation and number.
fn check_chain_head(generations: &[GenerationInfo], found: &RemoteHead) -> Result<(), RemoteError> {
    match generations.last() {
        Some(last) if last.reference == found.generation && last.number == found.number => Ok(()),
        _ => Err(RemoteError::Integrity(format!(
            "root record {} does not name the generation it holds",
            found.record.name
        ))),
    }
}

/// Makes remote objects locally present, from downloaded packs.
struct Fetcher<'a> {
    remote: &'a Remote<'a>,
    index: &'a RemoteIndex,
    incoming: PathBuf,
    damaged: PathBuf,
    base: &'a Path,
    pin: &'a V2NamespacePin,
    /// Downloaded packs; `None` marks a pack that failed verification.
    files: HashMap<usize, Option<File>>,
    installed: usize,
    downloaded: usize,
    downloaded_bytes: u64,
}

impl<'a> Fetcher<'a> {
    fn new(
        remote: &'a Remote<'a>,
        index: &'a RemoteIndex,
        incoming: PathBuf,
        damaged: PathBuf,
        base: &'a Path,
        pin: &'a V2NamespacePin,
    ) -> Self {
        Self {
            remote,
            index,
            incoming,
            damaged,
            base,
            pin,
            files: HashMap::new(),
            installed: 0,
            downloaded: 0,
            downloaded_bytes: 0,
        }
    }

    fn path(&self, pack: usize) -> PathBuf {
        self.incoming
            .join(format!("{}.zpk", self.index.packs[pack].file.id))
    }

    fn download(&self, pack: usize) -> Result<(), RemoteError> {
        self.remote
            .drive
            .download_to(&self.index.packs[pack].file, &self.path(pack))
    }

    fn opened(&mut self, pack: usize, result: Result<(), RemoteError>) -> Result<(), RemoteError> {
        let file = match result {
            Ok(()) => {
                self.downloaded += 1;
                self.downloaded_bytes += self.index.packs[pack].file.size().unwrap_or(0);
                Some(File::open(self.path(pack))?)
            }
            Err(RemoteError::Integrity(message)) => {
                self.remote.note(&format!("warning: {message}"));
                None
            }
            Err(error) => return Err(error),
        };
        self.files.insert(pack, file);
        Ok(())
    }

    /// Downloads packs in parallel; a pack failing verification is skipped
    /// and its objects are taken from other packs.
    fn prefetch(&mut self, packs: &[usize]) -> Result<(), RemoteError> {
        if packs.is_empty() {
            return Ok(());
        }
        self.remote
            .note(&format!("downloading {} pack(s)", packs.len()));
        let results = parallel_map(packs, DOWNLOAD_PARALLELISM, &|&pack| self.download(pack));
        first_fatal(&results)?;
        for (&pack, result) in packs.iter().zip(results) {
            if let Some(result) = result {
                self.opened(pack, result)?;
            }
        }
        Ok(())
    }

    fn ensure(&mut self, reference: ObjectRef) -> Result<(), RemoteError> {
        if replica::object_exists(self.base, self.pin, &reference)?
            && !self.remove_damaged(&reference)?
        {
            return Ok(());
        }
        let index = self.index;
        let locations = index.locations.get(&reference).ok_or_else(|| {
            RemoteError::NotFound(format!(
                "the remote closure is incomplete: object {} is in no intact pack",
                hex(reference.id())
            ))
        })?;
        for &(pack, slot) in locations {
            if !self.files.contains_key(&pack) {
                let result = self.download(pack);
                self.opened(pack, result)?;
            }
            let Some(Some(file)) = self.files.get(&pack) else {
                continue;
            };
            let entry = &index.packs[pack].entries[slot];
            let mut bytes = vec![0u8; entry.len as usize];
            file.read_exact_at(&mut bytes, entry.offset)?;
            if replica::ciphertext_digest(&bytes) != *reference.digest() {
                self.remote.note(&format!(
                    "warning: pack {} holds a damaged copy of object {}",
                    index.packs[pack].file.name,
                    hex(reference.id())
                ));
                continue;
            }
            if replica::install_ciphertext(self.base, self.pin, &reference, &bytes)? {
                self.installed += 1;
            }
            return Ok(());
        }
        Err(RemoteError::Integrity(format!(
            "no intact remote copy of object {} exists",
            hex(reference.id())
        )))
    }

    /// Removes a local copy of `reference` whose bytes miss its authenticated
    /// digest, as a crash between an install and its barrier can leave it,
    /// after keeping those bytes as evidence. Whether it was removed.
    fn remove_damaged(&self, reference: &ObjectRef) -> Result<bool, RemoteError> {
        let name = hex(reference.id());
        let mut kept = None;
        let removed =
            replica::remove_damaged_object(self.base, self.pin, reference, &mut |bytes| {
                ensure_private_dir(&self.damaged)?;
                let stamp = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_nanos();
                let path = self.damaged.join(format!("{name}.{stamp}.z2"));
                write_private_file(&path, bytes)?;
                kept = Some((path, bytes.len()));
                Ok(())
            })?;
        if removed && let Some((path, len)) = kept {
            telemetry::counter("remote.damaged_objects_replaced", 1);
            self.remote.note(&format!(
                "warning: local object {name} was damaged; kept its {len} bytes at {} and \
                 installing the authenticated copy",
                path.display()
            ));
        }
        Ok(removed)
    }
}

/// Whether `base` holds a bootstrap pull to finish.
pub(crate) fn bootstrap_pending(base: &Path) -> Result<bool, RemoteError> {
    Ok(entry_exists(&base.join(PULL_PENDING_FILE))?)
}

fn entry_exists(path: &Path) -> std::io::Result<bool> {
    match std::fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error),
    }
}

/// The remote store's `_kdf.json`, from which a new replica derives its
/// key, with the layout that vouches for it.
pub(crate) struct RemoteKdf {
    layout: Layout,
    pub(crate) bytes: Vec<u8>,
}

/// Reads the exact `_kdf.json` the remote marker commits to.
pub(crate) fn remote_kdf(remote: &Remote<'_>) -> Result<RemoteKdf, RemoteError> {
    let listing = remote.drive.list(remote.folder_id, false)?;
    let layout = read_layout(remote, &listing)?.ok_or_else(no_remote_store)?;
    let file = match listing.iter().find(|file| file.id == layout.kdf_file) {
        Some(file) => file.clone(),
        None => remote.drive.get(&layout.kdf_file)?,
    };
    let bytes = remote.drive.read_small(&file, MAX_SMALL_FILE)?;
    if !layout.holds_kdf(&bytes) {
        return Err(RemoteError::Integrity(format!(
            "the remote {KDF_NAME} does not match its marker"
        )));
    }
    Ok(RemoteKdf { layout, bytes })
}

/// The exact bytes of the head's root record.
fn head_bytes(remote: &Remote<'_>, head: &RemoteHead) -> Result<Vec<u8>, RemoteError> {
    match &head.bytes {
        Some(bytes) => Ok(bytes.clone()),
        None => remote.drive.read_small(&head.record, MAX_ROOT_RECORD),
    }
}

/// Fills the empty directory `base` with a complete replica of the remote
/// head. A pending marker makes an interrupted bootstrap resumable and keeps
/// the half-filled directory from being mounted.
pub(crate) fn bootstrap(
    remote: &Remote<'_>,
    base: &Path,
    display: &str,
    key: &[u8; 32],
    kdf: &RemoteKdf,
    state: &mut RemoteState,
) -> Result<PullReport, RemoteError> {
    let started = Instant::now();
    let result = bootstrap_unrecorded(remote, base, display, key, kdf, state);
    record_transfer(&BOOTSTRAP, started, pulled(&result));
    result
}

fn bootstrap_unrecorded(
    remote: &Remote<'_>,
    base: &Path,
    display: &str,
    key: &[u8; 32],
    kdf: &RemoteKdf,
    state: &mut RemoteState,
) -> Result<PullReport, RemoteError> {
    let layout = &kdf.layout;
    let kdf_bytes = kdf.bytes.as_slice();
    remember_layout(state, Some(layout))?;
    let pending = base.join(PULL_PENDING_FILE);
    let resuming = entry_exists(&pending)?;
    if resuming && let Some(root) = replica::read_root_bytes(base)? {
        // The root was published just before an interruption.
        replica::prepare_bootstrap(base, kdf_bytes)?;
        let pin = V2NamespacePin::capture(base)?;
        let head = replica::finish_bootstrap(base, key, &root, &pin)?;
        finish_pending(base, &pending)?;
        state.clear_incoming()?;
        return Ok(PullReport {
            outcome: PullOutcome::Bootstrapped,
            number: head.number,
            ..PullReport::default()
        });
    }
    let roots = remote.drive.list(&layout.roots, false)?;
    let found = remote_head(remote, layout, roots, key, &[], |message| {
        RemoteError::Auth(format!("{message}; check the passphrase"))
    })?
    .ok_or_else(|| RemoteError::NotFound("the remote holds no generation yet".to_string()))?;
    refuse_forks(&found)?;
    if !resuming {
        if std::fs::read_dir(base)?.next().is_some() {
            return Err(RemoteError::Conflict(format!(
                "{display} is not empty; a first pull needs an empty directory"
            )));
        }
        let mut marker = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&pending)?;
        marker.write_all(
            b"zerotrust-drive bootstrap pull in progress; run `zdrive remote pull` to finish\n",
        )?;
        marker.sync_all()?;
        File::open(base)?.sync_all()?;
    }
    replica::prepare_bootstrap(base, kdf_bytes)?;
    let pin = V2NamespacePin::capture(base)?;
    let index = remote_index(
        remote,
        remote.drive.list(&layout.packs, false)?,
        state,
        false,
    )?;
    let mut fetcher = Fetcher::new(
        remote,
        &index,
        state.incoming_dir(),
        state.damaged_dir(),
        base,
        &pin,
    );
    let all: Vec<usize> = (0..index.packs.len()).collect();
    fetcher.prefetch(&all)?;
    let mut walker = ClosureWalker::new(base, key, &pin);
    let mut ensure =
        |reference: ObjectRef, _bound: u64| fetcher.ensure(reference).map_err(std::io::Error::from);
    let generations = match walker.chain(found.generation, ChainBase::Origin, &mut ensure)? {
        ChainOutcome::Extends(generations) => generations,
        ChainOutcome::Diverged => {
            return Err(RemoteError::Integrity(
                "the remote lineage does not reach its origin".to_string(),
            ));
        }
    };
    check_chain_head(&generations, &found)?;
    for info in &generations {
        walker.generation(info, &mut ensure)?;
    }
    drop(walker);
    replica::sync_installed(base, &pin)?;
    let root = head_bytes(remote, &found)?;
    let head = replica::finish_bootstrap(base, key, &root, &pin)?;
    if head.generation != found.generation {
        return Err(RemoteError::Integrity(
            "the published bootstrap root names another generation".to_string(),
        ));
    }
    let report = PullReport {
        outcome: PullOutcome::Bootstrapped,
        number: head.number,
        previous: None,
        generations: generations.len(),
        objects: fetcher.installed,
        packs: fetcher.downloaded,
        bytes: fetcher.downloaded_bytes,
    };
    finish_pending(base, &pending)?;
    state.clear_incoming()?;
    record_synced(state, display, head.number, &head.generation, &found.record)?;
    Ok(report)
}

fn finish_pending(base: &Path, pending: &Path) -> Result<(), RemoteError> {
    match std::fs::remove_file(pending) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    File::open(base)?.sync_all()?;
    Ok(())
}

/// How the local and remote heads relate.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Relation {
    NoRemoteStore,
    DifferentStore,
    RemoteEmpty,
    Equal,
    LocalAhead,
    RemoteAhead,
    Diverged,
    Forked,
}

#[derive(Debug)]
pub(crate) struct StatusReport {
    pub(crate) local: u64,
    pub(crate) remote: Option<u64>,
    pub(crate) relation: Relation,
    pub(crate) packs: usize,
    pub(crate) pack_bytes: u64,
    pub(crate) damaged: usize,
    pub(crate) queued: usize,
    pub(crate) synced: Option<SyncedHead>,
}

pub(crate) fn status(
    remote: &Remote<'_>,
    local: &LocalStore<'_>,
    state: &mut RemoteState,
) -> Result<StatusReport, RemoteError> {
    let head = local.head()?.state;
    let mut report = StatusReport {
        local: head.number,
        remote: None,
        relation: Relation::NoRemoteStore,
        packs: 0,
        pack_bytes: 0,
        damaged: 0,
        queued: state.outgoing_packs()?.len(),
        synced: state.record.synced.clone(),
    };
    let Some(Snapshot {
        layout,
        roots,
        packs,
    }) = snapshot(remote, state, true)?
    else {
        return Ok(report);
    };
    if !layout.holds_kdf(local.kdf_bytes) {
        report.relation = Relation::DifferentStore;
        return Ok(report);
    }
    let index = remote_index(remote, packs_listing(remote, &layout, packs)?, state, false)?;
    report.packs = index.packs.len();
    report.pack_bytes = index.bytes;
    report.damaged = index.damaged.len();
    let Some(found) = remote_head(
        remote,
        &layout,
        roots,
        local.key,
        &known_records(state),
        RemoteError::Integrity,
    )?
    else {
        report.relation = Relation::RemoteEmpty;
        return Ok(report);
    };
    report.remote = Some(found.number);
    report.relation = relate(local, &head, &found)?;
    Ok(report)
}

fn relate(
    local: &LocalStore<'_>,
    head: &CommitState,
    found: &RemoteHead,
) -> Result<Relation, RemoteError> {
    Ok(if found.rivals > 0 {
        Relation::Forked
    } else if found.generation == head.generation {
        Relation::Equal
    } else if found.number > head.number {
        Relation::RemoteAhead
    } else if replica::object_exists(local.base, local.pin, &found.generation)?
        && matches!(
            ClosureWalker::new(local.base, local.key, local.pin).chain(
                head.generation,
                ChainBase::Ancestor {
                    number: found.number,
                    reference: found.generation,
                },
                &mut |_, _| Ok(()),
            )?,
            ChainOutcome::Extends(_)
        )
    {
        Relation::LocalAhead
    } else {
        Relation::Diverged
    })
}

/// What a periodic check during a mount learned.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Watch {
    pub(crate) relation: Relation,
    pub(crate) remote: Option<u64>,
    pub(crate) local: u64,
}

/// A cheap check for another writer: it lists the folder and `roots/`,
/// never `packs/`, and reads only root records it has not seen.
pub(crate) fn watch(
    remote: &Remote<'_>,
    local: &LocalStore<'_>,
    state: &mut RemoteState,
) -> Result<Watch, RemoteError> {
    let head = local.head()?.state;
    let mut watch = Watch {
        relation: Relation::NoRemoteStore,
        remote: None,
        local: head.number,
    };
    let Some(Snapshot { layout, roots, .. }) = snapshot(remote, state, false)? else {
        return Ok(watch);
    };
    if !layout.holds_kdf(local.kdf_bytes) {
        watch.relation = Relation::DifferentStore;
        return Ok(watch);
    }
    let Some(found) = remote_head(
        remote,
        &layout,
        roots,
        local.key,
        &known_records(state),
        RemoteError::Integrity,
    )?
    else {
        watch.relation = Relation::RemoteEmpty;
        return Ok(watch);
    };
    watch.remote = Some(found.number);
    watch.relation = relate(local, &head, &found)?;
    Ok(watch)
}

#[derive(Debug, Default)]
pub(crate) struct VerifyReport {
    pub(crate) number: Option<u64>,
    pub(crate) generations: usize,
    pub(crate) objects: usize,
    pub(crate) packs: usize,
    pub(crate) bytes: u64,
    /// Every finding; an empty list means the remote verified completely.
    pub(crate) problems: Vec<String>,
}

/// Audits the remote: layout, root records, fresh pack headers and, through
/// the local replica, that every object of the remote head's closure is in
/// an intact pack. `full` downloads every pack and checks each object's
/// digest.
pub(crate) fn verify(
    remote: &Remote<'_>,
    local: &LocalStore<'_>,
    state: &RemoteState,
    full: bool,
) -> Result<VerifyReport, RemoteError> {
    let listing = remote.drive.list(remote.folder_id, false)?;
    let layout = read_layout(remote, &listing)?.ok_or_else(no_remote_store)?;
    if !layout.holds_kdf(local.kdf_bytes) {
        return Err(RemoteError::Diverged(
            "the remote folder holds a store with different key material".to_string(),
        ));
    }
    let mut report = VerifyReport::default();
    for (id, name) in [
        (&layout.packs, PACKS_DIR),
        (&layout.roots, ROOTS_DIR),
        (&layout.leases, LEASES_DIR),
    ] {
        // The listing holds only untrashed children of the remote folder.
        if listing
            .iter()
            .any(|file| &file.id == id && file.is_folder())
        {
            continue;
        }
        match remote.drive.get(id) {
            Ok(folder)
                if folder.is_folder()
                    && !folder.trashed
                    && folder
                        .parents
                        .iter()
                        .any(|parent| parent == remote.folder_id) => {}
            Ok(_) | Err(RemoteError::NotFound(_)) => report
                .problems
                .push(format!("the remote {name} folder is missing or moved")),
            Err(error) => return Err(error),
        }
    }
    // An audit authenticates every record again.
    let known: Vec<KnownRecord> = known_records(state)
        .into_iter()
        .map(|record| KnownRecord {
            authenticated: None,
            ..record
        })
        .collect();
    let found = remote_head(
        remote,
        &layout,
        remote.drive.list(&layout.roots, false)?,
        local.key,
        &known,
        RemoteError::Integrity,
    )?;
    let index = remote_index(
        remote,
        remote.drive.list(&layout.packs, false)?,
        state,
        true,
    )?;
    report.packs = index.packs.len();
    report.bytes = index.bytes;
    for name in &index.damaged {
        report.problems.push(format!("pack {name} is damaged"));
    }
    if let Some(found) = &found {
        report.number = Some(found.number);
        if found.rivals > 0 {
            report.problems.push(format!(
                "{} different generations are published as number {}",
                found.rivals + 1,
                found.number
            ));
        }
        if replica::object_exists(local.base, local.pin, &found.generation)? {
            let mut walker = ClosureWalker::new(local.base, local.key, local.pin);
            let mut missing = 0usize;
            let mut seen = HashSet::new();
            let mut check = |reference: ObjectRef, _bound: u64| -> std::io::Result<()> {
                if seen.insert(reference) && !index.contains(&reference) {
                    missing += 1;
                }
                Ok(())
            };
            let ChainOutcome::Extends(generations) =
                walker.chain(found.generation, ChainBase::Origin, &mut check)?
            else {
                return Err(RemoteError::Integrity(
                    "the remote lineage does not reach its origin".to_string(),
                ));
            };
            check_chain_head(&generations, found)?;
            for info in &generations {
                walker.generation(info, &mut check)?;
            }
            report.generations = generations.len();
            report.objects = seen.len();
            if missing > 0 {
                report.problems.push(format!(
                    "{missing} objects of generation {} are in no intact pack",
                    found.number
                ));
            }
        } else {
            report.problems.push(format!(
                "the local replica lacks remote generation {}; pull to verify its closure",
                found.number
            ));
        }
    }
    if full {
        let incoming = state.incoming_dir();
        let packs: Vec<&RemotePack> = index.packs.iter().collect();
        let results = parallel_map(&packs, DOWNLOAD_PARALLELISM, &|pack| {
            verify_pack(
                remote.drive,
                pack,
                &incoming.join(format!("{}.zpk", pack.file.id)),
            )
        });
        first_fatal(&results)?;
        for result in results.into_iter().flatten() {
            match result {
                Ok(problems) => report.problems.extend(problems),
                Err(error) => report.problems.push(error.to_string()),
            }
        }
    }
    Ok(report)
}

/// Downloads one pack, checks every entry's digest, and deletes the copy.
fn verify_pack(
    drive: &GoogleDrive,
    pack: &RemotePack,
    path: &Path,
) -> Result<Vec<String>, RemoteError> {
    let result = (|| -> Result<Vec<String>, RemoteError> {
        drive.download_to(&pack.file, path)?;
        let file = File::open(path)?;
        let mut problems = Vec::new();
        for entry in &pack.entries {
            let mut bytes = vec![0u8; entry.len as usize];
            file.read_exact_at(&mut bytes, entry.offset)?;
            if replica::ciphertext_digest(&bytes) != *entry.reference.digest() {
                problems.push(format!(
                    "pack {} holds a damaged copy of object {}",
                    pack.file.name,
                    hex(entry.reference.id())
                ));
            }
        }
        Ok(problems)
    })();
    match std::fs::remove_file(path) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    result
}

#[cfg(test)]
#[path = "sync_tests.rs"]
pub(crate) mod tests;
