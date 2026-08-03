# ZeroTrust Drive reliability investigation

Investigation date: 2026-08-02

This file records implementation evidence and design decisions that should be
rechecked before changing the v2 beta status. It complements
`v2-crash-consistency.md` and `cloud-storage-backends-2026-08.md`.

## Baseline reviewed

- Source baseline: v2 format introduced by commit `f42d304` at package version
  `0.10.0`.
- Development host: Apple Silicon macOS on APFS.
- Existing v2 invariants: immutable authenticated objects, copy-on-write file
  trees and metadata generations, authenticated normal-write intent, and an
  atomic root exchange/no-replace publication performed last.
- Existing deterministic tests inject returned errors after write, file
  `fsync`, rename, directory `fsync`, cleanup, and recovery checkpoints. Those
  tests exercise protocol state but are not process-death or power-loss tests.

## Findings carried forward

1. V2 bounds file I/O memory independently of complete file size, but the
   original implementation materialized a new immutable chunk/tree/file-root
   path for every small FUSE write. Repeated writes before one metadata flush
   therefore created upload and object-count amplification.
2. Successful transactions retain authenticated roots and manifests. That is
   valuable evidence, but a collector must distinguish authenticated reachable
   state from unknown, incomplete, or provider-conflicted artifacts and must
   fail closed rather than guess.
3. Provider-generated sibling controls are not mergeable. A live mount latches
   read-only after detecting them; offline maintenance must apply the same
   one-writer lock and ambiguity checks.
4. The old-or-new argument depends on the real local filesystem honoring
   same-directory atomic exchange/no-replace rename plus file and directory
   `fsync`. Error injection alone does not validate those operating-system and
   filesystem semantics.

## NSFileCoordinator evaluation

`NSFileCoordinator` is still not implemented. A partial wrapper around only
`_root.age`, `_index.age`, or the backing directory would create a false
guarantee because v1 and v2 also access exact KDF, blob, immutable-object,
manifest, staging, migration, evidence, GC, maintenance-control, read, rename,
deletion, and cleanup paths.

A reasonable native implementation needs a small macOS Objective-C or Swift
shim with an explicit Rust FFI contract that covers:

- coordinated reads of every exact control and immutable-object URL;
- coordinated create-new writes and file synchronization;
- coordinated multi-URL rename/exchange and evidence moves without nested
  coordinator deadlocks;
- File Provider placeholder materialization and cancellation;
- presenter/provider changes arriving during a mounted transaction; and
- subprocess-kill tests on an iCloud Drive folder in addition to local APFS.

Reevaluate the integration when the POSIX storage operations have been routed
through one narrow backend trait or when Apple documents a coordination pattern
that preserves the required atomic exchange semantics. Until then, Google Drive
Mirror remains the recommended backing store and iCloud remains a constrained
macOS beta.

## Current implementation work

The following sections record the bounded dirty-chunk overlay, offline orphan
quarantine framework, and real subprocess-kill tests as implemented and
measured.

### Bounded dirty-chunk overlay

Implemented in `src/fs.rs` with these hard bounds and invariants:

- at most sixteen dirty 4 MiB plaintext slots (64 MiB) across the mount;
- at most 256 truncate-only or otherwise dirty inode records;
- each incoming v2 write is limited to one negotiated 4 MiB FUSE request and
  can therefore stage at most two unaligned chunk slots;
- every missing base chunk touched by one request is authenticated and fully
  staged before any bytes or logical size are changed;
- pressure flushes the complete prior overlay through the existing staged
  manifest and root-last generation transaction before accepting another
  chunk; and
- the overlay is cleared only after the authenticated root commit succeeds and
  the complete prospective index becomes the live in-memory state.

Reads merge immutable base spans, sparse zeroes, and dirty slots into the
existing bounded response buffer. Shrink followed by growth retains a minimum
visible-base boundary, so bytes discarded by truncate cannot reappear from an
old immutable chunk. Unlink and rename-overwrite reject a retained dirty inode
rather than discarding the only acknowledged copy after a failed flush.

Focused tests on the APFS development host cover repeated one-byte coalescing,
an unaligned two-chunk request, synchronous pressure flush at the seventeenth
slot, rejection of a new write when that pressure flush fails, shrink/re-extend
zeroing across fsync and reopen, immutable-object preservation, and read access
to retained dirty bytes after provider-conflict detection. A boundary test
also writes and reopens the last representable sparse byte below `u64::MAX`.
An exhaustive
returned-error test exercises every overlay-flush durability checkpoint and
accepts only the old or direct-child new root while retaining recognized
provider-conflict evidence. The pressure test materializes 64 MiB and passed
deterministically.

This bounds the shared dirty cache, not total process memory. Concurrent FUSE
responses, AEAD buffers, tree nodes, the metadata index, and the operating
system page cache add bounded per-operation overhead. A strict process-wide
memory ceiling would additionally require request admission control.

### Alias-safe local one-writer lock

The original outside-store advisory lock keyed only a canonical path string.
Two Linux bind-mount paths can canonicalize to different strings while naming
the same backing directory inode, allowing both paths to acquire different
locks.

The primary Unix lock now keys the pinned backing directory's `st_dev` and
`st_ino`, so textual aliases contend on the same outside-store lock. The client
also acquires the previous exact path-hash lock to contend with an older binary
using that same path and verifies by filesystem identity that every candidate
lock directory is outside the encrypted backing directory. After canonical
absolute paths are resolved, `fchdir` anchors all backing I/O to the retained
`O_DIRECTORY|O_NOFOLLOW` descriptor; later replacement of the user-facing path
cannot redirect a live mount, migration, rekey, or GC command to another inode.
The original absolute path is revalidated before and after anchoring and is
then retained for diagnostics and entrypoint identity revalidation. Unix fails closed when the filesystem
cannot provide a stable nonzero directory inode.

Nine focused tests cover identity derivation across textual aliases, actual
lock contention and reacquisition, deterministic fallback naming, legacy-lock
contention, outside-store lock placement, backing-directory replacement, and a
subprocess proof that anchored relative I/O continues to the pinned inode after
the absolute path is replaced.
An old binary opened through a different bind-mount alias cannot know the new
identity lock name, so mixed-version concurrent use remains prohibited.

### Startup and immutable-namespace hardening

A v2 root or recovery intent without `_kdf.json` now fails in `main` before GC
or legacy rekey/migration cleanup and again in the filesystem constructor. Main
also repeats the check immediately before and after each legacy recovery call.
Brand-new KDF publication rechecks for a provider-arriving v1 index, v2 root,
or write manifest immediately before hard-link publication, before its
create-new fallback, and immediately after publication. A conflict preserves
the provider artifact, canonical KDF if already published, and the durable KDF
temp. POSIX cannot atomically inspect those independent names and create
`_kdf.json`; an arrival inside the remaining syscall interval can still leave
an incompatible KDF beside retained evidence. Likewise, a provider arrival
inside a legacy cleanup call cannot be excluded by surrounding checks.

V2 now retains open no-follow descriptors and `st_dev`/`st_ino` identities for
the selected immutable namespace plus its `objects` and `evidence`
directories. Mounted dirty-COW materialization, migration import and
validation, generation creation, and recovery use the retained `objects`
descriptor through `openat`; root loading, recovery, and migration resolve the
authenticated generation and index through that same descriptor. After
create-new object publication, the client reopens the exact name and verifies
inode, single-link status, length, and bytes. Normal-write and migration
evidence inventories stream through the retained `evidence` descriptor with a
250,000-entry ceiling. Evidence moves use descriptor-relative atomic
no-replace rename, while the durable manifest anchor uses an atomic hard link;
the exact retained bytes and directory identities are revalidated after each
operation. Destination evidence and source directories are synchronized in
that order. Commit, recovery, and migration revalidate all canonical directory
identities around intent, root, manifest, and evidence publication. Existing
recovery state is pinned before both the evidence audit and atomic-exchange
probe so neither can follow or recreate a provider-replaced child directory.
Deterministic tests replace namespace, object, and evidence directories before
normal/recovery root publication, root loading, evidence inventory, evidence
rename, durable-link publication, manifest-last completion, and final object
name verification. They also inject target collisions and missing evidence;
all fail closed without overwriting the displaced or provider copy.

Completed update manifests are not accepted merely because their own bytes are
authentic. Audit requires the transaction's exact primary displaced-root
evidence, decodes that root through the retained objects descriptor, and
authenticates its generation, index, and complete file graph. It then walks the
authenticated parent chain to the declared origin, requiring generation numbers
to decrement exactly, lineage and origin references to remain constant, and
every historical index and file graph to remain complete. Already validated
generation objects are deduplicated under the same 250,000-entry safety bound as
evidence inventory. Every retained manifest and pre-publication manifest-ready
artifact also has its authenticated new-generation reference, number, parent,
origin, lineage, index, and complete file graph validated through the retained
objects descriptor before deduplication. This covers unpublished or conflicting
branches as well as completed old/new transactions. It prevents a
provider-replaced objects directory containing only the current and immediate
old heads from silently passing while older or branch lineage evidence is
unusable. The cost is additional startup work
proportional to unique retained update generations and their file graphs; it
remains bounded per object/file rather than by total file size, but long
histories can make mount substantially slower.

The same proof now runs for a pending canonical `_write.manifest` before recovery
mutates the root, staging names, or evidence. Recovery validates the manifest's
complete new lineage plus the exact displaced old root and its complete lineage,
whether the old root is still canonical, still occupies the exchanged staging
name, or has already reached the pinned evidence directory. This closes the
one-remount interval in which manifest-last completion could previously make
incomplete old evidence look like a completed transaction until the following
mount. A deterministic recovery checkpoint follows this validation and is part
of both real-process kill matrices.

These checks do not turn POSIX into a provider transaction. The child-directory
identity check and top-level `_root.age` exchange remain separate syscalls. An
ABA replacement or a provider change in the final check-to-exchange interval
can be detected only after root visibility. The formal old-or-new result is a
local process-crash proof under one writer and a stable selected namespace
during publication, not a proof against an adversarial concurrently mutating
sync client. This residual is a principal reason the beta status is unchanged
and a central input to any future `NSFileCoordinator` or generation-bound
namespace design.

The full reachability scrub still runs at writable startup, not before every
commit. A provider that removes or mutates an individual referenced object in
place after startup without replacing the pinned directories can make a later
metadata generation inherit that failure. A complete per-commit proof would
re-read all live data and is not implemented; this remains a beta limitation
and a reason to stop provider activity during maintenance.

### Evidence-aware offline orphan quarantine

Implemented in `src/v2_gc.rs` as an explicit offline protocol:

- preview authenticates current and historical generations, completed
  migration roots/evidence, recognized conflict evidence, and the complete
  immutable-object inventory without modifying the encrypted backing store or
  persisting a plan;
- plans bind portable authenticated store state, selected namespace, exact KDF
  and control anchors, object names, lengths, and ciphertext digests. New plans
  omit a host-local absolute path; legacy path-bearing plans remain readable
  after an exact store relocation;
- quarantine uses the union of planned source and quarantine names as durable
  progress, verifies exact bytes, uses no-replace cross-directory rename, and
  synchronizes the destination file and destination directory before the
  source directory;
- restore is additive until purge intent exists, including after a late root
  change or a semantically equivalent KDF reserialization that still derives
  the key authenticating the plan, and refuses both-present or both-missing
  ambiguity;
- new physical purge is disabled. A new `--gc-v2-purge` run authenticates and
  revalidates the plan but returns read-only before intent, tombstone creation,
  checkpoints, or any name/byte change. Only an authenticated compatibility
  state in which every candidate is already an exact zero tombstone can finish
  its completion record; full tombstones and quarantined bytes are preserved;
  and
- the operation namespace is exact and fail-closed. Unknown names, nonregular
  files, hard-linked immutable objects or controls, provider siblings, pending
  maintenance, and malformed evidence block mutation. One shared 250,000-entry
  budget covers immutable objects, namespace entries, ready controls,
  normal-write and migration evidence, migration receipts, GC operations,
  controls, quarantines, and compatibility tombstones. Plan ciphertext is
  capped at 64 MiB.

Plans and every marker are written to fresh
`gc-stage-<kind>-<32-lowercase-hex>.pending` files, checkpointed after write,
file-synchronized, atomically renamed no-replace to the final name, and then
directory-synchronized. A final-name race preserves and synchronizes the losing
stage before authenticating the winner. Recognized incomplete stages are never
selected as state, overwritten, or deleted. Subsequent GC scans inventory and
fingerprint stages from completed operations as anchors in the next plan. This
avoids a torn deterministic final control name from wedging new operations, at
the cost of append-only evidence that can eventually reach the namespace cap.

The first adversarial pass found eight issues in the initial implementation:
wrong cross-directory synchronization order, no restore after a late root race,
incomplete orphan-DAG resume, incomplete namespace inventory, a tautological
KDF resume check, non-durable visible purge intent, no per-unlink re-mark, and
path-based verify-then-mutate races. All eight were fixed with regression tests
or narrowed by pinned directory descriptors. A second pass found two further
P1 issues: direct writes to deterministic final control names and absolute host
path binding in plans. Both were fixed by the staged publication and portable
plan designs above. A third pass found a provider replacement race between
final verification and pathname unlink, path-text writer locks that aliases
could bypass, and evidence namespaces that could be enumerated outside a
shared limit. A first tombstone redesign removed pathname unlink but still
allowed the exact opened inode to be renamed, changed, or hard-linked before
descriptor truncation. The final adversarial pass rejected that design too.
Production contains no destructive reclaim primitive: new purge fails
read-only. The other findings drove anchored filesystem-identity locking and
the operation-wide scan budget described above.

A subsequent cross-component audit found that the mount snapshot was checked
before, but not carried through, normal root publication; recovery and
v1-to-v2 migration had equivalent namespace gaps. It also found the
root/intent-without-KDF check occurred after legacy cleanup, an object-name
replacement was not verified after `openat`, namespace errors could be mistaken
for random-ID collisions and loop, and a pending-recovery exchange probe could
recreate missing layout. Those findings produced the pinned-descriptor and KDF
changes above. The same audit demonstrated the remaining uncloseable POSIX
boundary: no pre/post identity check can be atomic with a separate root
exchange. Documentation and tests now distinguish that provider-concurrency
limitation from the local process-crash proof rather than claiming otherwise.

Focused verification passed 25 GC tests, including exhaustive returned-error
resume loops across quarantine, restore, and compatibility purge recovery; a
byte-for-byte proof that new purge is read-only; partial orphan graphs;
partial and malformed stages; valid and invalid final-name races; active,
completed, and legacy-plan relocation; KDF/root drift; namespace conflicts;
deep generation history; size/count bounds; and proof that disabled fresh purge
returns before a deliberately failing complete live-store scan. Compatibility
completion now performs two complete bounded validations plus linear
per-candidate exact checks rather than rescanning the complete store for every
candidate.

Residual limits remain explicit. Portable APIs do not supply a provider
transaction, so quarantine can still be interrupted by a provider namespace
change and must stop fail closed. Physical space reclamation is unavailable,
not conditionally unsafe. Paused sync, one writer, and an independent snapshot
are mandatory procedural preconditions. GC does not have its own
real-process-kill matrix.
An already-torn deterministic final control produced by the unreleased
pre-staging implementation remains conflict evidence and is not auto-replaced.

### APFS and ext4 subprocess-kill testing

An opt-in Unix test harness now records the exact event and context of every
checkpoint in a successful normal commit and recovery, starts a fresh copy of
the Rust test executable for each checkpoint, and sends that child
`SIGKILL` immediately after the selected checkpoint. A separate fresh process
then runs recovery and accepts only the complete old generation or complete new
generation. It installs a recognized `_root (conflicted copy).age` sibling,
proves recovery cannot mutate the root while that evidence exists, and checks
the sibling byte-for-byte. The harness then explicitly removes and
directory-synchronizes its own fixture before the separate old-or-new verifier.
Production recovery never removes that evidence. Child hangs have a 30-second
watchdog, and the parent
requires both a `SIGKILL` exit status and the exact checkpoint marker.

Empirical APFS result on 2026-08-02: the complete matrix passed on the local
macOS APFS volume under `/private/tmp`. It killed and freshly verified 46
normal-write checkpoints and 18 recovery checkpoints, for 64 real child-process
deaths. This covers the actual write, file-sync, rename, directory-sync,
cleanup, and recovery sequence exercised by those successful traces.

Empirical ext4 result on 2026-08-02: the same 46 plus 17 matrix passed on a real
1 GiB loopback ext4 filesystem mounted inside the local OrbStack Linux
7.0.11-orbstack VM on aarch64. The source was mounted read-only into an official
Rust bookworm container and Cargo output used a separate volume. This validates
the ext4 filesystem path but is not the still-unrun hosted x86 GitHub Actions
gate. Release jobs depend on both hosted APFS and ext4 durability jobs.

The harness drives one representative open, write, `fsync`, and release
transaction through direct `ZeroTrustFs` calls. It is not a live
kernel-mounted FUSE test. Each recovery case receives one process death from
the chosen baseline state; it does not repeatedly kill recovery from every
already-partial state. Deterministic returned-error tests cover those
idempotence transitions.

`SIGKILL` validates process-death behavior while the operating system and
storage device remain powered. It does not emulate torn sectors, volatile disk
caches, sudden power loss, remote cloud reordering, or a second writer. macOS
`File::sync_all` is not claimed to provide `F_FULLFSYNC` semantics. Real
migration and GC process-death testing remains deferred; both have
deterministic returned-error coverage at every checkpoint.

The durability-focused beta label remains unchanged despite both local
filesystem results. Hosted x86 qualification, live FUSE coverage, migration/GC
real-kill matrices, complete iCloud coordination, remote-provider ordering,
and evidence-retirement policy remain open.

## Final local verification

Package version after this change set: `0.11.0`.

- `cargo fmt --check`: passed.
- `cargo test --no-run --locked`: passed.
- `cargo clippy --all-targets --locked -- -D warnings`: passed.
- `cargo test --locked -- --test-threads=1`: 194 passed, 0 failed, and the
  opt-in filesystem gate was the only ignored test.
- APFS opt-in real-process matrix: 46 normal-write plus 18 recovery deaths,
  passed.
- Local OrbStack loopback-ext4 opt-in matrix: the same 46 plus 18 deaths,
  passed.

These results are local evidence, not a hosted x86 result and not a release of
the beta posture.
