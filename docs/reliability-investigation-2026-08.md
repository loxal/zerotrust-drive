# ZeroTrust Drive reliability investigation

Investigation date: 2026-08-03

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

## NSFileCoordinator evaluation and implementation status

A small no-presenter, exact-URL `NSFileCoordinator` shim and capability-rooted
storage boundary are implemented as safe primitives, but production storage
operations remain unwired and coordinated mode remains disabled. This does not
qualify iCloud or Proton File Provider storage.
A partial wrapper around only `_root.age`, `_index.age`, or the backing
directory would create a false guarantee because v1 and v2 also access exact
KDF, blob, immutable-object, manifest, staging, migration, evidence, GC,
maintenance-control, read, rename, deletion, and cleanup paths.

The current Unix entrypoint opens and validates the canonical backing directory,
calls `fchdir` on that pinned descriptor, and then deliberately changes the
operational base path to `.`. That protects raw POSIX operations from later
replacement of the user-facing path, but `.` is not a stable Finder/File
Provider presentation URL. Enabling coordination therefore requires retaining
both the canonical absolute presentation URL and the pinned no-follow directory
descriptor. Every exact relative path must be resolved for coordination under
the canonical URL while all raw POSIX operations, file `fsync`, rename or
exchange, and source/destination directory `fsync` checkpoints execute inside
the coordinator accessor. The URL must not replace the existing descriptor and
inode identity proof.

The path-family inventory that must be routed through that boundary is:

- top-level KDF and heads: `_kdf.json`, `._kdf.json.<pid>.<sequence>.tmp`,
  `_index.age`, v1 numeric `*.age` blobs, `_root.age`, `_write.manifest`,
  `_z2-head-<transaction>.ready`, `_z2-manifest-<transaction>.ready`, and the
  accepted legacy dot-prefixed ready names;
- v1 maintenance: `_rekey.lock`, `_rekey.manifest`, `.rekey_staging/`,
  `_migrate.lock`, `_migrate.manifest`, and `.migrate_staging/`;
- v2 immutable state: `_zdrive-v2/objects/*`, `_zdrive-v2/evidence/*`, the
  accepted legacy `.zdrive-v2/` namespace, root/manifest ready files, retained
  evidence, and every read used to authenticate their contents;
- v1-to-v2 migration: `_v2_migrate.plan.age`,
  `_v2_migrate.complete.age`, `.v2_migrate_progress/*.done.age`, receipt-ready
  files, imported objects, and migration evidence moves;
- v2 GC: `_zdrive-v2/gc/<plan-id>/plan.age`, quarantine, restore, purge
  compatibility controls, `quarantine/`, `purge-tombstones/`, and
  `gc-stage-*.pending`; and
- provider-generated siblings, iCloud placeholder/control names, cleanup,
  evidence retention, cross-directory moves, and every parent-directory sync
  that makes a name transition durable.

The implemented Rust/Objective-C boundary now provides:

- canonical presentation URLs paired with pinned no-follow directory
  descriptors and pre/post device-inode identity checks;
- exact one-item read/write/delete/replace access, exact two-item read/write or
  write/write access, and an explicit backend-owned `renameat` move;
- Apple's recommended Moving source plus Replacing destination options and
  balanced `willMoveToURL`/`didMoveToURL` notification even when rename succeeds
  but a later durability step returns an error or panics;
- rejection of Foundation-adjusted URLs, cross-kind or same-path moves,
  symlinked parents, ambiguous relative components, and recursive coordinated
  callbacks (which return `WouldBlock` instead of deadlocking);
- Objective-C exception and Rust panic containment, autorelease pools on every
  exported native call, and structured native error kind/domain/code/message;
  and
- current iCloud ubiquity/materialization, transfer-error, and conflict queries
  plus an explicit start-download primitive.

Local native tests cover exact root, Unicode, read, write, delete, replace,
two-item, move, moved-then-error, moved-then-panic, adjusted-URL, parent
replacement, and error-mapping paths. APFS rejected the attempted invalid UTF-8
fixture with `EILSEQ`; raw non-UTF8 entry behavior therefore has direct Unix
coverage on Linux but no native macOS fixture. A bounded opt-in real-iCloud
audit walks every exact descendant and requires current materialization, no
reported transfer error, and an explicitly false conflict flag. That audit is
ignored by default and was not run in this change set because no disposable
iCloud test root was supplied. It is point-in-time and query-only: it neither
proves Finder's persistent Keep Downloaded policy bit nor upload completion,
and it does not exercise a real provider rename or subprocess death.

Still required before production wiring are a mechanical port of every path
family below, provider/presenter changes during a mounted transaction, and
subprocess-kill tests inside both iCloud Drive and Proton Drive folders in
addition to ordinary local APFS. The existing process-wide one-writer and
persistence lock must be acquired before the per-`StoreRoot` guard so separately
opened roots cannot race.

Public Foundation APIs can request download/materialization and inspect the
current ubiquitous-item download status, download/upload errors, and unresolved
conflict state. They do not provide proof that Finder's Keep Downloaded or Make
Available Offline choice remains persistently pinned across future provider
updates, reboot, sign-out, or storage pressure. Coordination can make access
provider-aware, but it cannot turn a currently downloaded placeholder into a
durable local-retention contract. Production must continue to require the user
to apply and verify the provider's offline-retention control.

Reevaluate the integration when the POSIX storage operations have been routed
through one narrow backend trait or when Apple documents a coordination pattern
that preserves the required atomic exchange semantics. Proton Drive's current
macOS client also uses Apple's File Provider architecture and on-demand
placeholders, so coordination is a storage-backend concern rather than an
iCloud-only exception. Until then, Google Drive Mirror remains the recommended
backing store, iCloud remains a constrained macOS beta, and Proton remains
experimental. The beta status cannot change until the fully wired path passes
real iCloud-backed materialization, conflict, rename/exchange, recovery, and
subprocess-kill tests.

## Proton Drive provider evaluation

Proton's current macOS documentation requires macOS 13 or later, presents Drive
through Finder and Apple File Provider, and exposes cloud-only placeholders.
The complete backing folder must be marked Make Available Offline before mount.
Proton says that state protects local copies from macOS storage reclamation and
causes new children to download, but it must still be retested after client
updates, reboot, sign-out/sign-in, and low-disk-space events.

Proton's own Windows troubleshooting warns that large numbers of small files or
deeply nested folders can synchronize substantially more slowly than one large
file with the same total size. That warning directly matches v2's immutable
chunk, tree, generation, manifest, and evidence layout. No general macOS
conflict-name contract was found. Proton documents elsewhere that conflicts may
rename a file, create a version, or keep a numbered duplicate, so all such
siblings must remain retained conflict evidence.

The official Proton CLI is a transfer and automation client, not a mounted or
continuous sync engine. Proton's public SDK still marks Sync as coming soon and
does not offer a stable production third-party conditional-publication contract.
The reverse-engineered rclone backend is therefore not a supported writable
path. A first-class direct adapter should wait for a supported SDK sync surface
and then prove conditional root publication, event ordering, rate-limit resume,
and conflict retention under deterministic and real-kill testing.

Proton also controls its storage service, sync client, outer end-to-end
encryption, account, and outer recovery mechanism. ZeroTrust Drive preserves a
separate trust domain only because it independently encrypts and authenticates
the inner objects under a passphrase never given to Proton. Proton's encryption
is defense in depth, not a substitute for that boundary. It also creates a
second availability dependency: Proton password reset can leave Drive data
locked without the old password, recovery phrase, or recovery file. Both
recovery domains and an independent backup must be stored separately.

Primary sources and clearly labeled self-selected user reports are recorded in
`cloud-storage-backends-2026-08.md`. Recent reports include both successful
large/small-file libraries and File Provider CPU, stall, placeholder, duplicate,
and reinstall-dependent recovery problems. They justify an empirical many-object
matrix and experimental status, not a generalized data-loss claim.

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
are mandatory procedural preconditions. GC now has dedicated forward and
canonical post-rename real-process-kill matrices; hosted qualification remains
pending.
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
requires both a `SIGKILL` exit status and the exact checkpoint marker. Before
running recovery, a fresh verifier now authenticates the raw crash-visible root
and every reachable object, accepting only the byte-identical old root or the
complete authenticated new generation. Fixed expected checkpoint counts and
critical root/manifest context assertions make removed or silently displaced
durability checkpoints fail the gate. Explicitly selected ignored tests fail
when their opt-in environment is absent, and hosted jobs verify the exact test
exists before invoking its fully qualified name.

Empirical APFS result on 2026-08-02: the complete matrix passed on the local
macOS APFS volume under `/private/tmp`. It killed and freshly verified 46
normal-write checkpoints and 18 recovery checkpoints, for 64 real child-process
deaths. This covers the actual write, file-sync, rename, directory-sync,
cleanup, and recovery sequence exercised by those successful traces.

Empirical ext4 result on 2026-08-02: the same 46 plus 18 matrix passed on a real
1 GiB loopback ext4 filesystem mounted inside the local OrbStack Linux
7.0.11-orbstack VM on aarch64. The source was mounted read-only into an official
Rust bookworm container and Cargo output used a separate volume. This validates
the local ext4 filesystem path independently of the hosted result.

[GitHub PR #1](https://github.com/loxal/zerotrust-drive/pull/1) subsequently
passed the baseline hosted qualification: the unit job completed in 2m19s, the
macOS APFS durability job in 1m17s, and the x86 Linux loopback-ext4 durability
job in 1m23s. Release jobs continue to depend on both hosted APFS and ext4
durability jobs.

Dedicated maintenance matrices now also pass locally on APFS: 22 real
`SIGKILL` points for GC quarantine plus 14 from its canonical post-rename
recovery state, 9 for GC restore plus 8 from its canonical post-rename recovery
state, and 65 for resumable v1-to-v2 migration plus 29 from its authenticated
pending-root state. The migration matrix exposed completed-migration and
late-completion-publication paths that could accept a provider-generated root
sibling during that invocation; the implementation now rechecks around
completion and before every successful return, fails closed, and retains the
evidence. The new dedicated matrices have not yet run in hosted APFS or x86
ext4 jobs.

The harness drives one representative open, write, `fsync`, and release
transaction through direct `ZeroTrustFs` calls. It is not a live
kernel-mounted FUSE test. The maintenance matrices additionally repeat real
deaths from selected canonical post-rename and authenticated pending-root
states. They do not claim a Cartesian matrix of every manually malformed
staging artifact. Deterministic returned-error tests cover those validation
and idempotence transitions.

`SIGKILL` validates process-death behavior while the operating system and
storage device remain powered. It does not emulate torn sectors, volatile disk
caches, sudden power loss, remote cloud reordering, or a second writer. macOS
`File::sync_all` is not claimed to provide `F_FULLFSYNC` semantics. Real
migration and GC process-death testing has passed locally on APFS, while hosted
and ext4 qualification of those dedicated matrices remains pending. Both also
retain deterministic returned-error coverage at every checkpoint.

The durability-focused beta label remains unchanged. Live kernel-mounted FUSE
coverage, hosted APFS and x86 ext4 qualification of the new migration/GC
matrices, complete iCloud and Proton File Provider coordination,
remote-provider ordering, and evidence-retirement policy remain open.

## Final local verification

Package version after this change set: `0.12.0`.

- `cargo fmt --check`: passed.
- `cargo test --no-run --locked`: passed.
- `cargo clippy --all-targets --locked -- -D warnings`: passed.
- `cargo test --locked -- --test-threads=1`: 216 passed, 0 failed, and 4
  explicit provider/filesystem integration gates ignored.
- Native storage tests: 13 passed and the explicit real-iCloud audit ignored.
- Objective-C `-Wall -Wextra -Wpedantic -Werror` syntax check: passed.
- APFS opt-in real-process matrix: 46 normal-write plus 18 recovery deaths,
  passed.
- Local OrbStack loopback-ext4 opt-in matrix: the same 46 plus 18 deaths,
  passed.
- Hosted PR #1 baseline: unit 2m19s, APFS 1m17s, and x86 loopback-ext4
  1m23s, passed.
- Local APFS dedicated maintenance matrices: 22 GC-quarantine plus 14
  quarantine-recovery, 9 GC-restore plus 8 restore-recovery, and 65 v1-to-v2
  migration plus 29 pending-root-recovery deaths, passed.

The baseline now has hosted APFS and x86 evidence. The stronger raw-root
baseline and new maintenance results remain local-only until the updated commit
passes both hosted jobs; no result in this report promotes the beta posture.
