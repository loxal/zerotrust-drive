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
storage boundary are implemented as safe primitives. The direct backend now
owns one narrow production family: pinned v2 immutable-object publication.
Every other production storage operation remains unwired and coordinated mode
remains disabled. This partial direct-only port does not qualify iCloud or
Proton File Provider storage.
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

### First direct StoreRoot path family

The first bounded production port deliberately covers only creation and
verification of immutable object files. Its exact relative target is
`_zdrive-v2/objects/<32-lowercase-hex>.z2`, or
`.zdrive-v2/objects/<32-lowercase-hex>.z2` when the existing legacy namespace
is selected. The same primitive publishes bounded data chunks, COW tree nodes,
file roots, index objects, and generation objects. Explicit migration also
reuses this immutable-object primitive; no migration control, receipt, ready,
or evidence path moved in this port.

`V2NamespacePin` still owns the original no-follow `objects` descriptor and
its device/inode identity. It now also opens a direct `StoreRoot` at the
backing-store root and resolves the selected namespace and `objects` parent
with descriptor-relative no-follow directory opens. Immediately before
mutation the StoreRoot accessor descriptor and the transaction pin must
identify the same objects directory. The exact access inventory for one object
follows.

The complete read-only path set used to reach and validate that target is the
canonical backing-store root; both namespace candidates `_zdrive-v2` and
`.zdrive-v2`; and the selected namespace, its `objects` directory, and its
`evidence` directory. Namespace selection and pin verification use `lstat`-
equivalent no-follow metadata checks for those names. StoreRoot uses retained
descriptor `fstat`, no-follow `O_DIRECTORY` opens of the visible root, and
component-by-component `openat` of the selected namespace and `objects`
parent. The `evidence` name is identity-checked by `V2NamespacePin`, but it is
not mutated by this family. No other top-level control name is resolved.

The mutating syscall and durability sequence is:

1. `openat(objects_fd, name, O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC,
   0600)`; `EEXIST` selects no object and causes the random-ID caller to retry.
2. `fstat` requires a regular single-link new inode, followed by bounded
   `write` calls and `Write: publish immutable v2 object`.
3. `fsync(object_fd)` followed by
   `FileSync: publish immutable v2 object`, then close.
4. `fsync(objects_fd)` followed by
   `DirectorySync: publish immutable v2 object`.
5. `openat(objects_fd, name, O_RDONLY|O_NOFOLLOW|O_CLOEXEC)`, `fstat`, and
   bounded reads verify the exact inode, link count, length, and bytes before
   the reference can enter a COW tree or generation.

StoreRoot and `V2NamespacePin` additionally perform read-only pre/post
device-inode checks of the retained and visible object-directory path. They
add no durability checkpoint and do not re-resolve the object through a
process-relative pathname. No root, manifest, ready, evidence, GC, recovery,
or cleanup path and no rename/exchange operation changed. The three object
checkpoints therefore remain in the same order and retain the same event and
context strings; all immutable dependencies still become durable before the
staged manifest and the root-last exchange.

A focused test records the direct StoreRoot URL for both current and legacy
namespaces, requires exactly the generated object path with write intent, and
compares the complete checkpoint vector with the pre-port direct helper. Both
vectors are exactly Write, FileSync, DirectorySync with context
`publish immutable v2 object`. The exhaustive returned-error commit test and
the locally rerun real APFS process-kill gate also pass unchanged at 46 normal-write plus 18
recovery checkpoints. Coordinated mode must remain disabled until the rest of
the inventory above is ported and passes the real iCloud gates.

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
coverage on Linux but no native macOS fixture.

An independent `NSFilePresenter` probe now registers on the exact move source,
uses a private serial operation queue, and bounds notification observation with
a 10-second semaphore deadline. After unregistering, a separate queued barrier
gets the same deadline so a wedged callback cannot make queue draining
unbounded. The existing move shim invokes a Rust accessor that rejects adjusted
source or destination bytes and performs `renameat` through a retained
directory descriptor. The probe requires writer relinquishment, then exactly
one `presentedItemDidMoveToURL:` callback and the expected destination after
resolving macOS's equivalent `/var` and `/private/var` presentation aliases.
Callback bodies catch and record Objective-C exceptions; presenter removal,
queue handling, and final inspection are separately guarded so an exception is
reported instead of crossing the Rust FFI boundary. Foundation's synchronous
coordination and presenter-removal calls expose no cancellation deadline, so
the two semaphore waits are bounded but the complete probe is not advertised
as a hard wall-clock operation. This proves the local native move notification
contract; it does not prove that an iCloud provider process will always present
every remote change.

Three new retained-fixture real-iCloud gates share
`ZDRIVE_RUN_ICLOUD_TESTS=1` but use two separately selected roots. The Keep
Downloaded and SIGKILL gates require an
absolute canonical `ZDRIVE_ICLOUD_TEST_ROOT` plus
`ZDRIVE_ICLOUD_TEST_CONFIRM=disposable-keep-downloaded-folder`. Before creating
anything, they require the exact selected folder to be ubiquitous, settled,
conflict-free, recursively downloaded, and explicitly
`isKeepDownloaded=1` according to `/usr/bin/fileproviderctl evaluate`. The
materialization-transition gate instead requires an absolute canonical
`ZDRIVE_ICLOUD_MATERIALIZATION_ROOT`,
`ZDRIVE_ICLOUD_MATERIALIZATION_CONFIRM=disposable-evictable-folder`, and
`isKeepDownloaded=0`. This separation is necessary because a correct Keep
Downloaded policy can reject eviction or immediately rematerialize the item.
The harness never toggles Finder policy programmatically.

A fourth, older ignored storage audit,
`storage::tests::real_icloud_tree_is_currently_materialized_without_conflicts`,
is query-only and uses `ZDRIVE_ICLOUD_TEST_ROOT`, but scans that selected root
itself with pathname enumeration instead of allocating an isolated retained
child. It is retained as narrow `StoreRoot` ubiquity-query coverage and makes no
Keep Downloaded claim. The exact commands in the README intentionally run the
three retained-fixture gates, not this root-wide audit; a broad
`cargo test --ignored` with the iCloud environment would run all four.

Foundation does not expose Finder's persistent Keep Downloaded bit, so
`fileproviderctl` is the narrowest observable policy probe; its parser fails
closed if output is missing or ambiguous and retains at most 1 MiB from each
subprocess stream while continuing to drain both pipes. Each of the three
retained-fixture gates creates one random child with `mkdirat`, pins parent and child identities, writes a bounded
random owner marker with `openat`, and never traverses siblings. Descendant
enumeration and byte proofs stay below the retained child and use no-follow
descriptor-rooted traversal. File Provider/Foundation status requests still
use the exact presentation pathname after identity checks because those APIs
do not accept directory descriptors. A failed gate leaves the complete child
for inspection.

The Keep Downloaded gate uploads a nested byte-exact file and proves inherited
policy, current/uploaded status, and an unchanged descriptor-rooted inventory.
The separate evictable-folder gate asks Foundation to evict only the fixture's
local copy, requires an observed `NotDownloaded` state, requests a new download,
and verifies freshly reopened exact bytes after the item returns to `Current`.
Both inventories contain exact directory names/types plus regular-file sizes,
link counts, and streaming Blake2s byte digests. Per-file, total-byte,
entry-count, and depth limits are hard bounds. Deadlines are checked between
directory entries and file-read blocks; an individual filesystem or Foundation
call is not preemptible, so the configured timeout is cooperative rather than a
strict wall-clock bound.

The real-iCloud SIGKILL gate first waits for its non-hidden random child and
bounded owner marker to inherit the selected folder's policy. It then runs the
complete 46 normal-write plus 18 recovery death matrix, captures the exact tree
inventory, waits until every descendant is current, uploaded, not transferring,
free of reported conflicts or provider errors, recursively downloaded, and
still inherits the effective Keep Downloaded policy, and requires the inventory
to remain byte-for-byte equivalent. It retains both successful checkpoint
traces. For each death state it also retains a separate conflict-bearing copy,
proves that the recognized sibling blocks recovery without changing the root,
and recovers only the clean copy. Finally it re-authenticates the baseline,
both traces, retained pending-recovery state, every clean death root, every
conflict-bearing death root, and every complete reachable object graph before
comparing the inventory again.

Crash-fixture clones use the retained suite descriptor, reject symlinks and
special files, and compare bounded pre-copy and post-copy source inventories
plus the destination's exact relative names, types, sizes, and Blake2s byte
digests. This detects mutations visible at those snapshot boundaries or copied
into the destination, and preserves a partial destination as evidence on error. The crash subprocesses, synthetic
conflict creation, File Provider status calls, and final ZeroTrust
authentication still receive presentation pathnames. Retained parent/child
identity and final descriptor-rooted inventories detect persistent replacement,
but cannot exclude a provider ABA replacement and restoration. The real-iCloud
gate therefore assumes a stable selected child namespace during execution; it
does not yet provide a capability-rooted execution boundary.

No retained-fixture gate performs automatic recursive cleanup. Both failed and
successful children remain visible for operator inspection and manual removal from the
explicitly disposable selected parent. This avoids a destructive path-based
ABA window and guarantees that an unexpected provider artifact is not silently
discarded by the harness. Synthetic recognized conflict siblings remain in all
64 dedicated conflict copies through the File Provider settlement and exact
inventory comparison. A passing gate can therefore prove point-in-time upload
status and retention for those synthetic names. Provider-generated
`NSFileVersion` conflict metadata, cross-Mac arrival order, and remote atomic
visibility remain separate open gates. None of the four iCloud tests was run in
this change set because neither required user-selected folder was supplied.
Even when the three new retained-fixture gates pass, they prove local APFS/File
Provider process-death behavior, one explicit
evict/download transition, and point-in-time upload completion, not provider
upload ordering or atomic visibility on another Mac.

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

- at most sixteen dirty 4 MiB plaintext slots (64 MiB of logical retained
  bytes and requested steady-state capacities) across the mount; new, sparse,
  and short tails begin with a 4 KiB reservation and grow geometrically only as
  a write reaches farther into that chunk, while a write into an existing full
  base chunk necessarily retains that authenticated complete chunk;
- at most 256 truncate-only or otherwise dirty inode records;
- each incoming v2 write is limited to one negotiated 4 MiB FUSE request and
  can therefore stage at most two unaligned chunk slots;
- every missing base chunk touched by one request is authenticated, and all
  affected vectors are reserved through the highest written byte, before any
  acknowledged bytes or logical size are changed;
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

Focused tests on the APFS development host cover one-byte compact allocation,
capped geometric growth under sequential byte appends, growth to a high offset
inside one chunk, an unaligned two-chunk request with a compact second tail,
synchronous pressure flush at the seventeenth slot, rejection of a new write
when that pressure flush fails, shrink/re-extend zeroing across fsync and
reopen, immutable-object preservation, and read access to retained dirty bytes
after provider-conflict detection. The grow-then-shrink test also covers a
compact vector shorter than the new logical tail; truncation drops only bytes
that exist and the overlay read path zero-fills the rest instead of indexing
past the vector or revealing discarded base bytes. A boundary test also writes
and reopens the last representable sparse byte below `u64::MAX`.
An exhaustive
returned-error test exercises every overlay-flush durability checkpoint and
accepts only the old or direct-child new root while retaining recognized
provider-conflict evidence. Compact allocation does not alter the immutable
object graph, root-last transaction, checkpoint order, migration, GC, or the
sixteen-slot pressure decision.

This bounds logical dirty bytes and every requested steady-state vector
capacity, not exact allocator consumption or total process memory. An allocator
may over-allocate, and growing one vector can transiently retain its old and new
allocations. Concurrent FUSE responses, AEAD buffers, tree nodes, the metadata
index, and the operating system page cache add bounded per-operation overhead.
A strict process-wide memory ceiling would additionally require request
admission control and allocator-aware accounting.

### Small-file measurement and format decision

The small-file baseline was measured from merged `main` commit `08b96f8`
(`0.12.0`) on Apple Silicon macOS/APFS. The workload uses `ZeroTrustFs::new_v2`,
stops the debounce worker so capacity pressure is deterministic, counts
immutable objects and backing regular files, sums their recursive `st_size`
values, and records every `DurabilityEvent`. The initial baseline was captured
in an isolated clone.
The same full workloads plus an explicit close-per-file case are retained as four ignored
`fs::tests::measure_v2_*` tests, guarded by
`ZDRIVE_RUN_SMALL_FILE_MEASUREMENTS=1`. The exact two-phase Fish-shell recipe
below times the already-built test executable rather than Cargo or a compiler
child:

```fish
cargo test --no-run --locked --message-format=json > target/zdrive-test-artifacts.json
set test_binary (jq -r 'select(.target.name == "zerotrust-drive" and .profile.test == true and .executable != null) | .executable' target/zdrive-test-artifacts.json | tail -n 1)
test -x "$test_binary"
set tests \
    fs::tests::measure_v2_batch_of_1000_empty_files \
    fs::tests::measure_v2_batch_of_1000_one_byte_files \
    fs::tests::measure_v2_one_byte_file_with_100_fsyncs \
    fs::tests::measure_v2_100_one_byte_files_with_last_close
for test_name in $tests
    env ZDRIVE_RUN_SMALL_FILE_MEASUREMENTS=1 /usr/bin/time -l "$test_binary" --exact "$test_name" --ignored --nocapture
end
```

The tests never assert timing. These are local implementation measurements,
not iCloud sync-time claims.

- One batch of 1,000 empty files added 2 immutable objects, 5 backing regular
  files, and 200,195 aggregate backing regular-file `st_size` bytes. Its one transaction executed 27
  checkpoints: 5 writes, 5 file syncs, 4 renames, 11 directory syncs, and 2
  cleanup steps. It completed in 0.46 seconds with 31,178,752 bytes maximum
  resident set size.
- One best-case batch of 1,000 nonzero one-byte files kept all 1,000 handles
  open, flushed once, then released the clean handles. It added 3,126 immutable objects,
  3,315 backing regular files, and 10,783,170 aggregate backing regular-file
  `st_size` bytes. The sixteen-slot
  policy caused 63 pressure/final generations: 3 objects per file plus 126
  index/generation objects. It executed 10,701 checkpoints (3,315 writes,
  3,315 file syncs, 252 renames, 3,693 directory syncs, and 126 cleanup steps),
  completed in 33.75 seconds, and reached 97,894,400 bytes maximum resident set
  size. Sixteen useful payload bytes occupied 67,108,864 bytes of dirty-vector
  length and capacity before the change.
- One one-byte file modified and fsynced 100 times added 500 immutable objects,
  800 backing regular files, and 730,159 aggregate backing regular-file
  `st_size` bytes. It executed 3,600
  checkpoints (800 writes, 800 file syncs, 400 renames, 1,400 directory syncs,
  and 200 cleanup steps), completed in 10.85 seconds, and retained a 4 MiB dirty
  vector for each one-byte modification.
- The existing seventeen-slot sparse pressure test
  `fs::tests::v2_overlay_pressure_flushes_before_accepting_another_chunk` took 17.29 seconds and
  reached 105,971,712 bytes maximum RSS before compact tails. With compact
  tails it took 0.80 seconds and reached 30,752,768 bytes maximum RSS. Timing is
  reported as evidence only and is not asserted by tests. The committed tests
  instead assert structural length, capacity, sparse-zero, pressure, and crash
  invariants.

The retained workloads were rerun against the combined `0.13.0` working tree,
including the direct StoreRoot object-publication port. The already-built test
executable, rather than Cargo and a possible compiler child, was wrapped with
`/usr/bin/time -l`:

- 1,000 empty files again added exactly 2 objects and ran the same 27
  checkpoints; one sample added 200,203 aggregate backing regular-file
  `st_size` bytes, completed in 0.46
  seconds, and reached 31,539,200 bytes maximum RSS.
- The best-case 1,000 one-byte batch again added exactly 3,126 objects and ran
  the same 10,701 checkpoints; the latest sample added 10,782,191 aggregate
  backing regular-file `st_size` bytes,
  completed in 25.28 seconds, and reached 31,752,192 bytes maximum RSS.
  Compared with the recorded pre-change run, that is about 25 percent less wall
  time and 68 percent less maximum RSS on this host.
- 100 one-byte write-plus-fsync cycles again added exactly 500 objects and ran
  the same 3,600 checkpoints; one sample added 730,310 aggregate backing
  regular-file `st_size` bytes, completed
  in 8.58 seconds, and reached 31,522,816 bytes maximum RSS.
- 100 ordinary create/write/last-close operations also added exactly 500
  objects and ran exactly 3,600 checkpoints (800 writes, 800 file syncs, 400
  renames, 1,400 directory syncs, and 200 cleanup steps). The latest sample
  added 2,216,470 aggregate backing regular-file `st_size` bytes, completed in
  8.30 seconds, and reached
  31,866,880 bytes maximum RSS. It quantifies the important limitation hidden
  by the best-case batch: a last close is a durability boundary, so compact
  tails reduce RAM but do not reduce root-last generation or upload
  amplification for close-heavy small-file workloads.

Object, backing-regular-file, and checkpoint counts were repeatable observations
in these manual ignored workloads; the measurement tests print rather than
assert them. Aggregate backing regular-file `st_size` totals are neither
plaintext size, allocated blocks, nor measured upload traffic, and are also
observations rather than assertions: random object IDs and KDF
salt bytes are represented as JSON integer arrays, so their decimal width makes
otherwise equivalent stores differ slightly in ciphertext size. Timing and RSS
remain host/load observations. The committed tests print all structural counts
so a later review can distinguish implementation drift from that expected
random-size variation.

The implemented improvement changes no disk schema. A new one-byte tail now
has a small geometric reservation instead of a complete 4 MiB zero-filled
vector. A sparse dirty chunk is materialized only through its highest written
byte; absent authenticated chunk bytes already mean zero, and the existing v2
validator accepts nonempty short chunks below the per-position maximum. The
sixteen-slot rule still permits exactly 64 MiB of logical dirty chunk content
in the worst case. Reservation of all affected vectors remains fallible and
completes before acknowledged bytes or file size change, preserving atomic
acceptance of an unaligned two-chunk write.

Two disk-format optimizations were evaluated and deliberately deferred:

- Authenticated inline bytes in `FileRoot` would reduce the measured 1,000-file
  workload from about 3,126 to 1,126 immutable objects, roughly a 64 percent
  reduction. It would require an inline/tree discriminant, canonical threshold
  and sparse rules, inline-to-tree and tree-to-inline write/truncate handling,
  reachable-file validation, live and orphan GC graph parsing, migration
  receipt validation, corruption tests, and new deterministic and real-kill
  traces.
- A direct one-chunk `Data` reference in `FileRoot` would retain the current
  data-object AEAD and reduce the workload to about 2,126 objects, roughly a 32
  percent reduction. It is simpler for GC than embedded bytes but still needs
  every parser, validator, transition, migration, and crash-test touchpoint
  above.

Neither change is safely additive for existing v2 readers today:
`FileRoot` uses `serde(deny_unknown_fields)`, and its validator requires the
current height/tree shape. An added JSON field or sentinel height would make an
older binary reject a root published by a newer writer. Shipping either design
under the unchanged v2 capability would therefore create a downgrade and
mixed-version reliability hazard. A future format change needs an explicit
fail-fast store capability/subformat contract, complete GC and migration
support, and measured benefit in the real iCloud many-small-object gate. Until
then, compact in-memory tails earn their large measured gain without changing
the old-or-new proof or adding an object representation.

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
canonical post-rename real-process-kill matrices. Hosted qualification was
pending at that audit stage and subsequently passed in hosted APFS/x86_64
loopback-ext4 CI.
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

Dedicated maintenance matrices now also pass locally on APFS and in hosted
APFS/x86_64 loopback ext4: 22 real
`SIGKILL` points for GC quarantine plus 14 from its canonical post-rename
recovery state, 9 for GC restore plus 8 from its canonical post-rename recovery
state, and 65 for resumable v1-to-v2 migration plus 29 from its authenticated
pending-root state. The migration matrix exposed completed-migration and
late-completion-publication paths that could accept a provider-generated root
sibling during that invocation; the implementation now rechecks around
completion and before every successful return, fails closed, and retains the
evidence. Expanded PR run
[`30805725643`](https://github.com/loxal/zerotrust-drive/actions/runs/30805725643)
passed the 216-test job in 1m58s, macOS APFS in 1m19s, and asserted-x86_64
loopback ext4 in 1m06s. Both durability jobs ran the baseline, GC, and migration
matrices and the ext4 job unmounted its loopback filesystem cleanly.

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
migration and GC process-death testing has passed locally on APFS and in hosted
APFS/x86_64 loopback ext4. Both also retain deterministic returned-error
coverage at every checkpoint.

The durability-focused beta label remains unchanged. Live kernel-mounted FUSE
coverage, production wiring of the complete iCloud and Proton File Provider
path inventory, real-provider materialization and kill tests, remote-provider
ordering, and evidence-retirement policy remain open.

## Safe hot-path and CI-cost pass on 2026-08-03

The pinned immutable-object read path previously resolved the visible v2
namespace only to prepare a possible corruption message, then performed the
authoritative pinned pre-read verification, descriptor-rooted `openat` read,
and pinned post-read verification. Pinned reads now derive the diagnostic path
from the retained capability only if a digest mismatch occurs. Normal reads
therefore avoid an otherwise redundant provider-topology selection and path
allocation without removing either identity verification. A corruption test
still proves fail-closed `InvalidData` reporting at the captured exact path,
and the existing provider-replacement test remains in force.

The bounded range writer also no longer repeats an identical namespace
verification immediately after pinned immutable file-root publication. The
publication primitive still verifies the namespace before and after its exact
StoreRoot write, and no filesystem operation or durability checkpoint existed
between the two former caller/callee checks. Every write, file-sync,
directory-sync, rename, cleanup, recovery, and root-last checkpoint remains
unchanged.

Two allocation reductions were accepted as behavior-preserving resilience
work. Descriptor-rooted `readdir` scans now lend each exact `OsStr` name to the
synchronous visitor instead of allocating an `OsString` per entry. GC plan
construction moves the authenticated expectation/protection sets into its
walker and consumes the ordered object inventory into the plan after validation
instead of retaining full clones. Existing mutation-free repeated previews
continue to pin stable plan IDs and ordered candidates. The real-process fixture
copier also releases its redundant post-copy source snapshot before allocating
the destination snapshot. Unix tests cover dot filtering, and Linux additionally
covers an exact non-UTF-8 provider name.

The GitHub quota investigation separated public durability cost from private
release cost. GitHub's timing API reports zero billable Ubuntu and macOS
milliseconds for sampled `loxal/zerotrust-drive` runs because standard hosted
runners are free for this public repository. In contrast, the private Lifub
repository launched 66 `acli public binary release` workflows from 2026-08-01
through the investigation. Thirty-nine reached all three hosted builds, and
all 39 failed late on the same private credential-contract scan. Rounded job
times total 305 hosted Linux minutes plus 163 hosted macOS minutes. At GitHub's
current documented $0.006 Linux and $0.062 macOS standard rates, that is
$11.936 gross allowance value, or about 1,989 Linux-minute equivalents against
the 2,000-minute/$12 allowance. Six later jobs were rejected before runner
assignment because the spending limit had been reached. This one workflow
therefore explains effectively the complete quota.

The Lifub workflow is now explicit `workflow_dispatch` only; routine `main`
pushes and tags no longer start a release matrix. A typed, default-false
`publish` input requires an invocation from `main`, the exact next monotonic
version, and an unused immutable release directory. Trusted validation plus a
throwaway Linux public-artifact preflight runs on the configured self-hosted
runner. A missing runner variable falls back to the `self-hosted` label rather
than silently consuming hosted Linux minutes. The billed cross-platform matrix
and packaging jobs require the explicit default-false `publish` input and start
only after that preflight passes. A best-effort stale-input comparison on the
self-hosted runner rejects already-obsolete publish requests before the matrix;
the hosted publisher retains the authoritative current-main check.
Dispatch values enter hosted shell steps only through quoted environment
variables. Both stale-input inventories include Cargo's repository config in
addition to the source, lock, toolchain, workflow, and packaging inputs. Hosted
jobs consume the
GitHub-authenticated dispatch inputs directly, not self-hosted job outputs, and
the hosted publisher independently repeats the branch, source-version,
monotonicity, and immutable-target checks. A compromised self-hosted validator
can therefore fail or block a release but cannot authorize one or select its
version. Packaging downloads only the three exact hosted artifact names, not a
wildcard that could merge an extra artifact. Every job has an explicit timeout,
and every
publishable Linux/macOS artifact is still produced on a fresh GitHub-hosted
runner. If a newer release input reaches `main`, publication now
fails loudly and requires an explicit rerun instead of claiming a nonexistent
queued automatic workflow will publish it. The artifact scanner remains
strict; this cost guard does not convert its current private-credential
rejection into a release. Each ZeroTrust Drive durability OS job now lists its
test inventory once rather than rebuilding the same inventory for every exact
matrix invocation.
None of these scheduling changes is evidence for changing the durability beta
status.

## Verification record

Package version after this change set: `0.13.0`.

Current `0.13.0` local verification on Apple Silicon macOS/APFS:

- `cargo fmt --all -- --check` and `git diff --check`: passed.
- `cargo test --locked --no-run`: passed.
- `cargo clippy --locked --all-targets -- -D warnings`: passed.
- `cargo test --locked -- --test-threads=1`: 229 passed, 0 failed, and 11
  ignored. The ignored set is four manual small-file measurements, three
  explicit local-filesystem SIGKILL gates, three new retained-fixture iCloud
  gates, and the older query-only root-wide iCloud audit.
- Objective-C `-Wall -Wextra -Wpedantic -Werror` syntax check: passed.
- Current APFS normal-write/recovery matrix: 46 plus 18 real deaths, passed.
- Current APFS GC matrices: 22 quarantine plus 14 quarantine-recovery and 9
  restore plus 8 restore-recovery real deaths, passed.
- Current APFS migration matrix: 65 forward plus 29 pending-root-recovery real
  deaths, passed.
- A disposable Linux/arm64 Rust bookworm container compiled the current tree
  and passed the exact non-UTF-8 descriptor-directory scan test.
- Lifub `site-kit` product-page test: 4 passed; `cargo check -p site-kit` also
  passed at package version `1.25.0`. The `acli` release-security suite passed
  all 9 tests at package version `1.7.0`. `just acli-install` then refreshed
  the installed `acli`, `api-mcp`, and `api-mcp-proxy` binaries and synchronized
  the owned MCP registrations successfully.
- `just release` rebuilt the locally installed `zdrive`. Its SHA-256 digest
  matches `target/release/zerotrust-drive` at
  `1f3b2f9056fd2b84dfed616a27a31e1497e1e42f1f8d0c34d9c6c09593c8bdb9`, and
  the installed binary's help smoke test passed.
- No `ZDRIVE_RUN_ICLOUD_TESTS` or iCloud-root environment was configured. None
  of the four real-iCloud tests ran.
- The current `0.13.0` diff has not run in hosted APFS or x86_64 loopback-ext4
  CI. The workflow now includes the exact macOS storage-shim error/inventory
  probes, presenter module, and all three filesystem matrices, but that is
  configuration evidence rather than a passing hosted result.

Historical evidence inherited from merged PR #1 and its expanded run:

- Hosted PR #1 baseline: unit 2m19s, APFS 1m17s, and x86 loopback-ext4 1m23s,
  passed.
- The earlier local OrbStack loopback-ext4 baseline matrix passed the same 46
  normal-write plus 18 recovery deaths.
- Expanded hosted run `30805725643`: 216-test job 1m58s, APFS 1m19s, and
  asserted-x86_64 loopback ext4 1m06s; both filesystem jobs ran baseline, GC,
  and migration matrices, passed.

No current or historical result in this report promotes the beta posture.
