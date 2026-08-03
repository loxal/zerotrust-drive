# ZeroTrust Drive v2 format and crash-consistency argument

This document describes the v2 format implemented in the current source and
separates its filesystem argument from its deterministic test evidence. The
claim applies to a supported local filesystem with reliable same-directory
atomic no-replace/exchange rename plus working file and directory `fsync`.
Cloud synchronization is asynchronous replication, not part of that local
transaction.

## Format and compatibility

V2 retains the plaintext `_kdf.json` Argon2id parameters. Format selection is
backward-compatible:

- A valid `_root.age` selects v2.
- `_index.age` plus `_kdf.json`, with no v2 root, selects v1 compatibility
  mode.
- `_index.age` without `_kdf.json` is the pre-0.7 v0 format and must first use
  `--migrate-format`.
- A genuinely empty directory creates v2 on macOS/Linux after probing an
  internal directory on the same backing store for atomic exchange. Explicit
  migration performs the same preflight before publishing its plan. Platforms without that
  primitive keep creating v1 stores and refuse writable v2 mounts.

A KDF-only or partially populated directory is not treated as empty. It could
be an incompletely synchronized existing store, so initialization fails closed
rather than creating a divergent root.

The v2 layout is:

```text
_kdf.json
_root.age
_write.manifest                     while normal-write recovery is active
_z2-*.ready                         transaction-specific staging artifacts
_zdrive-v2/objects/<id>.z2          immutable authenticated objects
_zdrive-v2/evidence/*               retained roots/manifests/conflict evidence
_zdrive-v2/gc/<plan-id>/*           authenticated offline-GC plan and quarantine
_v2_migrate.plan.age                retained migration plan
_v2_migrate.complete.age            authenticated migration completion anchor
.v2_migrate_progress/*              authenticated per-file migration receipts
```

Preview v2 stores that already use `.zdrive-v2` and `._z2-*.ready` remain
readable and writable. New stores avoid those leading-dot and AppleDouble-like
names. Finding both current and legacy object directories, both forms of one
staging pair, or a provider-generated sibling directory is preserved and
reported as conflict evidence rather than silently choosing a namespace.

V2 roots and objects use XChaCha20-Poly1305. Object associated data binds the
format domain, object role, and random 128-bit object ID. Every authenticated
parent reference also stores a BLAKE2s-256 digest of the complete child
ciphertext. Short random object names reveal neither plaintext names nor
content roles.

Object roles are:

- Data: at most one 4 MiB logical-grid chunk. Tail and sparse chunks can have
  shorter physical plaintext instead of fixed padding.
- Tree: a bounded 256-way sparse radix node.
- File root: logical size, bounded tree height, and tree reference.
- Index: a bounded complete directory/inode metadata snapshot.
- Generation: generation number, random lineage ID, index, parent, and the
  first-generation origin reference.

Missing tree slots authenticate sparse zero ranges. Shrink prunes later
references and truncates the last partial chunk, so subsequent growth cannot
reveal an old tail. A mount validates the index graph and then traverses and
authenticates every reachable file root, tree, and data chunk before enabling
writes.

## Memory bound

V2 never puts a complete open file in the legacy `open_files` map.

- A read holds one bounded FUSE response, one encrypted/plaintext chunk, and a
  radix path.
- The kernel write request is capped at 4 MiB. An unaligned request can touch
  two chunk slots; every required base chunk is authenticated before the
  request changes acknowledged dirty state.
- A mount-wide overlay retains at most sixteen dirty 4 MiB slots (64 MiB of
  logical retained bytes and requested steady-state capacities) and 256 dirty
  inode records. New, sparse, and short tails reserve compactly; changing an
  existing full base chunk still retains that authenticated complete chunk.
  Allocator over-allocation and a transient old-plus-new allocation while one
  vector grows are additional bounded-operation overhead, so 64 MiB is not a
  hard RSS ceiling. Writes to the same slot coalesce. Capacity pressure commits
  the complete prior overlay before accepting another slot.
- Flush holds no complete file content. It materializes one dirty immutable
  path at a time, then serializes the metadata index, which has an independent
  64 MiB limit. Dirty state is cleared only after the root-last transaction
  succeeds.
- The pre-write mount scrub also visits one file path/chunk at a time. Its
  duration grows with stored data, but its working memory does not grow with an
  individual file's size.

V1 remains readable and writable, but its historical single AEAD tag covers a
complete file and therefore retains whole-file buffering. Explicit v1-to-v2
migration must also authenticate one complete legacy blob before emitting
bounded v2 chunks, so that one-time operation needs RAM for the largest v1
file. Normal v2 I/O does not.

## Normal commit protocol

Let `H0` be the complete authenticated old `_root.age`, `G0` its generation,
and `S0` its reachable immutable objects. Let `H1`, `G1`, and `S1` be the new
state.

1. Each changed data chunk is written under a fresh random ID with create-new,
   file `fsync`, and object-directory `fsync`. New radix nodes and file roots
   use the same publication rule. The mount writes through a pinned `objects`
   directory descriptor and reopens the final name to verify its inode, link
   count, length, and exact bytes. No object in `S0` is overwritten or deleted.
2. Flush serializes the complete prospective metadata index within its 64 MiB
   bound, then publishes a new index object and `G1`. `G1` authenticates the
   exact parent, origin, lineage, and index. Every object in `S1` is durable at
   this point.
3. The client writes and fsyncs `H1` at a random transaction-specific ready
   name, then fsyncs the containing directory.
4. It writes an AEAD-authenticated normal-write manifest at another ready name.
   The manifest binds the transaction ID, exact KDF bytes, complete old/new
   root fingerprints, parent/origin/new generation references, lineage,
   generation number, and both ready names.
5. After rechecking KDF, root, and provider-sibling state, it publishes the
   manifest as `_write.manifest` without replacement and directory-fsyncs it.
   That durable intent makes recovery unambiguous.
6. It rechecks the same conflict boundaries. For an update, it atomically
   exchanges ready `H1` with `_root.age`, leaving complete displaced `H0` at
   the ready name. Initial generation publication uses atomic no-replace. The
   parent directory is fsynced. This root switch is the last visibility change.
7. It verifies canonical `H1`, KDF, and sibling state again. Verified staging
   roots and manifests are moved by descriptor-relative atomic no-replace
   rename to transaction-bound names under `_zdrive-v2/evidence`; they are
   never unlinked. Before moving the canonical manifest last, the client
   atomically hard-links and fsyncs a durable manifest anchor through the
   retained evidence-directory descriptor. It synchronizes the destination
   evidence directory before the source directory and verifies the exact
   retained bytes and canonical directory identity afterward.

Once this transaction's authenticated intent may be durable, an error latches
the mount read-only. Positive root/KDF/sibling conflicts also latch. Classified
transient inspections before intent publication remain retryable because no
visible generation or recovery intent changed. Startup audits retained
manifest evidence and completes a surviving canonical intent before loading
the active generation.

## Crash argument

This is a local process-crash argument. It assumes one writer, the documented
filesystem semantics, and no concurrent provider replacement of the selected
object namespace during the root-publication syscall. The client pins the
namespace, `objects`, and `evidence` directory descriptors and revalidates their
canonical identities before and after intent, root, and manifest publication.
That detects persistent replacements at those boundaries, keeps generation and
index reads on the retained objects inode, and keeps evidence scans, links, and
moves on the retained evidence inode. POSIX cannot atomically bind a
child-directory identity check to the separate top-level root exchange,
however: an ABA replacement or a change in the final check-to-exchange interval
can be reported only after root visibility. Arbitrary provider mutation is
therefore outside this proof and remains a beta limitation requiring evidence
preservation and a settled sync state before retry.

Within that scope, the argument depends on these invariants:

1. Immutable publication: referenced objects are create-new and never
   overwritten.
2. Authenticated reachability: each reference and complete child ciphertext
   digest is authenticated by its parent.
3. Preparation: every object reachable from `H1` is file-fsynced and
   directory-fsynced before intent publication and before the root switch.
4. Old preservation: `S0` remains intact, and an update exchange leaves exact
   `H0` at the ready/evidence name.
5. One visibility pointer: only `_root.age` selects the visible generation.
6. Atomic namespace switch: an internal directory on the same backing store
   has passed an actual exchange probe before writable use; initial
   publication also uses no-replace rename with a create-new hard-link
   fallback.
7. Fail closed: malformed, missing, wrong-digest, wrong-parent, unexpected, or
   third-generation state is an error. Reads never fall back around a corrupt
   new generation.

For each crash phase:

- Before canonical manifest publication, `_root.age` remains `H0`. New files
  are unreferenced staging/orphan objects, so `H0` still reaches complete `S0`.
  Syntactically valid ready files from this phase are preserved as unbound
  evidence. With no authenticated canonical manifest they select no state and
  do not block a fresh transaction with new random names.
- After manifest publication but before root exchange, `_root.age` is `H0`.
  Recovery authenticates KDF, manifest, exact `H0`, ready `H1`, `G1`, parent,
  origin, lineage, and index before rolling forward. A mismatch preserves the
  artifacts and fails closed.
- Across the atomic exchange before its directory `fsync`, a conforming
  filesystem can recover the old or new complete name arrangement, not a
  byte mixture. The manifest recognizes exact `H0` or `H1`; `H0` reaches `S0`
  and `H1` reaches already durable `S1`.
- After root-directory `fsync`, `_root.age` is durably `H1`. A crash during
  evidence retention leaves the canonical manifest, its durable anchor, or an
  exact retained copy. Before recovery mutates any name, it validates the
  pending manifest's complete new lineage and the exact displaced old root and
  complete old lineage. Recovery then validates `H1` and finishes idempotently.
- Recovery performs the same root exchange and verified evidence moves, so an
  interruption reduces to the same old/new cases.

Therefore, under the stated filesystem contract, the canonical local root
after a crash is complete `H0` or complete `H1`. Because every reachable child
is immutable and authenticated, neither root can expose a mixed readable
generation.

## Conflict-evidence argument

Normal v2 transactions do not delete roots, manifests, or immutable objects.
Completed-manifest audit requires the exact retained displaced root, validates
its complete snapshot, and walks its authenticated parent chain to the declared
origin. A missing generation, index, file graph, or inconsistent generation
number, lineage, or origin fails closed; validated generation references are
deduplicated within the bounded evidence inventory. Every retained manifest and
manifest-ready artifact separately validates its authenticated new generation,
exact relationship metadata, complete snapshot, and ancestry before that
deduplication can short-circuit graph work. Thus replacing the objects directory
with only the current and immediate old generations cannot silently erase older
or unpublished conflict-lineage evidence.
They retain exact known artifacts under transaction-bound evidence names.
Unexpected siblings, symlinks, or nonregular files in covered root, control,
staging, evidence, and object-namespace paths, plus changed control files and
unknown root fingerprints, stop the applicable commit or recovery path.

Manifest-last cleanup has an unavoidable path race if a provider replaces the
canonical name between comparison and rename. To make that race detectable,
the client first persists an exact durable manifest hard link in the pinned
evidence directory. Evidence inventory and retention never re-resolve that
provider-controlled directory path. On every remount it streams and
authenticates all durable and retained normal-write manifests, verifies the
transaction ID encoded in each name, and requires every retained manifest to
equal its durable anchor. Every completed update manifest must also have its
exact primary displaced-root evidence; audit decodes that root and validates
the complete generation, index, and file graph through the retained objects
descriptor. A raced provider file or an objects replacement containing only
the current head therefore causes a loud mount failure instead of being
silently treated as complete evidence.

Migration similarly retains the exact v1 index and blobs, an authenticated
source plan, per-file receipts, and a completion anchor that binds the v2
lineage origin. Re-running `--migrate-v2` resumes or reconstructs missing
completion metadata without replacing a later descendant root.

This policy intentionally leaks storage and directory entries. It prefers
forensic evidence and recoverability over automatic deletion.

## Evidence-aware offline orphan quarantine

V2 GC is an explicit offline protocol, not background cleanup. It preserves
the authenticated active generation and its complete parent/origin history,
normal-write manifests and retained roots, completed migration plans,
completion anchors and receipts, and every recognized conflict artifact. A
v1-only preview does not modify the encrypted backing store.

`--gc-v2` authenticates the complete graph and inventory without modifying the
encrypted backing store or persisting a plan. It acquires only a local advisory
process lock outside the store. It emits a deterministic plan ID bound to
portable authenticated store state, the selected object namespace, KDF and
control/evidence fingerprints, and every canonical object name, length, and
ciphertext digest. Unknown evidence, untrusted artifacts, provider siblings,
hard-linked immutable objects or staged controls, nonregular entries,
missing/corrupt graph objects, pending migration, or a changed inventory abort
before mutation.

`--gc-v2-quarantine PLAN_ID --confirm-sync-paused` rechecks the exact plan and
moves each proven-unreachable immutable object with no-replace rename into the
authenticated plan's quarantine without unlinking its bytes. The durable
source-or-quarantine location of each candidate is its progress state: the
destination file and destination directory are synchronized before the source
directory, and the final marker records whole-plan completion.
`--gc-v2-restore` additively reverses a partial or complete quarantine until
purge intent exists. New physical purge is disabled on current platforms. No
portable primitive can atomically authenticate an inode while excluding a
concurrent rename, write, or hard-link mutation, so destructive truncation or
unlink could erase newly arrived conflict evidence. `--gc-v2-purge`
authenticates and revalidates a new plan, then fails without changing names or
bytes, publishing intent, or creating tombstones. It remains only for
backward-compatible completion of authenticated, already-zero tombstone
evidence. Plans and markers are
written under fresh recognized staging names, file-synchronized, and published
to their final names by atomic no-replace rename plus directory `fsync`, so a
partial staged write cannot wedge resume. Every mutating operation holds the
same local one-writer lock and is resumable after every write, file `fsync`,
rename, directory `fsync`, cleanup, and recovery checkpoint.

One shared 250,000-entry budget covers immutable-object and namespace
inventory, ready controls, normal-write and migration evidence, migration
receipts, GC operations, controls, quarantines, and compatibility tombstones.
Authenticated plan ciphertext is limited to 64 MiB, and preview rejects an
oversized scan or plan before creating persistent GC state.

Interrupted control stages are append-only evidence: they are never selected as
state, overwritten, or silently removed. Subsequent GC scans inventory and
fingerprint stages from completed operations as anchors in the next plan. They
can therefore accumulate until the explicit namespace bound is reached.

The framework identifies and reversibly isolates proven-unreachable COW
objects, including crash leftovers, not committed history. It currently does
not reclaim their storage. Sync must
be paused on every device and an independent backup must already exist. No
local scan can prove remote convergence or detect a complete, internally
consistent provider rollback without an external monotonic anchor.

## Deterministic test evidence

V2 durability code emits typed checkpoints after:

- writes;
- file `fsync`;
- rename/no-replace/exchange publication;
- directory `fsync`;
- cleanup/evidence-retention operations; and
- recovery validation/mutation steps.

`every_commit_checkpoint_recovers_to_exact_old_or_new_generation` records the
successful trace, then injects an error after every checkpoint in turn. It runs
recovery against that on-disk state, authenticates the visible index, asserts
the exact old or direct-child new generation, and checks recognized provider
conflict evidence byte-for-byte.

`recovery_is_fault_injected_and_idempotent_without_discarding_evidence` starts
from a durable pending intent, records recovery's trace, injects an error after
every recovery checkpoint, retries, verifies the exact new generation, and
checks a second recovery is a no-op.

`migration_resumes_after_every_durability_checkpoint` repeats that method
across plan and receipt publication, immutable object creation, root commit,
completion anchoring, and recovery. Additional tests cover evidence audit,
provider sibling preservation, lineage/origin validation, sparse-tree edge
cases, identical-write no-op behavior, and missing reachable objects.

The offline-GC tests apply the same exhaustive returned-error method across
quarantine, restore, staged controls, and compatibility purge recovery, then
re-authenticate the live root and resume the exact plan. Separate regressions
prove a new purge leaves the complete tree byte-for-byte unchanged.

An additional opt-in harness runs the normal commit and recovery traces in
fresh subprocesses and delivers `SIGKILL` immediately after each selected
checkpoint. On 2026-08-02 the complete 46 normal-write plus 18 recovery matrix
passed on local APFS and on a real loopback ext4 filesystem mounted inside the
local OrbStack Linux 7.0.11 aarch64 VM. The same baseline subsequently passed
in hosted APFS and x86 loopback-ext4 jobs on PR #1. The verifier now
authenticates the raw root and its complete reachable graph before recovery is
allowed to mutate names, then authenticates the recovered result again. The
gate pins audited checkpoint counts and critical root/manifest contexts, fails
if its opt-in environment is missing, and CI verifies the exact fully qualified
test name before execution.

A separate ignored iCloud/File Provider gate runs the same 46 plus 18 deaths
below an explicitly user-selected folder marked Keep Downloaded. Unlike the
ordinary local APFS/ext4 harness, it never removes a successful trace or a
synthetic recognized conflict sibling. Each death state gets a separate
conflict-bearing copy, the clean copy alone is recovered, and both remain for
descriptor-rooted post-settlement inventory. Authentication is a separate
pathname-based pass while the retained child identity remains unchanged. A
second ignored gate below the same Keep Downloaded root verifies inherited
policy and exact nested fixture bytes. The third gate requires another
user-selected iCloud folder that is explicitly not marked Keep Downloaded for
the eviction-to-`NotDownloaded`-to-materialized transition; Keep Downloaded
and eviction cannot form one reliable test. Neither real-iCloud root has been
exercised in this change set, so none of the three gates adds provider
qualification.

The current `0.13.0` tree passes dedicated matrices locally on APFS: 22
GC-quarantine plus 14 canonical post-rename quarantine-recovery deaths, 9
restore plus 8 canonical post-rename restore-recovery deaths, and 65
v1-to-v2 migration plus 29 authenticated pending-root-recovery deaths. Every GC case leaves exactly one byte-identical
live or quarantine name and retains passive and recognized conflict evidence.
Every migration case retains exact v1 sources, and every visible v2 root
authenticates a complete generation. These are selected reachable mutation
states, not a Cartesian matrix of manually malformed staging artifacts.
Historical expanded PR #1 run `30805725643` passed the 216-test job in 1m58s,
APFS in 1m19s, and asserted-x86_64 loopback ext4 in 1m06s. The current
`0.13.0` StoreRoot, compact-tail, and native-probe diff has not yet run in
hosted APFS or x86_64 loopback-ext4 CI.

The harness uses direct `ZeroTrustFs` calls for one representative open,
write, `fsync`, and release sequence; it is not a live kernel-mounted FUSE
test. Maintenance recovery repeats deaths from the selected canonical partial
states described above, not every manually corrupted recovery artifact. These
tests do not emulate sudden power loss, torn sectors, controller-cache loss,
provider reordering, concurrent writers, or a device lying about `fsync`.
macOS `File::sync_all` is not claimed to provide `F_FULLFSYNC`. The local proof
still depends on the stated filesystem contract.

## Cloud replication boundary

Root-last is a local durability order. A provider may upload `_root.age` before
one of its immutable dependencies reaches another machine. Before enabling
writes, that machine scrubs every authenticated object reachable from the root;
missing, corrupt, or wrong-digest material refuses the mount. This can be slow
and can force placeholder downloads, so the entire backing folder must be kept
local and synchronization must complete before switching machines.

There is no distributed writer lease or remote multi-file transaction. Two
offline writers can create valid sibling generations and require manual
reconciliation. Whole-store rollback also remains possible if a provider
restores an internally consistent historical root plus all of its objects;
detecting that requires a trusted monotonic anchor outside the synchronized
store.

## Current limitations and release posture

- V2 passphrase rotation is refused rather than risking a non-atomic
  `_kdf.json`/root pair. Export into a new v2 store to change the passphrase.
- The metadata index is a complete bounded snapshot. Metadata-heavy stores
  rewrite it on each committed generation.
- The bounded overlay coalesces writes only until capacity pressure, close,
  `fsync`, or the dirty timer commits it. Commit-heavy workloads can still
  produce substantial chunk/tree/file-root upload amplification.
- Orphan handling is offline and operator-driven. It can authenticate,
  quarantine, and restore objects proven unreachable, but new destructive
  reclaim is disabled. Committed generations, displaced roots, and
  durable/retained transaction evidence remain intentionally reachable.
  Historical growth and evidence retirement therefore remain open policy
  problems for sustained write-heavy use.
- Portable pathname APIs do not provide a transaction against a hostile sync
  provider. Rather than retain a final destructive race window, new purge
  fails read-only before intent publication. Pausing sync remains mandatory
  for quarantine and restore because no local check is a provider transaction.
- Pinned `openat` object I/O and pre/post identity checks do not make the
  top-level root exchange and child namespace one atomic provider operation.
  They fail closed when a change is visible at a validation boundary; they
  cannot exclude a final concurrent/ABA provider rename. The old-or-new proof
  is therefore about process crashes with a stable selected namespace, not an
  adversarial sync client mutating directory names during publication.
- A no-presenter, exact-URL `NSFileCoordinator` shim and capability-rooted
  storage boundary are implemented and tested. Pinned immutable-object
  publication now uses its direct backend, but coordinated mode and every
  remaining production POSIX path are intentionally unwired. Partial
  coordination would imply a guarantee the complete path inventory does not
  provide. iCloud remains a macOS beta target, the folder must be marked Keep
  Downloaded, and its backing store must pass the runtime atomic-exchange probe.
- The full mount scrub favors integrity over availability and startup speed. A
  partially synchronized generation cannot mount writable until all of its
  authenticated objects are local. The scrub is not repeated over all live
  data before every commit; post-mount in-place object loss or corruption can
  be inherited by a later metadata generation.
- Current `0.13.0` baseline, migration, and GC subprocess-kill qualification
  has local APFS results. Hosted APFS/x86_64 loopback-ext4 results are inherited
  from PR #1; the current diff still needs those hosted gates. The normal-write
  harness does not mount through the kernel FUSE path.

V2 is therefore a durability-focused beta/source preview. It is appropriate
for controlled testing and low-write workloads with one active writer and an
independent backup, not yet for write-heavy production storage.
