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
- The kernel write request is capped at 4 MiB. A write processes one chunk and
  one bounded radix path at a time.
- Flush holds no complete file content. File objects are already immutable and
  durable; flush serializes the metadata index, which has an independent 64
  MiB limit.
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
   use the same publication rule. No object in `S0` is overwritten or deleted.
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
   roots and manifests are moved to transaction-bound names under
   `_zdrive-v2/evidence`; they are never unlinked. Before moving the canonical
   manifest last, the client creates and fsyncs a durable manifest anchor.

Once this transaction's authenticated intent may be durable, an error latches
the mount read-only. Positive root/KDF/sibling conflicts also latch. Classified
transient inspections before intent publication remain retryable because no
visible generation or recovery intent changed. Startup audits retained
manifest evidence and completes a surviving canonical intent before loading
the active generation.

## Crash argument

The argument depends on these invariants:

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
  exact retained copy. Recovery validates `H1` and finishes idempotently.
- Recovery performs the same root exchange and verified evidence moves, so an
  interruption reduces to the same old/new cases.

Therefore, under the stated filesystem contract, the canonical local root
after a crash is complete `H0` or complete `H1`. Because every reachable child
is immutable and authenticated, neither root can expose a mixed readable
generation.

## Conflict-evidence argument

Normal v2 transactions do not delete roots, manifests, or immutable objects.
They retain exact known artifacts under transaction-bound evidence names.
Unexpected siblings, symlinks, nonregular files, changed control files, and
unknown root fingerprints stop commit/recovery.

Manifest-last cleanup has an unavoidable path race if a provider replaces the
canonical name between comparison and rename. To make that race detectable,
the client first persists an exact durable manifest anchor. On every remount it
authenticates all durable and retained normal-write manifests, verifies the
transaction ID encoded in each name, and requires every retained manifest to
equal its durable anchor. A raced provider file is therefore preserved at the
retained path and causes a loud mount failure instead of being silently treated
as completed cleanup.

Migration similarly retains the exact v1 index and blobs, an authenticated
source plan, per-file receipts, and a completion anchor that binds the v2
lineage origin. Re-running `--migrate-v2` resumes or reconstructs missing
completion metadata without replacing a later descendant root.

This policy intentionally leaks storage and directory entries. It prefers
forensic evidence and recoverability over automatic deletion.

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
the exact old or direct-child new generation, and checks unrelated evidence.

`recovery_is_fault_injected_and_idempotent_without_discarding_evidence` starts
from a durable pending intent, records recovery's trace, injects an error after
every recovery checkpoint, retries, verifies the exact new generation, and
checks a second recovery is a no-op.

`migration_resumes_after_every_durability_checkpoint` repeats that method
across plan and receipt publication, immutable object creation, root commit,
completion anchoring, and recovery. Additional tests cover evidence audit,
provider sibling preservation, lineage/origin validation, sparse-tree edge
cases, identical-write no-op behavior, and missing reachable objects.

These are deterministic error-injection checkpoints that approximate crash
boundaries. They do not kill a subprocess, emulate torn writes, discard dirty
page-cache data, roll back pre-fsync namespace changes, or model a device lying
about `fsync`. Actual process/power-loss behavior follows from the protocol
invariants plus the stated filesystem contract, not from error injection
alone.

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
- Every FUSE write performs chunk/tree/file-root COW immediately. Many small
  writes into one 4 MiB chunk can repeatedly rewrite the growing chunk and
  cause substantial upload amplification before metadata flush coalescing. A
  bounded dirty-chunk overlay is not implemented.
- Automatic garbage collection is not implemented. Orphan objects, old
  generations, displaced roots, and durable/retained transaction evidence
  accumulate. At the 30-second maximum dirty cadence, a continuously changing
  store can create thousands of evidence entries per day; close/fsync-heavy
  activity can create more. Evidence-aware compaction is a production blocker
  for sustained write-heavy use.
- `NSFileCoordinator` integration is not implemented. Partial coordination
  would imply a guarantee the Rust POSIX paths do not provide. iCloud remains a
  macOS beta target, the folder must be marked Keep Downloaded, and its backing
  store must pass the runtime atomic-exchange probe.
- The full mount scrub favors integrity over availability and startup speed. A
  partially synchronized generation cannot mount writable until all of its
  authenticated objects are local.

V2 is therefore a durability-focused beta/source preview. It is appropriate
for controlled testing and low-write workloads with one active writer and an
independent backup, not yet for write-heavy production storage.
