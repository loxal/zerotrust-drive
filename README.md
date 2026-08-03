# ZeroTrust Drive

FUSE-based encrypted overlay filesystem. You work with decrypted files in the mount directory
while all data is stored encrypted at rest with XChaCha20-Poly1305 AEAD encryption, under a key
derived from your passphrase with Argon2id (the `.age` file extension is a naming convention -
not the age crate).

The cloud storage service receives user content and filesystem metadata only as ciphertext through
the backing directory. That store also exposes non-secret plaintext KDF parameters, object sizes,
names, timing, and account metadata. A provider's desktop sync process still runs on the endpoint
and may have local access to the separate plaintext mount, so ordinary endpoint security remains
necessary. New stores use the v2 format:
immutable authenticated chunks on a 4 MiB logical grid, sparse copy-on-write radix trees, immutable metadata
generations, and a small authenticated `_root.age` visibility pointer. A plaintext `_kdf.json`
holds only the key-derivation salt and bounded cost parameters (not secret - see
[Encryption](#encryption)). The encrypted index stores the full directory tree, permissions,
sizes, timestamps, and opaque file-root references. Without the correct passphrase, this metadata
and every data object are unreadable.

Point `--encrypted-dir` at a fully local cloud-sync folder and its provider handles replication
of the ciphertext. Placeholder/on-demand storage is not a safe backing filesystem for this tool.

V2 does not buffer complete open files. Read, write, and flush memory are bounded independently of
logical file size: a bounded read decrypts at most one fixed-size chunk at a time in addition to
the bounded response buffer, and flush contains metadata rather than complete file content. Sparse
writes do not materialize holes.
Existing v1 stores still mount for compatibility and retain their legacy whole-file RAM behavior
until explicitly migrated with `--migrate-v2`.

If the selected authenticated root (or legacy v1 index), exact KDF metadata, or pinned control
topology changes externally while mounted, zerotrust-drive refuses the next local commit instead
of overwriting the external generation. It also fails closed when it finds provider-generated sibling
v1 blobs or indexes, the v2 root or object namespace, KDF metadata, or maintenance controls; iCloud
index-placeholder names; ambiguous non-UTF-8 top-level, control, or evidence entries; an unreferenced canonical blob that
could collide with future allocation; malformed or provider-conflicted staging names; or a stale
temp from an interrupted write. Valid transaction-ready files left before authenticated intent
publication remain unreferenced evidence: they are preserved, do not select a generation, and do
not prevent a fresh retry.
The mounted instance then latches read-only and persistence calls fail until remount, even if
synchronization later hides the conflicting artifact. Preserve every copy before reconciling.
Never mount the same store on two computers at once.

Metadata changes flush after 5 seconds without another change and after at most 30 seconds of
continuous dirty activity. Clean opens and clean `fsync` calls leave randomized ciphertext stable.
V2 writes fresh immutable objects and publishes an authenticated copy-on-write generation; only
the small `_root.age` pointer changes last. Updates atomically exchange it and retain the displaced
root as transaction evidence; the first generation is published with atomic no-replace.

### Cloud backend guidance

The primary supported target is a dedicated folder in Google Drive `My Drive`, with Google
Drive for desktop configured to **Mirror files**. Mirror mode keeps ordinary local files and
best matches the POSIX `fsync` and atomic-rename behavior used here. Do not use Google Drive
Stream mode or a Shared Drive as the backing store.

iCloud Drive is a macOS-only beta target. Mark the complete encrypted backing folder
**Keep Downloaded** before use. iCloud's File Provider placeholders and lack of a general
user-facing pause-sync control make migration and recovery less predictable. A safe exact-URL,
no-presenter `NSFileCoordinator` shim and capability-rooted storage boundary are implemented and
tested, but production routing remains disabled and unwired. The current client does not yet coordinate every backing-store operation; enabling only
partial coordination would give a false guarantee and can introduce nested-coordination failures.
Apple says an individual iCloud Drive folder or file over 50 GB is usually marked Ineligible.
Treat that as a conservative operational ceiling rather than a precisely specified recursive
quota contract. The relevant planning number here is the complete accumulated ciphertext footprint,
including unreachable copy-on-write objects and retained evidence, not the visible plaintext size. Offline v2 GC can authenticate and
reversibly quarantine exact unreachable objects, but new physical purge is deliberately disabled:
portable pathname APIs cannot exclude a final concurrent rename, write, or hard-link race without
risking conflict evidence. Quarantine therefore does not reclaim space. Use iCloud only for stores
that remain comfortably below the limit, monitor the encrypted folder, and migrate away before it
approaches 50 GB.

Proton Drive is an experimental macOS backing target. Use a dedicated folder under `My files`,
mark the complete encrypted folder **Make Available Offline**, and verify the client's last
successful synchronization before mounting or moving to another device. Proton's macOS client
uses Apple File Provider, and Proton officially warns that large numbers of small files can take
substantially longer to synchronize. This is directly relevant to v2's immutable-object layout.
Proton's own end-to-end encryption is welcome defense in depth, but it is not part of this
project's trust argument: `zerotrust-drive` must independently encrypt and authenticate the data
before Proton receives it. Keep the ZeroTrust Drive passphrase separate, retain Proton's recovery
phrase or file outside Proton, and maintain an independent backup. The official Proton CLI is a
transfer tool rather than a mounted or continuously synchronized filesystem; rclone's
reverse-engineered Proton backend is not supported for a writable store.

Yandex Disk is an experimental secondary target, strongest when its official Linux sync daemon is
useful. Prefer a fully local synchronized folder, not WebDAV. Its documented upload cap is twice
the current storage capacity for a 30-day accounting period that begins with the first upload and
then resets every 30 days. This is a material constraint for immutable copy-on-write churn and
migrations. Yandex also warns that simultaneous multi-device editing can create duplicate conflict
copies or lose files. Keep the same one-writer and independent-backup discipline.

None of these providers supplies a multi-file transaction, a cross-machine writer lock, or a backup.
Use one active mount, wait for sync to finish before switching computers, and keep an independent
versioned snapshot. See the [2026 cloud backend and user-experience review](docs/cloud-storage-backends-2026-08.md)
for the technical tradeoffs, vendor documentation, and reported failure modes.

Normal v2 commits never overwrite a referenced data object. They publish every immutable chunk,
tree node, file root, index, and generation first; publish an AEAD-authenticated normal-write
manifest; then atomically switch `_root.age` last (exchange for an update, no-replace for the first
root). Recovery accepts only the exact authenticated old or new root and never falls back around a
corrupt object. Deterministic tests return an injected
error after every write, file fsync, namespace publication/rename, directory fsync,
evidence-retention, and recovery checkpoint, then retry recovery against that state. An opt-in
subprocess matrix also uses real `SIGKILL` after every checkpoint and verifies recovery in a fresh
process. The baseline 64-kill normal-write/recovery matrix passes on local APFS, local loopback
ext4, hosted APFS, and hosted x86 loopback ext4. [GitHub PR #1](https://github.com/loxal/zerotrust-drive/pull/1) recorded the hosted unit job in
2m19s, APFS in 1m17s, and x86 ext4 in 1m23s. Dedicated local APFS matrices also pass 22 GC
quarantine plus 14 quarantine-recovery deaths, 9 GC restore plus 8 restore-recovery deaths, and
65 v1-to-v2 migration plus 29 pending-root recovery deaths. The migration matrix exposed and
helped fix completed-migration and late-publication root-sibling bypasses. Hosted runs of these new
dedicated matrices remain pending. The harnesses exercise `ZeroTrustFs` and maintenance
entrypoints directly; they are not live kernel-mounted FUSE tests. The maintenance suites repeat
death from selected canonical post-rename and pending-root recovery states, not every synthetic
malformed-artifact combination. Neither test emulates power loss,
torn sectors, controller caches, remote-provider ordering, or a device that lies about `fsync`;
the claim still relies on the documented filesystem contract. See the
[v2 crash-consistency argument](docs/v2-crash-consistency.md).

Each normal-write death is inspected in a fresh process before recovery: the
crash-visible root must authenticate either the byte-identical old generation
or the complete new generation and every reachable object. The matrices pin
their audited checkpoint counts, fail when their opt-in environment is absent,
and hosted CI verifies each exact test name before executing it.

The old-or-new proof is a local process-crash proof under the one-writer rule and a stable selected
object namespace during the root-publication syscall. The mount retains exact namespace,
`objects`, and `evidence` directory descriptors; immutable generation/index reads and writes use
the pinned `objects` descriptor and verify each newly published final name, inode, link count,
length, and bytes. Evidence inventory, atomic no-replace moves, and durable manifest hard links use
the pinned `evidence` descriptor. Commit, recovery, and migration revalidate the canonical
directory identities around publication and evidence retention.
Those checks fail closed for a replacement present at a validation boundary, but POSIX cannot
atomically couple a child-directory identity check to the separate `_root.age` exchange. A provider
replacement in that final interval can be detected only after the root became visible. This is a
provider-concurrency beta limitation, not part of the process-crash proof; preserve all artifacts
and remount only after synchronization has settled.

Writable v2 startup traverses and authenticates every file root, tree, and chunk reachable from
the active generation. It authenticates the new-generation graph named by every retained manifest
or manifest-ready artifact, and it authenticates each completed update's exact displaced root.
Both sides are walked through their parent chains to the declared origin, validating every
historical index and file graph. Provider replacement therefore cannot leave apparently valid but
unusable conflict or lineage evidence. This prevents a partially synchronized machine from committing on top of
incompleteness present at startup, but can make mount time proportional to live and retained history and can force
placeholder downloads. The full scrub is not repeated before every commit; post-mount in-place
object loss or corruption can be inherited by a later metadata generation. Keep the complete
backing folder local before mounting.

A pending canonical write manifest is checked the same way before recovery changes any name: its
complete new lineage and its exact displaced old root and lineage must already be readable through
the retained namespace. Recovery cannot make incomplete evidence look completed for one mount.

V2 is currently a durability-focused beta. A bounded dirty overlay coalesces writes in up to sixteen
4 MiB slots (64 MiB) across the mount before a root-last flush; pressure flushes the prior overlay
before accepting another chunk. This removes complete-file buffering and repeated object creation
for edits that remain in one dirty interval, but close/fsync-heavy workloads can still amplify
copy-on-write uploads. Evidence-aware orphan handling is explicit and offline: preview does not
modify the encrypted backing store or persist a plan, and quarantine is reversible. New physical
purge is refused before intent or tombstone creation because no supported portable primitive makes
it safe against concurrent inode mutation. The quarantine framework selects only authenticated objects proven
unreachable, never committed history or conflict/recovery evidence, but currently reclaims no
storage. Sustained write-heavy production use is not yet recommended.

The hosted baseline filesystem gates are green, but the beta status is unchanged. Hosted
qualification of the dedicated migration and GC matrices, live kernel-mounted FUSE coverage,
complete File Provider coordination, remote-provider ordering, and safe evidence retirement
remain open.

Legacy v1 commits still have the historical blob-before-index crash window. Migrate important v1
stores before relying on root-last atomicity.

A brand-new store publishes `_kdf.json` before its first authenticated root. If initialization stops
between those publications, restart refuses the KDF-only directory because it is indistinguishable
from incompletely synchronized existing data. Preserve and inspect the directory; delete it only
when you can prove that no user data was ever committed, or restore the missing cloud generation.
KDF creation rechecks for a provider-arriving v1 index, v2 root, or write manifest immediately
before and after publication and retains its durable temp on conflict. POSIX still cannot
atomically test three independent control names while creating a fourth; a provider arrival in the
remaining interval can leave an incompatible canonical KDF beside preserved conflict evidence.
Do not delete either side automatically.
Back up `_kdf.json` separately with the encrypted store. Its salt is not secret, but losing or
corrupting this single file makes every ciphertext undecryptable even with the correct passphrase.

### Prerequisites

A FUSE implementation is required. Install the one for your OS:

- **macOS** - [macFUSE](https://macfuse.github.io/)
- **Linux** - FUSE 3 (Debian/Ubuntu: `sudo apt install libfuse3-dev fuse3`, Fedora: `sudo dnf install fuse3-devel`)
- **Windows** - not supported (would require [WinFSP](https://winfsp.dev/) and a different FUSE crate)

#### macOS: permissions troubleshooting

On macOS, the privacy framework (TCC) can restrict access when the backing or mount location is
protected. An "Operation not permitted" or "Permission denied" result can also mean that the
mount is absent or ordinary directory permissions are wrong, so verify those conditions first.

If the location is TCC-protected, go to **System Settings > Privacy & Security > Full Disk
Access** and enable access for the terminal or application using the mount.

### Directory Layout

    ~/g.drive/.zerotrust.drive.encrypted/    encrypted storage - synced by Google Drive (ciphertext + non-secret KDF salt)
    ~/z.drive/                              FUSE mount point - local, NOT synced (you work here)

The encrypted directory is auto-managed by zerotrust-drive. Do not modify its contents directly.
Both paths are overridable via justfile variables or CLI flags `--encrypted-dir` / `--decrypted-dir`.

### Usage

    ZEROTRUST_PASSPHRASE="my-secret" just mount         # mount or create with a real secret
    just populate                                       # create test files on the mounted filesystem
    just umount                                         # unmount (decrypted dir becomes empty)
    just mount                                          # remount - files reappear from encrypted storage
    cargo run -- --migrate-v2                           # explicitly migrate a v1 store, resumably
    just test                                           # run unit tests
    just release                                        # build optimized release binary
    just clean                                          # remove build artifacts and encrypted storage

### Offline v2 orphan quarantine

Unmount the store everywhere, wait for every provider to report synchronization complete, make an
independent snapshot, and pause synchronization on every device. Preview does not modify the
encrypted backing store or persist a GC plan; it only acquires a local advisory process lock outside
that store:

    zerotrust-drive --encrypted-dir /fully/local/store --gc-v2

Copy the exact plan ID from that preview. Quarantine moves only the named, still-unreachable
immutable object bytes into its plan directory without unlinking those bytes; it is resumable and
reversible:

    zerotrust-drive --encrypted-dir /fully/local/store --gc-v2-quarantine PLAN_ID --confirm-sync-paused
    zerotrust-drive --encrypted-dir /fully/local/store --gc-v2-restore PLAN_ID --confirm-sync-paused

The `--gc-v2-purge` flag is retained only to finish authenticated compatibility evidence for an
already-reclaimed zero tombstone. A new purge authenticates and revalidates the plan, then returns
an unsupported error without changing any name or byte, publishing intent, or creating tombstones:

    zerotrust-drive --encrypted-dir /fully/local/store --gc-v2-purge PLAN_ID --confirm-sync-paused

Every plan-consuming operation re-authenticates the plan, and every GC action holds the one-writer
process lock. Preview,
quarantine, and compatibility purge reject pending maintenance, provider siblings, unknown evidence, and stale
live roots or object inventory. Restore is deliberately narrower and additive: before purge intent
exists, it authenticates the current key, stored plan, GC controls, and exact candidate state, then
can put the planned objects back even if unrelated live roots or evidence changed after quarantine.
Missing planned bytes or ambiguous source/quarantine copies fail closed. Existing full tombstones
and quarantined bytes are preserved; only a pre-existing, authenticated all-zero compatibility
state can publish purge completion. Compact authenticated GC records and append-only staged-control
evidence remain. Plans use portable authenticated store identity rather than a host-local absolute
path; old
path-bearing plans remain readable after relocation. V1 preview does not modify the encrypted
backing store or persist GC state. This collector does not retire committed generations or
recognized conflict/recovery evidence, and it cannot prove that a remote provider replica is
current.

GC uses one shared 250,000-entry budget across immutable-object and namespace inventory, ready
controls, normal-write and migration evidence, migration receipts, GC operations, controls,
quarantines, and compatibility tombstones. Its authenticated plan ciphertext is capped at 64 MiB;
preview refuses an oversized scan or plan before creating GC state.

### Passphrase

Set the encryption passphrase via env var or CLI flag. A new store refuses an empty
passphrase or the built-in `zerotrust-demo-passphrase`. The explicit
`--allow-default-passphrase` override exists only for throwaway tests. An existing store
created with either insecure value remains accessible but prints a warning.

    ZEROTRUST_PASSPHRASE="my-secret" just mount         # via env var (recommended)
    cargo run -- --passphrase "my-secret"                # via CLI flag
    cargo run -- --allow-default-passphrase              # throwaway new store only

The env var takes precedence if both are provided.

### Passphrase Rotation (Rekey)

This operation currently supports v1 only. V2 refuses passphrase rotation rather than risk a
non-atomic `_kdf.json`/`_root.age` pair. Until a root-last v2 rekey transaction is implemented,
export the decrypted data into a new v2 store created with the new passphrase.

Change the encryption passphrase for all files:

    just rekey "new-secret"                             # re-encrypt with new passphrase
    ZEROTRUST_PASSPHRASE="new-secret" just mount        # mount with new passphrase

Or directly:

    cargo run -- --new-passphrase "new-secret"

During rotation the filesystem mounts read-only - existing files are readable but writes
return EROFS. Once re-encryption finishes the filesystem becomes read-write again.

#### How rekey works

The rekey process has two phases. Originals are not replaced until staging is complete, and
post-commit recovery evidence is preserved when an operation cannot finish automatically.

**Phase 1 - Staging**: Each file is decrypted with the old passphrase, re-encrypted with
the new passphrase, and written into a hidden `.rekey_staging/` directory. The original
files remain untouched throughout this phase.

**Phase 2 - Rename pass**: Once every file has been staged, an immutable `_rekey.manifest`
is written (the commit point). It records a compact fingerprint for every staged ciphertext.
Each staged file is then atomically renamed over its original via a single `rename()` syscall.
After a crash, recovery uses the fingerprint to distinguish a completed rename from a missing
file without rewriting the whole manifest after every item. The encrypted index (`_index.age`)
is always renamed last - until that final rename, the old passphrase can still open the drive.

After all renames complete, `.rekey_staging/`, `_rekey.manifest`, and `_rekey.lock` are
removed.

#### Failure handling

| Scenario | What happens | Recovery |
|---|---|---|
| **Ctrl+C / crash during Phase 1** (staging) | Originals untouched. `.rekey_staging/` contains partial re-encrypted files. | Next `--new-passphrase` wipes the partial staging and starts fresh. Use `--continue-rekey` to resume instead (see below). |
| **Ctrl+C / crash during Phase 2** (rename pass) | Some files may already be renamed; immutable fingerprints identify them. | **Automatic** - on next startup `recover_interrupted_rekey()` verifies the manifest and completes the remaining renames. No user action needed. |
| **Wrong old passphrase** | Decryption of `_index.age` fails immediately. | Lock file removed, clear error shown. No files modified. |
| **Disk full during staging** | Write fails, no manifest written. | `.rekey_staging/` cleaned up on next run. Originals intact. |
| **Lock file exists** (`_rekey.lock`) | Another rekey may be in progress locally or on a synced device. | Machine-bound locks distinguish this host from a foreign owner and fail closed for foreign, legacy PID-only, or malformed records. Remove one manually only after verifying that no migration or rekey is active on any synced device. |
| **New passphrase same as old** | Rejected before any work begins. | - |

#### Resuming an interrupted rekey

By default, if a `.rekey_staging/` directory exists from a previous cancelled run, a fresh
`--new-passphrase` invocation **wipes it and starts over**. This prevents mixed-key
corruption if you changed your mind about the new passphrase.

To resume where you left off (skipping already-staged files), use `--continue-rekey`:

    just rekey-resume "same-passphrase"                 # resume interrupted staging

Or directly:

    cargo run -- --new-passphrase "same-passphrase" --continue-rekey

Before resuming, the passphrase is cryptographically probed against the staged index or one staged
blob. Each staged item is then reused only if it decrypts to the current plaintext; otherwise that
item is regenerated. ZeroTrust Drive does not persist the passphrase in the encrypted backing
store. Supplying it as a command-line argument can still leave it in shell history and expose it
temporarily through process inspection. Use a protected `ZEROTRUST_PASSPHRASE` injection method
and clear the variable after use; the client does not currently provide an interactive prompt.

### Limits

Filenames are limited by this implementation to **255 UTF-8 bytes** on its POSIX targets.
Operations that exceed this limit (create, mkdir, rename) return `ENAMETOOLONG`.

V2 content uses a 4 MiB logical chunk grid and short random 128-bit object IDs. A tail or sparse
chunk stores only its meaningful prefix rather than padding every ciphertext object to 4 MiB.
Tree nodes have at most 256 children and file roots have a bounded radix height. Referenced object names are never overwritten.
V1 disk filenames begin with a 6-digit hex counter (`000001.age` through `ffffff.age`) and grow
beyond 6 digits when needed. The counter increases monotonically and is not reused after normal
deletions. Rekey and format-migration transactions currently support at most **100,000 manifest
entries** and a 64 MiB manifest. Live encrypted metadata indexes are capped at 64 MiB before decryption.
The same cap is enforced before writing a new index, and authenticated index graph/blob/counter
invariants are validated before mount and persistence. If acknowledged live mutations push the index
over the cap, persistence latches read-only; those uncommitted mutations are not automatically
rolled back, so operate comfortably below the limit. These explicit bounds prevent malformed
cloud-supplied metadata from causing unbounded allocation.

Maintenance locks carry a hashed operating-system machine identity and PID. This prevents a lock
synced from another computer from being deleted merely because its PID is absent locally. It is
still detection, not a distributed lease: eventual consistency can hide simultaneous lock creation,
so concurrent computers remain unsupported.

### Encryption

Files are encrypted at rest with **XChaCha20-Poly1305**, an AEAD (Authenticated Encryption
with Associated Data) construction. It extends the ChaCha20-Poly1305 design with a 192-bit
(24-byte) nonce while retaining a 256-bit key. That extended-nonce construction is related to,
but not the same wire algorithm as, the ChaCha20-Poly1305 variants used by common network
protocols. Random 192-bit nonces make accidental collision negligibly probable even when one
long-lived per-drive key encrypts millions of objects and index generations.

AEAD provides both confidentiality and integrity: if a file is tampered with or corrupted (e.g.
during cloud sync), decryption fails rather than silently returning garbage. V2 associated data
binds each ciphertext to its object role and random object ID, while every authenticated parent
stores the complete BLAKE2s-256 ciphertext digest of its child. V1 blobs remain bound to their
stable on-disk filename. An attacker cannot swap a chunk, tree, index, or generation into another
role without authentication failing. Whole-store rollback to an internally consistent old root is
not defended against; that requires a trusted monotonic anchor outside the synchronized store.

The passphrase is never used as a key directly. It is stretched into the 256-bit key with
**Argon2id**, the memory-hard KDF that won the Password Hashing Competition, using a per-drive
random 16-byte salt and OWASP-baseline cost parameters (19 MiB memory, 2 iterations). The salt
and parameters are stored in plaintext in `_kdf.json` - a salt is not a secret; its job is to
defeat precomputation and to make two drives with the same passphrase derive different keys.
Memory-hardness is the primary defense against offline brute-forcing of the passphrase against
the cloud-stored ciphertext. The salt is nevertheless availability-critical: preserve an
independent exact copy of `_kdf.json` with every backup.

Apple FileVault uses AES-XTS, which is designed for fixed-size disk sectors and does not
authenticate. XChaCha20-Poly1305 is a better fit for file-level encryption with cloud sync
because its built-in authentication detects corruption or tampering automatically.

#### On-disk format versions

| Version | Drives | Key derivation | Cipher |
|---|---|---|---|
| **v2** | current new stores - have `_root.age` | Argon2id + per-drive salt | XChaCha20-Poly1305 immutable chunks, trees, generations, and root |
| **v1** | 0.7+ - have a `_kdf.json` | Argon2id + per-drive salt | XChaCha20-Poly1305 (24-byte nonce) |
| **v0** | pre-0.7 - no `_kdf.json` | homemade iterative KDF, no salt | ChaCha20-Poly1305 (12-byte nonce) |

The v1 format fixes two weaknesses in v0: a custom KDF with no memory-hardness (cheap to
brute-force offline against the at-rest blobs) and a 96-bit nonce (random nonces risk a
birthday-bound collision under a single long-lived key, which is catastrophic for a stream
cipher). A pre-0.7 drive refuses to mount until it is upgraded in place with the current
passphrase:

    zerotrust-drive --migrate-format

The migration re-encrypts every blob, so a cloud-sync backend will re-upload the whole drive.
It is crash-safe - re-run the same command to resume an interrupted migration.

After reaching v1, migrate explicitly to v2:

    zerotrust-drive --migrate-v2

The authenticated migration plan pins the complete v1 source generation and per-inode receipts
make conversion resumable. The v2 root is published last through the same normal-write transaction.
V1 blobs, the v1 index, the migration plan, and receipts are retained as recovery evidence; no
automatic garbage collection runs. Because v1 has one authentication tag per complete blob, this
one-time conversion still needs memory for the largest v1 file. Normal v2 operation is bounded.

#### Cloud-backed rekey and migration

Before either maintenance operation, unmount this store on every device, wait until cloud sync
reports complete, and create an independent recoverable snapshot. Pause Google Drive sync while
the local operation runs. For the iCloud beta target, first confirm the folder is fully downloaded
and synchronized, then disconnect the Mac from the network because iCloud has no equivalent
general Pause Sync control. Validate the transformed store locally before reconnecting or resuming
sync. Do not mount it on another device until every immutable object and `_root.age` has uploaded.
For Yandex Disk, also preflight the current 30-day upload allowance before migration.

### Building

Build an optimized release binary and install it as `zdrive`:

    just release                                        # build + install to ~/.cargo/bin/zdrive
    just mount-release                                  # mount using the installed zdrive binary

#### Cross-compilation

Build release binaries for the supported macOS and Linux targets (the Linux cross-build requires
[cross](https://github.com/cross-rs/cross)):

    just release-macos                                  # aarch64-apple-darwin   -> target/dist/zdrive-macos-aarch64
    just release-linux                                  # x86_64-unknown-linux   -> target/dist/zdrive-linux-x86_64
    just release-all                                    # both supported targets

The Linux target uses `cross`, which handles toolchains and sysroot dependencies via Docker.
Install it with `cargo install cross`. Windows does not compile with the current Unix-only
`fuser` backend; `just release-windows` remains only as a fail-fast explanation of that limit.
