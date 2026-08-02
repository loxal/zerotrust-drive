# ZeroTrust Drive

FUSE-based encrypted overlay filesystem. You work with decrypted files in the mount directory
while all data is stored encrypted at rest with XChaCha20-Poly1305 AEAD encryption, under a key
derived from your passphrase with Argon2id (the `.age` file extension is a naming convention -
not the age crate).

The cloud storage service and account receive only ciphertext through the backing directory. A
provider's desktop sync process still runs on the endpoint and may have local access to the
separate plaintext mount, so ordinary endpoint security remains necessary. New stores use the v2 format:
immutable authenticated chunks on a 4 MiB logical grid, sparse copy-on-write radix trees, immutable metadata
generations, and a small authenticated `_root.age` visibility pointer. A plaintext `_kdf.json`
holds only the key-derivation salt and bounded cost parameters (not secret - see
[Encryption](#encryption)). The encrypted index stores the full directory tree, permissions,
sizes, timestamps, and opaque file-root references. Without the correct passphrase, this metadata
and every data object are unreadable.

Point `--encrypted-dir` at a fully local cloud-sync folder and its provider handles replication
of the ciphertext. Placeholder/on-demand storage is not a safe backing filesystem for this tool.

V2 does not buffer complete open files. Read, write, and flush memory are bounded independently of
logical file size: random I/O decrypts at most one fixed chunk plus a bounded tree path, and flush
contains metadata rather than complete file content. Sparse writes do not materialize holes.
Existing v1 stores still mount for compatibility and retain their legacy whole-file RAM behavior
until explicitly migrated with `--migrate-v2`.

If the encrypted storage is modified externally (e.g. by cloud sync) while mounted,
zerotrust-drive fingerprints the authenticated root (or the legacy v1 index) and refuses the next local commit instead of
overwriting the external generation. It also fails closed when it finds provider-generated sibling
blobs, indexes, KDF metadata, or maintenance controls; iCloud index-placeholder names; ambiguous
non-UTF-8 backing entries; an unreferenced canonical blob that could collide with future allocation;
malformed or provider-conflicted staging names; or a stale temp from an interrupted write. Valid
transaction-ready files left before authenticated intent publication remain unreferenced evidence:
they are preserved, do not select a generation, and do not prevent a fresh retry.
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
user-facing pause-sync control make migration and recovery less predictable. The current client
does not yet route every backing-store operation through `NSFileCoordinator`; adding only partial
coordination would give a false guarantee and can introduce nested-coordination failures.
Apple also documents a 50 GB limit for an individual iCloud Drive folder or file. The relevant
number here is the complete accumulated ciphertext footprint, including unreachable copy-on-write
objects and retained evidence, not the visible plaintext size. Until evidence-aware garbage
collection exists, use iCloud only for small, low-write stores that remain comfortably below that
limit, monitor the encrypted folder, and migrate away before it approaches 50 GB.

Yandex Disk is an experimental secondary target, strongest when its official Linux sync daemon is
useful. Prefer a fully local synchronized folder, not WebDAV. Its documented rolling 30-day upload
allowance is twice the current storage capacity, which is a material constraint for immutable
copy-on-write churn and migrations. Yandex also warns that simultaneous multi-device editing can
create duplicate conflict copies or lose files. Keep the same one-writer and independent-backup
discipline.

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
evidence-retention, and recovery checkpoint, then retry recovery against that state. They do not
emulate process death, torn writes, or loss of pre-fsync page-cache state; the actual-crash claim
also relies on the documented filesystem contract. See the
[v2 crash-consistency argument](docs/v2-crash-consistency.md).

Writable v2 startup traverses and authenticates every file root, tree, and chunk reachable from
the active generation. This prevents a partially synchronized machine from committing on top of
missing data, but can make mount time proportional to live data and can force placeholder
downloads. Keep the complete backing folder local before mounting.

V2 is currently a durability-focused beta. Each small FUSE write performs chunk/tree/file-root
copy-on-write immediately, so repeated writes inside one 4 MiB chunk can amplify uploads.
Automatic garbage collection is not implemented: old generations, orphan objects, and retained
transaction evidence accumulate. Bounded dirty-chunk coalescing and evidence-aware compaction are
required before recommending sustained write-heavy production use.

Legacy v1 commits still have the historical blob-before-index crash window. Migrate important v1
stores before relying on root-last atomicity.

A brand-new store publishes `_kdf.json` before its first authenticated root. If initialization stops
between those publications, restart refuses the KDF-only directory because it is indistinguishable
from incompletely synchronized existing data. Preserve and inspect the directory; delete it only
when you can prove that no user data was ever committed, or restore the missing cloud generation.
Back up `_kdf.json` separately with the encrypted store. Its salt is not secret, but losing or
corrupting this single file makes every ciphertext undecryptable even with the correct passphrase.

### Prerequisites

A FUSE implementation is required. Install the one for your OS:

- **macOS** - [macFUSE](https://macfuse.github.io/)
- **Linux** - `libfuse-dev` (Debian/Ubuntu: `sudo apt install libfuse-dev`, Fedora: `sudo dnf install fuse-devel`)
- **Windows** - not supported (would require [WinFSP](https://winfsp.dev/) and a different FUSE crate)

#### macOS: Full Disk Access required

On macOS, the system's privacy framework (TCC) restricts which applications can access FUSE
mounts. If `ls`, `du`, or other commands return "Operation not permitted" or "Permission
denied" on the mount point, the terminal application you are using does not have Full Disk
Access.

To fix this, go to **System Settings > Privacy & Security > Full Disk Access** and enable
it for your terminal application (e.g. Terminal.app, iTerm2, Alacritty).

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

Before resuming, the passphrase is **cryptographically verified** against every recognized
staged blob and staged index. If any decryption fails, the resume is rejected with a clear
error. No passphrase is ever stored on disk.

### Limits

Filenames are limited to **255 bytes** - the standard maximum shared by ext4, APFS, and
NTFS. Operations that exceed this limit (create, mkdir, rename) return `ENAMETOOLONG`.

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
with Associated Data) cipher. It is the extended-nonce variant of the ChaCha20-Poly1305
construction standardized by the IETF in RFC 8439 - the same cipher used by WireGuard, TLS 1.3,
SSH (OpenSSH), and Google's QUIC. The 256-bit key makes it equally secure to AES-256, and its
192-bit (24-byte) random nonce is wide enough that randomly generated nonces never collide in
practice, even when one long-lived per-drive key encrypts millions of blobs and index rewrites.

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
For Yandex Disk, also preflight the rolling upload allowance before migration.

### Building

Build an optimized release binary and install it as `zdrive`:

    just release                                        # build + install to ~/.cargo/bin/zdrive
    just mount-release                                  # mount using the installed zdrive binary

#### Cross-compilation

Build release binaries for all platforms (requires [cross](https://github.com/cross-rs/cross)):

    just release-macos                                  # aarch64-apple-darwin   -> target/dist/zdrive-macos-aarch64
    just release-linux                                  # x86_64-unknown-linux   -> target/dist/zdrive-linux-x86_64
    just release-windows                                # x86_64-pc-windows-gnu  -> target/dist/zdrive-windows-x86_64.exe
    just release-all                                    # all three platforms

The Linux and Windows targets use `cross`, which handles toolchains and sysroot
dependencies via Docker. Install it with `cargo install cross`. Note that while the
Windows binary compiles, runtime support requires replacing `fuser` with a WinFSP-based
FUSE crate.
