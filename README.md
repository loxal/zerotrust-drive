# ZeroTrust Drive

FUSE-based encrypted overlay filesystem. You work with decrypted files in the mount directory
while all data is stored encrypted at rest with XChaCha20-Poly1305 AEAD encryption, under a key
derived from your passphrase with Argon2id (the `.age` file extension is a naming convention —
not the age crate).

The cloud provider never sees plaintext file names or content. The encrypted storage directory
contains opaque data files (`000001.age`, `000002.age`, ...), an encrypted index
(`_index.age`), and a small plaintext `_kdf.json` holding the key-derivation salt and cost
parameters (not secret — see [Encryption](#encryption)). The index stores the full directory tree — filenames, permissions, sizes,
timestamps, and the mapping from each real filename to its opaque `.age` counterpart. It is
encrypted with the same passphrase and rewritten when metadata changes are committed. Without the
correct passphrase, the index (and therefore the entire directory structure) is unreadable.

Point `--encrypted-dir` at a fully local cloud-sync folder and its provider handles replication
of the ciphertext. Placeholder/on-demand storage is not a safe backing filesystem for this tool.

This is an in-memory filesystem — all file content is held in RAM while open.
Not recommended for files larger than available memory.

If the encrypted storage is modified externally (e.g. by cloud sync) while mounted,
zerotrust-drive fingerprints the encrypted index and refuses the next local commit instead of
overwriting the external generation. Unmount and reconcile or remount to pick up external
changes. Never mount the same store on two computers at once.

### Cloud backend guidance

The primary supported target is a dedicated folder in Google Drive `My Drive`, with Google
Drive for desktop configured to **Mirror files**. Mirror mode keeps ordinary local files and
best matches the POSIX `fsync` and atomic-rename behavior used here. Do not use Google Drive
Stream mode or a Shared Drive as the backing store.

iCloud Drive is a macOS-only beta target. Mark the complete encrypted backing folder
**Keep Downloaded** before use. iCloud's File Provider placeholders and lack of a general
user-facing pause-sync control make migration and recovery less predictable.

Neither provider supplies a multi-file transaction, a cross-machine writer lock, or a backup.
Use one active mount, wait for sync to finish before switching computers, and keep an independent
versioned snapshot. See the [2026 cloud backend and user-experience review](docs/cloud-storage-backends-2026-08.md)
for the technical tradeoffs, vendor documentation, and reported failure modes.

### Prerequisites

A FUSE implementation is required. Install the one for your OS:

- **macOS** — [macFUSE](https://macfuse.github.io/)
- **Linux** — `libfuse-dev` (Debian/Ubuntu: `sudo apt install libfuse-dev`, Fedora: `sudo dnf install fuse-devel`)
- **Windows** — not supported (would require [WinFSP](https://winfsp.dev/) and a different FUSE crate)

#### macOS: Full Disk Access required

On macOS, the system's privacy framework (TCC) restricts which applications can access FUSE
mounts. If `ls`, `du`, or other commands return "Operation not permitted" or "Permission
denied" on the mount point, the terminal application you are using does not have Full Disk
Access.

To fix this, go to **System Settings > Privacy & Security > Full Disk Access** and enable
it for your terminal application (e.g. Terminal.app, iTerm2, Alacritty).

### Directory Layout

    ~/g.drive/.zerotrust.drive.encrypted/    encrypted storage — synced by Google Drive (ciphertext + non-secret KDF salt)
    ~/z.drive/                              FUSE mount point — local, NOT synced (you work here)

The encrypted directory is auto-managed by zerotrust-drive. Do not modify its contents directly.
Both paths are overridable via justfile variables or CLI flags `--encrypted-dir` / `--decrypted-dir`.

### Usage

    ZEROTRUST_PASSPHRASE="my-secret" just mount         # mount or create with a real secret
    just populate                                       # create test files on the mounted filesystem
    just umount                                         # unmount (decrypted dir becomes empty)
    just mount                                          # remount — files reappear from encrypted storage
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

Change the encryption passphrase for all files:

    just rekey "new-secret"                             # re-encrypt with new passphrase
    ZEROTRUST_PASSPHRASE="new-secret" just mount        # mount with new passphrase

Or directly:

    cargo run -- --new-passphrase "new-secret"

During rotation the filesystem mounts read-only — existing files are readable but writes
return EROFS. Once re-encryption finishes the filesystem becomes read-write again.

#### How rekey works

The rekey process has two phases. Originals are not replaced until staging is complete, and
post-commit recovery evidence is preserved when an operation cannot finish automatically.

**Phase 1 — Staging**: Each file is decrypted with the old passphrase, re-encrypted with
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
| **Lock file exists** (`_rekey.lock`) | Another rekey may be in progress. | Refuses to start. If no other process is running, delete the lock file manually. |
| **New passphrase same as old** | Rejected before any work begins. | — |

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

Filenames are limited to **255 bytes** — the standard maximum shared by ext4, APFS, and
NTFS. Operations that exceed this limit (create, mkdir, rename) return `ENAMETOOLONG`.

Disk filenames use a 6-digit hex counter (`000001.age` through `ffffff.age`), supporting
up to **16,777,215 files**. The counter increases monotonically and is never reused, even
after deletions. If the counter exceeds 6 digits the filenames simply grow longer. Rekey and
format-migration transactions currently support at most **100,000 manifest entries** and a
64 MiB manifest; these explicit bounds prevent a malformed cloud-supplied manifest from causing
unbounded memory allocation.

### Encryption

Files are encrypted at rest with **XChaCha20-Poly1305**, an AEAD (Authenticated Encryption
with Associated Data) cipher. It is the extended-nonce variant of the ChaCha20-Poly1305
construction standardized by the IETF in RFC 8439 — the same cipher used by WireGuard, TLS 1.3,
SSH (OpenSSH), and Google's QUIC. The 256-bit key makes it equally secure to AES-256, and its
192-bit (24-byte) random nonce is wide enough that randomly generated nonces never collide in
practice, even when one long-lived per-drive key encrypts millions of blobs and index rewrites.

AEAD provides both confidentiality and integrity: if a file is tampered with or corrupted (e.g.
during cloud sync), decryption fails rather than silently returning garbage. Each blob is
additionally bound to its on-disk filename through the AEAD associated data, and the index is
bound to a domain tag — so an attacker who can write to the encrypted store (e.g. a compromised
cloud-sync account) cannot swap one blob's ciphertext over another's, or substitute the index
for a data blob, without the read failing. (Whole-object rollback — restoring an older
authenticated copy of the same file — is not defended against; that would require a trusted
monotonic anchor the on-disk format does not have.)

The passphrase is never used as a key directly. It is stretched into the 256-bit key with
**Argon2id**, the memory-hard KDF that won the Password Hashing Competition, using a per-drive
random 16-byte salt and OWASP-baseline cost parameters (19 MiB memory, 2 iterations). The salt
and parameters are stored in plaintext in `_kdf.json` — a salt is not a secret; its job is to
defeat precomputation and to make two drives with the same passphrase derive different keys.
Memory-hardness is the primary defense against offline brute-forcing of the passphrase against
the cloud-stored ciphertext.

Apple FileVault uses AES-XTS, which is designed for fixed-size disk sectors and does not
authenticate. XChaCha20-Poly1305 is a better fit for file-level encryption with cloud sync
because its built-in authentication detects corruption or tampering automatically.

#### On-disk format versions

| Version | Drives | Key derivation | Cipher |
|---|---|---|---|
| **v1** | 0.7+ — have a `_kdf.json` | Argon2id + per-drive salt | XChaCha20-Poly1305 (24-byte nonce) |
| **v0** | pre-0.7 — no `_kdf.json` | homemade iterative KDF, no salt | ChaCha20-Poly1305 (12-byte nonce) |

The v1 format fixes two weaknesses in v0: a custom KDF with no memory-hardness (cheap to
brute-force offline against the at-rest blobs) and a 96-bit nonce (random nonces risk a
birthday-bound collision under a single long-lived key, which is catastrophic for a stream
cipher). A pre-0.7 drive refuses to mount until it is upgraded in place with the current
passphrase:

    zerotrust-drive --migrate-format

The migration re-encrypts every blob, so a cloud-sync backend will re-upload the whole drive.
It is crash-safe — re-run the same command to resume an interrupted migration.

#### Cloud-backed rekey and migration

Before either maintenance operation, unmount this store on every device, wait until cloud sync
reports complete, and create an independent recoverable snapshot. Pause Google Drive sync while
the local operation runs. For the iCloud beta target, first confirm the folder is fully downloaded
and synchronized, then disconnect the Mac from the network because iCloud has no equivalent
general Pause Sync control. Validate the transformed store locally before reconnecting or resuming
sync. Do not mount it on another device until every changed blob and `_index.age` has uploaded.

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
