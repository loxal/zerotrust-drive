# ZeroTrust Drive

FUSE-based encrypted overlay filesystem. You work with decrypted files in the mount directory
while all data is stored encrypted at rest using ChaCha20-Poly1305 AEAD encryption (the `.age`
file extension is a naming convention — not the age crate).

Google Drive never sees plaintext file names or content. The encrypted storage directory
contains only opaque files (`000001.age`, `000002.age`, ...) and an encrypted index
(`_index.age`). The index stores the full directory tree — filenames, permissions, sizes,
timestamps, and the mapping from each real filename to its opaque `.age` counterpart. It is
encrypted with the same passphrase and re-written on every metadata change. Without the
correct passphrase, the index (and therefore the entire directory structure) is unreadable.

Point `--encrypted-dir` at a Google Drive sync folder and Google Drive handles upload/sync
of the ciphertext automatically.

This is an in-memory filesystem — all file content is held in RAM while open.
Not recommended for files larger than available memory.

If the encrypted storage is modified externally (e.g. by cloud sync) while mounted,
zerotrust-drive detects the conflict, logs a warning, and preserves the in-memory state.
Unmount and remount to pick up external changes.

### Prerequisites

A FUSE implementation is required. Install the one for your OS:

- **macOS** — [macFUSE](https://macfuse.github.io/)
- **Linux** — `libfuse-dev` (Debian/Ubuntu: `sudo apt install libfuse-dev`, Fedora: `sudo dnf install fuse-devel`)
- **Windows** — not supported (would require [WinFSP](https://winfsp.dev/) and a different FUSE crate)

### Directory Layout

    ~/g.drive/.zerotrust.drive.encrypted/    encrypted storage — synced by Google Drive (ciphertext only)
    ~/z.drive/                              FUSE mount point — local, NOT synced (you work here)

The encrypted directory is auto-managed by zerotrust-drive. Do not modify its contents directly.
Both paths are overridable via justfile variables or CLI flags `--encrypted-dir` / `--decrypted-dir`.

### Usage

    just mount                                          # mount (warns if using default passphrase)
    just populate                                       # create test files on the mounted filesystem
    just umount                                         # unmount (decrypted dir becomes empty)
    just mount                                          # remount — files reappear from encrypted storage
    just test                                           # run unit tests
    just release                                        # build optimized release binary
    just clean                                          # remove build artifacts and encrypted storage

### Passphrase

Set the encryption passphrase via env var or CLI flag. If neither is set, the default
passphrase `zerotrust-demo-passphrase` is used and a warning is shown at mount.
Do not rely on this for real data.

    ZEROTRUST_PASSPHRASE="my-secret" just mount         # via env var (recommended)
    cargo run -- --passphrase "my-secret"                # via CLI flag

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

The rekey process has two phases. Originals are never modified in place — the design
guarantees that no data is lost regardless of when or how the process is interrupted.

**Phase 1 — Staging**: Each file is decrypted with the old passphrase, re-encrypted with
the new passphrase, and written into a hidden `.rekey_staging/` directory. The original
files remain untouched throughout this phase.

**Phase 2 — Rename pass**: Once every file has been staged, a `_rekey.manifest` is written
(the commit point). Each staged file is then atomically renamed over its original via a
single `rename()` syscall. After each successful rename the manifest is updated on disk,
so the exact progress is always known. The encrypted index (`_index.age`) is always renamed
last — until that final rename, the old passphrase can still open the drive.

After all renames complete, `.rekey_staging/`, `_rekey.manifest`, and `_rekey.lock` are
removed.

#### Failure handling

| Scenario | What happens | Recovery |
|---|---|---|
| **Ctrl+C / crash during Phase 1** (staging) | Originals untouched. `.rekey_staging/` contains partial re-encrypted files. | Next `--new-passphrase` wipes the partial staging and starts fresh. Use `--continue-rekey` to resume instead (see below). |
| **Ctrl+C / crash during Phase 2** (rename pass) | Some files already renamed, manifest tracks which. | **Automatic** — on next startup `recover_interrupted_rekey()` reads the manifest and completes the remaining renames. No user action needed. |
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

Before resuming, the passphrase is **cryptographically verified** — one file from the
staging directory is test-decrypted with the provided new passphrase. If decryption fails,
the resume is rejected with a clear error. No passphrase is ever stored on disk.

### Limits

Filenames are limited to **255 bytes** — the standard maximum shared by ext4, APFS, and
NTFS. Operations that exceed this limit (create, mkdir, rename) return `ENAMETOOLONG`.

Disk filenames use a 6-digit hex counter (`000001.age` through `ffffff.age`), supporting
up to **16,777,215 files**. The counter increases monotonically and is never reused, even
after deletions. If the counter exceeds 6 digits the filenames simply grow longer — there
is no hard cap.

### Encryption

zerotrust-drive uses ChaCha20-Poly1305, an AEAD (Authenticated Encryption with Associated
Data) cipher standardized by the IETF in RFC 8439. It provides both confidentiality and
integrity — if a file is tampered with or corrupted (e.g. during cloud sync), decryption
fails rather than silently returning garbage.

The same cipher is used by WireGuard, TLS 1.3, SSH (OpenSSH), Google's QUIC protocol, and
Android disk encryption. It is a 256-bit cipher considered equally secure to AES-256.

Apple FileVault uses AES-XTS, which is designed for fixed-size disk sectors and does not
provide authentication. ChaCha20-Poly1305 is a better fit for file-level encryption with
cloud sync because its built-in authentication detects corruption or tampering automatically.

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
