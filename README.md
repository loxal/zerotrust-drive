# ZeroTrust Drive

FUSE-based encrypted overlay filesystem. You work with decrypted files in the mount directory
while all data is stored encrypted at rest using ChaCha20-Poly1305 AEAD encryption (the `.age`
file extension is a naming convention — not the age crate).

Google Drive never sees plaintext file names or content. The encrypted storage directory
contains only opaque files (`000001.age`, `000002.age`, ...) and an encrypted index
(`_index.age`) that maps them to their real names. Point `--encrypted-dir` at a Google Drive
sync folder and Google Drive handles upload/sync of the ciphertext automatically.

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

    ~/gdrive/.zerotrust.drive.encrypted/    encrypted storage — synced by Google Drive (ciphertext only)
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

Set the encryption passphrase via env var or CLI flag. If neither is set, a default
demo passphrase is used and a warning is shown at mount.

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

**Cancel & resume**: The operation can be interrupted at any time (Ctrl+C, crash, power loss).
No files are ever lost. Re-encrypted files are staged in a hidden `.rekey_staging/` directory
and only swapped into place after all files are ready, so the originals are never modified
in place.

If interrupted during the rename phase, recovery is automatic on next startup. If interrupted
during the staging phase, a fresh `--new-passphrase` wipes the partial staging and starts over
(safe — originals are untouched). To resume staging instead:

    just rekey-resume "same-passphrase"                 # resume interrupted staging

The passphrase is cryptographically verified against the already-staged files — if you
provide a different passphrase, the resume is rejected to prevent mixed-key corruption.

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
