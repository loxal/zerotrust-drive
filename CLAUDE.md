# CLAUDE.md — zerotrust-drive

## Overview

FUSE-based encrypted overlay filesystem. Files are stored encrypted at rest using
XChaCha20-Poly1305 AEAD with keys derived via Argon2id. Point `--encrypted-dir` at a
Google Drive sync folder for transparent cloud backup of encrypted content.

## Build & Run

```bash
just build                  # cargo build
just mount                  # Build + mount (prompts for passphrase)
just mount-release          # Mount using installed binary
just umount                 # Unmount
cargo test                  # Run tests
```

## Architecture

- **Encrypted storage**: `~/g.drive/.zerotrust.drive.encrypted/` (opaque `.age` files + encrypted `_index.age` + plaintext `_kdf.json`)
- **Decrypted mount**: `~/z.drive/` (FUSE mount, in-memory)
- **Index**: `_index.age` stores the full directory tree (filenames, permissions, sizes, timestamps, file→blob mapping), encrypted with the same passphrase
- **KDF metadata**: `_kdf.json` (plaintext, salts are not secret) holds the per-drive Argon2id salt + cost params. Its presence marks a v1 (0.7+) drive
- **On-disk format**: v1 = Argon2id + per-drive 16-byte salt + XChaCha20-Poly1305 (24-byte nonce), with each blob AAD-bound to its disk filename and the index to a domain tag (defeats on-disk blob-swap/substitution). v0 (pre-0.7) = homemade KDF + ChaCha20-Poly1305 (12-byte nonce), no `_kdf.json`. Upgrade a v0 drive in place with `--migrate-format` (crash-safe; re-run to resume)
- **In-memory**: all file content held in RAM while open — not for files larger than available memory

## Key Files

| File | Purpose |
|------|---------|
| `src/main.rs` | CLI entry point (clap); `--migrate-format` v0→v1 upgrade |
| `src/fs.rs` | FUSE filesystem + encrypted directory index (InodeEntry tree) |
| `src/crypto.rs` | Argon2id KDF + XChaCha20-Poly1305 encrypt/decrypt (+ retained v0 legacy readers for migration) |
| `src/migrate.rs` | Crash-safe v0→v1 on-disk format migration |
| `src/rekey.rs` | Passphrase re-keying (keeps the drive salt; new passphrase → new key) |

## Conventions

- Rust edition 2024
- License: AGPL-3.0-only
- CI: GitHub Actions
- Passphrase via `ZEROTRUST_PASSPHRASE` env var or interactive prompt
