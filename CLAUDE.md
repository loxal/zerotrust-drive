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

- **Encrypted storage**: `~/g.drive/.zerotrust.drive.encrypted/` (v2 immutable authenticated objects + `_root.age` + plaintext `_kdf.json`; legacy v1 stores retain opaque `.age` blobs + `_index.age`)
- **Decrypted mount**: `~/z.drive/` (FUSE mount; v2 file I/O is chunked, while legacy v1 open files are RAM-backed)
- **Index**: v2 stores an immutable encrypted metadata snapshot referenced through an authenticated generation and `_root.age`; v1 uses mutable `_index.age`. Both describe the directory tree, permissions, sizes, timestamps, and opaque backing references.
- **KDF metadata**: `_kdf.json` (plaintext, salts are not secret) holds the per-drive Argon2id salt + cost params. Its presence marks a v1 (0.7+) drive
- **On-disk format**: v2 = immutable XChaCha20-Poly1305 chunks and sparse copy-on-write trees, immutable metadata generations, and an authenticated root switched last by atomic exchange/no-replace. V1 reads remain supported and explicit `--migrate-v2` is resumable without deleting the source. V1 = Argon2id + XChaCha20-Poly1305 whole-file blobs. V0 (pre-0.7) = legacy KDF + ChaCha20-Poly1305; upgrade it first with `--migrate-format`.
- **Memory**: normal v2 read, write, and flush memory is bounded independently of complete file size. A mount-wide overlay coalesces at most sixteen dirty 4 MiB slots and tracks at most 256 dirty inodes before pressure flush. V1 reads/writes and the one-time v1 migration still authenticate a complete legacy blob in memory.

## Key Files

| File | Purpose |
|------|---------|
| `src/main.rs` | CLI entry point (clap); `--migrate-format` v0→v1 upgrade |
| `src/fs.rs` | FUSE filesystem + encrypted directory index (InodeEntry tree) |
| `src/crypto.rs` | Argon2id KDF + XChaCha20-Poly1305 encrypt/decrypt (+ retained v0 legacy readers for migration) |
| `src/v2.rs` | Immutable chunk/tree objects, copy-on-write generations, authenticated root-last commit and recovery |
| `src/v2_gc.rs` | Evidence-aware offline v2 preview, reversible quarantine/restore, and read-only compatibility handling for disabled physical purge |
| `src/v2_migrate.rs` | Explicit resumable v1-to-v2 migration with authenticated plan and per-file receipts |
| `src/fault.rs` | Deterministic returned-error and test-only real-process kill injection at durability boundaries |
| `src/migrate.rs` | Crash-safe v0→v1 on-disk format migration |
| `src/rekey.rs` | Passphrase re-keying (keeps the drive salt; new passphrase → new key) |

## Conventions

- Rust edition 2024
- License: AGPL-3.0-only
- CI: GitHub Actions
- Passphrase via `ZEROTRUST_PASSPHRASE` env var or interactive prompt
