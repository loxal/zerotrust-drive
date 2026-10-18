<!-- SPDX-FileCopyrightText: Copyright 2026 Alexander Orlov <info@lifub.com> -->

# CLAUDE.md — zerotrust-drive

## Overview

FUSE-based encrypted overlay filesystem. Files are stored encrypted at rest using
XChaCha20-Poly1305 AEAD with keys derived via Argon2id. Point `--encrypted-dir` at a
Google Drive sync folder for transparent cloud backup of encrypted content, or keep it
local and let `--remote` / `zdrive remote` replicate the ciphertext through the Drive API.

## Build & Run

```bash
just build                  # cargo build
just mount                  # Build + mount (prompts for passphrase)
just mount-release          # Mount using installed binary
just umount                 # Unmount (Ctrl+C in the mounting terminal also unmounts and flushes)
just rekey                  # Rotate a v1 passphrase (prompts, or ZEROTRUST_NEW_PASSPHRASE)
just clean                  # cargo clean only; never touches the store or mount point
just icons                  # rebuild assets/icon/zerotrust-drive.icns from its SVG (rsvg-convert + iconutil)
cargo test                  # Run tests (hermetic: the Drive API tests use an in-process fake server)
# Live kernel-mounted signal/busy-unmount tests (Linux, needs fuse3):
ZDRIVE_RUN_LIVE_FUSE_TESTS=1 cargo test --locked --test live_fuse -- --ignored --test-threads=1
# Live Google Drive tests and the Drive-for-desktop benchmark (local only, need a configured
# remote; see the module docs of src/remote/live_tests.rs and src/remote/bench_tests.rs):
ZDRIVE_RUN_GDRIVE_TESTS=1 ZDRIVE_GDRIVE_REMOTE=NAME cargo test --locked remote::cli::live -- --ignored --test-threads=1
```

The justfile must never interpolate a passphrase: the binary reads the inherited
environment or prompts on `/dev/tty`.

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
| `src/main.rs` | CLI entry point (clap); `--migrate-format` v0→v1 upgrade; mounts through `fuser::Session` |
| `src/shutdown.rs` | SIGINT/SIGTERM/SIGHUP via a `sigwait` thread: non-lazy unmount while mounted so `destroy` flushes; default action otherwise |
| `src/prompt.rs` | No-echo `/dev/tty` passphrase prompt and source precedence (env, flag, prompt, demo fallback) |
| `src/fs.rs` | FUSE filesystem + encrypted directory index (InodeEntry tree) |
| `src/crypto.rs` | Argon2id KDF + XChaCha20-Poly1305 encrypt/decrypt (+ retained v0 legacy readers for migration) |
| `src/v2.rs` | Immutable chunk/tree objects, copy-on-write generations, authenticated root-last commit and recovery |
| `src/v2_gc.rs` | Evidence-aware offline v2 preview, reversible quarantine/restore, and read-only compatibility handling for disabled physical purge |
| `src/v2_migrate.rs` | Explicit resumable v1-to-v2 migration with authenticated plan and per-file receipts |
| `src/fault.rs` | Deterministic returned-error and test-only real-process kill injection at durability boundaries |
| `src/migrate.rs` | Crash-safe v0→v1 on-disk format migration |
| `src/rekey.rs` | Passphrase re-keying (keeps the drive salt; new passphrase → new key) |
| `src/remote/mod.rs` | Native Drive API replication of v2 stores: typed `RemoteError`, private config/state file helpers |
| `src/remote/cli.rs` | `zdrive remote auth\|push\|pull\|status\|verify`; never falls back to the demo passphrase |
| `src/remote/oauth.rs` | Installed-app OAuth: loopback redirect, PKCE S256, `state` check, `--no-browser` paste-back, token refresh |
| `src/remote/config.rs` | `~/.config/zerotrust-drive/remotes/<name>.json`; refresh token sealed under an Argon2id key from the store passphrase |
| `src/remote/gdrive.rs` | Blocking `ureq` Drive v3 client: GCRA pacer, jittered backoff, pre-generated ids, resumable uploads, md5 checks |
| `src/remote/format.rs` | Remote layout: marker, `_kdf.json` copy, append-only `packs/*.zpk`, `roots/*.zr`, `leases/` |
| `src/remote/sync.rs` | Checkpointed push (packs first, root record last, fork/writer refusal), fast-forward pull, status, verify |
| `src/remote/state.rs` | Per-replica sync state and resumable upload sessions under `~/.local/state/zerotrust-drive/` |
| `src/remote/mount.rs` | `--remote` mount: catch-up pull, replicator thread, 60 s remote-head watcher, read-only latch, final push (exit 75) |
| `src/remote/lease.rs` | Advisory writer leases (random replica id, heartbeat); fork detection stays the guarantee |
| `src/remote/fake.rs` | In-process fake Drive server with fault injection for the hermetic suite |
| `src/remote/crash_tests.rs` | Subprocess SIGKILL matrix at every push and pull checkpoint |
| `tests/live_fuse.rs` | Opt-in Linux live-mount tests: signals unmount, flush and exit 0; a busy mount keeps serving |
| `tests/fixtures/format/` | Committed v1/v2 stores pinning the on-disk format (with KATs in `crypto.rs`) |
| `assets/icon/` | ZeroTrust Drive icon: SVG source and the committed `.icns` built by `just icons` |

## Conventions

- Rust edition 2024
- License: AGPL-3.0-only
- CI: GitHub Actions
- Passphrase precedence: `ZEROTRUST_PASSPHRASE`, `--passphrase`, then a no-echo terminal prompt (confirmed for a new store); without a terminal the demo fallback applies and a new store refuses it
- Rotation needs `--rekey` (or `--new-passphrase` / `--continue-rekey`); the new passphrase comes from `ZEROTRUST_NEW_PASSPHRASE`, `--new-passphrase`, or a confirmed prompt
