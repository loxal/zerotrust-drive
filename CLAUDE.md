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
just deb                    # Linux .deb + tarballs (amd64, arm64) in dist/ via podman (Ubuntu 22.04 glibc baseline)
just deb-test arm64         # install that .deb on Ubuntu 22.04/24.04/26.04 and Debian 12, FUSE smoke as root and user
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

- **Encrypted storage**: `$XDG_DATA_HOME/zerotrust-drive/store/` by default since 0.18 (`~/.local/share/...`; `zdrive setup` uses `.../zerotrust-drive/<name>/store`; a pre-0.18 store in `~/g.drive/.zerotrust.drive.encrypted` is refused, never silently mounted) (v2 immutable authenticated objects + `_root.age` + plaintext `_kdf.json`; legacy v1 stores retain opaque `.age` blobs + `_index.age`)
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
| `src/prompt.rs` | No-echo `/dev/tty` passphrase prompt and source precedence (env, `$CREDENTIALS_DIRECTORY`, `--passphrase-file`, flag, prompt, demo fallback) |
| `src/setup.rs` | `zdrive setup`: guided sign-in, Drive folder create/join, first sync, auto-start; every prompt has a flag |
| `src/doctor.rs` | `zdrive doctor`: FUSE, bundled client presence, systemd/creds, remotes, services, telemetry; prints no secrets |
| `src/service/` | `zdrive service install\|uninstall\|status\|list\|run`: LaunchAgent plist / systemd user unit, passphrase custody (systemd-creds or 0600 file), sd_notify, stale-mount recovery |
| `src/refusal.rs` | Permanent start failures of a service: durable record, exit 78 (systemd `RestartPreventExitStatus`) or 0 (launchd), shown by `service status` and `doctor` |
| `src/fskit/` | macFUSE FSKit backend (`--fuse-backend auto\|kext\|fskit`): libfuse 2.9 channel relayed to a socket pair that fuser serves |
| `src/plain/` | Opt-in plain two-way sync (`zdrive sync`, no FUSE), and the mirror of all of My Drive (`setup --mirror`, full scope): `engine` (cycle, watch, backoff, root id, stop grace, parking), `pull` (changes feed, safe downloads, conflicts, mirror names and exclusions), `prefetch` (parallel mirror downloads), `push` (scan, uploads, moves, mass-deletion guard, Drive bin), `local` (ignore rules, conflict and mirror names, local trash), `state` (versioned locked index bound to folder, Drive id and `.zdrive-root-id`), `cli` |
| `src/telemetry/` | Local-only JSONL telemetry (`off`/`standard`/`full`): FUSE op histograms, snapshots, events, retention and caps, `zdrive telemetry status\|report\|export\|level\|purge` |
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
| `src/remote/remove.rs` | `zdrive remote remove`: forget a remote on this computer, optional `--revoke` (ends the grant for every install of the account) |
| `src/remote/oauth.rs` | Installed-app OAuth: loopback redirect, PKCE S256, `state` check, `--no-browser` paste-back, device flow, bundled `drive.file` clients (build-time `ZDRIVE_GOOGLE_*` env; full scope only for a mirror, never through the device flow) or BYO full scope, token refresh with the issuing client |
| `src/remote/config.rs` | `~/.config/zerotrust-drive/remotes/<name>.json`; refresh token sealed under an Argon2id key from the store passphrase |
| `src/remote/gdrive.rs` | Blocking `ureq` Drive v3 client: GCRA pacer, jittered backoff, pre-generated ids, resumable uploads, md5 checks |
| `src/remote/format.rs` | Remote layout: marker, `_kdf.json` copy, append-only `packs/*.zpk`, `roots/*.zr`, `leases/` |
| `src/remote/sync.rs` | Checkpointed push (packs first, root record last, fork/writer refusal), fast-forward pull, status, verify |
| `src/remote/state.rs` | Per-replica sync state and resumable upload sessions under `~/.local/state/zerotrust-drive/` |
| `src/remote/mount.rs` | `--remote` mount: catch-up pull, replicator thread, 60 s remote-head watcher, read-only latch, final push (exit 75) |
| `src/remote/lease.rs` | Advisory writer leases (random replica id, heartbeat); fork detection stays the guarantee |
| `src/remote/fake.rs` | In-process fake Drive server with fault injection for the hermetic suite |
| `src/remote/crash_tests.rs` | Subprocess SIGKILL matrix at every push and pull checkpoint |
| `tests/live_fuse.rs` | Opt-in Linux live-mount tests: signals unmount, flush and exit 0; a busy mount keeps serving, and under `--service` retries the unmount by itself |
| `tests/fixtures/format/` | Committed v1/v2 stores pinning the on-disk format (with KATs in `crypto.rs`) |
| `assets/icon/` | ZeroTrust Drive icon: SVG source and the committed `.icns` built by `just icons` |
| `packaging/` | `.deb` and tarball assembly (`just deb`, `just deb-test`), bundled-client release check |
| `PRIVACY.md` | Privacy policy the OAuth consent screen links to; keep it in sync with what telemetry and the remote store |

## Conventions

- Rust edition 2024
- License: AGPL-3.0-only
- CI: GitHub Actions
- Passphrase precedence: `ZEROTRUST_PASSPHRASE`, `$CREDENTIALS_DIRECTORY/zdrive-passphrase`, `--passphrase-file` (owner-only), `--passphrase`, then a no-echo terminal prompt (confirmed for a new store); without a terminal the demo fallback applies and a new store refuses it
- Rotation needs `--rekey` (or `--new-passphrase` / `--continue-rekey`); the new passphrase comes from `ZEROTRUST_NEW_PASSPHRASE`, `--new-passphrase`, or a confirmed prompt

## Finish with reconciled Git state

Synced copy of the global agent instructions' "Finish with reconciled Git
state" (Lifub `agent/prompts/agent-instructions.md`); update every copy in the
same change set.

Before concluding a task, apply the gist of Lifub's
`agent/public.skills/finalize-finish-address-open-topics-issues.skill.md`
unless that is beyond reasonable: finish the worthwhile open topics the task
left, and leave its Git state reconciled. In every repository the task
touched, inventory the registered worktrees, local branches, stashes and
uncommitted changes. Integrate each completed, authorized unit against the
current upstream, commit and push it under that repository's rules, and prove
its hosted CI where the repository requires it. Remove a clean worktree or a
merged branch once its head is on the upstream and its useful evidence is
preserved, with `git worktree remove` and `git branch -d`, never their forcing
variants. Give every other remnant an owner and a disposition instead of
forcing it: another session's active work, an unknown owner, a stash, a
missing authorization or an uncertain operation stays intact and is reported
with its exact prerequisite. It is beyond reasonable to take over or delete
foreign work, to pop, drop, reset or force-push merely to empty the
inventory, to retry an uncertain operation, to pre-empt a decision that
belongs to the operator, or to spend effort out of proportion to the task.
Under `/Users/alex/my/src/fastly`, corporate working hours and each
repository's branch and pull-request route govern every commit and push;
outside the window, report the prepared change as pending.
