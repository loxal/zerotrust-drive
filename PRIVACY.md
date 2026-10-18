<!-- SPDX-FileCopyrightText: Copyright 2026 Alexander Orlov <info@lifub.com> -->

# ZeroTrust Drive privacy policy

Last updated: 2026-10-18

ZeroTrust Drive (`zdrive`) is open-source software that runs entirely on
your own computer. Its developer operates no server for it and receives no
data from it: not your files, not your Google account data, and not its
telemetry.

## Google user data

zdrive uses the Google Drive API only to keep a copy of your drive in your
own Google Drive.

**What zdrive accesses.**

- With the bundled ZeroTrust Drive client, zdrive requests only the
  `https://www.googleapis.com/auth/drive.file` scope. It can see and change
  only the files and folders that zdrive itself created. The rest of your
  Drive stays invisible to it.
- With a bring-your-own client that you create in your own Google Cloud
  project, zdrive requests the full `https://www.googleapis.com/auth/drive`
  scope that you granted to your own client. That data is handled exactly as
  described here.
- zdrive reads your account's email address from the Drive API
  (`about.user.emailAddress`) once per authorization. It checks that you
  signed in to the account you named, and keeps the address in the local
  remote configuration as the sign-in hint for a later re-authorization.

**How zdrive uses it.** zdrive creates its folder, uploads, downloads,
lists changes, and moves to the Drive trash the files it manages. It does
nothing else with your Google data.

- In encrypted mode, the default, every file is encrypted on your computer
  before upload. Google stores ciphertext and never receives your
  passphrase, a key, a file name or plaintext content. It does see the
  number and sizes of encrypted packs and when they were uploaded.
- In plain mode, which you have to select explicitly, files are uploaded
  unencrypted, keep their names and are readable by Google and in the Drive
  web interface.

**Where it is stored.** Everything stays on your computer:

- The OAuth refresh token and the remote configuration are kept under
  `$XDG_CONFIG_HOME/zerotrust-drive/remotes/` (by default
  `~/.config/zerotrust-drive/remotes/`), readable only by your user.
- In encrypted mode, the refresh token is sealed with XChaCha20-Poly1305
  under a key derived with Argon2id from your passphrase. In plain mode,
  which has no passphrase, it is kept in a separate file readable only by
  your user.
- Short-lived access tokens are held only in memory.

**Sharing and transfer.** Google user data travels only between your
computer and Google's APIs. zdrive does not send it to its developer or to
any third party, does not use it for advertising, does not sell it, and does
not use it to train or improve AI or machine-learning models. No human reads
it.

**Limited Use.** ZeroTrust Drive's use and transfer of information received
from Google APIs adheres to the
[Google API Services User Data Policy](https://developers.google.com/terms/api-services-user-data-policy),
including the Limited Use requirements.

**Revocation and deletion.**

- Revoke zdrive's access at any time at https://myaccount.google.com/permissions.
- Delete the local configuration in `~/.config/zerotrust-drive/remotes/` to
  remove the stored token.
- Delete the zdrive folder in Google Drive to remove the uploaded copy.

## Local telemetry and metrics

zdrive records telemetry and metrics about its own operation **on your
computer only**. They exist so that you, or someone you choose to share them
with, can diagnose performance and reliability problems. Nothing is uploaded
automatically. `zdrive telemetry export` writes an archive that you may share
by hand.

**Levels.**

- `standard`, the default: start and stop events, one summary per minute,
  errors, and sync and remote-request summaries.
- `full`: adds ten-second summaries, operations slower than 250 ms, every
  remote request with its status and retries, and sync step events.
- `off`: records nothing. Data already recorded is kept until
  `zdrive telemetry purge`.

**What is recorded.** The zdrive version, operating system, architecture and
kernel; mode and remote kind; operation counts, latencies and error codes;
sync durations, byte counts and lag; remote request outcomes, retries and
rate limits; process memory and CPU time; and the code location of a crash
(at `full`, also the crash message with paths removed).

**What is never recorded.** File and directory names, paths inside your
drive, file contents, your passphrase, OAuth tokens, client secrets and your
email address.

**Where and how long.** Records are kept in
`$XDG_STATE_HOME/zerotrust-drive/telemetry/` (by default
`~/.local/state/zerotrust-drive/telemetry/`) for 30 days, capped at 64 MiB per
instance at `standard` and 256 MiB at `full`.

**Opting out.** Any one of these turns telemetry off:

- `zdrive telemetry off` (persistent)
- the environment variable `ZDRIVE_TELEMETRY=off`
- the command-line flag `--telemetry off`

`zdrive telemetry status` shows the effective level and where it came from.

## Changes and contact

Changes to this policy are published in this file; its history is the
repository's Git history. Questions and requests go to the issue tracker at
https://github.com/loxal/zerotrust-drive/issues.
