<!-- SPDX-FileCopyrightText: Copyright 2026 Alexander Orlov <info@lifub.com> -->

* Google brand verification of the bundled "ZeroTrust Drive" OAuth client: unverified, the consent
  screen may show a generic name and the privacy link stays hidden. Needs a domain-verified
  homepage and privacy page (github.com cannot be verified by us).
* Rerun the telemetry overhead benchmark (README "Telemetry > Overhead") on a quiet host: on a
  shared host at load 11-15 the 0.18.0 result was inconclusive against the declared 3% (`standard`)
  and 5% (`full`) margins. Same arms, workloads and pairing; more repeats if the spread stays wide.
* Services restart forever on permanent configuration failures (a refused or binned Drive folder,
  a wrong passphrase): `zdrive service run` exits 1, so systemd restarts it every 10 s and launchd
  every 30 s, each start refreshing a token. Exit with a dedicated code (`EX_CONFIG`, 78), add
  `RestartPreventExitStatus=78` to the unit, and on macOS stop the agent after repeated refusals.
* Yandex Disk remote through its REST API (not WebDAV, paid-only since June 2026 and deleting
  permanently): `overwrite=false` uploads fit the immutable packs and root records, but there are
  no resumable sessions and no compare-and-swap of a head, so keep the listing-based fork detection.
  `src/remote/sync.rs` calls `GoogleDrive` directly; first extract the operations it uses
  (reserved ids, create, list, get, ranged and whole downloads, resumable upload) into a provider trait.
* Faster `zdrive remote pull` of many small objects: installs are sequential and each object pays
  a file and a directory `F_FULLFSYNC` (`write_exclusive_verified_file_at`), measured at about
  6-7 ms per object (38-43 s for 6,006 objects / 71 MB in six runs). Batch the directory sync or install in
  parallel without weakening the per-object durability contract.
* macOS volume icon for the mount: macFUSE's `volicon` is a high-level libfuse module that fuser's
  low-level mount never runs. Serving a virtual `/.VolumeIcon.icns` plus the root FinderInfo xattr
  from `ZeroTrustFs` would need xattr support and a live macOS kernel-mount check.
* macFUSE FSKit backend on macOS 26+: macFUSE 5 can mount through a user-space FSKit extension
  (`-o backend=fskit`, https://github.com/macfuse/macfuse/wiki/FUSE-Backends) instead of the kernel
  extension, which on Apple silicon first needs kernel extensions enabled in recoveryOS. `zdrive
  doctor` already recognizes the registered module, but the mount never selects the backend. The
  wiki restricts its mount points to `/Volumes` and lists missing features and lower performance:
  measure W2/W3 against the kext, then decide whether a macOS service should prefer it.
* `zdrive remote remove NAME`: nothing forgets a remote today. Cleanup means deleting
  `remotes/NAME.{json,token}` and `$XDG_STATE_HOME/zerotrust-drive/remotes/NAME` by hand, and the
  refresh token stays valid until revoked at `https://oauth2.googleapis.com/revoke` (an encrypted
  remote seals it under the store passphrase). Observed on 2026-10-18: revoking one bundled-client
  token also invalidated the other bundled client's tokens for that account on another machine, so
  a revoke signs out every zdrive install of the account; warn and confirm before revoking.
* Remote garbage collection: remote packs and root records are append-only, so Drive usage grows
  with every generation's new objects, like the local store before GC.
