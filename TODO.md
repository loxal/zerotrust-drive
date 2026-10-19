<!-- SPDX-FileCopyrightText: Copyright 2026 Alexander Orlov <info@lifub.com> -->

* Google brand verification of the bundled "ZeroTrust Drive" OAuth client: unverified, the consent
  screen may show a generic name and the privacy link stays hidden. Needs a domain-verified
  homepage and privacy page (github.com cannot be verified by us).
* Rerun the telemetry overhead benchmark (README "Telemetry > Overhead") on a quiet host: on a
  shared host at load 11-15 the 0.18.0 result was inconclusive against the declared 3% (`standard`)
  and 5% (`full`) margins. Same arms, workloads and pairing; more repeats if the spread stays wide.
* Yandex Disk remote through its REST API (not WebDAV, paid-only since June 2026 and deleting
  permanently): `overwrite=false` uploads fit the immutable packs and root records, but there are
  no resumable sessions and no compare-and-swap of a head, so keep the listing-based fork detection.
  `src/remote/sync.rs` calls `GoogleDrive` directly; first extract the operations it uses
  (reserved ids, create, list, get, ranged and whole downloads, resumable upload) into a provider trait.
* macOS volume icon for the mount: macFUSE's `volicon` is a high-level libfuse module that fuser's
  low-level mount never runs. Serving a virtual `/.VolumeIcon.icns` plus the root FinderInfo xattr
  from `ZeroTrustFs` would need xattr support and a live macOS kernel-mount check.
* FSKit backend performance: 0.19.0 mounts through macFUSE's FSKit module when the kernel
  extension is absent (`--fuse-backend auto`), but W2/W3 were not measured against the kext. The
  macFUSE wiki lists missing features and lower performance; measure, then decide whether `auto`
  should ever prefer FSKit while the kext is loaded.
* Remote garbage collection: remote packs and root records are append-only, so Drive usage grows
  with every generation's new objects, like the local store before GC. Findings from the remote
  format that shape the design: a pack bundles many objects, so a pack is reclaimable only when
  none of its objects is reachable (or after repacking); no root record names the replica that
  wrote it; a pusher skips objects that already exist in remote packs, so a GC that deletes a pack
  between that check and the pusher's root record publishes a root that reaches a deleted object
  (needs a lease or epoch fence); and a pull fast-forwards one generation at a time, so a lagging
  replica needs every intermediate generation's objects, not only the head's.
