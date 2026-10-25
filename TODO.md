<!-- SPDX-FileCopyrightText: Copyright 2026 Alexander Orlov <info@lifub.com> -->

* Google brand verification of the bundled "ZeroTrust Drive" OAuth client: unverified, the consent
  screen may show a generic name and the privacy link stays hidden. Needs a domain-verified
  homepage and privacy page (github.com cannot be verified by us). Since 0.19.0 a mirror requests
  the restricted full `drive` scope through the bundled desktop client: until restricted-scope
  verification (including an annual CASA security assessment) the consent shows the
  unverified-app warning and at most 100 accounts can grant it. The operator confirmed that the
  full `drive` scope is listed on the project's Data Access page and the app is In production;
  brand and restricted-scope verification remain pending.
* Mirror and plain uploads run one at a time: about 1-2 s per small file in the 0.19.0 live test
  (13 files in 26.7 s), dominated by Drive's per-create latency. Upload a few files at once, like
  the mirror's four download workers, keeping the reserved-id create protocol.
* Plain and mirror cycles rescan the whole local folder every 15 s; use inotify (and FSEvents on
  macOS) to find local changes, with a periodic full scan as the backstop.
* The plain index is one JSON file rewritten whole (now only when it changed): for a mirror of
  100k items about 25 MB per save. Move to an append-only or keyed store if large mirrors appear.
* Plain mode restarts an interrupted large upload from the beginning; persist its resumable
  session as encrypted mode does.
* Mirror: Google Docs, Sheets and shortcuts stay on Drive only. Offer link files (as Drive for
  desktop's `.gdoc`) or an opt-in export.
* A Drive folder kept because it held items zdrive does not sync is forgotten locally; a later
  full relisting (an expired changes token) brings it back as an empty local folder.
* `zdrive doctor` does not show held deletions; only the sync's log and service status do.
  Persist the count in the plain state and report it.
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
