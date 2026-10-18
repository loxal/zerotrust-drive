<!-- SPDX-FileCopyrightText: Copyright 2026 Alexander Orlov <info@lifub.com> -->

* daemon mode - run in backgroundd as a long-lived service
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
* Remote garbage collection: remote packs and root records are append-only, so Drive usage grows
  with every generation's new objects, like the local store before GC.
