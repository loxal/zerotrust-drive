# Cloud storage backends for zerotrust-drive

Research date: 2026-08-02

## Decision

Use a dedicated folder in Google Drive `My Drive`, with Google Drive for desktop configured to **Mirror files**, as the primary supported cloud-backed location.

Offer iCloud Drive as a beta backend on macOS, with the complete store folder marked **Keep Downloaded**.

Offer Yandex Disk only as an experimental secondary backend, or as a Linux-focused option where its official console sync client is a decisive advantage. Use a fully local synchronized folder, not WebDAV, for a writable store.

This recommendation is about filesystem behavior, diagnostics, and portability rather than a claim that Google has better cloud-service uptime. Google Mirror mode gives `zerotrust-drive` ordinary, permanently local files, which best match its POSIX and FUSE assumptions. iCloud has lower onboarding friction for an Apple-only user, but it always uses Apple's File Provider model and therefore has more placeholder, materialization, and coordination behavior to account for. Yandex has useful REST, WebDAV, and Linux surfaces, but its rolling upload allowance is a poor match for copy-on-write churn and its macOS integration is less clearly documented than either American provider.

On macOS, Google or Yandex storage also creates a useful organizational split: Apple controls the operating system, another company stores ciphertext, and an independent open-source project handles client-side encryption. iCloud still keeps storage separate from the encryption project, but Apple controls both the OS and storage surface. In every case, the important boundary is that the storage provider does not also supply the only opaque client and update channel that handles the encryption key. A vendor privacy promise is not a substitute for that technical and organizational separation. Client-side encryption limits what a provider can learn from content; it does not prevent the provider from observing metadata or delaying, duplicating, blocking, or deleting ciphertext.

None of these backends is a database, a shared POSIX filesystem, or a backup. One store must have only one active writer at a time.

## Vendor-documented facts

### Behavior shared by all choices

- A successful local write, `fsync`, or atomic rename does not prove that a cloud upload has completed.
- Sync operates on individual files. None of the provider documentation reviewed exposes a multi-file transaction for an arbitrary synchronized folder.
- Offline changes made on multiple devices can produce conflicts or divergent copies.
- Deletion and corruption are synchronized. A separate versioned backup or snapshot is still required.
- A package or bundle does not create a remotely atomic directory transaction. V2's simple opaque object directory remains more portable than relying on package semantics.

The v1 format writes changed whole-file blobs and then replaces `_index.age`; a local or remote interruption can therefore leave v1 material from different commits without a recoverable normal-write intent. Those legacy stores retain their original caveats.

The v2 format removes that blob/index publication dependency locally. It writes immutable authenticated chunks, tree objects, file roots, an index object, and a generation record before publishing an authenticated normal-write manifest and atomically exchanging the small authenticated `_root.age` pointer last. The displaced root and verified transaction manifests are retained as evidence. Deterministic tests return an injected error after write, file `fsync`, rename, directory `fsync`, evidence-retention, and recovery checkpoints, then retry recovery against that state. They do not emulate process death or pre-fsync cache loss; the old-or-new crash argument also depends on the documented local filesystem contract.

Cloud replication can still reorder those already durable files. A second machine may temporarily receive a new `_root.age` before every immutable object it references, or receive objects while retaining the old root. The first state fails closed on missing or incorrectly digested authenticated objects; the second continues to expose the complete old generation. The client does not synthesize missing data, fall back to an unrelated root, or expose a partially materialized generation. Users must wait for provider synchronization to finish and remount after the referenced objects arrive. Cloud sync remains asynchronous replication, not the store's concurrency protocol.

Writable v2 startup now traverses and authenticates every reachable file root, tree, and chunk before accepting mutations. This prevents committing on top of a partially delivered generation, but startup work is proportional to live data and may force placeholder downloads. V2 also performs chunk/tree/file-root COW for every small FUSE write, not only at flush. Repeated writes within one 4 MiB chunk can amplify uploads substantially. There is no garbage collector, so immutable orphan objects, old generations, displaced roots, and retained manifests accumulate. This makes the current implementation a durability-focused beta and a poor fit for sustained write-heavy use with any consumer sync provider.

### Google Drive in Mirror mode

Google documents two modes for `My Drive`: Stream files and Mirror files. Stream is the default and keeps most content in the cloud or a local cache. Mirror maintains a full standard local copy, makes it available offline, and is recommended by Google when applications write extensively. Shared Drives can only be streamed.

Sources:

- [Google Drive: Stream and mirror files](https://support.google.com/drive/answer/13401938?hl=en)
- [Google Drive for desktop advanced configuration](https://support.google.com/drive/answer/16631477?hl=en-en)

Mirror mode is the better fit because:

- Files remain present when the Drive application is stopped or its cache has a problem.
- Reads do not need to materialize placeholders over the network.
- Unsynced data is not confined to the streaming cache. Google warns that unsynced streaming-cache changes can be lost if that cache is cleared or corrupted.
- The local tree behaves more like the ordinary filesystem assumed by the current durable-write implementation.

Costs and limitations:

- Mirroring `My Drive` downloads the full `My Drive`, not only the `zerotrust-drive` folder. Users with large existing Drives may need substantial disk space or a dedicated Google account.
- Google Drive for desktop is an additional installed process with filesystem and privacy permissions.
- Google's official desktop client supports macOS and Windows, but not Linux. The public Drive REST API still provides a credible path to a future native server or Linux backend.
- Google documents upload quotas and item-count limits. V2 no longer rewrites whole file ciphertext, but immutable chunks and retained generations increase object count. Garbage collection therefore has to remain explicit, evidence-preserving, and aware of provider synchronization rather than deleting unfamiliar objects opportunistically.

Sources:

- [Google Drive API](https://developers.google.com/workspace/drive/api/reference/rest/v3)
- [Google Drive API limits](https://developers.google.com/workspace/drive/api/guides/limits)
- [Google Drive resumable uploads](https://developers.google.com/workspace/drive/api/guides/manage-uploads)
- [Google Drive change tracking](https://developers.google.com/workspace/drive/api/guides/about-changes)
- [Google Drive for desktop system requirements](https://support.google.com/drive/answer/2375082?co=GENIE.Platform%3DDesktop&hl=en)

Google documents a Pause Sync control. This is useful for rekey and migration operations. Its troubleshooting documentation also describes conflict copies, Lost & Found recovery, quota failures, retry behavior, and File Provider initialization errors.

- [Pause or resume Google Drive sync](https://support.google.com/drive/answer/13470231?hl=en-en)
- [Fix Google Drive for desktop sync errors](https://support.google.com/drive/answer/2565956?co=GENIE.Platform%3DDesktop&hl=en)

Google retains revisions for ordinary non-Google files under documented retention rules. This must not be presented as a `zerotrust-drive` recovery guarantee: replacement can be represented as delete-plus-create, and the backing store still needs an independent backup.

- [Google Drive file versions](https://support.google.com/drive/answer/2409045)

### iCloud Drive with Keep Downloaded

Apple documents several iCloud Drive states. An item can exist only in iCloud and require a network download, be downloaded locally, be waiting to upload, or be marked Keep Downloaded. Optimize Mac Storage may remove older local downloads when space is needed unless they are kept downloaded.

Apple also documents a 50 GB limit for an individual iCloud Drive folder or file; an oversized item is marked Ineligible and cannot be stored in iCloud. This is a release-level constraint for the current v2 layout. The backing folder accumulates immutable copy-on-write objects, orphan objects, old generations, and retained conflict evidence because safe garbage collection is not implemented yet. Therefore the relevant size is accumulated encrypted backing data, not the current visible plaintext tree. An iCloud beta store must remain small and low-write, its backing folder must be monitored, and it must be moved to another backend comfortably before it approaches 50 GB. A store can hit this boundary even when its live data is much smaller.

Sources:

- [Apple: Check iCloud Drive file and folder status](https://support.apple.com/en-ie/guide/mac-help/mchlc994344b/mac)
- [Apple: Work with folders and files in iCloud Drive](https://support.apple.com/en-euro/guide/mac-help/mchl1a02d711/mac)
- [Apple File Provider synchronization](https://developer.apple.com/documentation/FileProvider/synchronizing-the-file-provider-extension)

iCloud's strengths are:

- No extra sync client for a Mac user.
- Low-friction integration with macOS, iOS, Finder, and an existing iCloud plan.
- Folder-level Keep Downloaded is simpler than mirroring an entire large cloud drive.
- Pending unsynced changes are protected from automatic File Provider eviction.

Its limitations for this implementation are:

- iCloud Drive is File Provider-managed. Without Keep Downloaded, reads may encounter placeholders and network materialization.
- An individual folder or file over 50 GB becomes ineligible. Current v2 retention can reach this limit well before live plaintext does.
- Apple recommends coordinated access through `NSFileCoordinator` for shared and iCloud locations. The current Rust implementation uses POSIX file operations and does not yet participate in that native coordination mechanism. Correct integration must cover every exact v1 index/blob path and every v2 root/object/manifest/staging/rename/deletion path; coordinating only the parent directory, `_index.age`, or `_root.age` would be misleading.
- Apple provides native clients for its platforms and Windows, but no general iCloud Drive REST API or native Linux filesystem client.
- Finder exposes current per-item state, but troubleshooting and historical incident information are less detailed than Google's.
- Neither Apple nor Google documents a contract for every internal filename used by this format. New stores avoid leading-dot and AppleDouble-like v2 names, but a two-device round trip of the complete backing folder is still required before trusting a provider/client version.

Apple documents numbered filenames and explicit version selection when offline edits conflict. A generated `_index 2.age` for v1 or `_root 2.age` for v2 cannot be merged meaningfully. The client scans for provider-generated siblings of v1 blobs and indexes, the v2 root and object directory, KDF metadata, and migration/rekey controls; iCloud placeholder names; malformed or provider-conflicted staging names; and stale write temps before startup recovery and before each commit. It pins the selected object namespace and canonical inactive-format controls for the lifetime of a mount, then fails closed if delayed synchronization changes that topology. Syntactically valid ready files left before authenticated intent publication are preserved as unbound evidence and select no generation, so they do not permanently block retry. V2's authenticated parent-generation link can prove whether one candidate directly follows another, but it does not authorize silently choosing between divergent provider copies.

- [Apple: Resolve document conflicts](https://support.apple.com/en-gb/guide/mac-help/mh40780/26/mac/26)
- [Apple Technical Note TN2336: File conflicts](https://developer.apple.com/library/archive/technotes/tn2336/)
- [Apple: Coordinating shared file access](https://developer.apple.com/documentation/technologyoverviews/shared-data)
- [Apple NSFileCoordinator](https://developer.apple.com/documentation/foundation/nsfilecoordinator)

macOS 26 adds APIs that can pause and resume File Provider synchronization around access to regular files and packages. This may support a future native integration, but it is not yet a replacement for a clear user-level migration procedure in the current implementation.

### Yandex Disk as an experimental secondary backend

Yandex documents an OAuth REST API, an application-folder-only permission, Windows and macOS desktop clients, WebDAV, and an official Linux console sync daemon. The Linux client can report synchronization errors, run continuously, exclude directories, and operate in read-only mode. This is a genuine advantage over Google Drive and iCloud Drive for an x86 Linux workstation or server. The official download table lists i386/amd64 `.deb` and i386/x86_64 `.rpm` packages, not ARM64, and its installation examples still use `apt-key` and HTTP repository URLs. Support on a current distribution such as Ubuntu 26.04 must be validated empirically before it is advertised.

Sources:

- [Yandex Disk REST API](https://yandex.com/dev/disk-api/doc/en/)
- [Yandex Disk API access and app-folder scope](https://yandex.com/dev/disk-api/doc/en/concepts/quickstart)
- [Yandex Disk desktop clients](https://yandex.com/support/yandex-360/customers/disk/web/en/desktop)
- [Yandex Disk Linux installation](https://yandex.com/support/yandex-360/customers/disk/desktop/linux/en/installation)
- [Yandex Disk Linux commands](https://yandex.com/support/yandex-360/customers/disk/desktop/linux/en/cli-commands)

The REST API has some properties that fit v2 and others that do not:

- Upload obtains a temporary URL and then sends one `PUT`. The default `overwrite=false` behavior is a good match for publishing immutable objects without replacement.
- The upload URL expires after 30 minutes. The documentation says to re-upload after a `500` or `503`; it does not document a Google-style resumable session with a durable acknowledged offset. A `202` response can mean that bytes were received but have not yet been moved into Yandex Disk.
- File move is available, but overwrite is documented as deleting the existing target and moving the source. The reviewed documentation does not promise POSIX-atomic replacement, conditional `If-Match`, compare-and-swap, or directory durability. A future direct Yandex adapter must therefore keep `_root.age` conflict checks and must not map a successful API call to local `rename` plus directory `fsync` semantics.
- Resource metadata includes MD5 and modification time. Those fields are useful for transfer diagnostics but do not replace v2's authenticated object digest and generation chain.

Sources:

- [Yandex Disk upload API](https://yandex.com/dev/disk-api/doc/en/reference/upload)
- [Yandex Disk move API](https://yandex.com/dev/disk-api/doc/en/reference/move)
- [Yandex Disk resource objects](https://yandex.com/dev/disk-api/doc/en/reference/response-objects)

The consumer sync and quota behavior makes Yandex a poor default for a frequently written COW store:

- Yandex says the desktop client uploads only the changed part of an ordinary modified file, but also warns that simultaneous multi-device edits can duplicate or lose files. V2 avoids in-place data-object replacement, yet concurrent `_root.age` publication still requires the one-writer rule and sibling preservation.
- Free accounts accept files up to 1 GB and paid Yandex 360 plans up to 50 GB. V2's bounded chunks avoid this per-file limit.
- The rolling 30-day upload allowance is only twice the account's storage capacity. Once reached, writes and uploads are disabled until the period resets. Immutable COW write amplification, initial migration, and later evidence-preserving retention all consume that allowance even when the live plaintext size is unchanged.
- WebDAV has required a paid Yandex 360 plan since June 22, 2026. Yandex describes it as network-only, dependent on stable connectivity, and less capable than its desktop app. WebDAV deletion bypasses Trash permanently. It is unsuitable as the primary writable filesystem under `zerotrust-drive`; use a fully synchronized local folder instead.

Sources:

- [Yandex Disk synchronization and conflict behavior](https://yandex.com/support/yandex-360/customers/disk/desktop/macos/en/sync-how-works)
- [Yandex Disk upload size limits](https://yandex.com/support/yandex-360/customers/disk/web/en/uploading)
- [Yandex Disk storage and rolling upload allowance](https://yandex.com/support/yandex-360/customers/disk/web/en/enlarge/disk-space)
- [Yandex Disk WebDAV](https://yandex.com/support/yandex-360/customers/disk/web/en/webdav)

Account availability and legal responsibility are more complex than a single country label suggests. Current international Yandex 360 terms name a Dubai entity and English law. Current Yandex ID terms assign the account entity according to the linked phone number: Russian or Belarusian numbers map to a Russian entity, several other named countries map to local entities, and most other numbers map to a Serbian entity. The privacy policy says processing may involve YANDEX LLC, incorporated in Russia, or affiliates and that cross-border protection levels may differ. The consumer material reviewed does not provide a storage-residency commitment.

Yandex ID depends materially on a current mobile number for registration and recovery, may restrict access when account identity data is incomplete, and may request supporting documents. Disk terms permit blocking after 44 days over capacity and permanent deletion 90 days after blocking; they also define a notice, block, and deletion path after two years without Disk activity. Yandex 360 is provided without a consumer warranty of uninterrupted, error-free operation or file safety. Its terms also say that functions may differ by account and country. These are availability and procurement risks, not evidence that a specific account will be blocked. Signup, card payment, renewal, recovery, and full export must be tested in the user's actual locale rather than inferred from another country's offer.

Client-side encryption remains necessary. Yandex's security documentation says transport is encrypted, but also says stored files up to 1 GB are scanned. V2 prevents the storage provider from reading or meaningfully classifying plaintext content, while leaving object sizes, timing, account metadata, and the power to withhold or delete ciphertext visible to the provider.

Sources:

- [Yandex 360 terms](https://yandex.com/legal/360_termsofuse/en/)
- [Yandex ID terms](https://yandex.com/legal/id_termsofuse/en/)
- [Yandex privacy policy](https://yandex.com/legal/confidential/en/)
- [Yandex Disk terms](https://yandex.com/legal/disk_termsofuse/en/)
- [Yandex Disk plan purchase and card payment](https://yandex.com/support/yandex-360/customers/disk/mobile/en/buy-space)
- [Yandex Disk security](https://yandex.com/support/yandex-360/business/disk/web/en/security)

### Incident transparency

Google publishes a searchable five-year Workspace incident history. It includes outages, degraded uploads, latency, and feature-specific incidents, so incident counts must not be treated as an uptime measurement.

- [Google Workspace status dashboard](https://www.google.com/appsstatus/dashboard/)
- [Google Drive incident history](https://www.google.com/appsstatus/dashboard/products/VHNA7p3Z5p3iakj5sA8V/history)

Apple publishes current service status but no comparable public five-year iCloud Drive archive was found as of the research date. The difference supports Google's observability advantage, not a conclusion that one provider fails more often.

- [Apple System Status](https://www.apple.com/support/systemstatus/)

No comparable searchable consumer Yandex Disk incident archive was found in the reviewed official material. Yandex's terms expressly acknowledge possible technical failures, but contractual disclaimers are not outage-rate evidence. Google therefore retains the strongest public incident observability of the three choices.

## Anecdotal user reports

The following are self-selected reports, not incidence-rate evidence. They are useful as a test inventory because the failure modes recur across independent discussions.

### iCloud Drive reports

- May 2023: a small folder reportedly remained at Waiting to Upload for weeks despite available capacity. [Apple Community report](https://discussions.apple.com/thread/254881484)
- December 2024: users described stuck uploads and limited diagnostic feedback, while other participants reported normal operation. [Reddit discussion](https://www.reddit.com/r/MacOS/comments/1h8gz9z)
- April 2025: one user reported that files marked Keep Downloaded unexpectedly needed downloading again. [Apple Community report](https://discussions.apple.com/thread/256047681)
- June 2025: a user reported placeholders for important files and a Download Now action that had no effect. [Apple Community report](https://discussions.apple.com/thread/256084740)
- October 2025, macOS 26: users reported uploads repeatedly stalling, with rebooting helping only temporarily. [Apple Community report](https://discussions.apple.com/thread/256158466)
- April 2025, iCloud for Windows: Excel's temporary-save pattern reportedly left a temporary file and removed the original. [Apple Community report](https://discussions.apple.com/thread/255997623)

Recurring reported failure modes: opaque upload queues, placeholder materialization failures, Keep Downloaded surprises, and poor diagnostics around temporary-file replacement.

### Google Drive reports

- April 2024 and February 2026: Mac users reported persistent File Provider initialization failures despite reinstall and restart attempts. [April 2024 report](https://support.google.com/drive/thread/271338406/) and [February 2026 report](https://support.google.com/drive/thread/408023483/)
- May 2024: a design team described recurring Fetching new items stalls and resource usage; replies contained mixed experiences. [Reddit discussion](https://www.reddit.com/r/MacOS/comments/1cocgsw/is_google_drive_driving_everyone_else_up_the_ing/)
- September 2024: users reported divergent copies across several Macs without clear errors. [Google Drive Community report](https://support.google.com/drive/thread/298176131/)
- December 2024, Mirror mode: a large upload reportedly looped until DriveFS was reset and reinstalled. [Google Drive Community report](https://support.google.com/drive/thread/314655237/)
- January 2025: Drive reportedly claimed Everything up to date while remote changes had not appeared locally; resetting the DriveFS cache fixed it. [Google Drive Community report](https://support.google.com/drive/thread/317695144/)
- February 2024, Stream/File Provider mode: replacing a file reportedly deleted the old object and created a new one without revision history. [Google Drive Community report](https://support.google.com/drive/thread/257913341/no-version-history-despite-using-option-key-to-replace-files)

Recurring reported failure modes: File Provider initialization, stale or misleading sync status, DriveFS cache repair, resource use, and divergent copies. Several of the most relevant reports concern Stream/File Provider mode, which reinforces the Mirror-only primary recommendation.

### Yandex Disk reports

- November 2025: a European user reported years without problems, excellent speed, and fast English-language support, while deliberately using Yandex only as a secondary cloud repository. [Reddit discussion](https://www.reddit.com/r/cloudstorage/comments/1ommcic/looking_for_yandex_disk_feedback/)
- November 2025: several users reported good transfer performance, while another found the desktop integration less native than Google Drive. An `rclone` user reported that encrypted filename expansion exceeded Yandex's filename limit and caused sync errors. V2's short opaque object names mitigate the filename-expansion case. [Reddit discussion](https://www.reddit.com/r/cloudstorage/comments/1p8lya3/why_no_one_ever_talks_about_yandex/)
- March 2026: one Linux user reported that the local daemon had stopped synchronizing while local files remained, and that the remote account later removed files for inactivity. This is a single unverified account, but it is a useful monitoring test because the official terms separately document inactivity deletion. [Reddit report](https://www.reddit.com/r/cloudstorage/comments/1rilg98/yandexdisk_does_not_sync_on_lincu/)

Yandex's own troubleshooting material also lists stuck `Syncing`, long filenames, antivirus or firewall interference, low-speed resource conservation, open-file conflicts, full storage, and cases where a local item has not appeared on the web or another computer. These vendor-documented conditions are stronger test inputs than anecdotes, though they still provide no frequency data.

- [Yandex Disk macOS sync troubleshooting](https://yandex.com/support/yandex-360/customers/disk/desktop/macos/en/sync-problems)

A broader May 2025 Mac discussion contains both favorable and unfavorable experiences for the two macOS default candidates and is a useful counterweight to failure-only reports: [iCloud versus Google Drive discussion](https://www.reddit.com/r/MacOS/comments/1kx2k71/icloud_vs_google_drive_which_one_do_you_use_and/)

## Required operating model

### One writer

Only one mounted `zerotrust-drive` instance may write a store at a time. Before moving to another computer, the user must unmount the first instance and wait until the provider explicitly reports that synchronization is complete.

Provider conflict resolution is not a concurrency mechanism. In v1, encrypted index versions cannot be merged, and provider-generated sibling indexes can strand otherwise valid encrypted blobs. In v2, `_root.age` is the sole mutable visibility pointer and each authenticated generation names its parent, but two concurrent children of one parent are still divergent histories that require human reconciliation. The application fingerprints the complete active `_index.age` for v1 or `_root.age` for v2 and the exact `_kdf.json`, scans for alternate control artifacts, and refuses a local commit when a check indicates a competing or interrupted generation. Maintenance locks contain a hashed operating-system machine identity and PID so a lock synchronized from another device is not declared stale by probing its PID on the wrong host. These controls are detection, not a cross-machine lease or remote transaction, so the one-writer rule remains mandatory.

After a mounted instance detects such a conflict, it latches persistence off until remount. Writes return read-only errors and flush/fsync report the stored conflict even if the provider later removes or hides the sibling. V2 recovery moves only byte-for-byte verified transaction artifacts into transaction-bound evidence names after authenticating the intent and generation relationship; it does not unlink roots or manifests. A separately fsynced manifest anchor lets remount detect a provider replacement raced with that move. This prevents an apparently self-healing sync state from silently resuming commits or discarding conflict evidence before a human has reconciled the generations.

Remote partial materialization is also an error, not an empty store. If `_kdf.json`, `_root.age`, a v2 write manifest, or referenced immutable objects arrive without their required counterparts, do not delete the directory and do not initialize a replacement drive. Wait for synchronization, preserve every artifact, and retry with the same passphrase. A missing object, digest mismatch, unsupported root, or root that is neither the authenticated old nor new generation fails closed.

The visible lock itself is also eventually synchronized. Two offline or partitioned machines can each believe they created it first, so machine-bound ownership does not make simultaneous maintenance safe. Foreign, legacy PID-only, and malformed locks are preserved for manual reconciliation rather than deleted automatically.

### Not a backup

Cloud synchronization copies deletion, corruption, and a bad rekey result. Users need a separate versioned snapshot or backup outside the synchronized tree. Provider trash and revision history are recovery conveniences, not sufficient backup guarantees.

The backup must include an exact copy of `_kdf.json`. Its Argon2id salt is not secret, but it is availability-critical: loss or corruption makes every encrypted object undecryptable even when the passphrase is known.

### Safe rekey or migration

The explicit `--migrate-v2` operation is resumable. It authenticates a migration plan, retains the v1 source ciphertext, records per-file progress, verifies the reachable immutable objects, and publishes `_root.age` through the normal root-last commit. Re-run it with the same passphrase after interruption; do not remove its plan, receipts, v1 blobs, or `_index.age` to force progress. V2 passphrase rotation is not implemented, so do not improvise an in-place cloud rekey for a v2 store.

1. Unmount the store on every device and confirm that no process is writing it.
2. Wait for the provider to report fully synchronized.
3. Create or verify an independent recoverable snapshot outside the synchronized tree.
4. Pause Google Drive sync. For iCloud beta, take the Mac offline after synchronization is complete because iCloud has no equivalent general Pause Sync control. For Yandex, stop the desktop application or Linux daemon only after its status reports complete.
5. Run the complete rekey or migration locally.
6. Validate that the migrated store opens and its expected contents are readable before removing the snapshot.
7. Resume Google Drive or Yandex synchronization, or reconnect the iCloud Mac.
8. For v1, wait until every changed blob and `_index.age` is fully uploaded. For v2, wait until every new immutable object, authenticated migration or write artifact, and `_root.age` is fully uploaded. Do not mount the store elsewhere during this interval.
9. Only after synchronization completes may another device download the complete store and mount it.

V2 deliberately retains immutable objects from more than one generation, so a mixture of object generations in the cloud directory is expected and is not itself corruption. Only the authenticated `_root.age` selects the visible generation. A provider may nevertheless deliver that root before its dependencies; the receiving client must remain unavailable and fail closed until all authenticated objects materialize. The root-last proof applies to the local durability protocol and its recovery model, not to provider upload order. The one-writer rule and waiting for complete replication remain mandatory.

## Support wording

- **Recommended:** Google Drive `My Drive`, Mirror files, dedicated backing folder, one active mount.
- **Constrained beta:** iCloud Drive only for small, low-write stores whose accumulated encrypted backing footprint stays comfortably below Apple's 50 GB per-folder limit; complete backing folder marked Keep Downloaded, one active mount.
- **Experimental secondary:** Yandex Disk fully local synchronized folder, preferably for Linux or cold secondary storage, one active mount, account and rolling-upload monitoring.
- **Unsupported:** Google Drive Stream mode, Shared Drives, Yandex WebDAV for writable mounts, concurrent mounts, network-mounted provider caches, or treating any provider as the only backup.

All three labels assume low-write beta use until bounded dirty-chunk coalescing and evidence-aware garbage collection exist. Yandex's rolling upload allowance makes the current write amplification especially unfavorable there.
