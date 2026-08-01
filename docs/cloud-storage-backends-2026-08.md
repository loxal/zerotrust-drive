# Cloud storage backends for zerotrust-drive

Research date: 2026-08-01

## Decision

Use a dedicated folder in Google Drive `My Drive`, with Google Drive for desktop configured to **Mirror files**, as the primary supported cloud-backed location.

Offer iCloud Drive as a beta backend on macOS, with the complete store folder marked **Keep Downloaded**.

This recommendation is about filesystem behavior, diagnostics, and portability rather than a claim that Google has better cloud-service uptime. Google Mirror mode gives `zerotrust-drive` ordinary, permanently local files, which best match its POSIX and FUSE assumptions. iCloud has lower onboarding friction for an Apple-only user, but it always uses Apple's File Provider model and therefore has more placeholder, materialization, and coordination behavior to account for.

On macOS, Google storage also creates a useful organizational split: Apple controls the operating system, Google stores ciphertext, and an independent open-source project handles client-side encryption. iCloud still keeps storage separate from the encryption project, but Apple controls both the OS and storage surface. In either case, the important boundary is that the storage provider does not also supply the only opaque client and update channel that handles the encryption key. A vendor privacy promise is not a substitute for that technical and organizational separation.

Neither backend is a database, a shared POSIX filesystem, or a backup. One store must have only one active writer at a time.

## Vendor-documented facts

### Behavior shared by both choices

- A successful local write, `fsync`, or atomic rename does not prove that a cloud upload has completed.
- Sync operates on individual files. Neither provider documentation reviewed exposes a multi-file transaction that can atomically publish data blobs and `_index.age` together.
- Offline changes made on multiple devices can produce conflicts or divergent copies.
- Deletion and corruption are synchronized. A separate versioned backup or snapshot is still required.
- A package or bundle does not create a remotely atomic directory transaction. The existing flat opaque-file layout is more portable.

For `zerotrust-drive`, the practical consequence is that cloud sync must be treated as asynchronous replication of a local store, not as the store's concurrency protocol.

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
- Google documents upload quotas and item-count limits. A large number of complete encrypted `_index.age` rewrites creates unnecessary upload and revision churn.

Sources:

- [Google Drive API](https://developers.google.com/workspace/drive/api/reference/rest/v3)
- [Google Drive API limits](https://developers.google.com/workspace/drive/api/guides/limits)
- [Google Drive for desktop system requirements](https://support.google.com/drive/answer/2375082?co=GENIE.Platform%3DDesktop&hl=en)

Google documents a Pause Sync control. This is useful for rekey and migration operations. Its troubleshooting documentation also describes conflict copies, Lost & Found recovery, quota failures, retry behavior, and File Provider initialization errors.

- [Pause or resume Google Drive sync](https://support.google.com/drive/answer/13470231?hl=en-en)
- [Fix Google Drive for desktop sync errors](https://support.google.com/drive/answer/2565956?co=GENIE.Platform%3DDesktop&hl=en)

Google retains revisions for ordinary non-Google files under documented retention rules. This must not be presented as a `zerotrust-drive` recovery guarantee: replacement can be represented as delete-plus-create, and the backing store still needs an independent backup.

- [Google Drive file versions](https://support.google.com/drive/answer/2409045)

### iCloud Drive with Keep Downloaded

Apple documents several iCloud Drive states. An item can exist only in iCloud and require a network download, be downloaded locally, be waiting to upload, or be marked Keep Downloaded. Optimize Mac Storage may remove older local downloads when space is needed unless they are kept downloaded.

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
- Apple recommends coordinated access through `NSFileCoordinator` for shared and iCloud locations. The current Rust implementation uses POSIX file operations and does not yet participate in that native coordination mechanism. Correct integration must cover every exact index, blob, manifest, staging, rename, and deletion path; coordinating only the parent directory or `_index.age` would be misleading.
- Apple provides native clients for its platforms and Windows, but no general iCloud Drive REST API or native Linux filesystem client.
- Finder exposes current per-item state, but troubleshooting and historical incident information are less detailed than Google's.

Apple documents numbered filenames and explicit version selection when offline edits conflict. Such a generated `_index 2.age` cannot be merged meaningfully. The client now scans for provider-generated siblings of blobs, the index, KDF metadata, and migration/rekey controls; iCloud index-placeholder names; unexpected staging entries; and stale write temps both before startup recovery and before each commit. It fails closed while preserving the artifacts for manual reconciliation.

- [Apple: Resolve document conflicts](https://support.apple.com/en-gb/guide/mac-help/mh40780/26/mac/26)
- [Apple Technical Note TN2336: File conflicts](https://developer.apple.com/library/archive/technotes/tn2336/)
- [Apple: Coordinating shared file access](https://developer.apple.com/documentation/technologyoverviews/shared-data)
- [Apple NSFileCoordinator](https://developer.apple.com/documentation/foundation/nsfilecoordinator)

macOS 26 adds APIs that can pause and resume File Provider synchronization around access to regular files and packages. This may support a future native integration, but it is not yet a replacement for a clear user-level migration procedure in the current implementation.

### Incident transparency

Google publishes a searchable five-year Workspace incident history. It includes outages, degraded uploads, latency, and feature-specific incidents, so incident counts must not be treated as an uptime measurement.

- [Google Workspace status dashboard](https://www.google.com/appsstatus/dashboard/)
- [Google Drive incident history](https://www.google.com/appsstatus/dashboard/products/VHNA7p3Z5p3iakj5sA8V/history)

Apple publishes current service status but no comparable public five-year iCloud Drive archive was found as of the research date. The difference supports Google's observability advantage, not a conclusion that one provider fails more often.

- [Apple System Status](https://www.apple.com/support/systemstatus/)

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

A broader May 2025 Mac discussion contains both favorable and unfavorable experiences for each provider and is a useful counterweight to failure-only reports: [iCloud versus Google Drive discussion](https://www.reddit.com/r/MacOS/comments/1kx2k71/icloud_vs_google_drive_which_one_do_you_use_and/)

## Required operating model

### One writer

Only one mounted `zerotrust-drive` instance may write a store at a time. Before moving to another computer, the user must unmount the first instance and wait until the provider explicitly reports that synchronization is complete.

Provider conflict resolution is not a concurrency mechanism. Encrypted index versions cannot be merged, and provider-generated sibling index files can strand otherwise valid encrypted blobs. The application fingerprints the complete active `_index.age` and exact `_kdf.json`, scans for alternate control artifacts, and refuses a local commit when a check indicates a competing or interrupted generation. Maintenance locks contain a hashed operating-system machine identity and PID so a lock synchronized from another device is not declared stale by probing its PID on the wrong host. These controls are detection, not a cross-machine lease or remote transaction, so the one-writer rule remains mandatory.

After a mounted instance detects such a conflict, it latches persistence off until remount. Writes return read-only errors and flush/fsync report the stored conflict even if the provider later removes or hides the sibling. This prevents an apparently self-healing sync state from silently resuming commits before a human has reconciled the generations.

The visible lock itself is also eventually synchronized. Two offline or partitioned machines can each believe they created it first, so machine-bound ownership does not make simultaneous maintenance safe. Foreign, legacy PID-only, and malformed locks are preserved for manual reconciliation rather than deleted automatically.

### Not a backup

Cloud synchronization copies deletion, corruption, and a bad rekey result. Users need a separate versioned snapshot or backup outside the synchronized tree. Provider trash and revision history are recovery conveniences, not sufficient backup guarantees.

### Safe rekey or migration

1. Unmount the store on every device and confirm that no process is writing it.
2. Wait for the provider to report fully synchronized.
3. Create or verify an independent recoverable snapshot outside the synchronized tree.
4. Pause Google Drive sync. For iCloud beta, take the Mac offline after synchronization is complete because iCloud has no equivalent general Pause Sync control.
5. Run the complete rekey or migration locally.
6. Validate that the migrated store opens and its expected contents are readable before removing the snapshot.
7. Resume Google Drive sync or reconnect the iCloud Mac.
8. Wait until every changed blob and `_index.age` is fully uploaded. Do not mount the store elsewhere during this interval.
9. Only after synchronization completes may another device download the complete store and mount it.

The cloud may temporarily contain a mixture of generations while step 8 is in progress. Safety comes from the one-writer rule and keeping every other mount closed until replication completes, not from remote transactionality.

## Support wording

- **Recommended:** Google Drive `My Drive`, Mirror files, dedicated backing folder, one active mount.
- **Beta:** iCloud Drive, complete backing folder marked Keep Downloaded, one active mount.
- **Unsupported:** Google Drive Stream mode, Shared Drives, concurrent mounts, network-mounted provider caches, or treating either provider as the only backup.
