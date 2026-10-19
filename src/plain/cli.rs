// SPDX-FileCopyrightText: Copyright 2026 Alexander Orlov <info@lifub.com>

//! `zdrive sync`: one plain sync cycle, or `--watch` cycles until SIGINT or
//! SIGTERM, between a local folder and a plain remote's Drive folder.

use std::path::{Path, PathBuf};
use std::time::Duration;

use super::{CycleReport, DEFAULT_STABLE_AGE, PlainOptions, Progress};
use crate::RunOptions;
use crate::refusal::{self, Class, Failure};
use crate::remote::cli as remote_cli;
use crate::remote::config::{Paths, RemoteConfig, RemoteMode, RemoteName};
use crate::remote::gdrive::GoogleDrive;
use crate::remote::oauth;
use crate::service;
use crate::telemetry::{self, Field, Level};

/// Seconds between `--watch` cycles unless `--interval` says otherwise.
pub(crate) const DEFAULT_INTERVAL_SECS: u64 = 15;

#[derive(clap::Args, Debug)]
pub(crate) struct SyncArgs {
    /// Plain remote created by `zdrive setup --plain` or
    /// `zdrive remote auth --plain`
    #[arg(long, value_name = "NAME")]
    pub(crate) remote: String,

    /// Local folder kept in sync with the remote's Drive folder; it must
    /// exist
    #[arg(long, value_name = "DIR")]
    pub(crate) dir: PathBuf,

    /// Keep syncing until SIGINT or SIGTERM. The first signal finishes the
    /// current cycle and runs a final one; a second stops at once
    #[arg(long)]
    pub(crate) watch: bool,

    /// Seconds between cycles with --watch; failed cycles back off up to
    /// five minutes
    #[arg(
        long,
        value_name = "SECONDS",
        default_value_t = DEFAULT_INTERVAL_SECS,
        requires = "watch",
        value_parser = clap::value_parser!(u64).range(1..=86_400)
    )]
    pub(crate) interval: u64,

    /// Move up to N items that are missing locally to the Drive bin,
    /// although the mass-deletion guard holds them back: after checking
    /// that they were deleted on purpose. One cycle, not with --watch
    #[arg(long, value_name = "N", conflicts_with = "watch")]
    pub(crate) allow_deletions: Option<u64>,

    #[command(flatten)]
    pub(crate) run: RunOptions,
}

pub(crate) fn run(args: SyncArgs) -> i32 {
    match sync(&args) {
        Ok(0) => 0,
        Ok(errors) => {
            eprintln!(
                "zerotrust-drive: {errors} item(s) were not synced; the next run retries them"
            );
            1
        }
        Err(failure) if failure.class.is_some() && refusal::armed() => refusal::exit(failure),
        Err(Failure { message, .. }) => {
            eprintln!("zerotrust-drive: error: {message}");
            if args.run.service {
                let _ = service::notify::status(&one_line(&format!("error: {message}")));
            }
            1
        }
    }
}

/// Per-item errors of the last cycle, or why syncing could not run.
fn sync(args: &SyncArgs) -> Result<usize, Failure> {
    let paths = Paths::from_env().map_err(|error| error.to_string())?;
    let name = RemoteName::parse(&args.remote)
        .map_err(|error| Failure::refused(Class::Remote, error.to_string()))?;
    let (drive, mut options, config) = open(&paths, &name, &args.dir)?;
    options.allow_deletions = args.allow_deletions;
    remote_cli::note(&format!(
        "{}: {} <-> {} (Google can read these files)",
        if config.mirror {
            "mirror"
        } else {
            "plain sync"
        },
        options.local_dir.display(),
        config.folder_hint
    ));
    let rerun = format!(
        "zdrive sync --remote {} --dir {}",
        name.as_str(),
        crate::service::shell_path(&options.local_dir)
    );

    if !args.watch {
        let result = super::sync_once(&drive, &options);
        record(&result);
        let report = result.map_err(Failure::from)?;
        print_report(&report, &rerun);
        return Ok(report.errors.len() + usize::from(report.held_deletions > 0));
    }

    let mut ready = false;
    let mut last_errors = 0;
    let mut last_held = 0;
    let service_mode = args.run.service;
    super::watch_until_signalled(
        &drive,
        &options,
        Duration::from_secs(args.interval),
        &mut |result| {
            record(result);
            match result {
                Ok(report) => {
                    // Quiet cycles every few seconds would only grow the
                    // log; repeated failures of the same items as well.
                    if report.changed()
                        || report.errors.len() != last_errors
                        || report.held_deletions != last_held
                    {
                        print_report(report, &rerun);
                    }
                    last_errors = report.errors.len();
                    last_held = report.held_deletions;
                }
                Err(message) => {
                    eprintln!("zerotrust-drive: sync cycle did not finish: {message}");
                }
            }
            if service_mode {
                if !ready {
                    ready = true;
                    report_to_service_manager(service::notify::ready());
                }
                report_to_service_manager(service::notify::status(&status_line(result)));
            }
        },
    )?;
    Ok(last_errors)
}

/// The Drive client of plain remote `name` and the options syncing `dir`
/// with it. Configuration problems are classed: they persist until the
/// operator acts.
fn open(
    paths: &Paths,
    name: &RemoteName,
    dir: &Path,
) -> Result<(GoogleDrive, PlainOptions, RemoteConfig), Failure> {
    let config = RemoteConfig::load(paths, name)
        .map_err(|error| Failure::refused(Class::Remote, error.to_string()))?;
    if config.mode != RemoteMode::Plain {
        return Err(Failure::refused(
            Class::Remote,
            format!(
                "remote {name} is an encrypted remote; mount it with `zdrive --remote {name} --encrypted-dir DIR --decrypted-dir DIR`"
            ),
        ));
    }
    let local_dir = local_folder(dir, paths)?;
    let client = oauth::client_for(&config.issuer())
        .map_err(|error| Failure::refused(Class::Remote, error.to_string()))?;
    let drive =
        remote_cli::open_drive(client, paths, &config, name, None).map_err(|error| Failure {
            class: refusal::remote_class(&error).or(Some(Class::Remote)),
            message: error.to_string(),
        })?;
    let options = options(paths, name, &config, local_dir);
    Ok((drive, options, config))
}

/// Setup's first cycle after sign-in: its summary, and the items that are
/// left for the next sync.
pub(crate) fn initial_sync(
    paths: &Paths,
    name: &RemoteName,
    dir: &Path,
) -> Result<Vec<String>, String> {
    let (drive, options, _) = open(paths, name, dir).map_err(|failure| failure.message)?;
    let result = super::sync_once(&drive, &options);
    record(&result);
    let report = result?;
    let mut lines = vec![summary(&report)];
    if let Some(held) = held_warning(
        &report,
        &format!(
            "zdrive sync --remote {} --dir {}",
            name.as_str(),
            crate::service::shell_path(dir)
        ),
    ) {
        lines.push(held);
    }
    if !report.errors.is_empty() {
        lines.push(format!(
            "{} item(s) were not synced; the next sync retries them:",
            report.errors.len()
        ));
        lines.extend(report.errors.iter().map(|error| format!("  {error}")));
    }
    Ok(lines)
}

/// The size of the My Drive that mirror remote `name` syncs.
pub(crate) fn mirror_size(paths: &Paths, name: &RemoteName) -> Result<super::MyDriveSize, String> {
    let config = RemoteConfig::load(paths, name).map_err(|error| error.to_string())?;
    let client = oauth::client_for(&config.issuer()).map_err(|error| error.to_string())?;
    let drive = remote_cli::open_drive(client, paths, &config, name, None)
        .map_err(|error| error.to_string())?;
    super::my_drive_size(&drive, &config.folder_id).map_err(|error| error.to_string())
}

/// The canonical local folder, refused when it overlaps zdrive's own
/// configuration, state or data, which would sync credentials or the
/// local trash.
pub(crate) fn local_folder(dir: &Path, paths: &Paths) -> Result<PathBuf, String> {
    let expanded = crate::expand_home_from_env(dir)?;
    let canonical = std::fs::canonicalize(&expanded).map_err(|error| {
        format!(
            "{}: {error}; create the folder first (or run `zdrive setup --plain`)",
            expanded.display()
        )
    })?;
    if !canonical.is_dir() {
        return Err(format!("{} is not a folder", canonical.display()));
    }
    for own in [&paths.config, &paths.state, &paths.data] {
        let own = std::fs::canonicalize(own).unwrap_or_else(|_| own.clone());
        if own.starts_with(&canonical) || canonical.starts_with(&own) {
            return Err(format!(
                "{} overlaps zdrive's own files in {}; choose a folder outside it",
                canonical.display(),
                own.display()
            ));
        }
    }
    Ok(canonical)
}

/// The sync index of a plain remote; its lock file sits next to it.
pub(crate) fn state_file(paths: &Paths, name: &RemoteName) -> PathBuf {
    paths
        .state
        .join("plain")
        .join(format!("{}.json", name.as_str()))
}

/// Where files deleted on Drive land locally, kept 30 days.
pub(crate) fn trash_dir(paths: &Paths, name: &RemoteName) -> PathBuf {
    paths.data.join(name.as_str()).join("trash")
}

pub(crate) fn options(
    paths: &Paths,
    name: &RemoteName,
    config: &RemoteConfig,
    local_dir: PathBuf,
) -> PlainOptions {
    PlainOptions {
        local_dir,
        folder_id: config.folder_id.clone(),
        state_file: state_file(paths, name),
        trash_dir: trash_dir(paths, name),
        host: short_host_name(),
        stable_age: DEFAULT_STABLE_AGE,
        mirror: config.mirror,
        allow_deletions: None,
        progress: Some(show_progress),
    }
}

/// The host name up to its first dot, for conflict copy names; `host` when
/// it cannot be read or would not be a safe file name part.
fn short_host_name() -> String {
    let mut buffer = [0u8; 256];
    // SAFETY: gethostname writes at most `buffer.len()` bytes into it.
    let rc = unsafe { libc::gethostname(buffer.as_mut_ptr().cast(), buffer.len()) };
    let end = buffer.iter().position(|&b| b == 0).unwrap_or(buffer.len());
    let name = if rc == 0 {
        String::from_utf8_lossy(&buffer[..end]).into_owned()
    } else {
        String::new()
    };
    sanitize_host(&name)
}

fn sanitize_host(name: &str) -> String {
    let short: String = name
        .split('.')
        .next()
        .unwrap_or_default()
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '_')
        .take(63)
        .collect();
    if short.is_empty() {
        "host".to_string()
    } else {
        short
    }
}

impl CycleReport {
    /// Whether the cycle changed anything on either side.
    fn changed(&self) -> bool {
        self.uploaded
            + self.downloaded
            + self.moved
            + self.remote_trashed
            + self.local_trashed
            + self.conflicts
            + self.folders_created
            > 0
    }
}

/// Telemetry of one cycle: counts and durations only, never the per-item
/// error texts, which can name files.
fn record(result: &Result<CycleReport, String>) {
    telemetry::counter("plain.cycles", 1);
    let report = match result {
        Ok(report) => report,
        Err(_) => {
            telemetry::counter("plain.cycles_failed", 1);
            telemetry::event(Level::Standard, "plain.cycle_failed", &[]);
            return;
        }
    };
    telemetry::duration("plain.cycle", report.total);
    telemetry::duration("plain.scan", report.scan);
    telemetry::duration("plain.remote", report.remote);
    for (name, value) in [
        ("plain.uploaded", report.uploaded),
        ("plain.upload_bytes", report.upload_bytes),
        ("plain.downloaded", report.downloaded),
        ("plain.download_bytes", report.download_bytes),
        ("plain.moved", report.moved),
        ("plain.remote_trashed", report.remote_trashed),
        ("plain.local_trashed", report.local_trashed),
        ("plain.conflicts", report.conflicts),
        ("plain.folders_created", report.folders_created),
        ("plain.skipped_unstable", report.skipped_unstable),
        ("plain.skipped_special", report.skipped_special),
        ("plain.held_deletions", report.held_deletions),
        ("plain.parked", report.parked),
        ("plain.kept_folders", report.kept_folders),
        ("plain.item_errors", report.errors.len() as u64),
    ] {
        if value > 0 {
            telemetry::counter(name, value);
        }
    }
    // A quiet cycle every 15 s would fill the standard budget with noise,
    // so it is an event only at `full`.
    let min = if report.changed() || !report.errors.is_empty() {
        Level::Standard
    } else {
        Level::Full
    };
    telemetry::event(
        min,
        "plain.cycle",
        &[
            ("scanned", Field::U64(report.scanned)),
            ("uploaded", Field::U64(report.uploaded)),
            ("downloaded", Field::U64(report.downloaded)),
            ("moved", Field::U64(report.moved)),
            ("remote_trashed", Field::U64(report.remote_trashed)),
            ("local_trashed", Field::U64(report.local_trashed)),
            ("conflicts", Field::U64(report.conflicts)),
            ("skipped_unstable", Field::U64(report.skipped_unstable)),
            ("skipped_special", Field::U64(report.skipped_special)),
            ("held_deletions", Field::U64(report.held_deletions)),
            ("parked", Field::U64(report.parked)),
            ("errors", Field::U64(report.errors.len() as u64)),
            ("scan_ms", Field::U64(millis(report.scan))),
            ("remote_ms", Field::U64(millis(report.remote))),
            ("total_ms", Field::U64(millis(report.total))),
        ],
    );
}

fn millis(duration: Duration) -> u64 {
    u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
}

fn summary(report: &CycleReport) -> String {
    let mut parts = vec![
        format!(
            "{} uploaded ({})",
            report.uploaded,
            remote_cli::size(report.upload_bytes)
        ),
        format!(
            "{} downloaded ({})",
            report.downloaded,
            remote_cli::size(report.download_bytes)
        ),
    ];
    for (count, label) in [
        (report.moved, "moved"),
        (report.remote_trashed, "moved to the Drive bin"),
        (report.local_trashed, "moved to the local trash"),
        (report.conflicts, "conflict copies"),
        (report.folders_created, "folders created"),
        (report.skipped_unstable, "still changing, left for later"),
        (report.skipped_special, "skipped (not a regular file)"),
        (report.parked, "set aside (Drive refuses this account)"),
        (
            report.kept_folders,
            "Drive folders kept for items zdrive does not sync",
        ),
    ] {
        if count > 0 {
            parts.push(format!("{count} {label}"));
        }
    }
    format!(
        "synced {} items in {:.1} s: {}",
        report.scanned,
        report.total.as_secs_f64(),
        parts.join(", ")
    )
}

/// A long cycle's progress, on stderr and to the service manager.
fn show_progress(progress: &Progress) {
    let mut line = if progress.planned > 0 {
        format!(
            "syncing: {} of {} files downloaded ({} of {})",
            progress.downloaded,
            progress.planned,
            remote_cli::size(progress.download_bytes),
            remote_cli::size(progress.planned_bytes)
        )
    } else {
        format!(
            "syncing: {} downloaded ({})",
            progress.downloaded,
            remote_cli::size(progress.download_bytes)
        )
    };
    if progress.uploaded > 0 {
        line.push_str(&format!(
            ", {} uploaded ({})",
            progress.uploaded,
            remote_cli::size(progress.upload_bytes)
        ));
    }
    eprintln!("zerotrust-drive: {line}");
    let _ = service::notify::status(&line);
}

/// Why missing items were not binned on Drive, and the command that bins
/// them after a review.
fn held_warning(report: &CycleReport, rerun: &str) -> Option<String> {
    (report.held_deletions > 0).then(|| {
        format!(
            "{} item(s) missing locally were NOT moved to the Drive bin: {}. Restore them, or if you deleted them on purpose, run: {rerun} --allow-deletions {}",
            report.held_deletions,
            report.held_reason.as_deref().unwrap_or("too many at once"),
            report.held_deletions
        )
    })
}

fn print_report(report: &CycleReport, rerun: &str) {
    println!("{}", summary(report));
    if let Some(held) = held_warning(report, rerun) {
        eprintln!("zerotrust-drive: warning: {held}");
    }
    for error in &report.errors {
        eprintln!("zerotrust-drive: warning: {error}");
    }
}

fn status_line(result: &Result<CycleReport, String>) -> String {
    match result {
        Ok(report) if report.held_deletions > 0 => one_line(&format!(
            "{}; {} deletion(s) held for review, see the log",
            summary(report),
            report.held_deletions
        )),
        Ok(report) if report.errors.is_empty() => one_line(&summary(report)),
        Ok(report) => one_line(&format!(
            "{}; {} item(s) failed",
            summary(report),
            report.errors.len()
        )),
        Err(message) => one_line(&format!("last cycle failed, retrying: {message}")),
    }
}

fn one_line(text: &str) -> String {
    text.chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .take(200)
        .collect()
}

fn report_to_service_manager(sent: std::io::Result<bool>) {
    if let Err(error) = sent {
        eprintln!("zerotrust-drive: warning: cannot notify the service manager: {error}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_names_shrink_to_a_safe_short_label() {
        assert_eq!(sanitize_host("alex-mbp.fritz.box"), "alex-mbp");
        assert_eq!(sanitize_host("odd/name:with space"), "oddnamewithspace");
        assert_eq!(sanitize_host(""), "host");
        assert_eq!(sanitize_host(".local"), "host");
        assert_eq!(sanitize_host(&"x".repeat(300)).len(), 63);
    }

    #[test]
    fn local_folder_refuses_zdrive_own_folders_and_missing_ones() {
        let base = std::env::temp_dir().join(format!(
            "zdrive-plain-cli-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let paths = Paths {
            config: base.join("config/zerotrust-drive"),
            state: base.join("state/zerotrust-drive"),
            data: base.join("data/zerotrust-drive"),
        };
        for dir in [&paths.config, &paths.state, &paths.data] {
            std::fs::create_dir_all(dir).unwrap();
        }
        let folder = base.join("plain");
        std::fs::create_dir_all(&folder).unwrap();

        let canonical = local_folder(&folder, &paths).unwrap();
        assert_eq!(canonical, std::fs::canonicalize(&folder).unwrap());
        for refused in [base.clone(), paths.data.clone(), paths.state.join("plain")] {
            std::fs::create_dir_all(&refused).unwrap();
            let error = local_folder(&refused, &paths).unwrap_err();
            assert!(error.contains("overlaps zdrive's own files"), "{error}");
        }
        let missing = local_folder(&base.join("absent"), &paths).unwrap_err();
        assert!(missing.contains("create the folder first"), "{missing}");
        let file = base.join("file");
        std::fs::write(&file, b"x").unwrap();
        assert!(
            local_folder(&file, &paths)
                .unwrap_err()
                .contains("is not a folder")
        );
        std::fs::remove_dir_all(&base).unwrap();
    }

    #[test]
    fn options_place_state_and_trash_per_remote_name() {
        let paths = Paths {
            config: PathBuf::from("/c/zerotrust-drive"),
            state: PathBuf::from("/s/zerotrust-drive"),
            data: PathBuf::from("/d/zerotrust-drive"),
        };
        let name = RemoteName::parse("photos").unwrap();
        let config = RemoteConfig::plain(
            &name,
            "you@example.com",
            "folder-id",
            "My Drive/ZeroTrust Drive (plain)",
            &crate::remote::config::Issuer::bundled(
                crate::remote::config::ClientKind::BundledDesktop,
            ),
        );
        let options = options(
            &paths,
            &name,
            &config,
            PathBuf::from("/home/you/zdrive/plain"),
        );
        assert_eq!(
            options.state_file,
            PathBuf::from("/s/zerotrust-drive/plain/photos.json")
        );
        assert_eq!(
            options.trash_dir,
            PathBuf::from("/d/zerotrust-drive/photos/trash")
        );
        assert_eq!(options.folder_id, "folder-id");
        assert!(!options.mirror && options.allow_deletions.is_none());
        let mirror = RemoteConfig::mirror(
            &name,
            "you@example.com",
            "0AMyDriveRoot",
            &crate::remote::config::Issuer::bundled_full(),
        );
        let mirrored = super::options(
            &paths,
            &name,
            &mirror,
            PathBuf::from("/home/you/GoogleDrive"),
        );
        assert!(mirrored.mirror);
        assert_eq!(mirrored.folder_id, "0AMyDriveRoot");
        assert_eq!(options.stable_age, DEFAULT_STABLE_AGE);
    }

    #[test]
    fn telemetry_of_a_cycle_has_counts_but_never_item_errors() {
        let report = CycleReport {
            scanned: 3,
            uploaded: 1,
            upload_bytes: 10,
            errors: vec!["secret-canary-name.txt: permission denied".to_string()],
            ..CycleReport::default()
        };
        let line = status_line(&Ok(report.clone()));
        assert!(!line.contains("secret-canary-name"), "{line}");
        assert!(line.contains("1 item(s) failed"), "{line}");
        assert!(report.changed());
        assert!(!CycleReport::default().changed());
    }

    /// A real cycle against the fake Drive, with names, folders and
    /// contents carrying a canary, at `full`: not one byte of telemetry may
    /// contain it, the local folder path or the host name.
    #[test]
    fn plain_sync_telemetry_never_carries_names_paths_or_contents() {
        use crate::telemetry::test_support::{GlobalSession, read_records};

        const CANARY: &str = "zq-plain-canary-5d1c";
        let session = GlobalSession::start(Level::Full, "plain");
        let env = crate::plain::tests::Env::new();
        let replica = env.replica(CANARY);
        assert!(replica.root().to_string_lossy().contains(CANARY));
        replica.write(
            &format!("{CANARY} dir/{CANARY}.txt"),
            format!("{CANARY} local content").as_bytes(),
        );
        replica.write("both.txt", format!("{CANARY} local").as_bytes());
        env.remote_file(
            "",
            &format!("{CANARY} remote.md"),
            format!("{CANARY} remote content").as_bytes(),
        );
        env.remote_file("", "both.txt", format!("{CANARY} remote").as_bytes());

        let report = replica.sync(&env.drive);
        assert!(report.conflicts >= 1 && report.uploaded >= 1, "{report:?}");
        record(&Ok(report));
        let mut failing = CycleReport {
            errors: vec![format!("{CANARY}.txt: permission denied")],
            ..CycleReport::default()
        };
        failing.uploaded = 1;
        record(&Ok(failing));
        record(&Err(format!("read {CANARY}: offline")));
        session.snapshot();
        session.stop("exit", 0);

        let records = read_records(&session.instance_dir());
        let events: Vec<_> = records
            .iter()
            .filter(|record| record["kind"] == "event")
            .filter_map(|record| record["name"].as_str())
            .collect();
        assert!(events.contains(&"plain.cycle"), "{events:?}");
        assert!(events.contains(&"plain.cycle_failed"), "{events:?}");
        let cycles: u64 = records
            .iter()
            .filter(|record| record["kind"] == "snapshot")
            .filter_map(|record| record["counters"]["plain.cycles"].as_u64())
            .sum();
        assert!(cycles >= 3, "plain counters in snapshots: {cycles}");
        let bytes = session.raw_bytes();
        let text = String::from_utf8_lossy(&bytes);
        for needle in [
            CANARY.to_string(),
            replica.root().display().to_string(),
            "testhost".to_string(),
        ] {
            assert!(!text.contains(&needle), "telemetry contains {needle:?}");
        }
    }
}
