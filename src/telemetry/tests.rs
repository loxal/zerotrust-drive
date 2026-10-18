// SPDX-FileCopyrightText: Copyright 2026 Alexander Orlov <info@lifub.com>

use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::time::{Duration, Instant};

use serde_json::Value;

use super::test_support::{GlobalSession, TestTelemetry, of_kind, read_records};
use super::*;
use crate::remote::TestDir;

const DAY_MS: u64 = 86_400_000;
const CANARY: &str = "CANARY-zdrive-secret-name";

fn options(cap_bytes: u64) -> Options {
    Options {
        cap_bytes,
        retention_days: RETENTION_DAYS,
        tick: Duration::from_secs(3600),
        queue_capacity: 256,
        paused: false,
    }
}

fn mode(path: &Path) -> u32 {
    std::fs::metadata(path).unwrap().permissions().mode() & 0o777
}

fn day_names(dir: &Path) -> Vec<String> {
    writer::day_files(dir)
        .unwrap()
        .into_iter()
        .map(|(day, _, _)| system::day_file_name(day))
        .collect()
}

fn dir_bytes(dir: &Path) -> u64 {
    writer::day_files(dir)
        .unwrap()
        .iter()
        .map(|(_, _, len)| len)
        .sum()
}

fn padded(ts: u64, pad: usize) -> Record {
    Record::at("event", ts)
        .with("name", "test.pad")
        .with("pad", "x".repeat(pad))
}

#[test]
fn a_first_telemetry_write_leaves_the_state_root_private_for_sync_state() {
    let telemetry = TestTelemetry::start(Level::Standard);
    assert!(!telemetry.records().is_empty());
    // The writer created the app's state root on the way to its instance
    // directory; remote sync state requires that very root to be private.
    let root = telemetry.state_dir();
    assert_eq!(mode(&root), 0o700);
    assert_eq!(mode(&root.join(DIR_NAME)), 0o700);
    crate::remote::ensure_private_dir(&root).expect("sync state accepts the root");
}

#[test]
fn records_round_trip_through_private_jsonl_files() {
    let telemetry = TestTelemetry::start(Level::Standard);
    telemetry.fuse_op(FuseOp::Lookup, Duration::from_micros(3), None, 0);
    telemetry.fuse_op(
        FuseOp::Lookup,
        Duration::from_micros(900),
        Some(libc::ENOENT),
        0,
    );
    telemetry.fuse_op(FuseOp::Read, Duration::from_micros(40), None, 4096);
    telemetry.remote_request(RequestClass::List, Some(200), Duration::from_millis(12), 1);
    telemetry.remote_request(RequestClass::List, Some(429), Duration::from_millis(3), 1);
    telemetry.remote_request(RequestClass::Upload, None, Duration::from_millis(5), 2);
    telemetry.retry(
        RequestClass::List,
        "rate_limit",
        Duration::from_millis(1500),
    );
    telemetry.duration("v2.commit", Duration::from_millis(7));
    telemetry.counter("v2.objects_written", 3);
    telemetry.event(
        Level::Standard,
        "remote.online",
        &[
            ("offline_ms", Field::U64(42)),
            ("delta", Field::I64(-1)),
            ("ratio", Field::F64(0.5)),
            ("nan", Field::F64(f64::NAN)),
            ("first", Field::Bool(true)),
            ("cause", Field::Tag("network")),
        ],
    );
    // Full-only records stay out at standard.
    telemetry.event(Level::Full, "remote.step", &[]);
    telemetry.fuse_op(FuseOp::Write, Duration::from_secs(1), None, 0);
    telemetry.snapshot();

    let raw = String::from_utf8(telemetry.raw_bytes()).unwrap();
    for line in raw.lines().filter(|line| line.starts_with('{')) {
        assert!(
            line.starts_with(&format!(
                "{{\"schema\":1,\"v\":\"{}\",\"ts\":",
                env!("CARGO_PKG_VERSION")
            )),
            "{line}"
        );
    }
    let records = telemetry.records();
    let kinds: Vec<&str> = records
        .iter()
        .map(|record| record["kind"].as_str().unwrap())
        .collect();
    assert_eq!(kinds, ["start", "event", "snapshot"], "{records:?}");

    let start = &records[0];
    assert_eq!(start["schema"], 1);
    assert_eq!(start["v"], env!("CARGO_PKG_VERSION"));
    assert_eq!(start["os"], std::env::consts::OS);
    assert_eq!(start["mode"], "mount");
    assert_eq!(start["level"], "standard");
    assert_eq!(start["pid"], std::process::id());
    assert!(["macfuse", "fusermount3", "none"].contains(&start["fuse"].as_str().unwrap()));

    let event = &records[1];
    assert_eq!(event["name"], "remote.online");
    assert_eq!(event["fields"]["offline_ms"], 42);
    assert_eq!(event["fields"]["delta"], -1);
    assert_eq!(event["fields"]["ratio"], 0.5);
    assert_eq!(event["fields"]["nan"], Value::Null);
    assert_eq!(event["fields"]["first"], true);
    assert_eq!(event["fields"]["cause"], "network");

    let snapshot = &records[2];
    assert_eq!(snapshot["seq"], 1);
    assert_eq!(snapshot["fuse"]["lookup"]["n"], 2);
    assert_eq!(snapshot["fuse"]["lookup"]["err"], 1);
    assert_eq!(snapshot["fuse"]["lookup"]["errno"]["ENOENT"], 1);
    assert_eq!(
        snapshot["fuse"]["lookup"]["hist"],
        serde_json::json!([[2, 1], [10, 1]])
    );
    assert_eq!(snapshot["fuse"]["read"]["bytes"], 4096);
    assert_eq!(snapshot["errno"]["ENOENT"], 1);
    assert_eq!(snapshot["remote"]["list"]["2xx"], 1);
    assert_eq!(snapshot["remote"]["list"]["429"], 1);
    assert_eq!(snapshot["remote"]["upload"]["network"], 1);
    assert_eq!(snapshot["retries"]["list"]["rate_limit"]["n"], 1);
    assert_eq!(
        snapshot["retries"]["list"]["rate_limit"]["backoff_ms"],
        1500
    );
    assert_eq!(snapshot["durations"]["v2.commit"]["n"], 1);
    assert_eq!(snapshot["counters"]["v2.objects_written"], 3);
    assert_eq!(snapshot["drops"], 0);
    assert_eq!(snapshot["write_errors"], 0);
    assert!(snapshot["rusage"]["max_rss_bytes"].as_u64().unwrap() > 1 << 20);
    assert!(snapshot["fds"].as_u64().unwrap() > 0);

    // A second snapshot reports deltas only.
    telemetry.snapshot();
    let records = telemetry.records();
    let second = records.last().unwrap();
    assert_eq!(second["seq"], 2);
    assert!(second.get("fuse").is_none(), "{second}");
    assert!(second.get("counters").is_none(), "{second}");

    let dir = telemetry.instance_dir();
    assert_eq!(mode(&dir), 0o700);
    assert_eq!(mode(dir.parent().unwrap()), 0o700);
    let (_, file, _) = writer::day_files(&dir).unwrap().pop().unwrap();
    assert_eq!(mode(&file), 0o600);
    assert_eq!(
        file.file_name().unwrap().to_str().unwrap(),
        system::day_file_name(system::utc_day(system::now_ms()))
    );
}

#[test]
fn full_level_adds_slow_ops_requests_and_step_events() {
    let telemetry = TestTelemetry::start(Level::Full);
    telemetry.fuse_op(
        FuseOp::Write,
        Duration::from_millis(300),
        Some(libc::EIO),
        0,
    );
    telemetry.fuse_op(FuseOp::Write, Duration::from_millis(200), None, 0);
    telemetry.remote_request(
        RequestClass::Download,
        Some(503),
        Duration::from_millis(9),
        3,
    );
    telemetry.retry(RequestClass::Download, "server", Duration::from_millis(250));
    telemetry.event(Level::Full, "remote.step", &[("step", Field::Tag("pack"))]);
    let records = telemetry.records();
    let slow = of_kind(&records, "slow_op");
    assert_eq!(slow.len(), 1, "{records:?}");
    assert_eq!(slow[0]["op"], "write");
    assert_eq!(slow[0]["elapsed_us"], 300_000);
    assert_eq!(slow[0]["errno"], "EIO");
    let request = of_kind(&records, "request");
    assert_eq!(request.len(), 1);
    assert_eq!(request[0]["class"], "download");
    assert_eq!(request[0]["status"], 503);
    assert_eq!(request[0]["attempt"], 3);
    let names: Vec<&str> = of_kind(&records, "event")
        .iter()
        .map(|event| event["name"].as_str().unwrap())
        .collect();
    assert_eq!(names, ["remote.retry", "remote.step"]);
    assert_eq!(records[0]["level"], "full");
}

#[test]
fn stop_writes_a_final_snapshot_and_stop_record_and_turns_collection_off() {
    let telemetry = TestTelemetry::start(Level::Standard);
    telemetry.fuse_op(FuseOp::Getattr, Duration::from_micros(5), None, 0);
    let started = Instant::now();
    telemetry.stop("signal", 130);
    assert!(started.elapsed() < Duration::from_millis(2500));
    assert_eq!(telemetry.level(), Level::Off);
    telemetry.fuse_op(FuseOp::Getattr, Duration::from_micros(5), None, 0);
    telemetry.stop("again", 1);

    let records = read_records(&telemetry.instance_dir());
    let kinds: Vec<&str> = records
        .iter()
        .map(|record| record["kind"].as_str().unwrap())
        .collect();
    assert_eq!(kinds, ["start", "snapshot", "stop"]);
    assert_eq!(records[1]["fuse"]["getattr"]["n"], 1);
    assert_eq!(records[2]["reason"], "signal");
    assert_eq!(records[2]["exit_code"], 130);
    assert!(records[2]["uptime_ms"].is_u64());
}

#[test]
fn off_writes_nothing() {
    let telemetry = TestTelemetry::start(Level::Off);
    assert_eq!(telemetry.level(), Level::Off);
    telemetry.fuse_op(FuseOp::Read, Duration::from_secs(1), Some(libc::EIO), 1);
    telemetry.remote_request(RequestClass::Get, Some(500), Duration::from_secs(1), 1);
    telemetry.retry(RequestClass::Get, "server", Duration::from_secs(1));
    telemetry.event(Level::Off, "remote.offline", &[]);
    telemetry.duration("v2.commit", Duration::from_secs(1));
    telemetry.counter("v2.objects_written", 1);
    telemetry.snapshot();
    telemetry.stop("exit", 0);
    assert!(!telemetry.state_dir().join(DIR_NAME).exists());

    let session = GlobalSession::start(Level::Off, "mount");
    assert_eq!(level(), Level::Off);
    fuse_op(FuseOp::Read, Duration::from_secs(1), Some(libc::EIO));
    event(Level::Off, "remote.offline", &[]);
    duration("v2.commit", Duration::from_secs(1));
    counter("v2.objects_written", 1);
    flush();
    session.stop("exit", 0);
    assert!(session.raw_bytes().is_empty());
}

#[test]
fn files_rotate_by_utc_day_and_expire_after_thirty_days() {
    let telemetry = TestTelemetry::start_with(Level::Standard, options(64 << 20));
    let today = system::utc_day(system::now_ms());
    let at = |days_ago: i64| ((today - days_ago) as u64) * DAY_MS + 1_000;
    let names = |days: &[i64]| -> Vec<String> {
        days.iter()
            .map(|days_ago| system::day_file_name(today - days_ago))
            .collect()
    };
    for days_ago in [40, 31, 30] {
        telemetry.send(padded(at(days_ago), 10));
    }
    telemetry.flush();
    assert_eq!(
        day_names(&telemetry.instance_dir()),
        names(&[40, 31, 30, 0])
    );

    // Opening a day file applies retention relative to that day.
    telemetry.send(padded(at(2), 10));
    telemetry.flush();
    assert_eq!(day_names(&telemetry.instance_dir()), names(&[31, 30, 2, 0]));
    telemetry.send(padded(at(0), 10));
    telemetry.flush();
    assert_eq!(day_names(&telemetry.instance_dir()), names(&[30, 2, 0]));
    let records = telemetry.records();
    assert_eq!(records.len(), 4, "{records:?}");
    for record in &records {
        let ts = record["ts"].as_u64().unwrap();
        assert!(today - system::utc_day(ts) <= 30);
    }
}

#[test]
fn the_size_cap_deletes_the_oldest_files_first_and_then_drops() {
    const CAP: u64 = 8 << 10;
    let telemetry = TestTelemetry::start_with(Level::Standard, options(CAP));
    let today = system::utc_day(system::now_ms());
    let at = |days_ago: i64| ((today - days_ago) as u64) * DAY_MS + 1_000;
    for days_ago in [5, 4, 3] {
        for _ in 0..4 {
            telemetry.send(padded(at(days_ago), 500));
        }
    }
    telemetry.flush();
    let before = day_names(&telemetry.instance_dir());
    assert_eq!(before.len(), 4, "{before:?}");

    // Today's records push the oldest days out, one file at a time.
    for _ in 0..8 {
        telemetry.send(padded(at(0), 500));
    }
    telemetry.flush();
    let after = day_names(&telemetry.instance_dir());
    assert!(!after.contains(&before[0]), "{after:?}");
    assert_eq!(after.last(), Some(&system::day_file_name(today)));
    assert!(dir_bytes(&telemetry.instance_dir()) <= CAP);
    assert_eq!(
        telemetry.shared.metrics.cap_drops.load(Ordering::Relaxed),
        0
    );

    // Once only today's file is left, further records are dropped.
    for _ in 0..40 {
        telemetry.send(padded(at(0), 500));
    }
    telemetry.flush();
    assert_eq!(
        day_names(&telemetry.instance_dir()),
        [system::day_file_name(today)]
    );
    assert!(dir_bytes(&telemetry.instance_dir()) <= CAP);
    assert!(telemetry.shared.metrics.cap_drops.load(Ordering::Relaxed) > 0);
}

#[test]
fn a_full_queue_counts_drops_instead_of_blocking() {
    let telemetry = TestTelemetry::start_with(
        Level::Standard,
        Options {
            queue_capacity: 4,
            paused: true,
            ..options(64 << 20)
        },
    );
    let started = Instant::now();
    for _ in 0..10 {
        telemetry.event(Level::Standard, "remote.offline", &[]);
    }
    assert!(started.elapsed() < Duration::from_millis(500));
    assert_eq!(telemetry.shared.metrics.drops.load(Ordering::Relaxed), 6);
    telemetry.resume().unwrap();
    telemetry.snapshot();
    let records = telemetry.records();
    assert_eq!(of_kind(&records, "event").len(), 4);
    assert_eq!(of_kind(&records, "snapshot")[0]["drops"], 6);
}

#[test]
fn an_unwritable_directory_counts_write_errors_without_blocking() {
    // SAFETY: geteuid has no preconditions.
    if unsafe { libc::geteuid() } == 0 {
        // Root ignores directory permissions.
        return;
    }
    let dir = TestDir::new("telemetry-readonly");
    let instance = dir
        .path()
        .join("state")
        .join(DIR_NAME)
        .join(DEFAULT_INSTANCE);
    std::fs::create_dir_all(&instance).unwrap();
    std::fs::set_permissions(
        instance.parent().unwrap(),
        std::fs::Permissions::from_mode(0o700),
    )
    .unwrap();
    std::fs::set_permissions(&instance, std::fs::Permissions::from_mode(0o500)).unwrap();
    let telemetry = Telemetry::new();
    telemetry
        .start_with(
            Start {
                instance: DEFAULT_INSTANCE.to_string(),
                level: Level::Full,
                mode: "mount",
                remote_kind: "none",
                service: false,
            },
            &dir.path().join("state"),
            options(64 << 20),
        )
        .unwrap();
    let started = Instant::now();
    for _ in 0..50 {
        telemetry.event(Level::Standard, "remote.offline", &[]);
        telemetry.fuse_op(FuseOp::Write, Duration::from_millis(1), None, 1);
    }
    telemetry.flush();
    assert!(started.elapsed() < Duration::from_secs(2));
    assert!(read_records(&instance).is_empty());
    assert_eq!(
        telemetry
            .shared
            .metrics
            .write_errors
            .load(Ordering::Relaxed),
        51
    );

    std::fs::set_permissions(&instance, std::fs::Permissions::from_mode(0o700)).unwrap();
    telemetry.snapshot();
    telemetry.stop("exit", 0);
    let records = read_records(&instance);
    assert_eq!(records[0]["kind"], "snapshot");
    assert_eq!(records[0]["write_errors"], 51);
    assert_eq!(records[0]["fuse"]["write"]["n"], 50);
    assert_eq!(records.last().unwrap()["kind"], "stop");
}

#[test]
fn an_unusable_state_directory_degrades_silently() {
    let dir = TestDir::new("telemetry-blocked");
    // A regular file where the state directory should be.
    let state = dir.path().join("state");
    std::fs::write(&state, b"").unwrap();
    let telemetry = Telemetry::new();
    telemetry
        .start(
            Start {
                instance: "blocked".to_string(),
                level: Level::Standard,
                mode: "plain",
                remote_kind: "none",
                service: true,
            },
            &state,
        )
        .unwrap();
    telemetry.event(Level::Standard, "remote.offline", &[]);
    telemetry.flush();
    assert!(
        telemetry
            .shared
            .metrics
            .write_errors
            .load(Ordering::Relaxed)
            >= 2
    );
    let started = Instant::now();
    telemetry.stop("exit", 0);
    assert!(started.elapsed() < Duration::from_millis(2500));
}

#[test]
fn start_rejects_invalid_instances_and_stays_off() {
    let dir = TestDir::new("telemetry-instance");
    for name in ["", "Upper", "-dash", "a/b", "..", &"x".repeat(64)] {
        let telemetry = Telemetry::new();
        let error = telemetry
            .start(
                Start {
                    instance: name.to_string(),
                    level: Level::Full,
                    mode: "mount",
                    remote_kind: "none",
                    service: false,
                },
                dir.path(),
            )
            .unwrap_err();
        assert!(error.contains("invalid telemetry instance"), "{error}");
        assert_eq!(telemetry.level(), Level::Off);
    }
    for name in ["zdrive", "0", "work_drive-2", &"x".repeat(63)] {
        assert_eq!(validate_instance(name), Ok(()), "{name}");
    }
}

#[test]
fn level_precedence_is_flag_then_env_then_config_then_default() {
    let dir = TestDir::new("telemetry-level");
    let config = dir.path().join("config");
    assert_eq!(
        resolve_level(None, None, &config),
        Ok((Level::Standard, LevelSource::Default))
    );
    assert_eq!(
        resolve_level(None, Some(" "), &config),
        Ok((Level::Standard, LevelSource::Default))
    );
    save_config_level(&config, Level::Off).unwrap();
    assert_eq!(
        resolve_level(None, None, &config),
        Ok((Level::Off, LevelSource::Config))
    );
    assert_eq!(
        resolve_level(None, Some("FULL"), &config),
        Ok((Level::Full, LevelSource::Env))
    );
    assert_eq!(
        resolve_level(Some(Level::Standard), Some("full"), &config),
        Ok((Level::Standard, LevelSource::Cli))
    );
    // An invalid environment value fails even when a flag would not need it.
    let error = resolve_level(None, Some("verbose"), &config).unwrap_err();
    assert!(
        error.contains("ZDRIVE_TELEMETRY") && error.contains("off, standard or full"),
        "{error}"
    );

    let file = config.join(CONFIG_FILE);
    crate::remote::write_private_file(&file, b"{\"level\":\"loud\"}").unwrap();
    let error = resolve_level(None, None, &config).unwrap_err();
    assert!(error.contains("off, standard or full"), "{error}");
    assert_eq!(
        resolve_level(None, Some("off"), &config),
        Ok((Level::Off, LevelSource::Env))
    );
    crate::remote::write_private_file(&file, b"not json").unwrap();
    assert!(resolve_level(None, None, &config).is_err());
    std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o644)).unwrap();
    assert!(
        resolve_level(None, None, &config)
            .unwrap_err()
            .contains("chmod 600")
    );
}

#[test]
fn panic_messages_are_redacted() {
    let cases = [
        (
            "failed to open /Users/alex/zdrive/Tax 2025/report.pdf: denied",
            // Every token with a slash is a path, even after a space.
            "failed to open <path> <path> denied",
        ),
        (
            "bad name \"secret plan.txt\" in dir",
            "bad name \"<str>\" in dir",
        ),
        (
            "index out of bounds: the len is 3 but the index is 7",
            "index out of bounds: the len is 3 but the index is 7",
        ),
        ("C:\\Users\\alex\\file", "<path>"),
        ("mail alex@example.com failed", "mail <email> failed"),
        ("cannot read notes.md now", "cannot read <name> now"),
        ("version 0.18.0 took 1.5 s", "version 0.18.0 took 1.5 s"),
        ("unterminated \"quote /etc", "unterminated \"<str>"),
    ];
    for (message, expected) in cases {
        assert_eq!(redact_panic_message(message), expected, "{message}");
    }
    let long = "word ".repeat(100);
    assert_eq!(redact_panic_message(&long).chars().count(), 200);
    assert_eq!(panic_location("src/fs.rs", 10, 5), "src/fs.rs:10:5");
    assert_eq!(
        panic_location(
            "/Users/alex/.cargo/registry/src/x/fuser-0.18/src/lib.rs",
            1,
            2
        ),
        "fuser-0.18/src/lib.rs:1:2"
    );
    assert_eq!(thread_label(Some("my secret thread")), "other");
    assert_eq!(thread_label(Some("zdrive-replicator")), "zdrive-replicator");
}

#[test]
fn export_writes_a_ustar_archive_that_tar_reads() {
    let telemetry = TestTelemetry::start(Level::Standard);
    telemetry.event(Level::Standard, "remote.online", &[]);
    telemetry.flush();
    let root = telemetry.state_dir().join(DIR_NAME);
    let (_, file, _) = writer::day_files(&telemetry.instance_dir())
        .unwrap()
        .pop()
        .unwrap();
    let expected = std::fs::read(&file).unwrap();
    let day = file.file_name().unwrap().to_str().unwrap().to_string();
    // Not an instance: skipped.
    std::fs::create_dir_all(root.join("Not An Instance")).unwrap();

    let out = TestDir::new("telemetry-export");
    let archive = out.path().join("telemetry.tar");
    let exported = tar::export(&root, &archive).unwrap();
    assert_eq!(exported.files, 1);
    assert_eq!(exported.bytes, expected.len() as u64);
    assert_eq!(mode(&archive), 0o600);
    assert_eq!(std::fs::metadata(&archive).unwrap().len() % 512, 0);
    // An existing archive is never replaced.
    assert!(tar::export(&root, &archive).is_err());

    let listing = std::process::Command::new("tar")
        .arg("-tf")
        .arg(&archive)
        .output()
        .unwrap();
    assert!(listing.status.success(), "{listing:?}");
    let names: Vec<String> = String::from_utf8(listing.stdout)
        .unwrap()
        .lines()
        .map(|line| line.trim_end_matches('/').to_string())
        .collect();
    let member = format!("{}/zdrive/{day}", tar::ARCHIVE_ROOT);
    assert_eq!(
        names,
        [
            tar::ARCHIVE_ROOT.to_string(),
            format!("{}/zdrive", tar::ARCHIVE_ROOT),
            member.clone()
        ]
    );
    let content = std::process::Command::new("tar")
        .arg("-xOf")
        .arg(&archive)
        .arg(&member)
        .output()
        .unwrap();
    assert!(content.status.success(), "{content:?}");
    assert_eq!(content.stdout, expected);
}

#[test]
fn report_merges_snapshots_lifecycle_and_final_push_outcomes() {
    let telemetry = TestTelemetry::start(Level::Full);
    // Nearest rank over 700, 800, 900 and 2000 us: p50 is the 800 us
    // bucket (< 1.024 ms), p95 and p99 the 2000 us bucket (< 2.048 ms).
    for micros in [700, 800, 2_000] {
        telemetry.fuse_op(FuseOp::Lookup, Duration::from_micros(micros), None, 0);
    }
    telemetry.fuse_op(
        FuseOp::Lookup,
        Duration::from_micros(900),
        Some(libc::ENOENT),
        0,
    );
    telemetry.remote_request(RequestClass::List, Some(429), Duration::from_millis(4), 1);
    telemetry.retry(
        RequestClass::List,
        "rate_limit",
        Duration::from_millis(1000),
    );
    telemetry.remote_request(RequestClass::List, Some(200), Duration::from_millis(4), 2);
    telemetry.duration("remote.push", Duration::from_millis(900));
    telemetry.event(
        Level::Standard,
        "remote.final_push",
        &[
            ("outcome", Field::Tag("pushed")),
            ("elapsed_ms", Field::U64(1200)),
        ],
    );
    telemetry.snapshot();
    telemetry.counter("remote.push.objects", 2);
    telemetry.stop("exit", 0);
    // A run of another process that vanished without a stop record.
    let dir = telemetry.instance_dir();
    let (_, file, _) = writer::day_files(&dir).unwrap().pop().unwrap();
    let crashed = Record::new("start")
        .with("mode", "mount")
        .with("pid", i32::MAX)
        .line();
    let mut text = std::fs::read_to_string(&file).unwrap();
    text.push_str(&crashed);
    text.push_str("\nnot json\n");
    std::fs::write(&file, text).unwrap();

    let root = telemetry.state_dir().join(DIR_NAME);
    let summary = report::build(
        &root,
        None,
        Duration::from_secs(3600),
        "1h",
        system::now_ms() + 1_000,
    )
    .unwrap();
    let json = summary.to_json();
    assert_eq!(json["instances"], serde_json::json!(["zdrive"]));
    assert_eq!(json["snapshots"], 2);
    assert_eq!(json["skipped_lines"], 1);
    assert_eq!(json["fuse"]["lookup"]["n"], 4);
    assert_eq!(json["fuse"]["lookup"]["err"], 1);
    assert_eq!(json["fuse"]["lookup"]["p50_ms"], 1.024);
    assert_eq!(json["fuse"]["lookup"]["p99_ms"], 2.048);
    assert_eq!(json["errnos"][0]["errno"], "ENOENT");
    assert_eq!(json["remote"]["list"]["429"], 1);
    assert_eq!(json["remote"]["list"]["2xx"], 1);
    assert_eq!(json["rate_limited_retries"], 1);
    assert_eq!(json["http_429"], 1);
    assert_eq!(json["full_request_records"], 2);
    assert_eq!(json["durations"]["remote.push"]["n"], 1);
    assert_eq!(json["counters"]["remote.push.objects"], 2);
    assert_eq!(json["final_push"]["pushed"], 1);
    assert_eq!(json["lifecycle"]["starts"], 2);
    assert_eq!(json["lifecycle"]["stops"], 1);
    assert_eq!(json["lifecycle"]["unclean_exits"], 1);
    assert_eq!(json["lifecycle"]["crashes"], 1);
    assert_eq!(json["evidence"][0], file.display().to_string());

    let text = summary.to_text();
    assert!(text.starts_with("telemetry report: last 1h,"), "{text}");
    assert!(text.contains("  lookup 4 1 1.024/2.048/2.048"), "{text}");
    assert!(text.contains("rate-limited 1, http 429 1"), "{text}");
    assert!(text.contains("final push: pushed=1"), "{text}");
    assert!(text.contains("unclean exits 1"), "{text}");
    assert!(text.contains(&file.display().to_string()), "{text}");

    let other = report::build(
        &root,
        Some("other"),
        Duration::from_secs(3600),
        "1h",
        system::now_ms(),
    )
    .unwrap()
    .to_json();
    assert_eq!(other["records"], 0);
}

#[test]
fn the_fuse_call_guard_records_every_exit_path() {
    let session = GlobalSession::start(Level::Standard, "mount");
    assert_eq!(level(), Level::Standard);
    let early = |fail: bool| {
        let call = FuseCall::begin(FuseOp::Mknod);
        if fail {
            return Err(call.fail(fuser::Errno::EROFS));
        }
        call.bytes(10);
        call.bytes(5);
        Ok(())
    };
    assert!(early(true).is_err());
    assert!(early(false).is_ok());
    session.snapshot();
    let records = session.records();
    let snapshot = of_kind(&records, "snapshot")[0];
    assert_eq!(snapshot["fuse"]["mknod"]["n"], 2);
    assert_eq!(snapshot["fuse"]["mknod"]["err"], 1);
    assert_eq!(snapshot["fuse"]["mknod"]["errno"]["EROFS"], 1);
    assert_eq!(snapshot["fuse"]["mknod"]["bytes"], 15);
}

/// Drives every record kind through the global session and the hooked
/// sync code with names, paths and contents carrying a canary; not one
/// byte of telemetry may contain it.
#[test]
fn no_name_path_or_content_reaches_telemetry() {
    use crate::remote::sync::tests::{CANARY as CONTENT_CANARY, Env, PASSPHRASE, Store, content};

    let session = GlobalSession::start(Level::Full, "remote");
    install_panic_hook();

    let env = Env::new();
    let mut store = Store::create_in(
        TestDir::new(CANARY),
        crate::remote::config::test_kdf(),
        &[(&format!("{CANARY}.txt"), content(7, 2_000))],
    );
    assert!(store.dir.path().to_string_lossy().contains(CANARY));
    env.push(&store).unwrap();
    store.write(&format!("{CANARY} inner.md"), content(8, 300_000));
    env.push(&store).unwrap();
    crate::remote::gdrive::fault_listings(&env.fake);
    env.drive.list(&env.folder, false).unwrap();

    fuse_op(
        FuseOp::Lookup,
        Duration::from_millis(300),
        Some(libc::ENOENT),
    );
    {
        let call = FuseCall::begin(FuseOp::Read);
        call.bytes(4096);
    }
    event(
        Level::Standard,
        "remote.final_push",
        &[("outcome", Field::Tag("pushed"))],
    );
    duration("plain.cycle", Duration::from_millis(3));
    counter("test.canary", 1);
    let result = std::panic::catch_unwind(|| {
        panic!(
            "open /home/user/{CANARY}/x failed: {:?} {CANARY}.txt user@{CANARY}.example",
            format!("{CANARY} plan")
        )
    });
    assert!(result.is_err());
    session.snapshot();
    session.stop("exit", 0);

    let bytes = session.raw_bytes();
    let records = read_records(&session.instance_dir());
    for kind in [
        "start", "snapshot", "slow_op", "request", "event", "panic", "stop",
    ] {
        assert!(
            !of_kind(&records, kind).is_empty(),
            "no {kind} record: {records:?}"
        );
    }
    // The hook is process-wide: panics of concurrently running tests may
    // be recorded as well.
    let panic = of_kind(&records, "panic")
        .into_iter()
        .find(|panic| {
            panic["message"]
                .as_str()
                .is_some_and(|message| message.starts_with("open <path> failed: \"<str>\""))
        })
        .unwrap_or_else(|| panic!("no redacted canary panic: {records:?}"));
    assert!(
        panic["location"]
            .as_str()
            .unwrap()
            .starts_with("src/telemetry/tests.rs:"),
        "{panic}"
    );
    let merged: serde_json::Map<String, Value> = of_kind(&records, "snapshot")
        .iter()
        .filter_map(|snapshot| snapshot["remote"].as_object())
        .flat_map(|remote| remote.clone())
        .collect();
    assert!(!merged.is_empty(), "the sync workload recorded no requests");
    for needle in [
        CANARY.as_bytes(),
        PASSPHRASE.as_bytes(),
        CONTENT_CANARY,
        b"/home/user",
    ] {
        assert!(
            !bytes.windows(needle.len()).any(|window| window == needle),
            "telemetry leaked {:?}: {}",
            String::from_utf8_lossy(needle),
            String::from_utf8_lossy(&bytes)
        );
    }
}
