// SPDX-FileCopyrightText: Copyright 2026 Alexander Orlov <info@lifub.com>

//! `zdrive telemetry report`: merges the records of a time window into
//! latency percentiles, error, retry and lifecycle summaries.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::io::{BufRead, BufReader, Read};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde_json::{Map, Value, json};

use super::histogram::{self, Buckets};
use super::{SCHEMA, system, tar, writer};

const MAX_LINE: usize = 1 << 20;
const MAX_SINCE_DAYS: u64 = 3650;

/// Parses `90m`, `24h`, `7d` or `30s`.
pub(crate) fn parse_since(text: &str) -> Result<Duration, String> {
    let invalid = || {
        format!(
            "invalid duration {:?}; use a positive number with s, m, h or d, e.g. 90m, 24h or 7d",
            text.chars().take(32).collect::<String>()
        )
    };
    let text = text.trim();
    let Some((split, _)) = text.char_indices().last() else {
        return Err(invalid());
    };
    let (number, unit) = text.split_at(split);
    let number: u64 = number.parse().map_err(|_| invalid())?;
    let seconds = match unit {
        "s" => 1,
        "m" => 60,
        "h" => 3_600,
        "d" => 86_400,
        _ => return Err(invalid()),
    };
    let total = number.checked_mul(seconds).ok_or_else(invalid)?;
    if total == 0 || total > MAX_SINCE_DAYS * 86_400 {
        return Err(invalid());
    }
    Ok(Duration::from_secs(total))
}

/// Histogram buckets with a `Default` (arrays this long have none).
struct Latency(Buckets);

impl Default for Latency {
    fn default() -> Self {
        Self([0; histogram::BUCKETS])
    }
}

impl std::ops::Deref for Latency {
    type Target = Buckets;

    fn deref(&self) -> &Buckets {
        &self.0
    }
}

impl std::ops::DerefMut for Latency {
    fn deref_mut(&mut self) -> &mut Buckets {
        &mut self.0
    }
}

#[derive(Default)]
struct OpSummary {
    n: u64,
    err: u64,
    bytes: u64,
    latency: Latency,
}

#[derive(Default)]
struct RemoteSummary {
    status: BTreeMap<String, u64>,
    latency: Latency,
}

#[derive(Clone, Copy)]
enum Lifecycle {
    Start,
    Stop,
    Panic,
}

/// Everything a report shows, merged over the window.
#[derive(Default)]
pub(crate) struct Summary {
    since: String,
    from_ts: u64,
    to_ts: u64,
    instances: BTreeSet<String>,
    evidence: Vec<PathBuf>,
    records: u64,
    skipped: u64,
    snapshots: u64,
    fuse: BTreeMap<String, OpSummary>,
    errnos: BTreeMap<String, BTreeMap<String, u64>>,
    remote: BTreeMap<String, RemoteSummary>,
    retries: BTreeMap<String, BTreeMap<String, (u64, u64)>>,
    durations: BTreeMap<String, Buckets>,
    counters: BTreeMap<String, u64>,
    lifecycle: BTreeMap<String, Vec<(u64, Lifecycle, u64)>>,
    starts_by_mode: BTreeMap<String, u64>,
    stop_reasons: BTreeMap<String, u64>,
    failed_exits: u64,
    panics: BTreeMap<String, u64>,
    unclean_exits: u64,
    running: u64,
    crashes: u64,
    final_push: BTreeMap<String, u64>,
    final_push_latency: Latency,
    slow_ops: BTreeMap<String, u64>,
    requests: u64,
    events: BTreeMap<String, u64>,
    max_rss_bytes: u64,
    user_ms: u64,
    sys_ms: u64,
    max_fds: u64,
    drops: u64,
    cap_drops: u64,
    write_errors: u64,
}

/// Reads every instance below `root` (or only `instance`) for the window
/// ending at `now_ms`.
pub(crate) fn build(
    root: &Path,
    instance: Option<&str>,
    since: Duration,
    since_label: &str,
    now_ms: u64,
) -> Result<Summary, String> {
    let window_ms = u64::try_from(since.as_millis()).unwrap_or(u64::MAX);
    let cutoff = now_ms.saturating_sub(window_ms);
    let mut summary = Summary {
        since: since_label.to_string(),
        from_ts: cutoff,
        to_ts: now_ms,
        ..Summary::default()
    };
    for (name, dir) in tar::instance_dirs(root)? {
        if instance.is_some_and(|wanted| wanted != name) {
            continue;
        }
        let files =
            writer::day_files(&dir).map_err(|error| format!("{}: {error}", dir.display()))?;
        for (day, path, _) in files {
            if day < system::utc_day(cutoff) {
                continue;
            }
            if summary.read_file(&name, &path, cutoff)? {
                summary.instances.insert(name.clone());
                summary.evidence.push(path);
            }
        }
    }
    summary.settle_lifecycle(system::process_alive);
    Ok(summary)
}

fn as_u64(value: &Value) -> u64 {
    value.as_u64().unwrap_or(0)
}

fn str_of<'a>(value: &'a Value, key: &str) -> &'a str {
    value.get(key).and_then(Value::as_str).unwrap_or("unknown")
}

impl Summary {
    /// `true` when the file held a record inside the window.
    fn read_file(&mut self, instance: &str, path: &Path, cutoff: u64) -> Result<bool, String> {
        let file = match std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW)
            .open(path)
        {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
            Err(error) => return Err(format!("{}: {error}", path.display())),
        };
        let mut reader = BufReader::new(file);
        let mut line = Vec::new();
        let mut used = false;
        loop {
            line.clear();
            let read = (&mut reader)
                .take(MAX_LINE as u64 + 1)
                .read_until(b'\n', &mut line)
                .map_err(|error| format!("{}: {error}", path.display()))?;
            if read == 0 {
                break;
            }
            if line.len() > MAX_LINE {
                self.skipped += 1;
                // Skip the rest of an overlong line.
                let mut rest = Vec::new();
                reader
                    .read_until(b'\n', &mut rest)
                    .map_err(|error| format!("{}: {error}", path.display()))?;
                continue;
            }
            let Ok(record) = serde_json::from_slice::<Value>(&line) else {
                self.skipped += 1;
                continue;
            };
            let (Some(SCHEMA), Some(ts), Some(kind)) = (
                record.get("schema").and_then(Value::as_u64),
                record.get("ts").and_then(Value::as_u64),
                record.get("kind").and_then(Value::as_str),
            ) else {
                self.skipped += 1;
                continue;
            };
            if ts < cutoff {
                continue;
            }
            used = true;
            self.records += 1;
            self.add(instance, ts, kind, &record);
        }
        Ok(used)
    }

    fn add(&mut self, instance: &str, ts: u64, kind: &str, record: &Value) {
        let pid = record.get("pid").map_or(0, as_u64);
        match kind {
            "start" => {
                *self
                    .starts_by_mode
                    .entry(str_of(record, "mode").to_string())
                    .or_default() += 1;
                self.lifecycle
                    .entry(instance.to_string())
                    .or_default()
                    .push((ts, Lifecycle::Start, pid));
            }
            "stop" => {
                *self
                    .stop_reasons
                    .entry(str_of(record, "reason").to_string())
                    .or_default() += 1;
                if failed_stop(record) {
                    self.failed_exits += 1;
                }
                self.lifecycle
                    .entry(instance.to_string())
                    .or_default()
                    .push((ts, Lifecycle::Stop, pid));
            }
            "snapshot" => self.add_snapshot(record),
            "slow_op" => {
                *self
                    .slow_ops
                    .entry(str_of(record, "op").to_string())
                    .or_default() += 1
            }
            "request" => self.requests += 1,
            "event" => {
                let name = str_of(record, "name");
                *self.events.entry(name.to_string()).or_default() += 1;
                if name == "remote.final_push" {
                    let fields = record.get("fields").unwrap_or(&Value::Null);
                    *self
                        .final_push
                        .entry(str_of(fields, "outcome").to_string())
                        .or_default() += 1;
                    if let Some(ms) = fields.get("elapsed_ms").and_then(Value::as_u64) {
                        histogram::record(&mut self.final_push_latency, ms.saturating_mul(1000));
                    }
                }
            }
            "panic" => {
                *self
                    .panics
                    .entry(str_of(record, "location").to_string())
                    .or_default() += 1;
                self.lifecycle
                    .entry(instance.to_string())
                    .or_default()
                    .push((ts, Lifecycle::Panic, pid));
            }
            _ => {}
        }
    }

    fn add_snapshot(&mut self, record: &Value) {
        self.snapshots += 1;
        if let Some(ops) = record.get("fuse").and_then(Value::as_object) {
            for (op, entry) in ops {
                let summary = self.fuse.entry(op.clone()).or_default();
                summary.n += entry.get("n").map_or(0, as_u64);
                summary.err += entry.get("err").map_or(0, as_u64);
                summary.bytes += entry.get("bytes").map_or(0, as_u64);
                if let Some(hist) = entry.get("hist") {
                    histogram::merge_sparse(&mut summary.latency, hist);
                }
                if let Some(errnos) = entry.get("errno").and_then(Value::as_object) {
                    for (name, count) in errnos {
                        *self
                            .errnos
                            .entry(name.clone())
                            .or_default()
                            .entry(op.clone())
                            .or_default() += as_u64(count);
                    }
                }
            }
        }
        if let Some(classes) = record.get("remote").and_then(Value::as_object) {
            for (class, entry) in classes {
                let summary = self.remote.entry(class.clone()).or_default();
                let Some(entry) = entry.as_object() else {
                    continue;
                };
                for (key, value) in entry {
                    if key == "hist" {
                        histogram::merge_sparse(&mut summary.latency, value);
                    } else {
                        *summary.status.entry(key.clone()).or_default() += as_u64(value);
                    }
                }
            }
        }
        if let Some(classes) = record.get("retries").and_then(Value::as_object) {
            for (class, reasons) in classes {
                let Some(reasons) = reasons.as_object() else {
                    continue;
                };
                for (reason, entry) in reasons {
                    let slot = self
                        .retries
                        .entry(class.clone())
                        .or_default()
                        .entry(reason.clone())
                        .or_default();
                    slot.0 += entry.get("n").map_or(0, as_u64);
                    slot.1 += entry.get("backoff_ms").map_or(0, as_u64);
                }
            }
        }
        if let Some(durations) = record.get("durations").and_then(Value::as_object) {
            for (name, entry) in durations {
                let buckets = self
                    .durations
                    .entry(name.clone())
                    .or_insert([0; histogram::BUCKETS]);
                if let Some(hist) = entry.get("hist") {
                    histogram::merge_sparse(buckets, hist);
                }
            }
        }
        if let Some(counters) = record.get("counters").and_then(Value::as_object) {
            for (name, value) in counters {
                *self.counters.entry(name.clone()).or_default() += as_u64(value);
            }
        }
        if let Some(rusage) = record.get("rusage") {
            self.max_rss_bytes = self
                .max_rss_bytes
                .max(rusage.get("max_rss_bytes").map_or(0, as_u64));
            self.user_ms += rusage.get("user_ms").map_or(0, as_u64);
            self.sys_ms += rusage.get("sys_ms").map_or(0, as_u64);
        }
        self.max_fds = self.max_fds.max(record.get("fds").map_or(0, as_u64));
        self.drops += record.get("drops").map_or(0, as_u64);
        self.cap_drops += record.get("cap_drops").map_or(0, as_u64);
        self.write_errors += record.get("write_errors").map_or(0, as_u64);
    }

    /// Pairs start, panic and stop records per instance and pid. A start
    /// followed by another start of the same pid, or whose process is gone,
    /// without a stop was an unclean exit; one whose process still runs is
    /// counted as running. A crashed run is one that panicked or exited
    /// uncleanly, counted once.
    fn settle_lifecycle(&mut self, alive: impl Fn(u32) -> bool) {
        for entries in self.lifecycle.values_mut() {
            entries.sort_by_key(|(ts, _, _)| *ts);
            // Open runs by pid, with whether they panicked.
            let mut open: HashMap<u64, bool> = HashMap::new();
            for (_, kind, pid) in entries.iter() {
                match kind {
                    Lifecycle::Start => {
                        if open.insert(*pid, false).is_some() {
                            self.unclean_exits += 1;
                            self.crashes += 1;
                        }
                    }
                    Lifecycle::Stop => {
                        if open.remove(pid) == Some(true) {
                            self.crashes += 1;
                        }
                    }
                    Lifecycle::Panic => match open.get_mut(pid) {
                        Some(panicked) => *panicked = true,
                        // A panic of a run that started before the window.
                        None => self.crashes += 1,
                    },
                }
            }
            for (pid, panicked) in open {
                if u32::try_from(pid).is_ok_and(&alive) {
                    self.running += 1;
                    if panicked {
                        self.crashes += 1;
                    }
                } else {
                    self.unclean_exits += 1;
                    self.crashes += 1;
                }
            }
        }
    }

    fn panic_count(&self) -> u64 {
        self.panics.values().sum()
    }

    pub(crate) fn to_json(&self) -> Value {
        let percentiles = |buckets: &Buckets, entry: &mut Map<String, Value>| {
            for (key, q) in [("p50_ms", 0.5), ("p95_ms", 0.95), ("p99_ms", 0.99)] {
                if let Some(ms) = histogram::percentile_ms(buckets, q) {
                    entry.insert(key.to_string(), json!(ms));
                }
            }
        };
        let mut fuse = Map::new();
        for (op, summary) in &self.fuse {
            let mut entry = Map::new();
            entry.insert("n".to_string(), summary.n.into());
            entry.insert("err".to_string(), summary.err.into());
            if summary.bytes > 0 {
                entry.insert("bytes".to_string(), summary.bytes.into());
            }
            percentiles(&summary.latency, &mut entry);
            fuse.insert(op.clone(), Value::Object(entry));
        }
        let errnos: Vec<Value> = self
            .top_errnos()
            .into_iter()
            .map(|(name, total, ops)| json!({"errno": name, "n": total, "ops": ops}))
            .collect();
        let mut remote = Map::new();
        for (class, summary) in &self.remote {
            let mut entry: Map<String, Value> = summary
                .status
                .iter()
                .map(|(key, count)| (key.clone(), Value::from(*count)))
                .collect();
            percentiles(&summary.latency, &mut entry);
            remote.insert(class.clone(), Value::Object(entry));
        }
        let retries: Map<String, Value> = self
            .retries
            .iter()
            .map(|(class, reasons)| {
                let reasons: Map<String, Value> = reasons
                    .iter()
                    .map(|(reason, (n, backoff_ms))| {
                        (reason.clone(), json!({"n": n, "backoff_ms": backoff_ms}))
                    })
                    .collect();
                (class.clone(), Value::Object(reasons))
            })
            .collect();
        let mut durations = Map::new();
        for (name, buckets) in &self.durations {
            let mut entry = Map::new();
            entry.insert("n".to_string(), histogram::total(buckets).into());
            percentiles(buckets, &mut entry);
            durations.insert(name.clone(), Value::Object(entry));
        }
        let mut final_push: Map<String, Value> = self
            .final_push
            .iter()
            .map(|(outcome, count)| (outcome.clone(), Value::from(*count)))
            .collect();
        percentiles(&self.final_push_latency, &mut final_push);
        json!({
            "since": self.since,
            "from_ts": self.from_ts,
            "to_ts": self.to_ts,
            "instances": self.instances,
            "records": self.records,
            "snapshots": self.snapshots,
            "skipped_lines": self.skipped,
            "fuse": fuse,
            "errnos": errnos,
            "remote": remote,
            "retries": retries,
            "rate_limited_retries": self.rate_limited_retries(),
            "http_429": self.http_429(),
            "full_request_records": self.requests,
            "durations": durations,
            "counters": self.counters,
            "lifecycle": {
                "starts": self.starts_by_mode.values().sum::<u64>(),
                "starts_by_mode": self.starts_by_mode,
                "stops": self.stop_reasons.values().sum::<u64>(),
                "stop_reasons": self.stop_reasons,
                "failed_exits": self.failed_exits,
                "unclean_exits": self.unclean_exits,
                "running": self.running,
                "panics": self.panic_count(),
                "panic_locations": self.panics,
                "crashes": self.crashes,
            },
            "final_push": final_push,
            "slow_ops": self.slow_ops,
            "events": self.events,
            "resources": {
                "max_rss_bytes": self.max_rss_bytes,
                "user_ms": self.user_ms,
                "sys_ms": self.sys_ms,
                "max_fds": self.max_fds,
            },
            "drops": self.drops,
            "cap_drops": self.cap_drops,
            "write_errors": self.write_errors,
            "evidence": self
                .evidence
                .iter()
                .map(|path| path.display().to_string())
                .collect::<Vec<_>>(),
        })
    }

    fn rate_limited_retries(&self) -> u64 {
        self.retries
            .values()
            .filter_map(|reasons| reasons.get("rate_limit"))
            .map(|(n, _)| n)
            .sum()
    }

    fn http_429(&self) -> u64 {
        self.remote
            .values()
            .filter_map(|summary| summary.status.get("429"))
            .sum()
    }

    /// Errno names by total count, each with its per-op counts.
    fn top_errnos(&self) -> Vec<(String, u64, BTreeMap<String, u64>)> {
        let mut errnos: Vec<_> = self
            .errnos
            .iter()
            .map(|(name, ops)| (name.clone(), ops.values().sum::<u64>(), ops.clone()))
            .collect();
        errnos.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
        errnos.truncate(10);
        errnos
    }

    pub(crate) fn to_text(&self) -> String {
        let mut out = String::new();
        let mut line = |text: String| {
            out.push_str(&text);
            out.push('\n');
        };
        let instances: Vec<&str> = self.instances.iter().map(String::as_str).collect();
        line(format!(
            "telemetry report: last {}, {} records in {} snapshots, instances: {}",
            self.since,
            self.records,
            self.snapshots,
            if instances.is_empty() {
                "none".to_string()
            } else {
                instances.join(", ")
            }
        ));
        if self.records == 0 {
            line("no telemetry recorded in this window".to_string());
        }
        let pct = |buckets: &Buckets| {
            ["p50", "p95", "p99"]
                .iter()
                .zip([0.5, 0.95, 0.99])
                .map(|(_, q)| {
                    histogram::percentile_ms(buckets, q).map_or("-".to_string(), format_ms)
                })
                .collect::<Vec<_>>()
                .join("/")
        };
        if !self.fuse.is_empty() {
            line("fuse ops (n err p50/p95/p99 ms):".to_string());
            for (op, summary) in &self.fuse {
                let bytes = if summary.bytes > 0 {
                    format!(" bytes={}", summary.bytes)
                } else {
                    String::new()
                };
                line(format!(
                    "  {op} {} {} {}{bytes}",
                    summary.n,
                    summary.err,
                    pct(&summary.latency)
                ));
            }
        }
        let errnos = self.top_errnos();
        if !errnos.is_empty() {
            let text: Vec<String> = errnos
                .iter()
                .map(|(name, total, ops)| format!("{name} {total} ({})", join_counts(ops)))
                .collect();
            line(format!("errnos: {}", text.join("; ")));
        }
        if !self.remote.is_empty() {
            line("remote requests (status counts | p50/p95/p99 ms):".to_string());
            for (class, summary) in &self.remote {
                line(format!(
                    "  {class}: {} | {}",
                    join_counts(&summary.status),
                    pct(&summary.latency)
                ));
            }
        }
        if !self.retries.is_empty() {
            let text: Vec<String> = self
                .retries
                .iter()
                .flat_map(|(class, reasons)| {
                    reasons.iter().map(move |(reason, (n, backoff_ms))| {
                        format!("{class}/{reason} {n} ({backoff_ms} ms backoff)")
                    })
                })
                .collect();
            line(format!(
                "retries: {}; rate-limited {}, http 429 {}",
                text.join(", "),
                self.rate_limited_retries(),
                self.http_429()
            ));
        }
        if !self.durations.is_empty() {
            line("durations (n p50/p95/p99 ms):".to_string());
            for (name, buckets) in &self.durations {
                line(format!(
                    "  {name} {} {}",
                    histogram::total(buckets),
                    pct(buckets)
                ));
            }
        }
        if !self.counters.is_empty() {
            line(format!("counters: {}", join_counts(&self.counters)));
        }
        line(format!(
            "lifecycle: starts {} ({}), stops {}, failed exits {}, unclean exits {}, running {}, panics {}, crashed runs {}",
            self.starts_by_mode.values().sum::<u64>(),
            join_counts(&self.starts_by_mode),
            self.stop_reasons.values().sum::<u64>(),
            self.failed_exits,
            self.unclean_exits,
            self.running,
            self.panic_count(),
            self.crashes
        ));
        if !self.panics.is_empty() {
            line(format!("panic locations: {}", join_counts(&self.panics)));
        }
        if !self.final_push.is_empty() {
            line(format!(
                "final push: {} | {}",
                join_counts(&self.final_push),
                pct(&self.final_push_latency)
            ));
        }
        if !self.slow_ops.is_empty() {
            line(format!(
                "slow ops (>250 ms): {}",
                join_counts(&self.slow_ops)
            ));
        }
        if !self.events.is_empty() {
            line(format!("events: {}", join_counts(&self.events)));
        }
        if self.snapshots > 0 {
            line(format!(
                "resources: max rss {} MiB, cpu user {} ms sys {} ms, max fds {}",
                self.max_rss_bytes >> 20,
                self.user_ms,
                self.sys_ms,
                self.max_fds
            ));
        }
        line(format!(
            "health: drops {}, cap drops {}, write errors {}, skipped lines {}",
            self.drops, self.cap_drops, self.write_errors, self.skipped
        ));
        if !self.evidence.is_empty() {
            line("evidence:".to_string());
            for path in &self.evidence {
                line(format!("  {}", path.display()));
            }
        }
        out
    }
}

/// A stop with a non-zero exit, or a refusal: on macOS a refusal exits 0
/// so that launchd stops restarting it, yet it still needs its operator.
fn failed_stop(record: &Value) -> bool {
    record.get("exit_code").and_then(Value::as_i64).unwrap_or(0) != 0
        || str_of(record, "reason") == "refused"
}

fn join_counts(counts: &BTreeMap<String, u64>) -> String {
    counts
        .iter()
        .map(|(key, count)| format!("{key}={count}"))
        .collect::<Vec<_>>()
        .join(" ")
}

fn format_ms(ms: f64) -> String {
    let text = format!("{ms:.3}");
    text.trim_end_matches('0').trim_end_matches('.').to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn since_accepts_units_and_rejects_nonsense() {
        assert_eq!(parse_since("90m"), Ok(Duration::from_secs(5_400)));
        assert_eq!(parse_since("24h"), Ok(Duration::from_secs(86_400)));
        assert_eq!(parse_since("7d"), Ok(Duration::from_secs(604_800)));
        assert_eq!(parse_since("30s"), Ok(Duration::from_secs(30)));
        for bad in ["", "h", "0h", "-1h", "1.5h", "24", "3w", "99999d", "\u{e9}"] {
            let error = parse_since(bad).unwrap_err();
            assert!(error.contains("90m, 24h or 7d"), "{bad}: {error}");
        }
    }

    #[test]
    fn lifecycle_counts_unclean_exits_and_running_processes() {
        let mut summary = Summary::default();
        let runs = [
            (1, Lifecycle::Start, 10),
            (2, Lifecycle::Stop, 10),
            // Pid 11 crashed and pid 11 was reused by a later start.
            (3, Lifecycle::Start, 11),
            (4, Lifecycle::Start, 11),
            (5, Lifecycle::Stop, 11),
            // Pid 12 vanished without a stop; pid 13 still runs.
            (6, Lifecycle::Start, 12),
            (7, Lifecycle::Start, 13),
            // A stop whose start is outside the window is ignored.
            (8, Lifecycle::Stop, 14),
            // Pid 15 panicked in a thread and still stopped; pid 16 panicked
            // and died, which is one crashed run, not two.
            (9, Lifecycle::Start, 15),
            (10, Lifecycle::Panic, 15),
            (11, Lifecycle::Stop, 15),
            (12, Lifecycle::Start, 16),
            (13, Lifecycle::Panic, 16),
        ];
        summary
            .lifecycle
            .insert("zdrive".to_string(), runs.to_vec());
        summary.settle_lifecycle(|pid| pid == 13);
        assert_eq!(summary.unclean_exits, 3);
        assert_eq!(summary.running, 1);
        assert_eq!(summary.crashes, 4);
    }

    #[test]
    fn a_refusal_is_a_failed_exit_whatever_its_exit_code() {
        let stop = |reason: &str, code: i64| serde_json::json!({ "kind": "stop", "reason": reason, "exit_code": code });
        assert!(!failed_stop(&stop("signal", 0)));
        assert!(failed_stop(&stop("error", 1)));
        // macOS exits 0 on a refusal, Linux 78.
        assert!(failed_stop(&stop("refused", 0)));
        assert!(failed_stop(&stop("refused", 78)));
        let mut summary = Summary::default();
        summary.add("home", 1, "stop", &stop("refused", 0));
        summary.add("home", 2, "stop", &stop("signal", 0));
        assert_eq!(summary.failed_exits, 1);
    }

    #[test]
    fn milliseconds_print_compactly() {
        assert_eq!(format_ms(0.128), "0.128");
        assert_eq!(format_ms(4.096), "4.096");
        assert_eq!(format_ms(1048.576), "1048.576");
        assert_eq!(format_ms(2.0), "2");
    }
}
