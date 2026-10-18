// SPDX-FileCopyrightText: Copyright 2026 Alexander Orlov <info@lifub.com>

//! In-memory metric accumulators. FUSE and remote request metrics are fixed
//! arrays of atomics, so recording never locks or allocates; named
//! durations, counters and retries live in small locked maps keyed by
//! `&'static str`, which allocate only when a name is first seen.
//! [`Metrics::take`] returns the deltas since its previous call.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, PoisonError};

use serde_json::{Map, Value};

use super::histogram::{self, AtomicHistogram, Buckets};
use super::{FuseOp, RequestClass, system};

/// Errno values `0..=MAX_ERRNO` have their own slot; larger or negative
/// values share the last one.
const MAX_ERRNO: usize = 133;
const ERRNO_SLOTS: usize = MAX_ERRNO + 2;
const OTHER_ERRNO: usize = ERRNO_SLOTS - 1;

pub(crate) const STATUS_CLASSES: [&str; 7] =
    ["2xx", "3xx", "4xx", "429", "5xx", "network", "other"];

struct OpCell {
    latency: AtomicHistogram,
    errno: [AtomicU64; ERRNO_SLOTS],
    bytes: AtomicU64,
}

struct RemoteCell {
    status: [AtomicU64; STATUS_CLASSES.len()],
    latency: AtomicHistogram,
}

/// Retry count and total backoff in ms per request class and reason.
type Retries = BTreeMap<(RequestClass, &'static str), (u64, u64)>;

pub(crate) struct Metrics {
    ops: Box<[OpCell]>,
    remote: Box<[RemoteCell]>,
    retries: Mutex<Retries>,
    durations: Mutex<BTreeMap<&'static str, Buckets>>,
    counters: Mutex<BTreeMap<&'static str, u64>>,
    /// Records lost because the writer queue was full.
    pub(crate) drops: AtomicU64,
    /// Records not written because the size cap was reached.
    pub(crate) cap_drops: AtomicU64,
    /// Failed directory, open or write attempts.
    pub(crate) write_errors: AtomicU64,
}

fn errno_slot(code: i32) -> usize {
    usize::try_from(code)
        .ok()
        .filter(|code| *code <= MAX_ERRNO)
        .unwrap_or(OTHER_ERRNO)
}

fn errno_label(slot: usize) -> String {
    if slot == OTHER_ERRNO {
        return "other".to_string();
    }
    let code = i32::try_from(slot).unwrap_or(-1);
    system::errno_name(code).map_or_else(|| format!("E{code}"), str::to_string)
}

/// Index into [`STATUS_CLASSES`]; `None` is a transport failure.
pub(crate) fn status_class(status: Option<u16>) -> usize {
    match status {
        Some(200..=299) => 0,
        Some(300..=399) => 1,
        Some(429) => 3,
        Some(400..=499) => 2,
        Some(500..=599) => 4,
        None => 5,
        Some(_) => 6,
    }
}

fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

fn take(counter: &AtomicU64) -> u64 {
    counter.swap(0, Ordering::Relaxed)
}

impl Metrics {
    pub(crate) fn new() -> Self {
        Self {
            ops: FuseOp::ALL
                .iter()
                .map(|_| OpCell {
                    latency: AtomicHistogram::new(),
                    errno: std::array::from_fn(|_| AtomicU64::new(0)),
                    bytes: AtomicU64::new(0),
                })
                .collect(),
            remote: RequestClass::ALL
                .iter()
                .map(|_| RemoteCell {
                    status: std::array::from_fn(|_| AtomicU64::new(0)),
                    latency: AtomicHistogram::new(),
                })
                .collect(),
            retries: Mutex::new(BTreeMap::new()),
            durations: Mutex::new(BTreeMap::new()),
            counters: Mutex::new(BTreeMap::new()),
            drops: AtomicU64::new(0),
            cap_drops: AtomicU64::new(0),
            write_errors: AtomicU64::new(0),
        }
    }

    /// Lock-free: one `fetch_add` plus one per error and per byte count.
    pub(crate) fn fuse(&self, op: FuseOp, micros: u64, errno: Option<i32>, bytes: u64) {
        let cell = &self.ops[op as usize];
        cell.latency.record(micros);
        if let Some(code) = errno.filter(|code| *code != 0) {
            cell.errno[errno_slot(code)].fetch_add(1, Ordering::Relaxed);
        }
        if bytes > 0 {
            cell.bytes.fetch_add(bytes, Ordering::Relaxed);
        }
    }

    pub(crate) fn remote(&self, class: RequestClass, status: Option<u16>, micros: u64) {
        let cell = &self.remote[class as usize];
        cell.status[status_class(status)].fetch_add(1, Ordering::Relaxed);
        cell.latency.record(micros);
    }

    pub(crate) fn retry(&self, class: RequestClass, reason: &'static str, backoff_ms: u64) {
        let mut retries = lock(&self.retries);
        let entry = retries.entry((class, reason)).or_insert((0, 0));
        entry.0 = entry.0.saturating_add(1);
        entry.1 = entry.1.saturating_add(backoff_ms);
    }

    pub(crate) fn duration(&self, name: &'static str, micros: u64) {
        let mut durations = lock(&self.durations);
        let buckets = durations.entry(name).or_insert([0; histogram::BUCKETS]);
        histogram::record(buckets, micros);
    }

    pub(crate) fn counter(&self, name: &'static str, delta: u64) {
        let mut counters = lock(&self.counters);
        let value = counters.entry(name).or_insert(0);
        *value = value.saturating_add(delta);
    }

    /// Discards everything accumulated so far.
    pub(crate) fn reset(&self) {
        let _ = self.take();
        for counter in [&self.drops, &self.cap_drops, &self.write_errors] {
            take(counter);
        }
    }

    /// The metrics since the previous call as snapshot fields; empty
    /// sections are omitted. Map entries are zeroed in place, so a name
    /// that recurs never allocates again.
    pub(crate) fn take(&self) -> Map<String, Value> {
        let mut body = Map::new();
        let mut errno_total: BTreeMap<usize, u64> = BTreeMap::new();
        let mut fuse = Map::new();
        for (op, cell) in FuseOp::ALL.iter().zip(self.ops.iter()) {
            let latency = cell.latency.take();
            let mut errors = Map::new();
            let mut error_count = 0u64;
            for (slot, counter) in cell.errno.iter().enumerate() {
                let count = take(counter);
                if count > 0 {
                    error_count = error_count.saturating_add(count);
                    *errno_total.entry(slot).or_insert(0) += count;
                    errors.insert(errno_label(slot), count.into());
                }
            }
            let bytes = take(&cell.bytes);
            let count = histogram::total(&latency);
            if count == 0 && error_count == 0 && bytes == 0 {
                continue;
            }
            let mut entry = Map::new();
            entry.insert("n".to_string(), count.into());
            entry.insert("err".to_string(), error_count.into());
            if !errors.is_empty() {
                entry.insert("errno".to_string(), Value::Object(errors));
            }
            if bytes > 0 {
                entry.insert("bytes".to_string(), bytes.into());
            }
            entry.insert("hist".to_string(), histogram::to_sparse(&latency));
            fuse.insert(op.name().to_string(), Value::Object(entry));
        }
        insert_nonempty(&mut body, "fuse", fuse);
        insert_nonempty(
            &mut body,
            "errno",
            errno_total
                .into_iter()
                .map(|(slot, count)| (errno_label(slot), count.into()))
                .collect(),
        );

        let mut remote = Map::new();
        for (class, cell) in RequestClass::ALL.iter().zip(self.remote.iter()) {
            let latency = cell.latency.take();
            let mut entry = Map::new();
            for (name, counter) in STATUS_CLASSES.iter().zip(&cell.status) {
                let count = take(counter);
                if count > 0 {
                    entry.insert((*name).to_string(), count.into());
                }
            }
            if entry.is_empty() && histogram::total(&latency) == 0 {
                continue;
            }
            entry.insert("hist".to_string(), histogram::to_sparse(&latency));
            remote.insert(class.name().to_string(), Value::Object(entry));
        }
        insert_nonempty(&mut body, "remote", remote);

        let mut retries = Map::new();
        for ((class, reason), (count, backoff_ms)) in lock(&self.retries).iter_mut() {
            let (count, backoff_ms) = (std::mem::take(count), std::mem::take(backoff_ms));
            if count == 0 {
                continue;
            }
            let reasons = retries
                .entry(class.name().to_string())
                .or_insert_with(|| Value::Object(Map::new()));
            if let Value::Object(reasons) = reasons {
                let mut entry = Map::new();
                entry.insert("n".to_string(), count.into());
                entry.insert("backoff_ms".to_string(), backoff_ms.into());
                reasons.insert((*reason).to_string(), Value::Object(entry));
            }
        }
        insert_nonempty(&mut body, "retries", retries);

        let mut durations = Map::new();
        for (name, buckets) in lock(&self.durations).iter_mut() {
            let taken = std::mem::replace(buckets, [0; histogram::BUCKETS]);
            let count = histogram::total(&taken);
            if count == 0 {
                continue;
            }
            let mut entry = Map::new();
            entry.insert("n".to_string(), count.into());
            entry.insert("hist".to_string(), histogram::to_sparse(&taken));
            durations.insert((*name).to_string(), Value::Object(entry));
        }
        insert_nonempty(&mut body, "durations", durations);

        let mut counters = Map::new();
        for (name, value) in lock(&self.counters).iter_mut() {
            let value = std::mem::take(value);
            if value > 0 {
                counters.insert((*name).to_string(), value.into());
            }
        }
        insert_nonempty(&mut body, "counters", counters);
        body
    }
}

fn insert_nonempty(body: &mut Map<String, Value>, key: &str, section: Map<String, Value>) {
    if !section.is_empty() {
        body.insert(key.to_string(), Value::Object(section));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn take_reports_deltas_and_resets() {
        let metrics = Metrics::new();
        metrics.fuse(FuseOp::Lookup, 100, None, 0);
        metrics.fuse(FuseOp::Lookup, 300, Some(libc::ENOENT), 0);
        metrics.fuse(FuseOp::Read, 50, None, 4096);
        metrics.fuse(FuseOp::Write, 50, Some(10_000), 0);
        metrics.remote(RequestClass::List, Some(200), 1_000);
        metrics.remote(RequestClass::List, Some(429), 2_000);
        metrics.remote(RequestClass::Upload, None, 3_000);
        metrics.retry(RequestClass::List, "rate_limit", 1_500);
        metrics.retry(RequestClass::List, "rate_limit", 500);
        metrics.duration("v2.commit", 2_000);
        metrics.counter("v2.objects_written", 3);

        let body = Value::Object(metrics.take());
        assert_eq!(body["fuse"]["lookup"]["n"], 2);
        assert_eq!(body["fuse"]["lookup"]["err"], 1);
        assert_eq!(body["fuse"]["lookup"]["errno"]["ENOENT"], 1);
        assert_eq!(body["fuse"]["read"]["bytes"], 4096);
        assert_eq!(body["fuse"]["write"]["errno"]["other"], 1);
        assert_eq!(body["errno"]["ENOENT"], 1);
        assert_eq!(body["remote"]["list"]["2xx"], 1);
        assert_eq!(body["remote"]["list"]["429"], 1);
        assert_eq!(body["remote"]["upload"]["network"], 1);
        assert_eq!(body["retries"]["list"]["rate_limit"]["n"], 2);
        assert_eq!(body["retries"]["list"]["rate_limit"]["backoff_ms"], 2_000);
        assert_eq!(body["durations"]["v2.commit"]["n"], 1);
        assert_eq!(body["counters"]["v2.objects_written"], 3);

        assert!(metrics.take().is_empty(), "a second take has no deltas");
        metrics.counter("v2.objects_written", 1);
        let body = Value::Object(metrics.take());
        assert_eq!(body["counters"]["v2.objects_written"], 1);
        assert!(body.get("durations").is_none());
    }

    #[test]
    fn status_classes_cover_every_outcome() {
        let classes: Vec<_> = [
            Some(204),
            Some(308),
            Some(404),
            Some(429),
            Some(503),
            None,
            Some(101),
        ]
        .into_iter()
        .map(|status| STATUS_CLASSES[status_class(status)])
        .collect();
        assert_eq!(classes, STATUS_CLASSES);
        assert_eq!(errno_slot(-5), OTHER_ERRNO);
        assert_eq!(errno_slot(133), 133);
        assert_eq!(errno_slot(134), OTHER_ERRNO);
        assert_eq!(errno_label(OTHER_ERRNO), "other");
    }
}
