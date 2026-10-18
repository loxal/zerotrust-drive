// SPDX-FileCopyrightText: Copyright 2026 Alexander Orlov <info@lifub.com>

//! Log2 latency histograms over microseconds.
//!
//! Bucket 0 holds 0 us; bucket `i >= 1` holds `[2^(i-1), 2^i)` us, and the
//! last bucket also takes everything larger. A percentile is reported as the
//! exclusive upper bound of its bucket, so it never understates a latency and
//! overstates it by less than a factor of two.

use std::sync::atomic::{AtomicU64, Ordering};

use serde_json::Value;

pub(crate) const BUCKETS: usize = 64;

pub(crate) type Buckets = [u64; BUCKETS];

pub(crate) fn bucket_of(micros: u64) -> usize {
    if micros == 0 {
        0
    } else {
        (64 - micros.leading_zeros() as usize).min(BUCKETS - 1)
    }
}

/// Exclusive upper bound of bucket `index`, in microseconds.
pub(crate) fn upper_bound_micros(index: usize) -> u64 {
    1u64 << index.min(BUCKETS - 1)
}

/// Lock-free histogram for hot paths: one relaxed `fetch_add` per sample.
pub(crate) struct AtomicHistogram([AtomicU64; BUCKETS]);

impl AtomicHistogram {
    pub(crate) fn new() -> Self {
        Self(std::array::from_fn(|_| AtomicU64::new(0)))
    }

    pub(crate) fn record(&self, micros: u64) {
        self.0[bucket_of(micros)].fetch_add(1, Ordering::Relaxed);
    }

    /// The samples since the previous call, resetting every bucket.
    pub(crate) fn take(&self) -> Buckets {
        std::array::from_fn(|index| self.0[index].swap(0, Ordering::Relaxed))
    }
}

pub(crate) fn record(buckets: &mut Buckets, micros: u64) {
    let slot = &mut buckets[bucket_of(micros)];
    *slot = slot.saturating_add(1);
}

pub(crate) fn total(buckets: &Buckets) -> u64 {
    buckets
        .iter()
        .fold(0u64, |sum, count| sum.saturating_add(*count))
}

#[cfg(test)]
pub(crate) fn merge(into: &mut Buckets, from: &Buckets) {
    for (target, count) in into.iter_mut().zip(from) {
        *target = target.saturating_add(*count);
    }
}

/// Non-empty buckets as `[[index, count], ...]`.
pub(crate) fn to_sparse(buckets: &Buckets) -> Value {
    Value::Array(
        buckets
            .iter()
            .enumerate()
            .filter(|(_, count)| **count > 0)
            .map(|(index, count)| Value::from(vec![index as u64, *count]))
            .collect(),
    )
}

/// Adds a sparse histogram read from a record. `false` when it is malformed;
/// nothing is added then.
pub(crate) fn merge_sparse(into: &mut Buckets, value: &Value) -> bool {
    let Some(pairs) = value.as_array() else {
        return false;
    };
    let mut parsed = Vec::with_capacity(pairs.len());
    for pair in pairs {
        let Some([index, count]) = pair
            .as_array()
            .map(Vec::as_slice)
            .and_then(|pair| match pair {
                [index, count] => Some([index.as_u64()?, count.as_u64()?]),
                _ => None,
            })
        else {
            return false;
        };
        let Ok(index) = usize::try_from(index) else {
            return false;
        };
        if index >= BUCKETS {
            return false;
        }
        parsed.push((index, count));
    }
    for (index, count) in parsed {
        into[index] = into[index].saturating_add(count);
    }
    true
}

/// Bucket index holding quantile `q` (0 < q <= 1), or `None` when empty.
pub(crate) fn percentile_bucket(buckets: &Buckets, q: f64) -> Option<usize> {
    let total = total(buckets);
    if total == 0 {
        return None;
    }
    let rank = ((q.clamp(0.0, 1.0) * total as f64).ceil() as u64).clamp(1, total);
    let mut seen = 0u64;
    for (index, count) in buckets.iter().enumerate() {
        seen = seen.saturating_add(*count);
        if seen >= rank {
            return Some(index);
        }
    }
    Some(BUCKETS - 1)
}

/// Quantile `q` as its bucket's upper bound in milliseconds.
pub(crate) fn percentile_ms(buckets: &Buckets, q: f64) -> Option<f64> {
    percentile_bucket(buckets, q).map(|index| upper_bound_micros(index) as f64 / 1000.0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn buckets_are_log2_ranges_of_microseconds() {
        assert_eq!(bucket_of(0), 0);
        assert_eq!(bucket_of(1), 1);
        assert_eq!(bucket_of(2), 2);
        assert_eq!(bucket_of(3), 2);
        assert_eq!(bucket_of(4), 3);
        assert_eq!(bucket_of(1023), 10);
        assert_eq!(bucket_of(1024), 11);
        assert_eq!(bucket_of(u64::MAX), BUCKETS - 1);
        for micros in [1u64, 5, 999, 1_000_000, 123_456_789] {
            let index = bucket_of(micros);
            assert!(
                micros < upper_bound_micros(index),
                "{micros} below its bound"
            );
            assert!(
                micros >= upper_bound_micros(index - 1),
                "{micros} at or above the previous bound"
            );
        }
    }

    #[test]
    fn percentiles_report_the_upper_bound_of_their_bucket() {
        let mut buckets = [0u64; BUCKETS];
        assert_eq!(percentile_ms(&buckets, 0.5), None);
        // 90 samples at 100 us (bucket 7, bound 128 us), 9 at 3 ms (bucket
        // 12, bound 4.096 ms) and 1 at 1 s (bucket 20, bound 1.048576 s).
        for _ in 0..90 {
            record(&mut buckets, 100);
        }
        for _ in 0..9 {
            record(&mut buckets, 3_000);
        }
        record(&mut buckets, 1_000_000);
        assert_eq!(total(&buckets), 100);
        assert_eq!(percentile_bucket(&buckets, 0.5), Some(7));
        assert_eq!(percentile_ms(&buckets, 0.5), Some(0.128));
        assert_eq!(percentile_ms(&buckets, 0.95), Some(4.096));
        assert_eq!(percentile_ms(&buckets, 0.99), Some(4.096));
        assert_eq!(percentile_ms(&buckets, 1.0), Some(1048.576));
    }

    #[test]
    fn sparse_round_trip_merges_snapshots_into_the_same_percentiles() {
        let atomic = AtomicHistogram::new();
        let mut whole = [0u64; BUCKETS];
        let mut merged = [0u64; BUCKETS];
        for round in 0..3u64 {
            for sample in 0..50u64 {
                let micros = (sample + 1) * (round + 1) * 37;
                atomic.record(micros);
                record(&mut whole, micros);
            }
            let delta = atomic.take();
            assert_eq!(total(&delta), 50, "take returns only the new samples");
            let sparse = to_sparse(&delta);
            let reparsed: Value = serde_json::from_str(&sparse.to_string()).unwrap();
            assert!(merge_sparse(&mut merged, &reparsed));
        }
        assert_eq!(merged, whole);
        for q in [0.5, 0.95, 0.99] {
            assert_eq!(percentile_bucket(&merged, q), percentile_bucket(&whole, q));
        }
        let mut other = [0u64; BUCKETS];
        merge(&mut other, &whole);
        assert_eq!(other, whole);
    }

    #[test]
    fn malformed_sparse_histograms_add_nothing() {
        let mut buckets = [0u64; BUCKETS];
        for text in [
            r#"{"7":1}"#,
            "[[64,1]]",
            "[[1]]",
            "[[1,2,3]]",
            r#"[[1,"2"]]"#,
            "[[1,2],[-1,2]]",
        ] {
            let value: Value = serde_json::from_str(text).unwrap();
            assert!(!merge_sparse(&mut buckets, &value), "{text}");
        }
        assert_eq!(total(&buckets), 0);
    }
}
