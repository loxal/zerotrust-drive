// SPDX-FileCopyrightText: Copyright 2026 Alexander Orlov <info@lifub.com>

//! Clock, calendar and process facts for telemetry records: UTC day
//! arithmetic without a date library, kernel and FUSE identification,
//! resource usage, and errno names.

use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

const DAY_MS: u64 = 86_400_000;

/// Milliseconds since the Unix epoch; 0 when the clock is before it.
pub(crate) fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| {
            u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX)
        })
}

/// UTC day number (days since 1970-01-01) of a Unix millisecond time.
pub(crate) fn utc_day(ms: u64) -> i64 {
    i64::try_from(ms / DAY_MS).unwrap_or(i64::MAX)
}

/// Gregorian `(year, month, day)` of a day number (Howard Hinnant's
/// `civil_from_days`).
pub(crate) fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let month = (if mp < 10 { mp + 3 } else { mp - 9 }) as u32;
    let year = yoe + era * 400 + i64::from(month <= 2);
    (year, month, day)
}

/// Day number of a Gregorian date (Howard Hinnant's `days_from_civil`).
pub(crate) fn days_from_civil(year: i64, month: u32, day: u32) -> i64 {
    let year = year - i64::from(month <= 2);
    let era = year.div_euclid(400);
    let yoe = year.rem_euclid(400);
    let month = i64::from(month);
    let mp = if month > 2 { month - 3 } else { month + 9 };
    let doy = (153 * mp + 2) / 5 + i64::from(day) - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// `YYYYMMDD.jsonl`, the file holding the records of UTC day `day`.
pub(crate) fn day_file_name(day: i64) -> String {
    let (year, month, day) = civil_from_days(day);
    format!("{year:04}{month:02}{day:02}.jsonl")
}

/// Inverse of [`day_file_name`]; `None` for any other name.
pub(crate) fn parse_day_file_name(name: &str) -> Option<i64> {
    let stamp = name.strip_suffix(".jsonl")?;
    if stamp.len() != 8 || !stamp.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    let year: i64 = stamp[..4].parse().ok()?;
    let month: u32 = stamp[4..6].parse().ok()?;
    let day: u32 = stamp[6..].parse().ok()?;
    if !(1..=12).contains(&month) || !(1..=31).contains(&day) {
        return None;
    }
    let number = days_from_civil(year, month, day);
    (civil_from_days(number) == (year, month, day)).then_some(number)
}

/// The running kernel's release, e.g. `24.6.0` or `6.8.0-45-generic`.
pub(crate) fn kernel_release() -> String {
    // SAFETY: `uname` fills the zeroed struct; its fields are NUL-terminated
    // C strings within their fixed-size arrays on success.
    let release = unsafe {
        let mut name: libc::utsname = std::mem::zeroed();
        if libc::uname(&mut name) != 0 {
            return "unknown".to_string();
        }
        std::ffi::CStr::from_ptr(name.release.as_ptr())
            .to_string_lossy()
            .into_owned()
    };
    let clean: String = release
        .chars()
        .filter(|ch| ch.is_ascii_graphic())
        .take(64)
        .collect();
    if clean.is_empty() {
        "unknown".to_string()
    } else {
        clean
    }
}

/// Which FUSE implementation this host provides.
pub(crate) fn fuse_flavour() -> &'static str {
    if crate::fskit::active() {
        return "macfuse-fskit";
    }
    if Path::new("/Library/Filesystems/macfuse.fs").exists() {
        return "macfuse";
    }
    let on_path = std::env::var_os("PATH").is_some_and(|path| {
        std::env::split_paths(&path).any(|dir| dir.join("fusermount3").is_file())
    });
    if on_path { "fusermount3" } else { "none" }
}

/// Process resource usage since it started.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct Usage {
    pub(crate) max_rss_bytes: u64,
    pub(crate) user_ms: u64,
    pub(crate) sys_ms: u64,
}

pub(crate) fn usage() -> Option<Usage> {
    // SAFETY: `getrusage` fills the zeroed struct for the calling process.
    let usage = unsafe {
        let mut usage: libc::rusage = std::mem::zeroed();
        if libc::getrusage(libc::RUSAGE_SELF, &mut usage) != 0 {
            return None;
        }
        usage
    };
    let max_rss = u64::try_from(usage.ru_maxrss).unwrap_or(0);
    // macOS reports bytes, Linux kibibytes.
    let max_rss_bytes = if cfg!(target_os = "macos") {
        max_rss
    } else {
        max_rss.saturating_mul(1024)
    };
    let millis = |time: libc::timeval| {
        u64::try_from(time.tv_sec)
            .unwrap_or(0)
            .saturating_mul(1000)
            .saturating_add(u64::try_from(time.tv_usec).unwrap_or(0) / 1000)
    };
    Some(Usage {
        max_rss_bytes,
        user_ms: millis(usage.ru_utime),
        sys_ms: millis(usage.ru_stime),
    })
}

/// Open file descriptors of this process.
pub(crate) fn open_fds() -> Option<u64> {
    let dir = if cfg!(target_os = "linux") {
        "/proc/self/fd"
    } else {
        "/dev/fd"
    };
    let entries = std::fs::read_dir(dir).ok()?;
    // The listing holds its own descriptor while it is read.
    let count = entries.filter(Result::is_ok).count() as u64;
    Some(count.saturating_sub(1))
}

/// Whether a process with this id exists.
pub(crate) fn process_alive(pid: u32) -> bool {
    let Ok(pid) = libc::pid_t::try_from(pid) else {
        return false;
    };
    if pid <= 0 {
        return false;
    }
    // SAFETY: signal 0 performs only the existence and permission check.
    if unsafe { libc::kill(pid, 0) } == 0 {
        return true;
    }
    std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM)
}

const ERRNO_NAMES: &[(i32, &str)] = &[
    (libc::EPERM, "EPERM"),
    (libc::ENOENT, "ENOENT"),
    (libc::EINTR, "EINTR"),
    (libc::EIO, "EIO"),
    (libc::ENXIO, "ENXIO"),
    (libc::E2BIG, "E2BIG"),
    (libc::EBADF, "EBADF"),
    (libc::EAGAIN, "EAGAIN"),
    (libc::ENOMEM, "ENOMEM"),
    (libc::EACCES, "EACCES"),
    (libc::EFAULT, "EFAULT"),
    (libc::EBUSY, "EBUSY"),
    (libc::EEXIST, "EEXIST"),
    (libc::EXDEV, "EXDEV"),
    (libc::ENODEV, "ENODEV"),
    (libc::ENOTDIR, "ENOTDIR"),
    (libc::EISDIR, "EISDIR"),
    (libc::EINVAL, "EINVAL"),
    (libc::ENFILE, "ENFILE"),
    (libc::EMFILE, "EMFILE"),
    (libc::EFBIG, "EFBIG"),
    (libc::ENOSPC, "ENOSPC"),
    (libc::ESPIPE, "ESPIPE"),
    (libc::EROFS, "EROFS"),
    (libc::EMLINK, "EMLINK"),
    (libc::EPIPE, "EPIPE"),
    (libc::ERANGE, "ERANGE"),
    (libc::EDEADLK, "EDEADLK"),
    (libc::ENAMETOOLONG, "ENAMETOOLONG"),
    (libc::ENOLCK, "ENOLCK"),
    (libc::ENOSYS, "ENOSYS"),
    (libc::ENOTEMPTY, "ENOTEMPTY"),
    (libc::ELOOP, "ELOOP"),
    (libc::EOVERFLOW, "EOVERFLOW"),
    (libc::ENOTSUP, "ENOTSUP"),
    (libc::ETIMEDOUT, "ETIMEDOUT"),
    (libc::ESTALE, "ESTALE"),
    (libc::EDQUOT, "EDQUOT"),
    (libc::ECANCELED, "ECANCELED"),
];

/// The symbolic name of an errno value on this platform.
pub(crate) fn errno_name(code: i32) -> Option<&'static str> {
    ERRNO_NAMES
        .iter()
        .find(|(value, _)| *value == code)
        .map(|(_, name)| *name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn calendar_round_trips_and_names_day_files() {
        assert_eq!(civil_from_days(0), (1970, 1, 1));
        assert_eq!(days_from_civil(1970, 1, 1), 0);
        assert_eq!(civil_from_days(19_782), (2024, 2, 29));
        assert_eq!(
            day_file_name(days_from_civil(2026, 12, 31)),
            "20261231.jsonl"
        );
        for day in (-800_000..800_000).step_by(997) {
            let (year, month, date) = civil_from_days(day);
            assert_eq!(days_from_civil(year, month, date), day);
            if (1000..=9999).contains(&year) {
                assert_eq!(parse_day_file_name(&day_file_name(day)), Some(day));
            }
        }
        assert_eq!(utc_day(1_700_000_000_000), 19_675);
        for name in [
            "20260230.jsonl",
            "20261301.jsonl",
            "2026010.jsonl",
            "2026-01-01.jsonl",
            "20260101.json",
            "x20260101.jsonl",
        ] {
            assert_eq!(parse_day_file_name(name), None, "{name}");
        }
    }

    #[test]
    fn process_facts_are_available() {
        assert!(!kernel_release().is_empty());
        assert!(["macfuse", "macfuse-fskit", "fusermount3", "none"].contains(&fuse_flavour()));
        let usage = usage().expect("getrusage");
        assert!(usage.max_rss_bytes > 1024 * 1024, "{usage:?}");
        assert!(open_fds().expect("fd listing") >= 3);
        assert!(process_alive(std::process::id()));
        assert!(!process_alive(0));
        assert_eq!(errno_name(libc::ENOENT), Some("ENOENT"));
        assert_eq!(errno_name(-1), None);
    }
}
