// SPDX-FileCopyrightText: Copyright 2026 Alexander Orlov <info@lifub.com>

//! Local filesystem primitives of plain sync: the scan and its ignore
//! rules, no-replace renames, conflict names and the recoverable trash.
//!
//! Names are compared as the exact bytes the OS reports. APFS and Linux
//! file systems return a name as it was created, so names round-trip
//! unchanged; HFS+ stores names decomposed (NFD), so a composed name
//! downloaded there is seen as a local rename once and propagated.

use std::collections::BTreeMap;
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{DirBuilderExt, MetadataExt};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Every name zdrive itself creates inside a synced folder starts with
/// this, and the scan ignores all of them.
pub(crate) const OWN_PREFIX: &str = ".zdrive-";
/// A download in progress; never user data, removed when found later
/// (see [`is_own_temp`]).
pub(crate) const TEMP_PREFIX: &str = ".zdrive-tmp-";
/// A replaced file set aside until its download is in place.
pub(crate) const ASIDE_PREFIX: &str = ".zdrive-old-";
/// Trash inside the synced folder, used when the configured trash lies
/// on another file system.
pub(crate) const FALLBACK_TRASH: &str = ".zdrive-trash";
pub(crate) const TRASH_RETENTION: Duration = Duration::from_secs(30 * 24 * 3600);
pub(crate) const NAME_MAX: usize = 255;

/// Names neither side syncs: Finder metadata, AppleDouble files and
/// zdrive's own working files.
pub(crate) fn ignored(name: &str) -> bool {
    name == ".DS_Store" || name.starts_with("._") || name.starts_with(OWN_PREFIX)
}

/// Whether a Drive name can be a single local path component.
pub(crate) fn valid_name(name: &str) -> bool {
    !name.is_empty()
        && name != "."
        && name != ".."
        && !name.contains('/')
        && !name.contains('\0')
        && name.len() <= NAME_MAX
}

/// The parent of a relative path ("" at the top) and its last component.
pub(crate) fn split_rel(rel: &str) -> (&str, &str) {
    rel.rsplit_once('/').unwrap_or(("", rel))
}

pub(crate) fn join_rel(parent: &str, name: &str) -> String {
    if parent.is_empty() {
        name.to_string()
    } else {
        format!("{parent}/{name}")
    }
}

/// Whether `rel` is `prefix` or lies below it.
pub(crate) fn within(rel: &str, prefix: &str) -> bool {
    rel == prefix
        || (rel.len() > prefix.len()
            && rel.starts_with(prefix)
            && rel.as_bytes()[prefix.len()] == b'/')
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Kind {
    File,
    Dir,
    /// Symlinks, sockets, fifos and devices, which are never synced.
    Special,
}

/// What the index remembers of a local file to notice changes cheaply.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Stat {
    pub(crate) kind: Kind,
    pub(crate) size: u64,
    pub(crate) mtime_ns: i64,
    pub(crate) inode: u64,
    pub(crate) dev: u64,
}

impl Stat {
    pub(crate) fn of(metadata: &std::fs::Metadata) -> Self {
        let file_type = metadata.file_type();
        let kind = if file_type.is_file() {
            Kind::File
        } else if file_type.is_dir() {
            Kind::Dir
        } else {
            Kind::Special
        };
        Self {
            kind,
            size: if kind == Kind::File {
                metadata.len()
            } else {
                0
            },
            mtime_ns: metadata
                .mtime()
                .saturating_mul(1_000_000_000)
                .saturating_add(metadata.mtime_nsec()),
            inode: metadata.ino(),
            dev: metadata.dev(),
        }
    }

    /// Whether the file was modified within `age` of now (or in the future).
    pub(crate) fn recent(&self, age: Duration) -> bool {
        if age.is_zero() {
            return false;
        }
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |since| {
                i64::try_from(since.as_nanos()).unwrap_or(i64::MAX)
            });
        let age = i64::try_from(age.as_nanos()).unwrap_or(i64::MAX);
        self.mtime_ns > now.saturating_sub(age)
    }
}

/// `lstat`, with `None` for a path that does not exist.
pub(crate) fn lstat(path: &Path) -> io::Result<Option<Stat>> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) => Ok(Some(Stat::of(&metadata))),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error),
    }
}

/// One walk of the synced folder.
#[derive(Debug, Default)]
pub(crate) struct Scan {
    /// Regular files and directories by relative path.
    pub(crate) items: BTreeMap<String, Stat>,
    /// Symlinks, devices, fifos, sockets, mount points and names that are
    /// not UTF-8.
    pub(crate) special: u64,
    /// zdrive's own leftovers (temp downloads, set-aside files).
    pub(crate) debris: Vec<String>,
    /// Paths that could not be read; nothing at or below them may be
    /// taken for deleted.
    pub(crate) unreadable: Vec<String>,
    pub(crate) errors: Vec<String>,
}

impl Scan {
    pub(crate) fn readable(&self, rel: &str) -> bool {
        !self.unreadable.iter().any(|prefix| within(rel, prefix))
    }
}

/// Walks `root` without following symlinks or crossing into other file
/// systems. `excluded` absolute paths (the trash or state inside the synced
/// folder) are skipped entirely.
pub(crate) fn scan(root: &Path, excluded: &[PathBuf]) -> Result<Scan, String> {
    let root_dev = std::fs::symlink_metadata(root)
        .map_err(|error| format!("{}: {error}", root.display()))?
        .dev();
    let mut out = Scan::default();
    let mut stack = vec![String::new()];
    while let Some(dir_rel) = stack.pop() {
        let dir = if dir_rel.is_empty() {
            root.to_path_buf()
        } else {
            root.join(&dir_rel)
        };
        let entries = match std::fs::read_dir(&dir) {
            Ok(entries) => entries,
            Err(error) if dir_rel.is_empty() => {
                return Err(format!("{}: {error}", root.display()));
            }
            Err(error) => {
                out.errors.push(format!("cannot read {dir_rel}: {error}"));
                out.unreadable.push(dir_rel);
                continue;
            }
        };
        for entry in entries {
            let entry = match entry {
                Ok(entry) => entry,
                Err(error) => {
                    out.errors.push(format!("cannot list {dir_rel}: {error}"));
                    out.unreadable.push(dir_rel.clone());
                    break;
                }
            };
            let raw = entry.file_name();
            let Ok(name) = std::str::from_utf8(raw.as_bytes()) else {
                out.special += 1;
                continue;
            };
            let rel = join_rel(&dir_rel, name);
            if ignored(name) {
                if is_own_temp(name) || aside_original(name).is_some() {
                    out.debris.push(rel);
                }
                continue;
            }
            let path = dir.join(name);
            let stat = match lstat(&path) {
                Ok(Some(stat)) => stat,
                Ok(None) => continue,
                Err(error) => {
                    out.errors.push(format!("cannot stat {rel}: {error}"));
                    out.unreadable.push(rel);
                    continue;
                }
            };
            match stat.kind {
                Kind::File => {
                    out.items.insert(rel, stat);
                }
                Kind::Dir if excluded.contains(&path) => {}
                Kind::Dir if stat.dev != root_dev => out.special += 1,
                Kind::Dir => {
                    out.items.insert(rel.clone(), stat);
                    stack.push(rel);
                }
                Kind::Special => out.special += 1,
            }
        }
    }
    Ok(out)
}

fn cstring(path: &Path) -> io::Result<std::ffi::CString> {
    std::ffi::CString::new(path.as_os_str().as_bytes())
        .map_err(|_| io::Error::from_raw_os_error(libc::EINVAL))
}

/// Renames `from` to `to` only if `to` does not exist: `EEXIST` otherwise.
pub(crate) fn rename_noreplace(from: &Path, to: &Path) -> io::Result<()> {
    let (from_c, to_c) = (cstring(from)?, cstring(to)?);
    #[cfg(target_vendor = "apple")]
    // SAFETY: both are valid NUL-terminated strings for the call's duration.
    let result = unsafe { libc::renamex_np(from_c.as_ptr(), to_c.as_ptr(), libc::RENAME_EXCL) };
    #[cfg(target_os = "linux")]
    // SAFETY: both are valid NUL-terminated strings for the call's duration.
    let result = unsafe {
        libc::renameat2(
            libc::AT_FDCWD,
            from_c.as_ptr(),
            libc::AT_FDCWD,
            to_c.as_ptr(),
            libc::RENAME_NOREPLACE,
        )
    };
    #[cfg(not(any(target_vendor = "apple", target_os = "linux")))]
    let result = {
        let _ = (&from_c, &to_c);
        -1
    };
    if result == 0 {
        return Ok(());
    }
    let error = io::Error::last_os_error();
    let unsupported = !cfg!(any(target_vendor = "apple", target_os = "linux"))
        || matches!(
            error.raw_os_error(),
            Some(libc::EINVAL | libc::ENOSYS | libc::ENOTSUP)
        );
    if !unsupported {
        return Err(error);
    }
    // A file system without an atomic no-replace rename: a hard link
    // refuses an existing target just as well.
    if std::fs::symlink_metadata(from)?.is_dir() {
        if lstat(to)?.is_some() {
            return Err(io::Error::from_raw_os_error(libc::EEXIST));
        }
        return std::fs::rename(from, to);
    }
    std::fs::hard_link(from, to)?;
    std::fs::remove_file(from)
}

/// [`rename_noreplace`] that also allows renaming a file onto another
/// spelling of its own name (a case-only rename on a case-insensitive file
/// system).
pub(crate) fn move_path(from: &Path, to: &Path) -> io::Result<()> {
    match rename_noreplace(from, to) {
        Err(error) if error.raw_os_error() == Some(libc::EEXIST) => {
            match (lstat(from)?, lstat(to)?) {
                (Some(a), Some(b)) if a.inode == b.inode && a.dev == b.dev => {
                    std::fs::rename(from, to)
                }
                _ => Err(error),
            }
        }
        other => other,
    }
}

pub(crate) fn fsync_dir(dir: &Path) -> io::Result<()> {
    std::fs::File::open(dir)?.sync_all()
}

/// Creates a 0700 directory and its missing parents.
pub(crate) fn create_private_dirs(dir: &Path) -> io::Result<()> {
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(dir)
}

/// `name` with the name extension split off: "a.tar.gz" gives
/// ("a.tar", ".gz"); dot files and directories have none.
fn split_ext(name: &str, dir: bool) -> (&str, &str) {
    if dir {
        return (name, "");
    }
    match name.rfind('.') {
        Some(at) if at > 0 && at + 1 < name.len() && name.len() - at <= 16 => {
            (&name[..at], &name[at..])
        }
        _ => (name, ""),
    }
}

fn truncate_to(text: &str, max: usize) -> &str {
    if text.len() <= max {
        return text;
    }
    let mut end = max;
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    &text[..end]
}

/// `name` with ` (<tag>)` before its extension, shortened to fit a file
/// name: "report.txt" gives "report (<tag>).txt".
pub(crate) fn tagged_name(name: &str, dir: bool, tag: &str) -> String {
    let (stem, ext) = split_ext(name, dir);
    let tag = format!(" ({tag})");
    let stem = truncate_to(stem, NAME_MAX.saturating_sub(tag.len() + ext.len()).max(1));
    format!("{stem}{tag}{ext}")
}

/// `name (conflict YYYY-MM-DD HHMMSS host).ext`, numbered from the second.
pub(crate) fn conflict_name(name: &str, dir: bool, stamp: &str, host: &str, n: u32) -> String {
    let tag = if n <= 1 {
        format!("conflict {stamp} {host}")
    } else {
        format!("conflict {stamp} {host} {n}")
    };
    tagged_name(name, dir, &tag)
}

/// A host name safe in a file name: ASCII letters, digits, `-`, `_`.
pub(crate) fn host_tag(host: &str) -> String {
    let short = host.split('.').next().unwrap_or_default();
    let tag: String = short
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '-'
            }
        })
        .take(32)
        .collect();
    if tag.is_empty() {
        "host".to_string()
    } else {
        tag
    }
}

pub(crate) fn now_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |since| {
            i64::try_from(since.as_secs()).unwrap_or(i64::MAX)
        })
}

/// Local time as `YYYY-MM-DD HHMMSS`, for conflict names.
pub(crate) fn local_stamp(secs: i64) -> String {
    let time = secs as libc::time_t;
    // SAFETY: a zeroed tm is a valid out-parameter and both pointers are
    // valid for the call; localtime_r is the thread-safe variant.
    let mut tm: libc::tm = unsafe { std::mem::zeroed() };
    if unsafe { libc::localtime_r(&time, &mut tm) }.is_null() {
        return utc_bucket(secs).replace('T', " ").replace('Z', "");
    }
    format!(
        "{:04}-{:02}-{:02} {:02}{:02}{:02}",
        tm.tm_year + 1900,
        tm.tm_mon + 1,
        tm.tm_mday,
        tm.tm_hour,
        tm.tm_min,
        tm.tm_sec
    )
}

/// Days since 1970-01-01 to (year, month, day), proleptic Gregorian.
fn civil_from_days(days: i64) -> (i64, i64, i64) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    (year, month, day)
}

fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let year = if month <= 2 { year - 1 } else { year };
    let era = year.div_euclid(400);
    let yoe = year.rem_euclid(400);
    let mp = if month > 2 { month - 3 } else { month + 9 };
    let doy = (153 * mp + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// UTC time as `YYYY-MM-DDTHHMMSSZ`, the name of a trash bucket.
pub(crate) fn utc_bucket(secs: i64) -> String {
    let (days, rest) = (secs.div_euclid(86_400), secs.rem_euclid(86_400));
    let (year, month, day) = civil_from_days(days);
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}{:02}{:02}Z",
        rest / 3600,
        rest / 60 % 60,
        rest % 60
    )
}

/// The time a bucket name encodes, or `None` for any other name.
pub(crate) fn parse_bucket(name: &str) -> Option<i64> {
    let bytes = name.as_bytes();
    if bytes.len() != 18
        || bytes[4] != b'-'
        || bytes[7] != b'-'
        || bytes[10] != b'T'
        || bytes[17] != b'Z'
    {
        return None;
    }
    let number = |range: std::ops::Range<usize>| -> Option<i64> {
        let digits = name.get(range)?;
        if !digits.bytes().all(|byte| byte.is_ascii_digit()) {
            return None;
        }
        digits.parse().ok()
    };
    let (year, month, day) = (number(0..4)?, number(5..7)?, number(8..10)?);
    let (hour, minute, second) = (number(11..13)?, number(13..15)?, number(15..17)?);
    if !(1..=12).contains(&month)
        || !(1..=31).contains(&day)
        || hour > 23
        || minute > 59
        || second > 59
    {
        return None;
    }
    Some(days_from_civil(year, month, day) * 86_400 + hour * 3600 + minute * 60 + second)
}

/// The recoverable local trash: `<dir>/<UTC bucket>/<relative path>`. A
/// file that cannot be renamed there (another file system) goes to
/// [`FALLBACK_TRASH`] inside the synced folder instead.
pub(crate) struct Trash<'a> {
    dir: &'a Path,
    root: &'a Path,
    bucket: Option<String>,
}

impl<'a> Trash<'a> {
    pub(crate) fn new(dir: &'a Path, root: &'a Path) -> Self {
        Self {
            dir,
            root,
            bucket: None,
        }
    }

    /// Moves `root/rel` into the trash, keeping its relative path, and
    /// returns where it went. Never copies and never unlinks.
    pub(crate) fn take(&mut self, rel: &str) -> io::Result<PathBuf> {
        self.take_as(rel, rel)
    }

    /// Moves `root/source` into the trash under the relative path `rel`.
    pub(crate) fn take_as(&mut self, source: &str, rel: &str) -> io::Result<PathBuf> {
        let bucket = self
            .bucket
            .get_or_insert_with(|| utc_bucket(now_secs()))
            .clone();
        let source = self.root.join(source);
        match place(&self.dir.join(&bucket), rel, &source) {
            Err(error) if error.raw_os_error() == Some(libc::EXDEV) => {
                place(&self.root.join(FALLBACK_TRASH).join(&bucket), rel, &source)
            }
            other => other,
        }
    }
}

fn place(base: &Path, rel: &str, source: &Path) -> io::Result<PathBuf> {
    let target = base.join(rel);
    let parent = target
        .parent()
        .ok_or_else(|| io::Error::from_raw_os_error(libc::EINVAL))?;
    create_private_dirs(parent)?;
    let (_, name) = split_rel(rel);
    let dir = std::fs::symlink_metadata(source)?.is_dir();
    for n in 1..=1000u32 {
        let candidate = if n == 1 {
            target.clone()
        } else {
            parent.join(tagged_name(name, dir, &n.to_string()))
        };
        match rename_noreplace(source, &candidate) {
            Ok(()) => {
                fsync_dir(parent)?;
                if let Some(from) = source.parent() {
                    fsync_dir(from)?;
                }
                return Ok(candidate);
            }
            Err(error) if error.raw_os_error() == Some(libc::EEXIST) => {}
            Err(error) => return Err(error),
        }
    }
    Err(io::Error::from_raw_os_error(libc::EEXIST))
}

/// Removes trash buckets older than [`TRASH_RETENTION`] below `base`;
/// anything that is not a bucket is left alone. Returns how many went.
pub(crate) fn purge(base: &Path, now: i64) -> Result<u64, String> {
    let entries = match std::fs::read_dir(base) {
        Ok(entries) => entries,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(0),
        Err(error) => return Err(format!("{}: {error}", base.display())),
    };
    let retention = TRASH_RETENTION.as_secs() as i64;
    let mut purged = 0;
    for entry in entries {
        let entry = entry.map_err(|error| format!("{}: {error}", base.display()))?;
        let name = entry.file_name();
        let Some(time) = name.to_str().and_then(parse_bucket) else {
            continue;
        };
        if now.saturating_sub(time) <= retention {
            continue;
        }
        let path = entry.path();
        if !std::fs::symlink_metadata(&path).is_ok_and(|metadata| metadata.is_dir()) {
            continue;
        }
        std::fs::remove_dir_all(&path).map_err(|error| format!("{}: {error}", path.display()))?;
        purged += 1;
    }
    Ok(purged)
}

fn is_serial(text: &str) -> bool {
    text.split_once('.').is_some_and(|(pid, serial)| {
        [pid, serial]
            .iter()
            .all(|part| !part.is_empty() && part.bytes().all(|byte| byte.is_ascii_digit()))
    })
}

/// A partial download as zdrive names it: `.zdrive-tmp-<pid>.<serial>`.
/// Other names with zdrive's prefixes are merely ignored, never removed.
pub(crate) fn is_own_temp(name: &str) -> bool {
    name.strip_prefix(TEMP_PREFIX).is_some_and(is_serial)
}

/// The original name of a file zdrive set aside as
/// `.zdrive-old-<pid>.<serial>-<name>`.
pub(crate) fn aside_original(name: &str) -> Option<&str> {
    let (serial, original) = name.strip_prefix(ASIDE_PREFIX)?.split_once('-')?;
    (is_serial(serial) && valid_name(original) && !ignored(original)).then_some(original)
}

/// Clears what an interrupted cycle left behind: partial downloads are
/// removed (they are never user data), and a set-aside file goes back to
/// its name when that is free, otherwise to the trash under that name.
pub(crate) fn recover_debris(root: &Path, debris: &[String], trash: &mut Trash<'_>) -> Vec<String> {
    let mut errors = Vec::new();
    for rel in debris {
        let path = root.join(rel);
        let (parent, name) = split_rel(rel);
        let result = if is_own_temp(name) {
            match lstat(&path) {
                Ok(Some(stat)) if stat.kind == Kind::File => std::fs::remove_file(&path),
                Ok(_) => Ok(()),
                Err(error) => Err(error),
            }
        } else {
            match aside_original(name) {
                Some(original) => {
                    let original = join_rel(parent, original);
                    match rename_noreplace(&path, &root.join(&original)) {
                        Ok(()) => Ok(()),
                        Err(error) if error.raw_os_error() == Some(libc::EEXIST) => {
                            trash.take_as(rel, &original).map(|_| ())
                        }
                        Err(error) => Err(error),
                    }
                }
                None => Ok(()),
            }
        };
        if let Err(error) = result {
            errors.push(format!("cannot clear {rel}: {error}"));
        }
    }
    errors
}
