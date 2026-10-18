// SPDX-FileCopyrightText: Copyright 2026 Alexander Orlov <info@lifub.com>

//! Native cloud replication of v2 stores through a provider REST API.
//!
//! The remote holds exact copies of the local store's immutable `.z2`
//! ciphertext objects, grouped into append-only packs, plus append-only
//! copies of each published `_root.age`. Nothing is overwritten or deleted,
//! so a remote is always at an old or a new authenticated generation, never
//! between them, and the provider never receives plaintext or key material.

pub(crate) mod cli;
pub(crate) mod config;
#[cfg(test)]
mod crash_tests;
#[cfg(test)]
pub(crate) mod fake;
pub(crate) mod format;
pub(crate) mod gdrive;
pub(crate) mod lease;
pub(crate) mod mount;
pub(crate) mod oauth;
pub(crate) mod state;
pub(crate) mod sync;

use std::fmt;

/// Typed remote failure. Each variant maps to one operator action.
#[derive(Debug)]
pub(crate) enum RemoteError {
    /// Credentials are missing, expired or revoked: authorize again.
    Auth(String),
    /// The provider account is out of storage.
    Quota(String),
    /// A required remote file or folder does not exist.
    NotFound(String),
    /// A pre-generated identifier already exists or names are ambiguous.
    Conflict(String),
    /// Remote bytes do not match their authenticated identity.
    Integrity(String),
    /// The remote and local lineages do not extend each other.
    Diverged(String),
    /// Transport or provider availability failure after bounded retries.
    Network(String),
    /// The provider answered outside the expected protocol.
    Protocol(String),
    /// A local filesystem or store failure.
    Local(String),
}

impl fmt::Display for RemoteError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Auth(message) => write!(formatter, "remote authorization failed: {message}"),
            Self::Quota(message) => write!(formatter, "remote storage quota exceeded: {message}"),
            Self::NotFound(message) => write!(formatter, "remote object not found: {message}"),
            Self::Conflict(message) => write!(formatter, "remote conflict: {message}"),
            Self::Integrity(message) => write!(formatter, "remote integrity failure: {message}"),
            Self::Diverged(message) => write!(formatter, "replicas diverged: {message}"),
            Self::Network(message) => write!(formatter, "remote unavailable: {message}"),
            Self::Protocol(message) => write!(formatter, "remote protocol error: {message}"),
            Self::Local(message) => write!(formatter, "local store error: {message}"),
        }
    }
}

impl std::error::Error for RemoteError {}

/// Local failures become `Local`; a `RemoteError` that travelled through an
/// `io::Error` (from a store-walk callback) keeps its type.
impl From<std::io::Error> for RemoteError {
    fn from(error: std::io::Error) -> Self {
        if !error
            .get_ref()
            .is_some_and(|inner| inner.is::<RemoteError>())
        {
            return Self::Local(error.to_string());
        }
        match error
            .into_inner()
            .map(|inner| inner.downcast::<RemoteError>())
        {
            Some(Ok(remote)) => *remote,
            Some(Err(other)) => Self::Local(other.to_string()),
            None => Self::Local("unknown local failure".to_string()),
        }
    }
}

impl From<RemoteError> for std::io::Error {
    fn from(error: RemoteError) -> Self {
        std::io::Error::other(error)
    }
}

pub(crate) fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(DIGITS[(byte >> 4) as usize] as char);
        out.push(DIGITS[(byte & 0x0f) as usize] as char);
    }
    out
}

/// Decodes exactly `N` bytes of lowercase hexadecimal.
pub(crate) fn unhex<const N: usize>(text: &str) -> Option<[u8; N]> {
    let digits = text.as_bytes();
    if digits.len() != N * 2 {
        return None;
    }
    let mut out = [0u8; N];
    for (index, pair) in digits.as_chunks::<2>().0.iter().enumerate() {
        out[index] = hex_pair(pair)?;
    }
    Some(out)
}

fn hex_pair(pair: &[u8; 2]) -> Option<u8> {
    let value = |digit: u8| match digit {
        b'0'..=b'9' => Some(digit - b'0'),
        b'a'..=b'f' => Some(digit - b'a' + 10),
        _ => None,
    };
    Some((value(pair[0])? << 4) | value(pair[1])?)
}

/// Decodes lowercase hexadecimal of any even length.
pub(crate) fn unhex_vec(text: &str) -> Option<Vec<u8>> {
    let (pairs, rest) = text.as_bytes().as_chunks::<2>();
    if !rest.is_empty() {
        return None;
    }
    pairs.iter().map(hex_pair).collect()
}

/// Percent-encodes everything outside the RFC 3986 unreserved set, so the
/// result is safe in a query string and in a form body.
pub(crate) fn form_encode(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for byte in text.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            out.push(byte as char);
        } else {
            out.push('%');
            out.push_str(&hex(&[byte]).to_ascii_uppercase());
        }
    }
    out
}

/// Strictly decodes one form-encoded component: `None` for a broken escape
/// or bytes that are not UTF-8.
pub(crate) fn form_decode(text: &str) -> Option<String> {
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        match bytes[index] {
            b'+' => out.push(b' '),
            b'%' => {
                let digits = bytes.get(index + 1..index + 3)?;
                let digits = std::str::from_utf8(digits).ok()?.to_ascii_lowercase();
                out.push(unhex::<1>(&digits)?[0]);
                index += 2;
            }
            byte => out.push(byte),
        }
        index += 1;
    }
    String::from_utf8(out).ok()
}

/// Parses a query string or form body. A repeated key is refused, so a
/// security parameter such as an OAuth `state` cannot be smuggled twice.
pub(crate) fn form_pairs(text: &str) -> Option<std::collections::BTreeMap<String, String>> {
    let mut pairs = std::collections::BTreeMap::new();
    for pair in text.split('&').filter(|pair| !pair.is_empty()) {
        let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
        if pairs
            .insert(form_decode(key)?, form_decode(value)?)
            .is_some()
        {
            return None;
        }
    }
    Some(pairs)
}

pub(crate) fn md5_bytes(bytes: &[u8]) -> [u8; 16] {
    use md5::Digest;
    md5::Md5::digest(bytes).into()
}

/// MD5 and length of a whole local file, streamed.
pub(crate) fn md5_file(path: &std::path::Path) -> std::io::Result<([u8; 16], u64)> {
    use md5::Digest;
    use std::io::Read;
    let mut file = std::fs::File::open(path)?;
    let mut hasher = md5::Md5::new();
    let mut buffer = vec![0u8; 1 << 20];
    let mut total = 0u64;
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
        total += read as u64;
    }
    Ok((hasher.finalize().into(), total))
}

fn current_uid() -> u32 {
    // SAFETY: getuid has no preconditions and cannot fail.
    unsafe { libc::getuid() }
}

/// Creates `path` (and missing parents) and requires the final directory to
/// be a real directory that only the current user can enter. Every directory
/// this call creates, parents included, is made 0700 as the XDG base
/// directory spec asks, so a later check of a parent such as the state root
/// passes; an existing one is never silently loosened or tightened, only
/// refused.
pub(crate) fn ensure_private_dir(path: &std::path::Path) -> Result<(), RemoteError> {
    use std::os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt};
    let context = |detail: String| RemoteError::Local(format!("{}: {detail}", path.display()));
    if let Some(parent) = path.parent() {
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(parent)
            .map_err(|error| context(error.to_string()))?;
    }
    match std::fs::DirBuilder::new().mode(0o700).create(path) {
        Ok(()) => {
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))?;
            if let Some(parent) = path.parent() {
                std::fs::File::open(parent)?.sync_all()?;
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(error) => return Err(context(error.to_string())),
    }
    let metadata = std::fs::symlink_metadata(path)?;
    if !metadata.file_type().is_dir() {
        return Err(context("is not a real directory".to_string()));
    }
    if metadata.uid() != current_uid() {
        return Err(context("is owned by another user".to_string()));
    }
    if metadata.mode() & 0o077 != 0 {
        return Err(context(format!(
            "holds credentials or sync state but is accessible to other users; run: chmod 700 {}",
            path.display()
        )));
    }
    Ok(())
}

/// Reads a regular file that only its owner, the current user, can access.
/// `Ok(None)` when it does not exist.
pub(crate) fn read_private_file(
    path: &std::path::Path,
    max_len: u64,
) -> Result<Option<Vec<u8>>, RemoteError> {
    use std::io::Read;
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
    let context = |detail: String| RemoteError::Local(format!("{}: {detail}", path.display()));
    let file = match std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
    {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(context(error.to_string())),
    };
    let metadata = file.metadata()?;
    if !metadata.is_file() {
        return Err(context("not a regular file".to_string()));
    }
    if metadata.uid() != current_uid() {
        return Err(context("owned by another user".to_string()));
    }
    if metadata.mode() & 0o077 != 0 {
        return Err(context(format!(
            "is accessible to other users; run: chmod 600 {}",
            path.display()
        )));
    }
    let mut bytes = Vec::new();
    file.take(max_len + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > max_len {
        return Err(context(format!("is larger than {max_len} bytes")));
    }
    Ok(Some(bytes))
}

/// Atomically replaces `path` with `bytes` as a 0600 file: a private temp
/// file is written and synced, renamed over the target, and the directory is
/// synced. A crash leaves the old or the new content, never a mix.
pub(crate) fn write_private_file(path: &std::path::Path, bytes: &[u8]) -> Result<(), RemoteError> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    use std::sync::atomic::{AtomicU64, Ordering};
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let parent = path
        .parent()
        .ok_or_else(|| RemoteError::Local(format!("{} has no parent", path.display())))?;
    let name = path
        .file_name()
        .ok_or_else(|| RemoteError::Local(format!("{} has no file name", path.display())))?;
    let mut temp_name = std::ffi::OsString::from(".");
    temp_name.push(name);
    temp_name.push(format!(
        ".{}.{}.tmp",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    let temp = parent.join(temp_name);
    let result = (|| -> std::io::Result<()> {
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&temp)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        std::fs::rename(&temp, path)?;
        std::fs::File::open(parent)?.sync_all()
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&temp);
    }
    result.map_err(|error| RemoteError::Local(format!("write {}: {error}", path.display())))
}

/// Self-removing scratch directory for remote tests.
#[cfg(test)]
pub(crate) struct TestDir(std::path::PathBuf);

#[cfg(test)]
impl TestDir {
    pub(crate) fn new(label: &str) -> Self {
        use std::sync::atomic::{AtomicU64, Ordering};
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "zerotrust-drive-remote-{label}-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).expect("create test directory");
        Self(path)
    }

    pub(crate) fn path(&self) -> &std::path::Path {
        &self.0
    }
}

#[cfg(test)]
impl Drop for TestDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_round_trips_and_rejects_malformed_text() {
        let bytes = [0x00, 0x7f, 0xa5, 0xff];
        assert_eq!(hex(&bytes), "007fa5ff");
        assert_eq!(unhex::<4>("007fa5ff"), Some(bytes));
        assert_eq!(unhex::<4>("007FA5FF"), None);
        assert_eq!(unhex::<4>("007fa5f"), None);
        assert_eq!(unhex::<4>("007fa5fg"), None);
    }

    #[test]
    fn variable_length_hex_round_trips() {
        assert_eq!(unhex_vec(""), Some(Vec::new()));
        assert_eq!(unhex_vec("00ff10"), Some(vec![0, 255, 16]));
        assert_eq!(unhex_vec("0"), None);
        assert_eq!(unhex_vec("0G"), None);
    }

    #[test]
    fn form_encoding_round_trips_and_refuses_ambiguity() {
        let raw = "a b&c=d/é~._-";
        let encoded = form_encode(raw);
        assert_eq!(encoded, "a%20b%26c%3Dd%2F%C3%A9~._-");
        assert_eq!(form_decode(&encoded).as_deref(), Some(raw));
        assert_eq!(form_decode("a+b%2f").as_deref(), Some("a b/"));
        assert_eq!(form_decode("%"), None);
        assert_eq!(form_decode("%4"), None);
        assert_eq!(form_decode("%zz"), None);
        assert_eq!(form_decode("%ff"), None, "not UTF-8");
        assert_eq!(form_decode("%é"), None, "escape split inside a character");
        let pairs = form_pairs("state=x&code=4%2F0A&scope=").unwrap();
        assert_eq!(pairs["code"], "4/0A");
        assert_eq!(pairs["scope"], "");
        assert!(form_pairs("state=x&state=y").is_none());
    }

    #[test]
    fn private_dirs_create_missing_parents_privately_and_leave_existing_ones() {
        use std::os::unix::fs::PermissionsExt;
        let test = TestDir::new("private-parents");
        let mode =
            |path: &std::path::Path| std::fs::metadata(path).unwrap().permissions().mode() & 0o777;
        let shared = test.path().join("shared");
        std::fs::create_dir(&shared).unwrap();
        std::fs::set_permissions(&shared, std::fs::Permissions::from_mode(0o755)).unwrap();

        let app = shared.join("app");
        ensure_private_dir(&app.join("telemetry").join("instance")).unwrap();
        assert_eq!(mode(&app), 0o700);
        assert_eq!(mode(&app.join("telemetry")), 0o700);
        // A later check of the app root, as the sync state makes, passes.
        ensure_private_dir(&app).unwrap();
        // An existing shared directory is refused, never tightened.
        assert_eq!(mode(&shared), 0o755);
        let refused = ensure_private_dir(&shared).unwrap_err().to_string();
        assert!(refused.contains("chmod 700"), "{refused}");
        assert_eq!(mode(&shared), 0o755);
    }

    #[test]
    fn md5_matches_the_rfc_1321_test_vector() {
        assert_eq!(hex(&md5_bytes(b"abc")), "900150983cd24fb0d6963f7d28e17f72");
    }
}
