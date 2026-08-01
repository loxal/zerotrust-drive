// Copyright 2026 Alexander Orlov <alexander.orlov@loxal.net>

//! Fail-closed ownership records for synced migration/rekey locks.
//!
//! A bare PID is meaningful only on the machine that created it. Cloud sync
//! can carry the same file to another host, where probing that PID can falsely
//! declare a foreign transaction stale (or live by coincidence). Versioned
//! records bind the PID to a privacy-preserving token for the local machine.

use std::fmt::Write as _;
use std::io::Write as _;

use blake2::{Blake2s256, Digest};

use crate::fs::read_bounded_backing_file;

const LOCK_RECORD_VERSION: &str = "ztd1";
const MAX_LOCK_RECORD_LEN: u64 = 64;

#[derive(Debug, Eq, PartialEq)]
enum ParsedOwner {
    Local(u32),
    Foreign(u32),
}

#[cfg(target_os = "macos")]
fn machine_identity() -> Result<Vec<u8>, String> {
    let mut uuid = [0u8; 16];
    let timeout = libc::timespec {
        tv_sec: 5,
        tv_nsec: 0,
    };
    let result = unsafe { libc::gethostuuid(uuid.as_mut_ptr(), &raw const timeout) };
    if result != 0 {
        return Err(format!(
            "gethostuuid failed: {}",
            std::io::Error::last_os_error()
        ));
    }
    if uuid.iter().all(|byte| *byte == 0) {
        return Err("gethostuuid returned an all-zero identifier".to_string());
    }
    Ok(uuid.to_vec())
}

#[cfg(target_os = "linux")]
fn machine_identity() -> Result<Vec<u8>, String> {
    let mut errors = Vec::new();
    for path in ["/etc/machine-id", "/var/lib/dbus/machine-id"] {
        match read_bounded_backing_file(std::path::Path::new(path), 64) {
            Ok(bytes) => {
                let Ok(value) = std::str::from_utf8(&bytes).map(str::trim) else {
                    errors.push(format!("{path} is not UTF-8"));
                    continue;
                };
                if value.len() == 32
                    && value.bytes().all(|byte| byte.is_ascii_hexdigit())
                    && !value.bytes().all(|byte| byte == b'0')
                {
                    return Ok(value.to_ascii_lowercase().into_bytes());
                }
                errors.push(format!(
                    "{path} is not a non-zero 32-digit machine identifier"
                ));
            }
            Err(error) => errors.push(format!("read {path}: {error}")),
        }
    }
    Err(format!(
        "no usable operating-system machine identifier ({})",
        errors.join("; ")
    ))
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
fn machine_identity() -> Result<Vec<u8>, String> {
    Err("machine-bound transaction locks are supported only on macOS and Linux".to_string())
}

fn local_machine_token() -> Result<String, String> {
    let identity = machine_identity()?;
    let mut hasher = Blake2s256::new();
    hasher.update(b"zerotrust-drive transaction lock v1\0");
    hasher.update(identity);
    let digest = hasher.finalize();
    let mut token = String::with_capacity(32);
    for byte in &digest[..16] {
        write!(&mut token, "{byte:02x}").expect("writing to String cannot fail");
    }
    Ok(token)
}

fn validate_pid(pid: u32) -> Result<u32, String> {
    if pid == 0 || pid > i32::MAX as u32 {
        return Err("PID must be between 1 and i32::MAX".to_string());
    }
    Ok(pid)
}

fn parse_owner(bytes: &[u8], local_token: &str) -> Result<ParsedOwner, String> {
    let value = std::str::from_utf8(bytes).map_err(|error| format!("not UTF-8: {error}"))?;
    if value.bytes().all(|byte| byte.is_ascii_digit()) && !value.is_empty() {
        return Err(
            "legacy PID-only lock has ambiguous machine ownership; inspect every synced device and remove it manually only when no transaction is active"
                .to_string(),
        );
    }
    let value = value
        .strip_suffix('\n')
        .ok_or_else(|| "versioned lock must end with one newline".to_string())?;
    if value.contains('\n') || value.contains('\r') {
        return Err("lock contains unexpected line breaks".to_string());
    }
    let mut fields = value.split(':');
    let version = fields.next().unwrap_or_default();
    let token = fields.next().unwrap_or_default();
    let pid = fields.next().unwrap_or_default();
    if fields.next().is_some() || version != LOCK_RECORD_VERSION {
        return Err("unsupported or malformed transaction-lock version".to_string());
    }
    if token.len() != 32
        || !token
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err("machine token must be 32 lowercase hexadecimal digits".to_string());
    }
    let pid = pid
        .parse::<u32>()
        .map_err(|_| "PID is not a decimal u32".to_string())?;
    let pid = validate_pid(pid)?;
    if token == local_token {
        Ok(ParsedOwner::Local(pid))
    } else {
        Ok(ParsedOwner::Foreign(pid))
    }
}

#[cfg(unix)]
fn local_pid_is_live(pid: u32) -> Result<bool, String> {
    let result = unsafe { libc::kill(pid as libc::pid_t, 0) };
    if result == 0 {
        return Ok(true);
    }
    match std::io::Error::last_os_error().raw_os_error() {
        Some(libc::EPERM) => Ok(true),
        Some(libc::ESRCH) => Ok(false),
        Some(error) => Err(format!(
            "cannot determine whether local PID {pid} is live: errno {error}"
        )),
        None => Err(format!(
            "cannot determine whether local PID {pid} is live: unknown OS error"
        )),
    }
}

#[cfg(not(unix))]
fn local_pid_is_live(pid: u32) -> Result<bool, String> {
    Ok(pid == std::process::id())
}

pub(crate) fn lock_owner_is_active(
    lock_path: &std::path::Path,
    operation: &str,
) -> Result<bool, String> {
    let bytes = match read_bounded_backing_file(lock_path, MAX_LOCK_RECORD_LEN) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(error) => {
            return Err(format!(
                "read {operation} lock {}: {error}; preserving it",
                lock_path.display()
            ));
        }
    };
    let local_token = local_machine_token()
        .map_err(|error| format!("identify this machine for {operation} lock: {error}"))?;
    match parse_owner(&bytes, &local_token).map_err(|error| {
        format!(
            "refusing to replace {operation} lock {}: {error}",
            lock_path.display()
        )
    })? {
        ParsedOwner::Local(pid) => local_pid_is_live(pid),
        ParsedOwner::Foreign(pid) => Err(format!(
            "refusing to replace {operation} lock {} owned by another machine (remote PID {pid}); no recovery artifacts were touched",
            lock_path.display()
        )),
    }
}

fn record_for_pid(pid: u32) -> Result<Vec<u8>, String> {
    let pid = validate_pid(pid)?;
    let token = local_machine_token()?;
    Ok(format!("{LOCK_RECORD_VERSION}:{token}:{pid}\n").into_bytes())
}

pub(crate) fn prepare_lock_owner(operation: &str) -> Result<Vec<u8>, String> {
    record_for_pid(std::process::id())
        .map_err(|error| format!("prepare machine-bound {operation} lock: {error}"))
}

pub(crate) fn write_lock_owner(
    file: &mut std::fs::File,
    record: &[u8],
    lock_path: &std::path::Path,
    operation: &str,
) -> Result<(), String> {
    file.write_all(record)
        .map_err(|error| format!("write {operation} lock {}: {error}", lock_path.display()))
}

#[cfg(test)]
pub(crate) fn local_lock_record_for_test(pid: u32) -> Vec<u8> {
    record_for_pid(pid).expect("test host must provide a machine identifier")
}

#[cfg(test)]
mod tests {
    use super::*;

    const LOCAL: &str = "0123456789abcdef0123456789abcdef";
    const FOREIGN: &str = "fedcba9876543210fedcba9876543210";

    #[test]
    fn parses_strict_machine_bound_records() {
        assert_eq!(
            parse_owner(format!("ztd1:{LOCAL}:123\n").as_bytes(), LOCAL),
            Ok(ParsedOwner::Local(123))
        );
        assert_eq!(
            parse_owner(format!("ztd1:{FOREIGN}:123\n").as_bytes(), LOCAL),
            Ok(ParsedOwner::Foreign(123))
        );
    }

    #[test]
    fn rejects_legacy_and_malformed_records() {
        let cases: &[&[u8]] = &[
            b"123",
            b"",
            b"ztd2:0123456789abcdef0123456789abcdef:123\n",
            b"ztd1:0123456789ABCDEF0123456789ABCDEF:123\n",
            b"ztd1:short:123\n",
            b"ztd1:0123456789abcdef0123456789abcdef:0\n",
            b"ztd1:0123456789abcdef0123456789abcdef:2147483648\n",
            b"ztd1:0123456789abcdef0123456789abcdef:123:extra\n",
            b"ztd1:0123456789abcdef0123456789abcdef:123",
            b"ztd1:0123456789abcdef0123456789abcdef:123\nextra\n",
            b"\xff",
        ];
        for value in cases {
            assert!(parse_owner(value, LOCAL).is_err(), "accepted {value:?}");
        }
    }

    #[test]
    fn foreign_legacy_and_malformed_lock_files_are_preserved() {
        let dir = std::path::PathBuf::from("target/test-transaction-lock-preservation");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("_rekey.lock");
        let local = local_machine_token().unwrap();
        let mut foreign = local.clone().into_bytes();
        foreign[0] = if foreign[0] == b'0' { b'1' } else { b'0' };
        let foreign = String::from_utf8(foreign).unwrap();
        let cases = [
            format!("ztd1:{foreign}:{}\n", std::process::id()).into_bytes(),
            b"2147483647".to_vec(),
            b"malformed".to_vec(),
        ];

        for value in cases {
            std::fs::write(&path, &value).unwrap();
            assert!(lock_owner_is_active(&path, "rekey").is_err());
            assert_eq!(std::fs::read(&path).unwrap(), value);
        }
        let _ = std::fs::remove_dir_all(dir);
    }
}
