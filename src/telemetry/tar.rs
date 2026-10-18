// SPDX-FileCopyrightText: Copyright 2026 Alexander Orlov <info@lifub.com>

//! A minimal POSIX ustar writer for `zdrive telemetry export`. Entries
//! carry no owner ids or names, so the archive does not reveal the local
//! account.

use std::fs::File;
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

use super::{system, validate_instance, writer};

const BLOCK: usize = 512;
/// Largest size an 11-digit octal field holds.
const MAX_ENTRY: u64 = 0o77_777_777_777;
/// Top-level directory inside the archive.
pub(crate) const ARCHIVE_ROOT: &str = "zdrive-telemetry";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum EntryKind {
    File,
    Directory,
}

/// One 512-byte ustar header. Names longer than 100 bytes are split into
/// the 155-byte prefix and the name at a `/`.
pub(crate) fn header(
    path: &str,
    kind: EntryKind,
    size: u64,
    mtime: u64,
) -> Result<[u8; BLOCK], String> {
    let mut block = [0u8; BLOCK];
    let (prefix, name) = split_name(path)?;
    block[..name.len()].copy_from_slice(name.as_bytes());
    let (mode, typeflag, size) = match kind {
        EntryKind::File => (0o600, b'0', size),
        EntryKind::Directory => (0o700, b'5', 0),
    };
    if size > MAX_ENTRY {
        return Err(format!("{path} is too large for a ustar entry"));
    }
    octal(&mut block[100..108], mode);
    octal(&mut block[108..116], 0);
    octal(&mut block[116..124], 0);
    octal(&mut block[124..136], size);
    octal(&mut block[136..148], mtime.min(MAX_ENTRY));
    block[156] = typeflag;
    block[257..263].copy_from_slice(b"ustar\0");
    block[263..265].copy_from_slice(b"00");
    octal(&mut block[329..337], 0);
    octal(&mut block[337..345], 0);
    block[345..345 + prefix.len()].copy_from_slice(prefix.as_bytes());
    // The checksum is computed with its own field read as spaces.
    block[148..156].fill(b' ');
    let checksum: u32 = block.iter().map(|byte| u32::from(*byte)).sum();
    let digits = format!("{checksum:06o}");
    block[148..154].copy_from_slice(digits.as_bytes());
    block[154] = 0;
    block[155] = b' ';
    Ok(block)
}

/// Writes `value` as zero-padded octal digits followed by a NUL.
fn octal(field: &mut [u8], value: u64) {
    let width = field.len() - 1;
    let digits = format!("{value:0width$o}");
    field[..width].copy_from_slice(&digits.as_bytes()[digits.len() - width..]);
    field[width] = 0;
}

fn split_name(path: &str) -> Result<(&str, &str), String> {
    if !path.is_ascii() || path.is_empty() {
        return Err(format!("{path:?} is not a portable archive name"));
    }
    if path.len() <= 100 {
        return Ok(("", path));
    }
    for (index, _) in path.match_indices('/') {
        let (prefix, name) = (&path[..index], &path[index + 1..]);
        if prefix.len() <= 155 && !name.is_empty() && name.len() <= 100 {
            return Ok((prefix, name));
        }
    }
    Err(format!("{path} is too long for a ustar entry"))
}

/// What [`export`] archived.
#[derive(Debug, Default)]
pub(crate) struct Exported {
    pub(crate) files: usize,
    pub(crate) bytes: u64,
}

/// Archives every instance's day files below `root` into a new `output`.
/// Refuses to replace an existing file; removes a partial archive.
pub(crate) fn export(root: &Path, output: &Path) -> Result<Exported, String> {
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(output)
        .map_err(|error| format!("create {}: {error}", output.display()))?;
    let result = write_entries(root, &mut file).and_then(|exported| {
        file.sync_all()
            .map_err(|error| format!("write {}: {error}", output.display()))?;
        Ok(exported)
    });
    if result.is_err() {
        drop(file);
        let _ = std::fs::remove_file(output);
    }
    result
}

fn write_entries(root: &Path, out: &mut File) -> Result<Exported, String> {
    let mut exported = Exported::default();
    let mtime = system::now_ms() / 1000;
    out.write_all(&header(
        &format!("{ARCHIVE_ROOT}/"),
        EntryKind::Directory,
        0,
        mtime,
    )?)
    .map_err(io_error)?;
    for (instance, dir) in instance_dirs(root)? {
        out.write_all(&header(
            &format!("{ARCHIVE_ROOT}/{instance}/"),
            EntryKind::Directory,
            0,
            mtime,
        )?)
        .map_err(io_error)?;
        let files =
            writer::day_files(&dir).map_err(|error| format!("{}: {error}", dir.display()))?;
        for (_, path, _) in files {
            let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
                continue;
            };
            let mut source = match std::fs::OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_NOFOLLOW)
                .open(&path)
            {
                Ok(source) => source,
                // Retention may delete a file between listing and opening.
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
                Err(error) => return Err(format!("{}: {error}", path.display())),
            };
            let metadata = source
                .metadata()
                .map_err(|error| format!("{}: {error}", path.display()))?;
            if !metadata.is_file() {
                continue;
            }
            let size = metadata.len();
            let modified = u64::try_from(metadata.mtime()).unwrap_or(0);
            out.write_all(&header(
                &format!("{ARCHIVE_ROOT}/{instance}/{name}"),
                EntryKind::File,
                size,
                modified,
            )?)
            .map_err(io_error)?;
            // A file still being appended to is cut at its listed size.
            let copied = std::io::copy(&mut (&mut source).take(size), out).map_err(io_error)?;
            let padding = (size - copied) as usize + (BLOCK - (size as usize % BLOCK)) % BLOCK;
            out.write_all(&vec![0u8; padding]).map_err(io_error)?;
            exported.files += 1;
            exported.bytes += size;
        }
    }
    out.write_all(&[0u8; BLOCK * 2]).map_err(io_error)?;
    Ok(exported)
}

/// Valid instance directories below `root`, sorted by name.
pub(crate) fn instance_dirs(root: &Path) -> Result<Vec<(String, PathBuf)>, String> {
    let entries = match std::fs::read_dir(root) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(format!("{}: {error}", root.display())),
    };
    let mut dirs = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|error| format!("{}: {error}", root.display()))?;
        let Ok(name) = entry.file_name().into_string() else {
            continue;
        };
        let is_dir = entry.file_type().map(|kind| kind.is_dir()).unwrap_or(false);
        if is_dir && validate_instance(&name).is_ok() {
            dirs.push((name, entry.path()));
        }
    }
    dirs.sort();
    Ok(dirs)
}

fn io_error(error: std::io::Error) -> String {
    format!("write archive: {error}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn headers_have_valid_checksums_and_split_long_names() {
        let block = header(
            "zdrive-telemetry/zdrive/20260101.jsonl",
            EntryKind::File,
            1234,
            1,
        )
        .unwrap();
        assert_eq!(&block[257..263], b"ustar\0");
        assert_eq!(&block[124..136], b"00000002322\0");
        let stored =
            u32::from_str_radix(std::str::from_utf8(&block[148..154]).unwrap(), 8).unwrap();
        let mut copy = block;
        copy[148..156].fill(b' ');
        assert_eq!(
            stored,
            copy.iter().map(|byte| u32::from(*byte)).sum::<u32>()
        );

        let long = format!("{}/{}", "a".repeat(120), "b".repeat(90));
        let block = header(&long, EntryKind::File, 0, 0).unwrap();
        assert_eq!(&block[..90], "b".repeat(90).as_bytes());
        assert_eq!(&block[345..465], "a".repeat(120).as_bytes());
        assert!(header(&"c".repeat(101), EntryKind::File, 0, 0).is_err());
        assert!(header("caf\u{e9}", EntryKind::File, 0, 0).is_err());
    }
}
