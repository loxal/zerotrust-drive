// SPDX-FileCopyrightText: Copyright 2026 Alexander Orlov <info@lifub.com>

//! Remote layout, version 1. Every name and header here is an untrusted
//! locator: objects are accepted only after their ciphertext matches the
//! digest committed by the authenticated generation graph.
//!
//! ```text
//! <folder>/zdrive-remote.json        marker, created last during init
//! <folder>/_kdf.json                 exact copy of the store's KDF metadata,
//!                                    named by id and md5 in the marker
//! <folder>/packs/<md5>-<size>.zpk    append-only object packs
//! <folder>/roots/<gen:020>-<md5>.zr  append-only exact `_root.age` copies
//! <folder>/leases/<host>-<id>.json   advisory writer leases
//! ```

use serde::{Deserialize, Serialize};

use super::{hex, unhex};
use crate::v2::ObjectRef;
use crate::v2::replica::MAX_OBJECT_CIPHERTEXT;

pub(crate) const MARKER_NAME: &str = "zdrive-remote.json";
pub(crate) const KDF_NAME: &str = "_kdf.json";
pub(crate) const PACKS_DIR: &str = "packs";
pub(crate) const ROOTS_DIR: &str = "roots";
pub(crate) const LEASES_DIR: &str = "leases";
pub(crate) const MAX_SMALL_FILE: u64 = 64 * 1024;

const MARKER_FORMAT: &str = "zerotrust-drive-remote";
pub(crate) const REMOTE_FORMAT_VERSION: u32 = 1;
const STORE_FORMAT_VERSION: u32 = 2;

pub(crate) const PACK_MAGIC: &[u8; 8] = b"ZDRVPK01";
pub(crate) const PACK_PREFIX_LEN: u64 = 12;
const PACK_ENTRY_LEN: u64 = 16 + 32 + 8;
/// Bounds a header to 14.7 MB even for packs of tiny metadata objects.
pub(crate) const MAX_PACK_OBJECTS: u32 = 1 << 18;
/// A pack is closed once its body reaches this size.
pub(crate) const TARGET_PACK_BYTES: u64 = 64 << 20;

/// Layout commit marker. Folder ids make concurrent initialization
/// deterministic: only the folders a marker names are part of the remote.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Marker {
    pub(crate) format: String,
    pub(crate) remote_format_version: u32,
    pub(crate) store_format_version: u32,
    pub(crate) created_by: String,
    pub(crate) packs_folder_id: String,
    pub(crate) roots_folder_id: String,
    pub(crate) leases_folder_id: String,
    pub(crate) kdf_file_id: String,
    /// Lowercase hex md5 of the exact `_kdf.json` bytes.
    pub(crate) kdf_md5: String,
}

impl Marker {
    pub(crate) fn new(
        packs: &str,
        roots: &str,
        leases: &str,
        kdf: &str,
        kdf_md5: &[u8; 16],
    ) -> Self {
        Self {
            format: MARKER_FORMAT.to_string(),
            remote_format_version: REMOTE_FORMAT_VERSION,
            store_format_version: STORE_FORMAT_VERSION,
            created_by: concat!("zerotrust-drive ", env!("CARGO_PKG_VERSION")).to_string(),
            packs_folder_id: packs.to_string(),
            roots_folder_id: roots.to_string(),
            leases_folder_id: leases.to_string(),
            kdf_file_id: kdf.to_string(),
            kdf_md5: hex(kdf_md5),
        }
    }

    pub(crate) fn encode(&self) -> Vec<u8> {
        let mut bytes = serde_json::to_vec_pretty(self).expect("marker serializes");
        bytes.push(b'\n');
        bytes
    }

    pub(crate) fn decode(bytes: &[u8]) -> Result<Self, String> {
        let marker: Self = serde_json::from_slice(bytes)
            .map_err(|error| format!("parse remote marker {MARKER_NAME}: {error}"))?;
        if marker.format != MARKER_FORMAT {
            return Err(format!(
                "{MARKER_NAME} is not a zerotrust-drive remote marker"
            ));
        }
        if marker.remote_format_version != REMOTE_FORMAT_VERSION {
            return Err(format!(
                "remote format version {} is not supported by this zerotrust-drive (expected {REMOTE_FORMAT_VERSION}); upgrade zdrive",
                marker.remote_format_version
            ));
        }
        if marker.store_format_version != STORE_FORMAT_VERSION {
            return Err(format!(
                "remote store format version {} is not supported (expected {STORE_FORMAT_VERSION})",
                marker.store_format_version
            ));
        }
        for id in [
            &marker.packs_folder_id,
            &marker.roots_folder_id,
            &marker.leases_folder_id,
            &marker.kdf_file_id,
        ] {
            if !valid_file_id(id) {
                return Err(format!("{MARKER_NAME} names an invalid file id"));
            }
        }
        if unhex::<16>(&marker.kdf_md5).is_none() {
            return Err(format!("{MARKER_NAME} names an invalid KDF md5"));
        }
        Ok(marker)
    }
}

/// Provider file ids are opaque but never need quoting in queries or paths.
pub(crate) fn valid_file_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 256
        && id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
}

pub(crate) fn pack_name(md5: &[u8; 16], size: u64) -> String {
    format!("{}-{size}.zpk", hex(md5))
}

pub(crate) fn parse_pack_name(name: &str) -> Option<([u8; 16], u64)> {
    let stem = name.strip_suffix(".zpk")?;
    let (md5, size) = stem.split_once('-')?;
    if size.is_empty() || size.len() > 20 || !size.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    if size.len() > 1 && size.starts_with('0') {
        return None;
    }
    Some((unhex::<16>(md5)?, size.parse().ok()?))
}

pub(crate) fn root_record_name(number: u64, md5: &[u8; 16]) -> String {
    format!("{number:020}-{}.zr", hex(md5))
}

pub(crate) fn parse_root_record_name(name: &str) -> Option<(u64, [u8; 16])> {
    let stem = name.strip_suffix(".zr")?;
    let (number, md5) = stem.split_once('-')?;
    if number.len() != 20 || !number.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    let number: u64 = number.parse().ok()?;
    if number == 0 {
        return None;
    }
    Some((number, unhex::<16>(md5)?))
}

/// One object inside a pack.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct PackEntry {
    pub(crate) reference: ObjectRef,
    pub(crate) offset: u64,
    pub(crate) len: u64,
}

pub(crate) fn pack_header_len(count: u32) -> u64 {
    PACK_PREFIX_LEN + u64::from(count) * PACK_ENTRY_LEN
}

/// Serializes the header for objects that follow it in this exact order.
pub(crate) fn encode_pack_header(objects: &[(ObjectRef, u64)]) -> Result<Vec<u8>, String> {
    let count = u32::try_from(objects.len())
        .ok()
        .filter(|count| (1..=MAX_PACK_OBJECTS).contains(count))
        .ok_or_else(|| format!("a pack holds 1 to {MAX_PACK_OBJECTS} objects"))?;
    let mut header = Vec::with_capacity(pack_header_len(count) as usize);
    header.extend_from_slice(PACK_MAGIC);
    header.extend_from_slice(&count.to_le_bytes());
    for (reference, len) in objects {
        if *len == 0 || *len > MAX_OBJECT_CIPHERTEXT {
            return Err("pack object length is outside the v2 object bound".to_string());
        }
        header.extend_from_slice(reference.id());
        header.extend_from_slice(reference.digest());
        header.extend_from_slice(&len.to_le_bytes());
    }
    Ok(header)
}

/// Object count from the fixed-size prefix.
pub(crate) fn parse_pack_prefix(bytes: &[u8]) -> Result<u32, String> {
    if bytes.len() < PACK_PREFIX_LEN as usize || &bytes[..8] != PACK_MAGIC {
        return Err("pack does not start with the ZDRVPK01 magic".to_string());
    }
    let count = u32::from_le_bytes(bytes[8..12].try_into().expect("four bytes"));
    if count == 0 || count > MAX_PACK_OBJECTS {
        return Err(format!("pack object count {count} is out of bounds"));
    }
    Ok(count)
}

/// Parses a complete header and proves that its entries exactly tile a
/// remote file of `file_len` bytes.
pub(crate) fn parse_pack_header(bytes: &[u8], file_len: u64) -> Result<Vec<PackEntry>, String> {
    let count = parse_pack_prefix(bytes)?;
    let header_len = pack_header_len(count);
    if (bytes.len() as u64) < header_len {
        return Err("pack header is truncated".to_string());
    }
    let mut entries = Vec::with_capacity(count as usize);
    let mut seen = std::collections::HashSet::with_capacity(count as usize);
    let mut offset = header_len;
    for raw in bytes[PACK_PREFIX_LEN as usize..header_len as usize]
        .as_chunks::<56>()
        .0
    {
        let id: [u8; 16] = raw[..16].try_into().expect("16 bytes");
        let digest: [u8; 32] = raw[16..48].try_into().expect("32 bytes");
        let len = u64::from_le_bytes(raw[48..56].try_into().expect("8 bytes"));
        if len == 0 || len > MAX_OBJECT_CIPHERTEXT {
            return Err("pack entry length is outside the v2 object bound".to_string());
        }
        let reference = ObjectRef::from_parts(id, digest);
        if !seen.insert(reference) {
            return Err("pack lists the same object twice".to_string());
        }
        entries.push(PackEntry {
            reference,
            offset,
            len,
        });
        offset = offset
            .checked_add(len)
            .ok_or_else(|| "pack entries overflow".to_string())?;
    }
    if offset != file_len {
        return Err(format!(
            "pack entries cover {offset} bytes but the remote file has {file_len}"
        ));
    }
    Ok(entries)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reference(seed: u8) -> ObjectRef {
        ObjectRef::from_parts([seed; 16], [seed.wrapping_add(1); 32])
    }

    #[test]
    fn pack_header_round_trips_and_tiles_the_file() {
        let objects = [(reference(1), 10), (reference(2), 3)];
        let header = encode_pack_header(&objects).unwrap();
        assert_eq!(header.len() as u64, pack_header_len(2));
        let total = header.len() as u64 + 13;
        let entries = parse_pack_header(&header, total).unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].reference, reference(1));
        assert_eq!(entries[0].offset, pack_header_len(2));
        assert_eq!(entries[1].offset, pack_header_len(2) + 10);
        assert_eq!(entries[1].len, 3);
    }

    #[test]
    fn pack_header_rejects_malformed_or_inconsistent_input() {
        let header = encode_pack_header(&[(reference(1), 10)]).unwrap();
        let total = header.len() as u64 + 10;
        assert!(parse_pack_header(&header, total + 1).is_err());
        assert!(parse_pack_header(&header[..header.len() - 1], total).is_err());
        let mut bad_magic = header.clone();
        bad_magic[0] ^= 1;
        assert!(parse_pack_header(&bad_magic, total).is_err());
        let mut zero_count = header.clone();
        zero_count[8..12].copy_from_slice(&0u32.to_le_bytes());
        assert!(parse_pack_header(&zero_count, total).is_err());
        let mut huge_count = header.clone();
        huge_count[8..12].copy_from_slice(&(MAX_PACK_OBJECTS + 1).to_le_bytes());
        assert!(parse_pack_header(&huge_count, total).is_err());
        let mut zero_len = header.clone();
        let at = PACK_PREFIX_LEN as usize + 48;
        zero_len[at..at + 8].copy_from_slice(&0u64.to_le_bytes());
        assert!(parse_pack_header(&zero_len, header.len() as u64).is_err());
        let duplicate = encode_pack_header(&[(reference(1), 1), (reference(1), 1)]).unwrap();
        assert!(parse_pack_header(&duplicate, duplicate.len() as u64 + 2).is_err());
        assert!(encode_pack_header(&[]).is_err());
        assert!(encode_pack_header(&[(reference(1), MAX_OBJECT_CIPHERTEXT + 1)]).is_err());
    }

    #[test]
    fn names_round_trip_and_reject_lookalikes() {
        let md5 = [0xab; 16];
        let pack = pack_name(&md5, 4096);
        assert_eq!(parse_pack_name(&pack), Some((md5, 4096)));
        assert_eq!(parse_pack_name("x.zpk"), None);
        assert_eq!(parse_pack_name(&format!("{}-01.zpk", hex(&md5))), None);
        assert_eq!(parse_pack_name(&format!("{}-1.zpk.part", hex(&md5))), None);
        let root = root_record_name(7, &md5);
        assert!(root.starts_with("00000000000000000007-"));
        assert_eq!(parse_root_record_name(&root), Some((7, md5)));
        assert_eq!(parse_root_record_name(&root_record_name(0, &md5)), None);
        assert_eq!(parse_root_record_name(&format!("7-{}.zr", hex(&md5))), None);
        assert_eq!(parse_root_record_name(".DS_Store"), None);
    }

    #[test]
    fn marker_round_trips_and_refuses_other_versions() {
        let marker = Marker::new("packs_1", "roots-2", "leases3", "kdf4", &[7; 16]);
        assert_eq!(Marker::decode(&marker.encode()).unwrap(), marker);
        let mut newer = marker.clone();
        newer.remote_format_version = REMOTE_FORMAT_VERSION + 1;
        assert!(Marker::decode(&serde_json::to_vec(&newer).unwrap()).is_err());
        let mut hostile = marker.clone();
        hostile.roots_folder_id = "x' or '1'='1".to_string();
        assert!(Marker::decode(&serde_json::to_vec(&hostile).unwrap()).is_err());
        let mut bad_md5 = marker;
        bad_md5.kdf_md5 = "ABC".to_string();
        assert!(Marker::decode(&serde_json::to_vec(&bad_md5).unwrap()).is_err());
    }
}
