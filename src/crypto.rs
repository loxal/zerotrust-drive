// Copyright 2026 Alexander Orlov <alexander.orlov@loxal.net>

//! Key derivation + authenticated encryption for the encrypted store.
//!
//! # On-disk format versions
//!
//! - **v0** (pre-0.7, implicit): homemade iterative KDF (no salt, no
//!   memory-hardness) + ChaCha20-Poly1305 with a random 12-byte nonce.
//!   A v0 drive has no `_kdf.json`.
//! - **v1** (0.7+): Argon2id with a per-drive random 16-byte salt
//!   (recorded in `_kdf.json`) + XChaCha20-Poly1305 with a random
//!   24-byte nonce.
//!
//! The v0→v1 switch fixes two distinct weaknesses:
//!
//! 1. **KDF.** The v0 KDF was a custom byte-mixing function with no
//!    memory-hardness — cheap to brute-force offline against the
//!    encrypted-at-rest blobs (the primary threat for cloud-synced
//!    storage). Argon2id with a per-drive salt is the fix.
//! 2. **Nonce width.** A single long-lived per-drive key encrypts every
//!    blob and every index rewrite. With ChaCha20-Poly1305's 96-bit
//!    nonce, random nonces risk a birthday-bound collision (~2^32
//!    messages) — and a (key, nonce) collision is catastrophic
//!    (keystream reuse + Poly1305 forgery). XChaCha20-Poly1305's
//!    192-bit nonce makes random nonces safe by a margin no filesystem
//!    will ever approach.
//!
//! The v0 derive/decrypt functions are retained solely so `migrate.rs`
//! can read existing drives during the one-time format upgrade.

use argon2::{Algorithm, Argon2, Params, Version};
use blake2::{Blake2s256, Digest};
#[cfg(test)]
use chacha20poly1305::aead::Payload;
use chacha20poly1305::{
    ChaCha20Poly1305, Nonce, XChaCha20Poly1305, XNonce,
    aead::{Aead, AeadInPlace, KeyInit, OsRng, rand_core::RngCore},
};
use serde::{Deserialize, Serialize};
use std::io::{Read, Seek, SeekFrom};
use std::sync::atomic::{AtomicU64, Ordering};

/// On-disk format version recorded in `_kdf.json`. Bump only on a
/// breaking change to the KDF or AEAD; the presence/absence of
/// `_kdf.json` is what distinguishes v1 from v0.
pub const FORMAT_VERSION: u32 = 1;

/// Argon2id salt length. 16 bytes is well above Argon2's 8-byte
/// minimum and matches common practice.
pub const SALT_LEN: usize = 16;

/// Reject cloud-supplied KDF settings that would turn metadata parsing into a
/// resource-exhaustion attack. Existing drives use about 19 MiB, two passes,
/// and one lane; these caps leave ample room for future strengthening.
const MAX_KDF_FILE_LEN: u64 = 64 * 1024;
const MAX_M_COST_KIB: u32 = 256 * 1024;
const MAX_T_COST: u32 = 10;
const MAX_P_COST: u32 = 16;

/// XChaCha20-Poly1305 extended nonce length (192-bit).
const XNONCE_LEN: usize = 24;

/// Poly1305 authentication-tag length appended to every ciphertext.
const TAG_LEN: usize = 16;

/// Bytes added to each v1 plaintext: 24-byte nonce + 16-byte tag.
pub(crate) const V1_CIPHERTEXT_OVERHEAD: u64 = (XNONCE_LEN + TAG_LEN) as u64;

/// `_kdf.json` is tiny. This bound prevents a malformed recovery manifest
/// from making startup retain an unexpectedly large exact fingerprint.
const MAX_EXACT_FINGERPRINT_LEN: u64 = 64 * 1024;
static KDF_TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Legacy (v0) ChaCha20-Poly1305 nonce length (96-bit).
const LEGACY_NONCE_LEN: usize = 12;

/// Bytes added to each legacy v0 plaintext: 12-byte nonce + 16-byte tag.
pub(crate) const LEGACY_CIPHERTEXT_OVERHEAD: u64 = (LEGACY_NONCE_LEN + TAG_LEN) as u64;

/// Argon2id parameters + per-drive salt, persisted unencrypted as
/// `_kdf.json`. The salt is not secret — its job is to defeat
/// precomputation/rainbow-table attacks and to make two drives with
/// the same passphrase derive different keys. The cost parameters are
/// recorded too so a future parameter change never locks anyone out of
/// an existing drive: its key is always reproducible from its own
/// recorded params.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct KdfParams {
    pub format_version: u32,
    pub algorithm: String,
    pub salt: Vec<u8>,
    pub m_cost: u32,
    pub t_cost: u32,
    pub p_cost: u32,
}

impl KdfParams {
    /// Fresh params with a CSPRNG-generated salt and the current
    /// Argon2id cost defaults (OWASP baseline: 19 MiB, t=2, p=1).
    pub fn new_random() -> Self {
        let mut salt = vec![0u8; SALT_LEN];
        OsRng.fill_bytes(&mut salt);
        Self {
            format_version: FORMAT_VERSION,
            algorithm: "argon2id".to_string(),
            salt,
            m_cost: Params::DEFAULT_M_COST,
            t_cost: Params::DEFAULT_T_COST,
            p_cost: Params::DEFAULT_P_COST,
        }
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.format_version != FORMAT_VERSION {
            return Err(format!(
                "unsupported KDF format version {} (expected {FORMAT_VERSION})",
                self.format_version
            ));
        }
        if self.algorithm != "argon2id" {
            return Err(format!(
                "unsupported KDF algorithm {:?} (expected argon2id)",
                self.algorithm
            ));
        }
        if self.salt.len() != SALT_LEN {
            return Err(format!(
                "invalid Argon2id salt length {} (expected {SALT_LEN})",
                self.salt.len()
            ));
        }
        if self.m_cost > MAX_M_COST_KIB || self.t_cost > MAX_T_COST || self.p_cost > MAX_P_COST {
            return Err(format!(
                "KDF resource parameters exceed safety caps (m_cost <= {MAX_M_COST_KIB} KiB, t_cost <= {MAX_T_COST}, p_cost <= {MAX_P_COST})"
            ));
        }
        Params::new(self.m_cost, self.t_cost, self.p_cost, Some(32))
            .map_err(|e| format!("invalid Argon2id parameters: {e}"))?;
        Ok(())
    }
}

/// Path to the per-drive KDF metadata file.
pub fn kdf_path(base_path: &std::path::Path) -> std::path::PathBuf {
    base_path.join("_kdf.json")
}

/// Read `_kdf.json` if present. `Ok(None)` means the drive has no KDF
/// file — i.e. it is brand-new or a pre-0.7 (v0) drive.
pub(crate) fn load_kdf_with_fingerprint(
    base_path: &std::path::Path,
) -> Result<Option<(KdfParams, RecoveryFingerprint)>, String> {
    let path = kdf_path(base_path);
    let file = {
        let mut options = std::fs::OpenOptions::new();
        options.read(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.custom_flags(libc::O_NOFOLLOW);
        }
        match options.open(&path) {
            Ok(file) => file,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(format!("open {}: {e}", path.display())),
        }
    };
    let metadata = file
        .metadata()
        .map_err(|e| format!("stat {}: {e}", path.display()))?;
    if !metadata.is_file() {
        return Err(format!(
            "{} is not a regular KDF metadata file",
            path.display()
        ));
    }
    let len = metadata.len();
    if len > MAX_KDF_FILE_LEN {
        return Err(format!(
            "{} is unexpectedly large ({len} bytes; maximum {MAX_KDF_FILE_LEN})",
            path.display()
        ));
    }
    let mut bytes = Vec::with_capacity(len as usize);
    file.take(MAX_KDF_FILE_LEN + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| format!("read {}: {e}", path.display()))?;
    if bytes.len() as u64 > MAX_KDF_FILE_LEN {
        return Err(format!(
            "{} grew beyond the {MAX_KDF_FILE_LEN}-byte maximum while being read",
            path.display()
        ));
    }
    let params: KdfParams =
        serde_json::from_slice(&bytes).map_err(|e| format!("parse {}: {e}", path.display()))?;
    params
        .validate()
        .map_err(|e| format!("validate {}: {e}", path.display()))?;
    let fingerprint = RecoveryFingerprint::Exact { bytes };
    Ok(Some((params, fingerprint)))
}

pub fn load_kdf(base_path: &std::path::Path) -> Result<Option<KdfParams>, String> {
    load_kdf_with_fingerprint(base_path).map(|loaded| loaded.map(|(params, _fingerprint)| params))
}

/// Persist brand-new KDF params without ever replacing an existing salt.
/// A delayed cloud copy appearing during initialization must win rather than
/// becoming undecryptable. A hard-link publication keeps the fully fsynced
/// temp atomic; filesystems without hard links use `create_new` and fail
/// closed with a partial target after a crash.
pub fn save_kdf(base_path: &std::path::Path, params: &KdfParams) -> Result<(), String> {
    use std::io::Write;
    params.validate()?;
    let path = kdf_path(base_path);
    let json = serde_json::to_vec_pretty(params).map_err(|e| e.to_string())?;
    let (tmp, mut f) = loop {
        let sequence = KDF_TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
        let tmp = base_path.join(format!("._kdf.json.{}.{sequence}.tmp", std::process::id()));
        let mut options = std::fs::OpenOptions::new();
        options.create_new(true).write(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.custom_flags(libc::O_NOFOLLOW);
        }
        match options.open(&tmp) {
            Ok(file) => break (tmp, file),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(format!("create {}: {e}", tmp.display())),
        }
    };
    let mut preserve_temp_on_error = false;
    let sync_parent = || {
        std::fs::File::open(base_path)
            .map_err(|e| format!("open KDF parent {}: {e}", base_path.display()))?
            .sync_all()
            .map_err(|e| format!("sync KDF parent {}: {e}", base_path.display()))
    };
    let result = (|| -> Result<(), String> {
        f.write_all(&json).map_err(|e| e.to_string())?;
        f.sync_all().map_err(|e| e.to_string())?;
        drop(f);
        // Make the complete temp name durable before attempting publication.
        sync_parent()?;
        preserve_temp_on_error = true;
        match std::fs::hard_link(&tmp, &path) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                return Err(format!(
                    "refusing to replace KDF metadata that appeared at {}",
                    path.display()
                ));
            }
            Err(link_error) => {
                let mut options = std::fs::OpenOptions::new();
                options.create_new(true).write(true);
                #[cfg(unix)]
                {
                    use std::os::unix::fs::OpenOptionsExt;
                    options.custom_flags(libc::O_NOFOLLOW);
                }
                let mut target = options.open(&path).map_err(|e| {
                    format!(
                        "publish new KDF metadata {} after hard-link publication failed ({link_error}): {e}",
                        path.display()
                    )
                })?;
                target
                    .write_all(&json)
                    .map_err(|e| format!("write new KDF metadata {}: {e}", path.display()))?;
                target
                    .sync_all()
                    .map_err(|e| format!("sync new KDF metadata {}: {e}", path.display()))?;
            }
        }
        // Persist the canonical publication before dropping its recovery name.
        sync_parent()?;
        std::fs::remove_file(&tmp)
            .map_err(|e| format!("remove published KDF temp {}: {e}", tmp.display()))?;
        sync_parent()
    })();
    if result.is_err() && !preserve_temp_on_error {
        let _ = std::fs::remove_file(&tmp);
    }
    result
}

/// Load the drive's KDF params, creating + persisting fresh random
/// params if none exist.
///
/// **Caller contract:** only safe on a v1 drive or a brand-new (empty)
/// drive. Calling this on a v0 drive that still has a ChaCha20 index
/// would mint a *new* Argon2id key that cannot decrypt the old data —
/// v0 drives must go through `migrate.rs` first. `ZeroTrustFs::new`
/// and `main` enforce that ordering.
pub fn load_or_create_kdf(base_path: &std::path::Path) -> Result<KdfParams, String> {
    load_or_create_kdf_with_fingerprint(base_path).map(|(params, _fingerprint)| params)
}

pub(crate) fn load_or_create_kdf_with_fingerprint(
    base_path: &std::path::Path,
) -> Result<(KdfParams, RecoveryFingerprint), String> {
    if let Some(loaded) = load_kdf_with_fingerprint(base_path)? {
        return Ok(loaded);
    }
    let params = KdfParams::new_random();
    save_kdf(base_path, &params)?;
    load_kdf_with_fingerprint(base_path)?.ok_or_else(|| {
        format!(
            "new KDF metadata {} disappeared immediately after publication",
            kdf_path(base_path).display()
        )
    })
}

/// Derive a 256-bit key from a passphrase with Argon2id, using the
/// drive's stored salt and cost parameters. Memory-hard — the primary
/// defense against offline passphrase guessing against the blobs.
pub fn try_derive_key(passphrase: &str, kdf: &KdfParams) -> Result<[u8; 32], String> {
    kdf.validate()?;
    let params = Params::new(kdf.m_cost, kdf.t_cost, kdf.p_cost, Some(32))
        .map_err(|e| format!("invalid Argon2id parameters: {e}"))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key = [0u8; 32];
    argon2
        .hash_password_into(passphrase.as_bytes(), &kdf.salt, &mut key)
        .map_err(|e| format!("Argon2id key derivation failed: {e}"))?;
    Ok(key)
}

/// Infallible compatibility wrapper for callers that already validated their
/// in-memory parameters. Production metadata paths should use
/// [`try_derive_key`] so resource/allocation failures remain recoverable.
#[cfg_attr(not(test), allow(dead_code))]
pub fn derive_key(passphrase: &str, kdf: &KdfParams) -> [u8; 32] {
    try_derive_key(passphrase, kdf).expect("argon2 key derivation failed")
}

/// Convenience for tests and brand-new-store setup: load or create KDF
/// metadata and derive the corresponding key.
pub fn try_derive_key_at(
    base_path: &std::path::Path,
    passphrase: &str,
) -> Result<[u8; 32], String> {
    let kdf = load_or_create_kdf(base_path)?;
    try_derive_key(passphrase, &kdf)
}

/// Load an existing drive's KDF params and derive its key. Maintenance paths
/// must use this variant: if `_kdf.json` is temporarily unavailable in a
/// cloud-backed store, minting a replacement salt would make the existing
/// ciphertext undecryptable.
pub fn try_derive_existing_key_at(
    base_path: &std::path::Path,
    passphrase: &str,
) -> Result<[u8; 32], String> {
    let kdf = load_kdf(base_path)?.ok_or_else(|| {
        format!(
            "required KDF metadata {} is missing",
            kdf_path(base_path).display()
        )
    })?;
    try_derive_key(passphrase, &kdf)
}

#[cfg_attr(not(test), allow(dead_code))]
pub fn derive_key_at(base_path: &std::path::Path, passphrase: &str) -> [u8; 32] {
    try_derive_key_at(base_path, passphrase).expect("failed to load KDF parameters or derive key")
}

/// v0 (pre-0.7) key derivation: homemade iterative mixing, no salt, no
/// memory-hardness. Retained ONLY so the format migration can decrypt
/// existing v0 blobs. Never use for new data.
pub fn derive_key_legacy(passphrase: &str) -> [u8; 32] {
    let mut key = [0u8; 32];
    let bytes = passphrase.as_bytes();
    let mut state = [0u8; 64];
    for (i, &b) in bytes.iter().enumerate() {
        state[i % 64] ^= b;
    }
    let len_bytes = (bytes.len() as u64).to_le_bytes();
    for (i, &b) in len_bytes.iter().enumerate() {
        state[56 + i] ^= b;
    }
    for _ in 0..100_000 {
        for i in 0..64 {
            state[i] = state[i]
                .wrapping_add(state[(i + 1) % 64])
                .wrapping_mul(7)
                .wrapping_add(0x9e);
        }
    }
    key.copy_from_slice(&state[..32]);
    key
}

/// Original v0 key derivation shipped by the tagged 0.6.0 release and
/// retained by early 0.6.1 builds: 10,000 mixing rounds and no passphrase
/// length fold. The hardened v0 derivation above changed both details without
/// an on-disk format marker, so migration must authenticate-probe both keys.
pub fn derive_key_legacy_tagged(passphrase: &str) -> [u8; 32] {
    let mut key = [0u8; 32];
    let bytes = passphrase.as_bytes();
    let mut state = [0u8; 64];
    for (i, &b) in bytes.iter().enumerate() {
        state[i % 64] ^= b;
    }
    for _ in 0..10_000 {
        for i in 0..64 {
            state[i] = state[i]
                .wrapping_add(state[(i + 1) % 64])
                .wrapping_mul(7)
                .wrapping_add(0x9e);
        }
    }
    key.copy_from_slice(&state[..32]);
    key
}

/// Compact identity for recovery artifacts. Ciphertexts include a streaming
/// BLAKE2s-256 digest of every byte; nonce, tag, and length retain diagnostics
/// and compatibility with manifests created before full digests were added.
/// `_kdf.json` uses an exact fingerprint because it is plaintext and tiny.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub(crate) enum RecoveryFingerprint {
    Ciphertext {
        len: u64,
        nonce: Vec<u8>,
        tag: Vec<u8>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        digest: Option<Vec<u8>>,
    },
    Exact {
        bytes: Vec<u8>,
    },
}

impl RecoveryFingerprint {
    pub(crate) fn is_ciphertext(&self) -> bool {
        matches!(self, Self::Ciphertext { .. })
    }

    pub(crate) fn is_exact(&self) -> bool {
        matches!(self, Self::Exact { .. })
    }

    pub(crate) fn is_well_formed(&self) -> bool {
        match self {
            Self::Ciphertext {
                len,
                nonce,
                tag,
                digest,
            } => {
                *len >= (XNONCE_LEN + TAG_LEN) as u64
                    && nonce.len() == XNONCE_LEN
                    && tag.len() == TAG_LEN
                    && digest.as_ref().is_none_or(|digest| digest.len() == 32)
            }
            Self::Exact { bytes } => bytes.len() as u64 <= MAX_EXACT_FINGERPRINT_LEN,
        }
    }

    pub(crate) fn has_full_content_identity(&self) -> bool {
        match self {
            Self::Ciphertext { digest, .. } => {
                digest.as_ref().is_some_and(|value| value.len() == 32)
            }
            Self::Exact { .. } => true,
        }
    }

    pub(crate) fn has_same_legacy_identity(&self, other: &Self) -> bool {
        match (self, other) {
            (
                Self::Ciphertext {
                    len, nonce, tag, ..
                },
                Self::Ciphertext {
                    len: other_len,
                    nonce: other_nonce,
                    tag: other_tag,
                    ..
                },
            ) => len == other_len && nonce == other_nonce && tag == other_tag,
            (Self::Exact { bytes }, Self::Exact { bytes: other_bytes }) => bytes == other_bytes,
            _ => false,
        }
    }

    pub(crate) fn ciphertext_len(&self) -> Option<u64> {
        match self {
            Self::Ciphertext { len, .. } => Some(*len),
            Self::Exact { .. } => None,
        }
    }
}

pub(crate) fn ciphertext_fingerprint(
    path: &std::path::Path,
) -> Result<RecoveryFingerprint, String> {
    ciphertext_fingerprint_with_bounds(path, None, u64::MAX)
}

pub(crate) fn ciphertext_fingerprint_bounded(
    path: &std::path::Path,
    max_len: u64,
) -> Result<RecoveryFingerprint, String> {
    ciphertext_fingerprint_with_bounds(path, None, max_len)
}

pub(crate) fn ciphertext_fingerprint_expected(
    path: &std::path::Path,
    expected_len: u64,
) -> Result<RecoveryFingerprint, String> {
    ciphertext_fingerprint_with_bounds(path, Some(expected_len), expected_len)
}

fn ciphertext_fingerprint_with_bounds(
    path: &std::path::Path,
    expected_len: Option<u64>,
    max_len: u64,
) -> Result<RecoveryFingerprint, String> {
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW);
    }
    let mut file = options
        .open(path)
        .map_err(|e| format!("open {}: {e}", path.display()))?;
    let metadata = file
        .metadata()
        .map_err(|e| format!("stat {}: {e}", path.display()))?;
    if !metadata.is_file() {
        return Err(format!(
            "{} is not a regular ciphertext file",
            path.display()
        ));
    }
    let len = metadata.len();
    if len > max_len {
        return Err(format!(
            "{} is unexpectedly large ({len} bytes; maximum {max_len})",
            path.display()
        ));
    }
    if let Some(expected_len) = expected_len
        && len != expected_len
    {
        return Err(format!(
            "{} has {len} bytes; expected {expected_len}",
            path.display()
        ));
    }
    if len < (XNONCE_LEN + TAG_LEN) as u64 {
        return Err(format!(
            "{} is too short to be an XChaCha20-Poly1305 ciphertext",
            path.display()
        ));
    }

    let mut nonce = vec![0u8; XNONCE_LEN];
    file.read_exact(&mut nonce)
        .map_err(|e| format!("read nonce from {}: {e}", path.display()))?;
    file.seek(SeekFrom::End(-(TAG_LEN as i64)))
        .map_err(|e| format!("seek tag in {}: {e}", path.display()))?;
    let mut tag = vec![0u8; TAG_LEN];
    file.read_exact(&mut tag)
        .map_err(|e| format!("read tag from {}: {e}", path.display()))?;
    file.seek(SeekFrom::Start(0))
        .map_err(|e| format!("rewind {} for hashing: {e}", path.display()))?;
    let mut hasher = Blake2s256::new();
    let mut total = 0u64;
    let mut chunk = [0u8; 64 * 1024];
    loop {
        let read = file
            .read(&mut chunk)
            .map_err(|e| format!("hash {}: {e}", path.display()))?;
        if read == 0 {
            break;
        }
        total = total
            .checked_add(read as u64)
            .ok_or_else(|| format!("{} is too large to fingerprint", path.display()))?;
        if total > len {
            return Err(format!(
                "{} grew while its ciphertext fingerprint was read",
                path.display()
            ));
        }
        hasher.update(&chunk[..read]);
    }
    let final_len = file
        .metadata()
        .map_err(|e| format!("restat {}: {e}", path.display()))?
        .len();
    if final_len != len || total != len {
        return Err(format!(
            "{} changed size while its ciphertext fingerprint was read (expected {len}, read {total}, final {final_len} bytes)",
            path.display()
        ));
    }
    let digest = Some(hasher.finalize().to_vec());

    Ok(RecoveryFingerprint::Ciphertext {
        len,
        nonce,
        tag,
        digest,
    })
}

pub(crate) fn ciphertext_bytes_fingerprint(bytes: &[u8]) -> Result<RecoveryFingerprint, String> {
    if bytes.len() < XNONCE_LEN + TAG_LEN {
        return Err("data is too short to be an XChaCha20-Poly1305 ciphertext".to_string());
    }
    Ok(RecoveryFingerprint::Ciphertext {
        len: bytes.len() as u64,
        nonce: bytes[..XNONCE_LEN].to_vec(),
        tag: bytes[bytes.len() - TAG_LEN..].to_vec(),
        digest: Some(Blake2s256::digest(bytes).to_vec()),
    })
}

pub(crate) fn exact_fingerprint(path: &std::path::Path) -> Result<RecoveryFingerprint, String> {
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW);
    }
    let file = options
        .open(path)
        .map_err(|e| format!("open {}: {e}", path.display()))?;
    let metadata = file
        .metadata()
        .map_err(|e| format!("stat {}: {e}", path.display()))?;
    if !metadata.is_file() {
        return Err(format!("{} is not a regular metadata file", path.display()));
    }
    let len = metadata.len();
    if len > MAX_EXACT_FINGERPRINT_LEN {
        return Err(format!(
            "{} is unexpectedly large ({len} bytes)",
            path.display()
        ));
    }
    let capacity = usize::try_from(len)
        .map_err(|_| format!("{} is too large for this platform", path.display()))?;
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(capacity)
        .map_err(|_| format!("cannot allocate {len} bytes to read {}", path.display()))?;
    file.take(MAX_EXACT_FINGERPRINT_LEN + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| format!("read {}: {e}", path.display()))?;
    if bytes.len() as u64 != len {
        return Err(format!(
            "{} changed size while being fingerprinted (expected {len}, read {})",
            path.display(),
            bytes.len()
        ));
    }
    Ok(RecoveryFingerprint::Exact { bytes })
}

// --- Associated data (AAD) binding -----------------------------------------
//
// XChaCha20-Poly1305 authenticates the AAD without encrypting it. Binding each
// ciphertext to its logical identity stops an attacker who can write the
// encrypted store (e.g. a compromised cloud-sync account) from **swapping**
// one blob's bytes over another's: a blob encrypted as "blob:000005.age"
// fails to authenticate when read as "blob:000003.age". Domain tags also keep
// an index ciphertext from being substituted into a data slot and vice versa.
//
// AAD does NOT defend against whole-object rollback/replay (restoring an older
// authenticated copy of the same name) — that needs a trusted monotonic
// anchor the on-disk scheme does not have. Documented limitation.

const AAD_DOMAIN: &[u8] = b"zerotrust-drive\x00v1\x00";

/// AAD for the directory index (`_index.age`).
fn index_aad() -> Vec<u8> {
    let mut a = AAD_DOMAIN.to_vec();
    a.extend_from_slice(b"index");
    a
}

/// AAD for a data blob, bound to its on-disk filename.
fn blob_aad(disk_filename: &str) -> Vec<u8> {
    let mut a = AAD_DOMAIN.to_vec();
    a.extend_from_slice(b"blob\x00");
    a.extend_from_slice(disk_filename.as_bytes());
    a
}

/// Low-level: encrypt with XChaCha20-Poly1305 and the given AAD — random
/// 24-byte nonce prepended. Prefer the [`encrypt_blob`]/[`encrypt_index`]
/// wrappers so the AAD policy lives in exactly one place.
pub fn encrypt_bytes(key: &[u8; 32], plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>, String> {
    let mut owned = Vec::new();
    owned
        .try_reserve(plaintext.len().saturating_add(XNONCE_LEN + TAG_LEN))
        .map_err(|e| format!("cannot allocate plaintext encryption buffer: {e}"))?;
    owned.extend_from_slice(plaintext);
    encrypt_bytes_owned(key, owned, aad)
}

/// Low-level: decrypt v1 XChaCha20-Poly1305 with the given AAD — first 24
/// bytes are the nonce. Fails if the AAD does not match the one used to
/// encrypt.
#[cfg(test)]
pub fn decrypt_bytes(key: &[u8; 32], data: &[u8], aad: &[u8]) -> Result<Vec<u8>, String> {
    if data.len() < XNONCE_LEN {
        return Err("ciphertext too short".to_string());
    }
    let cipher = XChaCha20Poly1305::new(key.into());
    let nonce = XNonce::from_slice(&data[..XNONCE_LEN]);
    cipher
        .decrypt(
            nonce,
            Payload {
                msg: &data[XNONCE_LEN..],
                aad,
            },
        )
        .map_err(|e| e.to_string())
}

/// Encrypt an owned buffer in place, avoiding a second full-size allocation.
/// The returned layout is identical to [`encrypt_bytes`].
fn encrypt_bytes_owned(
    key: &[u8; 32],
    mut plaintext: Vec<u8>,
    aad: &[u8],
) -> Result<Vec<u8>, String> {
    plaintext
        .try_reserve(XNONCE_LEN + TAG_LEN)
        .map_err(|e| format!("cannot allocate ciphertext buffer: {e}"))?;

    let cipher = XChaCha20Poly1305::new(key.into());
    let mut nonce_bytes = [0u8; XNONCE_LEN];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = XNonce::from_slice(&nonce_bytes);
    cipher
        .encrypt_in_place(nonce, aad, &mut plaintext)
        .map_err(|e| e.to_string())?;

    let ciphertext_len = plaintext.len();
    plaintext.resize(ciphertext_len + XNONCE_LEN, 0);
    plaintext.copy_within(0..ciphertext_len, XNONCE_LEN);
    plaintext[..XNONCE_LEN].copy_from_slice(&nonce_bytes);
    Ok(plaintext)
}

/// Decrypt an owned v1 buffer in place. This keeps peak memory near one copy
/// of the file instead of retaining both ciphertext and plaintext buffers.
fn decrypt_bytes_owned(key: &[u8; 32], mut data: Vec<u8>, aad: &[u8]) -> Result<Vec<u8>, String> {
    if data.len() < XNONCE_LEN + TAG_LEN {
        return Err("ciphertext too short".to_string());
    }
    let mut nonce_bytes = [0u8; XNONCE_LEN];
    nonce_bytes.copy_from_slice(&data[..XNONCE_LEN]);
    let encrypted_len = data.len() - XNONCE_LEN;
    data.copy_within(XNONCE_LEN.., 0);
    data.truncate(encrypted_len);

    let cipher = XChaCha20Poly1305::new(key.into());
    cipher
        .decrypt_in_place(XNonce::from_slice(&nonce_bytes), aad, &mut data)
        .map_err(|e| e.to_string())?;
    Ok(data)
}

/// Encrypt a data blob, binding it to its on-disk filename via AAD.
pub fn encrypt_blob(
    key: &[u8; 32],
    disk_filename: &str,
    plaintext: &[u8],
) -> Result<Vec<u8>, String> {
    encrypt_bytes(key, plaintext, &blob_aad(disk_filename))
}

/// Owned-buffer variant for maintenance/truncate paths where plaintext is no
/// longer needed after encryption.
pub fn encrypt_blob_owned(
    key: &[u8; 32],
    disk_filename: &str,
    plaintext: Vec<u8>,
) -> Result<Vec<u8>, String> {
    encrypt_bytes_owned(key, plaintext, &blob_aad(disk_filename))
}

/// Decrypt a data blob; fails if `disk_filename` does not match the name it
/// was encrypted under (i.e. the blob was moved/swapped on disk).
#[cfg(test)]
pub fn decrypt_blob(key: &[u8; 32], disk_filename: &str, data: &[u8]) -> Result<Vec<u8>, String> {
    decrypt_bytes(key, data, &blob_aad(disk_filename))
}

/// Owned-buffer variant used by normal filesystem reads to avoid holding a
/// second file-sized allocation during decryption.
pub fn decrypt_blob_owned(
    key: &[u8; 32],
    disk_filename: &str,
    data: Vec<u8>,
) -> Result<Vec<u8>, String> {
    decrypt_bytes_owned(key, data, &blob_aad(disk_filename))
}

/// Encrypt the directory index, bound to the index domain tag.
pub fn encrypt_index(key: &[u8; 32], plaintext: &[u8]) -> Result<Vec<u8>, String> {
    encrypt_bytes(key, plaintext, &index_aad())
}

/// Owned-buffer variant used by index commits to avoid retaining serialized
/// plaintext and ciphertext copies of the complete index simultaneously.
pub fn encrypt_index_owned(key: &[u8; 32], plaintext: Vec<u8>) -> Result<Vec<u8>, String> {
    encrypt_bytes_owned(key, plaintext, &index_aad())
}

/// Decrypt the directory index.
#[cfg(test)]
pub fn decrypt_index(key: &[u8; 32], data: &[u8]) -> Result<Vec<u8>, String> {
    decrypt_bytes(key, data, &index_aad())
}

/// Owned-buffer variant used at mount time to reduce peak index memory.
pub fn decrypt_index_owned(key: &[u8; 32], data: Vec<u8>) -> Result<Vec<u8>, String> {
    decrypt_bytes_owned(key, data, &index_aad())
}

/// Decrypt v0 ChaCha20-Poly1305 — first 12 bytes are the nonce. Used
/// only by `migrate.rs` to read pre-0.7 blobs during the upgrade.
pub fn decrypt_bytes_legacy(key: &[u8; 32], data: &[u8]) -> Result<Vec<u8>, String> {
    if data.len() < LEGACY_NONCE_LEN {
        return Err("ciphertext too short".to_string());
    }
    let cipher = ChaCha20Poly1305::new(key.into());
    let nonce = Nonce::from_slice(&data[..LEGACY_NONCE_LEN]);
    cipher
        .decrypt(nonce, &data[LEGACY_NONCE_LEN..])
        .map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_kdf() -> KdfParams {
        // Cheap params keep the test suite fast — production drives use
        // the OWASP defaults via `KdfParams::new_random`.
        KdfParams {
            format_version: FORMAT_VERSION,
            algorithm: "argon2id".to_string(),
            salt: vec![7u8; SALT_LEN],
            m_cost: 8, // KiB — minimum-ish, fast
            t_cost: 1,
            p_cost: 1,
        }
    }

    #[test]
    fn v1_roundtrip() {
        let key = derive_key("correct horse battery staple", &test_kdf());
        let pt = b"the quick brown fox";
        let ct = encrypt_bytes(&key, pt, b"aad").unwrap();
        // Nonce (24) + tag (16) overhead, and ciphertext != plaintext.
        assert!(ct.len() >= pt.len() + 24 + 16);
        assert_ne!(&ct[24..], pt);
        let rt = decrypt_bytes(&key, &ct, b"aad").unwrap();
        assert_eq!(rt, pt);
    }

    #[test]
    fn owned_v1_buffers_preserve_the_wire_format_and_authentication() {
        let key = derive_key("pw", &test_kdf());
        let plaintext = b"owned buffer".to_vec();

        let mut owned_plaintext =
            Vec::with_capacity(plaintext.len() + usize::try_from(V1_CIPHERTEXT_OVERHEAD).unwrap());
        owned_plaintext.extend_from_slice(&plaintext);
        let allocation = owned_plaintext.as_ptr();
        let index = encrypt_index_owned(&key, owned_plaintext).unwrap();
        assert_eq!(index.as_ptr(), allocation);
        assert_eq!(
            index.len() as u64,
            plaintext.len() as u64 + V1_CIPHERTEXT_OVERHEAD
        );
        assert_eq!(decrypt_index(&key, &index).unwrap(), plaintext);

        let borrowed_blob = encrypt_blob(&key, "000001.age", &plaintext).unwrap();
        let allocation = borrowed_blob.as_ptr();
        let decrypted = decrypt_blob_owned(&key, "000001.age", borrowed_blob).unwrap();
        assert_eq!(decrypted.as_ptr(), allocation);
        assert_eq!(decrypted, plaintext);
        let owned_blob =
            encrypt_bytes_owned(&key, plaintext.clone(), &blob_aad("000001.age")).unwrap();
        assert_eq!(
            decrypt_blob(&key, "000001.age", &owned_blob).unwrap(),
            plaintext
        );
        assert!(decrypt_blob_owned(&key, "000002.age", owned_blob).is_err());
    }

    #[test]
    fn ciphertext_fingerprint_covers_middle_bytes() {
        let dir = std::path::PathBuf::from("target/test-full-ciphertext-fingerprint");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let key = derive_key("pw", &test_kdf());
        let path = dir.join("000001.age");
        let mut ciphertext = encrypt_blob(&key, "000001.age", b"fingerprinted body").unwrap();
        std::fs::write(&path, &ciphertext).unwrap();
        let before = ciphertext_fingerprint(&path).unwrap();
        assert!(before.has_full_content_identity());

        ciphertext[XNONCE_LEN + 1] ^= 0x80;
        std::fs::write(&path, &ciphertext).unwrap();
        let after = ciphertext_fingerprint(&path).unwrap();
        assert_ne!(before, after);

        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn v1_nonce_is_24_bytes_and_random() {
        let key = derive_key("pw", &test_kdf());
        let a = encrypt_bytes(&key, b"x", b"").unwrap();
        let b = encrypt_bytes(&key, b"x", b"").unwrap();
        // Same plaintext, different nonce → different ciphertext prefix.
        assert_ne!(a[..24], b[..24], "nonces must differ between calls");
    }

    #[test]
    fn wrong_key_fails_to_decrypt() {
        let k1 = derive_key("right", &test_kdf());
        let mut other = test_kdf();
        other.salt = vec![9u8; SALT_LEN];
        let k2 = derive_key("right", &other); // same pw, different salt
        let ct = encrypt_bytes(&k1, b"secret", b"").unwrap();
        assert!(decrypt_bytes(&k2, &ct, b"").is_err());
    }

    #[test]
    fn aad_mismatch_fails_to_decrypt() {
        // The core anti-swap property: a blob encrypted under one
        // filename must not decrypt under another.
        let key = derive_key("pw", &test_kdf());
        let ct = encrypt_blob(&key, "000005.age", b"file five").unwrap();
        assert!(
            decrypt_blob(&key, "000003.age", &ct).is_err(),
            "a blob must not authenticate under a different filename (swap attack)"
        );
        // Correct filename still works.
        assert_eq!(decrypt_blob(&key, "000005.age", &ct).unwrap(), b"file five");
    }

    #[test]
    fn index_and_blob_domains_are_separated() {
        // An index ciphertext must not be substitutable into a data
        // slot (or vice versa), even at the same byte position.
        let key = derive_key("pw", &test_kdf());
        let idx = encrypt_index(&key, b"index bytes").unwrap();
        assert!(decrypt_blob(&key, "000001.age", &idx).is_err());
        let blob = encrypt_blob(&key, "000001.age", b"blob bytes").unwrap();
        assert!(decrypt_index(&key, &blob).is_err());
    }

    #[test]
    fn derive_key_is_deterministic_per_salt() {
        let kdf = test_kdf();
        assert_eq!(derive_key("pw", &kdf), derive_key("pw", &kdf));
    }

    #[test]
    fn different_salt_yields_different_key() {
        let mut a = test_kdf();
        a.salt = vec![1u8; SALT_LEN];
        let mut b = test_kdf();
        b.salt = vec![2u8; SALT_LEN];
        assert_ne!(derive_key("pw", &a), derive_key("pw", &b));
    }

    #[test]
    fn legacy_v0_decrypt_reads_chacha20_12byte_nonce() {
        // Reproduce a v0 blob: ChaCha20-Poly1305, 12-byte random nonce
        // prepended, key from the legacy KDF. `decrypt_bytes_legacy`
        // must read it; the v1 `decrypt_bytes` must NOT (different
        // cipher + nonce width) — proving the migration reads old data
        // while steady-state code only speaks v1.
        let key = derive_key_legacy("old-passphrase");
        let cipher = ChaCha20Poly1305::new((&key).into());
        let mut nonce_bytes = [0u8; LEGACY_NONCE_LEN];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);
        let ct_inner = cipher.encrypt(nonce, b"v0 data".as_ref()).unwrap();
        let mut blob = nonce_bytes.to_vec();
        blob.extend_from_slice(&ct_inner);

        let rt = decrypt_bytes_legacy(&key, &blob).unwrap();
        assert_eq!(rt, b"v0 data");
        assert!(
            decrypt_bytes(&key, &blob, b"").is_err(),
            "v1 reader must reject v0 blob"
        );
    }

    #[test]
    fn historical_v0_kdf_vectors_match_shipped_implementations() {
        fn decode_key(hex: &str) -> [u8; 32] {
            let mut key = [0u8; 32];
            for (i, byte) in key.iter_mut().enumerate() {
                *byte = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).unwrap();
            }
            key
        }

        assert_eq!(
            derive_key_legacy_tagged("historical-pw"),
            decode_key("c2e2ba62ba0a02fa5aa27222728a1a9a8212cf2e127d68321f1fb78bf2a6c461")
        );
        assert_eq!(
            derive_key_legacy("historical-pw"),
            decode_key("3208ac0566b6a79f30369c5f6454795968de7e0f5a3ac765d802749d4424df67")
        );
    }

    #[test]
    fn kdf_load_or_create_is_stable() {
        let dir = std::path::PathBuf::from("target/test-kdf-stable");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let a = load_or_create_kdf(&dir).unwrap();
        let b = load_or_create_kdf(&dir).unwrap();
        assert_eq!(a.salt, b.salt, "second load must return the persisted salt");
        assert_eq!(a.format_version, FORMAT_VERSION);
        assert_eq!(a.salt.len(), SALT_LEN);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn kdf_io_does_not_follow_metadata_or_predictable_temp_symlinks() {
        use std::os::unix::fs::symlink;

        let root = std::path::PathBuf::from("target/test-kdf-symlinks");
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        let outside = root.join("outside");
        std::fs::create_dir_all(&outside).unwrap();
        let sentinel = outside.join("sentinel");
        std::fs::write(&sentinel, b"unchanged").unwrap();

        let save_dir = root.join("save");
        std::fs::create_dir_all(&save_dir).unwrap();
        symlink(&sentinel, save_dir.join("_kdf.json.tmp")).unwrap();
        save_kdf(&save_dir, &test_kdf()).unwrap();
        assert_eq!(std::fs::read(&sentinel).unwrap(), b"unchanged");

        let existing = std::fs::read(save_dir.join("_kdf.json")).unwrap();
        assert!(save_kdf(&save_dir, &KdfParams::new_random()).is_err());
        assert_eq!(std::fs::read(save_dir.join("_kdf.json")).unwrap(), existing);

        let load_dir = root.join("load");
        std::fs::create_dir_all(&load_dir).unwrap();
        symlink("../save/_kdf.json", load_dir.join("_kdf.json")).unwrap();
        assert!(load_kdf(&load_dir).is_err());

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn load_kdf_rejects_untrusted_metadata_before_derivation() {
        let dir = std::path::PathBuf::from("target/test-kdf-validation");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        let mut invalid = Vec::new();
        let mut value = test_kdf();
        value.format_version = FORMAT_VERSION + 1;
        invalid.push(value);
        let mut value = test_kdf();
        value.algorithm = "argon2i".to_string();
        invalid.push(value);
        let mut value = test_kdf();
        value.salt.pop();
        invalid.push(value);
        let mut value = test_kdf();
        value.m_cost = MAX_M_COST_KIB + 1;
        invalid.push(value);
        let mut value = test_kdf();
        value.t_cost = MAX_T_COST + 1;
        invalid.push(value);
        let mut value = test_kdf();
        value.p_cost = MAX_P_COST + 1;
        invalid.push(value);
        let mut value = test_kdf();
        value.m_cost = 1;
        invalid.push(value);

        for params in invalid {
            std::fs::write(kdf_path(&dir), serde_json::to_vec(&params).unwrap()).unwrap();
            assert!(
                load_kdf(&dir).is_err(),
                "invalid metadata must be rejected: {params:?}"
            );
        }

        std::fs::write(kdf_path(&dir), vec![b' '; MAX_KDF_FILE_LEN as usize + 1]).unwrap();
        assert!(load_kdf(&dir).unwrap_err().contains("unexpectedly large"));
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn short_ciphertext_is_rejected() {
        let key = derive_key("pw", &test_kdf());
        assert!(decrypt_bytes(&key, &[0u8; 10], b"").is_err());
        assert!(decrypt_bytes_legacy(&key, &[0u8; 5]).is_err());
    }
}
