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
use chacha20poly1305::{
    ChaCha20Poly1305, Nonce, XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit, OsRng, Payload, rand_core::RngCore},
};
use serde::{Deserialize, Serialize};

/// On-disk format version recorded in `_kdf.json`. Bump only on a
/// breaking change to the KDF or AEAD; the presence/absence of
/// `_kdf.json` is what distinguishes v1 from v0.
pub const FORMAT_VERSION: u32 = 1;

/// Argon2id salt length. 16 bytes is well above Argon2's 8-byte
/// minimum and matches common practice.
pub const SALT_LEN: usize = 16;

/// XChaCha20-Poly1305 extended nonce length (192-bit).
const XNONCE_LEN: usize = 24;

/// Legacy (v0) ChaCha20-Poly1305 nonce length (96-bit).
const LEGACY_NONCE_LEN: usize = 12;

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
}

/// Path to the per-drive KDF metadata file.
pub fn kdf_path(base_path: &std::path::Path) -> std::path::PathBuf {
    base_path.join("_kdf.json")
}

/// Read `_kdf.json` if present. `Ok(None)` means the drive has no KDF
/// file — i.e. it is brand-new or a pre-0.7 (v0) drive.
pub fn load_kdf(base_path: &std::path::Path) -> Result<Option<KdfParams>, String> {
    let path = kdf_path(base_path);
    if !path.exists() {
        return Ok(None);
    }
    let bytes = std::fs::read(&path).map_err(|e| format!("read {}: {e}", path.display()))?;
    let params: KdfParams =
        serde_json::from_slice(&bytes).map_err(|e| format!("parse {}: {e}", path.display()))?;
    Ok(Some(params))
}

/// Persist KDF params with an atomic temp-write + rename + parent
/// fsync. Inlined here (rather than reusing `fs::durable_write`) to
/// avoid a crypto→fs dependency direction.
pub fn save_kdf(base_path: &std::path::Path, params: &KdfParams) -> Result<(), String> {
    use std::io::Write;
    let path = kdf_path(base_path);
    let json = serde_json::to_vec_pretty(params).map_err(|e| e.to_string())?;
    let tmp = path.with_extension("json.tmp");
    let mut f = std::fs::File::create(&tmp).map_err(|e| format!("create {}: {e}", tmp.display()))?;
    f.write_all(&json).map_err(|e| e.to_string())?;
    f.sync_all().map_err(|e| e.to_string())?;
    std::fs::rename(&tmp, &path).map_err(|e| e.to_string())?;
    if let Ok(dir) = std::fs::File::open(base_path) {
        let _ = dir.sync_all();
    }
    Ok(())
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
    if let Some(p) = load_kdf(base_path)? {
        return Ok(p);
    }
    let params = KdfParams::new_random();
    save_kdf(base_path, &params)?;
    Ok(params)
}

/// Derive a 256-bit key from a passphrase with Argon2id, using the
/// drive's stored salt and cost parameters. Memory-hard — the primary
/// defense against offline passphrase guessing against the blobs.
pub fn derive_key(passphrase: &str, kdf: &KdfParams) -> [u8; 32] {
    let params = Params::new(kdf.m_cost, kdf.t_cost, kdf.p_cost, Some(32))
        .expect("argon2 params invalid");
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key = [0u8; 32];
    argon2
        .hash_password_into(passphrase.as_bytes(), &kdf.salt, &mut key)
        .expect("argon2 key derivation failed");
    key
}

/// Convenience: load (or create) the drive's KDF params and derive the
/// key in one call. Used by the FUSE layer, rekey, and tests.
pub fn derive_key_at(base_path: &std::path::Path, passphrase: &str) -> [u8; 32] {
    let kdf = load_or_create_kdf(base_path).expect("failed to load/create KDF params");
    derive_key(passphrase, &kdf)
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
    let cipher = XChaCha20Poly1305::new(key.into());
    let mut nonce_bytes = [0u8; XNONCE_LEN];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = XNonce::from_slice(&nonce_bytes);
    let ciphertext = cipher
        .encrypt(nonce, Payload { msg: plaintext, aad })
        .map_err(|e| e.to_string())?;
    let mut out = Vec::with_capacity(XNONCE_LEN + ciphertext.len());
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

/// Low-level: decrypt v1 XChaCha20-Poly1305 with the given AAD — first 24
/// bytes are the nonce. Fails if the AAD does not match the one used to
/// encrypt.
pub fn decrypt_bytes(key: &[u8; 32], data: &[u8], aad: &[u8]) -> Result<Vec<u8>, String> {
    if data.len() < XNONCE_LEN {
        return Err("ciphertext too short".to_string());
    }
    let cipher = XChaCha20Poly1305::new(key.into());
    let nonce = XNonce::from_slice(&data[..XNONCE_LEN]);
    cipher
        .decrypt(nonce, Payload { msg: &data[XNONCE_LEN..], aad })
        .map_err(|e| e.to_string())
}

/// Encrypt a data blob, binding it to its on-disk filename via AAD.
pub fn encrypt_blob(key: &[u8; 32], disk_filename: &str, plaintext: &[u8]) -> Result<Vec<u8>, String> {
    encrypt_bytes(key, plaintext, &blob_aad(disk_filename))
}

/// Decrypt a data blob; fails if `disk_filename` does not match the name it
/// was encrypted under (i.e. the blob was moved/swapped on disk).
pub fn decrypt_blob(key: &[u8; 32], disk_filename: &str, data: &[u8]) -> Result<Vec<u8>, String> {
    decrypt_bytes(key, data, &blob_aad(disk_filename))
}

/// Encrypt the directory index, bound to the index domain tag.
pub fn encrypt_index(key: &[u8; 32], plaintext: &[u8]) -> Result<Vec<u8>, String> {
    encrypt_bytes(key, plaintext, &index_aad())
}

/// Decrypt the directory index.
pub fn decrypt_index(key: &[u8; 32], data: &[u8]) -> Result<Vec<u8>, String> {
    decrypt_bytes(key, data, &index_aad())
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
        assert!(decrypt_bytes(&key, &blob, b"").is_err(), "v1 reader must reject v0 blob");
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

    #[test]
    fn short_ciphertext_is_rejected() {
        let key = derive_key("pw", &test_kdf());
        assert!(decrypt_bytes(&key, &[0u8; 10], b"").is_err());
        assert!(decrypt_bytes_legacy(&key, &[0u8; 5]).is_err());
    }
}
