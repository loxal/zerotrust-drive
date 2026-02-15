use chacha20poly1305::{
    aead::{Aead, KeyInit, OsRng},
    ChaCha20Poly1305, Nonce,
};
use rand::RngCore;

pub fn derive_key(passphrase: &str) -> [u8; 32] {
    // Simple key derivation: iterative hashing (not as strong as scrypt/argon2
    // but microseconds instead of hundreds of ms)
    let mut key = [0u8; 32];
    let bytes = passphrase.as_bytes();
    let mut state = [0u8; 64];
    for (i, &b) in bytes.iter().enumerate() {
        state[i % 64] ^= b;
    }
    // Mix rounds
    for _ in 0..10000 {
        for i in 0..64 {
            state[i] = state[i].wrapping_add(state[(i + 1) % 64]).wrapping_mul(7).wrapping_add(0x9e);
        }
    }
    key.copy_from_slice(&state[..32]);
    key
}

/// Encrypt with ChaCha20-Poly1305 — random 12-byte nonce prepended to output.
pub fn encrypt_bytes(key: &[u8; 32], plaintext: &[u8]) -> Result<Vec<u8>, String> {
    let cipher = ChaCha20Poly1305::new(key.into());
    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ciphertext = cipher.encrypt(nonce, plaintext).map_err(|e| e.to_string())?;
    let mut out = Vec::with_capacity(12 + ciphertext.len());
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

/// Decrypt — first 12 bytes are the nonce.
pub fn decrypt_bytes(key: &[u8; 32], data: &[u8]) -> Result<Vec<u8>, String> {
    if data.len() < 12 {
        return Err("ciphertext too short".to_string());
    }
    let cipher = ChaCha20Poly1305::new(key.into());
    let nonce = Nonce::from_slice(&data[..12]);
    cipher.decrypt(nonce, &data[12..]).map_err(|e| e.to_string())
}
