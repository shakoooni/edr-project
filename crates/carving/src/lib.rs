#![deny(unsafe_code)]
#![deny(missing_docs)]
//! Carving module: securely dumps high-risk memory regions.


use aes_gcm::{Aes256Gcm, Nonce};
use aes_gcm::aead::{Aead, KeyInit, generic_array::GenericArray};
use sha2::{Sha256, Digest};
use std::fs::File;
use std::io::{Write, Result as IoResult};
use rand::RngCore;

/// Encrypt and dump a memory region to disk using AES-GCM.
pub fn dump_encrypted_region(
    region_data: &[u8],
    out_path: &str,
    key_bytes: &[u8; 32],
) -> IoResult<()> {
    use smallvec::SmallVec;
    let key = GenericArray::from_slice(key_bytes);
    let cipher = Aes256Gcm::new(key);
    let mut nonce_bytes: SmallVec<[u8; 12]> = SmallVec::from_elem(0u8, 12);
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ciphertext = cipher.encrypt(nonce, region_data)
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::Other, "encryption failed"))?;
    let mut file = File::create(out_path)?;
    file.write_all(&nonce_bytes)?;
    file.write_all(&ciphertext)?;
    Ok(())
}

/// Generate a deterministic AES-256 key from a passphrase (SHA256).
pub fn key_from_passphrase(pass: &str) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(pass.as_bytes());
    hasher.finalize().into()
}
