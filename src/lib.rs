use aes_gcm::aead::rand_core::RngCore;
use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use argon2::{
    password_hash::{rand_core::OsRng, PasswordHasher, SaltString},
    Argon2,
};
use base64::{engine::general_purpose::STANDARD, Engine};
use std::fmt;

#[derive(Debug)]
pub struct EncryptionError(pub String);

impl fmt::Display for EncryptionError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Encryption error: {}", self.0)
    }
}

impl std::error::Error for EncryptionError {}

pub fn encrypt(password: &str, plaintext: &str) -> Result<String, EncryptionError> {
    let salt = SaltString::generate(&mut OsRng); // random salt

    let argon2 = Argon2::default(); // derive key
    let password_hash = argon2
        .hash_password(password.as_bytes(), &salt)
        .map_err(|e| EncryptionError(e.to_string()))?;

    let hash = password_hash.hash.unwrap(); // hash it
    let key = hash.as_bytes();

    let mut nonce_bytes = [0u8; 12]; // nonce bytes lol
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    // give me the cipher!
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|e| EncryptionError(e.to_string()))?;

    let ciphertext = cipher // encrypt plaintext
        .encrypt(nonce, plaintext.as_bytes())
        .map_err(|e| EncryptionError(e.to_string()))?;

    // stuff it all in a box and encode it as base64
    let mut combined = Vec::new();
    combined.extend_from_slice(salt.as_str().as_bytes());
    combined.extend_from_slice(&nonce_bytes);
    combined.extend_from_slice(&ciphertext);

    Ok(STANDARD.encode(combined))
}

pub fn decrypt(password: &str, encrypted: &str) -> Result<String, EncryptionError> {
    let combined = STANDARD // decode base64 input first
        .decode(encrypted)
        .map_err(|e| EncryptionError(e.to_string()))?;
    // extract salt (first 22 bytes), nonce, and cipher
    let salt_str =
        std::str::from_utf8(&combined[0..22]).map_err(|e| EncryptionError(e.to_string()))?;
    let salt = SaltString::from_b64(salt_str).map_err(|e| EncryptionError(e.to_string()))?;

    let nonce_bytes = &combined[22..34];
    let ciphertext = &combined[34..];

    let argon2 = Argon2::default();
    let password_hash = argon2
        .hash_password(password.as_bytes(), &salt)
        .map_err(|e| EncryptionError(e.to_string()))?;

    let hash = password_hash.hash.unwrap();
    let key = hash.as_bytes();

    let cipher = Aes256Gcm::new_from_slice(key).map_err(|e| EncryptionError(e.to_string()))?;

    // decrypt
    let plaintext = cipher
        .decrypt(Nonce::from_slice(nonce_bytes), ciphertext)
        .map_err(|e| EncryptionError(e.to_string()))?;

    String::from_utf8(plaintext).map_err(|e| EncryptionError(e.to_string()))
}

pub fn add(left: u64, right: u64) -> u64 {
    left + right
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_works() {
        let result = add(2, 2);
        assert_eq!(result, 4);
    }
}
