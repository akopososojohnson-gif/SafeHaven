//! AES-256-GCM authenticated encryption.
//!
//! Provides encrypt/decrypt with:
//! - Random 12-byte IV (CSPRNG)
//! - Optional AAD (Additional Authenticated Data)
//! - 16-byte auth tag

use crate::{CryptoError, Result};
use aes_gcm::{
    aead::{Aead, KeyInit, Payload},
    Aes256Gcm, Key, Nonce,
};
use rand::RngCore;

/// Length of the AES-256-GCM authentication tag in bytes.
pub const TAG_LENGTH: usize = 16;
/// Length of the AES-256-GCM IV/nonce in bytes.
pub const IV_LENGTH: usize = 12;
/// Length of the AES-256 key in bytes.
pub const KEY_LENGTH: usize = 32;

/// Encrypted output containing all components needed for decryption.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ciphertext {
    pub iv: [u8; IV_LENGTH],
    pub ciphertext: Vec<u8>,
    pub tag: [u8; TAG_LENGTH],
}

impl Ciphertext {
    /// Serialize to `[iv || ciphertext || tag]`.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(IV_LENGTH + self.ciphertext.len() + TAG_LENGTH);
        out.extend_from_slice(&self.iv);
        out.extend_from_slice(&self.ciphertext);
        out.extend_from_slice(&self.tag);
        out
    }

    /// Deserialize from `[iv || ciphertext || tag]`.
    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        if data.len() < IV_LENGTH + TAG_LENGTH {
            return Err(CryptoError::InvalidLength {
                expected: IV_LENGTH + TAG_LENGTH,
                got: data.len(),
            });
        }
        let mut iv = [0u8; IV_LENGTH];
        iv.copy_from_slice(&data[..IV_LENGTH]);
        let mut tag = [0u8; TAG_LENGTH];
        tag.copy_from_slice(&data[data.len() - TAG_LENGTH..]);
        let ciphertext = data[IV_LENGTH..data.len() - TAG_LENGTH].to_vec();
        Ok(Ciphertext {
            iv,
            ciphertext,
            tag,
        })
    }
}

/// Encrypt `plaintext` with AES-256-GCM.
///
/// # Arguments
/// * `key` - 32-byte encryption key
/// * `plaintext` - Data to encrypt
/// * `aad` - Optional additional authenticated data
///
/// # Returns
/// A `Ciphertext` struct containing IV, ciphertext, and tag.
pub fn encrypt(key: &[u8; KEY_LENGTH], plaintext: &[u8], aad: Option<&[u8]>) -> Result<Ciphertext> {
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));

    let mut iv = [0u8; IV_LENGTH];
    rand::thread_rng().fill_bytes(&mut iv);
    let nonce = Nonce::from_slice(&iv);

    let payload = Payload {
        msg: plaintext,
        aad: aad.unwrap_or(&[]),
    };

    let mut encrypted = cipher
        .encrypt(nonce, payload)
        .map_err(|e| CryptoError::OperationFailed(format!("Encryption failed: {}", e)))?;

    // aes-gcm returns ciphertext || tag
    if encrypted.len() < TAG_LENGTH {
        return Err(CryptoError::OperationFailed(
            "Encryption output too short".into(),
        ));
    }

    let mut tag = [0u8; TAG_LENGTH];
    let ct_len = encrypted.len() - TAG_LENGTH;
    tag.copy_from_slice(&encrypted[ct_len..]);
    encrypted.truncate(ct_len);

    Ok(Ciphertext {
        iv,
        ciphertext: encrypted,
        tag,
    })
}

/// Decrypt a `Ciphertext` with AES-256-GCM.
///
/// # Arguments
/// * `key` - 32-byte encryption key
/// * `ct` - The ciphertext struct
/// * `aad` - Optional additional authenticated data (must match encryption)
///
/// # Returns
/// The decrypted plaintext, or `AuthenticationFailed` if the tag is invalid.
pub fn decrypt(
    key: &[u8; KEY_LENGTH],
    ct: &Ciphertext,
    aad: Option<&[u8]>,
) -> Result<Vec<u8>> {
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    let nonce = Nonce::from_slice(&ct.iv);

    // Reconstruct ciphertext || tag
    let mut payload = Vec::with_capacity(ct.ciphertext.len() + TAG_LENGTH);
    payload.extend_from_slice(&ct.ciphertext);
    payload.extend_from_slice(&ct.tag);

    let payload = Payload {
        msg: &payload,
        aad: aad.unwrap_or(&[]),
    };

    cipher
        .decrypt(nonce, payload)
        .map_err(|_| CryptoError::AuthenticationFailed)
}

/// Convenience: decrypt from raw bytes `[iv || ciphertext || tag]`.
pub fn decrypt_bytes(
    key: &[u8; KEY_LENGTH],
    data: &[u8],
    aad: Option<&[u8]>,
) -> Result<Vec<u8>> {
    let ct = Ciphertext::from_bytes(data)?;
    decrypt(key, &ct, aad)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_basic() {
        let key = [0x42u8; 32];
        let plaintext = b"Hello, SafeHaven!";
        let ct = encrypt(&key, plaintext, None).unwrap();
        let decrypted = decrypt(&key, &ct, None).unwrap();
        assert_eq!(plaintext.as_slice(), decrypted.as_slice());
    }

    #[test]
    fn roundtrip_with_aad() {
        let key = [0x42u8; 32];
        let plaintext = b"secret data";
        let aad = b"user_id:12345";
        let ct = encrypt(&key, plaintext, Some(aad)).unwrap();
        let decrypted = decrypt(&key, &ct, Some(aad)).unwrap();
        assert_eq!(plaintext.as_slice(), decrypted.as_slice());
    }

    #[test]
    fn tampered_ciphertext_fails() {
        let key = [0x42u8; 32];
        let plaintext = b"secret data";
        let mut ct = encrypt(&key, plaintext, None).unwrap();
        ct.ciphertext[0] ^= 0xFF;
        assert!(matches!(decrypt(&key, &ct, None), Err(CryptoError::AuthenticationFailed)));
    }

    #[test]
    fn wrong_aad_fails() {
        let key = [0x42u8; 32];
        let plaintext = b"secret data";
        let ct = encrypt(&key, plaintext, Some(b"correct aad")).unwrap();
        assert!(matches!(
            decrypt(&key, &ct, Some(b"wrong aad")),
            Err(CryptoError::AuthenticationFailed)
        ));
    }

    #[test]
    fn serialization_roundtrip() {
        let key = [0x42u8; 32];
        let plaintext = b"serialization test";
        let ct = encrypt(&key, plaintext, None).unwrap();
        let bytes = ct.to_bytes();
        let ct2 = Ciphertext::from_bytes(&bytes).unwrap();
        let decrypted = decrypt(&key, &ct2, None).unwrap();
        assert_eq!(plaintext.as_slice(), decrypted.as_slice());
    }
}
