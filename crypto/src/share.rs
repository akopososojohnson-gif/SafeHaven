//! Time-bound share link encryption.
//!
//! Items are re-encrypted with a random 256-bit Share Key (SK).
//! The server only sees the encrypted blob; SK never leaves the client.

use crate::cipher;
use crate::cipher::{Ciphertext, KEY_LENGTH};
use crate::Result;
use rand::RngCore;

/// Length of a share key in bytes.
pub const SHARE_KEY_LENGTH: usize = KEY_LENGTH;

/// Generate a random 256-bit Share Key.
pub fn generate_share_key() -> [u8; SHARE_KEY_LENGTH] {
    let mut key = [0u8; SHARE_KEY_LENGTH];
    rand::thread_rng().fill_bytes(&mut key);
    key
}

/// Re-encrypt an already-encrypted vault item with a share key.
///
/// # Arguments
/// * `share_key` - 32-byte share key
/// * `plaintext` - The decrypted item data (compressed JSON)
/// * `aad` - Additional authenticated data (e.g., share_id or context)
///
/// # Returns
/// A `Ciphertext` containing the encrypted share data.
pub fn encrypt_with_share_key(
    share_key: &[u8; SHARE_KEY_LENGTH],
    plaintext: &[u8],
    aad: Option<&[u8]>,
) -> Result<Ciphertext> {
    cipher::encrypt(share_key, plaintext, aad)
}

/// Decrypt a share blob with the share key.
///
/// # Arguments
/// * `share_key` - 32-byte share key
/// * `ct` - The ciphertext from the server
/// * `aad` - Additional authenticated data (must match encryption)
///
/// # Returns
/// The decrypted plaintext.
pub fn decrypt_with_share_key(
    share_key: &[u8; SHARE_KEY_LENGTH],
    ct: &Ciphertext,
    aad: Option<&[u8]>,
) -> Result<Vec<u8>> {
    cipher::decrypt(share_key, ct, aad)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn share_key_generation_unique() {
        let k1 = generate_share_key();
        let k2 = generate_share_key();
        assert_ne!(k1, k2);
    }

    #[test]
    fn share_encryption_roundtrip() {
        let key = generate_share_key();
        let data = b"shared secret password entry";
        let aad = b"share-context-123";
        let ct = encrypt_with_share_key(&key, data, Some(aad)).unwrap();
        let decrypted = decrypt_with_share_key(&key, &ct, Some(aad)).unwrap();
        assert_eq!(data.as_slice(), decrypted.as_slice());
    }

    #[test]
    fn share_wrong_key_fails() {
        let key = generate_share_key();
        let wrong_key = generate_share_key();
        let data = b"shared secret";
        let ct = encrypt_with_share_key(&key, data, None).unwrap();
        assert!(decrypt_with_share_key(&wrong_key, &ct, None).is_err());
    }
}
