//! Hashing utilities: SHA-256 and HMAC-SHA256.

use hmac::{Hmac, Mac};
use sha2::{Sha256, Digest};

/// Compute SHA-256 of the input.
pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().into()
}

/// Compute HMAC-SHA256 with the given key and data.
pub fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    type HmacSha256 = Hmac<Sha256>;
    let mut mac = HmacSha256::new_from_slice(key)
        .expect("HMAC accepts any key length");
    mac.update(data);
    mac.finalize().into_bytes().into()
}

/// Compute HMAC-SHA256 with a fixed-size key.
pub fn hmac_sha256_keyed(key: &[u8; 32], data: &[u8]) -> [u8; 32] {
    hmac_sha256(key, data)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha256_known_vector() {
        let input = b"abc";
        let expected = hex::decode("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad").unwrap();
        assert_eq!(sha256(input).to_vec(), expected);
    }

    #[test]
    fn hmac_sha256_known_vector() {
        let key = b"key";
        let data = b"The quick brown fox jumps over the lazy dog";
        let result = hmac_sha256(key, data);
        // Verified against Python hmac module
        let expected = hex::decode("f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8").unwrap();
        assert_eq!(result.to_vec(), expected);
    }
}
