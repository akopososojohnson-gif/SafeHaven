//! Key hierarchy derivation via HKDF-SHA256.
//!
//! From the 256-bit Master Key (MK), derives:
//! - Auth Key (32 bytes)   → login credential
//! - KEK (32 bytes)        → encrypts the Vault Key
//! - ZKP Scalar (32 bytes) → Schnorr private key

use crate::{CryptoError, Result};
use hkdf::Hkdf;
use sha2::Sha256;

/// Domain separator for authentication key derivation.
pub const AUTH_KEY_INFO: &[u8] = b"safehaven-auth-v1";
/// Domain separator for Key Encryption Key derivation.
pub const KEK_INFO: &[u8] = b"safehaven-kek-v1";
/// Domain separator for ZKP private key derivation.
pub const ZKP_KEY_INFO: &[u8] = b"safehaven-zkp-v1";
/// Domain separator for item key wrapping.
pub const ITEM_KEY_WRAP_INFO: &[u8] = b"item-key-wrap-v1";
/// Domain separator for search name HMAC.
pub const SEARCH_KEY_INFO: &[u8] = b"safehaven-search-v1";

/// Subkeys derived from the Master Key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubKeys {
    pub auth_key: [u8; 32],
    pub kek: [u8; 32],
    pub zkp_scalar: [u8; 32],
}

/// Derive the three main subkeys from a 32-byte master key.
pub fn derive_subkeys(master_key: &[u8; 32]) -> Result<SubKeys> {
    let hkdf = Hkdf::<Sha256>::new(None, master_key);

    let mut auth_key = [0u8; 32];
    hkdf.expand(AUTH_KEY_INFO, &mut auth_key)
        .map_err(|e| CryptoError::OperationFailed(format!("HKDF expand auth_key failed: {}", e)))?;

    let mut kek = [0u8; 32];
    hkdf.expand(KEK_INFO, &mut kek)
        .map_err(|e| CryptoError::OperationFailed(format!("HKDF expand kek failed: {}", e)))?;

    let mut zkp_scalar = [0u8; 32];
    hkdf.expand(ZKP_KEY_INFO, &mut zkp_scalar)
        .map_err(|e| CryptoError::OperationFailed(format!("HKDF expand zkp_scalar failed: {}", e)))?;

    Ok(SubKeys {
        auth_key,
        kek,
        zkp_scalar,
    })
}

/// Derive a search HMAC key from the master key.
pub fn derive_search_key(master_key: &[u8; 32]) -> Result<[u8; 32]> {
    let hkdf = Hkdf::<Sha256>::new(None, master_key);
    let mut key = [0u8; 32];
    hkdf.expand(SEARCH_KEY_INFO, &mut key)
        .map_err(|e| CryptoError::OperationFailed(format!("HKDF expand search_key failed: {}", e)))?;
    Ok(key)
}

/// Derive a domain-specific key from the vault key.
pub fn derive_vault_key(vault_key: &[u8; 32], info: &[u8]) -> Result<[u8; 32]> {
    let hkdf = Hkdf::<Sha256>::new(None, vault_key);
    let mut key = [0u8; 32];
    hkdf.expand(info, &mut key)
        .map_err(|e| CryptoError::OperationFailed(format!("HKDF expand failed: {}", e)))?;
    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn subkeys_deterministic() {
        let mk = [0xABu8; 32];
        let sk1 = derive_subkeys(&mk).unwrap();
        let sk2 = derive_subkeys(&mk).unwrap();
        assert_eq!(sk1.auth_key, sk2.auth_key);
        assert_eq!(sk1.kek, sk2.kek);
        assert_eq!(sk1.zkp_scalar, sk2.zkp_scalar);
    }

    #[test]
    fn subkeys_different_mks() {
        let mk1 = [0xABu8; 32];
        let mk2 = [0xACu8; 32];
        let sk1 = derive_subkeys(&mk1).unwrap();
        let sk2 = derive_subkeys(&mk2).unwrap();
        assert_ne!(sk1.auth_key, sk2.auth_key);
        assert_ne!(sk1.kek, sk2.kek);
        assert_ne!(sk1.zkp_scalar, sk2.zkp_scalar);
    }

    #[test]
    fn subkeys_are_distinct() {
        let mk = [0xABu8; 32];
        let sk = derive_subkeys(&mk).unwrap();
        assert_ne!(sk.auth_key, sk.kek);
        assert_ne!(sk.auth_key, sk.zkp_scalar);
        assert_ne!(sk.kek, sk.zkp_scalar);
    }

    #[test]
    fn search_key_deterministic() {
        let mk = [0xABu8; 32];
        let k1 = derive_search_key(&mk).unwrap();
        let k2 = derive_search_key(&mk).unwrap();
        assert_eq!(k1, k2);
    }

    #[test]
    fn search_key_different_from_subkeys() {
        let mk = [0xABu8; 32];
        let sk = derive_subkeys(&mk).unwrap();
        let search = derive_search_key(&mk).unwrap();
        assert_ne!(search, sk.auth_key);
        assert_ne!(search, sk.kek);
        assert_ne!(search, sk.zkp_scalar);
    }
}
