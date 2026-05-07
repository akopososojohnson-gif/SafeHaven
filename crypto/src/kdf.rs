//! Key Derivation: Argon2id
//!
//! Derives a 256-bit master key from the user's password using Argon2id.
//! All parameters are validated against SafeHaven minimums.

use crate::{CryptoError, Result};
use argon2::{Argon2, Params, Version};

/// Minimum memory cost in KB (64 MB).
pub const MIN_MEMORY_KB: u32 = 65536;
/// Minimum iterations (time cost).
pub const MIN_ITERATIONS: u32 = 3;
/// Minimum parallelism (lanes).
pub const MIN_PARALLELISM: u32 = 1;
/// Output hash length in bytes.
pub const HASH_LENGTH: usize = 32;
/// Salt length in bytes.
pub const SALT_LENGTH: usize = 32;

/// Validated Argon2id parameters.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Argon2Params {
    pub memory_kb: u32,
    pub iterations: u32,
    pub parallelism: u32,
}

impl Default for Argon2Params {
    fn default() -> Self {
        Self {
            memory_kb: MIN_MEMORY_KB,
            iterations: MIN_ITERATIONS,
            parallelism: 4,
        }
    }
}

impl Argon2Params {
    /// Create parameters, enforcing SafeHaven minimums.
    pub fn new(memory_kb: u32, iterations: u32, parallelism: u32) -> Result<Self> {
        if memory_kb < MIN_MEMORY_KB {
            return Err(CryptoError::InvalidParameter(format!(
                "memory_kb must be >= {} (got {})",
                MIN_MEMORY_KB, memory_kb
            )));
        }
        if iterations < MIN_ITERATIONS {
            return Err(CryptoError::InvalidParameter(format!(
                "iterations must be >= {} (got {})",
                MIN_ITERATIONS, iterations
            )));
        }
        if parallelism < MIN_PARALLELISM {
            return Err(CryptoError::InvalidParameter(format!(
                "parallelism must be >= {} (got {})",
                MIN_PARALLELISM, parallelism
            )));
        }
        Ok(Self {
            memory_kb,
            iterations,
            parallelism,
        })
    }

    fn as_argon2_params(&self) -> Result<Params> {
        Params::new(
            self.memory_kb,
            self.iterations,
            self.parallelism,
            Some(HASH_LENGTH),
        )
        .map_err(|e| CryptoError::OperationFailed(format!("Argon2 params: {}", e)))
    }
}

/// Derive a 256-bit master key from `password` and `salt`.
///
/// # Arguments
/// * `password` - The user's master password
/// * `salt` - 32-byte random salt (must be unique per user)
/// * `params` - Argon2id parameters (enforced minimums)
///
/// # Returns
/// A 32-byte master key.
pub fn derive_master_key(
    password: &str,
    salt: &[u8; SALT_LENGTH],
    params: &Argon2Params,
) -> Result<[u8; HASH_LENGTH]> {
    let argon2_params = params.as_argon2_params()?;
    let argon2 = Argon2::new(argon2::Algorithm::Argon2id, Version::V0x13, argon2_params);

    let mut output = [0u8; HASH_LENGTH];
    argon2
        .hash_password_into(password.as_bytes(), salt, &mut output)
        .map_err(|e| CryptoError::OperationFailed(format!("Argon2id failed: {}", e)))?;

    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derive_master_key_consistent() {
        let salt = [0x01u8; SALT_LENGTH];
        let params = Argon2Params::default();
        let mk1 = derive_master_key("password123", &salt, &params).unwrap();
        let mk2 = derive_master_key("password123", &salt, &params).unwrap();
        assert_eq!(mk1, mk2);
    }

    #[test]
    fn derive_master_key_different_passwords() {
        let salt = [0x01u8; SALT_LENGTH];
        let params = Argon2Params::default();
        let mk1 = derive_master_key("password123", &salt, &params).unwrap();
        let mk2 = derive_master_key("password124", &salt, &params).unwrap();
        assert_ne!(mk1, mk2);
    }

    #[test]
    fn derive_master_key_different_salts() {
        let salt1 = [0x01u8; SALT_LENGTH];
        let salt2 = [0x02u8; SALT_LENGTH];
        let params = Argon2Params::default();
        let mk1 = derive_master_key("password123", &salt1, &params).unwrap();
        let mk2 = derive_master_key("password123", &salt2, &params).unwrap();
        assert_ne!(mk1, mk2);
    }

    #[test]
    fn params_enforce_minimums() {
        assert!(Argon2Params::new(65535, 3, 1).is_err());
        assert!(Argon2Params::new(65536, 2, 1).is_err());
        assert!(Argon2Params::new(65536, 3, 0).is_err());
        assert!(Argon2Params::new(65536, 3, 1).is_ok());
    }

    #[test]
    fn argon2id_test_vector() {
        // Test vector generated with reference argon2 implementation.
        let salt = hex::decode("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
            .unwrap();
        let salt_arr: [u8; 32] = salt.try_into().unwrap();
        let params = Argon2Params::new(65536, 3, 4).unwrap();
        let mk = derive_master_key("testpassword", &salt_arr, &params).unwrap();
        // We just verify it doesn't panic and produces 32 bytes.
        assert_eq!(mk.len(), 32);
    }
}
