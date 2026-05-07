//! SafeHaven Cryptographic Core
//!
//! Implements the foundational cryptography for SafeHaven:
//! - Argon2id key derivation
//! - AES-256-GCM authenticated encryption
//! - Schnorr zero-knowledge proofs over Ristretto255
//! - Secure memory handling (mlock, zeroize, MADV_DONTDUMP)
//! - Key hierarchy via HKDF-SHA256

pub mod cipher;
pub mod hash;
pub mod kdf;
pub mod keys;
pub mod memory;
pub mod share;
pub mod zkp;

#[cfg(feature = "wasm")]
pub mod wasm;

use thiserror::Error;

/// Unified error type for all crypto operations.
#[derive(Error, Debug, Clone, PartialEq, Eq)]
pub enum CryptoError {
    #[error("invalid length: expected {expected}, got {got}")]
    InvalidLength { expected: usize, got: usize },

    #[error("cryptographic operation failed: {0}")]
    OperationFailed(String),

    #[error("authentication failed (bad tag or corrupt data)")]
    AuthenticationFailed,

    #[error("invalid parameter: {0}")]
    InvalidParameter(String),

    #[error("zero-knowledge proof verification failed")]
    ZkpVerificationFailed,

    #[error("secure memory allocation failed")]
    MemoryAllocationFailed,
}

/// Convenience result type.
pub type Result<T> = std::result::Result<T, CryptoError>;

/// Constant-time comparison of two byte slices.
///
/// Returns `true` if the slices are equal. Timing does not depend on the
/// content of the slices (only on their length).
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    use sha2::Sha256;
    use hmac::{Hmac, Mac};

    // If lengths differ, still do work on dummy data to avoid timing leak.
    let len = a.len().max(b.len());
    if len == 0 {
        return a.len() == b.len();
    }

    let dummy = vec![0u8; len];
    let a_padded = if a.len() == len { a } else { &dummy };
    let b_padded = if b.len() == len { b } else { &dummy };

    // Use HMAC as a constant-time comparison primitive.
    type HmacSha256 = Hmac<Sha256>;
    let mut mac_a =
        HmacSha256::new_from_slice(&[0u8; 32]).expect("HMAC key is valid length");
    mac_a.update(a_padded);
    let mut mac_b =
        HmacSha256::new_from_slice(&[0u8; 32]).expect("HMAC key is valid length");
    mac_b.update(b_padded);

    let result = mac_a.finalize().into_bytes() == mac_b.finalize().into_bytes();

    // If lengths actually differ, force false (but only after doing the work above).
    (a.len() == b.len()) && result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn constant_time_eq_matches() {
        assert!(constant_time_eq(b"hello", b"hello"));
        assert!(!constant_time_eq(b"hello", b"world"));
        assert!(!constant_time_eq(b"hi", b"hello"));
        assert!(!constant_time_eq(b"", b"x"));
        assert!(constant_time_eq(b"", b""));
    }
}
