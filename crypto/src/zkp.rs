//! Schnorr Zero-Knowledge Proof over Ristretto255.
//!
//! Implements the Schnorr identification protocol:
//! - Prover knows private scalar `x`
//! - Verifier knows public point `Y = x * G`
//! - Prover proves knowledge of `x` without revealing it.

use crate::{CryptoError, Result};
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use rand::rngs::OsRng;
use sha2::{Sha256, Digest};

/// A Schnorr ZKP keypair.
#[derive(Debug, Clone)]
pub struct ZkpKeypair {
    /// Private scalar x ∈ Z_q (derived from master key).
    pub private: Scalar,
    /// Public point Y = x * G.
    pub public: RistrettoPoint,
}

impl ZkpKeypair {
    /// Create a keypair from a 32-byte seed (the `zkp_scalar` from HKDF).
    ///
    /// The seed is reduced modulo the group order to produce a valid scalar.
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        let private = Scalar::from_bytes_mod_order(*seed);
        let public = private * RISTRETTO_BASEPOINT_POINT;
        ZkpKeypair { private, public }
    }

    /// Generate a fresh random keypair.
    pub fn generate() -> Self {
        let mut rng = OsRng;
        let private = Scalar::random(&mut rng);
        let public = private * RISTRETTO_BASEPOINT_POINT;
        ZkpKeypair { private, public }
    }

    /// Serialize the public key to 32 bytes.
    pub fn public_key_bytes(&self) -> [u8; 32] {
        self.public.compress().to_bytes()
    }
}

/// A Schnorr proof: (T, s) where T = r*G and s = r + C*x.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SchnorrProof {
    pub t: [u8; 32], // Compressed Ristretto point T
    pub s: [u8; 32], // Scalar s
}

/// A challenge issued by the verifier.
#[derive(Debug, Clone)]
pub struct Challenge {
    pub scalar: Scalar,
}

impl Challenge {
    /// Generate a random challenge.
    pub fn random() -> Self {
        let mut rng = OsRng;
        Self {
            scalar: Scalar::random(&mut rng),
        }
    }

    /// Create a challenge from 32 bytes (reduced modulo q).
    pub fn from_bytes(bytes: &[u8; 32]) -> Self {
        Self {
            scalar: Scalar::from_bytes_mod_order(*bytes),
        }
    }

    pub fn to_bytes(&self) -> [u8; 32] {
        self.scalar.to_bytes()
    }
}

/// Generate a Schnorr proof for the given challenge.
///
/// # Arguments
/// * `keypair` - The prover's keypair
/// * `challenge` - The verifier's challenge scalar
///
/// # Returns
/// A `SchnorrProof` that can be sent to the verifier.
pub fn prove(keypair: &ZkpKeypair, challenge: &Challenge) -> SchnorrProof {
    let mut rng = OsRng;
    let r = Scalar::random(&mut rng);
    let t_point = r * RISTRETTO_BASEPOINT_POINT;
    let s = r + challenge.scalar * keypair.private;

    SchnorrProof {
        t: t_point.compress().to_bytes(),
        s: s.to_bytes(),
    }
}

/// Verify a Schnorr proof.
///
/// # Arguments
/// * `public_key` - The prover's public key Y (32 bytes, compressed Ristretto)
/// * `challenge` - The challenge scalar that was issued
/// * `proof` - The proof (T, s) received from the prover
///
/// # Returns
/// `Ok(())` if the proof is valid, `Err(ZkpVerificationFailed)` otherwise.
pub fn verify(public_key_bytes: &[u8; 32], challenge: &Challenge, proof: &SchnorrProof) -> Result<()> {
    let y = CompressedRistretto::from_slice(public_key_bytes)
        .map_err(|_| CryptoError::InvalidParameter("invalid public key encoding".into()))?
        .decompress()
        .ok_or_else(|| CryptoError::InvalidParameter("invalid public key point".into()))?;

    let t = CompressedRistretto::from_slice(&proof.t)
        .map_err(|_| CryptoError::InvalidParameter("invalid proof T encoding".into()))?
        .decompress()
        .ok_or_else(|| CryptoError::InvalidParameter("invalid proof T point".into()))?;

    let s: Option<Scalar> = Scalar::from_canonical_bytes(proof.s).into();
    let s = s.ok_or_else(|| CryptoError::InvalidParameter("invalid proof scalar s".into()))?;

    // Verify: s * G == T + C * Y
    let lhs = s * RISTRETTO_BASEPOINT_POINT;
    let rhs = t + challenge.scalar * y;

    if lhs == rhs {
        Ok(())
    } else {
        Err(CryptoError::ZkpVerificationFailed)
    }
}

/// Deterministically derive a challenge from context data (for testing / non-interactive).
/// Uses Fiat-Shamir heuristic with SHA-256.
pub fn derive_challenge(context: &[u8]) -> Challenge {
    let mut hasher = Sha256::new();
    hasher.update(b"safehaven-zkp-challenge-v1");
    hasher.update(context);
    let bytes: [u8; 32] = hasher.finalize().into();
    Challenge::from_bytes(&bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prove_verify_roundtrip() {
        let keypair = ZkpKeypair::generate();
        let challenge = Challenge::random();
        let proof = prove(&keypair, &challenge);
        let pk = keypair.public_key_bytes();
        assert!(verify(&pk, &challenge, &proof).is_ok());
    }

    #[test]
    fn verify_fails_wrong_challenge() {
        let keypair = ZkpKeypair::generate();
        let challenge = Challenge::random();
        let proof = prove(&keypair, &challenge);
        let wrong_challenge = Challenge::random();
        let pk = keypair.public_key_bytes();
        assert!(matches!(
            verify(&pk, &wrong_challenge, &proof),
            Err(CryptoError::ZkpVerificationFailed)
        ));
    }

    #[test]
    fn verify_fails_wrong_key() {
        let keypair = ZkpKeypair::generate();
        let wrong_keypair = ZkpKeypair::generate();
        let challenge = Challenge::random();
        let proof = prove(&keypair, &challenge);
        let wrong_pk = wrong_keypair.public_key_bytes();
        assert!(matches!(
            verify(&wrong_pk, &challenge, &proof),
            Err(CryptoError::ZkpVerificationFailed)
        ));
    }

    #[test]
    fn from_seed_deterministic() {
        let seed = [0x01u8; 32];
        let kp1 = ZkpKeypair::from_seed(&seed);
        let kp2 = ZkpKeypair::from_seed(&seed);
        assert_eq!(kp1.public_key_bytes(), kp2.public_key_bytes());
        assert_eq!(kp1.private.to_bytes(), kp2.private.to_bytes());
    }

    #[test]
    fn public_key_serializes_to_32_bytes() {
        let keypair = ZkpKeypair::generate();
        let pk = keypair.public_key_bytes();
        assert_eq!(pk.len(), 32);
    }

    #[test]
    fn invalid_public_key_rejected() {
        let pk = [0xFFu8; 32]; // Invalid compressed Ristretto encoding
        let challenge = Challenge::random();
        let proof = SchnorrProof {
            t: RistrettoPoint::default().compress().to_bytes(),
            s: Scalar::ZERO.to_bytes(),
        };
        assert!(verify(&pk, &challenge, &proof).is_err());
    }
}
