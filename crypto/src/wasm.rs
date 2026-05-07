//! WASM bindings for SafeHaven cryptographic core.
//!
//! These functions are exposed to JavaScript/TypeScript via wasm-bindgen.

use wasm_bindgen::prelude::*;
use js_sys::Uint8Array;

/// Derive a master key from password and salt using Argon2id with default params.
///
/// # Arguments
/// * `password` - User's master password
/// * `salt` - 32-byte salt
///
/// # Returns
/// 32-byte master key
#[wasm_bindgen]
pub fn derive_master_key(password: &str, salt: &[u8]) -> Result<Uint8Array, JsValue> {
    if salt.len() != 32 {
        return Err(JsValue::from_str("salt must be 32 bytes"));
    }
    let salt_arr: [u8; 32] = salt.try_into().map_err(|_| "salt must be 32 bytes")?;
    let params = crate::kdf::Argon2Params::default();
    let mk = crate::kdf::derive_master_key(password, &salt_arr, &params)
        .map_err(|e| JsValue::from_str(&format!("{:?}", e)))?;
    Ok(Uint8Array::from(&mk[..]))
}

/// Derive subkeys from master key using HKDF-SHA256.
///
/// # Arguments
/// * `master_key` - 32-byte master key
///
/// # Returns
/// Object with auth_key, kek, zkp_scalar fields
#[wasm_bindgen]
pub fn derive_subkeys(master_key: &[u8]) -> Result<JsValue, JsValue> {
    if master_key.len() != 32 {
        return Err(JsValue::from_str("master_key must be 32 bytes"));
    }
    let mk: [u8; 32] = master_key.try_into().map_err(|_| "master_key must be 32 bytes")?;
    let keys = crate::keys::derive_subkeys(&mk)
        .map_err(|e| JsValue::from_str(&format!("{:?}", e)))?;

    let obj = js_sys::Object::new();
    js_sys::Reflect::set(&obj, &"auth_key".into(), &Uint8Array::from(&keys.auth_key[..]))?;
    js_sys::Reflect::set(&obj, &"kek".into(), &Uint8Array::from(&keys.kek[..]))?;
    js_sys::Reflect::set(&obj, &"zkp_scalar".into(), &Uint8Array::from(&keys.zkp_scalar[..]))?;

    Ok(obj.into())
}

/// Encrypt data with AES-256-GCM.
///
/// # Arguments
/// * `key` - 32-byte encryption key
/// * `plaintext` - Data to encrypt
/// * `aad` - Additional authenticated data (can be empty)
///
/// # Returns
/// Serialized ciphertext: [nonce (12 bytes) || ciphertext || tag (16 bytes)]
#[wasm_bindgen]
pub fn encrypt(key: &[u8], plaintext: &[u8], aad: &[u8]) -> Result<Uint8Array, JsValue> {
    if key.len() != 32 {
        return Err(JsValue::from_str("key must be 32 bytes"));
    }
    let key_arr: [u8; 32] = key.try_into().map_err(|_| "key must be 32 bytes")?;
    let aad_opt = if aad.is_empty() { None } else { Some(aad) };
    let ct = crate::cipher::encrypt(&key_arr, plaintext, aad_opt)
        .map_err(|e| JsValue::from_str(&format!("{:?}", e)))?;
    Ok(Uint8Array::from(&ct.to_bytes()[..]))
}

/// Decrypt data with AES-256-GCM.
///
/// # Arguments
/// * `key` - 32-byte encryption key
/// * `ciphertext` - Serialized ciphertext from encrypt()
/// * `aad` - Additional authenticated data (must match encryption)
///
/// # Returns
/// Decrypted plaintext
#[wasm_bindgen]
pub fn decrypt(key: &[u8], ciphertext: &[u8], aad: &[u8]) -> Result<Uint8Array, JsValue> {
    if key.len() != 32 {
        return Err(JsValue::from_str("key must be 32 bytes"));
    }
    let key_arr: [u8; 32] = key.try_into().map_err(|_| "key must be 32 bytes")?;
    let aad_opt = if aad.is_empty() { None } else { Some(aad) };
    let plaintext = crate::cipher::decrypt_bytes(&key_arr, ciphertext, aad_opt)
        .map_err(|e| JsValue::from_str(&format!("{:?}", e)))?;
    Ok(Uint8Array::from(&plaintext[..]))
}

/// Generate random bytes using the CSPRNG.
///
/// # Arguments
/// * `len` - Number of bytes to generate
#[wasm_bindgen]
pub fn random_bytes(len: usize) -> Uint8Array {
    let mut buf = vec![0u8; len];
    crate::cipher::fill_random(&mut buf);
    Uint8Array::from(&buf[..])
}

/// Compute SHA-256 hash.
#[wasm_bindgen]
pub fn sha256(data: &[u8]) -> Uint8Array {
    let hash = crate::hash::sha256(data);
    Uint8Array::from(&hash[..])
}

/// Compute HMAC-SHA256.
#[wasm_bindgen]
pub fn hmac_sha256(key: &[u8], data: &[u8]) -> Uint8Array {
    let mac = crate::hash::hmac_sha256(key, data);
    Uint8Array::from(&mac[..])
}
