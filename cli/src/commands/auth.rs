use anyhow::Result;
use base64::{engine::general_purpose::STANDARD, Engine as _};
use crypto::kdf::Argon2Params;

use crate::api::ApiClient;
use crate::config::Config;
use crate::storage;

pub async fn login(email: &str, password: &str, server: Option<&str>) -> Result<()> {
    let cfg = Config::load();
    let base = server.unwrap_or(&cfg.server_url);

    let client = ApiClient::new(base);

    // 1. Challenge
    let chal = client.challenge(email).await?;
    println!("Challenge received: {}", chal.challenge_id);

    // 2. Derive keys (need salt — in real CLI, salt is stored locally after registration)
    // For demo, we cannot login without locally stored salt.
    // A real implementation would fetch or cache the salt.
    println!("Login requires locally stored salt. Use 'register' first, then this command would use cached credentials.");
    println!("(Demo: registering fresh credentials instead...)");

    register(email, password, server).await
}

pub async fn register(email: &str, password: &str, server: Option<&str>) -> Result<()> {
    let cfg = Config::load();
    let base = server.unwrap_or(&cfg.server_url);

    let client = ApiClient::new(base);

    // 1. Generate salt and derive master key
    let salt = crypto::cipher::random_bytes(32);
    let params = Argon2Params::default();
    let salt_arr: [u8; 32] = salt.clone().try_into().unwrap();
    let mk = crypto::kdf::derive_master_key(password, &salt_arr, &params)?;

    // 2. Derive subkeys
    let keys = crypto::keys::derive_subkeys(&mk)?;

    // 3. Generate vault key and wrap it
    let vault_key = crypto::cipher::random_bytes(32);
    let aad = b"vault-key-wrap-v1";
    let wrap_ct = crypto::cipher::encrypt(&keys.kek, &vault_key, Some(aad))?;
    let wrap_bytes = wrap_ct.to_bytes();

    // 4. Generate ZKP public key (placeholder — real impl uses Ristretto255)
    let zkp_pk = crypto::hash::sha256(&keys.zkp_scalar);

    // 5. Call API
    let user_id = client
        .register(
            email,
            &STANDARD.encode(&zkp_pk),
            &STANDARD.encode(&salt),
            params.memory_kb,
            params.iterations,
            params.parallelism,
            &STANDARD.encode(&wrap_bytes),
        )
        .await?;

    println!("Registered user: {}", user_id);

    // 6. Auto-login: challenge + verify (demo uses dummy proof)
    let chal = client.challenge(email).await?;
    println!("Challenge: {}", chal.challenge_id);

    // In a real implementation, we compute the ZKP proof here.
    // For demo, we generate a dummy proof.
    let proof_t = crypto::cipher::random_bytes(32);
    let proof_s = crypto::cipher::random_bytes(32);

    let verify = client
        .verify(
            &chal.challenge_id,
            &STANDARD.encode(&proof_t),
            &STANDARD.encode(&proof_s),
        )
        .await?;

    storage::store_token(&verify.access_token)?;
    println!("Logged in. Access token stored.");
    Ok(())
}

pub async fn logout() -> Result<()> {
    if let Some(token) = storage::get_token()? {
        let cfg = Config::load();
        let client = ApiClient::with_token(&cfg.server_url, &token);
        client.logout().await?;
    }
    storage::delete_token()?;
    println!("Logged out and token cleared.");
    Ok(())
}
