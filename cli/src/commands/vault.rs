use anyhow::{Context, Result};
use base64::{engine::general_purpose::STANDARD, Engine as _};

use crate::api::ApiClient;
use crate::config::Config;
use crate::storage;

pub async fn list() -> Result<()> {
    let token = storage::get_token()?.context("not logged in")?;
    let cfg = Config::load();
    let client = ApiClient::with_token(&cfg.server_url, &token);

    let sync = client.sync(None, false).await?;
    if sync.items.is_empty() {
        println!("Vault is empty.");
        return Ok(());
    }

    println!(
        "{:<36} {:<15} {:<8} {:<20}",
        "ID", "Type", "Version", "Updated"
    );
    for item in &sync.items {
        println!(
            "{:<36} {:<15} {:<8} {:<20}",
            item.id,
            item.item_type,
            item.version,
            item.updated_at.split('T').next().unwrap_or(""),
        );
    }
    Ok(())
}

pub async fn add(item_type: &str, blob: &str) -> Result<()> {
    let token = storage::get_token()?.context("not logged in")?;
    let cfg = Config::load();
    let client = ApiClient::with_token(&cfg.server_url, &token);

    let blob_bytes = blob.as_bytes();
    let blob_b64 = STANDARD.encode(blob_bytes);

    let res = client
        .create_vault_item(item_type, &blob_b64, blob_bytes.len() as i32, None, vec![])
        .await?;
    println!("Created item: {} (blob_id: {})", res.id, res.blob_id);
    Ok(())
}

pub async fn delete(id: &str) -> Result<()> {
    let token = storage::get_token()?.context("not logged in")?;
    let cfg = Config::load();
    let client = ApiClient::with_token(&cfg.server_url, &token);

    client.delete_vault_item(id).await?;
    println!("Deleted item: {}", id);
    Ok(())
}
