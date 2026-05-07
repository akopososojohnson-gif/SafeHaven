use anyhow::Result;

pub async fn create(_blob: &str, _expiry_hours: u32) -> Result<()> {
    println!("Share creation requires web UI or API direct call. CLI support coming soon.");
    Ok(())
}

pub async fn redeem(_share_id: &str) -> Result<()> {
    println!("Share redemption requires web UI or API direct call. CLI support coming soon.");
    Ok(())
}
