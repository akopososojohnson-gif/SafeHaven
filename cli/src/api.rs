use anyhow::Result;
use reqwest::Client;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChallengeResponse {
    pub challenge_id: String,
    pub challenge: String,
    pub zkp_params: ZkpParams,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZkpParams {
    pub group: String,
    pub generator: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifyResponse {
    pub access_token: String,
    pub refresh_token: String,
    pub token_type: String,
    pub expires_in: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultItemResponse {
    pub id: String,
    pub blob_id: String,
    pub version: i32,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultItemSync {
    pub id: String,
    pub blob_id: String,
    pub item_type: String,
    pub version: i32,
    pub updated_at: String,
    pub deleted: bool,
    pub tags: Vec<String>,
    pub favorite: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncResponse {
    pub items: Vec<VaultItemSync>,
    pub deleted_ids: Vec<String>,
    pub server_timestamp: String,
    pub has_more: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserMe {
    pub id: String,
    pub email: String,
    pub mfa_enabled: bool,
    pub storage_used_bytes: i64,
    pub storage_quota_bytes: i64,
    pub created_at: String,
}

pub struct ApiClient {
    client: Client,
    base_url: String,
    token: Option<String>,
}

impl ApiClient {
    pub fn new(base_url: &str) -> Self {
        Self {
            client: Client::new(),
            base_url: base_url.trim_end_matches('/').to_string(),
            token: None,
        }
    }

    pub fn with_token(base_url: &str, token: &str) -> Self {
        Self {
            client: Client::new(),
            base_url: base_url.trim_end_matches('/').to_string(),
            token: Some(token.to_string()),
        }
    }

    fn headers(&self) -> reqwest::header::HeaderMap {
        let mut h = reqwest::header::HeaderMap::new();
        h.insert(
            reqwest::header::CONTENT_TYPE,
            "application/json".parse().unwrap(),
        );
        if let Some(t) = &self.token {
            h.insert(
                reqwest::header::AUTHORIZATION,
                format!("Bearer {}", t).parse().unwrap(),
            );
        }
        h
    }

    pub async fn health(&self) -> Result<String> {
        let url = format!("{}/health", self.base_url);
        let res = self.client.get(&url).send().await?;
        let text = res.text().await?;
        Ok(text)
    }

    pub async fn register(
        &self,
        email: &str,
        zkp_public_key: &str,
        argon2_salt: &str,
        argon2_memory: u32,
        argon2_iterations: u32,
        argon2_parallelism: u32,
        vault_key_wrap: &str,
    ) -> Result<String> {
        let url = format!("{}/api/v1/auth/register", self.base_url);
        let body = serde_json::json!({
            "email": email,
            "zkp_public_key": zkp_public_key,
            "argon2_salt": argon2_salt,
            "argon2_memory": argon2_memory,
            "argon2_iterations": argon2_iterations,
            "argon2_parallelism": argon2_parallelism,
            "vault_key_wrap": vault_key_wrap,
        });
        let res = self
            .client
            .post(&url)
            .headers(self.headers())
            .json(&body)
            .send()
            .await?;
        if !res.status().is_success() {
            let err = res.text().await.unwrap_or_default();
            anyhow::bail!("register failed: {}", err);
        }
        let json: serde_json::Value = res.json().await?;
        Ok(json["user_id"].as_str().unwrap_or("").to_string())
    }

    pub async fn challenge(&self, email: &str) -> Result<ChallengeResponse> {
        let url = format!("{}/api/v1/auth/challenge", self.base_url);
        let body = serde_json::json!({ "email": email });
        let res = self
            .client
            .post(&url)
            .headers(self.headers())
            .json(&body)
            .send()
            .await?;
        if !res.status().is_success() {
            let err = res.text().await.unwrap_or_default();
            anyhow::bail!("challenge failed: {}", err);
        }
        Ok(res.json().await?)
    }

    pub async fn verify(
        &self,
        challenge_id: &str,
        proof_t: &str,
        proof_s: &str,
    ) -> Result<VerifyResponse> {
        let url = format!("{}/api/v1/auth/verify", self.base_url);
        let body = serde_json::json!({
            "challenge_id": challenge_id,
            "proof_t": proof_t,
            "proof_s": proof_s,
        });
        let res = self
            .client
            .post(&url)
            .headers(self.headers())
            .json(&body)
            .send()
            .await?;
        if !res.status().is_success() {
            let err = res.text().await.unwrap_or_default();
            anyhow::bail!("verify failed: {}", err);
        }
        Ok(res.json().await?)
    }

    pub async fn logout(&self) -> Result<()> {
        let url = format!("{}/api/v1/auth/logout", self.base_url);
        let res = self
            .client
            .post(&url)
            .headers(self.headers())
            .send()
            .await?;
        if !res.status().is_success() {
            let err = res.text().await.unwrap_or_default();
            anyhow::bail!("logout failed: {}", err);
        }
        Ok(())
    }

    pub async fn sync(&self, since: Option<&str>, include_deleted: bool) -> Result<SyncResponse> {
        let mut url = format!("{}/api/v1/vault/sync", self.base_url);
        let mut params = vec![];
        if let Some(s) = since {
            params.push(format!("since={}", s));
        }
        if include_deleted {
            params.push("include_deleted=true".to_string());
        }
        if !params.is_empty() {
            url = format!("{}?{}", url, params.join("&"));
        }
        let res = self.client.get(&url).headers(self.headers()).send().await?;
        if !res.status().is_success() {
            let err = res.text().await.unwrap_or_default();
            anyhow::bail!("sync failed: {}", err);
        }
        Ok(res.json().await?)
    }

    pub async fn create_vault_item(
        &self,
        item_type: &str,
        blob: &str,
        blob_size: i32,
        name_hash: Option<&str>,
        tags: Vec<String>,
    ) -> Result<VaultItemResponse> {
        let url = format!("{}/api/v1/vault/items", self.base_url);
        let mut body = serde_json::json!({
            "item_type": item_type,
            "blob": blob,
            "blob_size": blob_size,
            "tags": tags,
        });
        if let Some(nh) = name_hash {
            body["name_hash"] = serde_json::json!(nh);
        }
        let res = self
            .client
            .post(&url)
            .headers(self.headers())
            .json(&body)
            .send()
            .await?;
        if !res.status().is_success() {
            let err = res.text().await.unwrap_or_default();
            anyhow::bail!("create item failed: {}", err);
        }
        Ok(res.json().await?)
    }

    pub async fn delete_vault_item(&self, id: &str) -> Result<()> {
        let url = format!("{}/api/v1/vault/items/{}", self.base_url, id);
        let res = self
            .client
            .delete(&url)
            .headers(self.headers())
            .send()
            .await?;
        if !res.status().is_success() {
            let err = res.text().await.unwrap_or_default();
            anyhow::bail!("delete item failed: {}", err);
        }
        Ok(())
    }

    pub async fn me(&self) -> Result<UserMe> {
        let url = format!("{}/api/v1/user/me", self.base_url);
        let res = self.client.get(&url).headers(self.headers()).send().await?;
        if !res.status().is_success() {
            let err = res.text().await.unwrap_or_default();
            anyhow::bail!("me failed: {}", err);
        }
        Ok(res.json().await?)
    }
}
