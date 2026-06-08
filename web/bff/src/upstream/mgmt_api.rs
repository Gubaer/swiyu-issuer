use std::sync::Arc;

use serde_json::Value;

use crate::auth::{FirstPartyTokenProvider, TokenError};

#[derive(Debug, thiserror::Error)]
pub enum CallError {
    #[error("transport error: {0}")]
    Transport(#[from] reqwest::Error),
    #[error("could not mint an access token for the management API: {0}")]
    Token(#[from] TokenError),
    #[error("upstream returned {status}: {body}")]
    Status { status: u16, body: String },
}

/// HTTP client for `swiyu-issuer-mgmtapi`. Authenticates every call with a
/// freshly-minted bearer token from the first-party provider (replacing the old
/// static `MGMTAPI_TOKEN`).
#[derive(Clone)]
pub struct MgmtApiClient {
    http: reqwest::Client,
    base_url: String,
    token_provider: Arc<FirstPartyTokenProvider>,
}

impl MgmtApiClient {
    pub fn new(
        http: reqwest::Client,
        base_url: &str,
        token_provider: Arc<FirstPartyTokenProvider>,
    ) -> Self {
        Self {
            http,
            base_url: base_url.trim_end_matches('/').to_string(),
            token_provider,
        }
    }

    /// The first-party bearer token to present on a management-API call.
    async fn bearer(&self) -> Result<String, CallError> {
        Ok(self.token_provider.token().await?)
    }

    /// Resolves a federated identity to the accounts it is linked to, across
    /// tenants. Authenticated by the first-party token; the identity is asserted as query params.
    pub async fn resolve_linked_accounts(&self, iss: &str, sub: &str) -> Result<Value, CallError> {
        let url = format!("{}/api/v1/linked-user-accounts", self.base_url);
        let response = self
            .http
            .get(&url)
            .bearer_auth(self.bearer().await?)
            .query(&[("iss", iss), ("sub", sub)])
            .send()
            .await?;
        read_json(response).await
    }

    pub async fn list_issuers(&self) -> Result<Value, CallError> {
        let url = format!("{}/api/v1/issuers", self.base_url);
        let response = self
            .http
            .get(&url)
            .bearer_auth(self.bearer().await?)
            .send()
            .await?;
        read_json(response).await
    }

    pub async fn create_issuer(&self, body: Value) -> Result<Value, CallError> {
        let url = format!("{}/api/v1/issuers", self.base_url);
        let response = self
            .http
            .post(&url)
            .bearer_auth(self.bearer().await?)
            .json(&body)
            .send()
            .await?;
        read_json(response).await
    }

    pub async fn get_issuer(&self, issuer_id: &str) -> Result<Value, CallError> {
        let url = format!("{}/api/v1/issuers/{issuer_id}", self.base_url);
        let response = self
            .http
            .get(&url)
            .bearer_auth(self.bearer().await?)
            .send()
            .await?;
        read_json(response).await
    }

    pub async fn deactivate_issuer(&self, issuer_id: &str) -> Result<Value, CallError> {
        let url = format!("{}/api/v1/issuers/{issuer_id}/deactivate", self.base_url);
        let response = self
            .http
            .post(&url)
            .bearer_auth(self.bearer().await?)
            .send()
            .await?;
        read_json(response).await
    }

    pub async fn rotate_keys(&self, issuer_id: &str, body: Value) -> Result<Value, CallError> {
        let url = format!("{}/api/v1/issuers/{issuer_id}/rotate-keys", self.base_url);
        let response = self
            .http
            .post(&url)
            .bearer_auth(self.bearer().await?)
            .json(&body)
            .send()
            .await?;
        read_json(response).await
    }

    pub async fn get_operation_task(&self, task_id: &str) -> Result<Value, CallError> {
        let url = format!("{}/api/v1/operation-tasks/{task_id}", self.base_url);
        let response = self
            .http
            .get(&url)
            .bearer_auth(self.bearer().await?)
            .send()
            .await?;
        read_json(response).await
    }

    pub async fn list_credential_offers(
        &self,
        issuer_id: &str,
        limit: Option<u32>,
        cursor: Option<&str>,
    ) -> Result<Value, CallError> {
        let url = format!(
            "{}/api/v1/issuers/{issuer_id}/credential-offers",
            self.base_url
        );
        // Only attach query params that are actually present; otherwise the
        // upstream sees `?limit=` (empty string) and rejects it as malformed.
        let mut query: Vec<(&str, String)> = Vec::new();
        if let Some(limit) = limit {
            query.push(("limit", limit.to_string()));
        }
        if let Some(cursor) = cursor {
            query.push(("cursor", cursor.to_string()));
        }
        let response = self
            .http
            .get(&url)
            .bearer_auth(self.bearer().await?)
            .query(&query)
            .send()
            .await?;
        read_json(response).await
    }

    pub async fn get_credential_offer(
        &self,
        issuer_id: &str,
        offer_id: &str,
    ) -> Result<Value, CallError> {
        let url = format!(
            "{}/api/v1/issuers/{issuer_id}/credential-offers/{offer_id}",
            self.base_url
        );
        let response = self
            .http
            .get(&url)
            .bearer_auth(self.bearer().await?)
            .send()
            .await?;
        read_json(response).await
    }

    pub async fn create_credential_offer(
        &self,
        issuer_id: &str,
        body: Value,
    ) -> Result<Value, CallError> {
        let url = format!(
            "{}/api/v1/issuers/{issuer_id}/credential-offers",
            self.base_url
        );
        let response = self
            .http
            .post(&url)
            .bearer_auth(self.bearer().await?)
            .json(&body)
            .send()
            .await?;
        read_json(response).await
    }

    pub async fn list_credential_types(&self, issuer_id: &str) -> Result<Value, CallError> {
        let url = format!(
            "{}/api/v1/issuers/{issuer_id}/credential-types",
            self.base_url
        );
        let response = self
            .http
            .get(&url)
            .bearer_auth(self.bearer().await?)
            .send()
            .await?;
        read_json(response).await
    }

    pub async fn get_credential_type_schema(
        &self,
        credential_type_id: &str,
    ) -> Result<Value, CallError> {
        // Upstream serves the schema as `application/schema+json`; `read_json`
        // parses the body regardless of content-type, so a JSON Schema document
        // deserializes the same as any other JSON response.
        let url = format!(
            "{}/api/v1/credential-types/{credential_type_id}/schema",
            self.base_url
        );
        let response = self
            .http
            .get(&url)
            .bearer_auth(self.bearer().await?)
            .send()
            .await?;
        read_json(response).await
    }
}

async fn read_json(response: reqwest::Response) -> Result<Value, CallError> {
    let status = response.status();
    if status.is_success() {
        Ok(response.json::<Value>().await?)
    } else {
        let body = response.text().await.unwrap_or_default();
        Err(CallError::Status {
            status: status.as_u16(),
            body,
        })
    }
}
