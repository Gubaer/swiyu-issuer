use std::sync::Arc;

use reqwest::RequestBuilder;
use serde_json::Value;

use crate::auth::{FirstPartyTokenProvider, TokenError};

/// Header naming the selected user account on act-as-user calls; mgmtapi verifies
/// it against the token's signed identity before deriving the tenant.
const X_USER_ACCOUNT: &str = "x-user-account";

#[derive(Debug, thiserror::Error)]
pub enum CallError {
    #[error("transport error: {0}")]
    Transport(#[from] reqwest::Error),
    #[error("could not mint an access token for the management API: {0}")]
    Token(#[from] TokenError),
    #[error("upstream returned {status}: {body}")]
    Status { status: u16, body: String },
}

/// The act-as-user authorization for a management-API call.
pub struct UserAuth {
    /// The exchanged mgmtapi access token.
    pub bearer: String,
    /// The selected account; travels in `X-User-Account`.
    pub account_id: String,
}

/// HTTP client for `swiyu-issuer-mgmtapi`.
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

    /// Applies the act-as-user authorization (exchanged bearer + `X-User-Account`)
    /// to a request.
    fn act_as_user(builder: RequestBuilder, auth: &UserAuth) -> RequestBuilder {
        builder
            .bearer_auth(&auth.bearer)
            .header(X_USER_ACCOUNT, &auth.account_id)
    }

    /// The BFF's own first-party bearer, for the (non-user) resolve call.
    async fn first_party_bearer(&self) -> Result<String, CallError> {
        Ok(self.token_provider.token().await?)
    }

    /// Resolves a federated identity to the accounts it is linked to, across
    /// tenants. Authenticated by the first-party token; the identity is asserted as query params.
    pub async fn resolve_linked_accounts(&self, iss: &str, sub: &str) -> Result<Value, CallError> {
        let url = format!("{}/api/v1/linked-user-accounts", self.base_url);
        let response = self
            .http
            .get(&url)
            .bearer_auth(self.first_party_bearer().await?)
            .query(&[("iss", iss), ("sub", sub)])
            .send()
            .await?;
        read_json(response).await
    }

    pub async fn list_issuers(&self, auth: &UserAuth) -> Result<Value, CallError> {
        let url = format!("{}/api/v1/issuers", self.base_url);
        let response = Self::act_as_user(self.http.get(&url), auth).send().await?;
        read_json(response).await
    }

    pub async fn create_issuer(&self, auth: &UserAuth, body: Value) -> Result<Value, CallError> {
        let url = format!("{}/api/v1/issuers", self.base_url);
        let response = Self::act_as_user(self.http.post(&url), auth)
            .json(&body)
            .send()
            .await?;
        read_json(response).await
    }

    pub async fn get_issuer(&self, auth: &UserAuth, issuer_id: &str) -> Result<Value, CallError> {
        let url = format!("{}/api/v1/issuers/{issuer_id}", self.base_url);
        let response = Self::act_as_user(self.http.get(&url), auth).send().await?;
        read_json(response).await
    }

    pub async fn deactivate_issuer(
        &self,
        auth: &UserAuth,
        issuer_id: &str,
    ) -> Result<Value, CallError> {
        let url = format!("{}/api/v1/issuers/{issuer_id}/deactivate", self.base_url);
        let response = Self::act_as_user(self.http.post(&url), auth).send().await?;
        read_json(response).await
    }

    pub async fn rotate_keys(
        &self,
        auth: &UserAuth,
        issuer_id: &str,
        body: Value,
    ) -> Result<Value, CallError> {
        let url = format!("{}/api/v1/issuers/{issuer_id}/rotate-keys", self.base_url);
        let response = Self::act_as_user(self.http.post(&url), auth)
            .json(&body)
            .send()
            .await?;
        read_json(response).await
    }

    pub async fn get_operation_task(
        &self,
        auth: &UserAuth,
        task_id: &str,
    ) -> Result<Value, CallError> {
        let url = format!("{}/api/v1/operation-tasks/{task_id}", self.base_url);
        let response = Self::act_as_user(self.http.get(&url), auth).send().await?;
        read_json(response).await
    }

    pub async fn list_credential_offers(
        &self,
        auth: &UserAuth,
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
        let response = Self::act_as_user(self.http.get(&url), auth)
            .query(&query)
            .send()
            .await?;
        read_json(response).await
    }

    pub async fn get_credential_offer(
        &self,
        auth: &UserAuth,
        issuer_id: &str,
        offer_id: &str,
    ) -> Result<Value, CallError> {
        let url = format!(
            "{}/api/v1/issuers/{issuer_id}/credential-offers/{offer_id}",
            self.base_url
        );
        let response = Self::act_as_user(self.http.get(&url), auth).send().await?;
        read_json(response).await
    }

    pub async fn create_credential_offer(
        &self,
        auth: &UserAuth,
        issuer_id: &str,
        body: Value,
    ) -> Result<Value, CallError> {
        let url = format!(
            "{}/api/v1/issuers/{issuer_id}/credential-offers",
            self.base_url
        );
        let response = Self::act_as_user(self.http.post(&url), auth)
            .json(&body)
            .send()
            .await?;
        read_json(response).await
    }

    pub async fn cancel_credential_offer(
        &self,
        auth: &UserAuth,
        issuer_id: &str,
        offer_id: &str,
    ) -> Result<Value, CallError> {
        let url = format!(
            "{}/api/v1/issuers/{issuer_id}/credential-offers/{offer_id}/cancel",
            self.base_url
        );
        let response = Self::act_as_user(self.http.post(&url), auth).send().await?;
        read_json(response).await
    }

    pub async fn list_credential_types(
        &self,
        auth: &UserAuth,
        issuer_id: &str,
    ) -> Result<Value, CallError> {
        let url = format!(
            "{}/api/v1/issuers/{issuer_id}/credential-types",
            self.base_url
        );
        let response = Self::act_as_user(self.http.get(&url), auth).send().await?;
        read_json(response).await
    }

    pub async fn get_credential_type_schema(
        &self,
        auth: &UserAuth,
        credential_type_id: &str,
    ) -> Result<Value, CallError> {
        // Upstream serves the schema as `application/schema+json`; `read_json`
        // parses the body regardless of content-type, so a JSON Schema document
        // deserializes the same as any other JSON response.
        let url = format!(
            "{}/api/v1/credential-types/{credential_type_id}/schema",
            self.base_url
        );
        let response = Self::act_as_user(self.http.get(&url), auth).send().await?;
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
