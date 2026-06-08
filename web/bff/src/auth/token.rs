//! The BFF's own first-party `client_credentials` access token.
//! Minted against the realm token endpoint, cached in memory,
//! refreshed single-flight.

use std::time::{Duration, Instant};

use serde::Deserialize;
use tokio::sync::Mutex;

/// Safety margin subtracted from the token's `expires_in` so a token is
/// refreshed before the realm considers it expired.
const SAFETY_MARGIN: Duration = Duration::from_secs(30);

#[derive(Debug, thiserror::Error)]
pub enum TokenError {
    #[error("token request transport error: {0}")]
    Transport(#[from] reqwest::Error),
    #[error("token endpoint returned {status}: {body}")]
    Status { status: u16, body: String },
}

#[derive(Debug, Deserialize)]
struct TokenResponse {
    access_token: String,
    expires_in: u64,
}

struct Cached {
    token: String,
    expires_at: Instant,
}

/// Mints and caches the BFF's first-party access token. One instance for the
/// whole process: the BFF authenticates as a single confidential client, so
/// there is exactly one credential set.
pub struct FirstPartyTokenProvider {
    http: reqwest::Client,
    token_endpoint: String,
    client_id: String,
    client_secret: String,
    cached: Mutex<Option<Cached>>,
}

impl FirstPartyTokenProvider {
    pub fn new(
        http: reqwest::Client,
        token_endpoint: String,
        client_id: String,
        client_secret: String,
    ) -> Self {
        Self {
            http,
            token_endpoint,
            client_id,
            client_secret,
            cached: Mutex::new(None),
        }
    }

    /// Returns a currently-valid access token, minting one if the cache is empty
    /// or within its safety margin of expiry. Holding the lock across the grant
    /// serialises refreshes (single-flight): concurrent callers await the same
    /// refresh and then observe the fresh token.
    pub async fn token(&self) -> Result<String, TokenError> {
        let mut cached = self.cached.lock().await;
        if let Some(entry) = cached.as_ref()
            && Instant::now() < entry.expires_at
        {
            return Ok(entry.token.clone());
        }

        let response = self.request_token().await?;
        let ttl = Duration::from_secs(response.expires_in).saturating_sub(SAFETY_MARGIN);
        let expires_at = Instant::now() + ttl;
        *cached = Some(Cached {
            token: response.access_token.clone(),
            expires_at,
        });
        Ok(response.access_token)
    }

    async fn request_token(&self) -> Result<TokenResponse, TokenError> {
        // `client_secret_post`: client credentials travel in the form body
        // (Keycloak accepts this for a confidential client), so no dependency on
        // reqwest's optional `.form()` / `.basic_auth()` helpers.
        let body = url::form_urlencoded::Serializer::new(String::new())
            .append_pair("grant_type", "client_credentials")
            .append_pair("client_id", &self.client_id)
            .append_pair("client_secret", &self.client_secret)
            .finish();

        let response = self
            .http
            .post(&self.token_endpoint)
            .header(
                reqwest::header::CONTENT_TYPE,
                "application/x-www-form-urlencoded",
            )
            .body(body)
            .send()
            .await?;

        let status = response.status();
        if status.is_success() {
            Ok(response.json::<TokenResponse>().await?)
        } else {
            let body = response.text().await.unwrap_or_default();
            Err(TokenError::Status {
                status: status.as_u16(),
                body,
            })
        }
    }
}
