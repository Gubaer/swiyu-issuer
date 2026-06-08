//! Per-user token grants against the realm: refreshing the logged-in user's
//! access token, and exchanging it (RFC 8693) for an mgmtapi act-as-user token.

use chrono::Utc;
use serde::Deserialize;

/// Subtracted from the refreshed token's `expires_in` so it is renewed before
/// the realm considers it expired.
const SAFETY_MARGIN_SECS: i64 = 30;

const TOKEN_EXCHANGE_GRANT: &str = "urn:ietf:params:oauth:grant-type:token-exchange";
const ACCESS_TOKEN_TYPE: &str = "urn:ietf:params:oauth:token-type:access_token";
/// Optional client scope that projects the brokered IdP's `(iss, sub)` into the
/// `user_identity` claim of the exchanged token.
const ACT_AS_USER_SCOPE: &str = "act-as-user";

#[derive(Debug, thiserror::Error)]
pub enum UserTokenError {
    #[error("token request transport error: {0}")]
    Transport(#[from] reqwest::Error),
    #[error("token endpoint returned {status}: {body}")]
    Status { status: u16, body: String },
}

#[derive(Debug, Deserialize)]
struct TokenResponse {
    access_token: String,
    #[serde(default)]
    refresh_token: Option<String>,
    #[serde(default)]
    expires_in: u64,
}

/// A refreshed user access token (and the rotated refresh token).
pub struct RefreshedUserToken {
    pub access_token: String,
    pub refresh_token: String,
    pub access_expiry_unix: i64,
}

/// Client for the per-user grants against the realm: the `refresh_token` grant
/// and the RFC 8693 token exchange.
pub struct UserTokens {
    http: reqwest::Client,
    token_endpoint: String,
    client_id: String,
    client_secret: String,
}

impl UserTokens {
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
        }
    }

    /// Renews the user's access token via a `refresh_token` grant, returning the
    /// new access token and the rotated refresh token (falling back to the
    /// presented one if the realm does not rotate).
    pub async fn refresh(&self, refresh_token: &str) -> Result<RefreshedUserToken, UserTokenError> {
        let body = url::form_urlencoded::Serializer::new(String::new())
            .append_pair("grant_type", "refresh_token")
            .append_pair("refresh_token", refresh_token)
            .append_pair("client_id", &self.client_id)
            .append_pair("client_secret", &self.client_secret)
            .finish();

        let response = self.post(body).await?;
        tracing::debug!(
            expires_in = response.expires_in,
            "refreshed user access token"
        );
        Ok(RefreshedUserToken {
            access_expiry_unix: Utc::now().timestamp()
                + (response.expires_in as i64 - SAFETY_MARGIN_SECS),
            refresh_token: response
                .refresh_token
                .unwrap_or_else(|| refresh_token.to_string()),
            access_token: response.access_token,
        })
    }

    /// Exchanges the user's access token for an mgmtapi act-as-user token
    /// (RFC 8693), requesting the `act-as-user` scope.
    pub async fn exchange_for_mgmtapi(
        &self,
        subject_access_token: &str,
    ) -> Result<String, UserTokenError> {
        let body = url::form_urlencoded::Serializer::new(String::new())
            .append_pair("grant_type", TOKEN_EXCHANGE_GRANT)
            .append_pair("subject_token", subject_access_token)
            .append_pair("subject_token_type", ACCESS_TOKEN_TYPE)
            .append_pair("scope", ACT_AS_USER_SCOPE)
            .append_pair("client_id", &self.client_id)
            .append_pair("client_secret", &self.client_secret)
            .finish();

        let response = self.post(body).await?;
        tracing::debug!(
            expires_in = response.expires_in,
            "exchanged user token for an mgmtapi act-as-user token"
        );
        Ok(response.access_token)
    }

    async fn post(&self, body: String) -> Result<TokenResponse, UserTokenError> {
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
            Err(UserTokenError::Status {
                status: status.as_u16(),
                body,
            })
        }
    }
}
