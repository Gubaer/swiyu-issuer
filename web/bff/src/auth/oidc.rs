//! OIDC provider endpoint discovery.

use serde::Deserialize;

#[derive(Debug, thiserror::Error)]
pub enum DiscoveryError {
    #[error("could not build the discovery http client: {0}")]
    HttpClient(String),
    #[error("OIDC discovery request failed: {0}")]
    Request(String),
    #[error("OIDC discovery document is missing the token_endpoint")]
    MissingTokenEndpoint,
}

/// The subset of the discovery document the BFF parses itself. We read it
/// plainly (rather than via `openidconnect`'s `CoreProviderMetadata`) because
/// `end_session_endpoint` is not modelled there without custom generics.
#[derive(Debug, Deserialize)]
struct DiscoveryDocument {
    token_endpoint: Option<String>,
    end_session_endpoint: Option<String>,
}

/// The endpoint URLs the BFF needs from the realm's discovery document.
#[derive(Debug, Clone)]
pub struct OidcEndpoints {
    pub issuer: String,
    pub token_endpoint: String,
    /// RP-initiated logout endpoint (RFC: OpenID Connect RP-Initiated Logout).
    /// `None` if the realm does not advertise it, in which case logout falls back
    /// to a local session clear.
    pub end_session_endpoint: Option<String>,
}

/// Fetches the realm's `.well-known/openid-configuration` once at startup for
/// the endpoint URLs the hand-built service grants and logout need:
/// `token_endpoint` (client-credentials + RFC 8693 exchange) and
/// `end_session_endpoint` (RP-initiated single sign-out). The authorization-code
/// login client does its own typed discovery — see [`super::login`] — because it
/// also needs the JWKS for `id_token` verification.
///
/// Fails fast (a misconfigured or unreachable realm is not something to limp
/// along with).
pub async fn discover(issuer_url: &str) -> Result<OidcEndpoints, DiscoveryError> {
    let issuer = issuer_url.trim_end_matches('/').to_string();
    let url = format!("{issuer}/.well-known/openid-configuration");

    let http = reqwest::Client::builder()
        .build()
        .map_err(|err| DiscoveryError::HttpClient(err.to_string()))?;

    let document: DiscoveryDocument = http
        .get(&url)
        .send()
        .await
        .map_err(|err| DiscoveryError::Request(err.to_string()))?
        .error_for_status()
        .map_err(|err| DiscoveryError::Request(err.to_string()))?
        .json()
        .await
        .map_err(|err| DiscoveryError::Request(err.to_string()))?;

    Ok(OidcEndpoints {
        issuer,
        token_endpoint: document
            .token_endpoint
            .ok_or(DiscoveryError::MissingTokenEndpoint)?,
        end_session_endpoint: document.end_session_endpoint,
    })
}
