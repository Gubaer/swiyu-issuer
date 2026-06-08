//! OIDC endpoint URLs.
//!
//! Built by Keycloak's well-known path convention from two bases: the **public**
//! issuer (browser-facing — authorize + logout — and the `id_token` `iss`) and
//! the **internal** base (the BFF's back-channel — token + JWKS). When
//! `OIDC_INTERNAL_URL` is unset the two are identical (the host-process
//! workflow). This split is the BFF analogue of mgmtapi keeping
//! `KEYCLOAK_ISSUER_URL` while overriding `KEYCLOAK_JWKS_URL` in-network.

/// The realm endpoints the BFF needs.
#[derive(Debug, Clone)]
pub struct OidcEndpoints {
    /// Public issuer; the `iss` the BFF verifies on the `id_token`.
    pub issuer: String,
    /// Browser-facing authorization endpoint (the login redirect target).
    pub authorize_endpoint: String,
    /// Browser-facing RP-initiated logout endpoint.
    pub end_session_endpoint: String,
    /// Back-channel token endpoint: code exchange, client-credentials, refresh,
    /// RFC 8693 exchange.
    pub token_endpoint: String,
    /// Back-channel JWKS endpoint, for `id_token` signature verification.
    pub jwks_uri: String,
}

impl OidcEndpoints {
    /// Builds the endpoints. Browser-facing URLs (and the verified `iss`) come
    /// from `issuer_url`; back-channel URLs come from `internal_url`.
    pub fn build(issuer_url: &str, internal_url: &str) -> Self {
        let issuer = issuer_url.trim_end_matches('/').to_string();
        let internal = internal_url.trim_end_matches('/').to_string();
        Self {
            authorize_endpoint: format!("{issuer}/protocol/openid-connect/auth"),
            end_session_endpoint: format!("{issuer}/protocol/openid-connect/logout"),
            token_endpoint: format!("{internal}/protocol/openid-connect/token"),
            jwks_uri: format!("{internal}/protocol/openid-connect/certs"),
            issuer,
        }
    }
}
