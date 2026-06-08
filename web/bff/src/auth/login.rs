//! The OIDC authorization-code login client (the user login).

use std::time::Instant;

use chrono::Utc;
use openidconnect::core::{CoreClient, CoreProviderMetadata, CoreResponseType};
use openidconnect::{
    AuthenticationFlow, AuthorizationCode, ClientId, ClientSecret, CsrfToken, IssuerUrl, Nonce,
    OAuth2TokenResponse, PkceCodeChallenge, PkceCodeVerifier, RedirectUrl, Scope, TokenResponse,
    reqwest,
};

use crate::config::OidcConfig;

use super::pending::PendingLogin;

#[derive(Debug, thiserror::Error)]
pub enum LoginClientError {
    #[error("invalid OIDC configuration: {0}")]
    Config(String),
    #[error("could not build the OIDC http client: {0}")]
    HttpClient(String),
    #[error("OIDC provider discovery failed: {0}")]
    Discover(String),
}

#[derive(Debug, thiserror::Error)]
pub enum LoginError {
    #[error("authorization-code exchange failed: {0}")]
    Exchange(String),
    #[error("the token response carried no id_token")]
    NoIdToken,
    #[error("id_token verification failed: {0}")]
    IdToken(String),
}

/// What a [`OidcLoginClient::begin_login`] produced: the URL to redirect the
/// browser to, the CSRF `state` (the key under which the pending login is
/// stashed), and the pending secrets themselves.
pub struct BeginLogin {
    pub authorize_url: String,
    pub state: String,
    pub pending: PendingLogin,
}

/// The cryptographically-established result of a completed login.
pub struct VerifiedUser {
    pub iss: String,
    pub sub: String,
    pub access_token: String,
    pub refresh_token: Option<String>,
    /// The compact `id_token`, kept as the `id_token_hint` for single sign-out.
    pub id_token: String,
    pub access_expiry_unix: i64,
}

/// `openidconnect`-backed client for the authorization-code login. The provider
/// metadata kept here includes the JWKS fetched at discovery; the per-request
/// `CoreClient` is rebuilt from it (cheap, no I/O).
pub struct OidcLoginClient {
    metadata: CoreProviderMetadata,
    client_id: ClientId,
    client_secret: ClientSecret,
    redirect_uri: RedirectUrl,
    http: reqwest::Client,
}

impl OidcLoginClient {
    /// Discovers the realm and builds the login client at startup.
    pub async fn discover(cfg: &OidcConfig) -> Result<Self, LoginClientError> {
        let issuer = IssuerUrl::new(cfg.issuer_url.clone())
            .map_err(|err| LoginClientError::Config(err.to_string()))?;
        let redirect_uri = RedirectUrl::new(cfg.redirect_uri.clone())
            .map_err(|err| LoginClientError::Config(err.to_string()))?;

        // OAuth requests must not follow redirects.
        let http = reqwest::ClientBuilder::new()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|err| LoginClientError::HttpClient(err.to_string()))?;

        let metadata = CoreProviderMetadata::discover_async(issuer, &http)
            .await
            .map_err(|err| LoginClientError::Discover(err.to_string()))?;

        Ok(Self {
            metadata,
            client_id: ClientId::new(cfg.client_id.clone()),
            client_secret: ClientSecret::new(cfg.client_secret.clone()),
            redirect_uri,
            http,
        })
    }

    /// Builds the authorization-code redirect with a fresh CSRF state, nonce, and
    /// PKCE challenge. The verifier and nonce travel back through the pending-login
    /// store, never the browser.
    ///
    /// oauth2's `Client` encodes which endpoints are configured in its type
    /// parameters, so `from_provider_metadata(...).set_redirect_uri(...)` yields a
    /// type distinct from the `CoreClient` alias and impractical to write out.
    /// Hence the client is built inline here and in `complete_login` (type
    /// inferred at the call site) rather than returned from a shared helper.
    pub fn begin_login(&self, return_to: String) -> BeginLogin {
        let client = CoreClient::from_provider_metadata(
            self.metadata.clone(),
            self.client_id.clone(),
            Some(self.client_secret.clone()),
        )
        .set_redirect_uri(self.redirect_uri.clone());

        let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();
        let (authorize_url, csrf_token, nonce) = client
            .authorize_url(
                AuthenticationFlow::<CoreResponseType>::AuthorizationCode,
                CsrfToken::new_random,
                Nonce::new_random,
            )
            .add_scope(Scope::new("openid".to_string()))
            .add_scope(Scope::new("profile".to_string()))
            .add_scope(Scope::new("email".to_string()))
            .set_pkce_challenge(pkce_challenge)
            .url();

        BeginLogin {
            authorize_url: authorize_url.to_string(),
            state: csrf_token.secret().clone(),
            pending: PendingLogin {
                nonce: nonce.secret().clone(),
                pkce_verifier: pkce_verifier.secret().clone(),
                return_to,
                created_at: Instant::now(),
            },
        }
    }

    /// Exchanges the authorization code (with the stored PKCE verifier) and
    /// verifies the returned `id_token`: signature against the realm JWKS, plus
    /// `iss` / `aud` / `exp` and the `nonce` from the pending login.
    pub async fn complete_login(
        &self,
        code: String,
        pending: &PendingLogin,
    ) -> Result<VerifiedUser, LoginError> {
        let client = CoreClient::from_provider_metadata(
            self.metadata.clone(),
            self.client_id.clone(),
            Some(self.client_secret.clone()),
        )
        .set_redirect_uri(self.redirect_uri.clone());
        let token_response = client
            .exchange_code(AuthorizationCode::new(code))
            .map_err(|err| LoginError::Exchange(err.to_string()))?
            .set_pkce_verifier(PkceCodeVerifier::new(pending.pkce_verifier.clone()))
            .request_async(&self.http)
            .await
            .map_err(|err| LoginError::Exchange(err.to_string()))?;

        let id_token = token_response.id_token().ok_or(LoginError::NoIdToken)?;
        let verifier = client.id_token_verifier();
        let nonce = Nonce::new(pending.nonce.clone());
        let claims = id_token
            .claims(&verifier, &nonce)
            .map_err(|err| LoginError::IdToken(err.to_string()))?;

        let now = Utc::now().timestamp();
        let access_expiry_unix = token_response
            .expires_in()
            .and_then(|ttl| i64::try_from(ttl.as_secs()).ok())
            .map(|secs| now + secs)
            .unwrap_or(now);

        Ok(VerifiedUser {
            iss: claims.issuer().as_str().to_string(),
            sub: claims.subject().as_str().to_string(),
            access_token: token_response.access_token().secret().clone(),
            refresh_token: token_response
                .refresh_token()
                .map(|token| token.secret().clone()),
            id_token: id_token.to_string(),
            access_expiry_unix,
        })
    }
}
