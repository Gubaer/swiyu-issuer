//! The OIDC authorization-code login client (the user login).
//!
//! Built from explicit endpoint URLs rather than discovery, so the **browser**
//! endpoint (authorize) can use the public issuer while the **back-channel**
//! endpoint (token) and the JWKS use the in-network base — see
//! [`super::oidc::OidcEndpoints`]. `id_token` verification checks `iss` against
//! the public issuer and the signature against the JWKS fetched at startup.

use std::time::Instant;

use chrono::Utc;
use openidconnect::core::{
    CoreClient, CoreIdToken, CoreIdTokenVerifier, CoreJsonWebKeySet, CoreJwsSigningAlgorithm,
    CoreResponseType,
};
use openidconnect::{
    AuthUrl, AuthenticationFlow, AuthorizationCode, ClientId, ClientSecret, CsrfToken, IssuerUrl,
    JsonWebKeySetUrl, Nonce, OAuth2TokenResponse, PkceCodeChallenge, PkceCodeVerifier, RedirectUrl,
    TokenResponse, TokenUrl, reqwest,
};

use super::oidc::OidcEndpoints;
use super::pending::PendingLogin;
use crate::config::OidcConfig;

#[derive(Debug, thiserror::Error)]
pub enum LoginClientError {
    #[error("invalid OIDC configuration: {0}")]
    Config(String),
    #[error("could not build the OIDC http client: {0}")]
    HttpClient(String),
    #[error("could not fetch the realm JWKS: {0}")]
    Jwks(String),
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

/// What [`OidcLoginClient::begin_login`] produced: the URL to redirect the
/// browser to, the CSRF `state` (the pending-login key), and the pending secrets.
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

/// `openidconnect`-backed client for the authorization-code login. Holds the
/// browser-facing authorize URL, the back-channel token URL, the public issuer
/// (for `iss` verification), and the JWKS fetched at startup; the per-request
/// `CoreClient` is rebuilt from these (cheap, no I/O).
pub struct OidcLoginClient {
    auth_url: AuthUrl,
    token_url: TokenUrl,
    issuer: IssuerUrl,
    jwks: CoreJsonWebKeySet,
    client_id: ClientId,
    client_secret: ClientSecret,
    redirect_uri: RedirectUrl,
    http: reqwest::Client,
}

impl OidcLoginClient {
    /// Builds the login client at startup, fetching the realm JWKS from the
    /// in-network JWKS endpoint (fail fast if the realm is unreachable).
    pub async fn build(
        cfg: &OidcConfig,
        endpoints: &OidcEndpoints,
    ) -> Result<Self, LoginClientError> {
        let issuer = IssuerUrl::new(endpoints.issuer.clone())
            .map_err(|err| LoginClientError::Config(err.to_string()))?;
        let auth_url = AuthUrl::new(endpoints.authorize_endpoint.clone())
            .map_err(|err| LoginClientError::Config(err.to_string()))?;
        let token_url = TokenUrl::new(endpoints.token_endpoint.clone())
            .map_err(|err| LoginClientError::Config(err.to_string()))?;
        let jwks_url = JsonWebKeySetUrl::new(endpoints.jwks_uri.clone())
            .map_err(|err| LoginClientError::Config(err.to_string()))?;
        let redirect_uri = RedirectUrl::new(cfg.redirect_uri.clone())
            .map_err(|err| LoginClientError::Config(err.to_string()))?;

        // OAuth requests must not follow redirects.
        let http = reqwest::ClientBuilder::new()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|err| LoginClientError::HttpClient(err.to_string()))?;

        let jwks = CoreJsonWebKeySet::fetch_async(&jwks_url, &http)
            .await
            .map_err(|err| LoginClientError::Jwks(err.to_string()))?;

        Ok(Self {
            auth_url,
            token_url,
            issuer,
            jwks,
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
    /// The configured client's endpoint-typestate is unnameable, so it is built
    /// inline here and in `complete_login`.
    pub fn begin_login(&self, return_to: String) -> BeginLogin {
        let client = CoreClient::new(
            self.client_id.clone(),
            self.issuer.clone(),
            self.jwks.clone(),
        )
        .set_client_secret(self.client_secret.clone())
        .set_auth_uri(self.auth_url.clone())
        .set_token_uri(self.token_url.clone())
        .set_redirect_uri(self.redirect_uri.clone());

        let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();
        let (authorize_url, csrf_token, nonce) = client
            .authorize_url(
                AuthenticationFlow::<CoreResponseType>::AuthorizationCode,
                CsrfToken::new_random,
                Nonce::new_random,
            )
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

    /// Exchanges the authorization code (with the stored PKCE verifier) at the
    /// back-channel token endpoint and verifies the returned `id_token`:
    /// signature against the JWKS, plus `iss` / `aud` / `exp` and the `nonce`.
    pub async fn complete_login(
        &self,
        code: String,
        pending: &PendingLogin,
    ) -> Result<VerifiedUser, LoginError> {
        let client = CoreClient::new(
            self.client_id.clone(),
            self.issuer.clone(),
            self.jwks.clone(),
        )
        .set_client_secret(self.client_secret.clone())
        .set_auth_uri(self.auth_url.clone())
        .set_token_uri(self.token_url.clone())
        .set_redirect_uri(self.redirect_uri.clone());

        let token_response = client
            .exchange_code(AuthorizationCode::new(code))
            .set_pkce_verifier(PkceCodeVerifier::new(pending.pkce_verifier.clone()))
            .request_async(&self.http)
            .await
            .map_err(|err| LoginError::Exchange(err.to_string()))?;

        let id_token = token_response.id_token().ok_or(LoginError::NoIdToken)?;
        let nonce = Nonce::new(pending.nonce.clone());
        let (iss, sub) = verify_id_token(
            &self.client_id,
            &self.client_secret,
            &self.issuer,
            &self.jwks,
            id_token,
            &nonce,
        )?;

        let now = Utc::now().timestamp();
        let access_expiry_unix = token_response
            .expires_in()
            .and_then(|ttl| i64::try_from(ttl.as_secs()).ok())
            .map(|secs| now + secs)
            .unwrap_or(now);

        Ok(VerifiedUser {
            iss,
            sub,
            access_token: token_response.access_token().secret().clone(),
            refresh_token: token_response
                .refresh_token()
                .map(|token| token.secret().clone()),
            id_token: id_token.to_string(),
            access_expiry_unix,
        })
    }
}

/// Verifies an `id_token`: signature against `jwks`, `iss` against `issuer`,
/// `aud` against `client_id`, plus `exp` and the `nonce`. EdDSA (Ed25519) is
/// allowed explicitly — the realm signs with it, and without provider metadata
/// the verifier would default to RS256 and reject the signature. Returns the
/// verified `(iss, sub)`.
fn verify_id_token(
    client_id: &ClientId,
    client_secret: &ClientSecret,
    issuer: &IssuerUrl,
    jwks: &CoreJsonWebKeySet,
    id_token: &CoreIdToken,
    nonce: &Nonce,
) -> Result<(String, String), LoginError> {
    let verifier = CoreIdTokenVerifier::new_confidential_client(
        client_id.clone(),
        client_secret.clone(),
        issuer.clone(),
        jwks.clone(),
    )
    .set_allowed_algs([CoreJwsSigningAlgorithm::EdDsa]);
    let claims = id_token
        .claims(&verifier, nonce)
        .map_err(|err| LoginError::IdToken(err.to_string()))?;
    Ok((
        claims.issuer().as_str().to_string(),
        claims.subject().as_str().to_string(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;
    use openidconnect::core::{CoreEdDsaPrivateSigningKey, CoreIdTokenClaims};
    use openidconnect::{
        Audience, EmptyAdditionalClaims, JsonWebKeyId, PrivateSigningKey, StandardClaims,
        SubjectIdentifier,
    };

    // A fixed Ed25519 key for the test, so the realm's signing algorithm (EdDSA /
    // Ed25519) is exercised end to end without a network or a live realm.
    const ED25519_PEM: &str = "-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEIE4JfFesXOv0UFvoqI9lfTLPlBud4SbG5YU1byKdYO5q\n-----END PRIVATE KEY-----\n";

    const ISSUER: &str = "http://localhost:8083/realms/swiyu-issuer";
    const CLIENT_ID: &str = "swiyu-issuer-web-bff";

    /// Mints an EdDSA-signed `id_token` and the matching JWKS, then verifies it.
    /// With `allow_eddsa = false` the verifier keeps openidconnect's default algs
    /// (RS256) — the regression case the fix guards against.
    fn mint_and_verify(allow_eddsa: bool) -> Result<(String, String), LoginError> {
        let issuer = IssuerUrl::new(ISSUER.to_string()).unwrap();
        let client_id = ClientId::new(CLIENT_ID.to_string());
        let client_secret = ClientSecret::new("dev-bff-secret".to_string());
        let nonce = Nonce::new("test-nonce".to_string());

        let signing_key = CoreEdDsaPrivateSigningKey::from_ed25519_pem(
            ED25519_PEM,
            Some(JsonWebKeyId::new("test-kid".to_string())),
        )
        .expect("valid Ed25519 PEM");
        let jwks = CoreJsonWebKeySet::new(vec![signing_key.as_verification_key()]);

        let claims = CoreIdTokenClaims::new(
            issuer.clone(),
            vec![Audience::new(client_id.to_string())],
            Utc::now() + Duration::hours(1),
            Utc::now(),
            StandardClaims::new(SubjectIdentifier::new("user-123".to_string())),
            EmptyAdditionalClaims {},
        )
        .set_nonce(Some(nonce.clone()));

        let id_token = CoreIdToken::new(
            claims,
            &signing_key,
            CoreJwsSigningAlgorithm::EdDsa,
            None,
            None,
        )
        .expect("signs the id_token");

        if allow_eddsa {
            verify_id_token(
                &client_id,
                &client_secret,
                &issuer,
                &jwks,
                &id_token,
                &nonce,
            )
        } else {
            let verifier = CoreIdTokenVerifier::new_confidential_client(
                client_id,
                client_secret,
                issuer,
                jwks,
            );
            id_token
                .claims(&verifier, &nonce)
                .map(|c| {
                    (
                        c.issuer().as_str().to_string(),
                        c.subject().as_str().to_string(),
                    )
                })
                .map_err(|err| LoginError::IdToken(err.to_string()))
        }
    }

    #[test]
    fn verifies_an_eddsa_signed_id_token() {
        let (iss, sub) = mint_and_verify(true).expect("EdDSA id_token must verify");
        assert_eq!(iss, ISSUER);
        assert_eq!(sub, "user-123");
    }

    #[test]
    fn rejects_eddsa_when_the_alg_is_not_allowed() {
        // Without set_allowed_algs([EdDsa]) the verifier defaults to RS256 and
        // rejects the EdDSA signature — this is the regression the fix prevents.
        assert!(mint_and_verify(false).is_err());
    }
}
