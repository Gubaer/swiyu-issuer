use std::sync::Arc;

use sqlx::PgPool;

use super::token_validator::TokenValidator;
use crate::state::ValidatorCache;

pub struct Config {
    /// Public base URL of the wallet-facing OIDC endpoints, used to
    /// build the `credential_offer_uri` in each offer deeplink. The
    /// binary resolves it from `ISSUER_OIDC_HTTP_URL` (falling back to
    /// `ISSUER_BASE_URL`) so the deeplink points the wallet at the OIDC
    /// server, which need not share this binary's port. See
    /// [`resolve_oidc_public_url`][crate::config::resolve_oidc_public_url].
    pub issuer_base_url: String,

    /// Public base URL of the `swiyu-issuer-web` front end, used to build the
    /// invitation link handed to a user. Distinct from `issuer_base_url` (the
    /// wallet-facing host): this is where the human opens the invitation and
    /// authenticates. Sourced from `ISSUER_WEB_BASE_URL`.
    pub web_base_url: String,
}

#[derive(Clone)]
pub struct AppState {
    pub pool: PgPool,
    pub config: Arc<Config>,
    pub validators: Arc<ValidatorCache>,
    /// OAuth2 bearer-JWT validator. `None` disables the JWT path, leaving only
    /// the legacy opaque-token auth — the default when no Keycloak environment
    /// is configured.
    pub jwt_validator: Option<Arc<TokenValidator>>,
}

impl AppState {
    pub fn new(pool: PgPool, config: Config) -> Self {
        Self {
            pool,
            config: Arc::new(config),
            validators: Arc::new(ValidatorCache::new()),
            jwt_validator: None,
        }
    }

    /// Attaches an OAuth2 JWT validator, enabling the resource-server auth
    /// path. Builder-style so existing callers (tests, the OIDC-less setups)
    /// keep using [`AppState::new`] unchanged.
    pub fn with_jwt_validator(mut self, validator: Option<Arc<TokenValidator>>) -> Self {
        self.jwt_validator = validator;
        self
    }
}
