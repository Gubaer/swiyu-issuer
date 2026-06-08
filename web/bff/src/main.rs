mod auth;
mod config;
mod error;
mod routes;
mod upstream;

use std::net::SocketAddr;
use std::sync::Arc;

use swiyu_registries::identifier::IdentifierRegistryClient;
use tracing_subscriber::EnvFilter;

use std::time::Duration;

use crate::auth::{FirstPartyTokenProvider, OidcLoginClient, PendingLogins, UserTokens};
use crate::config::Config;
use crate::routes::AppState;
use crate::upstream::MgmtApiClient;

/// How long an in-flight login (PKCE verifier / nonce) is kept before the sweep
/// evicts it, and how often the sweep runs.
const PENDING_LOGIN_TTL: Duration = Duration::from_secs(600);
const PENDING_SWEEP_INTERVAL: Duration = Duration::from_secs(60);

#[derive(Debug, thiserror::Error)]
enum StartupError {
    #[error("config error: {0}")]
    Config(#[from] config::ConfigError),
    #[error("http client construction failed: {0}")]
    HttpClient(#[from] reqwest::Error),
    #[error("OIDC login client setup failed: {0}")]
    LoginClient(#[from] auth::LoginClientError),
    #[error("identifier registry client construction failed: {0}")]
    Registry(#[from] swiyu_registries::common::RegistryError),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

#[tokio::main]
async fn main() -> Result<(), StartupError> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    let config = Config::from_env()?;

    // Browser-facing endpoints + `iss` come from the public issuer; back-channel
    // endpoints (token, JWKS) come from the internal base. The login client
    // fetches the JWKS now and fails fast if the realm is unreachable.
    let oidc = auth::OidcEndpoints::build(&config.oidc.issuer_url, &config.oidc.internal_url);
    let login = Arc::new(OidcLoginClient::build(&config.oidc, &oidc).await?);
    tracing::info!(issuer = %oidc.issuer, token_endpoint = %oidc.token_endpoint, "OIDC endpoints ready");

    // One HTTP client shared by the token provider and the management-API client.
    let http = reqwest::Client::builder().build()?;
    let first_party = Arc::new(FirstPartyTokenProvider::new(
        http.clone(),
        oidc.token_endpoint.clone(),
        config.oidc.client_id.clone(),
        config.oidc.client_secret.clone(),
    ));
    let user_tokens = Arc::new(UserTokens::new(
        http.clone(),
        oidc.token_endpoint.clone(),
        config.oidc.client_id.clone(),
        config.oidc.client_secret.clone(),
    ));
    let mgmt_api = MgmtApiClient::new(http, &config.mgmtapi_url, first_party);

    let identifier_registry =
        IdentifierRegistryClient::new(config.identifier_registry_url.clone())?;

    // In-flight logins, with a background sweep evicting abandoned entries.
    let pending = Arc::new(PendingLogins::new());
    {
        let pending = pending.clone();
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(PENDING_SWEEP_INTERVAL);
            loop {
                ticker.tick().await;
                pending.sweep(PENDING_LOGIN_TTL);
            }
        });
    }

    let port = config.bff_port;
    let state = AppState {
        config: Arc::new(config),
        mgmt_api,
        identifier_registry: Arc::new(identifier_registry),
        oidc: Arc::new(oidc),
        login,
        pending,
        user_tokens,
    };

    // Bind all interfaces: in the single-container deployment the BFF must
    // be reachable from outside the container, not just loopback.
    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    let listener = tokio::net::TcpListener::bind(addr).await?;
    tracing::info!(%addr, "swiyu-issuer-web-bff listening");

    axum::serve(listener, routes::router(state)).await?;
    Ok(())
}
