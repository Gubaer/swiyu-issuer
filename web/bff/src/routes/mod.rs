mod auth;
mod credential_offers;
mod credential_types;
mod credentials;
mod issuers;
mod me;
mod operation_tasks;

use std::sync::Arc;

use axum::Router;
use axum::extract::{FromRequestParts, Request, State};
use axum::http::request::Parts;
use axum::middleware::Next;
use axum::response::Response;
use axum::routing::{get, post};
use tower_http::services::{ServeDir, ServeFile};
use tower_http::trace::TraceLayer;
use tower_sessions::cookie::SameSite;
use tower_sessions::cookie::time::Duration as CookieDuration;
use tower_sessions::{Expiry, MemoryStore, Session, SessionManagerLayer};

use chrono::Utc;
use swiyu_registries::identifier::IdentifierRegistryClient;

use crate::auth::{
    OidcEndpoints, OidcLoginClient, PendingLogins, SESSION_DATA_KEY, SessionData, UserTokens,
};
use crate::config::{Config, SessionConfig};
use crate::error::{gateway_error, internal_error, unauthenticated};
use crate::upstream::{MgmtApiClient, UserAuth};

#[derive(Clone)]
pub struct AppState {
    pub config: Arc<Config>,
    pub mgmt_api: MgmtApiClient,
    pub identifier_registry: Arc<IdentifierRegistryClient>,
    /// Realm endpoints discovered at startup; consumed by the auth routes
    /// (login / callback / logout) and the token-exchange grant.
    pub oidc: Arc<OidcEndpoints>,
    /// The OIDC authorization-code login client.
    pub login: Arc<OidcLoginClient>,
    /// In-flight logins (state → PKCE verifier / nonce / return_to).
    pub pending: Arc<PendingLogins>,
    /// Per-user grants: refreshing the user's access token and exchanging it for
    /// an mgmtapi act-as-user token.
    pub user_tokens: Arc<UserTokens>,
}

pub fn router(state: AppState) -> Router {
    let spa_dir = state.config.spa_dir.clone();
    let session_layer = build_session_layer(&state.config.session);

    // Guarded: every data route behind the auth middleware (loads the session,
    // requires a selected account, else 401).
    let guarded = Router::new()
        .route(
            "/api/issuers",
            get(issuers::list_issuers).post(issuers::create_issuer),
        )
        .route("/api/issuers/{issuer_id}", get(issuers::get_issuer))
        .route(
            "/api/issuers/{issuer_id}/did-log",
            get(issuers::get_did_log),
        )
        .route(
            "/api/issuers/{issuer_id}/deactivate",
            post(issuers::deactivate_issuer),
        )
        .route(
            "/api/issuers/{issuer_id}/rotate-keys",
            post(issuers::rotate_keys),
        )
        .route(
            "/api/operation-tasks/{task_id}",
            get(operation_tasks::get_task),
        )
        .route(
            "/api/issuers/{issuer_id}/credential-offers",
            get(credential_offers::list_credential_offers)
                .post(credential_offers::create_credential_offer),
        )
        .route(
            "/api/issuers/{issuer_id}/credential-offers/{offer_id}",
            get(credential_offers::get_credential_offer),
        )
        .route(
            "/api/issuers/{issuer_id}/credential-offers/{offer_id}/cancel",
            post(credential_offers::cancel_credential_offer),
        )
        .route(
            "/api/issuers/{issuer_id}/credentials",
            get(credentials::list_credentials),
        )
        .route(
            "/api/issuers/{issuer_id}/credentials/{credential_id}",
            get(credentials::get_credential),
        )
        .route(
            "/api/issuers/{issuer_id}/credentials/{credential_id}/suspend",
            post(credentials::suspend_credential),
        )
        .route(
            "/api/issuers/{issuer_id}/credentials/{credential_id}/unsuspend",
            post(credentials::resume_credential),
        )
        .route(
            "/api/issuers/{issuer_id}/credentials/{credential_id}/revoke",
            post(credentials::revoke_credential),
        )
        .route(
            "/api/issuers/{issuer_id}/credential-types",
            get(credential_types::list_credential_types),
        )
        .route(
            "/api/credential-types/{credential_type_id}/schema",
            get(credential_types::get_credential_type_schema),
        )
        .route_layer(axum::middleware::from_fn_with_state(
            state.clone(),
            require_session,
        ));

    // Unguarded: /api/me answers for anonymous callers; the auth routes run the
    // login handshake / logout / account switch and must not sit behind the
    // session guard (select-account self-checks the session).
    let unguarded = Router::new()
        .route("/api/me", get(me::get_me))
        .route("/api/auth/login", get(auth::login))
        .route("/api/auth/callback", get(auth::callback))
        .route("/api/auth/logout", get(auth::logout))
        .route("/api/auth/select-account", post(auth::select_account));

    let api = guarded.merge(unguarded).with_state(state);

    // With SPA_DIR set, the BFF also serves the built SPA (single-container
    // prod), falling back to index.html for client-side routes. Unset means
    // `ng serve` owns the SPA and only `/api` is served here.
    let app = match spa_dir {
        Some(dir) => {
            let index = format!("{dir}/index.html");
            api.fallback_service(ServeDir::new(&dir).fallback(ServeFile::new(index)))
        }
        None => api,
    };

    app.layer(session_layer).layer(TraceLayer::new_for_http())
}

/// Builds the cookie/session layer from config. The cookie carries only an
/// opaque session id; all state is server-side in the in-memory store.
fn build_session_layer(cfg: &SessionConfig) -> SessionManagerLayer<MemoryStore> {
    let store = MemoryStore::default();
    // `__Host-` requires Secure + Path=/ + no Domain; only valid under TLS.
    let cookie_name = if cfg.cookie_secure {
        "__Host-swiyu_session"
    } else {
        "swiyu_session"
    };
    SessionManagerLayer::new(store)
        .with_secure(cfg.cookie_secure)
        .with_http_only(true)
        .with_same_site(SameSite::Lax)
        .with_name(cookie_name)
        .with_path("/".to_string())
        .with_expiry(Expiry::OnInactivity(CookieDuration::seconds(
            cfg.idle_timeout_secs as i64,
        )))
}

/// Auth middleware for the guarded routes: require a live session with a
/// selected account, else `401`. The handlers obtain the act-as-user token via
/// the [`UserAuth`] extractor, which re-reads the session.
async fn require_session(
    State(state): State<AppState>,
    session: Session,
    req: Request,
    next: Next,
) -> Response {
    let data = match session.get::<SessionData>(SESSION_DATA_KEY).await {
        Ok(Some(data)) => data,
        // No session, or expired — routine "not logged in", no log.
        Ok(None) => return unauthenticated(),
        // The store errored: a server fault, not "log in again", so 500 (not 401).
        Err(err) => {
            tracing::error!(%err, "failed to read session");
            return internal_error();
        }
    };
    let timeout = state.config.session.absolute_timeout_secs as i64;
    if data.is_live(Utc::now().timestamp(), timeout) && data.selected().is_some() {
        next.run(req).await
    } else {
        unauthenticated()
    }
}

/// Request extractor that yields the act-as-user authorization for a
/// management-API call: it reads the session, refreshes the user's Keycloak
/// access token if it has expired (persisting the rotation), then exchanges it
/// (RFC 8693) for an mgmtapi token. The selected account becomes `X-User-Account`.
impl FromRequestParts<AppState> for UserAuth {
    type Rejection = Response;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let session = Session::from_request_parts(parts, state)
            .await
            .map_err(|_| internal_error())?;

        let mut data: SessionData = match session.get(SESSION_DATA_KEY).await {
            Ok(Some(data)) => data,
            Ok(None) => return Err(unauthenticated()),
            Err(err) => {
                tracing::error!(%err, "failed to read session");
                return Err(internal_error());
            }
        };

        // Renew the user's access token if it has reached expiry, persisting the
        // rotated tokens. A failed refresh means the session is effectively over.
        if Utc::now().timestamp() >= data.kc_access_expiry_unix {
            match state.user_tokens.refresh(&data.kc_refresh_token).await {
                Ok(refreshed) => {
                    data.kc_access_token = refreshed.access_token;
                    data.kc_refresh_token = refreshed.refresh_token;
                    data.kc_access_expiry_unix = refreshed.access_expiry_unix;
                    if let Err(err) = session.insert(SESSION_DATA_KEY, &data).await {
                        tracing::error!(%err, "session insert failed");
                        return Err(internal_error());
                    }
                }
                Err(err) => {
                    tracing::warn!(%err, "user token refresh failed; session expired");
                    return Err(unauthenticated());
                }
            }
        }

        let bearer = state
            .user_tokens
            .exchange_for_mgmtapi(&data.kc_access_token)
            .await
            .map_err(|err| {
                tracing::error!(%err, "act-as-user token exchange failed");
                gateway_error("upstream authentication failed")
            })?;

        Ok(UserAuth {
            bearer,
            account_id: data.selected_account_id,
        })
    }
}
