mod auth;
mod credential_offers;
mod credential_types;
mod issuers;
mod me;
mod operation_tasks;

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::Json;
use axum::Router;
use axum::extract::{Request, State};
use axum::http::StatusCode;
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use serde_json::json;
use tower_http::services::{ServeDir, ServeFile};
use tower_http::trace::TraceLayer;
use tower_sessions::cookie::SameSite;
use tower_sessions::cookie::time::Duration as CookieDuration;
use tower_sessions::{Expiry, MemoryStore, Session, SessionManagerLayer};

use swiyu_registries::identifier::IdentifierRegistryClient;

use crate::auth::{OidcEndpoints, OidcLoginClient, PendingLogins, SESSION_DATA_KEY, SessionData};
use crate::config::{Config, SessionConfig};
use crate::upstream::MgmtApiClient;

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
/// selected account, and stash it in the request extensions for the handlers
/// (the act-as-user path in step 4 reads it from there). Otherwise `401`.
async fn require_session(
    State(state): State<AppState>,
    session: Session,
    mut req: Request,
    next: Next,
) -> Response {
    let data: Option<SessionData> = session.get(SESSION_DATA_KEY).await.unwrap_or(None);
    match data {
        Some(data) if session_is_live(&data, &state) && data.selected().is_some() => {
            req.extensions_mut().insert(Arc::new(data));
            next.run(req).await
        }
        _ => unauthenticated(),
    }
}

/// Absolute-lifetime check (idle timeout is enforced by the cookie expiry).
fn session_is_live(data: &SessionData, state: &AppState) -> bool {
    let absolute = data
        .logged_in_at_unix
        .saturating_add(state.config.session.absolute_timeout_secs as i64);
    now_unix() < absolute
}

pub(crate) fn unauthenticated() -> Response {
    (
        StatusCode::UNAUTHORIZED,
        Json(json!({ "error": "unauthenticated" })),
    )
        .into_response()
}

pub(crate) fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}
