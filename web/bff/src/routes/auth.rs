//! Auth routes: the OIDC login handshake, single sign-out, and account
//! selection.

use axum::extract::{Query, State};
use axum::response::{IntoResponse, Redirect, Response};
use axum::{Json, http::StatusCode};
use serde::Deserialize;
use serde_json::{Value, json};
use tower_sessions::Session;
use url::Url;

use crate::auth::{SESSION_DATA_KEY, SessionAccount, SessionData};

use super::{AppState, now_unix, unauthenticated};

#[derive(Debug, Deserialize)]
pub struct LoginQuery {
    pub return_to: Option<String>,
}

/// `GET /api/auth/login` — start the authorization-code flow.
pub async fn login(State(state): State<AppState>, Query(query): Query<LoginQuery>) -> Response {
    let return_to = sanitize_return_to(query.return_to.as_deref());
    let begin = state.login.begin_login(return_to);
    state.pending.insert(begin.state.clone(), begin.pending);
    Redirect::to(&begin.authorize_url).into_response()
}

#[derive(Debug, Deserialize)]
pub struct CallbackQuery {
    pub code: Option<String>,
    pub state: Option<String>,
    /// The realm sends `error` (and often `error_description`) instead of `code`
    /// when the user denies consent or the request is rejected.
    pub error: Option<String>,
    pub error_description: Option<String>,
}

/// `GET /api/auth/callback` — complete the flow: verify the `id_token`, resolve
/// the identity to its accounts, establish the session.
pub async fn callback(
    State(state): State<AppState>,
    session: Session,
    Query(query): Query<CallbackQuery>,
) -> Response {
    if let Some(realm_error) = &query.error {
        tracing::warn!(
            realm_error = %realm_error,
            error_description = ?query.error_description,
            "authorization request rejected by the realm",
        );
        return login_error("idp");
    }
    let (Some(code), Some(csrf_state)) = (query.code, query.state) else {
        // No `error`, yet missing `code` or `state`: a malformed callback or a
        // direct hit on the endpoint, not a real flow. The authorization code is
        // a secret, so it is not logged.
        tracing::warn!("callback missing code or state");
        return login_error("state");
    };
    let Some(pending) = state.pending.take(&csrf_state) else {
        // Unknown / expired / already-consumed state: an expired login, a BFF
        // restart that cleared the pending map, a double-submit — or a forged
        // callback (which is exactly what the state check defends against).
        // Suspicious but not a server fault, so `warn`. The raw state is a CSRF
        // token, so it is not logged.
        tracing::warn!("callback presented an unknown or expired state");
        return login_error("state");
    };

    let verified = match state.login.complete_login(code, &pending).await {
        Ok(verified) => verified,
        Err(err) => {
            tracing::warn!(%err, "login completion failed");
            return login_error("idp");
        }
    };

    let resolved = match state
        .mgmt_api
        .resolve_linked_accounts(&verified.iss, &verified.sub)
        .await
    {
        Ok(resolved) => resolved,
        Err(err) => {
            tracing::error!(%err, "identity resolution failed");
            return login_error("unavailable");
        }
    };

    let accounts = active_accounts(&resolved);
    let Some(first) = accounts.first() else {
        return login_error("no_access");
    };
    let selected_account_id = first.id.clone();

    let data = SessionData {
        iss: verified.iss,
        sub: verified.sub,
        kc_access_token: verified.access_token,
        kc_refresh_token: verified.refresh_token.unwrap_or_default(),
        kc_id_token: verified.id_token,
        kc_access_expiry_unix: verified.access_expiry_unix,
        logged_in_at_unix: now_unix(),
        accounts,
        selected_account_id,
    };

    if let Err(err) = session.insert(SESSION_DATA_KEY, &data).await {
        tracing::error!(%err, "session insert failed");
        return login_error("unavailable");
    }

    Redirect::to(&pending.return_to).into_response()
}

/// `GET /api/auth/logout` — single sign-out: clear the local session, then
/// redirect through the realm's end-session endpoint (RP-initiated logout).
pub async fn logout(State(state): State<AppState>, session: Session) -> Response {
    let id_token_hint = session
        .get::<SessionData>(SESSION_DATA_KEY)
        .await
        .ok()
        .flatten()
        .map(|data| data.kc_id_token);

    // Clear the server-side session and expire the cookie. A store failure means
    // the session may outlive the logout, so it is logged rather than swallowed.
    if let Err(err) = session.delete().await {
        tracing::error!(%err, "failed to clear session on logout");
    }

    let post_logout = &state.config.oidc.post_logout_redirect_uri;
    let Some(endpoint) = &state.oidc.end_session_endpoint else {
        // No RP-initiated logout advertised: local clear only.
        return Redirect::to(post_logout).into_response();
    };
    let Ok(mut url) = Url::parse(endpoint) else {
        // Discovery handed us a malformed end_session_endpoint; degrade to a
        // local logout. The endpoint URL is not a secret, so log it.
        tracing::error!(endpoint = %endpoint, "end_session_endpoint is not a valid URL; logging out locally");
        return Redirect::to(post_logout).into_response();
    };
    url.query_pairs_mut()
        .append_pair("post_logout_redirect_uri", post_logout);
    if let Some(hint) = &id_token_hint {
        url.query_pairs_mut().append_pair("id_token_hint", hint);
    }
    Redirect::to(url.as_str()).into_response()
}

#[derive(Debug, Deserialize)]
pub struct SelectAccountRequest {
    pub account_id: String,
}

/// `POST /api/auth/select-account` — switch the session's selected account.
pub async fn select_account(
    State(_state): State<AppState>,
    session: Session,
    Json(request): Json<SelectAccountRequest>,
) -> Response {
    let mut data = match session.get::<SessionData>(SESSION_DATA_KEY).await {
        Ok(Some(data)) => data,
        // No session: genuinely not logged in.
        Ok(None) => return unauthenticated(),
        // The store errored: a server fault, not "log in again", so 500 (not 401).
        Err(err) => {
            tracing::error!(%err, "failed to read session");
            return internal_error();
        }
    };

    if !data.accounts.iter().any(|a| a.id == request.account_id) {
        return bad_request("unknown account");
    }

    data.selected_account_id = request.account_id;
    let selected = data.selected().cloned();

    if let Err(err) = session.insert(SESSION_DATA_KEY, &data).await {
        tracing::error!(%err, "session insert failed");
        return internal_error();
    }

    match selected {
        // `SessionAccount` derives `Serialize` to exactly the wire shape.
        Some(account) => Json(account).into_response(),
        // Unreachable: account_id was just validated against `accounts` and set
        // as the selection, so `selected()` must resolve. Reaching here means an
        // internal invariant broke.
        None => {
            tracing::error!("selected account missing after validation");
            internal_error()
        }
    }
}

/// Validates `return_to` is a same-origin path: it must start with a single `/`
/// (not `//`, which a browser reads as a protocol-relative cross-origin URL).
fn sanitize_return_to(raw: Option<&str>) -> String {
    match raw {
        Some(path) if path.starts_with('/') && !path.starts_with("//") => path.to_string(),
        _ => "/".to_string(),
    }
}

fn login_error(code: &str) -> Response {
    tracing::debug!(error = code, "login failed; redirecting to /login");
    Redirect::to(&format!("/login?error={code}")).into_response()
}

fn internal_error() -> Response {
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(json!({ "error": "internal" })),
    )
        .into_response()
}

fn bad_request(error: &str) -> Response {
    (StatusCode::BAD_REQUEST, Json(json!({ "error": error }))).into_response()
}

/// Maps the mgmtapi resolve response to the session's active-account list. Only
/// `state == "active"` accounts can be logged into.
fn active_accounts(resolved: &Value) -> Vec<SessionAccount> {
    let Some(items) = resolved.get("items").and_then(|v| v.as_array()) else {
        return Vec::new();
    };
    items
        .iter()
        .filter(|item| item.get("state").and_then(|v| v.as_str()) == Some("active"))
        .filter_map(|item| {
            let id = item.get("id")?.as_str()?.to_string();
            let tenant_id = item.get("tenant_id")?.as_str()?.to_string();
            let tenant_display_name = item
                .get("tenant_display_name")
                .and_then(|v| v.as_str())
                .map(str::to_string);
            Some(SessionAccount {
                id,
                tenant_id,
                tenant_display_name,
                display_name: display_name(item),
            })
        })
        .collect()
}

/// Label for an account: the IDP-asserted name, else the provisioning name, else
/// the bare id.
fn display_name(item: &Value) -> String {
    let field = |key: &str| {
        item.get(key)
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty())
    };
    let join = |first: Option<&str>, last: Option<&str>| -> Option<String> {
        let parts: Vec<&str> = [first, last].into_iter().flatten().collect();
        (!parts.is_empty()).then(|| parts.join(" "))
    };
    join(field("idp_first_name"), field("idp_last_name"))
        .or_else(|| {
            join(
                field("provisioning_first_name"),
                field("provisioning_last_name"),
            )
        })
        .or_else(|| field("id").map(str::to_string))
        .unwrap_or_default()
}
