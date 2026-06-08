use axum::Json;
use axum::response::{IntoResponse, Response};
use serde::Serialize;
use tower_sessions::Session;

use crate::auth::{SESSION_DATA_KEY, SessionAccount, SessionData};
use crate::error::{internal_error, unauthenticated};

#[derive(Serialize)]
struct Identity {
    iss: String,
    sub: String,
}

#[derive(Serialize)]
struct MeResponse {
    /// The logged-in federated identity.
    identity: Identity,
    /// The account the user is currently acting as.
    selected_account: SessionAccount,
    /// All active accounts the identity is linked to, for the picker.
    accounts: Vec<SessionAccount>,
}

/// `GET /api/me` — the current session, or `401` when not logged in. Unguarded:
/// the SPA calls this to decide whether to show the app or redirect to `/login`.
pub async fn get_me(session: Session) -> Response {
    let data: SessionData = match session.get(SESSION_DATA_KEY).await {
        Ok(Some(data)) => data,
        Ok(None) => return unauthenticated(),
        Err(err) => {
            tracing::error!(%err, "failed to read session");
            return internal_error();
        }
    };

    let Some(selected_account) = data.selected().cloned() else {
        // A session whose selected account no longer resolves to one of its
        // accounts is inconsistent (it should always resolve). Recover as
        // not-logged-in so the SPA recovers via /login.
        tracing::warn!(
            selected_account_id = %data.selected_account_id,
            "session has an unresolvable selected account"
        );
        return unauthenticated();
    };

    Json(MeResponse {
        identity: Identity {
            iss: data.iss,
            sub: data.sub,
        },
        selected_account,
        accounts: data.accounts,
    })
    .into_response()
}
