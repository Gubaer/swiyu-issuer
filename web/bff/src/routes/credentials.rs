use axum::Json;
use axum::extract::{Path, Query, State};
use serde::Deserialize;
use serde_json::Value;

use super::AppState;
use crate::error::AppError;
use crate::upstream::UserAuth;

#[derive(Debug, Deserialize)]
pub struct ListQuery {
    pub limit: Option<u32>,
    pub cursor: Option<String>,
    pub state: Option<String>,
    pub vct: Option<String>,
}

// Forward the upstream list response verbatim. Unlike credential offers,
// credential records carry no `claims`, so there is nothing to strip.
pub async fn list_credentials(
    State(state): State<AppState>,
    auth: UserAuth,
    Path(issuer_id): Path<String>,
    Query(query): Query<ListQuery>,
) -> Result<Json<Value>, AppError> {
    let payload = state
        .mgmt_api
        .list_issued_credentials(
            &auth,
            &issuer_id,
            query.limit,
            query.cursor.as_deref(),
            query.state.as_deref(),
            query.vct.as_deref(),
        )
        .await?;
    Ok(Json(payload))
}

pub async fn get_credential(
    State(state): State<AppState>,
    auth: UserAuth,
    Path((issuer_id, credential_id)): Path<(String, String)>,
) -> Result<Json<Value>, AppError> {
    let payload = state
        .mgmt_api
        .get_issued_credential(&auth, &issuer_id, &credential_id)
        .await?;
    Ok(Json(payload))
}

// Each lifecycle action takes no request body and returns the updated record
// verbatim. Upstream `404`/`409` (unknown credential, or a disallowed
// transition) propagate through the gateway error mapping.
pub async fn suspend_credential(
    State(state): State<AppState>,
    auth: UserAuth,
    Path((issuer_id, credential_id)): Path<(String, String)>,
) -> Result<Json<Value>, AppError> {
    let payload = state
        .mgmt_api
        .suspend_issued_credential(&auth, &issuer_id, &credential_id)
        .await?;
    Ok(Json(payload))
}

// The UI label is *Resume*, but the management-API verb is *unsuspend*.
pub async fn resume_credential(
    State(state): State<AppState>,
    auth: UserAuth,
    Path((issuer_id, credential_id)): Path<(String, String)>,
) -> Result<Json<Value>, AppError> {
    let payload = state
        .mgmt_api
        .unsuspend_issued_credential(&auth, &issuer_id, &credential_id)
        .await?;
    Ok(Json(payload))
}

pub async fn revoke_credential(
    State(state): State<AppState>,
    auth: UserAuth,
    Path((issuer_id, credential_id)): Path<(String, String)>,
) -> Result<Json<Value>, AppError> {
    let payload = state
        .mgmt_api
        .revoke_issued_credential(&auth, &issuer_id, &credential_id)
        .await?;
    Ok(Json(payload))
}
