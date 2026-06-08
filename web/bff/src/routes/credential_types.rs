use axum::Json;
use axum::extract::{Path, State};
use serde_json::Value;

use super::AppState;
use crate::error::AppError;
use crate::upstream::UserAuth;

pub async fn list_credential_types(
    State(state): State<AppState>,
    auth: UserAuth,
    Path(issuer_id): Path<String>,
) -> Result<Json<Value>, AppError> {
    let payload = state
        .mgmt_api
        .list_credential_types(&auth, &issuer_id)
        .await?;
    Ok(Json(payload))
}

pub async fn get_credential_type_schema(
    State(state): State<AppState>,
    auth: UserAuth,
    Path(credential_type_id): Path<String>,
) -> Result<Json<Value>, AppError> {
    let payload = state
        .mgmt_api
        .get_credential_type_schema(&auth, &credential_type_id)
        .await?;
    Ok(Json(payload))
}
