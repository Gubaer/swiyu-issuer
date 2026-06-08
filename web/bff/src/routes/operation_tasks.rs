use axum::Json;
use axum::extract::{Path, State};
use serde_json::Value;

use super::AppState;
use crate::error::AppError;
use crate::upstream::UserAuth;

pub async fn get_task(
    State(state): State<AppState>,
    auth: UserAuth,
    Path(task_id): Path<String>,
) -> Result<Json<Value>, AppError> {
    let payload = state.mgmt_api.get_operation_task(&auth, &task_id).await?;
    Ok(Json(payload))
}
