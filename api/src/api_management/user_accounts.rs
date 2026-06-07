//! HTTP handlers for the user-account management endpoints (tenant-scoped).

use axum::Json;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use chrono::Utc;

use crate::domain::{UserAccount, UserAccountId, UserAccountState};
use crate::persistence;
use crate::persistence::user_accounts::ListPageQuery;

use super::AppState;
use super::auth::TenantContext;
use super::dto::{
    CreateUserAccountRequest, CreateUserAccountResponse, ListUserAccountsQuery,
    ListUserAccountsResponse, PatchUserAccountRequest, UserAccountResponse, UserIdentityResponse,
};
use super::error::ApiError;

/// Cap on the provisioning free-text fields after trim — API hygiene only; the
/// columns are unbounded TEXT.
const MAX_FIELD_LENGTH: usize = 255;

/// `POST /api/v1/user-accounts`
pub async fn create(
    State(state): State<AppState>,
    tenant_context: TenantContext,
    Json(payload): Json<CreateUserAccountRequest>,
) -> Result<(StatusCode, Json<CreateUserAccountResponse>), ApiError> {
    let provisioning_first_name = super::normalise_optional(
        "provisioning_first_name",
        payload.provisioning_first_name.as_deref(),
        MAX_FIELD_LENGTH,
    )?;
    let provisioning_last_name = super::normalise_optional(
        "provisioning_last_name",
        payload.provisioning_last_name.as_deref(),
        MAX_FIELD_LENGTH,
    )?;
    let provisioning_home_organization = super::normalise_optional(
        "provisioning_home_organization",
        payload.provisioning_home_organization.as_deref(),
        MAX_FIELD_LENGTH,
    )?;

    let id = UserAccountId::generate();
    let account = UserAccount {
        id: id.clone(),
        tenant_id: tenant_context.tenant_id.clone(),
        provisioning_first_name,
        provisioning_last_name,
        provisioning_home_organization,
        state: UserAccountState::Active,
        identity: None,
        idp_first_name: None,
        idp_last_name: None,
        linked_at: None,
        created_at: Utc::now(),
    };

    let mut conn = state
        .pool
        .acquire()
        .await
        .map_err(|err| ApiError::Internal(Box::new(err)))?;
    persistence::user_accounts::insert(&mut conn, &account).await?;

    Ok((
        StatusCode::CREATED,
        Json(CreateUserAccountResponse {
            user_account_id: id.bare().to_string(),
        }),
    ))
}

/// `GET /api/v1/user-accounts`
pub async fn list(
    State(state): State<AppState>,
    Query(query): Query<ListUserAccountsQuery>,
    tenant_context: TenantContext,
) -> Result<Json<ListUserAccountsResponse>, ApiError> {
    let limit = super::resolve_list_limit(query.limit)?;
    let decoded_cursor = query
        .cursor
        .as_deref()
        .map(|raw| super::cursor::decode(raw, |bare| UserAccountId::from_bare(bare).map(|_| ())))
        .transpose()?;

    let mut conn = state
        .pool
        .acquire()
        .await
        .map_err(|err| ApiError::Internal(Box::new(err)))?;

    let page = persistence::user_accounts::list_by_tenant(
        &mut conn,
        &tenant_context.tenant_id,
        ListPageQuery {
            cursor: decoded_cursor.map(|c| (c.timestamp, c.bare_id)),
            limit,
        },
    )
    .await?;

    let next_cursor = if page.has_more {
        page.items
            .last()
            .map(|a| super::cursor::encode(a.created_at, a.id.bare()))
    } else {
        None
    };

    let items = page
        .items
        .into_iter()
        .map(user_account_to_response)
        .collect();
    Ok(Json(ListUserAccountsResponse { items, next_cursor }))
}

/// `GET /api/v1/user-accounts/{id}`
pub async fn get(
    State(state): State<AppState>,
    Path(id_str): Path<String>,
    tenant_context: TenantContext,
) -> Result<Json<UserAccountResponse>, ApiError> {
    let id = super::parse_user_account_id(&id_str)?;
    let mut conn = state
        .pool
        .acquire()
        .await
        .map_err(|err| ApiError::Internal(Box::new(err)))?;

    let account = persistence::user_accounts::get(&mut conn, &tenant_context.tenant_id, &id)
        .await?
        .ok_or(ApiError::NotFound)?;
    Ok(Json(user_account_to_response(account)))
}

/// `PATCH /api/v1/user-accounts/{id}`
///
/// Updates the provisioning attributes
pub async fn patch(
    State(state): State<AppState>,
    Path(id_str): Path<String>,
    tenant_context: TenantContext,
    Json(payload): Json<PatchUserAccountRequest>,
) -> Result<Json<UserAccountResponse>, ApiError> {
    let id = super::parse_user_account_id(&id_str)?;
    let first = super::normalise_optional(
        "provisioning_first_name",
        payload.provisioning_first_name.as_deref(),
        MAX_FIELD_LENGTH,
    )?;
    let last = super::normalise_optional(
        "provisioning_last_name",
        payload.provisioning_last_name.as_deref(),
        MAX_FIELD_LENGTH,
    )?;
    let home = super::normalise_optional(
        "provisioning_home_organization",
        payload.provisioning_home_organization.as_deref(),
        MAX_FIELD_LENGTH,
    )?;

    let mut conn = state
        .pool
        .acquire()
        .await
        .map_err(|err| ApiError::Internal(Box::new(err)))?;

    let account = persistence::user_accounts::get(&mut conn, &tenant_context.tenant_id, &id)
        .await?
        .ok_or(ApiError::NotFound)?;

    // Merge: a provided value wins; otherwise keep the stored one.
    let provisioning_first_name = first.or(account.provisioning_first_name);
    let provisioning_last_name = last.or(account.provisioning_last_name);
    let provisioning_home_organization = home.or(account.provisioning_home_organization);

    persistence::user_accounts::update_provisioning(
        &mut conn,
        &tenant_context.tenant_id,
        &id,
        provisioning_first_name.as_deref(),
        provisioning_last_name.as_deref(),
        provisioning_home_organization.as_deref(),
    )
    .await?;

    let updated = UserAccount {
        provisioning_first_name,
        provisioning_last_name,
        provisioning_home_organization,
        ..account
    };
    Ok(Json(user_account_to_response(updated)))
}

/// `POST /api/v1/user-accounts/{id}/activate`
pub async fn activate(
    State(state): State<AppState>,
    Path(id_str): Path<String>,
    tenant_context: TenantContext,
) -> Result<Json<UserAccountResponse>, ApiError> {
    set_account_state(&state, &tenant_context, &id_str, UserAccountState::Active).await
}

/// `POST /api/v1/user-accounts/{id}/deactivate`
pub async fn deactivate(
    State(state): State<AppState>,
    Path(id_str): Path<String>,
    tenant_context: TenantContext,
) -> Result<Json<UserAccountResponse>, ApiError> {
    set_account_state(
        &state,
        &tenant_context,
        &id_str,
        UserAccountState::Deactivated,
    )
    .await
}

async fn set_account_state(
    state: &AppState,
    tenant_context: &TenantContext,
    id_str: &str,
    new_state: UserAccountState,
) -> Result<Json<UserAccountResponse>, ApiError> {
    let id = super::parse_user_account_id(id_str)?;
    let mut conn = state
        .pool
        .acquire()
        .await
        .map_err(|err| ApiError::Internal(Box::new(err)))?;

    // Tenant-scoped: `NotFound` covers both "no such account" and "wrong tenant".
    persistence::user_accounts::set_state(&mut conn, &tenant_context.tenant_id, &id, new_state)
        .await?;

    let account = persistence::user_accounts::get(&mut conn, &tenant_context.tenant_id, &id)
        .await?
        .ok_or(ApiError::NotFound)?;
    Ok(Json(user_account_to_response(account)))
}

/// Projects a [`UserAccount`] to its wire DTO. Ids are emitted in bare form, as
/// every other management endpoint does (and as the path parsers expect back).
pub(super) fn user_account_to_response(account: UserAccount) -> UserAccountResponse {
    UserAccountResponse {
        id: account.id.bare().to_string(),
        tenant_id: account.tenant_id.bare().to_string(),
        provisioning_first_name: account.provisioning_first_name,
        provisioning_last_name: account.provisioning_last_name,
        provisioning_home_organization: account.provisioning_home_organization,
        state: account.state.as_str().to_string(),
        identity: account.identity.map(|i| UserIdentityResponse {
            iss: i.iss,
            sub: i.sub,
        }),
        idp_first_name: account.idp_first_name,
        idp_last_name: account.idp_last_name,
        linked_at: account.linked_at,
        created_at: account.created_at,
    }
}
