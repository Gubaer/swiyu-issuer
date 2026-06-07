//! HTTP handlers for the invitation endpoints (tenant-scoped): create, list,
//! and revoke. The first-party linking/redeem path lives in [`super::linking`].

use axum::Json;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use chrono::{DateTime, Duration, Utc};

use crate::domain::{
    Invitation, InvitationCode, InvitationCodeHash, InvitationId, InvitationState,
};
use crate::persistence;
use crate::persistence::user_account_invitations::ListPageQuery;

use super::AppState;
use super::auth::{TenantContext, require_user_account_owned_by_tenant};
use super::dto::{
    CreateInvitationRequest, CreateInvitationResponse, InvitationResponse, ListInvitationsQuery,
    ListInvitationsResponse,
};
use super::error::ApiError;

/// Lifetime applied to an invitation when the caller omits `expires_in_seconds`.
/// A week to act on an emailed/QR link.
const DEFAULT_INVITATION_EXPIRES_IN_SECONDS: u32 = 604_800;
/// Lower bound: an invitation should outlive a slow round-trip but is not a
/// long-lived grant.
const MIN_INVITATION_EXPIRES_IN_SECONDS: u32 = 3_600;
/// Upper bound: a month caps how long an unredeemed link stays live.
const MAX_INVITATION_EXPIRES_IN_SECONDS: u32 = 2_592_000;

/// Path on `web_base_url` the invitation link points at. The user lands here in
/// `swiyu-issuer-web`, authenticates, and the BFF then calls the accept
/// endpoint. The exact route is a front-end decision.
const INVITATION_ACCEPT_PATH: &str = "/invitations/accept";

/// `POST /api/v1/user-accounts/{user_account_id}/invitations`
pub async fn create(
    State(state): State<AppState>,
    Path(account_id_str): Path<String>,
    tenant_context: TenantContext,
    Json(payload): Json<CreateInvitationRequest>,
) -> Result<(StatusCode, Json<CreateInvitationResponse>), ApiError> {
    let account_id = super::parse_user_account_id(&account_id_str)?;
    let expires_in = resolve_invitation_expires_in(payload.expires_in_seconds)?;
    let now = Utc::now();
    let expires_at = now + expires_in;

    let mut tx = state
        .pool
        .begin()
        .await
        .map_err(|err| ApiError::Internal(Box::new(err)))?;

    // Ownership + precondition check: the account is the tenant's and unlinked.
    let account = persistence::user_accounts::get(&mut tx, &tenant_context.tenant_id, &account_id)
        .await?
        .ok_or(ApiError::NotFound)?;
    if account.identity.is_some() {
        return Err(ApiError::Conflict {
            details: "user account is already linked to an identity".to_string(),
        });
    }

    // Clear a lazily-expired pending row so the partial `one_pending` index does
    // not block a fresh invitation (see persistence::…::expire_pending_if_due).
    persistence::user_account_invitations::expire_pending_if_due(&mut tx, &account_id, now).await?;

    let code = InvitationCode::generate();
    let code_hash = InvitationCodeHash::from(&code);
    let invitation_id = InvitationId::generate();
    let invitation = Invitation {
        id: invitation_id.clone(),
        user_account_id: account_id,
        tenant_id: tenant_context.tenant_id.clone(),
        state: InvitationState::Pending,
        expires_at,
        created_at: now,
        accepted_at: None,
        revoked_at: None,
    };
    // A still-live pending invitation violates `one_pending` → UniqueViolation →
    // ApiError::Conflict (409).
    persistence::user_account_invitations::insert(&mut tx, &invitation, &code_hash).await?;

    tx.commit()
        .await
        .map_err(|err| ApiError::Internal(Box::new(err)))?;

    let invitation_link = build_invitation_link(&state.config.web_base_url, &invitation_id, &code);
    Ok((
        StatusCode::CREATED,
        Json(CreateInvitationResponse {
            invitation_id: invitation_id.bare().to_string(),
            invitation_link,
            expires_at,
        }),
    ))
}

/// `GET /api/v1/user-accounts/{user_account_id}/invitations`
pub async fn list(
    State(state): State<AppState>,
    Path(account_id_str): Path<String>,
    Query(query): Query<ListInvitationsQuery>,
    tenant_context: TenantContext,
) -> Result<Json<ListInvitationsResponse>, ApiError> {
    let account_id = super::parse_user_account_id(&account_id_str)?;
    let limit = super::resolve_list_limit(query.limit)?;
    let decoded_cursor = query
        .cursor
        .as_deref()
        .map(|raw| super::cursor::decode(raw, |bare| InvitationId::from_bare(bare).map(|_| ())))
        .transpose()?;

    let mut conn = state
        .pool
        .acquire()
        .await
        .map_err(|err| ApiError::Internal(Box::new(err)))?;

    require_user_account_owned_by_tenant(&mut conn, &tenant_context.tenant_id, &account_id).await?;

    let page = persistence::user_account_invitations::list_by_account(
        &mut conn,
        &tenant_context.tenant_id,
        &account_id,
        ListPageQuery {
            cursor: decoded_cursor.map(|c| (c.timestamp, c.bare_id)),
            limit,
        },
    )
    .await?;

    let now = Utc::now();
    let next_cursor = if page.has_more {
        page.items
            .last()
            .map(|inv| super::cursor::encode(inv.created_at, inv.id.bare()))
    } else {
        None
    };
    let items = page
        .items
        .into_iter()
        .map(|inv| invitation_to_response(inv, now))
        .collect();
    Ok(Json(ListInvitationsResponse { items, next_cursor }))
}

/// `POST /api/v1/invitations/{invitation_id}/revoke`
pub async fn revoke(
    State(state): State<AppState>,
    Path(invitation_id_str): Path<String>,
    tenant_context: TenantContext,
) -> Result<Json<InvitationResponse>, ApiError> {
    let invitation_id = super::parse_invitation_id(&invitation_id_str)?;
    let now = Utc::now();

    let mut tx = state
        .pool
        .begin()
        .await
        .map_err(|err| ApiError::Internal(Box::new(err)))?;

    // Tenant-scoped: a wrong-tenant or missing invitation is the same 404.
    let invitation = persistence::user_account_invitations::find_by_id(&mut tx, &invitation_id)
        .await?
        .filter(|inv| inv.tenant_id == tenant_context.tenant_id)
        .ok_or(ApiError::NotFound)?;

    // Only a live pending invitation may be revoked; anything else (accepted,
    // already revoked, or observably expired) is a 409.
    if observed_state(&invitation, now) != InvitationState::Pending {
        return Err(ApiError::Conflict {
            details: format!(
                "invitation is {} and cannot be revoked",
                observed_state(&invitation, now).as_str()
            ),
        });
    }

    persistence::user_account_invitations::mark_revoked(&mut tx, &invitation_id, now).await?;
    tx.commit()
        .await
        .map_err(|err| ApiError::Internal(Box::new(err)))?;

    let revoked = Invitation {
        state: InvitationState::Revoked,
        revoked_at: Some(now),
        ..invitation
    };
    Ok(Json(invitation_to_response(revoked, now)))
}

fn resolve_invitation_expires_in(requested: Option<u32>) -> Result<Duration, ApiError> {
    let seconds = requested.unwrap_or(DEFAULT_INVITATION_EXPIRES_IN_SECONDS);
    if !(MIN_INVITATION_EXPIRES_IN_SECONDS..=MAX_INVITATION_EXPIRES_IN_SECONDS).contains(&seconds) {
        return Err(ApiError::InvalidInput {
            details: format!(
                "expires_in_seconds must be between {MIN_INVITATION_EXPIRES_IN_SECONDS} and {MAX_INVITATION_EXPIRES_IN_SECONDS}, got {seconds}"
            ),
        });
    }
    Ok(Duration::seconds(seconds.into()))
}

fn build_invitation_link(
    web_base_url: &str,
    invitation_id: &InvitationId,
    code: &InvitationCode,
) -> String {
    format!(
        "{}{}?invitation={}&code={}",
        web_base_url.trim_end_matches('/'),
        INVITATION_ACCEPT_PATH,
        invitation_id.bare(),
        code.as_str(),
    )
}

/// Lazily-projected state: a stored-`pending` invitation past its `expires_at`
/// is reported as `Expired` without a database write.
pub(super) fn observed_state(invitation: &Invitation, now: DateTime<Utc>) -> InvitationState {
    if invitation.state == InvitationState::Pending && now >= invitation.expires_at {
        InvitationState::Expired
    } else {
        invitation.state
    }
}

pub(super) fn invitation_to_response(
    invitation: Invitation,
    now: DateTime<Utc>,
) -> InvitationResponse {
    let state = observed_state(&invitation, now);
    InvitationResponse {
        id: invitation.id.bare().to_string(),
        state: state.as_str().to_string(),
        expires_at: invitation.expires_at,
        created_at: invitation.created_at,
        accepted_at: invitation.accepted_at,
        revoked_at: invitation.revoked_at,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolve_expires_in_defaults_when_absent() {
        let d = resolve_invitation_expires_in(None).unwrap();
        assert_eq!(
            d.num_seconds(),
            i64::from(DEFAULT_INVITATION_EXPIRES_IN_SECONDS)
        );
    }

    #[test]
    fn resolve_expires_in_rejects_below_min() {
        assert!(matches!(
            resolve_invitation_expires_in(Some(MIN_INVITATION_EXPIRES_IN_SECONDS - 1)),
            Err(ApiError::InvalidInput { .. })
        ));
    }

    #[test]
    fn resolve_expires_in_rejects_above_max() {
        assert!(matches!(
            resolve_invitation_expires_in(Some(MAX_INVITATION_EXPIRES_IN_SECONDS + 1)),
            Err(ApiError::InvalidInput { .. })
        ));
    }

    #[test]
    fn build_link_carries_invitation_and_code() {
        let id = InvitationId::generate();
        let code = InvitationCode::generate();
        let link = build_invitation_link("https://web.example/", &id, &code);
        assert!(link.starts_with("https://web.example/invitations/accept?"));
        assert!(link.contains(&format!("invitation={}", id.bare())));
        assert!(link.contains(&format!("code={}", code.as_str())));
    }
}
