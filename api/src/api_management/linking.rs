//! First-party (BFF) endpoints: redeem an invitation to link a user identity to
//! its account, and resolve an identity to the accounts it is linked to.
//!
//! Both authenticate as [`FirstPartyContext`] (a `first-party` token, no
//! tenant).

use axum::Json;
use axum::extract::{Path, Query, State};
use chrono::Utc;

use crate::domain::{InvitationCode, InvitationCodeHash, InvitationState, UserIdentity};
use crate::persistence;

use super::AppState;
use super::auth::FirstPartyContext;
use super::dto::{
    AcceptInvitationRequest, LinkedUserAccountsResponse, ResolveLinkedAccountsQuery,
    UserAccountResponse,
};
use super::error::ApiError;
use super::invitations::observed_state;
use super::user_accounts::user_account_to_response;

/// Cap on the asserted identity fields after trim. `iss` is a URL and `sub` an
/// opaque subject; both can be longer than the short provisioning fields.
const MAX_IDENTITY_FIELD_LENGTH: usize = 2_048;

/// `POST /api/v1/invitations/{invitation_id}/accept`
///
/// Redeems an invitation, linking the freshly-authenticated user identity to the
/// account the invitation was issued for.
pub async fn accept(
    State(state): State<AppState>,
    Path(invitation_id_str): Path<String>,
    _first_party: FirstPartyContext,
    Json(payload): Json<AcceptInvitationRequest>,
) -> Result<Json<UserAccountResponse>, ApiError> {
    let invitation_id = super::parse_invitation_id(&invitation_id_str)?;
    let identity = UserIdentity {
        iss: super::normalise_required("iss", &payload.iss, MAX_IDENTITY_FIELD_LENGTH)?,
        sub: super::normalise_required("sub", &payload.sub, MAX_IDENTITY_FIELD_LENGTH)?,
    };
    let idp_first_name = super::normalise_optional(
        "idp_first_name",
        payload.idp_first_name.as_deref(),
        MAX_IDENTITY_FIELD_LENGTH,
    )?;
    let idp_last_name = super::normalise_optional(
        "idp_last_name",
        payload.idp_last_name.as_deref(),
        MAX_IDENTITY_FIELD_LENGTH,
    )?;
    let code_hash = InvitationCodeHash::from(&InvitationCode::from_wire(&payload.code));
    let now = Utc::now();

    let mut tx = state
        .pool
        .begin()
        .await
        .map_err(|err| ApiError::Internal(Box::new(err)))?;

    // Resolve by code hash; the row must be the one named in the path. A bad code
    // and a mismatched id collapse to the same opaque 404.
    let invitation = persistence::user_account_invitations::find_by_code_hash(&mut tx, &code_hash)
        .await?
        .filter(|inv| inv.id == invitation_id)
        .ok_or(ApiError::NotFound)?;

    if observed_state(&invitation, now) != InvitationState::Pending {
        return Err(ApiError::Conflict {
            details: "invitation is no longer pending".to_string(),
        });
    }

    // Tenant comes from the invitation, not the token.
    let account = persistence::user_accounts::get(
        &mut tx,
        &invitation.tenant_id,
        &invitation.user_account_id,
    )
    .await?
    .ok_or(ApiError::NotFound)?;
    if account.identity.is_some() {
        return Err(ApiError::Conflict {
            details: "user account is already linked to an identity".to_string(),
        });
    }

    // The (tenant, iss, sub) unique index rejects an identity already linked to
    // another account in this tenant → UniqueViolation → ApiError::Conflict.
    persistence::user_accounts::link_identity(
        &mut tx,
        &account.id,
        &identity,
        idp_first_name.as_deref(),
        idp_last_name.as_deref(),
        now,
    )
    .await?;
    persistence::user_account_invitations::mark_accepted(&mut tx, &invitation.id, now).await?;

    let linked = persistence::user_accounts::get(&mut tx, &invitation.tenant_id, &account.id)
        .await?
        .ok_or(ApiError::NotFound)?;
    let tenant_display_name =
        persistence::tenants::find_display_name(&mut tx, &invitation.tenant_id).await?;

    tx.commit()
        .await
        .map_err(|err| ApiError::Internal(Box::new(err)))?;

    Ok(Json(user_account_to_response(linked, tenant_display_name)))
}

/// `GET /api/v1/linked-user-accounts?iss=…&sub=…`
///
/// Lists the accounts linked to the given identity, across tenants.
pub async fn resolve(
    State(state): State<AppState>,
    Query(query): Query<ResolveLinkedAccountsQuery>,
    _first_party: FirstPartyContext,
) -> Result<Json<LinkedUserAccountsResponse>, ApiError> {
    let identity = UserIdentity {
        iss: super::normalise_required("iss", &query.iss, MAX_IDENTITY_FIELD_LENGTH)?,
        sub: super::normalise_required("sub", &query.sub, MAX_IDENTITY_FIELD_LENGTH)?,
    };

    let mut conn = state
        .pool
        .acquire()
        .await
        .map_err(|err| ApiError::Internal(Box::new(err)))?;

    let accounts = persistence::user_accounts::resolve_linked_accounts(&mut conn, &identity).await?;
    let items = accounts
        .into_iter()
        .map(|resolved| user_account_to_response(resolved.account, resolved.tenant_display_name))
        .collect();
    Ok(Json(LinkedUserAccountsResponse { items }))
}
