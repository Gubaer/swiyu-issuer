use chrono::{DateTime, Utc};
use sqlx::postgres::PgConnection;

use crate::domain::{Invitation, InvitationCodeHash, InvitationId, TenantId, UserAccountId};

use super::PersistenceError;
use super::helpers::map_database_error;

pub use super::ListPage;

/// Projection for the [`Invitation`] domain struct. `invitation_code_hash` is
/// deliberately excluded — it is write-only, matched directly by the redeem
/// query and never surfaced.
const COLUMNS: &str = "id, user_account_id, tenant_id, state, \
     expires_at, created_at, accepted_at, revoked_at";

/// Inserts a fresh `pending` invitation together with the hash of its code.
///
/// A second live invitation for the account violates
/// `user_account_invitations_one_pending_uq`; a (vanishingly unlikely) hash
/// collision violates `user_account_invitations_code_hash_uq`. Either surfaces
/// as [`PersistenceError::UniqueViolation`] for the handler to map to `409`.
pub async fn insert(
    conn: &mut PgConnection,
    invitation: &Invitation,
    code_hash: &InvitationCodeHash,
) -> Result<(), PersistenceError> {
    sqlx::query(
        r#"
        INSERT INTO user_account_invitations (
            id, user_account_id, tenant_id, invitation_code_hash,
            state, expires_at, created_at, accepted_at, revoked_at
        )
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
        "#,
    )
    .bind(&invitation.id)
    .bind(&invitation.user_account_id)
    .bind(&invitation.tenant_id)
    .bind(code_hash)
    .bind(invitation.state)
    .bind(invitation.expires_at)
    .bind(invitation.created_at)
    .bind(invitation.accepted_at)
    .bind(invitation.revoked_at)
    .execute(conn)
    .await
    .map_err(map_database_error)?;
    Ok(())
}

/// Redeem lookup: the invitation whose stored hash matches the presented code's
/// hash. The hash is globally unique while populated, so this is not
/// tenant-scoped — the caller derives the tenant from the returned row. Expiry
/// is *not* applied here; the handler treats a stored-`pending` row past
/// `expires_at` as expired.
pub async fn find_by_code_hash(
    conn: &mut PgConnection,
    code_hash: &InvitationCodeHash,
) -> Result<Option<Invitation>, PersistenceError> {
    sqlx::query_as::<_, Invitation>(&format!(
        "SELECT {COLUMNS} FROM user_account_invitations WHERE invitation_code_hash = $1"
    ))
    .bind(code_hash)
    .fetch_optional(conn)
    .await
    .map_err(PersistenceError::from)
}

/// Inputs to a paginated list query against `user_account_invitations`.
#[derive(Debug)]
pub struct ListPageQuery {
    /// `(created_at, id)` of the last item of the previous page; `None` requests
    /// the first page. Ordering is `(created_at DESC, id DESC)`.
    pub cursor: Option<(DateTime<Utc>, String)>,
    pub limit: u32,
}

/// Cursor-paginated list of an account's invitations, newest first.
/// Tenant-scoped so a caller cannot list invitations of another tenant.
pub async fn list_by_account(
    conn: &mut PgConnection,
    tenant_id: &TenantId,
    user_account_id: &UserAccountId,
    query: ListPageQuery,
) -> Result<ListPage<Invitation>, PersistenceError> {
    let (cursor_created_at, cursor_id) = match query.cursor {
        Some((ts, id)) => (Some(ts), Some(id)),
        None => (None, None),
    };
    let limit_plus_one = i64::from(query.limit) + 1;

    let mut invitations = sqlx::query_as::<_, Invitation>(&format!(
        r#"
        SELECT {COLUMNS}
        FROM user_account_invitations
        WHERE tenant_id = $1
          AND user_account_id = $2
          AND ($3::TIMESTAMPTZ IS NULL OR (created_at, id) < ($3, $4))
        ORDER BY created_at DESC, id DESC
        LIMIT $5
        "#
    ))
    .bind(tenant_id)
    .bind(user_account_id)
    .bind(cursor_created_at)
    .bind(cursor_id.as_deref())
    .bind(limit_plus_one)
    .fetch_all(conn)
    .await?;

    let has_more = invitations.len() as i64 > i64::from(query.limit);
    if has_more {
        invitations.pop();
    }

    Ok(ListPage {
        items: invitations,
        has_more,
    })
}

/// Marks a `pending` invitation `accepted` and NULLs its code hash (a spent
/// code's hash is not retained). Guarded on `state = 'pending'`, so a
/// concurrent transition makes this a no-op → `NotFound`.
pub async fn mark_accepted(
    conn: &mut PgConnection,
    id: &InvitationId,
    accepted_at: DateTime<Utc>,
) -> Result<(), PersistenceError> {
    let result = sqlx::query(
        r#"
        UPDATE user_account_invitations
        SET state = 'accepted',
            accepted_at = $2,
            invitation_code_hash = NULL
        WHERE id = $1 AND state = 'pending'
        "#,
    )
    .bind(id)
    .bind(accepted_at)
    .execute(conn)
    .await?;

    if result.rows_affected() == 0 {
        return Err(PersistenceError::NotFound);
    }
    Ok(())
}

/// Marks a `pending` invitation `revoked` and NULLs its code hash. Guarded on
/// `state = 'pending'` → `NotFound` if it is no longer pending.
pub async fn mark_revoked(
    conn: &mut PgConnection,
    id: &InvitationId,
    revoked_at: DateTime<Utc>,
) -> Result<(), PersistenceError> {
    let result = sqlx::query(
        r#"
        UPDATE user_account_invitations
        SET state = 'revoked',
            revoked_at = $2,
            invitation_code_hash = NULL
        WHERE id = $1 AND state = 'pending'
        "#,
    )
    .bind(id)
    .bind(revoked_at)
    .execute(conn)
    .await?;

    if result.rows_affected() == 0 {
        return Err(PersistenceError::NotFound);
    }
    Ok(())
}

/// Flips the account's `pending` invitation to `expired` (NULLing its code
/// hash) if it is past `expires_at`. Called in the create transaction before
/// inserting a fresh invitation so a lazily-expired-but-still-`pending` row does
/// not block the partial `one_pending` unique index. A no-op (0 rows) when no
/// pending invitation is due; expiry is otherwise enforced lazily at read time.
pub async fn expire_pending_if_due(
    conn: &mut PgConnection,
    user_account_id: &UserAccountId,
    now: DateTime<Utc>,
) -> Result<(), PersistenceError> {
    sqlx::query(
        r#"
        UPDATE user_account_invitations
        SET state = 'expired',
            invitation_code_hash = NULL
        WHERE user_account_id = $1 AND state = 'pending' AND expires_at < $2
        "#,
    )
    .bind(user_account_id)
    .bind(now)
    .execute(conn)
    .await?;
    Ok(())
}
