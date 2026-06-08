use chrono::{DateTime, Utc};
use sqlx::postgres::PgConnection;

use crate::domain::{TenantId, UserAccount, UserAccountId, UserAccountState, UserIdentity};

use super::PersistenceError;
use super::helpers::map_database_error;

pub use super::ListPage;

// The SELECT projection is repeated inline in each query, as the other
// persistence modules do. It must include the two `identity_*` columns the
// [`UserAccount`] `FromRow` assembles into `Option<UserIdentity>`.

pub async fn insert(
    conn: &mut PgConnection,
    account: &UserAccount,
) -> Result<(), PersistenceError> {
    sqlx::query(
        r#"
        INSERT INTO user_accounts (
            id, tenant_id,
            provisioning_first_name, provisioning_last_name, provisioning_home_organization,
            state, identity_iss, identity_sub, idp_first_name, idp_last_name,
            linked_at, created_at
        )
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
        "#,
    )
    .bind(&account.id)
    .bind(&account.tenant_id)
    .bind(account.provisioning_first_name.as_deref())
    .bind(account.provisioning_last_name.as_deref())
    .bind(account.provisioning_home_organization.as_deref())
    .bind(account.state)
    .bind(account.identity.as_ref().map(|i| i.iss.as_str()))
    .bind(account.identity.as_ref().map(|i| i.sub.as_str()))
    .bind(account.idp_first_name.as_deref())
    .bind(account.idp_last_name.as_deref())
    .bind(account.linked_at)
    .bind(account.created_at)
    .execute(conn)
    .await
    .map_err(map_database_error)?;
    Ok(())
}

/// Tenant-scoped fetch. "Wrong tenant" collapses to `Ok(None)` so a caller
/// cannot probe for accounts in other tenants.
pub async fn get(
    conn: &mut PgConnection,
    tenant_id: &TenantId,
    id: &UserAccountId,
) -> Result<Option<UserAccount>, PersistenceError> {
    sqlx::query_as::<_, UserAccount>(
        r#"
        SELECT id, tenant_id,
               provisioning_first_name, provisioning_last_name, provisioning_home_organization,
               state, identity_iss, identity_sub, idp_first_name, idp_last_name,
               linked_at, created_at
        FROM user_accounts
        WHERE id = $1 AND tenant_id = $2
        "#,
    )
    .bind(id)
    .bind(tenant_id)
    .fetch_optional(conn)
    .await
    .map_err(PersistenceError::from)
}

/// Cross-tenant fetch used by the act-as-user auth path: the account with this
/// id, only if it is linked to `identity`. The identity (not a tenant) scopes the
/// lookup; `Ok(None)` covers "no such account", "unlinked", and "linked to a
/// different identity" alike, so the caller cannot distinguish them.
pub async fn get_by_id_and_identity(
    conn: &mut PgConnection,
    id: &UserAccountId,
    identity: &UserIdentity,
) -> Result<Option<UserAccount>, PersistenceError> {
    sqlx::query_as::<_, UserAccount>(
        r#"
        SELECT id, tenant_id,
               provisioning_first_name, provisioning_last_name, provisioning_home_organization,
               state, identity_iss, identity_sub, idp_first_name, idp_last_name,
               linked_at, created_at
        FROM user_accounts
        WHERE id = $1 AND identity_iss = $2 AND identity_sub = $3
        "#,
    )
    .bind(id)
    .bind(identity.iss.as_str())
    .bind(identity.sub.as_str())
    .fetch_optional(conn)
    .await
    .map_err(PersistenceError::from)
}

/// Overwrites the three `provisioning_*` columns (the `idp_*` names are sourced
/// from the IDP token and are not editable here). Merge semantics, if any, are
/// the handler's concern. `NotFound` if no row matches `(id, tenant_id)`.
pub async fn update_provisioning(
    conn: &mut PgConnection,
    tenant_id: &TenantId,
    id: &UserAccountId,
    first_name: Option<&str>,
    last_name: Option<&str>,
    home_organization: Option<&str>,
) -> Result<(), PersistenceError> {
    let result = sqlx::query(
        r#"
        UPDATE user_accounts
        SET provisioning_first_name = $3,
            provisioning_last_name = $4,
            provisioning_home_organization = $5
        WHERE id = $1 AND tenant_id = $2
        "#,
    )
    .bind(id)
    .bind(tenant_id)
    .bind(first_name)
    .bind(last_name)
    .bind(home_organization)
    .execute(conn)
    .await?;

    if result.rows_affected() == 0 {
        return Err(PersistenceError::NotFound);
    }
    Ok(())
}

/// Activates or deactivates the account. `NotFound` if no row matches
/// `(id, tenant_id)`.
pub async fn set_state(
    conn: &mut PgConnection,
    tenant_id: &TenantId,
    id: &UserAccountId,
    state: UserAccountState,
) -> Result<(), PersistenceError> {
    let result = sqlx::query(
        r#"
        UPDATE user_accounts
        SET state = $1
        WHERE id = $2 AND tenant_id = $3
        "#,
    )
    .bind(state)
    .bind(id)
    .bind(tenant_id)
    .execute(conn)
    .await?;

    if result.rows_affected() == 0 {
        return Err(PersistenceError::NotFound);
    }
    Ok(())
}

/// Links a user identity to the account: sets `identity_*`, `idp_*`, and
/// `linked_at`. Keyed by account id alone (the caller derived the account from
/// the invitation). Relies on `user_accounts_tenant_identity_uq` to enforce "one
/// identity per account per tenant" — a violation surfaces as
/// [`PersistenceError::UniqueViolation`] for the handler to map to `409`.
/// `NotFound` if the account does not exist. Preconditions (account unlinked,
/// active) are the handler's responsibility.
pub async fn link_identity(
    conn: &mut PgConnection,
    id: &UserAccountId,
    identity: &UserIdentity,
    idp_first_name: Option<&str>,
    idp_last_name: Option<&str>,
    linked_at: DateTime<Utc>,
) -> Result<(), PersistenceError> {
    let result = sqlx::query(
        r#"
        UPDATE user_accounts
        SET identity_iss = $2,
            identity_sub = $3,
            idp_first_name = $4,
            idp_last_name = $5,
            linked_at = $6
        WHERE id = $1
        "#,
    )
    .bind(id)
    .bind(identity.iss.as_str())
    .bind(identity.sub.as_str())
    .bind(idp_first_name)
    .bind(idp_last_name)
    .bind(linked_at)
    .execute(conn)
    .await
    .map_err(map_database_error)?;

    if result.rows_affected() == 0 {
        return Err(PersistenceError::NotFound);
    }
    Ok(())
}

/// Refreshes the IDP-asserted names on every account linked to `identity`
/// (across tenants), as observed on a successful authentication. A no-op (0
/// rows) when the identity is not linked anywhere.
pub async fn refresh_idp_names(
    conn: &mut PgConnection,
    identity: &UserIdentity,
    idp_first_name: Option<&str>,
    idp_last_name: Option<&str>,
) -> Result<(), PersistenceError> {
    sqlx::query(
        r#"
        UPDATE user_accounts
        SET idp_first_name = $3,
            idp_last_name = $4
        WHERE identity_iss = $1 AND identity_sub = $2
        "#,
    )
    .bind(identity.iss.as_str())
    .bind(identity.sub.as_str())
    .bind(idp_first_name)
    .bind(idp_last_name)
    .execute(conn)
    .await?;
    Ok(())
}

/// Inputs to a paginated list query against `user_accounts`.
#[derive(Debug)]
pub struct ListPageQuery {
    /// `(created_at, id)` of the last item of the previous page; `None` requests
    /// the first page. Ordering is `(created_at DESC, id DESC)`.
    pub cursor: Option<(DateTime<Utc>, String)>,
    pub limit: u32,
}

/// Cursor-paginated list of a tenant's user accounts, newest first.
pub async fn list_by_tenant(
    conn: &mut PgConnection,
    tenant_id: &TenantId,
    query: ListPageQuery,
) -> Result<ListPage<UserAccount>, PersistenceError> {
    let (cursor_created_at, cursor_id) = match query.cursor {
        Some((ts, id)) => (Some(ts), Some(id)),
        None => (None, None),
    };
    let limit_plus_one = i64::from(query.limit) + 1;

    let mut accounts = sqlx::query_as::<_, UserAccount>(
        r#"
        SELECT id, tenant_id,
               provisioning_first_name, provisioning_last_name, provisioning_home_organization,
               state, identity_iss, identity_sub, idp_first_name, idp_last_name,
               linked_at, created_at
        FROM user_accounts
        WHERE tenant_id = $1
          AND ($2::TIMESTAMPTZ IS NULL OR (created_at, id) < ($2, $3))
        ORDER BY created_at DESC, id DESC
        LIMIT $4
        "#,
    )
    .bind(tenant_id)
    .bind(cursor_created_at)
    .bind(cursor_id.as_deref())
    .bind(limit_plus_one)
    .fetch_all(conn)
    .await?;

    let has_more = accounts.len() as i64 > i64::from(query.limit);
    if has_more {
        accounts.pop();
    }

    Ok(ListPage {
        items: accounts,
        has_more,
    })
}

/// Every account linked to `identity`, across tenants — the cross-tenant
/// identity-resolution lookup. An identity links to at most one account per
/// tenant, so the result is small and unpaginated.
pub async fn list_by_identity(
    conn: &mut PgConnection,
    identity: &UserIdentity,
) -> Result<Vec<UserAccount>, PersistenceError> {
    sqlx::query_as::<_, UserAccount>(
        r#"
        SELECT id, tenant_id,
               provisioning_first_name, provisioning_last_name, provisioning_home_organization,
               state, identity_iss, identity_sub, idp_first_name, idp_last_name,
               linked_at, created_at
        FROM user_accounts
        WHERE identity_iss = $1 AND identity_sub = $2
        ORDER BY created_at DESC, id DESC
        "#,
    )
    .bind(identity.iss.as_str())
    .bind(identity.sub.as_str())
    .fetch_all(conn)
    .await
    .map_err(PersistenceError::from)
}

/// A linked account paired with its owning tenant's display name — the
/// projection the cross-tenant resolve endpoint needs so the SPA account picker
/// can label each candidate by tenant. `tenant_display_name` is `None` when the
/// tenant has no display name set.
#[derive(Debug, sqlx::FromRow)]
pub struct ResolvedAccount {
    #[sqlx(flatten)]
    pub account: UserAccount,
    pub tenant_display_name: Option<String>,
}

/// Like [`list_by_identity`], but joins `tenants` to carry each account's tenant
/// display name. Used by the cross-tenant resolve (login) endpoint, where the
/// caller has no tenant context to label the accounts itself.
pub async fn resolve_linked_accounts(
    conn: &mut PgConnection,
    identity: &UserIdentity,
) -> Result<Vec<ResolvedAccount>, PersistenceError> {
    sqlx::query_as::<_, ResolvedAccount>(
        r#"
        SELECT ua.id, ua.tenant_id,
               ua.provisioning_first_name, ua.provisioning_last_name,
               ua.provisioning_home_organization,
               ua.state, ua.identity_iss, ua.identity_sub,
               ua.idp_first_name, ua.idp_last_name,
               ua.linked_at, ua.created_at,
               t.display_name AS tenant_display_name
        FROM user_accounts ua
        JOIN tenants t ON t.id = ua.tenant_id
        WHERE ua.identity_iss = $1 AND ua.identity_sub = $2
        ORDER BY ua.created_at DESC, ua.id DESC
        "#,
    )
    .bind(identity.iss.as_str())
    .bind(identity.sub.as_str())
    .fetch_all(conn)
    .await
    .map_err(PersistenceError::from)
}
