use chrono::Utc;
use sqlx::PgPool;

use crate::domain::{TenantId, UserAccount, UserAccountId, UserAccountState, UserIdentity};
use crate::persistence;
use crate::test_support::fixtures::SAMPLE_IDP_ISS;

/// A sample user identity with a fixed test `iss` and the given `sub`.
pub fn test_identity(sub: &str) -> UserIdentity {
    UserIdentity {
        iss: SAMPLE_IDP_ISS.to_string(),
        sub: sub.to_string(),
    }
}

/// Builds an `Active`, unlinked user account with sample provisioning names. The
/// caller inserts it (and may tweak fields such as `created_at` first).
pub fn provisioned_account(tenant_id: &TenantId) -> UserAccount {
    UserAccount {
        id: UserAccountId::generate(),
        tenant_id: tenant_id.clone(),
        provisioning_first_name: Some("First".to_string()),
        provisioning_last_name: Some("Last".to_string()),
        provisioning_home_organization: None,
        state: UserAccountState::Active,
        identity: None,
        idp_first_name: None,
        idp_last_name: None,
        linked_at: None,
        created_at: Utc::now(),
    }
}

/// Inserts a fresh provisioned account for `tenant_id` and returns its id. The
/// tenant must already exist (see `insert_test_tenant`).
pub async fn insert_test_user_account(pool: &PgPool, tenant_id: &TenantId) -> UserAccountId {
    let account = provisioned_account(tenant_id);
    let mut conn = pool.acquire().await.unwrap();
    persistence::user_accounts::insert(&mut conn, &account)
        .await
        .unwrap();
    account.id
}
