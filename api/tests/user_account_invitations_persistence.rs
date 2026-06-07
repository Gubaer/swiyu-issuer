//! DB-integration tests for `persistence::user_account_invitations`, against a
//! `sqlx::test`-managed pool.

use chrono::{DateTime, Duration, Utc};
use sqlx::PgPool;

use swiyu_issuer::domain::{
    Invitation, InvitationCode, InvitationCodeHash, InvitationId, InvitationState, TenantId,
    UserAccountId,
};
use swiyu_issuer::persistence::user_account_invitations::ListPageQuery;
use swiyu_issuer::persistence::{self, PersistenceError};
use swiyu_issuer::test_support::persistence::tenants::insert_test_tenant;
use swiyu_issuer::test_support::persistence::user_accounts::insert_test_user_account;

/// Seeds a tenant and a provisioned (unlinked) account, returning its id.
async fn seed_account(pool: &PgPool, tenant: &TenantId) -> UserAccountId {
    insert_test_tenant(pool, tenant).await;
    insert_test_user_account(pool, tenant).await
}

fn pending(
    tenant: &TenantId,
    account_id: &UserAccountId,
    expires_at: DateTime<Utc>,
) -> (Invitation, InvitationCode) {
    let invitation = Invitation {
        id: InvitationId::generate(),
        user_account_id: account_id.clone(),
        tenant_id: tenant.clone(),
        state: InvitationState::Pending,
        expires_at,
        created_at: Utc::now(),
        accepted_at: None,
        revoked_at: None,
    };
    (invitation, InvitationCode::generate())
}

#[sqlx::test(migrations = "./migrations")]
async fn insert_then_find_by_id_and_code_hash(pool: PgPool) {
    let tenant = TenantId::generate();
    let account_id = seed_account(&pool, &tenant).await;
    let mut conn = pool
        .acquire()
        .await
        .expect("pool should acquire a connection");

    let (invitation, code) = pending(&tenant, &account_id, Utc::now() + Duration::hours(1));
    let hash = InvitationCodeHash::from(&code);
    persistence::user_account_invitations::insert(&mut conn, &invitation, &hash)
        .await
        .expect("insert should succeed");

    let by_id = persistence::user_account_invitations::find_by_id(&mut conn, &invitation.id)
        .await
        .expect("find_by_id should succeed")
        .expect("row should be present");
    assert_eq!(by_id.state, InvitationState::Pending);
    assert_eq!(by_id.tenant_id, tenant);

    let by_hash = persistence::user_account_invitations::find_by_code_hash(&mut conn, &hash)
        .await
        .expect("find_by_code_hash should succeed")
        .expect("row should be present");
    assert_eq!(by_hash.id, invitation.id);
}

#[sqlx::test(migrations = "./migrations")]
async fn one_pending_rejects_second_pending(pool: PgPool) {
    let tenant = TenantId::generate();
    let account_id = seed_account(&pool, &tenant).await;
    let mut conn = pool
        .acquire()
        .await
        .expect("pool should acquire a connection");

    let (first, code1) = pending(&tenant, &account_id, Utc::now() + Duration::hours(1));
    persistence::user_account_invitations::insert(
        &mut conn,
        &first,
        &InvitationCodeHash::from(&code1),
    )
    .await
    .expect("insert should succeed");

    let (second, code2) = pending(&tenant, &account_id, Utc::now() + Duration::hours(1));
    let err = persistence::user_account_invitations::insert(
        &mut conn,
        &second,
        &InvitationCodeHash::from(&code2),
    )
    .await
    .unwrap_err();
    assert!(matches!(err, PersistenceError::UniqueViolation { .. }));
}

#[sqlx::test(migrations = "./migrations")]
async fn mark_accepted_nulls_code_hash(pool: PgPool) {
    let tenant = TenantId::generate();
    let account_id = seed_account(&pool, &tenant).await;
    let mut conn = pool
        .acquire()
        .await
        .expect("pool should acquire a connection");

    let (invitation, code) = pending(&tenant, &account_id, Utc::now() + Duration::hours(1));
    let hash = InvitationCodeHash::from(&code);
    persistence::user_account_invitations::insert(&mut conn, &invitation, &hash)
        .await
        .expect("insert should succeed");

    let now = Utc::now();
    persistence::user_account_invitations::mark_accepted(&mut conn, &invitation.id, now)
        .await
        .expect("mark_accepted should succeed");

    // The hash is cleared — redeem-by-hash no longer resolves.
    assert!(
        persistence::user_account_invitations::find_by_code_hash(&mut conn, &hash)
            .await
            .expect("find_by_code_hash should succeed")
            .is_none()
    );
    let by_id = persistence::user_account_invitations::find_by_id(&mut conn, &invitation.id)
        .await
        .expect("find_by_id should succeed")
        .expect("row should be present");
    assert_eq!(by_id.state, InvitationState::Accepted);
    assert!(by_id.accepted_at.is_some());

    // A second accept is a no-op transition → NotFound.
    let err = persistence::user_account_invitations::mark_accepted(&mut conn, &invitation.id, now)
        .await
        .unwrap_err();
    assert!(matches!(err, PersistenceError::NotFound));
}

#[sqlx::test(migrations = "./migrations")]
async fn mark_revoked_nulls_code_hash(pool: PgPool) {
    let tenant = TenantId::generate();
    let account_id = seed_account(&pool, &tenant).await;
    let mut conn = pool
        .acquire()
        .await
        .expect("pool should acquire a connection");

    let (invitation, code) = pending(&tenant, &account_id, Utc::now() + Duration::hours(1));
    let hash = InvitationCodeHash::from(&code);
    persistence::user_account_invitations::insert(&mut conn, &invitation, &hash)
        .await
        .expect("insert should succeed");

    persistence::user_account_invitations::mark_revoked(&mut conn, &invitation.id, Utc::now())
        .await
        .expect("mark_revoked should succeed");

    assert!(
        persistence::user_account_invitations::find_by_code_hash(&mut conn, &hash)
            .await
            .expect("find_by_code_hash should succeed")
            .is_none()
    );
    let by_id = persistence::user_account_invitations::find_by_id(&mut conn, &invitation.id)
        .await
        .expect("find_by_id should succeed")
        .expect("row should be present");
    assert_eq!(by_id.state, InvitationState::Revoked);
    assert!(by_id.revoked_at.is_some());
}

#[sqlx::test(migrations = "./migrations")]
async fn expire_pending_if_due_flips_only_due_rows(pool: PgPool) {
    let tenant = TenantId::generate();
    let mut conn = pool
        .acquire()
        .await
        .expect("pool should acquire a connection");

    // Due row on account A (expires in the past).
    let account_a = seed_account(&pool, &tenant).await;
    let (due, due_code) = pending(&tenant, &account_a, Utc::now() - Duration::hours(1));
    persistence::user_account_invitations::insert(
        &mut conn,
        &due,
        &InvitationCodeHash::from(&due_code),
    )
    .await
    .expect("insert should succeed");

    // Not-due row on account B (expires in the future).
    let tenant_b = TenantId::generate();
    let account_b = seed_account(&pool, &tenant_b).await;
    let (live, live_code) = pending(&tenant_b, &account_b, Utc::now() + Duration::hours(1));
    persistence::user_account_invitations::insert(
        &mut conn,
        &live,
        &InvitationCodeHash::from(&live_code),
    )
    .await
    .expect("insert should succeed");

    let now = Utc::now();
    persistence::user_account_invitations::expire_pending_if_due(&mut conn, &account_a, now)
        .await
        .expect("expire_pending_if_due should succeed");
    persistence::user_account_invitations::expire_pending_if_due(&mut conn, &account_b, now)
        .await
        .expect("expire_pending_if_due should succeed");

    let due_after = persistence::user_account_invitations::find_by_id(&mut conn, &due.id)
        .await
        .expect("find_by_id should succeed")
        .expect("row should be present");
    assert_eq!(due_after.state, InvitationState::Expired);

    let live_after = persistence::user_account_invitations::find_by_id(&mut conn, &live.id)
        .await
        .expect("find_by_id should succeed")
        .expect("row should be present");
    assert_eq!(live_after.state, InvitationState::Pending);
}

#[sqlx::test(migrations = "./migrations")]
async fn list_by_account_is_tenant_scoped(pool: PgPool) {
    let tenant = TenantId::generate();
    let other = TenantId::generate();
    insert_test_tenant(&pool, &other).await;
    let account_id = seed_account(&pool, &tenant).await;
    let mut conn = pool
        .acquire()
        .await
        .expect("pool should acquire a connection");

    let (invitation, code) = pending(&tenant, &account_id, Utc::now() + Duration::hours(1));
    persistence::user_account_invitations::insert(
        &mut conn,
        &invitation,
        &InvitationCodeHash::from(&code),
    )
    .await
    .expect("insert should succeed");

    let owned = persistence::user_account_invitations::list_by_account(
        &mut conn,
        &tenant,
        &account_id,
        ListPageQuery {
            cursor: None,
            limit: 25,
        },
    )
    .await
    .expect("list_by_account should succeed");
    assert_eq!(owned.items.len(), 1);

    // Same account id, wrong tenant: nothing.
    let cross = persistence::user_account_invitations::list_by_account(
        &mut conn,
        &other,
        &account_id,
        ListPageQuery {
            cursor: None,
            limit: 25,
        },
    )
    .await
    .expect("list_by_account should succeed");
    assert!(cross.items.is_empty());
}
