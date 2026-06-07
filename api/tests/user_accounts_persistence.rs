//! DB-integration tests for `persistence::user_accounts`, against a
//! `sqlx::test`-managed pool.

use chrono::{Duration, Utc};
use sqlx::PgPool;

use swiyu_issuer::domain::{TenantId, UserAccountState};
use swiyu_issuer::persistence::user_accounts::ListPageQuery;
use swiyu_issuer::persistence::{self, PersistenceError};
use swiyu_issuer::test_support::persistence::tenants::insert_test_tenant;
use swiyu_issuer::test_support::persistence::user_accounts::{provisioned_account, test_identity};

#[sqlx::test(migrations = "./migrations")]
async fn insert_and_get_round_trips(pool: PgPool) {
    let mut conn = pool
        .acquire()
        .await
        .expect("pool should acquire a connection");
    let tenant = TenantId::generate();
    insert_test_tenant(&pool, &tenant).await;
    let account = provisioned_account(&tenant);

    persistence::user_accounts::insert(&mut conn, &account)
        .await
        .expect("insert should succeed");

    let fetched = persistence::user_accounts::get(&mut conn, &tenant, &account.id)
        .await
        .expect("get should succeed")
        .expect("account should exist");
    assert_eq!(fetched.id, account.id);
    assert_eq!(fetched.provisioning_first_name.as_deref(), Some("First"));
    assert_eq!(fetched.state, UserAccountState::Active);
    assert!(fetched.identity.is_none());
}

#[sqlx::test(migrations = "./migrations")]
async fn get_is_tenant_scoped(pool: PgPool) {
    let mut conn = pool
        .acquire()
        .await
        .expect("pool should acquire a connection");
    let owner = TenantId::generate();
    let other = TenantId::generate();
    insert_test_tenant(&pool, &owner).await;
    insert_test_tenant(&pool, &other).await;
    let account = provisioned_account(&owner);
    persistence::user_accounts::insert(&mut conn, &account)
        .await
        .expect("insert should succeed");

    // Wrong tenant collapses to None.
    let cross = persistence::user_accounts::get(&mut conn, &other, &account.id)
        .await
        .expect("get should succeed");
    assert!(cross.is_none());
}

#[sqlx::test(migrations = "./migrations")]
async fn link_identity_then_get_returns_linked(pool: PgPool) {
    let mut conn = pool
        .acquire()
        .await
        .expect("pool should acquire a connection");
    let tenant = TenantId::generate();
    insert_test_tenant(&pool, &tenant).await;
    let account = provisioned_account(&tenant);
    persistence::user_accounts::insert(&mut conn, &account)
        .await
        .expect("insert should succeed");

    let now = Utc::now();
    persistence::user_accounts::link_identity(
        &mut conn,
        &account.id,
        &test_identity("sub-1"),
        Some("Idp"),
        Some("Name"),
        now,
    )
    .await
    .expect("link_identity should succeed");

    let fetched = persistence::user_accounts::get(&mut conn, &tenant, &account.id)
        .await
        .expect("get should succeed")
        .expect("row should be present");
    assert_eq!(fetched.identity, Some(test_identity("sub-1")));
    assert_eq!(fetched.idp_first_name.as_deref(), Some("Idp"));
    assert!(fetched.linked_at.is_some());
}

#[sqlx::test(migrations = "./migrations")]
async fn link_identity_rejects_duplicate_identity_in_same_tenant(pool: PgPool) {
    let mut conn = pool
        .acquire()
        .await
        .expect("pool should acquire a connection");
    let tenant = TenantId::generate();
    insert_test_tenant(&pool, &tenant).await;
    let a1 = provisioned_account(&tenant);
    let a2 = provisioned_account(&tenant);
    persistence::user_accounts::insert(&mut conn, &a1)
        .await
        .expect("insert should succeed");
    persistence::user_accounts::insert(&mut conn, &a2)
        .await
        .expect("insert should succeed");

    let now = Utc::now();
    persistence::user_accounts::link_identity(
        &mut conn,
        &a1.id,
        &test_identity("dup"),
        None,
        None,
        now,
    )
    .await
    .expect("link_identity should succeed");
    let err = persistence::user_accounts::link_identity(
        &mut conn,
        &a2.id,
        &test_identity("dup"),
        None,
        None,
        now,
    )
    .await
    .unwrap_err();
    assert!(matches!(err, PersistenceError::UniqueViolation { .. }));
}

#[sqlx::test(migrations = "./migrations")]
async fn same_identity_links_across_different_tenants(pool: PgPool) {
    let mut conn = pool
        .acquire()
        .await
        .expect("pool should acquire a connection");
    let t1 = TenantId::generate();
    let t2 = TenantId::generate();
    insert_test_tenant(&pool, &t1).await;
    insert_test_tenant(&pool, &t2).await;
    let a1 = provisioned_account(&t1);
    let a2 = provisioned_account(&t2);
    persistence::user_accounts::insert(&mut conn, &a1)
        .await
        .expect("insert should succeed");
    persistence::user_accounts::insert(&mut conn, &a2)
        .await
        .expect("insert should succeed");

    let now = Utc::now();
    persistence::user_accounts::link_identity(
        &mut conn,
        &a1.id,
        &test_identity("x"),
        None,
        None,
        now,
    )
    .await
    .expect("link_identity should succeed");
    // Same identity, different tenant: allowed.
    persistence::user_accounts::link_identity(
        &mut conn,
        &a2.id,
        &test_identity("x"),
        None,
        None,
        now,
    )
    .await
    .expect("link_identity should succeed");

    let all = persistence::user_accounts::list_by_identity(&mut conn, &test_identity("x"))
        .await
        .expect("list_by_identity should succeed");
    assert_eq!(all.len(), 2);
}

#[sqlx::test(migrations = "./migrations")]
async fn set_state_is_tenant_scoped(pool: PgPool) {
    let mut conn = pool
        .acquire()
        .await
        .expect("pool should acquire a connection");
    let owner = TenantId::generate();
    let other = TenantId::generate();
    insert_test_tenant(&pool, &owner).await;
    insert_test_tenant(&pool, &other).await;
    let account = provisioned_account(&owner);
    persistence::user_accounts::insert(&mut conn, &account)
        .await
        .expect("insert should succeed");

    // Wrong tenant: NotFound, no change.
    let err = persistence::user_accounts::set_state(
        &mut conn,
        &other,
        &account.id,
        UserAccountState::Deactivated,
    )
    .await
    .unwrap_err();
    assert!(matches!(err, PersistenceError::NotFound));

    // Owner: succeeds.
    persistence::user_accounts::set_state(
        &mut conn,
        &owner,
        &account.id,
        UserAccountState::Deactivated,
    )
    .await
    .expect("set_state should succeed");
    let fetched = persistence::user_accounts::get(&mut conn, &owner, &account.id)
        .await
        .expect("get should succeed")
        .expect("row should be present");
    assert_eq!(fetched.state, UserAccountState::Deactivated);
}

#[sqlx::test(migrations = "./migrations")]
async fn list_by_tenant_keyset_paginates(pool: PgPool) {
    let mut conn = pool
        .acquire()
        .await
        .expect("pool should acquire a connection");
    let tenant = TenantId::generate();
    insert_test_tenant(&pool, &tenant).await;

    // Three accounts with distinct, increasing created_at.
    let base = Utc::now();
    for i in 0..3i64 {
        let mut a = provisioned_account(&tenant);
        a.created_at = base + Duration::seconds(i);
        persistence::user_accounts::insert(&mut conn, &a)
            .await
            .expect("insert should succeed");
    }

    let page1 = persistence::user_accounts::list_by_tenant(
        &mut conn,
        &tenant,
        ListPageQuery {
            cursor: None,
            limit: 2,
        },
    )
    .await
    .expect("list_by_tenant should succeed");
    assert_eq!(page1.items.len(), 2);
    assert!(page1.has_more);

    let last = page1.items.last().unwrap();
    let page2 = persistence::user_accounts::list_by_tenant(
        &mut conn,
        &tenant,
        ListPageQuery {
            cursor: Some((last.created_at, last.id.bare().to_string())),
            limit: 2,
        },
    )
    .await
    .expect("list_by_tenant should succeed");
    assert_eq!(page2.items.len(), 1);
    assert!(!page2.has_more);
}
