//! Integration tests for the act-as-user auth path (subaspect 6): a first-party
//! *exchanged* token plus an `X-User-Account` header makes the tenant-scoped
//! endpoints reachable, with the tenant derived from the verified account.

use axum::Router;
use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use chrono::Utc;
use sqlx::PgPool;
use tower::ServiceExt;

use swiyu_issuer::api_management::router;
use swiyu_issuer::domain::{UserAccountId, UserAccountState};
use swiyu_issuer::persistence;
use swiyu_issuer::test_support::api::authenticated_app_state;
use swiyu_issuer::test_support::api::tokens::mint_act_as_user_token;
use swiyu_issuer::test_support::fixtures::SAMPLE_IDP_ISS as ISS;
use swiyu_issuer::test_support::persistence::user_accounts::{
    insert_test_user_account, test_identity,
};

/// Seeds an account in the authenticated tenant linked to `(ISS, sub)`.
async fn linked_account(
    pool: &PgPool,
    tenant_id: &swiyu_issuer::domain::TenantId,
    sub: &str,
) -> UserAccountId {
    let account_id = insert_test_user_account(pool, tenant_id).await;
    let mut conn = pool
        .acquire()
        .await
        .expect("pool should acquire a connection");
    persistence::user_accounts::link_identity(
        &mut conn,
        &account_id,
        &test_identity(sub),
        None,
        None,
        Utc::now(),
    )
    .await
    .expect("link_identity should succeed");
    account_id
}

fn get_acting_as_user(uri: &str, bearer: &str, x_user_account: Option<&str>) -> Request<Body> {
    let mut builder = Request::builder()
        .method("GET")
        .uri(uri)
        .header(header::AUTHORIZATION, format!("Bearer {bearer}"));
    if let Some(account) = x_user_account {
        builder = builder.header("x-user-account", account);
    }
    builder.body(Body::empty()).unwrap()
}

async fn get(app: &Router, request: Request<Body>) -> StatusCode {
    app.clone()
        .oneshot(request)
        .await
        .expect("router should serve the request")
        .status()
}

#[sqlx::test(migrations = "./migrations")]
async fn act_as_user_reaches_a_tenant_scoped_endpoint(pool: PgPool) {
    let (state, tenant_id, _tenant_secret) = authenticated_app_state(&pool).await;
    let account_id = linked_account(&pool, &tenant_id, "u1").await;
    let app = router(state);

    // Exchanged token for the linked identity + the selected account → 200; the
    // tenant is derived from the verified account.
    let token = mint_act_as_user_token(ISS, "u1");
    let status = get(
        &app,
        get_acting_as_user(
            &format!("/api/v1/user-accounts/{}", account_id.bare()),
            &token.as_wire(),
            Some(account_id.bare()),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
}

#[sqlx::test(migrations = "./migrations")]
async fn act_as_user_with_account_not_linked_to_the_token_identity_is_401(pool: PgPool) {
    let (state, tenant_id, _tenant_secret) = authenticated_app_state(&pool).await;
    let account_id = linked_account(&pool, &tenant_id, "u1").await;
    let app = router(state);

    // The account is linked to `u1`, but the token acts as `u2` → not linked → 401.
    let token = mint_act_as_user_token(ISS, "u2");
    let status = get(
        &app,
        get_acting_as_user(
            &format!("/api/v1/user-accounts/{}", account_id.bare()),
            &token.as_wire(),
            Some(account_id.bare()),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[sqlx::test(migrations = "./migrations")]
async fn act_as_user_without_x_user_account_header_is_401(pool: PgPool) {
    let (state, tenant_id, _tenant_secret) = authenticated_app_state(&pool).await;
    let account_id = linked_account(&pool, &tenant_id, "u1").await;
    let app = router(state);

    let token = mint_act_as_user_token(ISS, "u1");
    let status = get(
        &app,
        get_acting_as_user(
            &format!("/api/v1/user-accounts/{}", account_id.bare()),
            &token.as_wire(),
            None,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[sqlx::test(migrations = "./migrations")]
async fn act_as_user_on_a_deactivated_account_is_401(pool: PgPool) {
    let (state, tenant_id, _tenant_secret) = authenticated_app_state(&pool).await;
    let account_id = linked_account(&pool, &tenant_id, "u1").await;
    let mut conn = pool
        .acquire()
        .await
        .expect("pool should acquire a connection");
    persistence::user_accounts::set_state(
        &mut conn,
        &tenant_id,
        &account_id,
        UserAccountState::Deactivated,
    )
    .await
    .expect("set_state should succeed");
    let app = router(state);

    let token = mint_act_as_user_token(ISS, "u1");
    let status = get(
        &app,
        get_acting_as_user(
            &format!("/api/v1/user-accounts/{}", account_id.bare()),
            &token.as_wire(),
            Some(account_id.bare()),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}
