//! Integration tests for the tenant-scoped invitation endpoints (create, list,
//! revoke), driven through the management router against a `sqlx::test` pool.

use axum::Router;
use axum::http::StatusCode;
use chrono::{Duration, Utc};
use serde_json::json;
use sqlx::PgPool;
use tower::ServiceExt;

use swiyu_issuer::api_management::router;
use swiyu_issuer::domain::{
    Invitation, InvitationCode, InvitationCodeHash, InvitationId, InvitationState, UserAccountId,
};
use swiyu_issuer::persistence;
use swiyu_issuer::test_support::api::authenticated_app_state;
use swiyu_issuer::test_support::http::{post_request_empty, post_request_json, read_body};
use swiyu_issuer::test_support::persistence::user_accounts::test_identity;

/// Creates a user account via the API, returning its bare id.
async fn create_account(app: &Router, bearer: &str) -> String {
    let body = read_body(
        app.clone()
            .oneshot(post_request_json(
                "/api/v1/user-accounts",
                Some(bearer),
                json!({}),
            ))
            .await
            .expect("router should serve the request"),
    )
    .await;
    body["user_account_id"].as_str().unwrap().to_string()
}

/// Extracts the bare `code` query parameter from an invitation link.
fn code_from_link(link: &str) -> InvitationCode {
    let code = link
        .rsplit("code=")
        .next()
        .expect("link should carry a code");
    InvitationCode::from_wire(code)
}

#[sqlx::test(migrations = "./migrations")]
async fn create_returns_201_and_link_resolves_to_hash(pool: PgPool) {
    let (state, _tenant_id, secret) = authenticated_app_state(&pool).await;
    let app = router(state);
    let account_id = create_account(&app, &secret.as_wire()).await;

    let response = app
        .oneshot(post_request_json(
            &format!("/api/v1/user-accounts/{account_id}/invitations"),
            Some(&secret.as_wire()),
            json!({}),
        ))
        .await
        .expect("router should serve the request");
    assert_eq!(response.status(), StatusCode::CREATED);
    let body = read_body(response).await;

    let invitation_id =
        InvitationId::from_bare(body["invitation_id"].as_str().unwrap().to_string()).unwrap();
    let code = code_from_link(body["invitation_link"].as_str().unwrap());

    // The link's bare code hashes to the persisted hash for this invitation.
    let mut conn = pool
        .acquire()
        .await
        .expect("pool should acquire a connection");
    let found = persistence::user_account_invitations::find_by_code_hash(
        &mut conn,
        &InvitationCodeHash::from(&code),
    )
    .await
    .expect("find_by_code_hash should succeed")
    .expect("code should resolve");
    assert_eq!(found.id, invitation_id);
}

#[sqlx::test(migrations = "./migrations")]
async fn create_on_linked_account_returns_409(pool: PgPool) {
    let (state, _tenant_id, secret) = authenticated_app_state(&pool).await;
    let app = router(state);
    let account_id_str = create_account(&app, &secret.as_wire()).await;
    let account_id = UserAccountId::from_bare(account_id_str.clone()).unwrap();

    // Link an identity directly, so the account is no longer invitable.
    let mut conn = pool
        .acquire()
        .await
        .expect("pool should acquire a connection");
    persistence::user_accounts::link_identity(
        &mut conn,
        &account_id,
        &test_identity("u1"),
        None,
        None,
        Utc::now(),
    )
    .await
    .expect("link_identity should succeed");

    let response = app
        .oneshot(post_request_json(
            &format!("/api/v1/user-accounts/{account_id_str}/invitations"),
            Some(&secret.as_wire()),
            json!({}),
        ))
        .await
        .expect("router should serve the request");
    assert_eq!(response.status(), StatusCode::CONFLICT);
}

#[sqlx::test(migrations = "./migrations")]
async fn create_with_live_pending_returns_409(pool: PgPool) {
    let (state, _tenant_id, secret) = authenticated_app_state(&pool).await;
    let app = router(state);
    let account_id = create_account(&app, &secret.as_wire()).await;
    let uri = format!("/api/v1/user-accounts/{account_id}/invitations");

    let first = app
        .clone()
        .oneshot(post_request_json(&uri, Some(&secret.as_wire()), json!({})))
        .await
        .expect("router should serve the request");
    assert_eq!(first.status(), StatusCode::CREATED);

    let second = app
        .oneshot(post_request_json(&uri, Some(&secret.as_wire()), json!({})))
        .await
        .expect("router should serve the request");
    assert_eq!(second.status(), StatusCode::CONFLICT);
}

#[sqlx::test(migrations = "./migrations")]
async fn create_after_expired_pending_returns_201(pool: PgPool) {
    let (state, tenant_id, secret) = authenticated_app_state(&pool).await;
    let app = router(state);
    let account_id_str = create_account(&app, &secret.as_wire()).await;
    let account_id = UserAccountId::from_bare(account_id_str.clone()).unwrap();

    // Seed a stored-pending invitation already past its expiry.
    let stale = Invitation {
        id: InvitationId::generate(),
        user_account_id: account_id,
        tenant_id,
        state: InvitationState::Pending,
        expires_at: Utc::now() - Duration::hours(1),
        created_at: Utc::now() - Duration::hours(2),
        accepted_at: None,
        revoked_at: None,
    };
    let mut conn = pool
        .acquire()
        .await
        .expect("pool should acquire a connection");
    persistence::user_account_invitations::insert(
        &mut conn,
        &stale,
        &InvitationCodeHash::from(&InvitationCode::generate()),
    )
    .await
    .expect("insert should succeed");

    // Create succeeds: the stale pending row is expired on demand first.
    let response = app
        .oneshot(post_request_json(
            &format!("/api/v1/user-accounts/{account_id_str}/invitations"),
            Some(&secret.as_wire()),
            json!({}),
        ))
        .await
        .expect("router should serve the request");
    assert_eq!(response.status(), StatusCode::CREATED);
}

#[sqlx::test(migrations = "./migrations")]
async fn revoke_pending_then_409(pool: PgPool) {
    let (state, _tenant_id, secret) = authenticated_app_state(&pool).await;
    let app = router(state);
    let account_id = create_account(&app, &secret.as_wire()).await;

    let created = read_body(
        app.clone()
            .oneshot(post_request_json(
                &format!("/api/v1/user-accounts/{account_id}/invitations"),
                Some(&secret.as_wire()),
                json!({}),
            ))
            .await
            .expect("router should serve the request"),
    )
    .await;
    let invitation_id = created["invitation_id"].as_str().unwrap();
    let revoke_uri = format!("/api/v1/invitations/{invitation_id}/revoke");

    let first = app
        .clone()
        .oneshot(post_request_empty(&revoke_uri, Some(&secret.as_wire())))
        .await
        .expect("router should serve the request");
    assert_eq!(first.status(), StatusCode::OK);
    assert_eq!(read_body(first).await["state"], "revoked");

    // Already revoked → 409.
    let second = app
        .oneshot(post_request_empty(&revoke_uri, Some(&secret.as_wire())))
        .await
        .expect("router should serve the request");
    assert_eq!(second.status(), StatusCode::CONFLICT);
}
