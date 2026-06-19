//! Integration tests for the first-party linking/resolution endpoints
//! (`.../accept`, `/linked-user-accounts`), driven through the management
//! router against a `sqlx::test` pool.

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
use swiyu_issuer::test_support::api::tokens::mint_first_party_token;
use swiyu_issuer::test_support::fixtures::SAMPLE_IDP_ISS;
use swiyu_issuer::test_support::http::{get_request, post_request_json, read_body};
use swiyu_issuer::test_support::persistence::user_accounts::test_identity;

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

/// Creates an account and a pending invitation for it, returning
/// `(invitation_id, bare_code)`.
async fn create_invitation(app: &Router, bearer: &str) -> (String, String) {
    let account_id = create_account(app, bearer).await;
    let body = read_body(
        app.clone()
            .oneshot(post_request_json(
                &format!("/api/v1/user-accounts/{account_id}/invitations"),
                Some(bearer),
                json!({}),
            ))
            .await
            .expect("router should serve the request"),
    )
    .await;
    let invitation_id = body["invitation_id"].as_str().unwrap().to_string();
    let link = body["invitation_link"].as_str().unwrap();
    let code = link.rsplit("code=").next().unwrap().to_string();
    (invitation_id, code)
}

#[sqlx::test(migrations = "./migrations")]
async fn accept_links_identity(pool: PgPool) {
    let (state, tenant_id, tenant_secret) = authenticated_app_state(&pool).await;
    let app = router(state);
    let (invitation_id, code) = create_invitation(&app, &tenant_secret.as_wire()).await;

    let first_party = mint_first_party_token();
    let response = app
        .oneshot(post_request_json(
            &format!("/api/v1/invitations/{invitation_id}/accept"),
            Some(&first_party.as_wire()),
            json!({ "code": code, "iss": SAMPLE_IDP_ISS, "sub": "user-1" }),
        ))
        .await
        .expect("router should serve the request");
    assert_eq!(response.status(), StatusCode::OK);
    let body = read_body(response).await;
    assert_eq!(body["identity"]["iss"], SAMPLE_IDP_ISS);
    assert_eq!(body["identity"]["sub"], "user-1");

    // The account row is now linked.
    let id = UserAccountId::from_bare(body["id"].as_str().unwrap().to_string()).unwrap();
    let mut conn = pool
        .acquire()
        .await
        .expect("pool should acquire a connection");
    let account = persistence::user_accounts::get(&mut conn, &tenant_id, &id)
        .await
        .expect("get should succeed")
        .expect("row should be present");
    assert_eq!(account.identity, Some(test_identity("user-1")));
}

#[sqlx::test(migrations = "./migrations")]
async fn accept_with_tenant_token_is_unauthorised(pool: PgPool) {
    let (state, _tenant_id, tenant_secret) = authenticated_app_state(&pool).await;
    let app = router(state);
    let (invitation_id, code) = create_invitation(&app, &tenant_secret.as_wire()).await;

    // A tenant token is the wrong principal for the first-party accept endpoint.
    let response = app
        .oneshot(post_request_json(
            &format!("/api/v1/invitations/{invitation_id}/accept"),
            Some(&tenant_secret.as_wire()),
            json!({ "code": code, "iss": SAMPLE_IDP_ISS, "sub": "user-1" }),
        ))
        .await
        .expect("router should serve the request");
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[sqlx::test(migrations = "./migrations")]
async fn accept_with_wrong_code_is_not_found(pool: PgPool) {
    let (state, _tenant_id, tenant_secret) = authenticated_app_state(&pool).await;
    let app = router(state);
    let (invitation_id, _code) = create_invitation(&app, &tenant_secret.as_wire()).await;

    let first_party = mint_first_party_token();
    let response = app
        .oneshot(post_request_json(
            &format!("/api/v1/invitations/{invitation_id}/accept"),
            Some(&first_party.as_wire()),
            json!({ "code": "wrongcode", "iss": SAMPLE_IDP_ISS, "sub": "user-1" }),
        ))
        .await
        .expect("router should serve the request");
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[sqlx::test(migrations = "./migrations")]
async fn accept_of_expired_invitation_is_conflict(pool: PgPool) {
    let (state, tenant_id, tenant_secret) = authenticated_app_state(&pool).await;
    let app = router(state);
    let account_id_str = create_account(&app, &tenant_secret.as_wire()).await;
    let account_id = UserAccountId::from_bare(account_id_str).unwrap();

    // Seed a stored-pending invitation already past its expiry, with a known code.
    let code = InvitationCode::generate();
    let invitation = Invitation {
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
        &invitation,
        &InvitationCodeHash::from(&code),
    )
    .await
    .expect("insert should succeed");

    // The code resolves, but the invitation is observably expired → 409.
    let first_party = mint_first_party_token();
    let response = app
        .oneshot(post_request_json(
            &format!("/api/v1/invitations/{}/accept", invitation.id.bare()),
            Some(&first_party.as_wire()),
            json!({ "code": code.as_str(), "iss": SAMPLE_IDP_ISS, "sub": "user-1" }),
        ))
        .await
        .expect("router should serve the request");
    assert_eq!(response.status(), StatusCode::CONFLICT);
}

#[sqlx::test(migrations = "./migrations")]
async fn resolve_returns_linked_accounts(pool: PgPool) {
    let (state, _tenant_id, tenant_secret) = authenticated_app_state(&pool).await;
    let app = router(state);
    let account_id_str = create_account(&app, &tenant_secret.as_wire()).await;
    let account_id = UserAccountId::from_bare(account_id_str).unwrap();

    // Link the account to an identity directly.
    let mut conn = pool
        .acquire()
        .await
        .expect("pool should acquire a connection");
    persistence::user_accounts::link_identity(
        &mut conn,
        &account_id,
        &test_identity("user-1"),
        None,
        None,
        Utc::now(),
    )
    .await
    .expect("link_identity should succeed");

    let query = serde_urlencoded::to_string([("iss", SAMPLE_IDP_ISS), ("sub", "user-1")]).unwrap();
    let first_party = mint_first_party_token();
    let response = app
        .oneshot(get_request(
            &format!("/api/v1/linked-user-accounts?{query}"),
            Some(&first_party.as_wire()),
        ))
        .await
        .expect("router should serve the request");
    assert_eq!(response.status(), StatusCode::OK);
    let body = read_body(response).await;
    let items = body["items"].as_array().unwrap();
    assert_eq!(items.len(), 1);
    assert_eq!(items[0]["id"], account_id.bare());
}

#[sqlx::test(migrations = "./migrations")]
async fn resolve_with_tenant_token_is_unauthorised(pool: PgPool) {
    let (state, _tenant_id, tenant_secret) = authenticated_app_state(&pool).await;
    let app = router(state);

    let query = serde_urlencoded::to_string([("iss", SAMPLE_IDP_ISS), ("sub", "user-1")]).unwrap();
    let response = app
        .oneshot(get_request(
            &format!("/api/v1/linked-user-accounts?{query}"),
            Some(&tenant_secret.as_wire()),
        ))
        .await
        .expect("router should serve the request");
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}
