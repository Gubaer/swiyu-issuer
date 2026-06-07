//! Integration tests for the tenant-scoped user-account endpoints, driven
//! through the full management router against a `sqlx::test`-managed pool.

use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use serde_json::json;
use sqlx::PgPool;
use tower::ServiceExt;

use swiyu_issuer::api_management::router;
use swiyu_issuer::domain::{TenantId, UserAccountId, UserAccountState};
use swiyu_issuer::persistence;
use swiyu_issuer::test_support::api::authenticated_app_state;
use swiyu_issuer::test_support::http::{
    get_request, patch_request_json, post_request_empty, post_request_json, read_body,
};

#[sqlx::test(migrations = "./migrations")]
async fn create_returns_201_and_inserts(pool: PgPool) {
    let (state, tenant_id, secret) = authenticated_app_state(&pool).await;
    let app = router(state);

    let response = app
        .oneshot(post_request_json(
            "/api/v1/user-accounts",
            Some(&secret.as_wire()),
            json!({ "provisioning_first_name": "Ada" }),
        ))
        .await
        .expect("router should serve the request");
    assert_eq!(response.status(), StatusCode::CREATED);

    let body = read_body(response).await;
    let id_str = body["user_account_id"]
        .as_str()
        .expect("user_account_id should be a string");
    let id = UserAccountId::from_bare(id_str.to_string()).expect("id should parse as a bare id");

    let mut conn = pool
        .acquire()
        .await
        .expect("pool should acquire a connection");
    let account = persistence::user_accounts::get(&mut conn, &tenant_id, &id)
        .await
        .expect("get should succeed")
        .expect("account should be inserted");
    assert_eq!(account.provisioning_first_name.as_deref(), Some("Ada"));
    assert_eq!(account.state, UserAccountState::Active);
}

#[sqlx::test(migrations = "./migrations")]
async fn get_returns_404_for_unknown(pool: PgPool) {
    let (state, _tenant_id, secret) = authenticated_app_state(&pool).await;
    let app = router(state);

    let unknown = UserAccountId::generate();
    let response = app
        .oneshot(get_request(
            &format!("/api/v1/user-accounts/{}", unknown.bare()),
            Some(&secret.as_wire()),
        ))
        .await
        .expect("router should serve the request");
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[sqlx::test(migrations = "./migrations")]
async fn list_returns_tenant_accounts(pool: PgPool) {
    let (state, _tenant_id, secret) = authenticated_app_state(&pool).await;
    let app = router(state);

    for name in ["A", "B"] {
        let resp = app
            .clone()
            .oneshot(post_request_json(
                "/api/v1/user-accounts",
                Some(&secret.as_wire()),
                json!({ "provisioning_first_name": name }),
            ))
            .await
            .expect("router should serve the request");
        assert_eq!(resp.status(), StatusCode::CREATED);
    }

    let response = app
        .oneshot(get_request(
            "/api/v1/user-accounts",
            Some(&secret.as_wire()),
        ))
        .await
        .expect("router should serve the request");
    assert_eq!(response.status(), StatusCode::OK);
    let body = read_body(response).await;
    assert_eq!(body["items"].as_array().unwrap().len(), 2);
    assert!(body["next_cursor"].is_null());
}

#[sqlx::test(migrations = "./migrations")]
async fn patch_updates_provisioning(pool: PgPool) {
    let (state, _tenant_id, secret) = authenticated_app_state(&pool).await;
    let app = router(state);

    let created = read_body(
        app.clone()
            .oneshot(post_request_json(
                "/api/v1/user-accounts",
                Some(&secret.as_wire()),
                json!({ "provisioning_first_name": "Ada" }),
            ))
            .await
            .expect("router should serve the request"),
    )
    .await;
    let id = created["user_account_id"].as_str().unwrap();

    let response = app
        .oneshot(patch_request_json(
            &format!("/api/v1/user-accounts/{id}"),
            Some(&secret.as_wire()),
            json!({ "provisioning_last_name": "Lovelace" }),
        ))
        .await
        .expect("router should serve the request");
    assert_eq!(response.status(), StatusCode::OK);
    let body = read_body(response).await;
    // Provided field set; the untouched first name is preserved.
    assert_eq!(body["provisioning_first_name"], "Ada");
    assert_eq!(body["provisioning_last_name"], "Lovelace");
}

#[sqlx::test(migrations = "./migrations")]
async fn x_tenant_header_is_inert_on_a_tenant_token(pool: PgPool) {
    let (state, _tenant_id, secret) = authenticated_app_state(&pool).await;
    let app = router(state);
    let id = read_body(
        app.clone()
            .oneshot(post_request_json(
                "/api/v1/user-accounts",
                Some(&secret.as_wire()),
                json!({}),
            ))
            .await
            .expect("router should serve the request"),
    )
    .await["user_account_id"]
        .as_str()
        .expect("router should serve the request")
        .to_string();

    // A stray `X-Tenant` naming a different tenant must be ignored on a tenant
    // token: the tenant comes from the token, so the account is still found.
    // (Were the header honoured, the request would scope to the other tenant and
    // 404.)
    let other_tenant = TenantId::generate();
    let request = Request::builder()
        .method("GET")
        .uri(format!("/api/v1/user-accounts/{id}"))
        .header(
            header::AUTHORIZATION,
            format!("Bearer {}", secret.as_wire()),
        )
        .header("x-tenant", other_tenant.to_string())
        .body(Body::empty())
        .unwrap();
    let response = app
        .oneshot(request)
        .await
        .expect("router should serve the request");
    assert_eq!(response.status(), StatusCode::OK);
}

#[sqlx::test(migrations = "./migrations")]
async fn deactivate_then_activate_flips_state(pool: PgPool) {
    let (state, _tenant_id, secret) = authenticated_app_state(&pool).await;
    let app = router(state);

    let created = read_body(
        app.clone()
            .oneshot(post_request_json(
                "/api/v1/user-accounts",
                Some(&secret.as_wire()),
                json!({}),
            ))
            .await
            .expect("router should serve the request"),
    )
    .await;
    let id = created["user_account_id"].as_str().unwrap();

    let deactivated = read_body(
        app.clone()
            .oneshot(post_request_empty(
                &format!("/api/v1/user-accounts/{id}/deactivate"),
                Some(&secret.as_wire()),
            ))
            .await
            .expect("router should serve the request"),
    )
    .await;
    assert_eq!(deactivated["state"], "deactivated");

    let activated = read_body(
        app.oneshot(post_request_empty(
            &format!("/api/v1/user-accounts/{id}/activate"),
            Some(&secret.as_wire()),
        ))
        .await
        .expect("router should serve the request"),
    )
    .await;
    assert_eq!(activated["state"], "active");
}
