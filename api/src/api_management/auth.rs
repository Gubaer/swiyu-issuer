use axum::extract::FromRequestParts;
use axum::http::header::AUTHORIZATION;
use axum::http::request::Parts;
use chrono::Utc;
use sqlx::Postgres;
use sqlx::pool::PoolConnection;
use sqlx::postgres::PgConnection;

use crate::domain::{IssuerId, TenantId};
use crate::persistence;

use super::AppState;
use super::error::ApiError;
use super::token_validator::{Principal, TokenError};

const BEARER_PREFIX: &str = "Bearer ";

/// Header a `first-party` caller uses to name the target tenant when acting
/// administratively on a tenant's behalf (subaspect 7). Honored **only** for
/// first-party tokens — a `tenant` principal derives its tenant from the token,
/// so this is never consulted there and a stray or forged header is inert.
const X_TENANT_HEADER: &str = "x-tenant";

/// A request authenticated as operating within a single tenant. Satisfied by a
/// `tenant` token (the tenant comes from the token) or by a `first-party` token
/// that names the tenant in an `X-Tenant` header.
pub struct TenantContext {
    pub tenant_id: TenantId,
}

impl FromRequestParts<AppState> for TenantContext {
    type Rejection = ApiError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let tenant_id = match authenticate(parts, state).await? {
            // A validly-signed `tenant` token naming a tenant we don't have is an
            // invalid principal → 401 (and non-leaky).
            Principal::Tenant(tenant_id) => {
                require_tenant_exists(state, &tenant_id, ApiError::Unauthorised).await?;
                tenant_id
            }
            // The BFF acting administratively for a tenant names it explicitly in
            // `X-Tenant` (read only on this first-party branch). The caller is
            // authenticated but named a tenant that does not exist → 404.
            Principal::FirstParty => {
                let tenant_id = require_x_tenant(parts)?;
                require_tenant_exists(state, &tenant_id, ApiError::NotFound).await?;
                tenant_id
            }
        };
        Ok(TenantContext { tenant_id })
    }
}

/// A request authenticated as the trusted first-party caller (the BFF), bound to
/// no tenant — for the cross-tenant resolution endpoint. A `tenant` token is
/// rejected here.
// Wired into routes in Stage 4 (the `GET /linked-user-accounts` resolution and
// `POST /invitations/{id}/accept` linking handlers); unused until then.
#[allow(dead_code)]
pub struct FirstPartyContext;

impl FromRequestParts<AppState> for FirstPartyContext {
    type Rejection = ApiError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        match authenticate(parts, state).await? {
            Principal::FirstParty => Ok(FirstPartyContext),
            Principal::Tenant(_) => {
                tracing::debug!("auth: first-party principal required, got tenant");
                Err(ApiError::Unauthorised)
            }
        }
    }
}

/// Validates the bearer JWT and classifies the principal; shared by both
/// extractors. A bad token is a generic 401 the client cannot disambiguate (the
/// `tracing::debug!` lines keep the detail server-side); the one exception is a
/// transient JWKS outage, which surfaces as 503 (not the caller's fault). When
/// no validator is configured, all requests are rejected.
async fn authenticate(parts: &Parts, state: &AppState) -> Result<Principal, ApiError> {
    let credential = extract_bearer(parts)?;
    let Some(validator) = state.jwt_validator.as_deref() else {
        tracing::debug!("auth: JWT presented but OAuth2 validation is not configured");
        return Err(ApiError::Unauthorised);
    };
    match validator.validate(credential, Utc::now()).await {
        Ok(principal) => Ok(principal),
        Err(TokenError::Invalid) => Err(ApiError::Unauthorised),
        Err(TokenError::KeysUnavailable) => Err(ApiError::ServiceUnavailable),
    }
}

/// Reads and parses the `X-Tenant` header into a [`TenantId`]. A first-party
/// caller acting on a tenant's behalf must supply it (in prefixed form, e.g.
/// `tenant_9hXq2vRtL8pK7f`); absence or a malformed value is a `400`.
fn require_x_tenant(parts: &Parts) -> Result<TenantId, ApiError> {
    let header = parts.headers.get(X_TENANT_HEADER).ok_or_else(|| {
        tracing::debug!("auth: first-party token without X-Tenant on a tenant-scoped request");
        ApiError::InvalidInput {
            details: "X-Tenant header is required for this request".to_string(),
        }
    })?;
    let value = header.to_str().map_err(|_| {
        tracing::debug!("auth: X-Tenant header is not valid UTF-8");
        ApiError::InvalidInput {
            details: "X-Tenant header is not valid UTF-8".to_string(),
        }
    })?;
    value.parse::<TenantId>().map_err(|err| {
        tracing::debug!(error = %err, "auth: X-Tenant is not a valid tenant id");
        ApiError::InvalidInput {
            details: format!("X-Tenant header is not a valid tenant id: {err}"),
        }
    })
}

/// Confirms a derived tenant actually exists, returning `not_found` (the
/// caller's chosen rejection) for a phantom tenant. A `tenant_id` is only
/// format-checked during token validation; without this boundary check a
/// well-formed request for a nonexistent tenant would otherwise surface later as
/// a `tenant_id` FK violation — a `500` — on any write.
async fn require_tenant_exists(
    state: &AppState,
    tenant_id: &TenantId,
    not_found: ApiError,
) -> Result<(), ApiError> {
    let mut conn = state
        .pool
        .acquire()
        .await
        .map_err(|err| ApiError::Internal(Box::new(err)))?;
    if persistence::tenants::exists(&mut conn, tenant_id).await? {
        Ok(())
    } else {
        tracing::debug!(%tenant_id, "auth: token/header names a tenant that does not exist");
        Err(not_found)
    }
}

/// Strips the `Bearer ` scheme and returns the credential that follows,
/// without inspecting or validating it — whether it is an opaque token or a
/// JWT is for the caller to decide.
fn extract_bearer(parts: &Parts) -> Result<&str, ApiError> {
    let header = parts.headers.get(AUTHORIZATION).ok_or_else(|| {
        tracing::debug!("auth: missing Authorization header");
        ApiError::Unauthorised
    })?;
    let value = header.to_str().map_err(|_| {
        tracing::debug!("auth: Authorization header is not valid UTF-8");
        ApiError::Unauthorised
    })?;
    value.strip_prefix(BEARER_PREFIX).ok_or_else(|| {
        tracing::debug!("auth: Authorization header is not a Bearer credential");
        ApiError::Unauthorised
    })
}

/// Verifies that `issuer_id` exists and belongs to `tenant_id`.
///
/// This is the request-boundary ownership check the multi-tenancy
/// spec calls for. Every handler that accepts an [`IssuerId`] from
/// the URL path runs it before touching persistence functions
/// scoped to the issuer.
///
/// # Errors
///
/// Returns [`ApiError::NotFound`] if the issuer does not exist, or
/// exists under a different tenant. The same status is used for
/// "wrong tenant" and for "no such issuer" so an attacker cannot
/// probe for the existence of issuers outside their tenant.
pub async fn require_issuer_owned_by_tenant(
    conn: &mut PgConnection,
    tenant_id: &TenantId,
    issuer_id: &IssuerId,
) -> Result<(), ApiError> {
    let exists = persistence::issuers::exists_for_tenant(conn, tenant_id, issuer_id).await?;
    if exists {
        Ok(())
    } else {
        Err(ApiError::NotFound)
    }
}

/// Acquires a pool connection and verifies issuer ownership before
/// returning it. Every issuer-scoped management handler runs through
/// this so the ownership check cannot be skipped by accident: a
/// handler that needs a connection at all gets the check for free.
pub async fn acquire_pool_for_issuer(
    state: &AppState,
    tenant_id: &TenantId,
    issuer_id: &IssuerId,
) -> Result<PoolConnection<Postgres>, ApiError> {
    let mut conn = state
        .pool
        .acquire()
        .await
        .map_err(|err| ApiError::Internal(Box::new(err)))?;
    require_issuer_owned_by_tenant(&mut conn, tenant_id, issuer_id).await?;
    Ok(conn)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::{HeaderName, HeaderValue, Request};

    fn parts_with_header(value: Option<&str>) -> Parts {
        let mut req = Request::builder().body(()).unwrap();
        if let Some(v) = value {
            req.headers_mut()
                .insert(AUTHORIZATION, HeaderValue::from_str(v).unwrap());
        }
        let (parts, _body) = req.into_parts();
        parts
    }

    fn parts_with_headers(pairs: &[(&str, &str)]) -> Parts {
        let mut req = Request::builder().body(()).unwrap();
        for (name, value) in pairs {
            req.headers_mut().insert(
                HeaderName::from_bytes(name.as_bytes()).unwrap(),
                HeaderValue::from_str(value).unwrap(),
            );
        }
        let (parts, _body) = req.into_parts();
        parts
    }

    #[test]
    fn extract_bearer_returns_credential_verbatim() {
        // The credential is returned untouched for the validator to parse.
        let parts = parts_with_header(Some("Bearer aaa.bbb.ccc"));
        assert_eq!(extract_bearer(&parts).unwrap(), "aaa.bbb.ccc");
    }

    #[test]
    fn extract_bearer_rejects_missing_header() {
        let parts = parts_with_header(None);
        assert!(extract_bearer(&parts).is_err());
    }

    #[test]
    fn extract_bearer_rejects_basic_scheme() {
        let parts = parts_with_header(Some("Basic dXNlcjpwYXNz"));
        assert!(extract_bearer(&parts).is_err());
    }

    #[test]
    fn require_x_tenant_parses_prefixed_id() {
        let tenant_id = TenantId::generate();
        let parts = parts_with_headers(&[("x-tenant", &tenant_id.to_string())]);
        assert_eq!(require_x_tenant(&parts).unwrap(), tenant_id);
    }

    #[test]
    fn require_x_tenant_rejects_missing_header() {
        let parts = parts_with_headers(&[]);
        assert!(matches!(
            require_x_tenant(&parts),
            Err(ApiError::InvalidInput { .. })
        ));
    }

    #[test]
    fn require_x_tenant_rejects_bare_id_without_prefix() {
        // The wire form is prefixed (`tenant_<base58>`); a bare id is rejected.
        let parts = parts_with_headers(&[("x-tenant", "9hXq2vRtL8pK7f")]);
        assert!(matches!(
            require_x_tenant(&parts),
            Err(ApiError::InvalidInput { .. })
        ));
    }

    #[test]
    fn require_x_tenant_rejects_malformed_value() {
        let parts = parts_with_headers(&[("x-tenant", "not a tenant id")]);
        assert!(matches!(
            require_x_tenant(&parts),
            Err(ApiError::InvalidInput { .. })
        ));
    }
}
