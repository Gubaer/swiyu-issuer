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
use super::token_validator::TokenError;

const BEARER_PREFIX: &str = "Bearer ";

pub struct TenantContext {
    pub tenant_id: TenantId,
}

impl FromRequestParts<AppState> for TenantContext {
    type Rejection = ApiError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        // Every request authenticates with a Keycloak bearer JWT. A bad token
        // is a generic 401 the client cannot disambiguate (the tracing::debug!
        // lines keep the detail server-side); the one exception is a transient
        // JWKS outage, which surfaces as 503 (not the caller's fault).
        let credential = extract_bearer(parts)?;
        authenticate_jwt(state, credential).await
    }
}

/// Validate a Keycloak bearer JWT and derive the tenant. When no validator is
/// configured, all requests are rejected.
async fn authenticate_jwt(state: &AppState, credential: &str) -> Result<TenantContext, ApiError> {
    let Some(validator) = state.jwt_validator.as_deref() else {
        tracing::debug!("auth: JWT presented but OAuth2 validation is not configured");
        return Err(ApiError::Unauthorised);
    };
    match validator.validate_tenant(credential, Utc::now()).await {
        Ok(tenant_id) => Ok(TenantContext { tenant_id }),
        Err(TokenError::Invalid) => Err(ApiError::Unauthorised),
        Err(TokenError::KeysUnavailable) => Err(ApiError::ServiceUnavailable),
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
    use axum::http::{HeaderValue, Request};

    fn parts_with_header(value: Option<&str>) -> Parts {
        let mut req = Request::builder().body(()).unwrap();
        if let Some(v) = value {
            req.headers_mut()
                .insert(AUTHORIZATION, HeaderValue::from_str(v).unwrap());
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
}
