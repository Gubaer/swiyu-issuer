use axum::extract::FromRequestParts;
use axum::http::header::AUTHORIZATION;
use axum::http::request::Parts;
use chrono::Utc;
use sqlx::Postgres;
use sqlx::pool::PoolConnection;
use sqlx::postgres::PgConnection;

use crate::domain::{ApiTokenSecret, IssuerId, TenantId};
use crate::persistence;

use super::AppState;
use super::error::ApiError;
use super::token_validator::TokenError;

const BEARER_PREFIX: &str = "Bearer ";
/// Prefix carried by legacy opaque API tokens (`tok_<base58>`). It is the
/// discriminator between the legacy path and a Keycloak JWT: a credential with
/// this prefix is opaque, anything else is treated as a JWT.
const OPAQUE_TOKEN_PREFIX: &str = "tok_";

pub struct TenantContext {
    pub tenant_id: TenantId,
}

impl FromRequestParts<AppState> for TenantContext {
    type Rejection = ApiError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        // Opaque `tok_…` credentials take the legacy path; anything else is
        // treated as a Keycloak JWT.
        let credential = extract_bearer(parts)?;
        if credential.starts_with(OPAQUE_TOKEN_PREFIX) {
            // Every failure collapses to a generic 401 so the client cannot
            // distinguish "no header" from "wrong scheme" from "expired
            // token"; the tracing::debug! lines keep the detail server-side.
            authenticate_opaque(state, credential).await
        } else {
            // As on the opaque path, a bad token is a generic 401; the one
            // exception is a transient JWKS outage, which surfaces as 503
            // (not the caller's fault).
            authenticate_jwt(state, credential).await
        }
    }
}

/// Legacy path: SHA-256 the opaque token and look it up in `api_tokens`.
async fn authenticate_opaque(
    state: &AppState,
    credential: &str,
) -> Result<TenantContext, ApiError> {
    let secret = ApiTokenSecret::from_wire(credential).map_err(|err| {
        tracing::debug!(error = %err, "auth: malformed opaque token");
        ApiError::Unauthorised
    })?;
    let hash = secret.hash();

    let mut conn = state.pool.acquire().await.map_err(|err| {
        tracing::debug!(error = %err, "auth: failed to acquire DB connection");
        ApiError::Unauthorised
    })?;

    let token = persistence::api_tokens::find_valid_by_hash(&mut conn, &hash, Utc::now())
        .await
        .map_err(|err| {
            tracing::debug!(error = %err, "auth: token lookup failed");
            ApiError::Unauthorised
        })?
        .ok_or_else(|| {
            tracing::debug!("auth: no valid token matches the presented hash");
            ApiError::Unauthorised
        })?;

    // last_used_at is best-effort: a failure here means the audit signal is
    // missing, not that the request should be denied.
    if let Err(err) = persistence::api_tokens::mark_used(&mut conn, &token.id, Utc::now()).await {
        tracing::warn!(error = %err, token_id = %token.id, "auth: failed to bump last_used_at");
    }

    Ok(TenantContext {
        tenant_id: token.tenant_id,
    })
}

/// OAuth2 path: validate a Keycloak bearer JWT and derive the tenant. When no
/// validator is configured, the JWT path is disabled and any non-`tok_`
/// credential is rejected.
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
    fn extract_bearer_returns_opaque_credential_verbatim() {
        let parts = parts_with_header(Some("Bearer tok_DevDevDevDevDev"));
        assert_eq!(extract_bearer(&parts).unwrap(), "tok_DevDevDevDevDev");
    }

    #[test]
    fn extract_bearer_returns_jwt_credential_verbatim() {
        // A non-`tok_` credential is returned as-is for the JWT branch.
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
