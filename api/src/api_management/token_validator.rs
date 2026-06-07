//! OAuth2 resource-server validation for the management API.
//!
//! `swiyu-issuer-mgmtapi` accepts Keycloak-issued JWT bearer tokens, validates
//! their EdDSA signature against the realm JWKS, and classifies the caller on
//! the `principal_type` claim into a [`Principal`] (a tenant, or the first-party
//! BFF). This module is the JWT half; the extractors in [`super::auth`] turn a
//! `Principal` into a request context.
//!
//! The validator is optional. When the Keycloak environment is absent the
//! binary builds no validator, the JWT path stays disabled, and the legacy
//! opaque-token path is the only one.

use std::collections::HashMap;
use std::sync::RwLock;
use std::time::{Duration, Instant};

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chrono::{DateTime, Utc};
use serde::Deserialize;
use serde_json::{Value, json};

use crate::domain::TenantId;

/// Only EdDSA is accepted: the realm signs with Ed25519, and pinning the
/// algorithm here means the token header cannot talk us into a different
/// verification path.
const EXPECTED_ALG: &str = "EdDSA";

/// `principal_type` claim values this validator recognises. A `tenant` token is
/// bound to one tenant and carries `tenant_id`; a `first-party` token is the
/// trusted `swiyu-issuer-web` BFF and carries no tenant. Any other value is
/// rejected. See `aspect-authn.md`.
const PRINCIPAL_TYPE_TENANT: &str = "tenant";
const PRINCIPAL_TYPE_FIRST_PARTY: &str = "first-party";

/// Clock-skew leeway for `exp`/`nbf`, in seconds.
const DEFAULT_LEEWAY_SECS: i64 = 60;
/// Background freshness horizon for the JWKS: a cached key older than this
/// triggers a (cooldown-gated) refresh so rotated-out keys eventually drop.
const DEFAULT_JWKS_TTL: Duration = Duration::from_secs(600);
/// Minimum spacing between JWKS fetches. Bounds load on Keycloak and turns a
/// spray of unknown `kid`s into at most one fetch per window (the negative
/// cache).
const DEFAULT_JWKS_COOLDOWN: Duration = Duration::from_secs(30);
/// HTTP timeout for a single JWKS fetch.
const JWKS_HTTP_TIMEOUT: Duration = Duration::from_secs(10);

/// Why validation failed, at the granularity the caller needs to pick an HTTP
/// status.
#[derive(Debug, PartialEq, Eq)]
pub enum TokenError {
    /// The token is the caller's fault (bad signature, wrong claims, expired,
    /// unknown `kid`, …). Maps to 401; the body stays generic so the failure
    /// reason does not leak.
    Invalid,
    /// No keys are currently held to validate against — a cold start with
    /// Keycloak unreachable. Maps to 503 (transient), so it is not reported as
    /// a bad token.
    KeysUnavailable,
}

/// Validates Keycloak bearer JWTs and extracts the tenant.
pub struct TokenValidator {
    expected_iss: String,
    expected_aud: String,
    leeway_secs: i64,
    jwks: JwksCache,
}

impl TokenValidator {
    /// `issuer_url` is the realm issuer (the token `iss`, e.g.
    /// `https://host/realms/swiyu-issuer`); `jwks_url` is its JWKS endpoint;
    /// `audience` is this resource server's identifier (the required `aud`).
    pub fn new(
        issuer_url: String,
        jwks_url: String,
        audience: String,
        http: reqwest::Client,
    ) -> Self {
        Self {
            expected_iss: issuer_url,
            expected_aud: audience,
            leeway_secs: DEFAULT_LEEWAY_SECS,
            jwks: JwksCache::new(jwks_url, http, DEFAULT_JWKS_TTL, DEFAULT_JWKS_COOLDOWN),
        }
    }

    /// Derives the JWKS URL from the realm issuer per the OIDC convention.
    pub fn jwks_url_for_issuer(issuer_url: &str) -> String {
        format!(
            "{}/protocol/openid-connect/certs",
            issuer_url.trim_end_matches('/')
        )
    }

    /// Validates `token` and returns the [`Principal`] it authenticates.
    ///
    /// On success the token is a non-expired, EdDSA-signed JWT from the expected
    /// realm and audience, classified on its `principal_type` claim. Any failure
    /// is a [`TokenError`]; the reason is kept in a server-side `tracing::debug!`
    /// rather than in the error, so it does not leak to the caller.
    pub async fn validate(&self, token: &str, now: DateTime<Utc>) -> Result<Principal, TokenError> {
        let parsed = parse_jwt(token).map_err(|_| {
            tracing::debug!("auth(jwt): malformed JWT structure");
            TokenError::Invalid
        })?;

        // Pin the algorithm before any key lookup: rejecting a non-EdDSA `alg`
        // here closes `alg`-confusion / `alg: none`.
        if parsed.alg != EXPECTED_ALG {
            tracing::debug!(alg = %parsed.alg, "auth(jwt): header alg is not EdDSA");
            return Err(TokenError::Invalid);
        }

        let kid = parsed.kid.as_deref().ok_or_else(|| {
            tracing::debug!("auth(jwt): header is missing `kid`");
            TokenError::Invalid
        })?;

        let jwk = self.jwks.jwk_for_kid(kid).await.map_err(|err| match err {
            JwksError::Unavailable => {
                tracing::warn!("auth(jwt): JWKS unavailable, cannot validate token");
                TokenError::KeysUnavailable
            }
            JwksError::UnknownKid => {
                tracing::debug!(%kid, "auth(jwt): no JWKS key matches the token `kid`");
                TokenError::Invalid
            }
        })?;

        // Verify by reusing the OIDC JWS primitive (the same one the
        // wallet-proof path uses, so no JWT crate is needed): build a JOSE
        // header carrying the JWKS key and force `alg = EdDSA`, so a `kid` that
        // maps to an EC key is rejected as a mismatch.
        let header = json!({ "alg": EXPECTED_ALG, "jwk": jwk });
        swiyu_core::jws::verify_with_embedded_jwk(
            &header,
            parsed.signing_input.as_bytes(),
            &parsed.signature,
        )
        .map_err(|err| {
            tracing::debug!(error = %err, "auth(jwt): signature verification failed");
            TokenError::Invalid
        })?;

        validate_claims(
            &parsed.payload,
            &self.expected_iss,
            &self.expected_aud,
            now.timestamp(),
            self.leeway_secs,
        )
    }

    /// Tenant-only convenience over [`validate`](Self::validate): succeeds for a
    /// `tenant` principal, rejecting a `first-party` token as [`TokenError::Invalid`].
    /// Used where only a tenant context is meaningful.
    pub async fn validate_tenant(
        &self,
        token: &str,
        now: DateTime<Utc>,
    ) -> Result<TenantId, TokenError> {
        match self.validate(token, now).await? {
            Principal::Tenant(tenant_id) => Ok(tenant_id),
            Principal::FirstParty => {
                tracing::debug!("auth(jwt): tenant principal required, got first-party");
                Err(TokenError::Invalid)
            }
        }
    }
}

/// The JWT broken into the pieces signature verification and claim checks need.
struct ParsedJwt {
    alg: String,
    kid: Option<String>,
    payload: Value,
    /// `header_b64.payload_b64` — the bytes the signature covers.
    signing_input: String,
    signature: Vec<u8>,
}

fn parse_jwt(token: &str) -> Result<ParsedJwt, ()> {
    let mut segments = token.split('.');
    let header_b64 = segments.next().ok_or(())?;
    let payload_b64 = segments.next().ok_or(())?;
    let signature_b64 = segments.next().ok_or(())?;
    if segments.next().is_some() {
        return Err(());
    }

    let header_bytes = URL_SAFE_NO_PAD.decode(header_b64).map_err(|_| ())?;
    let payload_bytes = URL_SAFE_NO_PAD.decode(payload_b64).map_err(|_| ())?;
    let signature = URL_SAFE_NO_PAD.decode(signature_b64).map_err(|_| ())?;

    let header: Value = serde_json::from_slice(&header_bytes).map_err(|_| ())?;
    let payload: Value = serde_json::from_slice(&payload_bytes).map_err(|_| ())?;

    let alg = header
        .get("alg")
        .and_then(Value::as_str)
        .ok_or(())?
        .to_string();
    let kid = header
        .get("kid")
        .and_then(Value::as_str)
        .map(str::to_string);

    Ok(ParsedJwt {
        alg,
        kid,
        payload,
        signing_input: format!("{header_b64}.{payload_b64}"),
        signature,
    })
}

/// Checks `iss`/`aud`/`exp`/`nbf`/`principal_type` and returns the classified
/// [`Principal`]. Split out from [`TokenValidator::validate`] so it is
/// unit-testable without a signature or a network round-trip.
fn validate_claims(
    payload: &Value,
    expected_iss: &str,
    expected_aud: &str,
    now_ts: i64,
    leeway: i64,
) -> Result<Principal, TokenError> {
    let iss = payload.get("iss").and_then(Value::as_str).ok_or_else(|| {
        tracing::debug!("auth(jwt): payload missing `iss`");
        TokenError::Invalid
    })?;
    if iss != expected_iss {
        tracing::debug!(%iss, "auth(jwt): `iss` does not match the expected realm");
        return Err(TokenError::Invalid);
    }

    if !aud_contains(payload.get("aud"), expected_aud) {
        tracing::debug!("auth(jwt): `aud` does not contain this resource server");
        return Err(TokenError::Invalid);
    }

    let exp = payload.get("exp").and_then(Value::as_i64).ok_or_else(|| {
        tracing::debug!("auth(jwt): payload missing `exp`");
        TokenError::Invalid
    })?;
    if now_ts > exp + leeway {
        tracing::debug!("auth(jwt): token is expired");
        return Err(TokenError::Invalid);
    }

    if let Some(nbf) = payload.get("nbf").and_then(Value::as_i64)
        && now_ts + leeway < nbf
    {
        tracing::debug!("auth(jwt): token is not yet valid (`nbf`)");
        return Err(TokenError::Invalid);
    }

    let principal_type = payload
        .get("principal_type")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            tracing::debug!("auth(jwt): payload missing `principal_type`");
            TokenError::Invalid
        })?;
    match principal_type {
        PRINCIPAL_TYPE_TENANT => {
            let tenant_id = payload
                .get("tenant_id")
                .and_then(Value::as_str)
                .ok_or_else(|| {
                    tracing::debug!("auth(jwt): tenant principal missing `tenant_id`");
                    TokenError::Invalid
                })?;
            // The claim carries the prefixed form (e.g. `tenant_9hXq2vRtL8pK7f`).
            // This only *format*-checks the id; whether a tenant with this id
            // actually exists is a data question, not a token-validity one, and
            // is kept out of here so claim validation stays pure (no DB, unit-
            // testable). The boundary existence check lives in the
            // `TenantContext` extractor (`super::auth::require_tenant_exists`).
            let tenant_id = tenant_id.parse::<TenantId>().map_err(|err| {
                tracing::debug!(error = %err, "auth(jwt): `tenant_id` is not a valid tenant id");
                TokenError::Invalid
            })?;
            Ok(Principal::Tenant(tenant_id))
        }
        // A first-party token carries no tenant; the request supplies one where
        // needed (`X-Tenant` or a path resource), handled by the extractors.
        PRINCIPAL_TYPE_FIRST_PARTY => Ok(Principal::FirstParty),
        other => {
            tracing::debug!(principal_type = %other, "auth(jwt): unsupported principal_type");
            Err(TokenError::Invalid)
        }
    }
}

/// `aud` may be a single string or an array of strings (RFC 7519); accept
/// either as long as `expected` is present.
fn aud_contains(aud: Option<&Value>, expected: &str) -> bool {
    match aud {
        Some(Value::String(s)) => s == expected,
        Some(Value::Array(items)) => items.iter().any(|v| v.as_str() == Some(expected)),
        _ => false,
    }
}

/// Why a `kid` lookup could not produce a key.
enum JwksError {
    /// No keys are cached at all (cold start with Keycloak unreachable). The
    /// caller maps this to 503 — it is transient, not a bad token.
    Unavailable,
    /// Keys are cached, but none has this `kid`. The caller maps this to 401.
    UnknownKid,
}

/// The kind of principal a validated token represents, classified on its
/// `principal_type` claim. This establishes *who* is calling and how the
/// request's tenant is derived — not what they may do (authorization is flat 
/// for the time being).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Principal {
    /// A tenant-bound caller (subaspect 4). Carries the tenant from `tenant_id`.
    Tenant(TenantId),
    /// The trusted first-party caller — the `swiyu-issuer-web` BFF (subaspects 5
    /// and 7). Carries no tenant; where one is needed it comes from the request
    /// (an `X-Tenant` header or a path resource), never from the token.
    FirstParty,
}

#[derive(Deserialize)]
struct JwksDoc {
    keys: Vec<Value>,
}

struct CacheState {
    /// `kid` → raw JWK value (verified lazily per request via swiyu-core).
    keys: HashMap<String, Value>,
    /// When the current `keys` were last fetched; drives the TTL.
    fetched_at: Option<Instant>,
    /// When a fetch was last attempted; drives the cooldown / single-flight.
    last_attempt: Option<Instant>,
}

/// Caches the realm JWKS with a resilience policy: serve-stale on refresh
/// error, cooldown-gated refresh on an unknown `kid`, and a distinct
/// "no keys yet" signal for cold starts.
struct JwksCache {
    jwks_url: String,
    http: reqwest::Client,
    ttl: Duration,
    cooldown: Duration,
    state: RwLock<CacheState>,
}

impl JwksCache {
    fn new(jwks_url: String, http: reqwest::Client, ttl: Duration, cooldown: Duration) -> Self {
        Self {
            jwks_url,
            http,
            ttl,
            cooldown,
            state: RwLock::new(CacheState {
                keys: HashMap::new(),
                fetched_at: None,
                last_attempt: None,
            }),
        }
    }

    /// Returns the JWK for `kid`, refreshing the JWKS when needed.
    async fn jwk_for_kid(&self, kid: &str) -> Result<Value, JwksError> {
        // Hit: serve it. If the cache is stale, kick a cooldown-gated refresh
        // for next time but still return the (valid) cached key now.
        if let Some((jwk, stale)) = self.read_kid(kid) {
            if stale {
                self.refresh_if_due().await;
            }
            return Ok(jwk);
        }

        // Miss: an unknown `kid` is the key-rotation signal — refresh once
        // (cooldown-gated) and look again.
        self.refresh_if_due().await;
        if let Some((jwk, _)) = self.read_kid(kid) {
            return Ok(jwk);
        }

        if self.is_empty() {
            Err(JwksError::Unavailable)
        } else {
            Err(JwksError::UnknownKid)
        }
    }

    /// Returns `(jwk, stale)` for `kid` if cached. `stale` means the cache is
    /// older than the TTL.
    fn read_kid(&self, kid: &str) -> Option<(Value, bool)> {
        let state = self.state.read().expect("jwks lock poisoned");
        let jwk = state.keys.get(kid)?.clone();
        let stale = state
            .fetched_at
            .is_none_or(|fetched| fetched.elapsed() >= self.ttl);
        Some((jwk, stale))
    }

    fn is_empty(&self) -> bool {
        self.state
            .read()
            .expect("jwks lock poisoned")
            .keys
            .is_empty()
    }

    /// Refreshes the JWKS at most once per cooldown window (single-flight via
    /// the cooldown), and **never evicts on failure** — a refresh error keeps
    /// the existing keys so a brief Keycloak blip does not drop all auth.
    async fn refresh_if_due(&self) {
        {
            // Claim the cooldown slot atomically so concurrent callers don't
            // stampede; the lock is released before the await.
            let mut state = self.state.write().expect("jwks lock poisoned");
            if let Some(last) = state.last_attempt
                && last.elapsed() < self.cooldown
            {
                return;
            }
            state.last_attempt = Some(Instant::now());
        }

        match self.fetch().await {
            Ok(keys) => {
                let mut state = self.state.write().expect("jwks lock poisoned");
                state.keys = keys;
                state.fetched_at = Some(Instant::now());
            }
            Err(err) => {
                tracing::warn!(error = %err, "jwks: refresh failed; serving cached keys");
            }
        }
    }

    async fn fetch(&self) -> Result<HashMap<String, Value>, reqwest::Error> {
        let doc: JwksDoc = self
            .http
            .get(&self.jwks_url)
            .timeout(JWKS_HTTP_TIMEOUT)
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;

        let keys = doc
            .keys
            .into_iter()
            .filter_map(|key| {
                key.get("kid")
                    .and_then(Value::as_str)
                    .map(|kid| (kid.to_string(), key.clone()))
            })
            .collect();
        Ok(keys)
    }
}

/// Test-only constructor: a validator backed by a fixed, in-memory JWKS so
/// tests can mint and validate JWTs without an HTTP round-trip to Keycloak.
#[cfg(any(test, feature = "test-support"))]
impl TokenValidator {
    pub fn with_static_jwks(issuer_url: String, audience: String, jwks_keys: Vec<Value>) -> Self {
        let keys = jwks_keys
            .into_iter()
            .filter_map(|key| {
                key.get("kid")
                    .and_then(Value::as_str)
                    .map(|kid| (kid.to_string(), key.clone()))
            })
            .collect();
        Self {
            expected_iss: issuer_url,
            expected_aud: audience,
            leeway_secs: DEFAULT_LEEWAY_SECS,
            jwks: JwksCache::with_static_keys(keys),
        }
    }
}

#[cfg(any(test, feature = "test-support"))]
impl JwksCache {
    fn with_static_keys(keys: HashMap<String, Value>) -> Self {
        Self {
            jwks_url: String::new(),
            http: reqwest::Client::new(),
            // A TTL far past any test run, so the cache is never stale and
            // never attempts an HTTP refresh.
            ttl: Duration::from_secs(60 * 60 * 24 * 3650),
            cooldown: Duration::from_secs(0),
            state: RwLock::new(CacheState {
                keys,
                fetched_at: Some(Instant::now()),
                last_attempt: None,
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ISS: &str = "https://kc.example/realms/swiyu-issuer";
    const AUD: &str = "swiyu-issuer-mgmtapi";
    const NOW: i64 = 1_700_000_000;
    const TENANT: &str = "tenant_9hXq2vRtL8pK7f";

    fn base_claims() -> Value {
        json!({
            "iss": ISS,
            "aud": AUD,
            "exp": NOW + 300,
            "principal_type": "tenant",
            "tenant_id": TENANT,
        })
    }

    fn validate(payload: &Value) -> Result<Principal, TokenError> {
        validate_claims(payload, ISS, AUD, NOW, DEFAULT_LEEWAY_SECS)
    }

    #[test]
    fn accepts_well_formed_tenant_claims() {
        match validate(&base_claims()).expect("valid claims") {
            Principal::Tenant(tid) => assert_eq!(tid.to_string(), TENANT),
            other => panic!("expected tenant principal, got {other:?}"),
        }
    }

    #[test]
    fn accepts_aud_as_array_containing_audience() {
        let mut claims = base_claims();
        claims["aud"] = json!(["other-api", AUD]);
        assert!(validate(&claims).is_ok());
    }

    #[test]
    fn rejects_wrong_issuer() {
        let mut claims = base_claims();
        claims["iss"] = json!("https://evil.example/realms/swiyu-issuer");
        assert_eq!(validate(&claims), Err(TokenError::Invalid));
    }

    #[test]
    fn rejects_audience_not_present() {
        let mut claims = base_claims();
        claims["aud"] = json!(["some-other-api"]);
        assert_eq!(validate(&claims), Err(TokenError::Invalid));
    }

    #[test]
    fn rejects_expired_token_beyond_leeway() {
        let mut claims = base_claims();
        claims["exp"] = json!(NOW - DEFAULT_LEEWAY_SECS - 1);
        assert_eq!(validate(&claims), Err(TokenError::Invalid));
    }

    #[test]
    fn accepts_just_expired_token_within_leeway() {
        let mut claims = base_claims();
        claims["exp"] = json!(NOW - 1);
        assert!(validate(&claims).is_ok());
    }

    #[test]
    fn rejects_not_yet_valid_token() {
        let mut claims = base_claims();
        claims["nbf"] = json!(NOW + DEFAULT_LEEWAY_SECS + 1);
        assert_eq!(validate(&claims), Err(TokenError::Invalid));
    }

    #[test]
    fn accepts_first_party_principal_type() {
        let mut claims = base_claims();
        claims["principal_type"] = json!("first-party");
        // A first-party token carries no tenant; `tenant_id` is not read.
        claims.as_object_mut().unwrap().remove("tenant_id");
        assert_eq!(validate(&claims), Ok(Principal::FirstParty));
    }

    #[test]
    fn rejects_unknown_principal_type() {
        for pt in ["user_account", "bff", "anything"] {
            let mut claims = base_claims();
            claims["principal_type"] = json!(pt);
            assert_eq!(validate(&claims), Err(TokenError::Invalid), "pt={pt}");
        }
    }

    #[test]
    fn rejects_tenant_principal_missing_tenant_id() {
        let mut claims = base_claims();
        claims.as_object_mut().unwrap().remove("tenant_id");
        assert_eq!(validate(&claims), Err(TokenError::Invalid));
    }

    #[test]
    fn rejects_missing_principal_type() {
        let mut claims = base_claims();
        claims.as_object_mut().unwrap().remove("principal_type");
        assert_eq!(validate(&claims), Err(TokenError::Invalid));
    }

    #[test]
    fn rejects_malformed_tenant_id() {
        let mut claims = base_claims();
        claims["tenant_id"] = json!("not-a-tenant-id");
        assert_eq!(validate(&claims), Err(TokenError::Invalid));
    }

    #[test]
    fn rejects_bare_tenant_id_without_prefix() {
        let mut claims = base_claims();
        claims["tenant_id"] = json!("9hXq2vRtL8pK7f");
        assert_eq!(validate(&claims), Err(TokenError::Invalid));
    }

    #[test]
    fn jwks_url_is_derived_from_issuer() {
        assert_eq!(
            TokenValidator::jwks_url_for_issuer("https://kc.example/realms/swiyu-issuer/"),
            "https://kc.example/realms/swiyu-issuer/protocol/openid-connect/certs"
        );
    }

    #[test]
    fn parse_jwt_rejects_wrong_segment_count() {
        assert!(parse_jwt("only.two").is_err());
        assert!(parse_jwt("a.b.c.d").is_err());
    }

    #[test]
    fn parse_jwt_extracts_alg_and_kid() {
        let header = URL_SAFE_NO_PAD.encode(br#"{"alg":"EdDSA","kid":"k1"}"#);
        let payload = URL_SAFE_NO_PAD.encode(br#"{"sub":"x"}"#);
        let sig = URL_SAFE_NO_PAD.encode([0u8; 64]);
        let token = format!("{header}.{payload}.{sig}");
        let parsed = parse_jwt(&token).expect("parses");
        assert_eq!(parsed.alg, "EdDSA");
        assert_eq!(parsed.kid.as_deref(), Some("k1"));
        assert_eq!(parsed.signing_input, format!("{header}.{payload}"));
        assert_eq!(parsed.signature.len(), 64);
    }

    #[test]
    fn aud_contains_handles_string_and_array() {
        assert!(aud_contains(Some(&json!("a")), "a"));
        assert!(!aud_contains(Some(&json!("a")), "b"));
        assert!(aud_contains(Some(&json!(["a", "b"])), "b"));
        assert!(!aud_contains(Some(&json!(["a", "b"])), "c"));
        assert!(!aud_contains(None, "a"));
    }
}
