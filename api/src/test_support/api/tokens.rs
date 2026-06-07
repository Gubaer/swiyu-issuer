//! Test bearer credentials for the management API.
//!
//! Authentication is Keycloak-issued JWTs. Tests mint an EdDSA-signed JWT with
//! a fixed test key and validate it through a [`TokenValidator`] seeded with
//! the matching public key — no Keycloak or HTTP round-trip. [`build_state`]
//! attaches that validator; [`mint_test_token`] signs a matching token.
//!
//! [`build_state`]: super::build_state

use std::sync::LazyLock;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ed25519_dalek::{Signer, SigningKey};
use serde_json::{Value, json};
use sqlx::PgPool;

use crate::api_management::TokenValidator;
use crate::domain::TenantId;

/// Issuer the test validator expects and test tokens carry.
pub const TEST_ISS: &str = "https://test-keycloak.invalid/realms/swiyu-issuer";
/// Audience the test validator expects and test tokens carry.
pub const TEST_AUD: &str = "swiyu-issuer-mgmtapi";
const TEST_KID: &str = "test-key";

/// Deterministic Ed25519 signing key shared by [`test_token_validator`] (as the
/// verifying half, in the JWKS) and [`mint_test_token`] (as the signer).
static TEST_SIGNING_KEY: LazyLock<SigningKey> =
    LazyLock::new(|| SigningKey::from_bytes(&[42u8; 32]));

/// A bearer credential for tests. `as_wire()` yields the JWT string, mirroring
/// the credential API the management routes consume.
pub struct TestToken(String);

impl TestToken {
    pub fn as_wire(&self) -> String {
        self.0.clone()
    }

    /// A credential that must not authenticate: a syntactically-valid JWT
    /// signed by a key the validator does not trust.
    pub fn bogus() -> Self {
        let impostor = SigningKey::from_bytes(&[7u8; 32]);
        TestToken(sign_with(&impostor, &tenant_claims(&TenantId::generate())))
    }
}

/// A [`TokenValidator`] that trusts [`TEST_SIGNING_KEY`], for wiring into an
/// `AppState` in tests.
pub fn test_token_validator() -> TokenValidator {
    let public = TEST_SIGNING_KEY.verifying_key();
    let jwk = json!({
        "kty": "OKP",
        "crv": "Ed25519",
        "kid": TEST_KID,
        "x": URL_SAFE_NO_PAD.encode(public.to_bytes()),
    });
    TokenValidator::with_static_jwks(TEST_ISS.to_string(), TEST_AUD.to_string(), vec![jwk])
}

/// Mints a valid tenant-principal JWT for `tenant_id`, accepted by the
/// validator from [`test_token_validator`]. The `pool` is unused (kept so the
/// signature matches the callers that seed a tenant alongside).
pub async fn mint_test_token(_pool: &PgPool, tenant_id: &TenantId) -> TestToken {
    TestToken(sign_with(&TEST_SIGNING_KEY, &tenant_claims(tenant_id)))
}

/// Mints a valid first-party-principal JWT (the `swiyu-issuer-web` BFF),
/// accepted by the validator from [`test_token_validator`]. Carries no tenant —
/// classifies as `Principal::FirstParty`.
pub fn mint_first_party_token() -> TestToken {
    TestToken(sign_with(&TEST_SIGNING_KEY, &first_party_claims()))
}

fn first_party_claims() -> Value {
    json!({
        "iss": TEST_ISS,
        "aud": TEST_AUD,
        "azp": "swiyu-issuer-web-bff",
        "iat": 1_700_000_000_i64,
        "exp": 9_999_999_999_i64,
        "principal_type": "first-party",
    })
}

fn tenant_claims(tenant_id: &TenantId) -> Value {
    json!({
        "iss": TEST_ISS,
        "aud": TEST_AUD,
        "azp": "test-ba",
        "iat": 1_700_000_000_i64,
        "exp": 9_999_999_999_i64,
        "principal_type": "tenant",
        "tenant_id": tenant_id.to_string(),
    })
}

fn sign_with(key: &SigningKey, claims: &Value) -> String {
    let header = json!({ "alg": "EdDSA", "typ": "JWT", "kid": TEST_KID });
    let header_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).unwrap());
    let payload_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(claims).unwrap());
    let signing_input = format!("{header_b64}.{payload_b64}");
    let signature = key.sign(signing_input.as_bytes());
    format!(
        "{signing_input}.{}",
        URL_SAFE_NO_PAD.encode(signature.to_bytes())
    )
}
