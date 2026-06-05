//! End-to-end tests for the management-API OAuth2 JWT validator. These
//! exercise the real signature-verification and JWKS-fetch paths that the
//! in-module unit tests deliberately skip: an Ed25519-signed token is
//! validated against an EdDSA JWKS served by a mock Keycloak.

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chrono::{Duration, Utc};
use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use serde_json::{Value, json};
use swiyu_issuer::api_management::TokenValidator;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

const ISS: &str = "https://issuer.example/realms/swiyu-issuer";
const AUD: &str = "swiyu-issuer-mgmtapi";
const KID: &str = "k1";
const TENANT: &str = "tenant_9hXq2vRtL8pK7f";
const CERTS_PATH: &str = "/realms/swiyu-issuer/protocol/openid-connect/certs";

fn signing_key() -> SigningKey {
    SigningKey::from_bytes(&[42u8; 32])
}

/// A JWKS document advertising `pk` as the Ed25519 signing key under `kid`.
fn jwks_for(kid: &str, pk: &VerifyingKey) -> Value {
    json!({
        "keys": [{
            "kty": "OKP",
            "crv": "Ed25519",
            "use": "sig",
            "alg": "EdDSA",
            "kid": kid,
            "x": URL_SAFE_NO_PAD.encode(pk.to_bytes()),
        }]
    })
}

/// Builds an EdDSA-signed JWT with header `kid` and the given claims.
fn sign_jwt(key: &SigningKey, kid: &str, claims: &Value) -> String {
    let header = json!({ "alg": "EdDSA", "typ": "JWT", "kid": kid });
    let header_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).unwrap());
    let payload_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(claims).unwrap());
    let signing_input = format!("{header_b64}.{payload_b64}");
    let sig = key.sign(signing_input.as_bytes());
    let sig_b64 = URL_SAFE_NO_PAD.encode(sig.to_bytes());
    format!("{signing_input}.{sig_b64}")
}

fn valid_claims() -> Value {
    json!({
        "iss": ISS,
        "aud": AUD,
        "azp": "dev-ba",
        "exp": (Utc::now() + Duration::minutes(5)).timestamp(),
        "iat": Utc::now().timestamp(),
        "principal_type": "tenant",
        "tenant_id": TENANT,
    })
}

/// Starts a mock Keycloak serving `jwks` at the certs path and returns a
/// validator pointed at it.
async fn validator_with_jwks(jwks: Value) -> (MockServer, TokenValidator) {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path(CERTS_PATH))
        .respond_with(ResponseTemplate::new(200).set_body_json(jwks))
        .mount(&server)
        .await;
    let jwks_url = format!("{}{CERTS_PATH}", server.uri());
    let validator = TokenValidator::new(
        ISS.to_string(),
        jwks_url,
        AUD.to_string(),
        reqwest::Client::new(),
    );
    (server, validator)
}

#[tokio::test]
async fn accepts_valid_token_and_extracts_tenant() {
    let key = signing_key();
    let (_server, validator) = validator_with_jwks(jwks_for(KID, &key.verifying_key())).await;

    let token = sign_jwt(&key, KID, &valid_claims());
    let tenant = validator
        .validate_tenant(&token, Utc::now())
        .await
        .expect("valid token");
    assert_eq!(tenant.to_string(), TENANT);
}

#[tokio::test]
async fn rejects_token_signed_by_a_different_key() {
    // JWKS advertises the real key under KID; the token is signed by an
    // impostor key but claims the same KID → signature must not verify.
    let real = signing_key();
    let (_server, validator) = validator_with_jwks(jwks_for(KID, &real.verifying_key())).await;

    let impostor = SigningKey::from_bytes(&[7u8; 32]);
    let token = sign_jwt(&impostor, KID, &valid_claims());
    assert!(validator.validate_tenant(&token, Utc::now()).await.is_err());
}

#[tokio::test]
async fn rejects_unknown_kid() {
    let key = signing_key();
    let (_server, validator) = validator_with_jwks(jwks_for(KID, &key.verifying_key())).await;

    // Token references a kid the JWKS does not advertise.
    let token = sign_jwt(&key, "other-kid", &valid_claims());
    assert!(validator.validate_tenant(&token, Utc::now()).await.is_err());
}

#[tokio::test]
async fn rejects_expired_token() {
    let key = signing_key();
    let (_server, validator) = validator_with_jwks(jwks_for(KID, &key.verifying_key())).await;

    let mut claims = valid_claims();
    claims["exp"] = json!((Utc::now() - Duration::hours(1)).timestamp());
    let token = sign_jwt(&key, KID, &claims);
    assert!(validator.validate_tenant(&token, Utc::now()).await.is_err());
}

#[tokio::test]
async fn rejects_wrong_audience() {
    let key = signing_key();
    let (_server, validator) = validator_with_jwks(jwks_for(KID, &key.verifying_key())).await;

    let mut claims = valid_claims();
    claims["aud"] = json!("some-other-api");
    let token = sign_jwt(&key, KID, &claims);
    assert!(validator.validate_tenant(&token, Utc::now()).await.is_err());
}

#[tokio::test]
async fn rejects_non_tenant_principal_type() {
    let key = signing_key();
    let (_server, validator) = validator_with_jwks(jwks_for(KID, &key.verifying_key())).await;

    let mut claims = valid_claims();
    claims["principal_type"] = json!("bff");
    let token = sign_jwt(&key, KID, &claims);
    assert!(validator.validate_tenant(&token, Utc::now()).await.is_err());
}

#[tokio::test]
async fn cold_start_with_jwks_down_is_distinct_from_bad_token() {
    use swiyu_issuer::api_management::TokenError;

    // Mock Keycloak that fails the certs fetch — the cache never populates.
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path(CERTS_PATH))
        .respond_with(ResponseTemplate::new(500))
        .mount(&server)
        .await;
    let jwks_url = format!("{}{CERTS_PATH}", server.uri());
    let validator = TokenValidator::new(
        ISS.to_string(),
        jwks_url,
        AUD.to_string(),
        reqwest::Client::new(),
    );

    let token = sign_jwt(&signing_key(), KID, &valid_claims());
    // No keys cached → transient KeysUnavailable (→ 503), not Invalid (→ 401).
    assert_eq!(
        validator.validate_tenant(&token, Utc::now()).await,
        Err(TokenError::KeysUnavailable)
    );
}
