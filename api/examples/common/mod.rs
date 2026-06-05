//! Shared helpers for the smoke-test examples.
//!
//! Lives in a subdirectory so Cargo does not treat it as its own example
//! target; each smoke binary pulls it in with `mod common;`.

use serde::Deserialize;

#[derive(Deserialize)]
struct TokenResponse {
    access_token: String,
}

/// Obtains a `dev-ba` access token — a Keycloak-issued JWT — via the
/// client-credentials grant, for use as the `Authorization: Bearer` credential
/// against `swiyu-issuer-mgmtapi`.
///
/// Reads `KEYCLOAK_TOKEN_URL`, `DEV_BA_CLIENT_ID`, and `DEV_BA_CLIENT_SECRET`
/// from the environment. Errors are returned as a human-readable string for the
/// caller to wrap in its own error type.
pub async fn fetch_dev_ba_token() -> Result<String, String> {
    let token_url = env_var("KEYCLOAK_TOKEN_URL")?;
    let client_id = env_var("DEV_BA_CLIENT_ID")?;
    let client_secret = env_var("DEV_BA_CLIENT_SECRET")?;

    let response = reqwest::Client::new()
        .post(&token_url)
        .form(&[
            ("grant_type", "client_credentials"),
            ("client_id", client_id.as_str()),
            ("client_secret", client_secret.as_str()),
        ])
        .send()
        .await
        .map_err(|e| format!("token request to {token_url}: {e}"))?;

    let status = response.status();
    let body = response
        .text()
        .await
        .map_err(|e| format!("read token response: {e}"))?;
    if !status.is_success() {
        return Err(format!(
            "token endpoint {token_url} returned {status}: {body}"
        ));
    }

    let parsed: TokenResponse =
        serde_json::from_str(&body).map_err(|e| format!("parse token response: {e}"))?;
    Ok(parsed.access_token)
}

fn env_var(name: &str) -> Result<String, String> {
    std::env::var(name).map_err(|_| format!("{name} must be set"))
}
