//! Minimal Keycloak Admin REST client used to provision the `dev-ba`
//! `tenant_id` claim mapper.
//!
//! The tenant's own id is generated at tenant-creation time, so it cannot be
//! baked into the static realm export. After the tenant exists, this upserts a
//! hardcoded `tenant_id` mapper onto a client over the Admin API,
//! authenticating as a least-privilege provisioning service-account client.
//! The operation is idempotent: it updates the mapper if present, creates it
//! otherwise.

use reqwest::Client;
use serde::Deserialize;
use serde_json::{Value, json};

/// Name of the protocol mapper this module manages.
const TENANT_ID_MAPPER_NAME: &str = "tenant_id";

/// Whether the mapper was newly created or an existing one updated.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MapperOutcome {
    Created,
    Updated,
}

impl MapperOutcome {
    pub fn verb(self) -> &'static str {
        match self {
            MapperOutcome::Created => "created",
            MapperOutcome::Updated => "updated",
        }
    }
}

#[derive(Deserialize)]
struct TokenResponse {
    access_token: String,
}

/// Upserts a hardcoded `tenant_id = <tenant_id_value>` claim mapper on
/// `client_id` in `realm`, authenticating to the Admin API as the provisioning
/// service-account client.
///
/// `keycloak_url` is the server base (e.g. `http://keycloak:8080`).
/// `tenant_id_value` is the claim value to emit — the prefixed tenant id (e.g.
/// `tenant_9hXq2vRtL8pK7f`), which is what the resource server parses.
pub async fn sync_tenant_id_mapper(
    keycloak_url: &str,
    realm: &str,
    client_id: &str,
    tenant_id_value: &str,
    provisioner_client_id: &str,
    provisioner_client_secret: &str,
) -> Result<MapperOutcome, Box<dyn std::error::Error>> {
    let base = keycloak_url.trim_end_matches('/');
    let http = Client::new();

    let token = fetch_admin_token(
        &http,
        base,
        realm,
        provisioner_client_id,
        provisioner_client_secret,
    )
    .await?;
    let client_uuid = find_client_uuid(&http, base, realm, &token, client_id).await?;

    let models_url =
        format!("{base}/admin/realms/{realm}/clients/{client_uuid}/protocol-mappers/models");
    let mappers: Vec<Value> = http
        .get(&models_url)
        .bearer_auth(&token)
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    let existing = mappers
        .iter()
        .find(|m| m.get("name").and_then(Value::as_str) == Some(TENANT_ID_MAPPER_NAME));

    if let Some(existing) = existing {
        // Preserve the server-assigned id; replace the config with the desired
        // value so a changed tenant id is corrected on re-run.
        let mapper_id = existing
            .get("id")
            .and_then(Value::as_str)
            .ok_or("existing tenant_id mapper has no id")?;
        let mut body = existing.clone();
        body["config"] = mapper_config(tenant_id_value);
        http.put(format!("{models_url}/{mapper_id}"))
            .bearer_auth(&token)
            .json(&body)
            .send()
            .await?
            .error_for_status()?;
        Ok(MapperOutcome::Updated)
    } else {
        http.post(&models_url)
            .bearer_auth(&token)
            .json(&mapper_representation(tenant_id_value))
            .send()
            .await?
            .error_for_status()?;
        Ok(MapperOutcome::Created)
    }
}

/// The `config` block of a hardcoded `tenant_id` claim mapper. Mirrors the
/// `principal_type` mapper shape in the realm export.
fn mapper_config(tenant_id_value: &str) -> Value {
    json!({
        "claim.name": TENANT_ID_MAPPER_NAME,
        "claim.value": tenant_id_value,
        "jsonType.label": "String",
        "access.token.claim": "true",
        "id.token.claim": "false",
        "introspection.token.claim": "true",
    })
}

/// A full protocol-mapper representation for a create (POST).
fn mapper_representation(tenant_id_value: &str) -> Value {
    json!({
        "name": TENANT_ID_MAPPER_NAME,
        "protocol": "openid-connect",
        "protocolMapper": "oidc-hardcoded-claim-mapper",
        "config": mapper_config(tenant_id_value),
    })
}

async fn fetch_admin_token(
    http: &Client,
    base: &str,
    realm: &str,
    client_id: &str,
    client_secret: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    let response = http
        .post(format!(
            "{base}/realms/{realm}/protocol/openid-connect/token"
        ))
        .form(&[
            ("grant_type", "client_credentials"),
            ("client_id", client_id),
            ("client_secret", client_secret),
        ])
        .send()
        .await?;
    let status = response.status();
    let text = response.text().await?;
    if !status.is_success() {
        return Err(format!("Keycloak admin token request failed ({status}): {text}").into());
    }
    let parsed: TokenResponse = serde_json::from_str(&text)?;
    Ok(parsed.access_token)
}

async fn find_client_uuid(
    http: &Client,
    base: &str,
    realm: &str,
    token: &str,
    client_id: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    let clients: Vec<Value> = http
        .get(format!("{base}/admin/realms/{realm}/clients"))
        .query(&[("clientId", client_id)])
        .bearer_auth(token)
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    clients
        .first()
        .and_then(|c| c.get("id"))
        .and_then(Value::as_str)
        .map(String::from)
        .ok_or_else(|| format!("no client '{client_id}' found in realm '{realm}'").into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mapper_config_carries_prefixed_tenant_id() {
        let cfg = mapper_config("tenant_9hXq2vRtL8pK7f");
        assert_eq!(cfg["claim.name"], "tenant_id");
        assert_eq!(cfg["claim.value"], "tenant_9hXq2vRtL8pK7f");
        assert_eq!(cfg["jsonType.label"], "String");
        assert_eq!(cfg["access.token.claim"], "true");
    }

    #[test]
    fn mapper_representation_is_a_hardcoded_claim_mapper() {
        let rep = mapper_representation("tenant_abc");
        assert_eq!(rep["name"], TENANT_ID_MAPPER_NAME);
        assert_eq!(rep["protocolMapper"], "oidc-hardcoded-claim-mapper");
        assert_eq!(rep["protocol"], "openid-connect");
        assert_eq!(rep["config"]["claim.value"], "tenant_abc");
    }
}
