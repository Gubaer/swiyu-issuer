use std::env::{self, VarError};

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("required env var `{0}` is missing or empty")]
    MissingVar(&'static str),
    #[error("env var `{name}` is not valid UTF-8")]
    NonUnicodeVar { name: &'static str },
    #[error("env var `{name}` could not be parsed as a port: {source}")]
    InvalidPort {
        name: &'static str,
        #[source]
        source: std::num::ParseIntError,
    },
    #[error("env var `{name}` could not be parsed as an integer: {source}")]
    InvalidInt {
        name: &'static str,
        #[source]
        source: std::num::ParseIntError,
    },
    #[error("env var `{name}` could not be parsed as a boolean (expected true/false)")]
    InvalidBool { name: &'static str },
}

/// OIDC + session configuration for the admin-login flow. The BFF is a
/// confidential first-party client of the Keycloak realm.
#[derive(Debug)]
pub struct OidcConfig {
    /// Realm issuer URL; the provider's metadata is discovered from
    /// `{issuer}/.well-known/openid-configuration` at startup.
    pub issuer_url: String,
    pub client_id: String,
    pub client_secret: String,
    /// Where the realm redirects back after the authorization-code step; must be
    /// registered on the client.
    pub redirect_uri: String,
    /// Where the realm redirects back after single sign-out; must be registered
    /// as a post-logout redirect URI on the client.
    pub post_logout_redirect_uri: String,
}

/// Session-cookie and lifetime configuration.
#[derive(Debug)]
pub struct SessionConfig {
    /// `Secure` cookie attribute. `false` for the plain-HTTP dev workflow; must
    /// be `true` behind TLS (and gates the `__Host-` cookie-name prefix).
    pub cookie_secure: bool,
    pub idle_timeout_secs: u64,
    pub absolute_timeout_secs: u64,
}

#[derive(Debug)]
pub struct Config {
    pub bff_port: u16,
    pub mgmtapi_url: String,
    // Only used if identifier-registry write APIs are added later;
    // DID-log fetches resolve through the DID's own `log_url`.
    pub identifier_registry_url: String,
    pub oidc: OidcConfig,
    pub session: SessionConfig,
    pub dev_user_id: String,
    pub dev_tenant_name: String,
    // Directory of built SPA assets to serve as a static fallback. When
    // unset (the dev workflow, where `ng serve` serves the SPA and proxies
    // `/api` here), the BFF serves only the `/api` routes.
    pub spa_dir: Option<String>,
}

impl Config {
    pub fn from_env() -> Result<Self, ConfigError> {
        Ok(Self {
            bff_port: parse_port("BFF_PORT", 3000)?,
            mgmtapi_url: required("MGMTAPI_URL")?,
            identifier_registry_url: optional("IDENTIFIER_REGISTRY_URL", ""),
            oidc: OidcConfig {
                issuer_url: required("OIDC_ISSUER_URL")?,
                client_id: required("OIDC_CLIENT_ID")?,
                client_secret: required("OIDC_CLIENT_SECRET")?,
                redirect_uri: required("OIDC_REDIRECT_URI")?,
                post_logout_redirect_uri: required("OIDC_POST_LOGOUT_REDIRECT_URI")?,
            },
            session: SessionConfig {
                cookie_secure: parse_bool("SESSION_COOKIE_SECURE", false)?,
                idle_timeout_secs: parse_u64("SESSION_IDLE_TIMEOUT_SECS", 1800)?,
                absolute_timeout_secs: parse_u64("SESSION_ABSOLUTE_TIMEOUT_SECS", 36000)?,
            },
            dev_user_id: optional("DEV_USER_ID", "test"),
            dev_tenant_name: optional("DEV_TENANT_NAME", "dev"),
            spa_dir: optional_present("SPA_DIR"),
        })
    }
}

fn required(name: &'static str) -> Result<String, ConfigError> {
    match env::var(name) {
        Ok(value) if !value.trim().is_empty() => Ok(value),
        Ok(_) | Err(VarError::NotPresent) => Err(ConfigError::MissingVar(name)),
        Err(VarError::NotUnicode(_)) => Err(ConfigError::NonUnicodeVar { name }),
    }
}

fn optional(name: &str, default: &str) -> String {
    env::var(name).unwrap_or_else(|_| default.to_string())
}

fn optional_present(name: &str) -> Option<String> {
    match env::var(name) {
        Ok(value) if !value.trim().is_empty() => Some(value),
        _ => None,
    }
}

fn parse_port(name: &'static str, default: u16) -> Result<u16, ConfigError> {
    match env::var(name) {
        Ok(value) => value
            .parse()
            .map_err(|source| ConfigError::InvalidPort { name, source }),
        Err(VarError::NotPresent) => Ok(default),
        Err(VarError::NotUnicode(_)) => Err(ConfigError::NonUnicodeVar { name }),
    }
}

fn parse_u64(name: &'static str, default: u64) -> Result<u64, ConfigError> {
    match env::var(name) {
        Ok(value) if value.trim().is_empty() => Ok(default),
        Ok(value) => value
            .trim()
            .parse()
            .map_err(|source| ConfigError::InvalidInt { name, source }),
        Err(VarError::NotPresent) => Ok(default),
        Err(VarError::NotUnicode(_)) => Err(ConfigError::NonUnicodeVar { name }),
    }
}

fn parse_bool(name: &'static str, default: bool) -> Result<bool, ConfigError> {
    match env::var(name) {
        Ok(value) if value.trim().is_empty() => Ok(default),
        Ok(value) => match value.trim().to_ascii_lowercase().as_str() {
            "true" | "1" | "yes" => Ok(true),
            "false" | "0" | "no" => Ok(false),
            _ => Err(ConfigError::InvalidBool { name }),
        },
        Err(VarError::NotPresent) => Ok(default),
        Err(VarError::NotUnicode(_)) => Err(ConfigError::NonUnicodeVar { name }),
    }
}
