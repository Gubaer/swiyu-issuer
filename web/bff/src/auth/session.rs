//! Server-side session state. The browser only ever holds an opaque session id
//! in a cookie; everything here lives in the BFF's session store.

use serde::{Deserialize, Serialize};

/// Key under which [`SessionData`] is stored in the `tower-sessions` session.
pub const SESSION_DATA_KEY: &str = "data";

/// One account the logged-in identity is linked to, as resolved at login.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SessionAccount {
    pub id: String,
    pub tenant_id: String,
    /// The owning tenant's display name (from the resolve response); the SPA
    /// falls back to `tenant_id` when absent.
    pub tenant_display_name: Option<String>,
    /// Precomputed label (idp_* → provisioning_* → id) for the picker/topbar.
    pub display_name: String,
}

/// The full server-side session for a logged-in admin. Never serialised to the
/// browser.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SessionData {
    /// The user's federated identity, cryptographically established at login.
    pub iss: String,
    pub sub: String,
    /// The user's Keycloak tokens. `kc_access_token` is the `subject_token` for
    /// the act-as-user RFC 8693 exchange; `kc_refresh_token` refreshes it;
    /// `kc_id_token` is the `id_token_hint` for single sign-out. None of these
    /// reach the browser.
    pub kc_access_token: String,
    pub kc_refresh_token: String,
    pub kc_id_token: String,
    pub kc_access_expiry_unix: i64,
    /// Wall-clock login time, for the absolute-session-lifetime check.
    pub logged_in_at_unix: i64,
    /// Active accounts the identity resolves to, and the selected one.
    pub accounts: Vec<SessionAccount>,
    pub selected_account_id: String,
}

impl SessionData {
    /// The currently-selected account, if `selected_account_id` still names one
    /// of `accounts`.
    pub fn selected(&self) -> Option<&SessionAccount> {
        self.accounts
            .iter()
            .find(|account| account.id == self.selected_account_id)
    }
}
