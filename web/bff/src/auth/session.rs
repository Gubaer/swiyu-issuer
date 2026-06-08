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

    /// Whether the absolute session lifetime is still in effect at `now_unix`
    /// (the idle timeout is enforced separately by the cookie expiry). `now` is
    /// injected so the check is pure and testable.
    pub fn is_live(&self, now_unix: i64, absolute_timeout_secs: i64) -> bool {
        now_unix < self.logged_in_at_unix.saturating_add(absolute_timeout_secs)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn account(id: &str) -> SessionAccount {
        SessionAccount {
            id: id.to_string(),
            tenant_id: "t1".to_string(),
            tenant_display_name: None,
            display_name: id.to_string(),
        }
    }

    fn session(logged_in_at_unix: i64, accounts: Vec<SessionAccount>, selected: &str) -> SessionData {
        SessionData {
            iss: "iss".to_string(),
            sub: "sub".to_string(),
            kc_access_token: String::new(),
            kc_refresh_token: String::new(),
            kc_id_token: String::new(),
            kc_access_expiry_unix: 0,
            logged_in_at_unix,
            accounts,
            selected_account_id: selected.to_string(),
        }
    }

    #[test]
    fn is_live_until_the_absolute_timeout_elapses() {
        let data = session(1_000, vec![account("a1")], "a1");
        // now < logged_in + timeout
        assert!(data.is_live(1_500, 600));
        // boundary: now == logged_in + timeout is no longer live
        assert!(!data.is_live(1_600, 600));
        assert!(!data.is_live(2_000, 600));
    }

    #[test]
    fn selected_resolves_the_selected_account_or_none() {
        let data = session(0, vec![account("a1"), account("a2")], "a2");
        assert_eq!(data.selected().map(|a| a.id.as_str()), Some("a2"));

        let stale = session(0, vec![account("a1")], "gone");
        assert!(stale.selected().is_none());
    }
}
