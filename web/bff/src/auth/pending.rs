//! In-flight logins, keyed by the OIDC `state` parameter.
//!
//! The PKCE verifier must never reach the browser, so the per-login secrets live
//! here server-side (not in a cookie) between the `login` redirect and the
//! `callback`. Single-replica only — like the session store, this is in-memory
//! behind a clean seam.

use std::time::{Duration, Instant};

use dashmap::DashMap;

/// Secrets stashed for one in-flight login, retrieved at the callback.
pub struct PendingLogin {
    pub nonce: String,
    pub pkce_verifier: String,
    pub return_to: String,
    pub created_at: Instant,
}

/// Concurrent map of `state` → [`PendingLogin`], with TTL eviction.
#[derive(Default)]
pub struct PendingLogins {
    inner: DashMap<String, PendingLogin>,
}

impl PendingLogins {
    pub fn new() -> Self {
        Self {
            inner: DashMap::new(),
        }
    }

    pub fn insert(&self, state: String, pending: PendingLogin) {
        self.inner.insert(state, pending);
    }

    /// Removes and returns the pending login for `state`, if present. A login is
    /// single-use: the entry is consumed on lookup.
    pub fn take(&self, state: &str) -> Option<PendingLogin> {
        self.inner.remove(state).map(|(_, pending)| pending)
    }

    /// Drops entries older than `ttl`. Called periodically by the sweep task so
    /// abandoned logins do not accumulate.
    pub fn sweep(&self, ttl: Duration) {
        let now = Instant::now();
        self.inner
            .retain(|_, pending| now.duration_since(pending.created_at) < ttl);
    }
}
