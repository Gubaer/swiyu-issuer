//! Authentication layer for the BFF: OIDC provider discovery and the token
//! sources the BFF presents to `swiyu-issuer-mgmtapi`.

mod login;
mod oidc;
mod pending;
mod session;
mod token;

pub use login::{LoginClientError, OidcLoginClient};
pub use oidc::{DiscoveryError, OidcEndpoints, discover};
pub use pending::PendingLogins;
pub use session::{SESSION_DATA_KEY, SessionAccount, SessionData};
pub use token::{FirstPartyTokenProvider, TokenError};
