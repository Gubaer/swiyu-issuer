use std::str::FromStr;

use chrono::{DateTime, Utc};
use sqlx::Row;

use super::DomainError;
use super::ids::{TenantId, UserAccountId};

/// An external identity provider's identifier for a user. Not its own table — an
/// account links to at most one identity, held in two nullable columns.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserIdentity {
    /// The token's `iss` claim — identifies the identity provider.
    pub iss: String,
    /// The token's `sub` claim — the subject (the user) at that provider.
    pub sub: String,
}

impl UserIdentity {
    /// Assembles the optional identity from the two nullable identity columns
    /// (`identity_iss` / `identity_sub`). The `user_accounts_identity_pair` CHECK
    /// makes the pair all-or-nothing, so a half-populated pair is unreachable in
    /// practice; it is reported as an error rather than silently dropped.
    fn from_columns(
        iss: Option<String>,
        sub: Option<String>,
    ) -> Result<Option<Self>, &'static str> {
        match (iss, sub) {
            (Some(iss), Some(sub)) => Ok(Some(Self { iss, sub })),
            (None, None) => Ok(None),
            _ => Err("user_accounts.identity_iss/identity_sub must both be set or both NULL"),
        }
    }
}

/// Lifecycle state of a user account, mirroring [`IssuerState`](super::IssuerState).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UserAccountState {
    /// The initial state of a new account; usable by its linked user.
    Active,
    /// Deactivated and no longer usable by its linked user. One-way — there is
    /// no reactivation.
    Deactivated,
}

impl UserAccountState {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Deactivated => "deactivated",
        }
    }

    pub fn is_terminal(self) -> bool {
        matches!(self, Self::Deactivated)
    }
}

impl FromStr for UserAccountState {
    type Err = DomainError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "active" => Ok(Self::Active),
            "deactivated" => Ok(Self::Deactivated),
            _ => Err(DomainError::InvalidInput {
                details: format!("unknown user account state: {s}"),
            }),
        }
    }
}

impl sqlx::Type<sqlx::Postgres> for UserAccountState {
    fn type_info() -> sqlx::postgres::PgTypeInfo {
        <String as sqlx::Type<sqlx::Postgres>>::type_info()
    }

    fn compatible(ty: &sqlx::postgres::PgTypeInfo) -> bool {
        <String as sqlx::Type<sqlx::Postgres>>::compatible(ty)
    }
}

impl<'r> sqlx::Decode<'r, sqlx::Postgres> for UserAccountState {
    fn decode(value: sqlx::postgres::PgValueRef<'r>) -> Result<Self, sqlx::error::BoxDynError> {
        let s = <&str as sqlx::Decode<'r, sqlx::Postgres>>::decode(value)?;
        s.parse::<UserAccountState>()
            .map_err(|e| Box::new(e) as sqlx::error::BoxDynError)
    }
}

impl<'q> sqlx::Encode<'q, sqlx::Postgres> for UserAccountState {
    fn encode_by_ref(
        &self,
        buf: &mut sqlx::postgres::PgArgumentBuffer,
    ) -> Result<sqlx::encode::IsNull, sqlx::error::BoxDynError> {
        <&str as sqlx::Encode<'q, sqlx::Postgres>>::encode_by_ref(&self.as_str(), buf)
    }
}

/// A provisioned user account, owned by exactly one tenant and linked to at most
/// one user identity.
#[derive(Debug, Clone)]
pub struct UserAccount {
    pub id: UserAccountId,
    pub tenant_id: TenantId,
    /// The intended user as asserted by the provisioning party at creation (all
    /// `provisioning_*` fields are optional). Kept separate from the `idp_*`
    /// fields so the admin UI can show "provisioned for X, signed in as Y" rather
    /// than silently overwriting one with the other.
    pub provisioning_first_name: Option<String>,
    pub provisioning_last_name: Option<String>,
    pub provisioning_home_organization: Option<String>,
    pub state: UserAccountState,
    /// Assembled from the `identity_iss` / `identity_sub` columns: `Some` when
    /// linked, `None` when provisioned-but-unlinked.
    pub identity: Option<UserIdentity>,
    /// The names the IDP asserts for the linked identity, populated and refreshed
    /// on each successful login (may stay `None` if the IDP omits the claims).
    pub idp_first_name: Option<String>,
    pub idp_last_name: Option<String>,
    pub linked_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}

// Hand-written because `identity` is assembled from two columns; the derive
// cannot map `identity_iss` + `identity_sub` into one `Option<UserIdentity>`.
impl<'r> sqlx::FromRow<'r, sqlx::postgres::PgRow> for UserAccount {
    fn from_row(row: &'r sqlx::postgres::PgRow) -> Result<Self, sqlx::Error> {
        let identity =
            UserIdentity::from_columns(row.try_get("identity_iss")?, row.try_get("identity_sub")?)
                .map_err(|msg| sqlx::Error::Decode(msg.into()))?;
        Ok(Self {
            id: row.try_get("id")?,
            tenant_id: row.try_get("tenant_id")?,
            provisioning_first_name: row.try_get("provisioning_first_name")?,
            provisioning_last_name: row.try_get("provisioning_last_name")?,
            provisioning_home_organization: row.try_get("provisioning_home_organization")?,
            state: row.try_get("state")?,
            identity,
            idp_first_name: row.try_get("idp_first_name")?,
            idp_last_name: row.try_get("idp_last_name")?,
            linked_at: row.try_get("linked_at")?,
            created_at: row.try_get("created_at")?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn state_round_trips_through_str() {
        for state in [UserAccountState::Active, UserAccountState::Deactivated] {
            assert_eq!(state.as_str().parse::<UserAccountState>().unwrap(), state);
        }
    }

    #[test]
    fn state_parse_rejects_unknown() {
        assert!(matches!(
            "retired".parse::<UserAccountState>(),
            Err(DomainError::InvalidInput { .. })
        ));
    }

    #[test]
    fn deactivated_is_terminal_active_is_not() {
        assert!(UserAccountState::Deactivated.is_terminal());
        assert!(!UserAccountState::Active.is_terminal());
    }

    #[test]
    fn identity_assembles_when_both_present() {
        let identity =
            UserIdentity::from_columns(Some("iss".to_string()), Some("sub".to_string())).unwrap();
        assert_eq!(
            identity,
            Some(UserIdentity {
                iss: "iss".to_string(),
                sub: "sub".to_string()
            })
        );
    }

    #[test]
    fn identity_is_none_when_both_absent() {
        assert_eq!(UserIdentity::from_columns(None, None).unwrap(), None);
    }

    #[test]
    fn identity_half_populated_pair_is_an_error() {
        assert!(UserIdentity::from_columns(Some("iss".to_string()), None).is_err());
        assert!(UserIdentity::from_columns(None, Some("sub".to_string())).is_err());
    }
}
