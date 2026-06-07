use std::str::FromStr;

use chrono::{DateTime, Utc};

use super::DomainError;
use super::ids::{InvitationId, TenantId, UserAccountId};

/// Lifecycle state of an invitation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InvitationState {
    /// Issued and awaiting redemption — the only non-terminal state, and the
    /// only one whose `invitation_code_hash` is populated.
    Pending,
    /// The user redeemed the invitation and the identity was linked. Terminal.
    Accepted,
    /// Cancelled by the tenant before redemption. Terminal.
    Revoked,
    /// Reached its `expires_at` while still pending. Enforced lazily: a stored
    /// `Pending` row past `expires_at` is treated as `Expired` at read/redeem
    /// time. Terminal.
    Expired,
}

impl InvitationState {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Accepted => "accepted",
            Self::Revoked => "revoked",
            Self::Expired => "expired",
        }
    }

    pub fn is_terminal(self) -> bool {
        !matches!(self, Self::Pending)
    }
}

impl FromStr for InvitationState {
    type Err = DomainError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "pending" => Ok(Self::Pending),
            "accepted" => Ok(Self::Accepted),
            "revoked" => Ok(Self::Revoked),
            "expired" => Ok(Self::Expired),
            _ => Err(DomainError::InvalidInput {
                details: format!("unknown invitation state: {s}"),
            }),
        }
    }
}

impl sqlx::Type<sqlx::Postgres> for InvitationState {
    fn type_info() -> sqlx::postgres::PgTypeInfo {
        <String as sqlx::Type<sqlx::Postgres>>::type_info()
    }

    fn compatible(ty: &sqlx::postgres::PgTypeInfo) -> bool {
        <String as sqlx::Type<sqlx::Postgres>>::compatible(ty)
    }
}

impl<'r> sqlx::Decode<'r, sqlx::Postgres> for InvitationState {
    fn decode(value: sqlx::postgres::PgValueRef<'r>) -> Result<Self, sqlx::error::BoxDynError> {
        let s = <&str as sqlx::Decode<'r, sqlx::Postgres>>::decode(value)?;
        s.parse::<InvitationState>()
            .map_err(|e| Box::new(e) as sqlx::error::BoxDynError)
    }
}

impl<'q> sqlx::Encode<'q, sqlx::Postgres> for InvitationState {
    fn encode_by_ref(
        &self,
        buf: &mut sqlx::postgres::PgArgumentBuffer,
    ) -> Result<sqlx::encode::IsNull, sqlx::error::BoxDynError> {
        <&str as sqlx::Encode<'q, sqlx::Postgres>>::encode_by_ref(&self.as_str(), buf)
    }
}

/// An invitation to link a user identity to a user account.
///
/// `invitation_code` is intentionally absent: it is a write-only secret stored
/// hashed and matched directly by the redeem query, never surfaced through the
/// domain struct.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct Invitation {
    pub id: InvitationId,
    pub user_account_id: UserAccountId,
    pub tenant_id: TenantId,
    pub state: InvitationState,
    pub expires_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
    pub accepted_at: Option<DateTime<Utc>>,
    pub revoked_at: Option<DateTime<Utc>>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn state_round_trips_through_str() {
        for state in [
            InvitationState::Pending,
            InvitationState::Accepted,
            InvitationState::Revoked,
            InvitationState::Expired,
        ] {
            assert_eq!(state.as_str().parse::<InvitationState>().unwrap(), state);
        }
    }

    #[test]
    fn state_parse_rejects_unknown() {
        assert!(matches!(
            "draft".parse::<InvitationState>(),
            Err(DomainError::InvalidInput { .. })
        ));
    }

    #[test]
    fn only_pending_is_non_terminal() {
        assert!(!InvitationState::Pending.is_terminal());
        for state in [
            InvitationState::Accepted,
            InvitationState::Revoked,
            InvitationState::Expired,
        ] {
            assert!(state.is_terminal());
        }
    }
}
