use std::fmt;

use sha2::{Digest, Sha256};

const INVITATION_CODE_BYTES: usize = 16;

/// The single-use secret carried in an invitation link, handed to a user so they
/// can link their identity to a provisioned account.
///
/// 16 bytes from the OS CSPRNG, base58-encoded. The bare value is returned to the
/// caller exactly once at invitation creation (embedded in the link) and is
/// **never persisted** — only its [`InvitationCodeHash`] is.
pub struct InvitationCode(String);

impl InvitationCode {
    pub fn generate() -> Self {
        let mut bytes = [0u8; INVITATION_CODE_BYTES];
        getrandom::fill(&mut bytes).expect("OS RNG must be available");
        Self(bs58::encode(&bytes).into_string())
    }

    /// Reconstructs the code from the value a redeem request carries (the `code`
    /// in the invitation link), so it can be hashed and matched. Distinct from a
    /// `from_stored`: the bare code never comes out of the database.
    pub fn from_wire(s: impl Into<String>) -> Self {
        Self(s.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

// Custom Debug, and no Display/Serialize, so the secret is never rendered into
// logs or responses by accident.
impl fmt::Debug for InvitationCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("InvitationCode")
            .field(&"<redacted>")
            .finish()
    }
}

/// The persistable form of an [`InvitationCode`]: SHA-256 of the bare value.
///
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InvitationCodeHash(String);

impl InvitationCodeHash {
    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn from_stored(s: impl Into<String>) -> Self {
        Self(s.into())
    }
}

/// SHA-256 of the bare code, base58-encoded. Borrows the code (rather than
/// consuming it) so it can be hashed for storage while still being usable — e.g.
/// embedded in the invitation link on the create path.
impl From<&InvitationCode> for InvitationCodeHash {
    fn from(code: &InvitationCode) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(code.0.as_bytes());
        let digest = hasher.finalize();
        Self(bs58::encode(&digest).into_string())
    }
}

impl sqlx::Type<sqlx::Postgres> for InvitationCodeHash {
    fn type_info() -> sqlx::postgres::PgTypeInfo {
        <String as sqlx::Type<sqlx::Postgres>>::type_info()
    }

    fn compatible(ty: &sqlx::postgres::PgTypeInfo) -> bool {
        <String as sqlx::Type<sqlx::Postgres>>::compatible(ty)
    }
}

impl<'r> sqlx::Decode<'r, sqlx::Postgres> for InvitationCodeHash {
    fn decode(value: sqlx::postgres::PgValueRef<'r>) -> Result<Self, sqlx::error::BoxDynError> {
        let s = <String as sqlx::Decode<'r, sqlx::Postgres>>::decode(value)?;
        Ok(Self::from_stored(s))
    }
}

impl<'q> sqlx::Encode<'q, sqlx::Postgres> for InvitationCodeHash {
    fn encode_by_ref(
        &self,
        buf: &mut sqlx::postgres::PgArgumentBuffer,
    ) -> Result<sqlx::encode::IsNull, sqlx::error::BoxDynError> {
        <&str as sqlx::Encode<'q, sqlx::Postgres>>::encode_by_ref(&self.0.as_str(), buf)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_codes_are_distinct() {
        let a = InvitationCode::generate();
        let b = InvitationCode::generate();
        assert_ne!(a.as_str(), b.as_str());
    }

    #[test]
    fn hash_is_deterministic() {
        let code = InvitationCode::generate();
        assert_eq!(
            InvitationCodeHash::from(&code),
            InvitationCodeHash::from(&code)
        );
    }

    #[test]
    fn hash_matches_for_reconstructed_code() {
        // The redeem path hashes a code rebuilt from the wire; it must match the
        // hash taken of the freshly-generated code.
        let code = InvitationCode::generate();
        let stored = InvitationCodeHash::from(&code);
        let presented = InvitationCode::from_wire(code.as_str());
        assert_eq!(stored, InvitationCodeHash::from(&presented));
    }

    #[test]
    fn hash_differs_for_different_codes() {
        let stored = InvitationCodeHash::from(&InvitationCode::generate());
        let other = InvitationCode::generate();
        assert_ne!(stored, InvitationCodeHash::from(&other));
    }

    #[test]
    fn debug_does_not_reveal_code() {
        let code = InvitationCode::generate();
        let rendered = format!("{code:?}");
        assert!(!rendered.contains(code.as_str()));
        assert!(rendered.contains("redacted"));
    }
}
