-- User management: provisioned user accounts and the invitations that link an
-- external user identity to them. Lands on top of the 20260430 baseline.
--
-- See specs/aspect-user-management.md and specs/impl-user-management.md for the
-- design rationale.

-- ============================================================================
-- User accounts
-- ============================================================================
--
-- A user account is owned by exactly one tenant and linked to at most one
-- external user identity (the (iss, sub) pair from the user's token).

CREATE TABLE user_accounts (
    id                             TEXT PRIMARY KEY,
    tenant_id                      TEXT NOT NULL REFERENCES tenants(id),
    -- Provisioning attributes: who the account is intended for, asserted by the
    -- provisioning party at creation time. All optional. Independent of whether
    -- an identity has been linked yet.
    provisioning_first_name        TEXT,
    provisioning_last_name         TEXT,
    provisioning_home_organization TEXT,
    state                          TEXT NOT NULL,   -- 'active' | 'deactivated'
    -- Linked user identity. Both NULL = provisioned but unlinked; both set =
    -- linked. The CHECK keeps the pair all-or-nothing.
    identity_iss                   TEXT,
    identity_sub                   TEXT,
    -- Names as asserted by the IDP in the user's token (given_name /
    -- family_name). NULL until linked, and may stay NULL if the IDP omits the
    -- claims. Refreshed on each successful authentication.
    idp_first_name                 TEXT,
    idp_last_name                  TEXT,
    linked_at                      TIMESTAMPTZ,     -- set when the identity is linked
    created_at                     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT user_accounts_identity_pair
        CHECK ((identity_iss IS NULL) = (identity_sub IS NULL))
);

-- "A user identity is linked to at most one account per owning tenant." NULLs
-- compare distinct in a UNIQUE index, so any number of *unlinked* accounts may
-- coexist in a tenant; only populated identity pairs are constrained.
-- Cross-tenant linking is unconstrained by construction, since the key includes
-- tenant_id.
CREATE UNIQUE INDEX user_accounts_tenant_identity_uq
    ON user_accounts (tenant_id, identity_iss, identity_sub);

-- Identity resolution (GET /api/v1/linked-user-accounts) looks up every account
-- linked to one identity, across tenants.
CREATE INDEX user_accounts_identity_idx
    ON user_accounts (identity_iss, identity_sub);

-- Stable order for the cursor-paginated tenant listing.
CREATE INDEX user_accounts_tenant_created_idx
    ON user_accounts (tenant_id, created_at DESC, id DESC);

-- ============================================================================
-- User account invitations
-- ============================================================================
--
-- An invitation hands a user a single-use code (carried in a link) so they can
-- link their identity to a provisioned account. Only the hash of the code is
-- stored; the bare value lives only in the link.

CREATE TABLE user_account_invitations (
    id                   TEXT PRIMARY KEY,
    user_account_id      TEXT NOT NULL REFERENCES user_accounts(id),
    tenant_id            TEXT NOT NULL REFERENCES tenants(id),  -- denormalised, as on credential_offers
    invitation_code_hash TEXT,             -- hash of the single-use code; NULLed once spent
    state                TEXT NOT NULL,     -- 'pending' | 'accepted' | 'revoked' | 'expired'
    expires_at           TIMESTAMPTZ NOT NULL,
    created_at           TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    accepted_at          TIMESTAMPTZ,
    revoked_at           TIMESTAMPTZ
);

-- The redeem path (POST …/accept) hashes the presented code and looks the
-- invitation up by that hash, so the column is unique while populated.
CREATE UNIQUE INDEX user_account_invitations_code_hash_uq
    ON user_account_invitations (invitation_code_hash);

-- At most one live invitation per account keeps the redeem path unambiguous;
-- partial so accepted/revoked/expired rows are retained as history without
-- blocking a fresh invitation.
CREATE UNIQUE INDEX user_account_invitations_one_pending_uq
    ON user_account_invitations (user_account_id)
    WHERE state = 'pending';
