# User Management – Design 

## Data structures

User management adds two aggregates — the **user account** and the
**invitation** — plus the persisted **user identity** carried on a linked
account. Both aggregates follow the existing conventions (see
[`impl_persistence.md`](impl_persistence.md) and
[`impl_domain.md`](impl_domain.md)): a bare base58 id in a `TEXT PRIMARY KEY`,
`tenant_id TEXT NOT NULL REFERENCES tenants(id)`, lifecycle `state` held as
`TEXT` rather than a Postgres enum, and `TIMESTAMPTZ … DEFAULT NOW()` for
audit/ordering columns. The schema lands in a new migration on top of the
baseline (e.g. `20260606_000001_user_management.sql`), not by editing
`20260430_000001_init.sql`.

### Identifiers

Two new id newtypes, defined alongside the others via the `define_id!` macro in
[`api/src/domain/ids.rs`](../src/domain/ids.rs):

```rust
define_id!(UserAccountId, "account");   // account_9hXq2vRtL8pK7f
define_id!(InvitationId,  "invite");    // invite_9hXq2vRtL8pK7f
```

They inherit the shared scheme: 10 bytes of CSPRNG, base58-encoded; bare form in
the database, prefixed form on the wire and in logs.

### User identity

A **user identity** is the pair `(iss, sub)` from `aspect-user-management.md`. It
is not its own table — an account links to at most one identity, so the identity
lives in two nullable columns on the account row. In the domain it is a small
value object:

```rust
/// An external identity provider's identifier for a user: the `iss`
/// (identity provider) and `sub` (subject) claims of the user's token.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserIdentity {
    pub iss: String,
    pub sub: String,
}
```

### `user_accounts` table

```sql
CREATE TABLE user_accounts (
    id                            TEXT PRIMARY KEY,
    tenant_id                     TEXT NOT NULL REFERENCES tenants(id),
    -- Provisioning attributes: who the account is intended for, asserted
    -- by the provisioning party at creation time. All optional — the
    -- provisioning party supplies what it knows. Independent of whether
    -- an identity has been linked yet.
    provisioning_first_name       TEXT,
    provisioning_last_name        TEXT,
    provisioning_home_organization TEXT,
    state                         TEXT NOT NULL,   -- 'active' | 'deactivated'
    -- Linked user identity. Both NULL = provisioned but unlinked;
    -- both set = linked. The CHECK keeps the pair all-or-nothing.
    identity_iss                  TEXT,
    identity_sub                  TEXT,
    -- Names as asserted by the IDP in the user's token (given_name /
    -- family_name). NULL until linked, and may stay NULL if the IDP
    -- omits the claims. Refreshed on each successful authentication.
    idp_first_name                TEXT,
    idp_last_name                 TEXT,
    linked_at                     TIMESTAMPTZ,     -- set when the identity is linked
    created_at                    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT user_accounts_identity_pair
        CHECK ((identity_iss IS NULL) = (identity_sub IS NULL))
);

-- "A user identity is linked to at most one account per owning tenant."
-- NULLs compare distinct in a UNIQUE index, so any number of *unlinked*
-- accounts may coexist in a tenant; only populated identity pairs are
-- constrained. Cross-tenant linking is unconstrained by construction,
-- since the key includes tenant_id.
CREATE UNIQUE INDEX user_accounts_tenant_identity_uq
    ON user_accounts (tenant_id, identity_iss, identity_sub);

-- Identity resolution (GET /api/v1/linked-user-accounts) looks up every
-- account linked to one identity, across tenants.
CREATE INDEX user_accounts_identity_idx
    ON user_accounts (identity_iss, identity_sub);

-- Stable order for the cursor-paginated tenant listing.
CREATE INDEX user_accounts_tenant_created_idx
    ON user_accounts (tenant_id, created_at DESC, id DESC);
```

The `provisioning_*` columns record the intended user as asserted at
provisioning; the `idp_*` columns record the names the IDP actually asserts for
the linked identity. Keeping them separate lets the admin UI show "provisioned
for X, signed in as Y" and surfaces identity mismatches rather than silently
overwriting one with the other. `provisioning_home_organization` is the *user's*
home organization (the SWITCH edu-ID `swissEduPersonHomeOrganization` /
`schac_home_organization` attribute), distinct from the tenant, which is the
SWIYU Business Partner organization.

### `user_account_invitations` table

```sql
CREATE TABLE user_account_invitations (
    id              TEXT PRIMARY KEY,
    user_account_id TEXT NOT NULL REFERENCES user_accounts(id),
    tenant_id       TEXT NOT NULL REFERENCES tenants(id),  -- denormalised, as on credential_offers
    invitation_code_hash TEXT,             -- hash of the single-use code carried in the invitation link
    state           TEXT NOT NULL,         -- 'pending' | 'accepted' | 'revoked' | 'expired'
    expires_at      TIMESTAMPTZ NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    accepted_at     TIMESTAMPTZ,
    revoked_at      TIMESTAMPTZ
);

-- The redeem path (POST …/accept) hashes the presented code and looks the
-- invitation up by that hash, so the column is unique while populated.
CREATE UNIQUE INDEX user_account_invitations_code_hash_uq
    ON user_account_invitations (invitation_code_hash);

-- At most one live invitation per account keeps the redeem path
-- unambiguous; partial so accepted/revoked/expired rows are retained
-- as history without blocking a fresh invitation.
CREATE UNIQUE INDEX user_account_invitations_one_pending_uq
    ON user_account_invitations (user_account_id)
    WHERE state = 'pending';
```

The bare code is never persisted: `invitation_code_hash` holds `bs58(SHA-256(code))`
(the `access_token.rs` `AccessTokenHash` precedent — a plain deterministic
SHA-256, since the code is high-entropy and the redeem path must look up by hash).
The hash is present while the invitation is `pending` and is NULLed out when the
invitation leaves that state (accepted, revoked, or swept as expired), so a spent
code's hash is not retained. Invitations carry a longer exposure window than a
wallet pre-auth code (the link is emailed or shown as a QR), which is why the
bare value is not kept at rest as `credential_offers.pre_auth_code` does.

### Domain types

```rust
/// Lifecycle state of a user account. Mirrors IssuerState: new accounts
/// start Active; deactivation is one-way.
pub enum UserAccountState { Active, Deactivated }

/// Lifecycle state of an invitation.
pub enum InvitationState { Pending, Accepted, Revoked, Expired }

/// A provisioned user account, owned by exactly one tenant and linked
/// to at most one user identity.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct UserAccount {
    pub id: UserAccountId,
    pub tenant_id: TenantId,
    // Set at provisioning; all optional.
    pub provisioning_first_name: Option<String>,
    pub provisioning_last_name: Option<String>,
    pub provisioning_home_organization: Option<String>,
    pub state: UserAccountState,
    pub identity: Option<UserIdentity>,    // assembled from identity_iss / identity_sub
    // Asserted by the IDP for the linked identity; populated/refreshed at login.
    pub idp_first_name: Option<String>,
    pub idp_last_name: Option<String>,
    pub linked_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}

/// An invitation to link a user identity to a user account.
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
    // `invitation_code_hash` is intentionally excluded from the domain struct:
    // it is a write-only value matched directly by the redeem query, never
    // surfaced. The bare code is never persisted (see the table above).
}
```

Each lifecycle enum gets the same `as_str` / `parse` plus `sqlx::Type` /
`Encode` / `Decode` TEXT mapping that `IssuerState` carries. The `identity`
field maps the two nullable columns into an `Option<UserIdentity>`; because the
CHECK guarantees the pair is all-or-nothing, the assembly is total.

### Persistence module

```
api/src/persistence/user_accounts.rs
    fn insert(conn, &UserAccount)                          — INSERT INTO user_accounts
    fn get(conn, tenant_id, user_account_id)               — tenant-scoped fetch
    fn update_provisioning(conn, …)                        — partial UPDATE of provisioning_* attributes
    fn set_state(conn, tenant_id, id, state)               — activate / deactivate
    fn link_identity(conn, id, &UserIdentity, idp_names)   — set identity_* + idp_* + linked_at; relies on the UNIQUE index
    fn refresh_idp_names(conn, &UserIdentity, idp_names)   — update idp_* on each successful authentication
    fn list_by_tenant(conn, tenant_id, ListPageQuery)      — cursor page, tenant-scoped
    fn list_by_identity(conn, &UserIdentity)               — cross-tenant resolution

api/src/persistence/user_account_invitations.rs
    fn insert(conn, &Invitation, invitation_code_hash)     — INSERT (pending)
    fn find_by_code_hash(conn, invitation_code_hash)       — redeem lookup
    fn list_by_account(conn, tenant_id, account_id, …)     — cursor page
    fn mark_accepted(conn, id) / mark_revoked(conn, id)    — state transition + NULL the code hash
    fn expire_pending_if_due(conn, user_account_id, now)   — flip a due pending row to 'expired' (NULL hash) on demand
```

Expiry is enforced **lazily**, not by a scheduled sweep: a stored-`pending`
invitation whose `expires_at` has passed is treated as `Expired` wherever its
state is surfaced or acted on (`list_by_account` projects it, `find_by_code_hash`
and the accept handler reject it). The stored `state` stays `pending` — the same
way credential offers compute expiry at read time without persisting it. The one
place expiry must be persisted is invitation creation: because
`user_account_invitations_one_pending_uq` is partial on `state = 'pending'`, a
lazily-expired row that is still physically `pending` would block a fresh
invitation, so `create` runs `expire_pending_if_due` first (same transaction)
before inserting the new pending row.

All functions take `&mut PgConnection`; transaction boundaries are owned by the
calling handler. `link_identity` and `mark_accepted` run in one transaction on
the redeem path so the link and the invitation state flip commit together.

## API

All endpoints live under `swiyu-issuer-mgmtapi` at the `/api/v1` base path,
exchange JSON, and follow the conventions already used by the issuer and
credential-type endpoints: opaque generated ids, collections that accept `POST`
to create and `GET` to list, item resources at `/{id}`, state transitions
expressed as `POST` action sub-resources, and cursor-based list pagination
(`limit` plus an opaque `cursor`, with `next_cursor` returned for the following
page).

The endpoints fall into three authentication contexts, all defined in
[`aspect-authn.md`](./aspect-authn.md):

- **Tenant-scoped** — the request is bound to a single tenant and operates only
  on user accounts owned by that tenant. The owning tenant is derived from the
  access token. Reached either by a business application acting on its own
  behalf (subaspect 4) or by the `swiyu-issuer-web` BFF acting on behalf of a
  selected user account via token exchange (subaspect 6, where an
  `X-User-Account` header names the selected account). Covers user-account
  provisioning and invitation management.
- **BFF on its own behalf** — the BFF authenticates with its own client
  credentials (subaspect 5). It is not acting for any one tenant or user
  account, so the user identity `(iss, sub)` is not carried in the token;
  instead the BFF supplies the identity it has just authenticated as an explicit
  parameter. Used only for identity resolution, which spans tenants because an
  identity may be linked to accounts owned by different tenants.
- **BFF on behalf of a tenant (linking)** — the redeem step is a tenant-scoped
  write performed by the BFF (subaspect 7), *not* on behalf of a logged-in user
  (subaspect 6): subaspect 6 presupposes an existing identity↔account link, and
  linking is precisely what establishes that link. The BFF presents the same
  `principal_type = first-party` token as for resolution; what makes this a tenant-scoped
  write is the request, not a distinct principal. The target tenant is not named
  explicitly — it is derived from the invitation identified in the request path
  — and the freshly authenticated user identity `(iss, sub)` rides in the
  request body as the data to link rather than as the authorizing principal.
  (Tenant-admin operations with no such path resource instead name the tenant in
  an `X-Tenant` header; see subaspect 7.)

User-account provisioning is a synchronous database operation, so — unlike
issuer creation — it does not return an operation task to poll.

### User accounts (tenant-scoped)

| Method & path | Purpose |
| --- | --- |
| `POST /api/v1/user-accounts` | Provision a user account for the calling tenant. Optional `provisioning_first_name`, `provisioning_last_name`, and `provisioning_home_organization` may be supplied. Returns the new `user_account_id`. |
| `GET /api/v1/user-accounts` | List the tenant's user accounts (cursor-paginated). Each entry reports its provisioning attributes, activation state, and the linked user identity with its IDP names (if linked). |
| `GET /api/v1/user-accounts/{user_account_id}` | Retrieve a single user account. Returns `404` if it is not owned by the calling tenant. |
| `PATCH /api/v1/user-accounts/{user_account_id}` | Update the provisioning attributes of the user account. The `idp_*` names are not editable — they are sourced from the IDP token. |
| `POST /api/v1/user-accounts/{user_account_id}/activate` | Activate the user account. |
| `POST /api/v1/user-accounts/{user_account_id}/deactivate` | Deactivate the user account. A deactivated account cannot be used by its linked user. |

### Invitations (tenant-scoped)

An invitation is the artifact handed to a user so they can link their own user
identity to a provisioned account. It carries a single-use code, a link to the
`swiyu-issuer-web` interface, and an expiry.

| Method & path | Purpose |
| --- | --- |
| `POST /api/v1/user-accounts/{user_account_id}/invitations` | Create an invitation for the account. Returns the `invitation_id`, the invitation link, and the expiry. Rejected if the account is already linked to a user identity. |
| `GET /api/v1/user-accounts/{user_account_id}/invitations` | List the invitations issued for the account (cursor-paginated), with their state (pending, accepted, revoked, expired). |
| `POST /api/v1/invitations/{invitation_id}/revoke` | Revoke a pending invitation. |

### Linking (BFF on behalf of a tenant)

When the user authenticates at `swiyu-issuer-web` and opens the invitation link,
the BFF redeems the invitation, acting on behalf of the tenant that owns the
invited account (subaspect 7; see the linking authentication context above). The
target account, and therefore the tenant, is identified by the `invitation_id`
in the request path. The request body carries both the bare single-use `code`
from the link and the freshly authenticated user identity `(iss, sub)` to link:
the server hashes the code, resolves the invitation via the code hash, and
requires it to match the `invitation_id` in the path, so both the unguessable id
and the secret code must agree before the link is established.

| Method & path | Purpose |
| --- | --- |
| `POST /api/v1/invitations/{invitation_id}/accept` | Link the supplied user identity to the user account named by the invitation, then mark the invitation accepted. Rejected if the invitation is not pending, if it has expired, or if the identity is already linked to another account owned by the same tenant. |

### Identity resolution (BFF on its own behalf)

| Method & path | Purpose |
| --- | --- |
| `GET /api/v1/linked-user-accounts?iss={iss}&sub={sub}` | List the user accounts currently linked to the supplied user identity. Because a user identity may be linked to accounts owned by different tenants, the result spans tenants; each entry names its owning tenant so the BFF can select one. |

