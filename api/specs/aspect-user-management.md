# User Management

This aspect describes how `swiyu-issuer` models the human users who operate on a
tenant's behalf, how those users are represented internally, and how an external
user identity becomes associated with an internal account.

## Concepts

- A **user** is a natural person who authenticates at a web application
  (typically `swiyu-issuer-web`) and thereby accesses `swiyu-issuer-mgmtapi`
  indirectly.
- A **user identity** is a pair `(iss, sub)`, where `iss` uniquely identifies an
  identity provider and `sub` uniquely identifies a subject at that provider. In
  this context the subject is a user.
- A **user account** is a data object managed by `swiyu-issuer`, addressed by a
  unique **user account id**. Each user account is owned by exactly one tenant.

## Linking user identities to user accounts

A user account is linked to either zero or one user identity:

- **Provisioned, unlinked** — the account is linked to no user identity. It
  exists but cannot yet be used by a user.
- **Provisioned and linked** — the account is linked to exactly one user
  identity and is usable by the corresponding user.

The following constraints govern the relationship:

- A user identity is linked to at most one user account per owning tenant.
- A user identity may be linked to multiple user accounts, provided each account
  is owned by a different tenant.

## Provisioning

`swiyu-issuer-mgmtapi` exposes an API to provision user accounts — that is, to
create, update, and activate or deactivate them. Provisioning an account does
not link it to a user identity; linking is a separate step.

## Invitation flow

A user identity is linked to a user account through an invitation:

1. Create an invitation that includes a link to a web interface.
2. Deliver the invitation to the user (for example by email or QR code).
3. The user authenticates with a user identity at `swiyu-issuer-web`.
4. `swiyu-issuer-web` calls an API to link the user identity to the user
   account.

## Identity resolution

`swiyu-issuer-mgmtapi` exposes an API that `swiyu-issuer-web` uses to retrieve
the list of user accounts currently linked to a given user identity.

