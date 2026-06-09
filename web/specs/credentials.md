# Credentials — UI, data structures, and use cases

## UI

1. A **Credentials** menu entry in the sidebar, placed below **Credential Offerings**.
2. A **list view** that shows the credentials issued by a selected issuer in the main container.
    * Its internal structure mirrors that of the credential offerings.
    * Each credential row carries a row menu with actions to suspend, resume, and revoke the credential.
3. A **detail page** that shows the full details of a single credential, along with buttons to suspend, resume, and revoke it.

## Services

### `CredentialsService` (SPA)

An injectable Angular service that wraps the BFF credential endpoints, mirroring the existing `CredentialOffersService`. It exposes:

* `list(issuerId, options?)` — `GET /api/issuers/{id}/credentials`, cursor-paginated. Forwards the optional `limit`, `cursor`, `state`, and `vct` query parameters and returns `{ items, next_cursor }`.
* `get(issuerId, credentialId)` — `GET /api/issuers/{id}/credentials/{credential_id}`, the full record for a single credential.
* `suspend(issuerId, credentialId)` — `POST .../suspend`.
* `resume(issuerId, credentialId)` — `POST .../unsuspend` (the management API names this `unsuspend`; the UI labels it *Resume*).
* `revoke(issuerId, credentialId)` — `POST .../revoke`.

All three lifecycle calls are **synchronous**: the management API flips the state in one transaction and returns the updated credential record on `200 OK` — there is no operation-task to poll. A disallowed transition comes back as `409 Conflict`; `revoked` is terminal.

A credential record has the shape:

```ts
type CredentialState = 'active' | 'suspended' | 'revoked';

interface Credential {
  id: string;
  issuer_id: string;
  credential_offer_id: string;
  vct: string;
  holder_key_jkt: string;
  status_list_id: string;
  status_list_index: number;
  state: CredentialState;
  expired: boolean; // derived view over expires_at; never a stored state
  issued_at: string;
  expires_at: string;
}
```

### BFF endpoints

The BFF gains thin proxies that forward to the management API with the bearer token injected, mirroring the existing credential-offer proxies (paths drop the `/v1` segment):

| SPA need | BFF route | Management API |
| --- | --- | --- |
| List an issuer's credentials | `GET /api/issuers/{id}/credentials` | `GET /api/v1/issuers/{id}/credentials` |
| Get one credential | `GET /api/issuers/{id}/credentials/{credential_id}` | `GET /api/v1/issuers/{id}/credentials/{credential_id}` |
| Suspend | `POST /api/issuers/{id}/credentials/{credential_id}/suspend` | `POST /api/v1/issuers/{id}/credentials/{credential_id}/suspend` |
| Resume | `POST /api/issuers/{id}/credentials/{credential_id}/unsuspend` | `POST /api/v1/issuers/{id}/credentials/{credential_id}/unsuspend` |
| Revoke | `POST /api/issuers/{id}/credentials/{credential_id}/revoke` | `POST /api/v1/issuers/{id}/credentials/{credential_id}/revoke` |

Query parameters (`limit`, `cursor`, `state`, `vct`) are forwarded as-is, and upstream status codes and JSON bodies are passed through verbatim so the SPA can tell a precondition conflict (`409`) apart from a gateway failure.

## Use Cases

### UC01: Load and render the credential list
* The user clicks **Credentials** and selects an issuer.
* The SPA fetches that issuer's credentials from the mgmtapi through the BFF and renders them.

### UC02: Load and render a single credential
* The user clicks a credential in the credential list.
* The SPA fetches the credential from the mgmtapi through the BFF and renders it on an individual page.

### UC03: Suspend a credential
* Allowed only while the credential is active.
* The SPA calls the suspend API on the mgmtapi through the BFF.
* The call is synchronous: it returns the updated credential record, which the SPA uses to refresh the row and detail view. A disallowed transition comes back as `409 Conflict`. (Propagating the new state to the SWIYU status registry happens out of band in a background worker; the SPA neither triggers nor polls it.)

### UC04: Resume a credential
* Allowed only while the credential is suspended.
* The SPA calls the resume API (mgmtapi `unsuspend`) through the BFF.
* The call is synchronous: it returns the updated credential record, which the SPA uses to refresh the row and detail view. A disallowed transition comes back as `409 Conflict`.

### UC05: Revoke a credential
* Allowed only while the credential is active or suspended.
* The SPA asks the user to confirm, since revocation is permanent and cannot be undone.
* The SPA calls the revoke API on the mgmtapi through the BFF.
* The call is synchronous: it returns the updated credential record, which the SPA uses to refresh the row and detail view. A disallowed transition comes back as `409 Conflict`.

Note: there is no create operation in the SPA. Credentials are minted by holder wallets on behalf of holder using the `swiyu-issuer-oidcapi`.