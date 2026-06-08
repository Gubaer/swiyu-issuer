# Design and implementation of login and authn

Detailed design for the login and authentication capabilities described in
[`aspect-login-and-authn.md`](aspect-login-and-authn.md). That document names the
three authentication contexts; this one designs how `swiyu-issuer-web` (SPA +
BFF) realises them, end to end.

## Scope and relationship to other specs

The mgmtapi side of this story — how `swiyu-issuer-mgmtapi` *authenticates the
caller* — is already designed and **implemented on this branch**. It is specified
in [`../../api/specs/aspect-authn.md`](../../api/specs/aspect-authn.md),
subaspects 4–7, and realised by `TokenValidator`, the `Principal` /
`principal_type` classification, and the `TenantContext` / `FirstPartyContext`
extractors in `api/src/api_management/`. **This document does not redesign that.**
It designs the **web tier** — the SPA and the BFF — that sits in front of it and
*produces* the tokens mgmtapi already knows how to consume.

The mapping between the two documents' numbering:

| `aspect-login-and-authn.md` context | `aspect-authn.md` subaspect | mgmtapi status |
|---|---|---|
| 3.1 — BFF on behalf of itself (resolve) | 5 — first-party, read-only resolve | implemented (`FirstPartyContext`) |
| 3.2 — BFF on behalf of a tenant (`X-Tenant`) | 7 — first-party admin / invitation linking | implemented (`FirstPartyContext` + `X-Tenant`) |
| 3.3 — BFF on behalf of a selected account (`X-User-Account`) | 6 — act-as-user, token exchange | implemented (`TenantContext` act-as-user path) |

So the work this document plans is **entirely in `web/bff/` and `web/spa/`**, plus
the Keycloak realm wiring (already present in the dev realm) and configuration.
The single-account happy path plus the multi-account picker are both in scope; a
shared/clustered session store is **not** (single-replica memory store, behind a
trait seam).

## The contract mgmtapi already offers

The BFF is a client of these. They are fixed inputs to this design.

**Identity resolution (context 3.1 / subaspect 5).**
`GET /api/v1/linked-user-accounts?iss=…&sub=…`, authenticated by a `first-party`
token (`FirstPartyContext`), returns every account linked to `(iss, sub)` across
tenants:

```jsonc
// 200 — LinkedUserAccountsResponse
{
  "items": [
    {
      "id": "<UserAccountId>",
      "tenant_id": "tenant_…",
      "tenant_display_name": "SWIYU Dev",     // for the picker; null if unset
      "provisioning_first_name": "Dev", "provisioning_last_name": "User",
      "provisioning_home_organization": null,
      "state": "active",                       // or "deactivated"
      "identity": { "iss": "…", "sub": "…" },
      "idp_first_name": "Dev", "idp_last_name": "User",
      "linked_at": "…", "created_at": "…"
    }
  ]
}
```

Notes that shape the BFF logic:
- The list is **unfiltered by state** — it includes `deactivated` accounts. The
  BFF selects only `state == "active"` candidates (a deactivated principal cannot
  log in).
- Each item carries `tenant_id` **and** `tenant_display_name` (the resolve
  endpoint joins `tenants` to supply it), so the picker can label each candidate
  by tenant. The display name is `null` only when the tenant has none set, in
  which case the SPA falls back to the bare `tenant_id`.
- `display_name` is computed by the BFF: `idp_*` when present, else
  `provisioning_*`, else the account id.

**Invitation linking (context 3.2 / subaspect 7).**
`POST /api/v1/invitations/{invitation_id}/accept` with a `first-party` token and a
body asserting `{ code, iss, sub, idp_first_name?, idp_last_name? }`. Used by the
invitation-acceptance flow (a sibling feature; this document references it but the
flow lives in `impl-user-management.md`).

**Act-as-user calls (context 3.3 / subaspect 6).**
Every tenant-scoped mgmtapi route (`/api/v1/issuers`, `/credential-offers`, …)
behind `TenantContext` accepts the act-as-user path: an **exchanged** first-party
token carrying a signed `user_identity` + `act`, plus an `X-User-Account: <UA1>`
header. mgmtapi verifies `UA1` is linked to the token's `(iss, sub)` and derives
the owning tenant from it. The BFF never sends `X-Tenant` on these.

**Token classification.** mgmtapi keys on the `principal_type` claim and (for
first-party) the presence of `act` + `user_identity`. The BFF's only job is to
present the right *shape* of token for the operation.

## Keycloak: what the dev realm already provides

`api/deploy/keycloak/realm/swiyu-issuer-realm.json`, realm `swiyu-issuer`
(dev: `http://localhost:8083/realms/swiyu-issuer`):

- **`swiyu-issuer-web-bff`** — confidential client, secret `dev-bff-secret`.
  - `standardFlowEnabled` (the user OIDC login) **and** `serviceAccountsEnabled`
    (client-credentials, for the BFF's own first-party token).
  - `standard.token.exchange.enabled = true` (RFC 8693).
  - `redirectUris: ["http://localhost:4200/api/auth/callback"]`,
    `webOrigins: ["http://localhost:4200"]`.
  - **post-logout redirect** (`post.logout.redirect.uris`) for single sign-out —
    must include the SPA's post-logout URL, e.g.
    `http://localhost:4200/login`. **This is the one realm change this design
    adds** (the dev realm's BFF client does not yet declare it).
  - default scopes `basic, roles, mgmtapi-audience` (the last stamps
    `aud = swiyu-issuer-mgmtapi`); optional scope `act-as-user` adds the
    `user_identity.iss` / `user_identity.sub` claims — requested **only** at token
    exchange.
  - hardcoded `principal_type = first-party`.
  - access tokens signed `EdDSA` (matches mgmtapi's `TokenValidator`, which only
    accepts `EdDSA`).
- **`dev-user` / `dev-user`** — a local realm user, id
  `11111111-1111-4111-8111-111111111111`, the same `(iss, sub)` the CLI's
  dev-user bootstrap links to the dev tenant's account. In dev the realm *is* the
  IdP; in production `user_identity` is projected from a brokered IdP, but the BFF
  code is identical either way.

Apart from adding the post-logout redirect URI above, no Keycloak changes are
needed for the dev happy path. The BFF otherwise consumes this realm as
configured.

## Context 2 first: the SPA ↔ BFF session

This is the backbone the other two contexts hang off, so it is designed first.

**Server-side session, opaque cookie.** The BFF holds all session state
server-side; the browser gets only an opaque session id in a cookie. Nothing
sensitive (no tokens, no identity) ever reaches the browser.

- Store: `tower-sessions` with its in-memory store. `tower_sessions::SessionStore`
  *is* the seam — swapping to Redis/Postgres for multi-replica is a store-impl
  change with no call-site churn. (Single-replica is an explicit current
  constraint.)
- Cookie: `HttpOnly`, `SameSite=Lax`, `Path=/`, `Secure` from
  `SESSION_COOKIE_SECURE`; name `__Host-swiyu_session` when secure, else
  `swiyu_session`. Idle + absolute timeouts from config.
- CSRF: the SPA sends `X-Requested-With: XMLHttpRequest` on every `/api/*` XHR;
  the BFF requires it on state-changing, session-authenticated routes. Combined
  with `SameSite=Lax` this blocks cross-site form posts. (Login, callback, and
  logout are full-page navigations and exempt.)

**Session contents** (server-side only):

```rust
struct SessionData {
    // identity, cryptographically established at login
    iss: String,
    sub: String,
    // the Keycloak tokens for THIS user — needed to mint act-as-user tokens
    kc_access_token: String,     // subject_token for RFC 8693 exchange
    kc_refresh_token: String,    // to refresh the above when it expires
    kc_access_expiry: i64,
    kc_id_token: String,         // id_token_hint for RP-initiated logout (SLO)
    // the accounts (iss,sub) resolves to, and which one is selected
    accounts: Vec<SessionAccount>,   // active accounts only
    selected_account_id: String,     // one of accounts[].id
}
struct SessionAccount {
    id: String,
    tenant_id: String,
    tenant_display_name: Option<String>, // from resolve; SPA falls back to tenant_id
    display_name: String,
}
```

The Keycloak refresh token is **more** sensitive than the access token; it is
session-scoped, never logged, never serialised to the browser.

**Guarded vs unguarded routes.** The BFF router splits in two:
- **Unguarded:** `/api/auth/login`, `/api/auth/callback`, `/api/auth/logout`,
  and `/api/me`. (Login/callback run the handshake; `/api/me` must answer for an
  anonymous caller so the SPA can decide whether to redirect.)
- **Guarded:** every other `/api/*` route, behind an auth middleware
  (`axum::middleware::from_fn_with_state`) that loads the session, requires a
  `selected_account_id`, inserts the resolved `SessionData` into request
  extensions, and otherwise returns `401 { "error": "unauthenticated" }`.

## Context 1: the user authenticates at the SPA

The full login handshake, owned by the BFF, driven by the SPA.

### BFF auth routes — `web/bff/src/routes/auth.rs` (new)

`GET /api/auth/login?return_to=…`
1. Validate `return_to` is same-origin (`starts_with('/')` && not `starts_with("//")`,
   else `/`).
2. Generate CSRF `state`, OIDC `nonce`, PKCE verifier/challenge (`S256`).
3. Stash a `PendingLogin { nonce, pkce_verifier, return_to, created_at }` in an
   in-memory `DashMap<state, PendingLogin>` on `AppState`, swept on a TTL
   (~10 min) — the verifier must never reach the browser, so this is **not** a
   cookie.
4. `302` to the realm authorization endpoint, scopes `openid profile email`,
   the BFF's `redirect_uri`.

`GET /api/auth/callback?code=…&state=…`
1. Look up and remove the `PendingLogin` by `state` (unknown/expired → `302
   /login?error=state`).
2. Exchange `code` (+ PKCE verifier) at the token endpoint → the user's Keycloak
   `access_token` + `refresh_token` + `id_token`.
3. Verify the `id_token` (signature via realm JWKS, `iss`, `aud`, `exp`, and the
   `nonce` from the pending login). Extract `(iss, sub)` and the `given_name` /
   `family_name` / `email` claims.
   - In dev `(iss, sub)` is `(realm-url, dev-user-id)`; in prod it is the brokered
     IdP's. Either way it is the pair mgmtapi's linking recorded.
4. **Resolve** (context 3.1): call mgmtapi
   `GET /api/v1/linked-user-accounts?iss=&sub=` with the BFF's first-party token.
   Filter to `state == "active"`.
   - `0` active accounts → `302 /login?error=no_access`.
   - `≥1` → build `SessionData`, store the user's Keycloak tokens (including the
     verified `id_token`, retained as the logout `id_token_hint`), store the
     active accounts, set `selected_account_id` to the first (deterministic order),
     persist the session, set the cookie.
5. `302` to `return_to`.

The multi-account case does **not** block login: the user lands authenticated on
the first account and switches afterward via the picker (below). This avoids a
second interstitial in the hot path while still surfacing the choice.

`GET /api/auth/logout` — **single sign-out (RP-initiated logout, full SLO).**
Logging out of the SPA ends the realm SSO session too, so the next visit does not
silently re-authenticate from a live Keycloak session.
1. Read the session; capture its `id_token` (the `id_token_hint`, below). Clear
   the server session and expire the cookie.
2. `302` to the realm `end_session_endpoint` with
   `id_token_hint=<the stored id_token>` and
   `post_logout_redirect_uri=<the SPA's post-logout URL, e.g. /login>`. The hint
   lets Keycloak skip its logout-confirmation page and identifies which SSO
   session to end; the redirect URI must be pre-registered on the BFF client (see
   *Keycloak* and *Configuration*).
3. Keycloak terminates the realm session and redirects the browser back to
   `post_logout_redirect_uri` → the SPA `/login`.

This is a **top-level navigation**, not an XHR: the SPA does
`window.location.href = '/api/auth/logout'` (like login). It is therefore exempt
from the `X-Requested-With` requirement; the worst a forged logout can do is sign
the user out, so the relaxed CSRF posture is acceptable for this route. The
`id_token` rides in the redirect to Keycloak (standard for RP-initiated logout) —
it is the user's own identity token and never carries the access/refresh tokens.

### BFF `/api/me` — `web/bff/src/routes/me.rs` (rewrite)

Replace the dev stub. Read the optional session:
- Present → `200` with the shape the SPA needs:
  ```jsonc
  {
    "identity": { "iss": "…", "sub": "…" },
    "selected_account": {
      "id": "…", "tenant_id": "tenant_…",
      "tenant_display_name": "SWIYU Dev", "display_name": "Dev User"
    },
    "accounts": [ /* all active accounts, for the picker */ ]
  }
  ```
- Absent → `401 { "error": "unauthenticated" }` (not an error the SPA logs; it
  drives the redirect to `/login`).

`DEV_USER_ID` / `DEV_TENANT_NAME` config and the stub are deleted once this lands.

### Account selection / switch — `POST /api/auth/select-account` (guarded)

Body `{ "account_id": "…" }`. The BFF verifies the id is among the session's
active `accounts`, updates `selected_account_id`, returns the new
`selected_account`. (No mgmtapi round-trip — the candidate set is already in the
session and was authoritative at login. mgmtapi re-verifies on every act-as-user
call regardless, so a stale selection cannot escalate.)

## Context 3: the BFF authenticates at mgmtapi

Three token sources. The BFF replaces today's single static `MGMTAPI_TOKEN`
bearer with a small token layer.

### 3.1 / 3.2 — the first-party client-credentials token (process-wide)

A single `FirstPartyTokenProvider` mints a `client_credentials` token for the
`swiyu-issuer-web-bff` client against the realm, caches it in memory with its
`expires_in` (minus a safety margin), and refreshes single-flight on demand. This
is the BFF analogue of mgmtapi's per-tenant `TokenProvider` for SWIYU
(`aspect-authn.md` subaspect 1) — same state-machine shape, one credential set,
no persistence needed (client-credentials re-mints freely).

Used for:
- **3.1 resolve** — `GET /linked-user-accounts` at login. No tenant context, no
  user identity; the BFF asserts `(iss, sub)` as query params.
- **3.2 admin / invitation linking** — `POST /invitations/{id}/accept` (tenant
  from the invitation) and any future tenant-admin write (`X-Tenant` header). The
  BFF asserts the identity in the body. *(These are driven by the
  user-management flows, not the steady-state login; listed here for
  completeness of the token layer.)*

### 3.3 — the act-as-user exchanged token (per session)

For every tenant-scoped data call the logged-in user makes (list issuers, create
an offer, …), the BFF presents an **exchanged** token + `X-User-Account`:

1. Take the user's Keycloak `access_token` from the session
   (`SessionData.kc_access_token`); refresh it via the stored refresh token if
   expired.
2. RFC 8693 token exchange at the realm token endpoint: `grant_type=
   urn:ietf:params:oauth:grant-type:token-exchange`, `subject_token=<user AT>`,
   client auth = the BFF's confidential client, requested scope `act-as-user`,
   audience `swiyu-issuer-mgmtapi`. Keycloak returns a token with
   `principal_type=first-party`, `act={sub: bff}`, and the signed `user_identity`
   `(iss, sub)`.
3. Call mgmtapi with `Authorization: Bearer <exchanged>` and
   `X-User-Account: <selected_account_id>`. **Never** `X-Tenant`.

The exchanged token is short-lived; cache it per session keyed by selected
account, refresh on expiry. mgmtapi verifies the account against the signed
identity and derives the tenant — so the BFF does not need to know or send the
tenant for these calls.

### Routing the existing proxy calls

Today `web/bff/src/routes/{issuers,credential_offers,credential_types,operation_tasks}.rs`
proxy to mgmtapi through one `MgmtApiClient` holding a static bearer. The change:
the guarded data routes acquire an **act-as-user** token (3.3) for the request's
`selected_account_id` and add `X-User-Account`. The client gains a way to send a
per-request `Authorization` + headers rather than only its constructor default.

## SPA design

### Session service — `web/spa/src/app/core/session-service.ts` (from `me-service.ts`)

A signal-backed `SessionService`: `load()` fetches `/api/me` once and caches it;
exposes `me()` and `isAuthenticated()`; a `401` leaves it unauthenticated rather
than throwing. Shape grows from `{ id, tenant_name }` to `{ identity,
selected_account, accounts }`.

### Guard + interceptor — `web/spa/src/app/core/`

- `auth-guard.ts` (`CanActivateFn`): ensure the session is loaded; if
  unauthenticated, `router.navigate(['/login'], { queryParams: { return_to:
  state.url } })`, return `false`.
- `auth-interceptor.ts` (`HttpInterceptorFn`): add `X-Requested-With:
  XMLHttpRequest` to `/api/*`; on a `401` from `/api/*` (except `/api/me`'s own
  probe) clear the cached session and route to `/login`. Registered via
  `withInterceptors([...])` in `app.config.ts`.

### Login page + routes — `web/spa/src/app/features/auth/`

- `login.ts` (+ `.html`/`.scss`): a standalone PrimeNG card with a **Sign in**
  button doing a full-page nav (`window.location.href =
  '/api/auth/login?return_to=' + encodeURIComponent(rt)`) — not an Angular nav,
  not an XHR (the response is a cross-origin `302`). Renders an optional
  `?error=` (`no_access`, `state`, `idp`, `unavailable`).
- `app.routes.ts`: `/login` as a sibling **outside** `AppLayout`; wrap the
  `AppLayout` route (`path: ''`) with `canActivate: [authGuard]`.

### Topbar + account switcher — `web/spa/src/app/layout/component/app.topbar.ts`

Read `SessionService`; show `display_name @ tenant` for the selected account; a
**logout** action doing a full-page nav (`window.location.href =
'/api/auth/logout'`) — not an XHR, because logout is single sign-out: the BFF
`302`s to Keycloak's `end_session_endpoint` and Keycloak redirects back to
`/login`. When `accounts.length > 1`, render a switcher that `POST`s
`/api/auth/select-account` and reloads the session (and current data view).

## Configuration

BFF `web/bff/src/config.rs` + `.env.example` gain (the stale OIDC vars left in an
uncommitted `.env` from the abandoned plan are replaced by these; note the realm
is `swiyu-issuer` on `:8083`, **not** the `:8082/swiyu-issuer-dev` those leftover
lines name):

```
OIDC_ISSUER_URL=http://localhost:8083/realms/swiyu-issuer
OIDC_CLIENT_ID=swiyu-issuer-web-bff
OIDC_CLIENT_SECRET=dev-bff-secret
OIDC_REDIRECT_URI=http://localhost:4200/api/auth/callback
OIDC_POST_LOGOUT_REDIRECT_URI=http://localhost:4200/login
SESSION_COOKIE_SECURE=false
SESSION_IDLE_TIMEOUT_SECS=1800
SESSION_ABSOLUTE_TIMEOUT_SECS=36000
```

`MGMTAPI_TOKEN` (the static bearer) is **removed** — the BFF now mints its own
tokens. `DEV_USER_ID` / `DEV_TENANT_NAME` are removed once `/api/me` is
session-backed.

New BFF dependencies: `openidconnect` (discovery, PKCE, code exchange, id_token
verification), `tower-sessions` (+ memory store), `dashmap` (pending-login map).
`reqwest` is already present. The two non-OIDC service grants — the BFF's own
`client_credentials` token (3.1/3.2) and the RFC 8693 token exchange (3.3) — are
plain form `POST`s to the discovered token endpoint, since `openidconnect` does
not model them; discovery still supplies that endpoint URL.

## Error paths

| Where | Condition | Result |
|---|---|---|
| callback | unknown/expired `state` | `302 /login?error=state` |
| callback | id_token verification fails | `302 /login?error=idp` |
| callback | resolve returns 0 active accounts | `302 /login?error=no_access` |
| callback | mgmtapi resolve unreachable / 5xx | `302 /login?error=unavailable` |
| guarded route | no/expired session | `401 { "error": "unauthenticated" }` → SPA → `/login` |
| act-as-user call | mgmtapi rejects `X-User-Account` (account no longer linked/active) | surface as `401`; SPA re-loads session, may re-pick or `/login` |
| token exchange | user refresh token expired | treat as session expiry → `401` |

The BFF owns the `302 /login?error=…` mapping; the SPA renders `?error=` and the
interceptor owns the mid-session `401 → /login`.


