# Implementation plan — Admin login (OIDC authentication flow)

Implements [`authn-login-flow.md`](authn-login-flow.md) — the steady-state
admin login (boundary ① / design-space **A.1** + **B** of
[`../../specs/aspect-authn-authz.md`](../../specs/aspect-authn-authz.md)).

The feature spans three tiers, so the plan is **three ordered phases**, each
shippable and testable on its own:

| Phase | Tier | Outcome |
|---|---|---|
| **P0** | management API (`api/`) | `(iss, sub)` → account(s) resolution (pure read), service-authenticated. |
| **P1** | BFF (`web/bff/`) | The OIDC handshake, server-side session, guarded `/api/*`, real `/api/me`. |
| **P2** | SPA (`web/spa/`) | Login page, route guard, 401 interceptor, logout, session-backed topbar. |

P0 is the only new backend dependency; P1 consumes it; P2 consumes P1. P1 can be
built against a stub resolver while P0 lands in parallel, but P0 is small and
should go first.

This plan covers the **single-account happy path** plus the `0`-account reject.
The multi-account picker, UC04 claim, design-space C/D, a shared session store,
and **`authn_*` refresh at login** are **out of scope** (see the spec's
[*Deferred follow-ons*](authn-login-flow.md#deferred-follow-ons)); where this
plan makes a provisional choice that a deferred item will revisit, it says so.

---

## Decisions to lock for this slice

Inherits every decision in the spec's *Decisions locked* table. The
implementation-level additions:

| Question | Decision for this slice |
|---|---|
| BFF OIDC crate | **`openidconnect`** — provider discovery, PKCE `S256`, code exchange, and `id_token` verification (signature via JWKS, `iss`/`aud`/`exp`/`nonce`) in one crate. Avoids hand-rolling JWT/JWKS. |
| BFF session/cookie plumbing | **`tower-sessions`** + its in-memory store. `tower_sessions::SessionStore` **is** the `SessionStore` trait the spec calls for, so the multi-replica swap (Redis/Postgres) is later a store-impl change, no call-site churn. |
| Pending-login (state → verifier/nonce/return_to) | In-memory `DashMap<state, PendingLogin>` with a TTL sweep (same single-replica caveat as sessions; same sweep idiom as `credential_offers`). Not a cookie — the verifier must never reach the browser. |
| How the **resolve** endpoint is authenticated (it is **cross-tenant**, so `TenantContext` cannot gate it) | A **dedicated service credential**: a `ServiceContext` extractor that constant-time-compares a configured shared secret (`IDENTITY_RESOLVER_TOKEN`). Distinct from the tenant `MGMTAPI_TOKEN`. This is the **minimal seam** for design-space C and will be subsumed by it. |
| `authn_*` refresh at login | **Out of this slice.** `resolve` is a **pure, side-effect-free read** keyed on `(iss, sub)` — it never writes. The BFF already has the IdP's claims from the verified `id_token` for the session and display, so refreshing the stored `authn_*` snapshot is a separate, later concern that only affects an admin *browsing* stored identity attributes — not the logging-in user. See [*Deferred*](authn-login-flow.md#deferred-follow-ons). The endpoint still *reads* `authn_*` (which may be `NULL`) to compute each account's `display_name`, falling back to `provisioning_*`. |
| New DB migration | **None.** P0 reuses `user_identities` + `user_account_identities` + `user_accounts` + `tenants` as-is. |

---

## P0 — management API: identity resolution

### P0.1 Route contract

```
POST /api/v1/identities/resolve        # authenticated (service token required), NOT tenant-scoped
```

A **pure read**: given a verified `(iss, sub)`, return the accounts it is
linked to. No request body field other than the identity; no write.

**Authenticated, but not by a tenant.** "Not tenant-scoped" means the *result*
spans tenants — it does **not** mean the endpoint is open. A valid credential is
still required on every call; a missing/invalid one is `401`. The difference
from the rest of `/api/v1/...` is only *which* credential: a **service token**
(`ServiceContext`, P0.2), not a tenant API token (`TenantContext`).

Request:

```jsonc
{
  "iss": "http://localhost:8082/realms/swiyu-issuer-dev",
  "sub": "11111111-1111-4111-8111-111111111111"
}
```

Response `200`:

```jsonc
{
  "identity": { "iss": "…", "sub": "…" },
  "accounts": [
    {
      "account_id":   "<base58 UserAccountId>",
      "tenant_name":  "swiyu-dev",            // tenants.display_name, fallback to bare id
      "state":        "active",
      "display_name": "Dev User"              // authn_* if present, else provisioning_*
    }
  ]                                            // 0 ⇒ no access; 1 ⇒ happy; >1 ⇒ picker
}
```

`accounts` lists only **active** accounts (`state = active`). A disabled account
is excluded — a disabled principal cannot log in. (`0` after that filter is the
no-access case.) The dev `(iss, sub)` is fixed in
`api/src/cli/tenant/mod.rs` (`DEV_USER_IDENTITY_ISS` + the realm user id).

### P0.2 Service authentication — `ServiceContext`

`api/src/api_management/auth.rs` — add alongside `TenantContext`:

```rust
/// Authenticates a trusted internal service (today: the BFF) by a shared
/// secret, NOT a tenant. Gates cross-tenant operations that `TenantContext`
/// cannot express. Provisional: the per-tenant / on-behalf-of credential
/// (aspect design-space C) supersedes this.
pub struct ServiceContext;

impl FromRequestParts<AppState> for ServiceContext {
    type Rejection = ApiError;
    async fn from_request_parts(parts, state) -> Result<Self, ApiError> {
        let presented = extract_bearer_raw(parts)?;                 // raw, not ApiTokenSecret
        let expected = state.config.identity_resolver_token.as_deref()
            .ok_or(ApiError::Unauthorised)?;                        // unset ⇒ endpoint closed
        if constant_time_eq(presented, expected) { Ok(ServiceContext) }
        else { Err(ApiError::Unauthorised) }
    }
}
```

- `Config` (`api/src/api_management/state.rs`) gains
  `identity_resolver_token: Option<String>`; the mgmtapi binary reads
  `IDENTITY_RESOLVER_TOKEN` (unset ⇒ the route returns `401`, i.e. disabled — no
  open-by-default). Note the existing `Config` is small (`issuer_base_url` only);
  add the field there and populate it in `bin/swiyu-issuer-mgmtapi.rs`.
- Constant-time compare (the `subtle` crate or a small fixed-time byte compare),
  matching the security posture of the hashed-token path.
- **A tenant API token is *not* accepted here, by design.** `ServiceContext`
  checks only `IDENTITY_RESOLVER_TOKEN`; it never consults `api_tokens`, so a
  valid `TenantContext` token fails this gate (and the resolver secret, absent
  from `api_tokens`, fails every tenant route — the two credentials are
  disjoint). This is the point, not an oversight: the resolve **result is
  cross-tenant**, so accepting any tenant token would let tenant A enumerate
  which other tenants an arbitrary `(iss, sub)` has accounts in. Access is
  therefore restricted to the single trusted caller (the BFF), not "any
  authenticated tenant." Do **not** "simplify" this to reuse the tenant-token
  path.

### P0.3 Persistence — cross-tenant resolve (read-only)

`api/src/persistence/user_identities.rs` — add (no schema change; complements the
existing tenant-scoped `find_account_linked_to_identity`):

```rust
pub struct ResolvedAccount {
    pub account_id: UserAccountId,
    pub tenant_id: TenantId,
    pub tenant_display_name: Option<String>,
    pub state: UserAccountState,
    // provisioning_* (per account) is the display-name fallback when the
    // identity's authn_* is still NULL.
    pub provisioning_firstname: String,
    pub provisioning_lastname: String,
    pub provisioning_home_organization: String,
    // authn_* (per identity — same across all this identity's accounts);
    // preferred for display_name when present.
    pub authn_firstname: Option<String>,
    pub authn_lastname: Option<String>,
    pub authn_home_organization: Option<String>,
}

/// All accounts `(iss, sub)` is linked to, ACROSS tenants (login resolution).
/// Joins user_identities → user_account_identities → user_accounts → tenants;
/// filters state = 'active'. Empty Vec ⇒ no access. Read-only — no write.
/// Selects the stored authn_* (may be NULL) so the DTO layer can compute the
/// display-name fallback.
pub async fn resolve_accounts_for_identity(
    conn: &mut PgConnection, iss: &str, sub: &str,
) -> Result<Vec<ResolvedAccount>, PersistenceError>;
```

No `refresh_authn` / `AuthnClaims` in this slice — `resolve` does not write.
The `authn_*` columns and the `(iss, sub)` UNIQUE already exist
(`20260604_000001_user_identities.sql`); `resolve` only reads them.

The display-name fallback (stored `authn_*` → `provisioning_*`) is computed in
the DTO layer from the resolved row, not in SQL.

### P0.4 Handler, DTO, route

- `api/src/api_management/dto.rs`: `ResolveIdentityRequest`
  (`#[serde(deny_unknown_fields)]`, just `iss`/`sub`), `ResolveIdentityResponse`,
  `ResolvedAccountDto`.
- `api/src/api_management/identities.rs` (new — identities are their own resource
  now): a `resolve` handler gated by `ServiceContext`:
  1. normalise `iss`/`sub` (reuse `normalise_required`, `MAX_*_LENGTH` as in
     `link_identity`);
  2. `resolve_accounts_for_identity` (a single pooled-connection read — no
     transaction needed, nothing is written);
  3. build the response (active accounts, display-name fallback).
- Route in `api_management/mod.rs::router`:
  `.route("/api/v1/identities/resolve", post(identities::resolve))`.

### P0.5 Tests

- **Persistence** (`api/tests/user_identities_persistence.rs`, `#[sqlx::test]`):
  resolve returns one account for a linked dev identity; returns **two** when the
  same `(iss, sub)` is linked in two tenants; **excludes disabled** accounts;
  empty for an unknown identity; the resolve read leaves `user_identities`
  **unchanged** (no write side-effect).
- **Integration** (`api/tests/api_resolve_identity.rs`, router `oneshot`): happy
  path `200` (1 account, `display_name` from `provisioning_*` when `authn_*` is
  `NULL`); `0` accounts → `200` with empty `accounts`; wrong/missing
  `IDENTITY_RESOLVER_TOKEN` → `401`; unknown field → `422`/`400` per the house
  convention.

---

## P1 — BFF: OIDC handshake + session

### P1.1 Dependencies & config

`web/bff/Cargo.toml`: `openidconnect`, `tower-sessions`
(+ `tower-sessions-memory-store`), `dashmap`, `subtle` (or reuse), and the
existing `tower`/`tower-http`. `reqwest` is already present (openidconnect can
use it as the HTTP client).

`web/bff/src/config.rs` + `.env.example` — add (per the spec's *Configuration*):

```
OIDC_ISSUER_URL=http://localhost:8082/realms/swiyu-issuer-dev
OIDC_CLIENT_ID=swiyu-issuer-web-bff
OIDC_CLIENT_SECRET=dev-bff-secret
OIDC_REDIRECT_URI=http://localhost:4200/api/auth/callback
SESSION_COOKIE_SECURE=false
SESSION_IDLE_TIMEOUT_SECS=1800
SESSION_ABSOLUTE_TIMEOUT_SECS=36000
IDENTITY_RESOLVER_TOKEN=<same value/var as the api's IDENTITY_RESOLVER_TOKEN>
```

`DEV_USER_ID` / `DEV_TENANT_NAME` stay until `/api/me` is session-backed, then
are deleted (the aspect doc's "retire the dev stub").

### P1.2 OIDC client — `web/bff/src/auth/oidc.rs` (new)

- At startup: discover the provider from `OIDC_ISSUER_URL`
  (`.well-known/openid-configuration`), build a `CoreClient` with client id /
  secret / redirect URI. Discovery failure is a `StartupError` (fail fast).
- `begin_login(return_to) -> (authorize_url, PendingLogin)`: generates CSRF
  `state`, `nonce`, PKCE challenge; requests scopes `openid profile email`.
- `complete_login(code, pending) -> VerifiedIdentity`: exchanges the code with
  the stored PKCE verifier, verifies the `id_token` against the nonce, returns
  `{ iss, sub, authn: AuthnClaims, refresh_token, access_expiry }`. Claims map:
  `given_name`→firstname, `family_name`→lastname, `home_organization` (the realm
  already maps this claim), `email`.

### P1.3 Session + pending-login — `web/bff/src/auth/session.rs` (new)

```rust
#[derive(Clone, Serialize, Deserialize)]   // stored in the tower-sessions session
pub struct Principal {
    pub account_id: String,
    pub tenant_name: String,
    pub display_name: String,
    pub iss: String,
    pub sub: String,
    // refresh_token kept server-side for future IdP-bound calls; never serialised
    // to the browser (the cookie is an opaque session id only).
}
```

- `tower-sessions` `MemoryStore`; cookie configured `HttpOnly`, `SameSite=Lax`,
  `Path=/`, `Secure` from `SESSION_COOKIE_SECURE`, name
  `__Host-swiyu_session` when secure else `swiyu_session`, expiry from the
  idle/absolute timeouts.
- `PendingLogin { nonce, pkce_verifier, return_to, created_at }` in a
  `DashMap<String, PendingLogin>` on `AppState`, with a Tokio interval task
  sweeping entries older than the login TTL (~10 min).

### P1.4 Auth routes — `web/bff/src/routes/auth.rs` (new)

`login`, `callback`, `logout` exactly as the spec's *BFF endpoints* section
specifies. `return_to` validated same-origin (`starts_with('/')` && not
`starts_with("//")`, else `/`). `callback` branches on the resolve result:
`0` → `302 /login?error=no_access`; `1` → set `Principal`, `302 return_to`;
`>1` → set a partial principal **and pick the first, logging the truncation**
(picker deferred, no silent ambiguity), `302 return_to`. Error → the spec's
`/login?error=…` table.

### P1.5 Resolve call — `web/bff/src/upstream/mgmt_api.rs`

Add `resolve_identity(iss, sub) -> Value` (or a typed struct). It must present
the **resolver** token, not the default tenant bearer, so either build a second
`reqwest::Client` for resolver calls or send a per-request `Authorization`
header overriding the default. POSTs `{ iss, sub }` to
`{base}/api/v1/identities/resolve`. A non-2xx maps to the spec's
`/login?error=unavailable`. The BFF keeps the IdP's `authn_*` claims (from the
`id_token`) in the session for display; it does **not** send them to resolve.

### P1.6 Wiring — `web/bff/src/routes/mod.rs`, `main.rs`

- `AppState` gains: `oidc` client, `sessions` store handle, `pending` map,
  `resolver_token`. `main.rs` does discovery, builds the store, spawns the
  sweep, and applies the `tower-sessions` `SessionManagerLayer`.
- Router split: mount `/api/auth/login|callback|logout` and `/api/me`
  **without** the guard; put every other `/api/*` route behind an auth
  middleware (`axum::middleware::from_fn_with_state`) that loads the session,
  requires a `Principal`, inserts it into request extensions, else `401`. (Today
  all `/api/*` are ungated in `routes/mod.rs`.)
- `/api/me` (`routes/me.rs`): read the optional `Principal`; present → the spec's
  body; absent → `401 { "error": "unauthenticated" }`. Drop the config-stub.

### P1.7 Tests

BFF has no test harness today (no `web/bff/tests`). Add unit tests for the pure
pieces — `return_to` validation, claims mapping, the resolve-count → branch
decision — and defer a full handshake integration test (needs a mock IdP) to a
follow-on, noted explicitly so the gap is not silent.

---

## P2 — SPA: login page, guard, interceptor

### P2.1 Session service — `web/spa/src/app/core/session-service.ts`

Evolve `me-service.ts` into a signal-backed `SessionService`: `load()` fetches
`/api/me` once and caches the `Me` (now `{ account_id, tenant_name,
display_name, identity, accounts }`); exposes `me()` signal and
`isAuthenticated()`. A `401` leaves it unauthenticated rather than erroring.

### P2.2 Guard + interceptor

- `core/auth-guard.ts` — `CanActivateFn`: ensure the session is loaded; if
  unauthenticated, `router.navigate(['/login'], { queryParams: { return_to:
  state.url } })` and return `false`.
- `core/auth-interceptor.ts` — functional `HttpInterceptorFn`: add
  `X-Requested-With: XMLHttpRequest` to `/api/*` requests (the CSRF custom-header
  signal); on a `401` from `/api/*` (except `/api/me`’s own probe) clear the
  cached session and route to `/login`. Register via
  `withInterceptors([...])` in `app.config.ts`'s `provideHttpClient`.

### P2.3 Login page + routes

- `features/auth/login.ts` (+ `.html`/`.scss`) — standalone component: centered
  PrimeNG card, product mark, **Sign in** button doing a full-page nav
  (`window.location.href = '/api/auth/login?return_to=' + encodeURIComponent(rt)`)
  — not an Angular router nav and not an XHR (the response is a cross-origin
  302). Render an optional `?error=` message (`no_access`, `idp`, `state`,
  `token`, `unavailable`).
- `app.routes.ts` — add `/login` as a sibling **outside** `AppLayout`; wrap the
  `AppLayout` route (`path: ''`) with `canActivate: [authGuard]`.

### P2.4 Topbar — `layout/component/app.topbar.ts`

Read `SessionService` instead of calling `MeService` directly; show
`display_name @ tenant_name`; add a **logout** action → `POST /api/auth/logout`
(XHR, carries `X-Requested-With`) then `router.navigate(['/login'])`. When
`accounts.length > 1`, this is where the account switcher lands later.

### P2.5 Tests

Vitest unit tests (the repo uses vitest): guard redirects when unauthenticated;
interceptor adds the header and routes to `/login` on `401`; login builds the
correct `return_to`. Update `app.spec.ts` / any `me-service` spec to the new
`SessionService` shape.

---

## Error paths

Implemented exactly as the spec's *Error paths* table. The BFF owns the
`302 /login?error=…` mapping; the SPA renders the `error` query param and the
interceptor owns the mid-session-expiry `401 → /login` path.

---

## Ordered task list

**P0 — backend (do first):**
1. `ServiceContext` + `IDENTITY_RESOLVER_TOKEN` config (P0.2).
2. `resolve_accounts_for_identity` + `ResolvedAccount` (P0.3).
3. DTOs + `resolve` handler + route (P0.4).
4. Persistence + integration tests (P0.5).

**P1 — BFF:**
5. Deps + config + `.env.example` (P1.1).
6. `auth/oidc.rs` — discovery, begin/complete (P1.2).
7. `auth/session.rs` — `Principal`, tower-sessions store, pending-login map + sweep (P1.3).
8. `routes/auth.rs` — login/callback/logout (P1.4).
9. `mgmt_api.rs::resolve_identity` (P1.5).
10. Wire `AppState`, session layer, auth middleware, session-backed `/api/me`; remove the stub (P1.6).
11. Unit tests (P1.7).

**P2 — SPA:**
12. `SessionService` (P2.1).
13. Guard + interceptor + register (P2.2).
14. Login page + routes (P2.3).
15. Topbar display + logout (P2.4).
16. Vitest specs (P2.5).

**Close-out:**
17. BFF `cargo fmt && cargo clippy --all-targets` clean; SPA `ng build` + `prettier` clean; then **ask the user to run `cargo test` and `ng test`** (do not run the suites). End-to-end manual check: `docker compose up` Keycloak, mgmtapi with `IDENTITY_RESOLVER_TOKEN`, BFF, `ng serve`; log in as `dev`/`dev`.

---

## Files touched (anticipated)

```
# P0 — management API
api/src/api_management/auth.rs              ServiceContext + raw-bearer extractor
api/src/api_management/state.rs             Config.identity_resolver_token
api/src/bin/swiyu-issuer-mgmtapi.rs         read IDENTITY_RESOLVER_TOKEN
api/src/api_management/identities.rs        (new) resolve handler
api/src/api_management/mod.rs               mod + route
api/src/api_management/dto.rs               Resolve* DTOs
api/src/persistence/user_identities.rs      resolve_accounts_for_identity, ResolvedAccount
api/tests/api_resolve_identity.rs           (new)
api/tests/user_identities_persistence.rs    + resolve cases (read-only)

# P1 — BFF
web/bff/Cargo.toml                          openidconnect, tower-sessions, dashmap, subtle
web/bff/src/config.rs                        OIDC + session + resolver config
web/bff/src/auth/mod.rs                      (new)
web/bff/src/auth/oidc.rs                     (new)
web/bff/src/auth/session.rs                  (new) Principal, store, pending-login + sweep
web/bff/src/routes/auth.rs                   (new) login/callback/logout
web/bff/src/routes/me.rs                     session-backed /api/me
web/bff/src/routes/mod.rs                    mount auth routes + guard middleware
web/bff/src/upstream/mgmt_api.rs             resolve_identity
web/bff/src/main.rs                          discovery, session layer, sweep task
web/bff/.env.example                         new vars

# P2 — SPA
web/spa/src/app/core/session-service.ts     (from me-service.ts)
web/spa/src/app/core/auth-guard.ts          (new)
web/spa/src/app/core/auth-interceptor.ts    (new)
web/spa/src/app/features/auth/login.ts      (new, + .html/.scss)
web/spa/src/app/app.routes.ts               /login + authGuard
web/spa/src/app/app.config.ts               withInterceptors
web/spa/src/app/layout/component/app.topbar.ts  display_name + logout
```
