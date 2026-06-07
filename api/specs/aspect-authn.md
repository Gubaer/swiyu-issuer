# Authentication 

The aspect of authentication in `swiyu-issuer` (both in the `swiyu-issuer-mgmtapi` and in the `swiyu-issuer-oidcapi`) is rich. We distinguish the following subaspects:

1. `swiyu-issuer-mgmtapi` as an authenticated principal for SWIYU registries
    * Approach: Client Credential flow. Currently incomplete, because SWIYU doesn't yet offer a token endpoint with client credential flow. We have to mint an access token and a refresh token in ePortal and configure them manually in `swiyu-issuer-mgmtapi`.
    * Status: currently implemented 
2. a holders wallet as an authenticated principal to access `swiyu-issuer-oidcapi`
    * Approach: Pre-Authorized Code flow. `swiyu-issuer-oidcapi` mints a one-time pre-authorization code. The wallet exchanges the pre-authorization code for an access token at the token endpoint of `swiyu-issuer-oidcapi`.
    * Status: currently implemented
3. a holder proves possession of its own key pair so that the credential issued by `swiyu-issuer-oidcapi` is cryptographically bound to that key
    * Approach: when requesting the credential, the holder submits a Proof-of-Possession (PoP): a JWT signed with the holder's private key that embeds the matching public key (as a `jwk`) and the `c_nonce` previously issued at the token endpoint. `swiyu-issuer-oidcapi` verifies the signature (EdDSA or ES256) and binds the issued credential to that public key via the `cnf` claim. The PoP is presented alongside the access token from subaspect 2, which is what authenticates the request.
    * Status: currently implemented
4. a business application (BA) accesses the `swiyu-issuer-mgmtapi` **on behalf of** a tenant
    * Approach: Client Credentials flow against a Keycloak authorization server (AS). One confidential client per BA, bound to one tenant; its access token carries `principal_type = tenant` and a `tenant_id` claim. `swiyu-issuer-mgmtapi` is an OAuth2 resource server that scopes the request to that tenant and authorizes against its own policy. See [Authenticating callers into `swiyu-issuer-mgmtapi`](#authenticating-callers-into-swiyu-issuer-mgmtapi-subaspects-47) below.
    * Status: not yet implemented (currently uses a shared, tenant-specific opaque token)
5. the BFF of `swiyu-issuer-web` accesses the `swiyu-issuer-mgmtapi` **on behalf of** the BFF (to resolve a user identity against available user accounts)
    * Approach: the first-party BFF authenticates with Client Credentials; its token carries `principal_type = first-party`. Used for the read-only, cross-tenant identity-resolution lookup; the user identity `(iss, sub)` is supplied by the trusted BFF as a parameter. See below.
    * Status: not yet implemented (currently uses a shared secret)
6. the BFF of `swiyu-issuer-web` accesses the `swiyu-issuer-mgmtapi` **on behalf of** a specific user account UA1 owned by a tenant T1
    * Approach: OAuth Token Exchange (RFC 8693). An OIDC Authorization Code login yields the user's identity; the BFF exchanges it into an mgmtapi token that carries that identity in a signed `user_identity` claim and whose `act` names the BFF (still `principal_type = first-party`). Because identity→account is 1:n and the choice is interactive, the selected account UA1 travels out-of-band in `X-User-Account` and `swiyu-issuer-mgmtapi` verifies it against the identity before deriving the owning tenant. This is the only path where the identity is cryptographically established rather than asserted. See below.
    * Status: not yet implemented
7. the BFF of `swiyu-issuer-web` accesses the `swiyu-issuer-mgmtapi` **on behalf of** a tenant, without a selected user account
    * Approach: a `principal_type = first-party` token acting administratively for a tenant — e.g. linking a user identity to a user account (the tenant is taken from the invitation named in the request path; see [`impl-user-management.md`](impl-user-management.md)), or other tenant-admin writes that name the target tenant in an `X-Tenant` header. The identity to link is asserted by the trusted BFF in the request body. No distinct principal type and no per-tenant client are needed. See below.
    * Status: not yet implemented

## Subaspect 1: Authenticate swiyu-issuer-mgmtapi at SWIYU registries

This section describes how `swiyu-issuer` obtains, caches, and refreshes the OAuth2 access tokens it presents to the SWIYU registries on behalf of its tenants.

It is the issuer-side complement to [`swiyu-registries/specs/aspect-oauth2.md`](../../swiyu-registries/specs/aspect-oauth2.md). That document describes the SWIYU OAuth2 protocol itself — endpoints, grant types, partner credentials, the empirical facts about TTLs and rotation. This section describes how a multi-tenant issuer process implements the partner side of that protocol: the `TokenProvider` abstraction, the refresh state machine, the integration with tenant configuration, and the operational considerations around the seven-day refresh-token TTL.

### Where this layer sits

`swiyu-registries` is a thin HTTP wrapper. Its registry clients (`IdentifierRegistryClient`, `StatusRegistryClient`) accept an `&AccessToken` as a per-call argument and do nothing about acquiring or refreshing it. Everything OAuth2 — the token endpoint, the `refresh_token` grants, the per-tenant in-memory cache, the rotation handling, and the per-tenant persistence of the rotated refresh token — lives in `swiyu-issuer`. This split matches the dependency direction (registries cannot depend on issuer) and concentrates the operational concerns (tenant configuration, persistence, monitoring) where they naturally belong.

### TokenProvider abstraction

The `TokenProvider` is the in-memory state machine for one OAuth2 credential set. It exposes two operations:

- `async fn get(&self) -> Result<AccessToken, ...>` — return a currently-valid access token, refreshing transparently via a `refresh_token` grant if the cached one has elapsed its safety margin.
- `async fn invalidate(&self) -> Result<AccessToken, ...>` — discard the cached access token and force a fresh `refresh_token` grant. Called by code that observed a `401` from a registry and wants to retry once with a new token.

A small helper around the trait keeps the 401-refresh-retry pattern terse at worker call sites — for example:

```text
with_refreshed_token(provider, |token| client.allocate_did(token, partner_id))
```

— which calls `provider.get()`, runs the inner closure with the resulting token, and retries the closure once with a freshly-`invalidate`d token if the first attempt returned `RegistryError::HttpStatus { status: 401, .. }`. Other failure modes (network errors during a grant, 5xx from the token endpoint, transport errors during the registry call) are surfaced to the caller; backoff and outer retry policy belong to the worker, not to this layer.

Two implementations are needed in the initial release:

- **`OAuth2TokenProvider`** — the real implementation. Performs `refresh_token` grants against the SWIYU Keycloak realm, caches the access token in memory, runs single-flight refresh, and writes the rotated refresh token back to the tenant row's `refresh_token` column. The column is the single source of truth for the tenant's refresh token: operators populate it manually at onboarding (with the renewal token from the ePortal) and again for recovery; in between, the runtime keeps it up to date automatically on every grant.
- **`StaticTokenProvider`** — test-only. Wraps a fixed `AccessToken`. No caching, no refresh. Used by integration tests that do not exercise the OAuth2 flow, and (potentially) by `swiyu-didtool` for one-shot CLI invocations against a manually-pasted token.

### Multi-tenancy

`swiyu-issuer` is multi-tenant: a single process serves many tenants, with each tenant in 1:1 correspondence with a SWIYU business partner. Every business partner is provisioned with its own credentials in the Swiss ePortal, so every tenant carries its own `(client_id, client_secret, refresh_token)` triple on the tenant row and mints its own access tokens at runtime.

The shape of the design:

- **One `TokenProvider` per tenant.** A `TokenProvider` instance is the in-memory state machine for exactly one OAuth2 credential set: it owns the cached access token, the refresh token, the expiry instant, and the single-flight refresh slot. Two tenants with different credential sets hold two distinct `TokenProvider` instances; their state never crosses.
- **Per-tenant fault isolation.** Token caches, refresh-in-flight slots, and refresh-token values are scoped strictly to a single `TokenProvider`. A failed refresh, a revoked credential, or a misconfigured tenant affects only that tenant's flows; other tenants continue untouched.
- **Tenant-to-provider mapping.** `swiyu-issuer` holds the equivalent of a `tenant_id -> Arc<dyn TokenProvider>` map. Providers are constructed lazily on first use for a given tenant and cached for the lifetime of the process (or until the tenant's configuration changes, whichever is shorter).
- **Single registry-client instance.** `swiyu-registries` clients are tenant-agnostic — they take a token per call — so a single `IdentifierRegistryClient` (and a single `StatusRegistryClient`) serves every tenant in the process. No per-tenant client construction, no duplicated `reqwest::Client` connection pools.

The cost of this design is per-tenant state proportional to the number of active tenants. For realistic deployments (tens to low hundreds of tenants) this is a few KiB of memory per tenant plus one in-flight refresh slot — negligible. The benefit is a sharp per-tenant fault boundary and a clean follow-up path to per-tenant persistence without disturbing `swiyu-registries`.

### Acquisition flow

The runtime maintains a small state machine per tenant. The access token lives in memory only and is re-acquired after a process restart; the refresh token is the durable state, held in the tenant row's `refresh_token` column. Every successful grant rotates that column to the new value the realm returned.

1. **Cold start.** Read the tenant's `refresh_token` column. Perform a `refresh_token` grant against the configured token endpoint. Cache the resulting access token in memory together with the response's `expires_in` (deriving an absolute expiry instant `now + expires_in - safety_margin`), and write the rotated `refresh_token` back to the column.
2. **Warm path, token still valid.** `provider.get()` returns the cached access token without contacting the token endpoint.
3. **Pre-emptive refresh.** Before the cached expiry instant elapses, perform a `refresh_token` grant using the in-memory refresh token. Cache the new access token and persist the rotated refresh token to the tenant row. This keeps live calls off the slow path and keeps the system away from the `expires_in` boundary where clock skew bites.
4. **Lazy refresh on `401`.** A protected registry call that returns `401 Unauthorized` is surfaced by `swiyu-registries` as `RegistryError::HttpStatus { status: 401, .. }`. The wrapper around `provider.invalidate()` performs an on-demand `refresh_token` grant (persisting the rotated refresh token) and retries the original call once. This covers two cases the scheduler cannot: revocation by the SWIYU operations team, and clock skew between this process and the authorization server that makes a token look valid locally when the server already considers it expired.
5. **Refresh-token failure.** A 4xx response on a `refresh_token` grant means the held refresh token is no longer valid — typically because the deployment went more than seven days without a successful refresh and the refresh-token TTL elapsed, or the operations team revoked the credential. There is no fallback: `client_credentials` is gateway-forbidden (900908). The error is surfaced; recovery is a human operation: paste a fresh renewal token from the ePortal into the tenant's `refresh_token` column. The next grant attempt picks it up automatically.

### Lifecycle invariants

These properties must hold for any `TokenProvider` implementation in this crate.

- **One credential set per `TokenProvider`.** A given instance holds exactly one `(client_id, client_secret)` pair together with the access and refresh tokens minted from it. Multi-tenant isolation is achieved by holding one provider per tenant; the provider itself is not aware of tenancy.
- **Tokens never appear in logs.** The `AccessToken` newtype in `swiyu-registries` masks `Debug` and zeroizes on drop. Refresh tokens — which are *more* sensitive than access tokens, since they directly mint new access tokens — must be wrapped equivalently inside this crate.
- **No token endpoint URL is ever hardcoded.** The URL is configuration, supplied at construction. Default values (e.g. an obvious-default for the integration environment) belong in the binary's startup path, not in this crate.
- **No clock-trust beyond `expires_in`.** The runtime's clock is trusted to compare against an expiry instant derived from the response's `expires_in`. JWT `exp` claims inside the access token are not parsed — they are the authorization server's concern, not this client's.
- **Refresh is serialised per credential set, both within one replica and across replicas.** Within one replica, an in-memory single-flight pattern (one concurrent refresh, additional callers awaiting the same future) coalesces concurrent demand. Across replicas, the actual grant is wrapped in a DB transaction with a row-level lock on the tenant row (`SELECT … FOR UPDATE`): a concurrent refresher on another replica blocks until the lock releases, then re-reads the rotated token and skips its own grant if the freshly-read token's TTL is comfortable. This avoids races that would otherwise rely on the SWIYU grace-window rotation to be tolerable.
- **Acquisition is async.** Every operation that touches the token endpoint is `async` on tokio. There is no blocking variant.

### What this layer does not do

- It does not authenticate end users. There is no human in the loop on the registry side. End-user authentication for the management API is a different concern.
- It does not negotiate scopes. The SWIYU Keycloak realm issues a single tier of access; there is no need to request specific scopes per call.
- It does not relax the seven-day refresh-token TTL. Persistence keeps the refresh token alive across process restarts, so a restart of an otherwise-healthy deployment is invisible to the OAuth2 layer; but a real outage longer than seven days still strands the deployment and requires an operator to paste a fresh renewal token from the ePortal into the tenant row.
- It does not persist access tokens. Only the refresh token is durable. Access tokens are session artefacts: a process restart re-acquires them via a `refresh_token` grant on the next call (one Keycloak round-trip per tenant on cold start). This avoids encrypting yet another short-lived secret at rest, at the cost of one extra grant per restart.

### Out of scope for the time being

- Any grant other than `refresh_token`. `client_credentials` is gateway-forbidden for SWIYU partner Anwendungen — see [`swiyu-registries/specs/aspect-oauth2.md`](../../swiyu-registries/specs/aspect-oauth2.md).
- Token introspection (`POST /token/introspect`) or revocation (`POST /revocations`).

### Operational considerations

- **Seven-day refresh-token cliff is bounded by outage length.** Because the refresh token is persisted on the tenant row and rotated on every scheduled refresh, normal operation never approaches the cliff: as long as the deployment performs at least one successful refresh within any seven-day window, the stored token stays alive indefinitely. The cliff only triggers on a real outage longer than seven days (a long holiday shutdown, a forgotten dev environment, a stalled disaster-recovery scenario). When that happens, the stored refresh token is dead and an operator must paste a fresh renewal token from the ePortal into the tenant's `refresh_token` column. Monitoring should alert on consecutive `refresh_token` grant failures so the cliff is detected before it becomes user-visible.
- **Secret-at-rest surface.** The `refresh_token` column is as sensitive as `client_secret` and must be encrypted at rest with the same care. It is the single durable token secret for the tenant; access tokens are not persisted.
- **Manual seeding and recovery share a code path.** Onboarding a tenant, recovering after a >7-day outage, and recovering from a revoked credential are all the same operation: paste the renewal token from the ePortal into the tenant's `refresh_token` column. The runtime does not distinguish between "first use" and "recovery" — it just reads the column on the next grant attempt.
- **`client_id` / `client_secret` rotation from the ePortal.** Rotating these is a tenant-config update followed by replacing the affected `TokenProvider` instance. The previously stored refresh token was minted under the old client and may no longer be valid against the rotated client, so operators paste a fresh renewal token at the same time as updating `client_id` / `client_secret`.

## Subaspect 4-7: Authenticating callers into `swiyu-issuer-mgmtapi`

Subaspects 4–7 all authenticate a caller *into* `swiyu-issuer-mgmtapi` (unlike subaspect 1, where mgmtapi is the client, and subaspects 2–3, which are wallet-facing on `swiyu-issuer-oidcapi`). They look like four scenarios, but they collapse onto **two principals** and one small mechanism. This section is the unified design; the four list entries above are the scenarios it realises.

### The premise: the token authenticates, the service authorizes

`swiyu-issuer-mgmtapi` already decides *what a caller may do* in its own code, against its own data (ownership, tenant scoping, roles) — see `require_issuer_owned_by_tenant` in `api_management/auth.rs`. We keep that, and take it to its conclusion: **the token does not carry roles, scopes, or permissions.** Authentication then reduces to:

1. **Who is calling?** An external business application (bound to one tenant), or the first-party `swiyu-issuer-web` BFF.
2. **On behalf of whom?** For a logged-in user, the authenticated identity `(iss, sub)`.

There is one irreducible complication, on the act-as-a-user path only. `(iss, sub)` is **not** enough to pin a tenant or an account, because **identity → user account is 1:n**: one federated identity may be linked to several accounts — at most one per tenant, but potentially many across tenants (see [`aspect-user-management.md`](aspect-user-management.md)). Which account the user is acting as is an **interactive choice made at login**, so it cannot be derived from the identity and cannot be baked into a token minted before the choice exists. The selected account — call it `UA1` — is therefore a third, runtime input: it travels out-of-band, and mgmtapi **verifies** it is among the accounts linked to `(iss, sub)` before deriving the owning tenant from it.

So mgmtapi derives *what is permitted*, and derives the tenant once the account is known — but on the user path the account *selection* is genuinely not derivable. (It is not a problem for the other modes: resolution returns the candidate accounts, linking takes the account from the invitation, and tenant-admin names the tenant directly.)

### Two principals

#### Tenant principal — a business application (subaspect 4)

An external business application authenticates with the OAuth2 client-credentials grant against the Keycloak realm. It has one confidential client per business application, bound to one tenant; its access token carries `principal_type = tenant` and a `tenant_id` claim. mgmtapi scopes every request to that tenant. This is unavoidable: the callers are external, each acts for exactly one tenant, and the tenant *is* the principal.

#### BFF principal — the first-party web app (subaspects 5–7)

The `swiyu-issuer-web` BFF is **one** confidential first-party client and **one** principal (`principal_type = first-party`), not three. What it is doing on a given call is conveyed by the request itself — the endpoint, plus whether the call carries an authenticated user identity — and mgmtapi authorizes accordingly:

| What the BFF is doing | Subaspect | Tenant context | User identity comes from | Blast radius if BFF misbehaves |
|---|---|---|---|---|
| Resolve an identity to its linked accounts (read-only, cross-tenant) | 5 | none | asserted by the BFF | read-only |
| Link an identity to an account (invitation flow) | 7 | the invitation named in the path | asserted by the BFF (request body) | one invitation, single-use, tenant-created |
| Other admin writes on behalf of a tenant | 7 | `X-Tenant` header | n/a | the named tenant |
| **Act as a logged-in user, with that user's roles** | 6 | the selected account `UA1` (out-of-band, verified against the identity) | **cryptographically established (see below)** | **whatever that user may do** |

The first three are administrative or read-only; the fourth is different in kind.

### One trust rule, stated once

The BFF is a **trusted first-party component**. It MAY simply *assert* a user identity (`iss`, `sub`) for operations whose damage is bounded — read-only resolution and invitation-gated linking — and it MAY name a target tenant (`X-Tenant`) for tenant-admin writes. mgmtapi trusts these because only the BFF can present a `principal_type = first-party` token and the BFF is ours.

**The one exception:** acting as a logged-in user *with that user's own roles* (subaspect 6). There, a compromised or buggy BFF that could assert identities would be able to impersonate any user. So for that path — and only that path — the user identity must be **cryptographically established, not asserted**: an OIDC Authorization Code login produces a token whose signed `sub`/`iss` are the user's identity, and the BFF turns it into an mgmtapi token via Keycloak token exchange (RFC 8693). The selected account `UA1` still travels out-of-band and mgmtapi verifies it against the signed identity.

That is the whole justification for token exchange: spend the heavy mechanism exactly where impersonation is dangerous, and nowhere else.

### Classifying the principal

Classification keys on a single explicit claim the AS stamps — `principal_type`, with **two** values — and never on `azp` or on which client minted the token:

1. **`principal_type = tenant`** → tenant principal. The token also carries `tenant_id`; mgmtapi scopes the request to that tenant.
2. **`principal_type = first-party`** → the first-party BFF. Within BFF tokens, the *shape* of the token tells the situations apart: a plain client-credentials token is the BFF acting administratively (resolution, linking, tenant-admin); an *exchanged* token carrying a signed user identity in a `user_identity` claim plus `act` naming the BFF is the act-as-a-user path. This is a property of the token, not a client id.

Using an explicit `principal_type` claim — rather than inferring from `azp` — keeps mgmtapi decoupled from the AS's client naming, in **two** values versus a four-valued enumeration.

`swiyu-issuer-mgmtapi` processes a request as follows:

1. **Opaque vs JWT (migration).** Today's shared-secret tokens are opaque strings. A bearer value of that shape takes the legacy path; a three-segment JWT takes the path below. (This branch disappears once subaspects 4–7 fully replace the shared secret.)
2. **Validate the JWT:** signature against the realm JWKS, `iss` = expected realm, `aud` contains `swiyu-issuer-mgmtapi`, not expired. Reject otherwise.
3. **Classify on `principal_type`** (`tenant` / `first-party`; any other or absent value → reject), then establish context:
    * `tenant` → tenant = the `tenant_id` claim.
    * `first-party`, plain token → administrative. Target tenant from a tenant-owned resource named in the path (e.g. the invitation) or the `X-Tenant` header; user identity, where needed, is asserted by the BFF in the request.
    * `first-party`, exchanged token (`act` + a signed `user_identity` carrying `(iss, sub)`) → act-as-user. The selected `UA1` arrives in `X-User-Account`; mgmtapi MUST verify `UA1` is linked to `(iss, sub)` and rejects otherwise. Tenant = the owning tenant of the verified `UA1`.
4. **Authorize inside mgmtapi.** Apply the service's own role-/attribute-/relationship-based policy for the classified principal and target resource; `403` if it does not permit the operation.

Per-request context that is not in the token:

- **Target tenant** — from a tenant-owned resource named in the path (e.g. the invitation), else an `X-Tenant` header.
- **Selected account `UA1`** (act-as-user only) — an `X-User-Account` request header, verified server-side against the token's signed identity.

Both headers are honored **only** for `principal_type = first-party` tokens; on a tenant token they are ignored, so a stray or forged header is inert.

### Example tokens

Tenant principal (subaspect 4):

```json
{
  "iss": "https://<keycloak-host>/realms/swiyu-issuer",
  "aud": "swiyu-issuer-mgmtapi",
  "principal_type": "tenant",
  "tenant_id": "tenant_9hXq2vRtL8pK7f"
}
```

BFF base token, client-credentials (subaspects 5 and 7):

```json
{
  "iss": "https://<keycloak-host>/realms/swiyu-issuer",
  "aud": "swiyu-issuer-mgmtapi",
  "azp": "swiyu-issuer-web-bff",
  "principal_type": "first-party"
}
```

BFF exchanged token, act-as-user (subaspect 6) — presented with an `X-User-Account: <UA1>` header on each call:

```json
{
  "iss": "https://<keycloak-host>/realms/swiyu-issuer",
  "aud": "swiyu-issuer-mgmtapi",
  "azp": "swiyu-issuer-web-bff",
  "sub": "<U1's Keycloak subject>",
  "act": { "sub": "swiyu-issuer-web-bff" },
  "principal_type": "first-party",
  "user_identity": {
    "iss": "<federated IdP issuer — e.g. SWITCH edu-ID>",
    "sub": "<U1's subject at that IdP>"
  }
}
```

The user's identity rides in the `user_identity` claim, not in the token's
top-level `iss`/`sub` (those are the realm and U1's Keycloak subject). Keycloak
populates it from the brokered IdP via a claim mapper, so it is the **same**
`(iss, sub)` pair that linking (subaspect 7) records on the user account; mgmtapi
verifies the `X-User-Account` selection against it.

### Keycloak configuration (minimal)

**Fixed (once):** one realm as the authorization server; `swiyu-issuer-mgmtapi` modeled as the protected resource, its identifier used as the token `aud`.

**Per business application:** a confidential client, *Service accounts* only (→ `client_credentials`), hardcoded `principal_type = tenant` and `tenant_id` mappers, and the `aud` mapper. The secret is delivered to the BA operator out-of-band.

**The BFF:** one confidential first-party client with a hardcoded `principal_type = first-party` mapper. Phase 1 needs only *Service accounts* (→ `client_credentials`) and the `aud` mapper; the secret lives in the BFF's own deployment config. Phase 2 (below) additionally enables *Standard flow* for the user login, a token-exchange permission, and a mapper that projects the brokered IdP's issuer and subject into the `user_identity` claim — and the exchanged token keeps `principal_type = first-party` (the actor is still the BFF), the act-as-user case being recognised by the token's `act` + the signed `user_identity` claim, not a distinct `principal_type` value.

One hardcoded `principal_type` mapper per client kind; no optional-scope flavor trick and no per-mode claim mappers. Because authorization lives in the service rather than the token, changing what a principal may do is a code/policy change in mgmtapi, not a Keycloak reconfiguration — and a leaked token can never exceed what the service's policy grants the principal it names.
