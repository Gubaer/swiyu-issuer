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
    * Approach: Client Credential flow. The `swiyu-issuer-mgmtapi` is an OAuth2 resource server. We deploy a Keycloak instance as an authorization server (AS). A business application is provisioned with an OAuth2 client id and client secret (out-of-band channel). In the AS, we configure a respective client and link it to a specific tenant T1. The BA authns at the AS's token endpoint and mints an access token to access the `swiyu-issuer-mgmtapi`. The token includes a claim with the tenant id.
    * Status: not yet implemented (currently uses a shared, tenant specific secret, a token)
5. the BFF of `swiyu-issuer-web` accesses the `swiyu-issuer-mgmtapi` **on behalf of** the BFF (to resolve a user identity against available user accounts)
    * Approach: Client Credential flow. The BFF is assigned a client in the AS, with a client id and a client secret. It authns at `swiyu-issuer-mgmtapi` like any other BA.
    * Status: not yet implemented (currently uses a shared secret)
6. the BFF of `swiyu-issuer-web` accesses the `swiyu-issuer-mgmtapi` **on behalf of** a specific user account UA1 owned by a tenant T1
    * Approach: OAuth Token Exchange (RFC 8693), following the delegation pattern. First, an OIDC Authorization Code flow authenticates user U1 at the AS, yielding U1's identity UI1 and an access token for `swiyu-issuer-web`. The BFF resolves UI1 against a user account UA1, then exchanges that access token at the AS's token endpoint for an access token for `swiyu-issuer-mgmtapi`. The exchanged token keeps U1's identity as its subject and names the BFF in the `act` claim, expressing that the BFF acts on behalf of UA1; the selected user account UA1 is sent to `swiyu-issuer-mgmtapi` out-of-band in a request header, not in the token. `swiyu-issuer-mgmtapi` verifies UA1 against that identity and derives the owning tenant from UA1: there is exactly one owning tenant for each user account.
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

## Subaspect 4: Authenticate a business application

### Keycloak configuration

The following describes how to onboard one concrete business application `BA1`, acting on behalf of one tenant `T1`, against a Keycloak instance acting as the authorization server (AS).

**Fixed elements (configured once, shared by all BAs):**

* A single realm — e.g. `swiyu-issuer` — serves as the AS. It issues tokens with `iss = https://<keycloak-host>/realms/swiyu-issuer`, and exposes its signing keys at `https://<keycloak-host>/realms/swiyu-issuer/protocol/openid-connect/certs`.
* `swiyu-issuer-mgmtapi` is modeled as the protected resource. We fix an identifier for it — e.g. `swiyu-issuer-mgmtapi` — that is used as the token **audience** (`aud`). The resource server rejects any token whose `aud` does not contain this value.

**Per business application (`BA1` → tenant `T1`):**

1. **Create a dedicated confidential client for `BA1`.**
    * Client ID: `ba1` (one client per business application).
    * *Client authentication*: **On** (confidential client — `BA1` holds a client secret).
    * *Authentication flow*: enable **only** *Service accounts roles*; disable *Standard flow* (authorization code) and *Direct access grants*. Enabling the service account is what makes the `client_credentials` grant available, and disabling the others ensures `BA1` can use no other flow.

2. **Issue the client secret.**
    * Take the generated secret from the client's *Credentials* tab and deliver it to the `BA1` operator over an out-of-band channel together with the client id `ba1`. Rotate by regenerating the secret in Keycloak.

3. **Bind `BA1` to tenant `T1` (the tenant claim).**
    * Add a *Hardcoded claim* protocol mapper to the `ba1` client:
        * Token Claim Name: `tenant_id`
        * Claim value: the tenant id of `T1` (the `tenants.id`, e.g. `tenant_9hXq2vRtL8pK7f`) — **not** the SWIYU Business Partner UUID (`tenants.partner_id`). `swiyu-issuer-mgmtapi` keys the tenant context off its own tenant id.
        * Claim JSON type: `String`
        * *Add to access token*: **On**
    * Because there is exactly one client per business application, hardcoding the tenant on the client is sufficient: every token minted by `ba1` carries `tenant_id = <T1's tenant id>`.
    * *Alternative:* instead of a hardcoded mapper, set a `tenant_id` attribute on the client's service-account user and add a *User Attribute* mapper. Prefer this only if the tenant must be resolved per service-account user rather than per client.

4. **Set the audience.**
    * Add an *Audience* protocol mapper to the `ba1` client (or assign a shared `mgmtapi-audience` client scope) so the minted access token's `aud` contains `swiyu-issuer-mgmtapi`. Without this, `swiyu-issuer-mgmtapi` rejects the token.

5. **(Optional) Coarse admission gate.**
    * Optionally define a client role or scope such as `mgmtapi:access` and assign it to the `ba1` service account, as a coarse "may reach `swiyu-issuer-mgmtapi` at all" gate that is revocable independently of the credentials. This is *not* operation-level authorization — what `BA1` may actually do is decided inside `swiyu-issuer-mgmtapi` (see [Token classification](#token-classification-in-swiyu-issuer-mgmtapi)).

**Resulting access token.** `BA1` requests a token with the client credentials grant:

```http
POST /realms/swiyu-issuer/protocol/openid-connect/token HTTP/1.1
Host: <keycloak-host>
Content-Type: application/x-www-form-urlencoded
Authorization: Basic base64(ba1:<client-secret>)

grant_type=client_credentials
```

Keycloak returns a signed JWT whose relevant claims are:

```json
{
  "iss": "https://<keycloak-host>/realms/swiyu-issuer",
  "aud": "swiyu-issuer-mgmtapi",
  "azp": "ba1",
  "tenant_id": "tenant_9hXq2vRtL8pK7f",
  "exp": 1700000000,
  "iat": 1699999700
}
```

**What `swiyu-issuer-mgmtapi` validates (resource server side).** On each request, `swiyu-issuer-mgmtapi` validates the bearer token's signature against the realm's JWKS, checks `iss` equals the expected realm, checks `aud` contains `swiyu-issuer-mgmtapi`, and checks it is unexpired. It then reads the `tenant_id` claim to establish the tenant context — replacing today's shared, tenant-specific token (see subaspect 4 status above).

## Subaspect 5: Authenticate the BFF as itself

### Keycloak configuration

The BFF of `swiyu-issuer-web` authenticates to `swiyu-issuer-mgmtapi` as itself, with the client credentials grant — mechanically the same as a business application (subaspect 4), but its token represents the **BFF principal** (`principal_type = bff`), not a tenant. The BFF uses it for its own operations against `swiyu-issuer-mgmtapi`, such as resolving a user identity against the available user accounts.

This reuses the *Fixed elements* configured for subaspect 4 (the realm as AS; `swiyu-issuer-mgmtapi` modeled as the protected resource and token audience).

**The BFF client:**

1. **Create one confidential client for the BFF.**
    * Client ID: e.g. `swiyu-issuer-web-bff` — a single, well-known client. `swiyu-issuer-mgmtapi` recognizes this id to tell the BFF apart from BA clients.
    * *Client authentication*: **On** (confidential).
    * *Authentication flow*: enable **only** *Service accounts roles* (→ `client_credentials` grant); disable *Standard flow* and *Direct access grants*.
    * This is the **same client** reused for subaspect 6: its base client-credentials tokens are subaspect-5 tokens (`principal_type = bff`), and its token-exchange output are subaspect-6 tokens (`principal_type = user_account`). See *Keycloak provisioning* under [Token classification](#token-classification-in-swiyu-issuer-mgmtapi).

2. **Issue the client secret.**
    * Unlike a BA secret (handed out-of-band to an external operator), the BFF is our own deployed component: place the secret in the BFF's deployment secret store / configuration, and let the BFF authenticate with it at startup.

3. **Classify as the BFF principal.**
    * Add a *Hardcoded claim* protocol mapper to the client's base tokens:
        * Token Claim Name: `principal_type`
        * Claim value: `bff`
        * Claim JSON type: `String`
        * *Add to access token*: **On**
    * Do **not** add a `tenant_id` claim — the BFF acts as itself, with no tenant context.

4. **Set the audience.**
    * Add an *Audience* protocol mapper (or assign the shared `mgmtapi-audience` client scope) so the minted token's `aud` contains `swiyu-issuer-mgmtapi`.

5. **No operation scopes.**
    * Per the [classification design](#design-the-token-classifies-swiyu-issuer-mgmtapi-authorizes), the token carries no `mgmt:*` scopes. `swiyu-issuer-mgmtapi` caps the `bff` principal to identity-resolution operations by its own policy, keyed on `principal_type = bff`. The optional coarse `mgmtapi:access` admission gate from subaspect 4 may still be assigned.

**Resulting access token.** The BFF requests a token with the client credentials grant:

```http
POST /realms/swiyu-issuer/protocol/openid-connect/token HTTP/1.1
Host: <keycloak-host>
Content-Type: application/x-www-form-urlencoded
Authorization: Basic base64(swiyu-issuer-web-bff:<client-secret>)

grant_type=client_credentials
```

Keycloak returns a signed JWT whose relevant claims are:

```json
{
  "iss": "https://<keycloak-host>/realms/swiyu-issuer",
  "aud": "swiyu-issuer-mgmtapi",
  "azp": "swiyu-issuer-web-bff",
  "principal_type": "bff",
  "exp": 1700000000,
  "iat": 1699999700
}
```

There is no `tenant_id` and no `act`; `sub` is the client's service-account id, not a user. `swiyu-issuer-mgmtapi` classifies this as the BFF principal and authorizes only identity-resolution operations.

## Subaspect 6: Authenticate the BFF acting on behalf of a user account UA1

### Keycloak configuration

Subaspect 6 builds on two pieces already configured: the **BFF client** from subaspect 5 (`swiyu-issuer-web-bff`) and the **user login**. Here we add Keycloak **token exchange** (RFC 8693) so the BFF can turn a logged-in user's session into a *delegated* access token for `swiyu-issuer-mgmtapi`. It reuses the *Fixed elements* (realm as AS; `swiyu-issuer-mgmtapi` as protected resource / audience).

**Prerequisite — user login (authorization code).**

The exchange consumes a *subject token*: the user's access token for `swiyu-issuer-web`, obtained by logging `U1` in via an OIDC Authorization Code flow at the AS (detailed in `web/specs/impl-authn-login-flow.md`). The BFF client therefore needs the **Standard flow (authorization code) enabled**, *in addition to* the *Service accounts* setting from subaspect 5 — so the one BFF client carries both: authorization code for user login, client credentials for its own calls. The login yields the user's identity `UI1` as the subject token's `sub`.

**Token-exchange configuration (BFF → `swiyu-issuer-mgmtapi`):**

1. **Enable token exchange on the Keycloak server.**
    * Token exchange is a gated feature — enable it at server start (`--features=token-exchange` for the preview, or the standard token exchange in Keycloak ≥ 26). Without it the token endpoint rejects the exchange grant.

2. **Permit the BFF to exchange into `swiyu-issuer-mgmtapi`.**
    * On the `swiyu-issuer-mgmtapi` client, enable fine-grained *Permissions* and add a **token-exchange** permission whose policy allows the `swiyu-issuer-web-bff` client. Only the BFF may mint mgmtapi tokens by exchange.

3. **Shape the exchanged token.** Configure mappers / a client scope that apply to the **exchange output only**, never to the BFF's base client-credentials token:
    * `aud` = `swiyu-issuer-mgmtapi` (audience mapper).
    * `act` = `{ "sub": "swiyu-issuer-web-bff" }` — in a delegation exchange Keycloak sets the actor to the requesting client. This is the delegation marker that distinguishes a subaspect-6 token from a subaspect-5 token (both come from the same client).
    * `principal_type` = `user_account` — a *Hardcoded claim* attached via a client scope requested only during the exchange, so the base token keeps `principal_type = bff` (subaspect 5) while the exchanged token gets `user_account`.

    The token's `sub`/`iss` carry the federated identity `UI1 = (iss, sub)` through unchanged. The selected account `UA1` does **not** travel in the token — `swiyu-issuer-web` sends it to `swiyu-issuer-mgmtapi` out-of-band on each call (see [Selecting the user account](#selecting-the-user-account)), so the AS needs only built-in mappers and no custom extension.

4. **No tenant or operation claims from Keycloak.**
    * The exchanged token carries no `tenant_id` and no `mgmt:*` scopes. `swiyu-issuer-mgmtapi` derives the owning tenant and applies its own authorization, consistent with subaspects 4 and 5.

**The exchange request.** Having logged the user in and decided to call `swiyu-issuer-mgmtapi`, the BFF exchanges the user's subject token:

```http
POST /realms/swiyu-issuer/protocol/openid-connect/token HTTP/1.1
Host: <keycloak-host>
Content-Type: application/x-www-form-urlencoded
Authorization: Basic base64(swiyu-issuer-web-bff:<client-secret>)

grant_type=urn:ietf:params:oauth:grant-type:token-exchange
&subject_token=<user's access token for swiyu-issuer-web>
&subject_token_type=urn:ietf:params:oauth:token-type:access_token
&audience=swiyu-issuer-mgmtapi
&requested_token_type=urn:ietf:params:oauth:token-type:access_token
```

The exchange uses standard parameters only — the selected `UA1` is **not** sent here; it travels out-of-band on the subsequent calls to `swiyu-issuer-mgmtapi` (see below).

#### Selecting the user account

The selected account `UA1` cannot be derived from the token's subject, because the relation between a federated identity `UI1 = (iss, sub)` and `swiyu-issuer`'s user accounts is **one-to-many** and the choice among them is **made by `U1` at login time**. So `UA1` is a runtime input the BFF establishes *before* the exchange, not a static property of the identity. The flow:

1. `U1` authenticates at the AS. `swiyu-issuer-web` receives the identity `UI1 = (iss, sub)` from the login (OIDC) token.
2. `swiyu-issuer-web` **resolves** `(iss, sub)` to the user accounts it is linked to — exactly the subaspect-5 lookup into `swiyu-issuer-mgmtapi`, which holds the `user_identities → user_account_identities → user_accounts` linking:
    * **0** linked accounts → authentication fails.
    * **1** linked account → it is the selected account.
    * **> 1** linked accounts → `swiyu-issuer-web` lets `U1` choose one.
3. Only now does `swiyu-issuer-web` perform the token exchange (standard parameters only). The exchanged token's `sub`/`iss` carry the federated identity `(iss, sub)` through unchanged; the selected `UA1` does not go into the token. On each subsequent call to `swiyu-issuer-mgmtapi`, `swiyu-issuer-web` sends the selected `UA1` in a request header.

This is why the resolution lives neither purely in `swiyu-issuer-mgmtapi` (it cannot read `U1`'s interactive choice from the token) nor in a static Keycloak user attribute (the choice varies per login): the authoritative `(iss, sub) → accounts` linking is held in `swiyu-issuer` and surfaced via subaspect 5, but the *selection* among the candidates is `swiyu-issuer-web`'s, supplied to the AS at exchange time.

**Conveying the selected `UA1`.** `UA1` is *asserted* by `swiyu-issuer-web`; how it travels to `swiyu-issuer-mgmtapi` is a separate choice. Either way the exchanged token's `sub`/`iss` carry the federated identity unchanged, and `swiyu-issuer-mgmtapi` verifies the link (next paragraph).

* **(a) As an application-level header (chosen — Keycloak stays stock).** The exchanged token carries only the standard claims (`principal_type`, `act`, `sub`/`iss`); `swiyu-issuer-web` sends the selected `UA1` to `swiyu-issuer-mgmtapi` in a request header (e.g. `X-User-Account: <UA1>`) on each call. No custom mapper, no preview feature, no provider JAR — Keycloak is configured entirely with built-in mappers. The examples above (exchange request, example token, classification table) use this option. The trade-off: `UA1` rides outside the signed token, so it carries no authority of its own — it is trustworthy *only* because `swiyu-issuer-mgmtapi` verifies it against the token's `(iss, sub)`.
* **(b) As a token claim (custom Keycloak mapper) — alternative.** `swiyu-issuer-web` instead passes a `user_account_id` parameter in the exchange request and the AS emits it as a `user_account_id` claim, putting `UA1` inside the signed token. The AS does not override `sub` — it only *adds* this claim — but there is no stock mapper that copies an arbitrary request parameter into a claim, so this needs a small extension: a **custom protocol mapper** (Java SPI, deployed as a provider JAR — type-checked, no preview flag) or a **Script Mapper** (requires `--features=scripts` and deploying the script as a provider JAR, since console editing is disabled by default). *[TODO: confirm the exact Keycloak extension point for the target version.]* Choose this only if `UA1` must be carried in the signed token, at the cost of bespoke AS code.

**Trust and verification.** Under either option `swiyu-issuer-web` merely *asserts* `UA1`; the AS does not check the link, because the authoritative `(iss, sub) → accounts` mapping lives in `swiyu-issuer`, not the AS. Therefore `swiyu-issuer-mgmtapi` **MUST** verify, on every request, that the asserted `UA1` is among the accounts linked to the token's `(iss, sub)` identity, and reject otherwise; only then does it derive the owning tenant from `UA1`. Because the identity travels in the signed `sub`/`iss` while `UA1` is only asserted, a compromised or buggy BFF cannot act as an account the authenticated identity is not linked to. With the chosen header transport (option (a)) `UA1` is unsigned, so this check is the *only* thing standing behind it — it is non-negotiable.

## Token classification in `swiyu-issuer-mgmtapi`

Subaspects 4, 5, and 6 all result in a bearer token presented to `swiyu-issuer-mgmtapi`, each standing for a different principal:

* **tenant principal** — a business application acting on behalf of a tenant (subaspect 4)
* **BFF principal** — the BFF acting as itself, e.g. to resolve a user identity (subaspect 5)
* **user-account principal** — the BFF acting on behalf of a user account `UA1` (subaspect 6)

`swiyu-issuer-mgmtapi` must decide which principal a given token represents and scope the request accordingly. This section specifies how.

### Why the obvious discriminators do not work

The three tokens are **structurally indistinguishable at the envelope level**: all are JWTs from the same realm (same `iss`) targeting `swiyu-issuer-mgmtapi` (same `aud`). And there is no standard `token_type` claim to lean on — RFC 8693 registers no such claim, and its token-type identifiers describe a token's *format*, not its *business principal*. Classification must therefore be driven by a dedicated claim the AS emits — hence `principal_type`.

### Design: the token classifies, `swiyu-issuer-mgmtapi` authorizes

The two questions — *what kind of principal is this?* and *what may it do?* — are answered in two different layers, and authorization is deliberately kept **out of the token**:

* **Authentication & classification → claims minted by the AS.** Keycloak authenticates the caller and stamps a private `principal_type` claim (`tenant` / `bff` / `user_account`) plus the identity that pins the principal: `tenant_id` for a tenant; the federated identity in `sub`/`iss` (with `act`) for a user account, whose selected account `UA1` the BFF supplies out-of-band in a request header (see subaspect 6). `swiyu-issuer-mgmtapi` reads `principal_type` to decide which subaspect applies — no inference from the presence of `act` or from which client minted the token.
* **Authorization → inside `swiyu-issuer-mgmtapi`.** The token carries **no `mgmt:*` operation scopes**. What a principal may do is decided by the resource server against its own data, using role-based (roles assigned to a user account), attribute-based (tenant/account attributes), and relationship-based (account → owning tenant, issuer → owning tenant) policies. This keeps the authorization model — which is domain-specific and evolves with the API — versioned with the code in one place, rather than split across Keycloak client and scope configuration. The service already does this for ownership today (`require_issuer_owned_by_tenant` in `api_management/auth.rs`).

So the token answers *who is this principal?*; `swiyu-issuer-mgmtapi` answers *what may it do?*.

The `act` claim (RFC 8693 §4.1) stays on user-account tokens, but its job is narrow: it carries the **delegation detail** — which actor (the BFF) acts on behalf of `UA1` — and serves as a consistency check on the `user_account` type. It is not the classifier.

| Principal | Subaspect | `principal_type` | `act` | `sub` | tenant source | how `swiyu-issuer-mgmtapi` authorizes |
|---|---|---|---|---|---|---|
| tenant | 4 | `tenant` | absent | BA service account | `tenant_id` claim | scoped to tenant `T1`; resources must be owned by `T1` (relationship-based) |
| BFF | 5 | `bff` | absent | BFF service account | none | fixed, narrow capability: identity resolution only |
| user account | 6 | `user_account` | present (`act` = BFF) | `(iss, sub)` identity (selected `UA1` via request header) | owning tenant of `UA1` (after verifying `UA1` is linked to `(iss, sub)`) | by `UA1`'s roles and relationships within its owning tenant (role- + relationship-based) |

### Resolution order

`swiyu-issuer-mgmtapi` processes a request as follows:

1. **Opaque vs JWT (migration).** Today's shared-secret tokens are opaque `tok_<base58>` strings, resolved by SHA-256 hash lookup in `api_tokens`. A bearer value of that shape takes the legacy path; a three-segment JWT takes the path below. (This branch disappears once subaspects 4–6 fully replace the shared secret.)
2. **Validate the JWT:** signature against the realm JWKS, `iss` = expected realm, `aud` contains `swiyu-issuer-mgmtapi`, not expired. Reject otherwise.
3. **Classify on `principal_type`:**
    * `tenant` → tenant principal (subaspect 4). Tenant = the `tenant_id` claim.
    * `user_account` → user-account principal (subaspect 6). The identity is the token's `(iss, sub)`; the selected account `UA1` arrives in the `X-User-Account` request header (not a token claim). `act` MUST be present — reject if absent (a `user_account` token without a delegation actor is malformed). `swiyu-issuer-mgmtapi` MUST verify `UA1` is among the accounts linked to `(iss, sub)` — reject otherwise. Tenant = the owning tenant of the verified `UA1`.
        * **`X-User-Account` is honored only here.** The header is consulted **only** for `user_account`-principal tokens, and always verified against the token's `(iss, sub)`. For `tenant` (subaspect 4) and `bff` (subaspect 5) principals it is ignored. This `principal_type` gate — not edge filtering — is what makes a forged or stray header inert: an external business application (subaspect 4) presents a `tenant` token, so any `X-User-Account` it sends is never read.
    * `bff` → BFF principal (subaspect 5). No tenant context.
    * absent or any other value → reject.
4. **Authorize inside `swiyu-issuer-mgmtapi`.** Apply the service's own role-/attribute-/relationship-based policy for the classified principal and the target resource; respond `403` if it does not permit the operation. The `bff` principal is capped at identity resolution here — there is no scope to omit, so the cap is enforced by policy keyed on `principal_type = bff`.

### Keycloak provisioning

For every token type the AS emits **only** the classification and identity claims — never operation scopes:

* **BA client (`ba1`, subaspect 4):** a *Hardcoded claim* mapper `principal_type = tenant`, alongside the `tenant_id` mapper from the *Keycloak configuration* section above.
* **BFF client, base token (subaspect 5):** a *Hardcoded claim* mapper `principal_type = bff` on the client's base (client-credentials) tokens.
* **BFF client, exchanged token (subaspect 6):** apply `principal_type = user_account` on the **token-exchange output**, not on the BFF's base token — the same client yields `principal_type = bff` for its base tokens and `principal_type = user_account` for exchanged ones. Configure this on the token-exchange policy / a mapper scoped to the exchange, so the exchanged token carries `principal_type = user_account` and `act = { "sub": "<BFF client>" }`, while `sub`/`iss` carry the federated identity through unchanged. The selected `UA1` is not in the token — it travels in a request header (see subaspect 6).

Because authorization lives in the service rather than in the token, changing what a principal may do is a code/policy change in `swiyu-issuer-mgmtapi`, not a Keycloak reconfiguration — and a leaked token can never exceed what the service's policy grants the principal it names.

### Example exchanged token (subaspect 6)

```json
{
  "iss": "https://<keycloak-host>/realms/swiyu-issuer",
  "aud": "swiyu-issuer-mgmtapi",
  "azp": "swiyu-issuer-web-bff",
  "sub": "<U1's subject at the AS — the sub of the federated identity (iss, sub)>",
  "act": { "sub": "swiyu-issuer-web-bff" },
  "principal_type": "user_account",
  "exp": 1700000000,
  "iat": 1699999700
}
```

The selected account is not in the token; `swiyu-issuer-web` carries it on each call to `swiyu-issuer-mgmtapi`:

```http
GET /api/v1/issuers HTTP/1.1
Host: <mgmtapi-host>
Authorization: Bearer <exchanged token above>
X-User-Account: <selected UA1 — user_accounts.id, base58 UserAccountId>
```

`swiyu-issuer-mgmtapi` checks that this `UA1` is linked to the token's `(iss, sub)` before acting on it.

