# Implementation plan — Credentials area

This plan implements [`credentials.md`](./credentials.md): a **Credentials** list view, a
credential **detail page**, and the three lifecycle actions (suspend / resume / revoke), plus the
BFF proxies that back them.

The feature is a near-clone of the existing **Credential Offers** slice. Wherever possible we copy
the established pattern rather than invent a new one. The plan below is organised as "build the BFF
proxies, then the SPA service + store, then the UI, then wire navigation/i18n, then test."

## Key differences from credential-offers (read first)

These are the only places the mirror is *not* literal — everything else follows the offers code
verbatim.

| Aspect | Credential Offers | Credentials |
| --- | --- | --- |
| Record has `claims` | Yes — BFF strips it from list, detail keeps it | **No claims at all.** BFF is a pure pass-through for both list and detail; no stripping, no claims card on detail. |
| Lifecycle actions | One (`cancel`, pending-only) | **Three**: `suspend` (active→suspended), `resume`/`unsuspend` (suspended→active), `revoke` (active|suspended→revoked, terminal). |
| Confirmation | Cancel always confirms | **Revoke confirms** (permanent, UC05); **suspend & resume do not** (reversible, UC03/UC04). |
| List query params forwarded | `limit`, `cursor` | `limit`, `cursor`, **`state`, `vct`** (spec §Services). No filter UI in this slice — the service forwards them; the page does not surface them yet, matching how offers deferred its state filter. |
| State enum | `pending`/`issued`/`cancelled`/`expired` | `active`/`suspended`/`revoked` + derived `expired` boolean (never a state). |
| Create flow | Yes (wizard) | **None** — credentials are minted by wallets via the OIDC API. No create route, no “New” button. |
| Lifecycle response | `cancel` returns offer summary | All three return the full updated `GetIssuedCredentialResponse`; sync, `409` on disallowed transition. |

Reference files to mirror (all under `web/`):
- BFF route: `bff/src/routes/credential_offers.rs`, wired in `bff/src/routes/mod.rs`
- BFF upstream: `bff/src/upstream/mgmt_api.rs`
- SPA service: `spa/src/app/features/credential-offers/credential-offers-service.ts`
- SPA store: `…/credential-offers-store.ts`
- SPA list: `…/credential-offers-list.{ts,html,scss}`
- SPA detail: `…/credential-offer-detail.{ts,html,scss}`
- SPA shared action flow: `…/credential-offer-cancellation.ts`
- Menu: `spa/src/app/layout/component/app.menu.ts`
- Routes: `spa/src/app/app.routes.ts`
- i18n: `spa/public/i18n/en.json` + `de.json`
- Upstream contract: `api/openapi-mgmt.yml` (`listIssuedCredentials`, `getIssuedCredential`,
  `suspendIssuedCredential`, `unsuspendIssuedCredential`, `revokeIssuedCredential`;
  schema `GetIssuedCredentialResponse`, `ListIssuedCredentialsResponse`).

---

## Step 1 — BFF: upstream client methods (`mgmt_api.rs`)

Add five thin methods to `MgmtApiClient`, mirroring `list_credential_offers` / `get_credential_offer`
/ `cancel_credential_offer`. All use `Self::act_as_user(...)` + `read_json`, so upstream status codes
and bodies propagate through the existing gateway error mapping (404 → not found, 409 → conflict).

- `list_issued_credentials(&self, auth, issuer_id, limit: Option<u32>, cursor, state: Option<&str>, vct: Option<&str>)`
  — `GET /api/v1/issuers/{issuer_id}/credentials`. Build the `query` vec the same way
  `list_credential_offers` does (only push params that are `Some`, so the upstream never sees
  `?state=`). Add `state` and `vct` to that conditional push list.
- `get_issued_credential(&self, auth, issuer_id, credential_id)` — `GET …/credentials/{credential_id}`.
- `suspend_issued_credential(&self, auth, issuer_id, credential_id)` — `POST …/credentials/{id}/suspend`, no body.
- `unsuspend_issued_credential(&self, auth, issuer_id, credential_id)` — `POST …/credentials/{id}/unsuspend`, no body.
- `revoke_issued_credential(&self, auth, issuer_id, credential_id)` — `POST …/credentials/{id}/revoke`, no body.

## Step 2 — BFF: route handlers (`routes/credential_offers.rs` sibling)

Create `bff/src/routes/credentials.rs` and register `mod credentials;` in `routes/mod.rs`.

- Extend the local `ListQuery` (or add a `CredentialListQuery`) with `state: Option<String>` and
  `vct: Option<String>` alongside `limit`/`cursor`.
- `list_credentials` → calls `list_issued_credentials`, returns `Json(payload)` **unchanged** (no
  `strip_claims` — credential records carry no claims). The response is already
  `{ items, next_cursor }`.
- `get_credential` → `Path((issuer_id, credential_id))`, returns the record verbatim.
- `suspend_credential` / `resume_credential` / `revoke_credential` → each `Path((issuer_id,
  credential_id))`, no request body, returns the updated record verbatim. `resume_credential` calls
  the upstream `unsuspend` method (UI label is *Resume*, API verb is *unsuspend*).
- No `strip_claims` helpers needed in this file. Keep the inline `#[cfg(test)] mod tests` minimal —
  there is no payload transformation to unit-test here (unlike offers, which tested claim
  stripping). A test asserting `ListQuery` deserialises `state`/`vct` is enough, or omit tests in
  this file and rely on the SPA/integration layer. (Decision: skip BFF unit tests here; the handlers
  are pure pass-throughs.)

## Step 3 — BFF: register routes (`routes/mod.rs`)

In `router()`’s `guarded` chain, add below the credential-offers routes:

```rust
.route(
    "/api/issuers/{issuer_id}/credentials",
    get(credentials::list_credentials),
)
.route(
    "/api/issuers/{issuer_id}/credentials/{credential_id}",
    get(credentials::get_credential),
)
.route(
    "/api/issuers/{issuer_id}/credentials/{credential_id}/suspend",
    post(credentials::suspend_credential),
)
.route(
    "/api/issuers/{issuer_id}/credentials/{credential_id}/unsuspend",
    post(credentials::resume_credential),
)
.route(
    "/api/issuers/{issuer_id}/credentials/{credential_id}/revoke",
    post(credentials::revoke_credential),
)
```

(The BFF path uses `unsuspend` to match the management API exactly, per the spec’s endpoint table.)
Verify with `cargo build` / `cargo test` in `web/bff`.

---

## Step 4 — SPA: service (`features/credentials/credentials-service.ts`)

New `@Injectable({ providedIn: 'root' })` `CredentialsService`, mirroring `CredentialOffersService`.

```ts
export type CredentialState = 'active' | 'suspended' | 'revoked';

export interface Credential {
  id: string;
  issuer_id: string;
  credential_offer_id: string;
  vct: string;
  holder_key_jkt: string;
  status_list_id: string;
  status_list_index: number;
  state: CredentialState;
  expired: boolean;
  issued_at: string;
  expires_at: string;
}

export interface CredentialsResponse { items: Credential[]; next_cursor: string | null; }
export interface ListOptions { limit?: number; cursor?: string | null; state?: CredentialState; vct?: string; }
```

There is no `CredentialSummary` vs `Credential` split — list and detail return the same shape
(no claims to strip), so one interface serves both.

Methods:
- `list(issuerId, options?)` → `GET /api/issuers/{id}/credentials`, set `limit`/`cursor`/`state`/`vct`
  on `HttpParams` when present (copy the conditional-set pattern from offers).
- `get(issuerId, credentialId)` → `GET …/credentials/{credentialId}`.
- `suspend(issuerId, credentialId)` → `POST …/suspend`, `{}` body, returns `Credential`.
- `resume(issuerId, credentialId)` → `POST …/unsuspend`, `{}` body, returns `Credential`.
- `revoke(issuerId, credentialId)` → `POST …/revoke`, `{}` body, returns `Credential`.

## Step 5 — SPA: store (`features/credentials/credentials-store.ts`)

Copy `CredentialOffersStore` almost verbatim: `items`/`nextCursor`/`loading`/`error` signals,
`intendedIssuerId` tag for the race-on-issuer-switch guard, and `loadFor` / `loadMore` / `refresh` /
`clear`. Same cursor-accumulation semantics.

Replace `markCancelled` with one in-place patch helper used by all three lifecycle actions:

```ts
// Replace the matching row with the server's updated record (state, expired, etc.).
applyUpdate(updated: Credential): void {
  this.itemsSignal.update((items) =>
    items.map((c) => (c.id === updated.id ? updated : c)),
  );
}
```

Since the lifecycle calls return the full updated record, patching with the whole object is simpler
and more correct than the offers approach of stitching individual fields.

## Step 6 — SPA: shared lifecycle flow (`features/credentials/credential-lifecycle.ts`)

Mirror `CredentialOfferCancellation` as an injectable `CredentialLifecycle` shared by the list and
the detail page (so the confirm dialog, API call, and toasts live once). Three entry points, all
taking the issuer id, the credential, and an `{ onUpdated(updated), onConflict?() }` callback pair:

- `suspend(issuerId, credential, cb)` — guard `state === 'active'`; **no confirm**; call
  `service.suspend`; on success `onUpdated(updated)` + success toast; on `409` `onConflict?()` +
  error toast.
- `resume(issuerId, credential, cb)` — guard `state === 'suspended'`; **no confirm**; call
  `service.resume`; same success/error handling.
- `revoke(issuerId, credential, cb)` — guard `state === 'active' || 'suspended'`; **confirm via
  `ConfirmationService`** (danger accept, “revocation cannot be undone”, UC05); on accept call
  `service.revoke`; same success/error handling.

Use `TranslocoService.translate` for all dialog text and toasts, exactly like the cancellation
service. The confirm renders through the existing global `<p-confirmDialog />` host.

## Step 7 — SPA: list page (`features/credentials/credentials-list.{ts,html,scss}`)

Copy `credential-offers-list.*` and adapt:

**`.ts`** — same structure: inject `IssuersStore` + new `CredentialsStore` + `CredentialLifecycle`;
URL `?issuerId=` as source of truth; auto-select-sole-issuer effect; `effect()` keyed on
`selectedIssuer()` calling `store.loadFor(id)` / `store.clear()`; issuer autocomplete search;
refresh; load-more. Changes:
- Remove `createOffer()` and the “New” button wiring (no create flow).
- `stateSeverity(state: CredentialState)`: `active → success`, `suspended → warn`,
  `revoked → danger`. (Pick a sensible mapping; `p-tag` supports `danger`.)
- `openRowMenu(event, credential)` builds **three** menu items, each disabled unless its transition
  is legal:
  - Suspend — `disabled: state !== 'active'` → `lifecycle.suspend(...)`
  - Resume — `disabled: state !== 'suspended'` → `lifecycle.resume(...)`
  - Revoke — `disabled: state === 'revoked'` → `lifecycle.revoke(...)`
  Each command passes `{ onUpdated: (u) => store.applyUpdate(u), onConflict: () => store.refresh() }`.
  Keep the build-on-click pattern (avoids translating before the language file loads).

**`.html`** — copy the offers template; keep the picker section and table scaffolding (`p-table
p-datatable-sm`, count badge, load-more footer, empty/error/loading states, `p-confirmDialog`,
`#rowMenu` popup). Adapt columns to credential fields:

| Column | Source | Notes |
| --- | --- | --- |
| Credential ID | `id` | Monospaced, truncated, tooltip; links to `/credentials/:id?issuerId=…` |
| VCT | `vct` | Monospaced, muted, truncated |
| State | `state` | `p-tag` via `stateSeverity` |
| Expired | `expired` | small tag/icon — `true` shows a warning chip, else “—” |
| Issued | `issued_at` | `localeDate` + ISO tooltip |
| Expires | `expires_at` | `localeDate` + ISO tooltip |
| (actions) | — | kebab → `openRowMenu` |

Drop the “New offer” header button; keep the refresh button. Adjust `colspan` on the empty/footer
rows to the new column count.

**`.scss`** — copy `credential-offers-list.scss` unchanged (class names reused); rename the page
wrapper class if desired (`credentials-page`).

## Step 8 — SPA: detail page (`features/credentials/credential-detail.{ts,html,scss}`)

Copy `credential-offer-detail.*` and adapt:

**`.ts`** — read `:id` route param + `?issuerId=` query param; `service.get` on init; `loading` /
`error` / `credential` signals; `stateSeverity` as above. **Remove** the highlight.js / `hasClaims` /
`highlightedClaims` machinery — credentials have no claims. Replace the single `cancel()` with three
methods `suspend()` / `resume()` / `revoke()` delegating to `CredentialLifecycle`, each with
`{ onUpdated: (u) => this.credential.set(u), onConflict: () => this.reload(...) }`.

**`.html`** — copy the detail card; **remove the claims `p-card`**. The detail grid (`<dl>`) lists:
`id`, `state` (tag), `expired` (Yes/No or tag), `vct`, `credential_offer_id`, `holder_key_jkt`
(mono, truncate + tooltip), `status_list_id`, `status_list_index`, `issued_at`, `expires_at`
(localeDate + tooltip). Header actions become **three buttons**:
- Suspend — `[disabled]="credential.state !== 'active'"` → `suspend()`
- Resume — `[disabled]="credential.state !== 'suspended'"` → `resume()`
- Revoke — `severity="danger"` `[disabled]="credential.state === 'revoked'"` → `revoke()`
Keep `<p-confirmDialog />` at the top and the back button (routes to `/credentials?issuerId=…`).

**`.scss`** — reuse `credential-offer-detail.scss` (detail-grid / mono / muted classes).

---

## Step 9 — Routing (`app.routes.ts`)

Add three lazy routes inside the authenticated layout children, after the credential-offers block:

```ts
{ path: 'credentials',
  loadComponent: () => import('./features/credentials/credentials-list').then(m => m.CredentialsList) },
{ path: 'credentials/:id',
  loadComponent: () => import('./features/credentials/credential-detail').then(m => m.CredentialDetail) },
```

No `credentials/new` route (no create flow).

## Step 10 — Navigation (`app.menu.ts`)

Add a **Credentials** menu item directly **below** the Credential Offers entry (spec §UI.1):

```ts
{ label: 'Credentials', icon: 'pi pi-fw pi-verified', routerLink: ['/credentials'] }
```

(Plain string label, matching the existing entries; picks an icon distinct from offers’ `pi-send` —
`pi-verified` or `pi-id-card` variant. Confirm the icon exists in the PrimeIcons set in use.)

## Step 11 — i18n (`public/i18n/en.json` + `de.json`)

Add a `credential` top-level block mirroring `credential_offer` (`list`, `detail`, and a
`lifecycle` sub-block for the action labels / confirm dialog / toasts). Keys needed:

- `credential.list.*`: title (“Credentials”), refresh, issuer section title/hint, retry,
  issuers_loading / no_issuers / issuers_load_error, issuer_search_placeholder,
  credentials_section_title, select_issuer_prompt, credentials_load_error, `col_id`, `col_vct`,
  `col_state`, `col_expired`, `col_issued`, `col_expires`, empty, load_more, row_actions.
- `credential.detail.*`: back, title, load_error, and one label per `<dl>` field (id, state,
  expired, vct, credential_offer_id, holder_key_jkt, status_list_id, status_list_index, issued,
  expires).
- `credential.lifecycle.*`: `suspend_action`, `resume_action`, `revoke_action`,
  `revoke_confirm_header`, `revoke_confirm_message` (with `{{id}}`), `revoke_confirm_accept`,
  `revoke_confirm_reject`, and `suspend_success` / `resume_success` / `revoke_success` /
  `*_error` toasts (or a single generic success/error pair).

Add the German equivalents in `de.json` in the same shape (translate; keep keys identical).

---

## Step 12 — Tests & verification

- **BFF**: `cargo build` + `cargo test` in `web/bff`. Handlers are pass-throughs; no new unit tests
  required (unlike the offers claim-stripping tests). Optionally add a `ListQuery` deserialisation
  test for `state`/`vct`.
- **SPA**: `npm run build` (or `ng build`) and `npm test` in `web/spa`. Follow the existing spec
  pattern (`credential-types-store.spec.ts`) to add a `credentials-store.spec.ts` covering
  `loadFor` reset, `loadMore` append, the issuer-switch race guard, and `applyUpdate` row patching.
- **Lint/format**: run the repo’s formatters (`cargo fmt`, prettier/eslint as configured).
- **Manual smoke** (optional, via the `verify`/`run` skills): select an issuer → list renders →
  open a credential → suspend → resume → revoke (confirm) → row + detail reflect each new state;
  attempting a disallowed transition surfaces the 409 error toast.

## Build order / dependencies

1. BFF (Steps 1–3) — independent, compile-checkable on its own.
2. SPA service + store + lifecycle (Steps 4–6) — depend on the BFF routes existing (paths) but not
   on the BFF being built.
3. SPA list + detail (Steps 7–8) — depend on 4–6.
4. Routing + menu + i18n (Steps 9–11) — depend on the components existing.
5. Tests/verification (Step 12) — last.

## Out of scope (consistent with the offers slice)

- No state/VCT **filter UI** (the service forwards the params; no controls surface them yet).
- No search-by-id, no numbered pagination (Load-more only), no polling.
- No create flow (credentials are wallet-minted).
- Shared global issuer-context model (the per-page picker, encoded in the URL, is reused as-is).
