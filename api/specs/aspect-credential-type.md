# Credential types

This document captures how `swiyu-issuer` models, owns, and operates credential types: who manages them, how they are made available to issuers, and how they connect to the issuance flow.

Status: preliminary; living document.

Builds on [`aspect-domain.md`](aspect-domain.md) (vocabulary for *CredentialType*, *CredentialConfiguration*, *CredentialSchema*) and [`aspect-multi-tenancy.md`](aspect-multi-tenancy.md) (tenant vs. issuer). Read those first if the terminology here is unfamiliar.

## Scope

`swiyu-issuer` operates with **stable, already-designed** credential types. It is **not** a credential-type authoring or standardisation tool. The following are explicitly out of scope:

- Interactive editing or structural validation of JSON Schema documents — schema authoring UI, lint rules, schema-style checks.
- Interactive editing of claim structures or display configurations beyond accepting a finished document and rejecting malformed input.
- Multi-user authoring workflows — *draft / review / finalise / publish* with distinct roles for designers, reviewers, and approvers.
- Versioning, branching, or diffing of schemas across revisions.

A `CredentialType` arrives in `swiyu-issuer` already designed: authored externally by a tenant administrator, an e-government organisation, or another standardisation body (see *Worked example 2*), then uploaded to the tenant's management surface as a finished artefact. The system's job is to host it, validate credentials against it, project it into OID4VCI metadata, and govern its lifecycle. Designing it is somebody else's job.

This narrows the management surface to receiving and storing finished structured properties and document blobs, performing surface-level acceptance checks (well-formed JSON, parseable JSON Schema, required fields present), and offering CRUD and lifecycle operations on the accepted artefacts. Anything beyond that — schema linting, change diffing, reviewer roles — is delegated to whatever upstream tooling the tenant or standardisation body uses.

## Ownership

A credential type is **owned by a tenant**, not by an issuer.

- Each tenant manages its own set of `CredentialType` records. Creating, editing, retiring, and deleting credential types are tenant-level administrative actions.
- The system does **not** maintain a tenant-independent registry of credential types. If tenant *A* and tenant *B* both manage a credential type with `vct = urn:vct:vct-1`, those are two distinct `CredentialType` rows. They may diverge in claim schema, display, signing algorithm, or any other configuration attribute. This redundancy is intentional and consistent with the multi-tenant isolation model — see [`aspect-domain.md` § *`vct` sharing across issuers*](aspect-domain.md).
- A `CredentialType` belongs to exactly one tenant. It cannot be moved between tenants.

This supersedes the earlier statement in `aspect-domain.md` that *"each `CredentialType` belongs to exactly one issuer"*. Ownership lives at the tenant level; the relationship to an issuer is an assignment (next section), not ownership.

## Properties

A `CredentialType` carries the data needed to (a) identify the kind of credential, (b) configure how an issuer offers it through OID4VCI, (c) validate and describe its claims, and (d) govern its administrative lifecycle. The properties below are grouped by purpose. Field names here are illustrative; canonical Rust/SQL names belong in [`impl_domain.md`](impl_domain.md).

### Identity

- **`id`** — system identifier, generated at creation and stable across edits of other properties. A single, globally unique opaque value (the row's primary key), not a `(tenant_id, slug)` composite and not the `vct`. It uses the same identifier scheme as `tenant`, `issuer`, and `offer` ids: ~10 bytes of CSPRNG output, base58-encoded, displayed with a per-type prefix (`ctype_`). Tenant ownership is carried by the separate `tenant_id` field, not encoded into `id`.
- **`tenant_id`** — the owning tenant. Immutable; types cannot move between tenants.
- **`vct`** — the semantic identifier (URI), e.g. `urn:vct:proof-of-residency`. Embedded in every issued credential's `vct` claim. Two tenants may carry the same `vct` value on independent rows; see [`aspect-domain.md` § *`vct` sharing across issuers*](aspect-domain.md).

### Display

OID4VCI defines `display` as a **localised** structure: an array of `{locale, name, description, logo, background_color, text_color}` entries. `CredentialType` carries this verbatim for projection into the issuer's OID4VCI metadata.

- **`display`** — the OID4VCI display array. Multiple locales are supported: the array carries one entry per locale (e.g. `en-US` and `de-CH`), and `claims` metadata is localised the same way.
- **`internal_description`** — a short admin-facing description, unlocalised. Audience: tenant admins in the management UI. Distinct from the wallet-facing `display.description` and not exposed via OID4VCI.

### Claim schema and claim metadata

Two distinct concerns, both stored directly on the `CredentialType`:

- **`claim_schema`** — the JSON Schema document that **validates** the claims supplied by the BA at issuance, and that the issued credential's `credentialSchema` reference resolves to. Stored as a `JSONB` document blob on the `CredentialType` row, **not** lifted into a separate `CredentialSchema` entity. The reasoning: under the tenant ownership model, schemas can no more cross the tenant boundary than `CredentialType` rows can, so a separate entity earns no reuse to amortise. Storage details and validator-compilation strategy are in [`impl-credential-type.md`](impl-credential-type.md).
- **`claim_schema_source_url`** — optional URL recording where the schema document was originally fetched from when it has an external canonical source (e.g. a SWIYU-operated registry serving a federal type). `NULL` for issuer-private schemas authored in-tenant.
- **`claims` metadata** — the OID4VCI `claims` structure: per-claim **display** information (localised label, mandatory flag, value-type hints) shown by the wallet UI. The schema validates; the claims metadata describes for humans. They are not interchangeable, and currently we carry them as separate fields.

### OID4VCI protocol configuration

These properties together project into one entry of an issuer's `credential_configurations_supported` map.

- **`format`** — wire format identifier, e.g. `vc+sd-jwt` (the only format SWIYU supports today). Because `vc+sd-jwt` is a selective-disclosure format, this single value is what makes every credential of the type selectively disclosable; combined with the `claim_schema` (which fixes the set of candidate claims) it is the only property selective disclosure depends on today. There is deliberately no separate disclosure-policy property — see *Selective disclosure* for why disclosability is currently driven by convention rather than configuration.
- **`signing_algorithm`** — the JWS algorithm the issuer signs credentials of this type with, e.g. `ES256`.
- **`cryptographic_binding_methods_supported`** — how the holder's key is bound to the credential, e.g. `did:jwk`, `did:key`. Multi-valued.
- **`proof_types_supported`** — accepted OID4VCI proof types and the signing algorithms each must use, e.g. `jwt` with `ES256`. Multi-valued, structured per the OID4VCI metadata schema.

### Issuance behaviour

Defaults that the issuer applies when issuing credentials of this type. Whether per-issuance overrides are accepted from the BA is decided in [`aspect-credential-management.md`](aspect-credential-management.md), not here.

- **`default_validity_duration`** — how long credentials of this type are valid by default (e.g. one year). Translates to the issued credential's `exp` / `validUntil`.
- **`revocation_mode`** — one of `revocable`, `suspendable`, `revocable_and_suspendable`, `none`. Determines the status-list bit width allocated for credentials of this type and which lifecycle operations the BA may later invoke against issued credentials.

### Audit and lifecycle metadata

- **`created_at`** — first persisted; immutable.
- **`updated_at`** — last edit. Updated on any property change.
- **`retired_at`** — set when the type is retired (per *Lifecycle*); `NULL` while active. Soft-delete vs. hard-delete is open; see *Open questions*.
- **`created_by` / `updated_by`** — admin user identifiers for audit. Optional at v0.1.0; revisit once admin authentication is in place.

### Structured columns and document blobs

The properties of a `CredentialType` fall into two persistence flavours. Both live in the same RDBMS row; they differ in storage shape and query model.

**Structured columns** carry properties with a fixed, scalar shape — identifiers, enums, durations, timestamps, small structured collections. Examples: `id`, `tenant_id`, `vct`, `format`, `signing_algorithm`, `default_validity_duration`, `revocation_mode`, `created_at`, `retired_at`. SQL relational features (filters, joins, indexes, `NOT NULL` and foreign-key constraints) apply directly.

**Document blobs** carry properties whose shape is itself a document — open-ended, externally defined, or evolving faster than DDL. Examples: the OID4VCI `display` array (per-locale entries of name, description, logo, colours), the `claims` metadata structure (per-claim display information), and the `claim_schema` JSON Schema validating the credential's claims. All are stored as `JSONB` columns alongside the structured ones, so individual fields remain queryable in SQL where useful, but the column type is not coupled to the document's internal evolution.

The split is a deliberate design choice: structured columns where relational features pay off, document blobs where the property is itself a document or where its shape changes faster than the schema can keep up. Concrete column types, blob shapes, and indexes are fixed in [`impl_domain.md`](impl_domain.md), not here.

### Not properties of `CredentialType`

Stated for clarity, since these come up naturally in discussion but live elsewhere:

- The set of issuers the type is assigned to — separate `(issuer_id, credential_type_id)` assignment records, not a field on the type.
- Already-issued credentials of this type — the `IssuedCredential` 1:n relation.
- Per-issuer overrides of any of the properties above — explicitly out of scope at v0.1.0.
- A disclosure policy — which claims are selectively disclosable versus kept in the JWT body as cleartext. This is not a stored property and deliberately not configurable: `format = vc+sd-jwt` plus a fixed partition (a fixed envelope of registered claims is always cleartext; every BA-supplied business claim is selectively disclosable) fully determine it. Neither a `vct` author nor an issuer can override it per claim. See *Selective disclosure*.

## Selective disclosure

The wire format every credential type uses — `vc+sd-jwt` (SD-JWT VC) — is a *selective-disclosure* format: the issuer splits a credential's claims into a signed JWT and a set of **disclosures**, one per selectively-disclosable claim. The JWT carries only salted digests of the disclosable claims (the `_sd` array), not their values; the holder receives all disclosures at issuance and, when presenting to a verifier, forwards only the subset it chooses to reveal. The verifier recomputes each forwarded disclosure's digest and matches it against the signed `_sd` digests, so the issuer's signature covers every claim while the holder controls which ones a given verifier sees. This is the mechanism behind the format identifier the rest of this document otherwise treats as opaque.

Selective disclosure partitions a credential's claims into two groups. The partition is **not** drawn from the credential type's configured claims; it is fixed and identical for every credential type.

**Group 1 — never selectively disclosable (always present in cleartext in the JWT body).** A fixed set of registered SD-JWT VC envelope claims, present on every credential regardless of `vct`:

- **`iss`** — issuer identifier.
- **`vct`** — credential type identifier.
- **`iat`** — issued-at timestamp.
- **`cnf`** — holder key binding.
- **`status`** — status-list pointer; present when the type's `revocation_mode` is not `none`.
- **`nbf`** — not-before; present only when a validity-from is set.
- **`exp`** — expiry; present only when a validity-until is set.

A verifier needs these unconditionally to validate the credential at all, so making them withholdable would be meaningless. The SD-JWT structural members `_sd`, `_sd_alg`, `sd_hash`, and the array-element placeholder `...` are machinery rather than claims: they are never disclosures and the BA may not set them. `sub` is reserved and unused.

**Group 2 — selectively disclosable.** Every claim the type configures — that is, everything validated by its `claim_schema` and supplied by the BA at issuance — without exception. None of a type's business claims is ever forced into cleartext.

The two groups are not a partition of the type's configured claims into a disclosable and a non-disclosable bucket: Group 1 is the fixed envelope and is not made of business claims at all, and Group 2 is the entire configured claim set. Because no business claim can belong to Group 1, there is no claim a type author or issuer could even attempt to move between groups. This makes two rules clean and absolute:

- **A `vct` author cannot mark an individual business claim as always-disclosed.** SD-JWT VC Type Metadata *permits* a per-claim `sd` policy (`always` / `allowed` / `never`); this system deliberately does not support it. The capability is declined, not overlooked — the management surface carries no per-claim disclosure flag, and a type's Type Metadata, where present, is not consulted for disclosure decisions.
- **An issuer cannot override disclosability when creating a credential offer.** The offer supplies claim *values* only; which claims are disclosable is fixed by the partition above, uniform across every credential of the type and every issuer the type is assigned to — exactly like the claim schema and display.

A future version could revisit the first rule if a concrete need for an always-disclosed business claim appears — for example a type discriminator a verifier always needs — in which case the natural home would be a per-claim flag on the `claims` metadata or an annotation on the `claim_schema`. There is no such need today.

### Current behaviour

`CredentialType` carries **no disclosure-policy field**: the partition is fixed in the signing engine, not stored alongside the type. This is the most holder-favourable default, matches the SWIYU profile's expectation that wallets can disclose claims one at a time, and is exactly what the reference SWIYU issuer does — it hardcodes the same envelope/business-claim split. It also keeps the management surface unchanged: no new blob, no new structured column, nothing for an admin to misconfigure. The SD-JWT VC assembly itself — building the `_sd` digests, salting, and serialising the disclosures — is a signing-engine concern documented under [`impl-credential-management.md`](impl-credential-management.md), not a `CredentialType` property.

The partition fixes *which top-level claims* are disclosable; it does not fix how a claim whose value is an object or array is decomposed (whole-value disclosure vs. recursive per-property / per-element disclosure). That axis is orthogonal and remains open — see *Open questions — Disclosure granularity for nested objects and arrays*.

### Relationship to `claims` metadata and `mandatory`

Selective disclosure is orthogonal to the OID4VCI `claims` metadata's `mandatory` flag, and the two are easy to confuse:

- **`mandatory`** governs *issuance*: whether a claim must be present in the credential the issuer mints. A mandatory claim cannot be omitted by the BA at issuance time.
- **Selective disclosure** governs *presentation*: whether the holder may withhold a claim from a verifier after issuance.

A claim can be both mandatory and selectively disclosable. Currently, every mandatory BA claim is exactly that. "Mandatory" binds the issuer and BA; it places no obligation on the holder to reveal the claim to any downstream verifier.

## Assignment to issuers

A tenant may **assign** any of its credential types to **zero, one, or more of its own issuers**. The assignment is the link that makes a credential type issuable through a specific issuer.

- An issuer can issue credentials of a given `CredentialType` if and only if that type is currently assigned to it by its tenant.
- The assignment is purely an *(issuer, credential_type)* link within a tenant. **No per-issuer overrides** of the `CredentialType` data are supported at v0.1.0: display, claim schema, signing algorithm, binding methods, and accepted proof types are taken from the `CredentialType` itself and are identical across every issuer it is assigned to. The default is to keep this simple; per-issuer overrides may be revisited only if a real need appears (the most plausible candidate would be issuer-specific display/branding, but issuer-level branding already lives on the issuer record per `aspect-multi-tenancy.md`).
- Both the credential type and the issuer must belong to the same tenant. Cross-tenant assignment is not possible.

### Effect on the protocol surface

An issuer's OID4VCI `credential_configurations_supported` is **exactly** the set of credential types its tenant has assigned to it — no other source. Assigning a type to an issuer adds an entry; un-assigning removes it. The wallet-facing OIDC metadata is a direct projection of these assignments.

## Issuance via a Business Application

A Business Application (BA) requests an issuer to issue a credential of a specific type on the BA's behalf.

- The BA's request to the management API carries `(issuer_id, credential_type_id, claims)` (plus offer-specific parameters). Concrete request schema is defined in [`impl-credential-management.md`](impl-credential-management.md).
- The server validates, in order:
  1. The authenticated tenant owns the issuer.
  2. The authenticated tenant owns the credential type.
  3. The credential type is currently assigned to that issuer.
  4. The supplied claims validate against the credential type's schema.
- Any of (1)–(3) failing is a scoping error and is rejected before claim validation.
- A single credential offer always references one issuer and one credential type; multi-type offers are out of scope at v0.1.0.

## Lifecycle

Two distinct operations affect the issuability of a type:

**Un-assigning** a credential type from an issuer (tenant action, scoped to one issuer):

- The *(issuer, type)* link is removed.
- The type disappears from that issuer's OID4VCI metadata.
- New credential offers cannot be created for that *(issuer, type)* pair.
- Already-issued credentials are **not** affected: they remain valid, can still be revoked or suspended through the normal status-list flow, and the issuer continues to honour status lookups for them.
- Other issuers within the same tenant that still have the type assigned are unaffected.

**Retiring or deleting** a credential type at the tenant level (tenant action, affects all assignments):

- This is a larger operation: it transitively un-assigns the type from every issuer the tenant had assigned it to, and prevents future re-assignment.
- Already-issued credentials are not invalidated by retiring the type. Revocation/suspension of issued credentials is a separate, per-credential operation and is unchanged by retirement.
- Retirement is a **soft-delete**: the row is kept with a `retired_at` timestamp set, not hard-deleted. The row stays available for audit and for historical lookup from already-issued credentials, whose `vct` verifiers may still resolve long after the type is retired. Hard deletion would either be blocked by references from offers and issued credentials or would erase that historical link, so it is not used.

The tenant operations described here govern the *type definition*. They are independent of the lifecycle of individual issued credentials, which is handled per `aspect-credential-management.md`.

## Management surface

Credential types are managed through the same tenant-authenticated **management API** that BAs use for issuance — both BAs and the admin web UI call it, both authenticated as the tenant. Detailed endpoint shapes (paths, request/response schemas, error codes, authorisation rules) belong to the API design document for credential-type management, separate from this aspect document. This section fixes only the principle that drives that design.

The API mirrors the persistence split documented under *Properties → Structured columns and document blobs*:

- **Structured properties** are managed through CRUD on a `credential-type` resource: create, list, fetch, update structured fields, retire. Request and response bodies carry the structured columns as JSON; document-blob properties are not embedded — they appear as references to their own endpoints.
- **Document-blob properties** are managed through per-document upload/download endpoints. Example: `POST /credential-type/{id}/schema` uploads the JSON Schema validating the type's claims; `GET /credential-type/{id}/schema` returns the current document. The same shape applies to `display`, `claims` metadata, and any further document-blob fields added later.

Practical consequences of the split:

- Editing a single structured property (e.g. correcting an entry in `display`) does not require re-uploading the schema document.
- The schema's `GET` endpoint *is* the URL referenced from issued credentials' `credentialSchema`, so verifiers fetch from the same endpoint the management surface writes to.
- Listing endpoints stay compact: a list of credential types returns each row's structured columns plus URLs to its blobs, not the embedded blobs.

The URL segment is the credential type's `id` (the `ctype_`-prefixed identifier described under *Properties → Identity*), the same way tenant and issuer resources are addressed by their ids.

## Cardinalities

Restating the relationships involving `CredentialType`, with the change from `aspect-domain.md` made explicit:

- **Tenant → CredentialType**: 1:n. Each credential type belongs to exactly one tenant.
- **Tenant → Issuer**: 1:{0..n} (from `aspect-multi-tenancy.md`).
- **Issuer ↔ CredentialType (assignment)**: n:m, **constrained to types and issuers within the same tenant**. An issuer is assigned to zero or more of its tenant's credential types; a credential type is assigned to zero or more of its tenant's issuers.
- **CredentialType → CredentialOffer**: 1:n (unchanged).
- **CredentialOffer → IssuedCredential**: 1:{0..1} (unchanged).

## Relation to other aspects

- **Vocabulary** — `CredentialType`, `CredentialConfiguration`, `CredentialSchema` are defined in [`aspect-domain.md`](aspect-domain.md). This document refines the ownership rules stated there.
- **Multi-tenancy** — tenant and issuer are defined in [`aspect-multi-tenancy.md`](aspect-multi-tenancy.md). The assignment model in this document depends on the cross-cutting scoping mitigations listed there (newtypes for `TenantId`/`IssuerId`, the `(tenant_id, issuer_id)` ownership check at the request boundary, row-level security as defence in depth).
- **Credential-type implementation** — [`impl-credential-type.md`](impl-credential-type.md) covers the `credential_types` table DDL, the `JSONB` blob columns (`claim_schema`, `display`, `claims`), the compiled-validator cache, the OID4VCI metadata projection from assignments, and the tenant-admin management API.
- **Credential management API** — [`aspect-credential-management.md`](aspect-credential-management.md) and [`impl-credential-management.md`](impl-credential-management.md) define the BA-facing endpoints; the validation rules in *Issuance via a Business Application* above are enforced there.

## Worked examples

Two scenarios that exercise the model from different angles: a wholly tenant-internal credential type, and a credential type standardised by an external body and adopted independently by several tenants.

### Example 1 — a tenant-internal credential type

The commune of **Flawil** is registered as a tenant in `swiyu-issuer`. Acting as that tenant, a Flawil administrator:

1. **Creates a `CredentialType`** with `vct = "urn:communal:3402:library-card"`, a `display` entry naming it *"Bibliotheksausweis Flawil"* in `de-CH`, an internal description (*"Library card for the communal library"*), a claim schema covering cardholder details, `format = vc+sd-jwt`, `signing_algorithm = ES256`, and `revocation_mode = revocable_and_suspendable`. The type belongs to the Flawil tenant.
2. **Registers an issuer `I1`** with display name *"Gemeindebibliothek Flawil"* under the Flawil tenant. `I1` is identified by a DID generated at registration; a Trust Statement linking that DID to Flawil's SWIYU Business Partner identity may be minted later but is not required for `I1` to exist.
3. **Assigns** `urn:communal:3402:library-card` to `I1`. From this point on, `I1`'s OID4VCI `credential_configurations_supported` contains one entry — the library-card type — and wallets discovering `I1` see exactly that. The type is now issuable through `I1`.
4. **The business application inside the communal library** issues credentials by calling the management API with a Flawil-tenant token: `(issuer_id = I1, credential_type_id = …, claims = …)`. The server confirms that Flawil owns both `I1` and the library-card type, that the type is assigned to `I1`, validates the claims against the schema, and drives the OID4VCI offer flow that delivers the signed credential to the patron's wallet.

How this maps onto the rules:

- *Ownership.* A neighbouring tenant — say, the commune of Wil — that wanted its own library card would create a **separate** `CredentialType` row, even if it picked the same `vct` value. There is no shared registry.
- *Assignment.* If Flawil later spins up a second issuer `I2` (for example, a partner reading-room), it can assign the same type to `I2`; both `I1` and `I2` would then offer the type without any per-issuer customisation.
- *Lifecycle.* If Flawil later un-assigns the type from `I1`, library cards already issued continue to work and remain revocable / suspendable through the normal flow; only **new** offers through `I1` for that type are blocked. Retiring the type at the tenant level un-assigns it from every issuer that had it.

### Example 2 — a standardised credential type used by several tenants

The **canton of St. Gallen e-government organisation** acts as a standardisation body for credentials that multiple communes are expected to issue under a common shape. It is **not** a system entity inside `swiyu-issuer`; it is an external stakeholder that publishes governance artefacts (a `vct` value, a standardised claim set, a JSON Schema, recommended display) for use by tenants.

The e-gov organisation publishes a standard for credentials certifying that a person is a member of a municipal council or commission: a `vct` of `urn:cantonal:sg:council-and-commission-membership`, a standardised claim set (member name, body name, role, term start/end), and a JSON Schema validating those claims.

Two communes adopt the standard, independently of one another:

- **Flawil** is a tenant and operates issuer `I1` *"Kanzlei"*. Flawil creates a `CredentialType` row with the standard's `vct`, claims, and schema. The row is owned by the Flawil tenant. Flawil assigns the type to `I1`.
- **Buchs** is also a tenant and operates issuer `I2` *"Gemeindeverwaltung"*. Buchs creates **its own separate `CredentialType` row**, again with the standard's `vct`, claims, and schema. The row is owned by the Buchs tenant. Buchs assigns the type to `I2`.

Both communes' BAs then issue council-membership credentials through their respective issuers via the management API.

How this maps onto the rules:

- *Standardisation lives outside the system.* The e-gov organisation is a stakeholder providing governance, not a database entity. Standards are consumed by tenant administrators when they configure their `CredentialType` rows; conformance to the standard is an operational matter, not enforced by `swiyu-issuer`.
- *Sharing a `vct` does not share a row.* Flawil's and Buchs's rows carry the same `vct` value but are two independent records, each owned by its own tenant, each independently editable and assignable. This is precisely the scenario described in [`aspect-domain.md` § *`vct` sharing across issuers*](aspect-domain.md), arrived at here through standardisation rather than coincidence.
- *No template inheritance* If the e-gov organisation later revises the standard (adds a claim, tightens the schema), each adopting tenant updates its own row. Bulk assignment or templating — letting the canton publish a "standard" type that communes copy into their own tenant scope, with some flow for propagating updates — is operational tooling rather than a domain change, and is currently out of scope.

## Open questions

- **Edit semantics on a type with issued credentials.** Which attributes of a `CredentialType` are mutable once credentials of that type have been issued (e.g., display strings yes, claim schema no), and how mutation propagates (or deliberately does not propagate) to the OID4VCI metadata.
- **Validity overrides per issuance.** Whether the BA can override `default_validity_duration` per credential offer, or whether the type's default is fixed for all credentials it produces. Decision belongs in [`aspect-credential-management.md`](aspect-credential-management.md).
- **Disclosure granularity for nested objects and arrays.** SD-JWT VC permits selective disclosure of individual object properties and individual array elements, not only top-level claims. The current "every top-level claim is one disclosure" rule does not fix how a claim whose value is an object or array is decomposed (whole-value disclosure vs. recursive per-property / per-element disclosure). Deferred until a credential type with structured claims needs it.
- **Decoy digests.** Whether the issuer pads the `_sd` array with decoy digests to obscure how many disclosable claims a credential carries. A privacy-hardening measure with no holder-visible effect; currently out of scope.
