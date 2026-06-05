# swiyu-issuer examples

Standalone smoke programs that drive `swiyu-issuer` end-to-end against a live stack (Postgres + `swiyu-issuer-mgmtapi` + `swiyu-issuer-oidcapi` + the SWIYU integration registries). They are **not** unit or integration tests — they expect real services to be running and they call out to the SWIYU integration backend.

Run any of them with:

```
cargo run --example <name>
```

`cargo build` and `cargo test` do not build examples; they are compiled only on demand.

## What's here

| Example                              | What it exercises                                                                                                  |
|--------------------------------------|--------------------------------------------------------------------------------------------------------------------|
| `issuer_lifecycle_smoke`             | Issuer DID lifecycle: create, rotate keys, deactivate. Talks to the management API only; verifies each phase against the Identifier Registry. |
| `credential_lifecycle_smoke`         | Full credential issuance flow: management API mints an offer, then a synthetic wallet drives the pre-authorized-code grant against `swiyu-issuer-oidcapi` and receives a credential. |
| `credential_status_lifecycle_smoke`  | Credential issuance plus status-list lifecycle: revoke/suspend bit updates land in the Status Registry as signed `application/statuslist+jwt` documents. |

All three:

- obtain a `dev-ba` access token at startup — a Keycloak-issued JWT via the client-credentials grant against `KEYCLOAK_TOKEN_URL` — and use it as the `Authorization: Bearer` credential, so the smokes exercise the same OAuth2 path real callers use,
- print `=== smoke run PASSED ===` on success and exit non-zero on failure, so they're CI-friendly.

## Environment

The examples read configuration from the process environment. The repo's `.env.example` files document every variable; the ones the examples themselves consume are:

| Variable                  | Required? | Used by                                  | Notes                                                                                  |
|---------------------------|-----------|------------------------------------------|----------------------------------------------------------------------------------------|
| `ISSUER_BASE_URL`         | yes       | all three                                | Management API base, e.g. `http://localhost:8080`. Also used as the OIDC `aud`.        |
| `KEYCLOAK_TOKEN_URL`      | yes       | all three                                | Realm token endpoint, e.g. `http://localhost:8083/realms/swiyu-issuer/protocol/openid-connect/token`. The smokes obtain a `dev-ba` JWT here via the client-credentials grant. |
| `DEV_BA_CLIENT_ID`        | yes       | all three                                | Keycloak client id of the sample business application (`dev-ba`).                       |
| `DEV_BA_CLIENT_SECRET`    | yes       | all three                                | Client secret for `dev-ba`. Treat as a secret.                                          |
| `ISSUER_OIDC_HTTP_URL`    | no        | `credential_lifecycle_smoke`, `credential_status_lifecycle_smoke` | URL the OIDC binary listens on. Defaults to `http://localhost:8081`.                   |
| `LIFECYCLE_TIMEOUT_SECS`  | no        | all three                                | Per-phase timeout. Default: 120.                                                       |
| `LIFECYCLE_POLL_MS`       | no        | all three                                | Polling interval while waiting on async sagas. Default: 1000.                          |
| `SIGNING_ENGINE`          | no        | all three (informational)                | Logged at startup so the run record shows which backend `swiyu-issuer-mgmtapi` is using. The smoke does not act on it — it is `swiyu-issuer-mgmtapi`'s choice.                                                       |
| `RUST_LOG`                | no        | all three                                | Standard `tracing-subscriber` filter. Default: `info`.                                 |

The smokes do not call the registries or the database directly; they go through the management and OIDC APIs over HTTP, authenticating with a `dev-ba` JWT. Whichever `SWIYU_*` and `OAUTH2_*` variables `swiyu-issuer-mgmtapi` needs must therefore be set in *its* environment, not the smoke's.

## Typical run against the dev compose stack

```
# In one terminal:
cd api
docker compose up -d

# In another terminal, with the workspace .env loaded (e.g. via direnv):
cargo run --example issuer_lifecycle_smoke
cargo run --example credential_lifecycle_smoke
cargo run --example credential_status_lifecycle_smoke
```

Each one is independent and idempotent in the sense that it owns the rows it creates; running them in any order, repeatedly, is safe.
