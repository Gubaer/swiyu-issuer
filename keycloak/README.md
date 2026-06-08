# Keycloak for swiyu-issuer (development)

A Keycloak authorization server for the swiyu-issuer development stacks — the
local dev stack (`api/docker-compose.yml`), the web front end
(`web/docker-compose.yml`), and the explorer stack (`deploy/explorer/`) — with
the `swiyu-issuer` realm baked in. It lives at the repo root because the realm
is shared by the api and web tiers: `swiyu-issuer-mgmtapi` validates the
EdDSA-signed JWTs the realm issues (deriving the tenant from a `tenant_id`
claim), and the web BFF runs the user login + act-as-user token exchange
against the same realm.

> Development only. The realm uses fixed dev secrets and `sslRequired=none`
> (plain HTTP). Do not use it as-is in production.

## What the realm contains

- **Realm `swiyu-issuer`** — issues `iss = http(s)://<host>/realms/swiyu-issuer`;
  JWKS at `.../protocol/openid-connect/certs`. Tokens are **EdDSA-signed**
  (realm default signature algorithm `EdDSA`, backed by an `eddsa-generated`
  Ed25519 key).
- **`swiyu-issuer-mgmtapi`** — a bearer-only client representing the protected
  API. It holds no flows and gets no tokens; it exists only to be the token
  **audience**. Its client id is the `aud` value mgmtapi requires
  (`MGMTAPI_AUDIENCE`).
- **`mgmtapi-audience`** client scope — an audience mapper that adds
  `swiyu-issuer-mgmtapi` to the access-token `aud`. Assigned to `dev-ba`.
- **`dev-ba`** — the sample business application: a confidential client using
  the client-credentials grant. It emits `principal_type = tenant`. The
  `tenant_id` claim is **not** in the realm; it is added at bootstrap (see
  below).
- **`provisioner`** — a least-privilege service-account client
  (`realm-management:manage-clients`) the CLI authenticates as to upsert the
  `dev-ba` `tenant_id` mapper. No human admin password needed.

## Build and run

```sh
docker build -f keycloak/Dockerfile -t swiyu-issuer-keycloak:dev keycloak
docker run --rm -p 8083:8080 -p 9000:9000 \
    -e KC_BOOTSTRAP_ADMIN_USERNAME=admin \
    -e KC_BOOTSTRAP_ADMIN_PASSWORD=admin \
    swiyu-issuer-keycloak:dev
```

Readiness: `GET http://localhost:9000/health/ready`. Both the local dev stack
(`api/docker-compose.yml`) and the explore stack (`deploy/explorer/`) wire
this up.

## The `tenant_id` mapper is provisioned after import

A federated tenant's id (`tenants.id`) is generated at tenant-creation time, so
it cannot be baked into the realm export. After the dev tenant exists, the CLI
adds/updates a hardcoded `tenant_id` mapper on `dev-ba` over the Admin API,
authenticating as `provisioner`. Until that runs, `dev-ba` tokens carry no
`tenant_id` and mgmtapi rejects them. (This step and its wiring into both
compose stacks land with the stack integration.)

## Minting a `dev-ba` token by hand (debugging)

```sh
curl -s -X POST \
  http://localhost:8083/realms/swiyu-issuer/protocol/openid-connect/token \
  -d grant_type=client_credentials \
  -u dev-ba:dev-ba-secret
```

Decode the returned `access_token` (e.g. on jwt.io) and confirm it carries
`iss`, `aud=swiyu-issuer-mgmtapi`, `azp=dev-ba`, `principal_type=tenant`, and —
once the mapper is provisioned — `tenant_id=tenant_…`. The JOSE header `alg`
must be `EdDSA`.
