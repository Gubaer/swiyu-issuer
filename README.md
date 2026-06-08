# swiyu-issuer

A credential issuer for [SWIYU](https://www.eid.admin.ch/) — the Swiss eID
infrastructure. This repository bundles the issuer service and its web
administration interface into a single polyglot project: a Rust workspace plus
an Angular application.

## Layout

```
swiyu-issuer/
├── api/            # crate `swiyu-issuer` — issuer service + CLI
│   │               #   binaries: swiyu-issuer-mgmtapi, swiyu-issuer-oidcapi,
│   │               #             swiyu-issuer-cli
│   └── …           # see api/README.md
├── web/            # browser-facing tier
│   ├── bff/        # crate `swiyu-issuer-web-bff` — auth-injecting proxy to the mgmt API
│   └── spa/        # Angular admin SPA (npm); served by the BFF
├── keycloak/       # Keycloak realm + image, shared by the api and web stacks
└── deploy/
    └── explorer/   # run-from-published-images bundle (see deploy/explorer/README.md)
```

- **[`api/`](./api/README.md)** — the core issuer: a multi-tenant
  [OID4VCI](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html)
  service (management API + wallet-facing OIDC API) and an operator CLI. Start
  here to build and run from source.
- **[`web/`](./web/spa/README.md)** — the administration interface: an Angular
  single-page app served by a thin axum BFF that proxies, with auth injected,
  to the management API.

The repository is a Cargo workspace (`members = ["api", "web/bff"]`); the SPA is
a standalone npm project under `web/spa`.

## Shared crates

`api` and `web/bff` depend on two shared crates, `swiyu-core` and
`swiyu-registries`, which live in the [`swiyu-rs`](https://github.com/Gubaer/swiyu-rs)
repository (they are also used by `swiyu-didtool` there) and are **not** published
to crates.io.

## Status

Work in progress. The service runs end-to-end against the SWIYU integration
environment, but APIs and on-disk state are not yet stable.

Credentials are currently issued against DIDs registered with `did:tdw` 0.3.
`did:webvh` 1.0 code paths exist in the shared `swiyu-rs` crates but are
unverified.

## Run it without building

To run the full stack — backend **and** the web UI — without cloning the repo or
installing a Rust/Node toolchain, use the **explorer deploy bundle**: a
standalone `docker-compose.yml` that pulls prebuilt images from GitHub Container
Registry. You need Docker, an [ePortal](https://eportal.admin.ch/) account with a
registered Business Partner, and the two files in
[`deploy/explorer/`](./deploy/explorer/README.md). Then open the web UI at
<http://localhost:3000>.

→ [`deploy/explorer/README.md`](./deploy/explorer/README.md)

## Building

- **Rust** (`api`, `web/bff`): `cargo build` / `cargo test` from the repo root.
  Builds use `clang` + `mold` as the linker (see `.cargo/config.toml`); install
  both, or adjust the config.
- **SPA** (`web/spa`): `npm ci && npm run build` from `web/spa`.

See [`api/README.md`](./api/README.md) for the dev compose stack, tenant
bootstrap, and the end-to-end smoke programs.

## License

Licensed under the [MIT License](./LICENSE).

## Acknowledgments

[swiyu-issuer-generic][swiyu-issuer-generic] is the SWIYU generic credential
issuer (Java/Spring); it informed the design of this project and its API and
credential-issuance flows were cross-checked against it during development.

[swiyu-issuer-generic]: https://github.com/swiyu-admin-ch/swiyu-issuer
