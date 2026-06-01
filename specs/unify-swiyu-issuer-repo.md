# Plan: Unify swiyu-issuer components into the `swiyu-issuer` repo

## Goal

Move two components currently living in the `swiyu-rs` monorepo into this new,
currently-empty `swiyu-issuer` repository, **preserving git history**:

1. **API server + CLI** — `swiyu-rs/swiyu-issuer/` (crate `swiyu-issuer`,
   management API, OIDC API, CLI). Latest code on branch `swiyu-issuer`.
2. **Web interface** — `swiyu-rs/swiyu-issuer-web/` on branch `swiyu-issuer-web`:
   - `bff/` — Rust crate `swiyu-issuer-web-bff`
   - `spa/` — Angular app (npm)

## Source facts (verified 2026-06-01)

- Both components are members of the **`swiyu-rs` Cargo workspace**, not separate repos.
- `swiyu-rs` remotes: `github` = `git@github.com:Gubaer/swiyu-rs.git`,
  `origin` = `git@bitbucket.org:gubaer/swiyu-rs.git`.
- The target `swiyu-issuer` repo is empty (only `.git`, branch `master`, no commits;
  the only working-tree content is `specs/` holding this plan, not yet committed).
- Crate versions: `swiyu-issuer` **0.1.16**; shared `swiyu-core` **0.3.2**,
  `swiyu-registries` **0.1.3**.
- Prereqs satisfied: `uv` installed; `uvx git-filter-repo` runs.

### Dependency graph (the reason this needs care)

```
swiyu-issuer        -> swiyu-core, swiyu-registries (features = ["status"])
swiyu-issuer-web/bff-> swiyu-core, swiyu-registries (features = ["identifier"])
swiyu-registries    -> swiyu-core
swiyu-didtool       -> swiyu-core, swiyu-registries   (stays in swiyu-rs)
spa (Angular)       -> no Rust deps
```

`swiyu-core` (v0.3.2) and `swiyu-registries` (v0.1.3) are shared and **also used
by `swiyu-didtool`, which stays in `swiyu-rs`**. They are **not** published to
crates.io.

### Branch divergence — RESOLVED (2026-06-01)

The divergence the plan originally had to reconcile no longer exists. Manual
cleanup in `swiyu-rs` unified the branches:

- `master` was merged into `swiyu-issuer`, then `swiyu-issuer` was merged into
  `swiyu-issuer-web`. No uncommitted work remains in the web worktree.
- **`swiyu-issuer` is now fully contained in `swiyu-issuer-web`** (0 ahead, 27
  behind); `master` is fully contained in both (0 ahead).
- The 2 formerly issuer-ahead commits (`3e98e11`, `9d76f03`, which modify
  `swiyu-issuer/`: credential-decrypt error handling, wallet-URL resolution,
  config) are now ancestors of `swiyu-issuer-web` — so the **stale-copy problem
  is gone**: the web branch carries the latest API *and* latest web code.
- **`swiyu-issuer-web` is the single unified extraction point.** Its tip is
  `a225ebf "temporary work"` (relevant merges below it:
  `89e9508 Merge branch 'swiyu-issuer' into swiyu-issuer-web`,
  `730755e Merge branch 'master' into swiyu-issuer`).
- ⚠️ The tip commit message is `"temporary work"`. Consider amending/renaming it
  before extraction, since it becomes the newest commit in the extracted history.
- merge-base (historical, for reference): `391a995262299e929092f4fbda5ab94da66375c3`.
- The web tip still also carries `swiyu-core`, `swiyu-registries`, and
  `swiyu-didtool` — these are excluded by the filter-repo path selection (Option B).

## Decisions

| Decision | Choice |
|---|---|
| Shared crates (`swiyu-core`, `swiyu-registries`) | **Option B** — keep in `swiyu-rs`, depend via **git dependency** (no crates.io publish needed). |
| Git history | **Preserve** (via `git-filter-repo`). |
| Phase-1 unification | **Done (2026-06-01)** via direct merges on existing branches — `swiyu-issuer-web` now holds the latest of both. No separate integration branch was needed. |
| Git-dep pin form | **Tag** `shared-crates-2026-06-01` pinned in the new repo's `Cargo.toml`. |
| `git-filter-repo` install | Via **`uv`** (`uv tool install git-filter-repo`, or run with `uvx git-filter-repo`). |
| Target layout | `swiyu-issuer/` (was `swiyu-issuer/`) → **`api/`**; `swiyu-issuer-web/` → **`web/`**. Renamed in the filter-repo pass (history preserved). |

## Target layout

```
swiyu-issuer/                # repo root
├── Cargo.toml               # workspace: members = ["api", "web/bff"]
├── api/                     # was swiyu-issuer/  → crate `swiyu-issuer` (+ mgmt/oidc/CLI bins)
│   ├── Cargo.toml
│   ├── src/ migrations/ schemas/ specs/ deploy/ ...
│   └── Dockerfile docker-compose.yml .env.example ...
└── web/                     # was swiyu-issuer-web/
    ├── bff/                 # crate `swiyu-issuer-web-bff`
    └── spa/                 # Angular app (npm)
```

- Directory names need not match crate names; Cargo keys off `name` in `Cargo.toml`.
  Crate names (`swiyu-issuer`, `swiyu-issuer-web-bff`) and binary names are unchanged.
- The split is intentional: `web/` is the browser-facing tier (SPA + the BFF that
  serves it); `api/` is the core issuer service + CLI.

## Plan

### Phase 0 — Prerequisites
- Install `git-filter-repo` using `uv`:
  - `uv tool install git-filter-repo` (or invoke ad hoc via `uvx git-filter-repo ...`).
- Verify availability.

### Phase 1 — Unify the two branches in `swiyu-rs`

**Merge step: DONE (2026-06-01).** `swiyu-issuer-web` is the unified extraction
ref (`swiyu-issuer` and `master` are both ancestors of it). No integration branch
was created — the existing `swiyu-issuer-web` branch is used directly.

**Remaining: tag the shared crates on `swiyu-issuer-web`.**
- **Tag** the shared crates' state on `swiyu-issuer-web` as **`shared-crates-2026-06-01`**
  and push it to both remotes — this tag is what the new repo's git deps pin to.
  It guarantees `swiyu-core`/`swiyu-registries` match exactly what the moved code
  was built against.
- Because the tag pins a commit independently of any branch, no integration branch
  needs to be kept alive afterward.

### Phase 2 — Extract with history (and rename to `api/` + `web/`)
- Clone `swiyu-rs` (the `swiyu-issuer-web` ref) to a scratch directory.
- Run a single filter-repo pass that keeps both paths **and** renames them:
  ```
  git filter-repo \
    --path swiyu-issuer/ --path swiyu-issuer-web/ \
    --path-rename swiyu-issuer/:api/ \
    --path-rename swiyu-issuer-web/:web/
  ```
  - Keeps full history of both paths; **excludes** `swiyu-core`/`swiyu-registries`
    (Option B), `swiyu-didtool`, workspace root files, etc.
  - The rename is history-preserving: `git log --follow` works across the move.
- Result: a history with just `api/` and `web/` at repo root.

### Phase 3 — Land in the new `swiyu-issuer` repo
- Add the filtered scratch repo as a remote to `swiyu-issuer` and fetch.
- Fast-forward / merge its history onto `master`, preserving commits.

### Phase 4 — Rewire dependencies (Option B)
- Add a new workspace `Cargo.toml` at the repo root:
  ```toml
  [workspace]
  members = ["api", "web/bff"]
  resolver = "2"
  ```
- Rewrite path deps to git deps pinned to the Phase-1 tag, in both
  `api/Cargo.toml` and `web/bff/Cargo.toml`:
  ```toml
  swiyu-core       = { git = "ssh://git@github.com/Gubaer/swiyu-rs.git", tag = "shared-crates-2026-06-01" }
  swiyu-registries = { git = "ssh://git@github.com/Gubaer/swiyu-rs.git", tag = "shared-crates-2026-06-01", features = ["status"] }
  # web/bff uses features = ["identifier"]
  ```
- Regenerate `Cargo.lock`.
- Angular SPA (`web/spa`) needs no Rust wiring; moves as files.

### Phase 4b — Fix internal path references + rework Dockerfiles
After the rename, references to the old directory names must be updated.

**Functional refs (build/run-breaking — must fix):**
- `api/docker-compose.yml` — `dockerfile: swiyu-issuer/Dockerfile` (×5) and build contexts → `api/`.
- `api/Dockerfile` — header comments + COPY/context lines.
- `api/deploy/explorer/{publish-images.sh, gen-compose.py, README.md, docker-compose.yml}` — `swiyu-issuer/` → `api/`
  (incl. the raw.githubusercontent.com URLs, which also move from `swiyu-rs/.../swiyu-issuer/` to this repo's `api/`).

**Dockerfile rework (driven by Option B, not just the rename):**
- The Dockerfiles currently assume a monorepo build context that COPYs
  `swiyu-core` + `swiyu-registries` + `swiyu-issuer` together. Under Option B those
  two crates are **git dependencies** fetched by cargo at build time, so the build
  context becomes just this repo. Update COPY paths, build context, and any
  `--path`/workspace assumptions accordingly (cargo will need network/git access
  to fetch the pinned tag, or a vendoring step).

**Documentation refs (cosmetic — optional but recommended):**
- `web/spa/specs/*.md` breadcrumbs referencing `swiyu-issuer-web/bff/...` and
  `swiyu-issuer-web/spa/...` (~20 lines) → `web/...`.

### Phase 5 — Verify
- Rust: `cargo build` + `cargo test` for `api` and `web/bff`.
- SPA: `npm install` + build in `web/spa`.
- Docker: build images via the reworked `api/Dockerfile` to confirm the git-dep
  build context resolves.
- Confirm no stale `swiyu-issuer/` or `swiyu-issuer-web/` path refs remain in
  functional files (`git grep -n 'swiyu-issuer\(-web\)\?/'`).
- Sanity-check that ancillary assets came along inside the two dirs: `README`,
  `.env.example`, Dockerfiles, `migrations/`, `schemas/`, `specs/`, openapi specs.
- Optional: update root `README.md` describing the unified repo layout.

### Phase 6 — Clean up `swiyu-rs` (run only after the new repo is verified)

Three levels, increasing risk. **Default to Level 1.** The shared crates
(`swiyu-core`, `swiyu-registries`) and `swiyu-didtool` stay in `swiyu-rs`.

Pre-check (dependency-safe): nothing remaining depends on `swiyu-issuer` —
`swiyu-didtool` depends only on `swiyu-core` + `swiyu-registries`. Note
`swiyu-issuer-web/` only ever existed on the `swiyu-issuer-web` branch, never on
`master`.

**⚠️ Ordering guard:** the `shared-crates-2026-06-01` **tag must be created and pushed
before deleting any of the source branches** (`swiyu-issuer`, `swiyu-issuer-web`).
A tag keeps its commit alive independently of any branch, so once the tag exists,
deleting the branches is safe. (No `integration/web-move` branch exists — the
unification was done on `swiyu-issuer-web` directly.)

#### Level 1 — Logical cleanup (recommended; low risk, history retained)
1. On `master`: `git rm -r swiyu-issuer/`, remove `"swiyu-issuer"` from root
   `Cargo.toml` `members`, commit, push to both remotes (`github`, `origin`).
   (No web dir on `master` to remove.)
2. Delete the branches locally + on both remotes (remove the
   `.worktrees/swiyu-issuer-web` worktree first):
   ```
   git worktree remove .worktrees/swiyu-issuer-web
   git branch -D swiyu-issuer swiyu-issuer-web
   git push github :swiyu-issuer :swiyu-issuer-web
   git push origin :swiyu-issuer :swiyu-issuer-web
   ```
- Does **not** shrink the repo: old commits still hold the blobs; a fresh clone
  still downloads them. Normal and usually harmless.

#### Level 2 — Physical purge from the object store (high risk; only if needed)
Use only for genuinely sensitive content or repo bloat — not for a routine move.
```
# in a fresh clone of swiyu-rs
git filter-repo --invert-paths --path swiyu-issuer/ --path swiyu-issuer-web/
git reflog expire --expire=now --all
git gc --prune=now --aggressive
# then force-push every branch + tag to both remotes
```
(`git filter-repo` or `BFG Repo-Cleaner`; `git filter-branch` is deprecated.)

Caveats — why this is gated and runs **last**:
- **Rewrites every commit SHA** from the merge-base onward. The `shared-crates-2026-06-01`
  tag gets rewritten to the new commit, so a fresh `cargo update` in the new repo
  re-resolves fine — but any existing `Cargo.lock` (new repo, CI, clones) pins the
  **old rev that no longer exists** → builds fail until `cargo update`. So: verify
  the new repo first, purge `swiyu-rs` last, then re-lock the new repo.
- **Force-push breaks every clone, CI pipeline, and open PR** on both remotes;
  everyone must re-clone. Remote gc (forks, PR refs, caches) may retain old
  objects for a long time regardless.
- Effectively irreversible.

## Open / follow-up items
- `swiyu-rs` cleanup is now **Phase 6** — confirm Level 1 vs Level 2 when ready.
- Confirm whether the new repo should also push to a GitHub/Bitbucket remote.
- ~~Exact tag name for the shared-crates pin.~~ **Decided: `shared-crates-2026-06-01`.**

## Notes
- Git dependencies resolve fine against **workspace-member** crates inside a repo
  (cargo locates the crate by name); crates.io publishing is not required.
- The new repo is intentionally **polyglot**: a Rust workspace + an Angular/npm app.
