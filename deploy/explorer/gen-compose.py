#!/usr/bin/env python3
"""Generate the explorer docker-compose.yml from the dev compose files.

From deploy/explorer/:

  uv run gen-compose.py            # write
  uv run gen-compose.py --check    # CI guard

The dev composes are the single source of truth:
  - api/docker-compose.yml  — the backend stack (Postgres, Vault, Keycloak,
    mgmtapi, oidcapi, the bootstrap sidecars)
  - web/docker-compose.yml  — the swiyu-issuer-web front end (SPA + BFF)

The explorer copy merges both and is regenerated whenever either changes.
Dependencies (ruamel.yaml) are pinned via this directory's pyproject.toml
and uv.lock — `uv run` provisions the venv on first use.
"""

import argparse
import difflib
import io
import sys
from pathlib import Path

try:
    from ruamel.yaml import YAML
    from ruamel.yaml.comments import CommentedMap
except ImportError:
    sys.stderr.write(
        "error: ruamel.yaml is required. From deploy/explorer/:\n"
        "  uv sync && uv run gen-compose.py\n"
    )
    sys.exit(2)

REGISTRY = "ghcr.io/gubaer"

# Dev-compose service name -> image name in the registry. The
# bootstrap sidecars (`bootstrap-dev-tenant`, `bootstrap-dev-issuer`,
# `bootstrap-dev-ba-mapper`, `bootstrap-dev-user`) all run the
# swiyu-issuer-cli image, differing only in entrypoint / command —
# same binary, different invocations.
SERVICE_TO_IMAGE = {
    "swiyu-issuer-mgmtapi": "swiyu-issuer-mgmtapi",
    "swiyu-issuer-oidcapi": "swiyu-issuer-oidcapi",
    "swiyu-issuer-cli": "swiyu-issuer-cli",
    "keycloak": "swiyu-issuer-keycloak",
    "bootstrap-dev-tenant": "swiyu-issuer-cli",
    "bootstrap-dev-issuer": "swiyu-issuer-cli",
    "bootstrap-dev-ba-mapper": "swiyu-issuer-cli",
    "bootstrap-dev-user": "swiyu-issuer-cli",
    "swiyu-issuer-web": "swiyu-issuer-web",
}

EXPLORER_HEADER = """\
# swiyu-issuer explorer stack — pulls published images from GHCR.
#
# Goal: no clone, no cargo, no build — just `docker compose up -d`, then open
# the web UI at http://localhost:3000. The simulated wallet (swiyu-wallet-sim)
# comes up alongside it at http://localhost:8088.
#
# GENERATED FILE. Do not edit by hand. The sources of truth are
# api/docker-compose.yml and web/docker-compose.yml (plus the swiyu-wallet-sim
# service literal in gen-compose.py — that project lives in a separate repo, so
# there is no dev compose here to merge); regenerate with
#   python3 deploy/explorer/gen-compose.py
# CI runs `gen-compose.py --check` to block drift.
#
# IMAGE_TAG defaults to the floating `swiyu-beta`. Pin to a release by setting
# e.g. IMAGE_TAG=0.1.12-swiyu-beta in .env. The web UI and the simulated wallet
# are versioned separately: pin them with WEB_IMAGE_TAG and WALLET_IMAGE_TAG
# (both also default to swiyu-beta).
"""

# The simulated SWIYU wallet is built and published from a separate repo
# (swiyu-wallet-sim), so — unlike every other service — there is no dev compose
# in this repo to merge. Its service is defined here as a literal. Body only;
# the explanatory comment is attached to the `swiyu-wallet-sim` key in
# add_wallet_sim().
WALLET_SIM_SERVICE = """\
image: ghcr.io/gubaer/swiyu-wallet-sim:${WALLET_IMAGE_TAG:-swiyu-beta}
container_name: swiyu-wallet-sim
ports:
  - "${WALLET_HOST_PORT:-8088}:8088"
restart: unless-stopped
"""

WALLET_SIM_COMMENT = (
    "The simulated SWIYU wallet (OID4VCI). Built and published from a separate\n"
    "repo (swiyu-wallet-sim) and versioned independently, so it pins via its own\n"
    "WALLET_IMAGE_TAG. A static SPA served by nginx that talks to the issuer OIDC\n"
    "API from the browser (host side), not over the compose network — hence no\n"
    "depends_on. The host port is WALLET_HOST_PORT (default 8088); 8088 in-container\n"
    "is baked into the nginx config at build time from the wallet's web_dev_config.yaml."
)


def merge_web(api_data, web_data) -> None:
    """Fold the `swiyu-issuer-web` service from the web compose into the api
    compose. The standalone web compose joins the backend over an *external*
    network; in the merged explorer compose it shares the default network with
    the api services, so the external-network indirection is dropped and an
    explicit dependency on the realm + mgmtapi is added."""
    web_service = web_data["services"]["swiyu-issuer-web"]

    # Same default network as the api services — drop the standalone external-net.
    if "networks" in web_service:
        del web_service["networks"]

    # Scrub comments that described the standalone external-network setup so they
    # do not dangle in the merged output. The comment preceding the web compose's
    # top-level `networks:` block attaches to the service's last key (`restart`).
    for key in ("networks", "restart"):
        web_service.ca.items.pop(key, None)

    # Start only once the realm and mgmtapi are healthy (the BFF fetches the
    # realm JWKS at startup and calls mgmtapi on every request).
    depends_on = CommentedMap()
    depends_on["keycloak"] = CommentedMap([("condition", "service_healthy")])
    depends_on["swiyu-issuer-mgmtapi"] = CommentedMap(
        [("condition", "service_healthy")]
    )
    web_service["depends_on"] = depends_on

    api_data["services"]["swiyu-issuer-web"] = web_service


def add_wallet_sim(data) -> None:
    """Append the standalone swiyu-wallet-sim service. Its image lives in a
    separate repo (no dev compose to merge), so the service is parsed from the
    WALLET_SIM_SERVICE literal and added last, after the web front end."""
    yaml = YAML()
    yaml.preserve_quotes = True
    service = yaml.load(io.StringIO(WALLET_SIM_SERVICE))

    services = data["services"]
    services["swiyu-wallet-sim"] = service
    services.yaml_set_comment_before_after_key(
        "swiyu-wallet-sim", before=WALLET_SIM_COMMENT, indent=2
    )


def transform(data) -> None:
    services = data["services"]
    for service_name, image_name in SERVICE_TO_IMAGE.items():
        if service_name not in services:
            sys.stderr.write(
                f"error: dev compose missing expected service '{service_name}'\n"
            )
            sys.exit(2)
        service = services[service_name]
        if "build" in service:
            del service["build"]
        # `profiles` makes sense in the dev compose (keeps the CLI service
        # out of `docker compose up`), but the explorer compose has no
        # always-on CLI to hide, so drop it if present.
        if "profiles" in service:
            del service["profiles"]
        # swiyu-issuer-web is versioned independently from the rust/keycloak
        # images, so it pins via its own WEB_IMAGE_TAG (both default to the
        # floating `swiyu-beta`, which every image carries).
        tag_var = "WEB_IMAGE_TAG" if service_name == "swiyu-issuer-web" else "IMAGE_TAG"
        service["image"] = (
            f"{REGISTRY}/{image_name}:" + "${" + tag_var + ":-swiyu-beta}"
        )
        service.move_to_end("image", last=False)

    # Replace the dev-compose top header with the explorer-audience version.
    # yaml_set_start_comment attaches to the document root; clearing the
    # existing comment list first ensures the dev header is not preserved
    # alongside the new one.
    if data.ca.comment is not None:
        data.ca.comment[1] = []
    data.yaml_set_start_comment(EXPLORER_HEADER)


def generate(api_compose: Path, web_compose: Path) -> str:
    yaml = YAML()
    yaml.preserve_quotes = True
    yaml.indent(mapping=2, sequence=4, offset=2)
    yaml.width = 4096  # don't reflow long scalar values

    with api_compose.open("r", encoding="utf-8") as f:
        api_data = yaml.load(f)
    with web_compose.open("r", encoding="utf-8") as f:
        web_data = yaml.load(f)

    merge_web(api_data, web_data)
    transform(api_data)
    add_wallet_sim(api_data)

    buf = io.StringIO()
    yaml.dump(api_data, buf)
    return buf.getvalue()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--check",
        action="store_true",
        help="exit non-zero if the committed explorer compose is stale",
    )
    args = parser.parse_args()

    script_dir = Path(__file__).resolve().parent
    repo_root = script_dir.parent.parent
    api_compose = repo_root / "api" / "docker-compose.yml"
    web_compose = repo_root / "web" / "docker-compose.yml"
    out_path = script_dir / "docker-compose.yml"

    generated = generate(api_compose, web_compose)

    if args.check:
        existing = out_path.read_text(encoding="utf-8") if out_path.exists() else ""
        if generated != existing:
            sys.stderr.write(
                f"error: {out_path} is stale — regenerate with gen-compose.py\n"
            )
            sys.stdout.writelines(
                difflib.unified_diff(
                    existing.splitlines(keepends=True),
                    generated.splitlines(keepends=True),
                    fromfile=str(out_path),
                    tofile="<generated>",
                )
            )
            return 1
        return 0

    out_path.write_text(generated, encoding="utf-8")
    print(f"wrote {out_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
