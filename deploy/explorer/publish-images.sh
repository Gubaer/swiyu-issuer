#!/usr/bin/env bash
# Build the swiyu-issuer Docker images and optionally push to GHCR.
#
# Local tags applied to every build, per image:
#   swiyu-issuer-<name>:swiyu-beta
#   swiyu-issuer-<name>:<version>-swiyu-beta
# With --push, also tags as <REGISTRY>/swiyu-issuer-<name>:... and pushes both.
#
# Env vars:
#   REGISTRY   defaults to ghcr.io/gubaer; override for a fork.
#   PLATFORMS  defaults to linux/amd64; set e.g. linux/amd64,linux/arm64 for multi-arch.
#
# Other arguments are forwarded to `docker buildx build` (e.g. --no-cache).

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# This script lives at deploy/explorer/; the repo root is two levels up.
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

# All images share one version, defined once in the workspace root Cargo.toml
# ([workspace.package]) and inherited by the api and web/bff crates in lockstep.
VERSION="$(grep -m1 '^version' "${REPO_ROOT}/Cargo.toml" \
    | sed -E 's/^version *= *"([^"]+)".*/\1/')"

REGISTRY="${REGISTRY:-ghcr.io/gubaer}"
PLATFORMS="${PLATFORMS:-linux/amd64}"

# Dynamic OCI labels — describe the build, not the source tree. The static
# org.opencontainers.image.* labels live in the Dockerfile per runtime stage.
# `set -e` aborts the script if `git rev-parse HEAD` fails (e.g. run outside a
# checkout), so no label-less image is ever produced.
GIT_REVISION="$(git rev-parse HEAD)"
BUILD_CREATED="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

PUSH=0
DOCKER_ARGS=()
for arg in "$@"; do
    case "$arg" in
        --push) PUSH=1 ;;
        *) DOCKER_ARGS+=("$arg") ;;
    esac
done

if ! docker buildx version >/dev/null 2>&1; then
    echo "error: 'docker buildx' is not available. Install Docker 19.03+ with the buildx plugin." >&2
    exit 1
fi

if ! docker buildx inspect >/dev/null 2>&1; then
    echo "error: no usable buildx builder for platforms '${PLATFORMS}'." >&2
    echo "       create one with: docker buildx create --use" >&2
    exit 1
fi

if [[ "${PUSH}" -eq 1 ]] && ! command -v jq >/dev/null 2>&1; then
    echo "error: 'jq' is required with --push to extract image digests." >&2
    exit 1
fi

cd "${REPO_ROOT}"

PUSHED_REFS=()

# build_image <image_name> <dockerfile> <context> [target] [version]
#
# Builds one image and, on a --push run, appends its pushed digest ref to the
# global PUSHED_REFS. The runtime-* stages share api/Dockerfile and the repo
# root as context; Keycloak has its own Dockerfile, its own context, and no
# build target — hence the parameterization. `version` tags + labels the image
# and defaults to the api ${VERSION}; swiyu-issuer-web overrides it.
build_image() {
    local image_name="$1"
    local dockerfile="$2"
    local context="$3"
    local target="${4:-}"
    local version="${5:-${VERSION}}"

    # buildx pushes every -t when --push is set, so on a push run we use
    # only the ${REGISTRY}/-prefixed names. Unprefixed local-only tags
    # would otherwise resolve to docker.io/library/<name> and fail with
    # "push access denied". Dry runs (--load) keep the local-only tags
    # so the images can be used from the local docker daemon directly.
    local TAGS
    if [[ "${PUSH}" -eq 1 ]]; then
        TAGS=(
            -t "${REGISTRY}/${image_name}:swiyu-beta"
            -t "${REGISTRY}/${image_name}:${version}-swiyu-beta"
        )
    else
        TAGS=(
            -t "${image_name}:swiyu-beta"
            -t "${image_name}:${version}-swiyu-beta"
        )
    fi

    local LABELS=(
        --label "org.opencontainers.image.version=${version}"
        --label "org.opencontainers.image.revision=${GIT_REVISION}"
        --label "org.opencontainers.image.created=${BUILD_CREATED}"
    )

    # Registry cache is only used alongside --push. Without --push there's no
    # cache to import from (nothing was ever pushed) and trying logs a noisy
    # buildx ERROR. Local buildkit cache handles repeat dry runs.
    local CACHE_ARGS=()
    if [[ "${PUSH}" -eq 1 ]]; then
        CACHE_ARGS+=(
            --cache-from "type=registry,ref=${REGISTRY}/${image_name}:buildcache"
            --cache-to "type=registry,ref=${REGISTRY}/${image_name}:buildcache,mode=max"
        )
    fi

    local metadata_file=""
    local EXTRA_ARGS=()
    if [[ "${PUSH}" -eq 1 ]]; then
        metadata_file="$(mktemp)"
        EXTRA_ARGS+=(--push --metadata-file "${metadata_file}")
    else
        EXTRA_ARGS+=(--load)
    fi

    local TARGET_ARGS=()
    if [[ -n "${target}" ]]; then
        TARGET_ARGS+=(--target "${target}")
    fi

    echo "==> Building ${image_name} (${target:+target ${target}, }platforms ${PLATFORMS})"
    docker buildx build \
        -f "${dockerfile}" \
        "${TARGET_ARGS[@]+"${TARGET_ARGS[@]}"}" \
        --platform "${PLATFORMS}" \
        "${TAGS[@]}" \
        "${LABELS[@]}" \
        "${CACHE_ARGS[@]+"${CACHE_ARGS[@]}"}" \
        "${EXTRA_ARGS[@]}" \
        "${DOCKER_ARGS[@]+"${DOCKER_ARGS[@]}"}" \
        "${context}"

    if [[ "${PUSH}" -eq 1 ]]; then
        local digest
        digest="$(jq -r '."containerimage.digest"' "${metadata_file}")"
        rm -f "${metadata_file}"
        PUSHED_REFS+=("${REGISTRY}/${image_name}@${digest}")
    fi
}

# The Rust runtime images, all built from api/Dockerfile with the repo root as
# context.
for stage in mgmtapi oidcapi cli; do
    build_image "swiyu-issuer-${stage}" "api/Dockerfile" "." "runtime-${stage}"
done

# Keycloak: stock Keycloak with the swiyu-issuer realm baked in. Its own
# Dockerfile and context at the repo root (the realm COPY is relative to
# keycloak/), and no build target. The explorer stack pulls this as
# ${REGISTRY}/swiyu-issuer-keycloak.
build_image "swiyu-issuer-keycloak" "keycloak/Dockerfile" "keycloak"

# The web front end (SPA + BFF), built from web/Dockerfile with the repo root as
# context (the cargo workspace and the SPA both live under the root). No build
# target, and the shared workspace ${VERSION}. The explorer stack pulls this as
# ${REGISTRY}/swiyu-issuer-web.
build_image "swiyu-issuer-web" "web/Dockerfile" "."

if [[ "${PUSH}" -eq 1 ]]; then
    echo
    echo "Pushed images:"
    for ref in "${PUSHED_REFS[@]}"; do
        echo "  ${ref}"
    done
fi
