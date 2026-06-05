# Keycloak image for the swiyu-issuer development stacks (the local dev stack in
# api/docker-compose.yml and the explore stack in api/deploy/explorer/): the
# stock Keycloak with the swiyu-issuer realm baked in for import on startup.
#
# Build (context = this directory):
#
#   docker build -f api/deploy/keycloak/Dockerfile -t swiyu-issuer-keycloak:dev \
#       api/deploy/keycloak
#
# The container runs in dev mode (`start-dev`), which uses the embedded H2
# store and serves plain HTTP — fine for development, not for production. The realm
# is re-imported on each start, so the stack stays reproducible. Health and
# metrics are enabled so compose can wait on `/health/ready` (management port
# 9000).
#
# Standard token exchange (v2) is on by default in Keycloak >= 26.2, so no
# build feature is needed here; the per-client switch is flipped when that
# flow is implemented.
FROM quay.io/keycloak/keycloak:26.6.3

ENV KC_HEALTH_ENABLED=true
ENV KC_METRICS_ENABLED=true

# Imported on startup via `--import-realm`.
COPY realm/swiyu-issuer-realm.json /opt/keycloak/data/import/swiyu-issuer-realm.json

LABEL org.opencontainers.image.title="swiyu-issuer-keycloak" \
      org.opencontainers.image.description="SWIYU issuer — Keycloak authorization server (development)" \
      org.opencontainers.image.source="https://github.com/Gubaer/swiyu-issuer" \
      org.opencontainers.image.url="https://github.com/Gubaer/swiyu-issuer" \
      org.opencontainers.image.documentation="https://github.com/Gubaer/swiyu-issuer/tree/master/api/deploy/keycloak" \
      org.opencontainers.image.vendor="Gubaer" \
      org.opencontainers.image.licenses="MIT"

ENTRYPOINT ["/opt/keycloak/bin/kc.sh"]
CMD ["start-dev", "--import-realm"]
