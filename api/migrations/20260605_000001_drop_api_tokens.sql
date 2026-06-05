-- Retire the legacy opaque API-token table.
--
-- Authentication to the management API is now exclusively via Keycloak-issued
-- JWTs, validated as a resource server. The `tok_<base58>` shared-secret path
-- and its table are removed. Dropping the table also drops its dependent
-- index (api_tokens_by_tenant). Irreversible: the token rows are discarded.
DROP TABLE IF EXISTS api_tokens;
