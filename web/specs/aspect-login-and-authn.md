# Aspect login and authn

## Abbreviations

* SPA - the Single Page Application (web UI) of `swiyu-issuer-web`
* BFF - the Backend For Frontend of `swiyu-issuer-web`

## Authentication contexts

The concepts **User**, **User Identity**, and **User Account** are defined [in this spec](../../api/specs/aspect-authn.md).

A user accesses the SPA. By interacting with the SPA, they indirectly trigger API calls from the SPA to the BFF and from the BFF to `swiyu-issuer-mgmtapi`. We therefore have to distinguish three authentication contexts.

1. A user authenticates at the SPA
    Main approach:
    * Successfully authenticate the user using a federated user identity. The SPA delegates authn to an identity provider (IDP).
    * Resolve a user identity `(iss, sub)` against the user accounts linked to it, and successfully select one active user account from the available linked user accounts.
    * From the selected user account, derive the tenant on behalf of which it is working.
2. The SPA authenticates at the BFF when it calls a BFF API endpoint
    Main approach:
    * Successfully establish a session between the SPA and the BFF.
    * The SPA authns with a valid session key at the BFF.
3. The BFF authenticates at the `swiyu-issuer-mgmtapi` when it calls a management API endpoint
    1. BFF acts on behalf of itself
        * Example: BFF resolves an authenticated user identity against the linked user accounts in the `swiyu-issuer-mgmtapi`.
        * Main approach:
            * BFF mints an access token at the AS (the Keycloak instance).
            * BFF submits the access token as a bearer token in the API request.
    2. BFF acts on behalf of a specific tenant
        * Example: BFF accepts an invitation (the tenant can be derived from the invitation, but no user account is selected yet).
        * Main approach:
            * BFF mints an access token at the AS (the Keycloak instance).
            * BFF submits the access token as a bearer token in the API request and sets the header X-Tenant.
    3. BFF acts on behalf of the currently selected user account
        * Example: BFF submits an API call to create an issuer, to create a credential offering, etc.
        * Main approach:
            * BFF exchanges the access token submitted by the federated IDP for the user for an access token to access the management API.
            * BFF submits the new access token (which includes the `iss` and `sub` of the user identity) as a bearer token to the management API and sets the header X-User-Account to the currently selected account.

        


