# Nayori OAuth separation design

Date: 2026-08-27
Status: approved by Julio

## Outcome

Nayori uses three explicit security identities:

- `https://nayori.ai` is the OAuth protected-resource identifier and JWT audience.
- `https://oauth.nayori.ai` is the authorization-server issuer, token endpoint and JWKS origin.
- `https://api.nayori.ai` is the resource server for API, MCP and x402 operations.

The OAuth service owns invitation, wallet challenge and OAuth-client state in its own PostgreSQL
database. It owns an Ed25519 signing key that is not reused by Platform quote or receipt signing.
Platform verifies short-lived access tokens with the OAuth JWKS and still checks that the merchant
is active. OAuth never signs or approves a Stacks transaction.

## Enrollment and token flow

1. An operator creates a one-time invitation for an existing Platform merchant and selected scopes.
2. The invited partner requests a challenge for its Stacks address.
3. Leather signs the exact returned plaintext. The service derives the address from the public key,
   verifies the recoverable signature and atomically consumes the invitation and challenge.
4. The client secret is returned once and only its SHA-256 digest is persisted.
5. `client_credentials` with `client_secret_basic` issues a short-lived EdDSA access token with
   issuer, audience, merchant subject, client ID, wallet and minimum scopes.
6. Platform verifies signature, issuer, audience, lifetime and scopes before checking its own
   merchant state and executing an API or MCP operation.

There are no refresh tokens. Disabling a client prevents new tokens; already-issued tokens expire
within the configured 60–900 second TTL.

## Failure and rollback boundaries

The service refuses to boot without its signing key or database configuration. Partner enrollment
is disabled by default. Metadata advertises registration only when the route is enabled. Database
migrations are checksummed and serialized by an advisory lock.

Deployment order is DNS A record, TLS/reverse proxy, private database and migration, OAuth service,
Platform external-token verification, then apex discovery. The embedded Platform issuer remains a
rollback option until the external path passes preview, a clean client flow and production probes.

DNS-AID and DNSSEC are a separate operational gate. Only the existing index and MCP service are
published; no A2A record is created until Nayori implements a real A2A endpoint.

