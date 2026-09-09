# Private evidence identity boundary

This is an opt-in identity check, not an upload service or a generic RFC 7662 introspection endpoint.
`PRIVATE_EVIDENCE_IDENTITY_ENABLED=false` is the default. No deployment/configuration is implied.

When enabled, an operator can explicitly grant `evidence:read` and/or `evidence:write` in a wallet-linked
partner invitation. Existing clients/invitations and `agent:self` claims are not upgraded. Token
issuance still requires the registered client secret and grants no scope beyond the stored client.
Disabling the flag stops evidence token issuance and removes the identity route/discovery scopes.
An existing client holding other scopes can continue requesting those scopes explicitly.

## Protocol for the resource server

POST `/oauth/evidence/identity` with:

- `Authorization: Bearer <access token>`
- `X-Nayori-Evidence-Scope: evidence:read` (or `evidence:write`)
- No request body or query parameters. Never put tokens in URLs, prompts or logs.

The issuer verifies its configured EdDSA keys, issuer, canonical resource audience, `at+jwt` type,
required claims, expiration/issued-at (maximum 15 minutes), wallet network and explicit scope.
It then reads the current active OAuth client from PostgreSQL and requires matching client ID,
wallet, merchant and all token scopes. Disabled clients, changed bindings or removed grants fail
closed even while the old JWT signature and expiry are still valid. Database failure denies access.
This is client/grant revocation, not an individual-JTI revocation list or a new admin revocation API.

Success returns only `{active, clientId, walletAddress, merchantId, scope, expiresAt}` (`expiresAt`
is Unix seconds). The response is `Cache-Control: no-store`. Failures return a generic 401; rate
limits return 429. GET/disabled routes are not available. Request body/token/secret values are not logged.

Platform must independently validate the JWT, compare the returned identity, check its own active
merchant, and authorize the current on-chain job before reading/writing/decrypting any evidence.
This endpoint is never a substitute for per-job authorization. A bearer token is still a bearer
capability: safeguard it; wallet binding is not proof-of-possession on every HTTP call.

Use the configured issuer only, HTTPS, no redirects/cookies/authorization cache, bounded responses
and timeouts. Do not implement cross-database access or distribute the issuer's signing key.
Issuer and resource-server checks cannot eliminate a change occurring after the check; revalidate
on each access and immediately before returning sensitive content.

## Remaining gates

Private upload routes, SDK/MCP client credentials, evaluator reads and private output handling,
retention/deletion/backup/key lifecycle and full private evidence E2E remain separate work.
The external developer's LLM and wallet signer remain under their control; none are requested here.
