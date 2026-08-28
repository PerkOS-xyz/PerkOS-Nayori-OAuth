# Nayori anonymous agent and wallet-claim design

Date: 2026-08-28
Status: approved by Julio

## Outcome

Nayori lets a software agent create an anonymous OAuth identity without an invitation or wallet.
The registration can later be claimed by a human-controlled Stacks wallet through a SIP-018
structured signature in Leather. The authorization boundary is intentionally unchanged by the
claim: before and after it, the only automatic scope is `agent:self`.

Commerce scopes, merchant provisioning, API settlement and MCP access remain on the existing
invite-only partner path. An anonymous assertion, claim token or agent access token is never a
partner invitation or client credential.

## Protocol

1. The agent posts identity type `anonymous` and an optional label to `/agent/identity`.
2. OAuth persists digests of an opaque claim token and separate user code, then returns a
   short-lived EdDSA identity assertion, claim link, expiry and polling interval.
3. The agent can exchange the assertion with the JWT bearer grant for an `agent:self` token and use
   `/v1/agent-registrations/self`.
4. A human opens the claim link. Its secret is carried in the URL fragment and removed from the
   visible URL before the browser calls OAuth. The human enters the separate code supplied by the
   agent.
5. OAuth constructs the canonical SIP-018 domain and message. Leather signs domain name, version,
   Stacks chain ID, issuer origin, registration ID, challenge ID, code and expiry.
6. OAuth derives the Stacks address from the returned public key, verifies the signature and
   atomically binds the first valid wallet. Expired, mismatched and replayed claims fail.
7. The agent polls with the claim grant. Pending, excessive and expired polls return standard
   errors; a completed claim returns an `agent:self` token and refreshed identity assertion.

## Security and operations

Registration is fail-closed behind `AGENT_REGISTRATION_ENABLED`. PostgreSQL owns replay state and
the migration runner checksums schema changes. Assertions and access tokens are short-lived; there
are no refresh tokens or public revocation endpoint. Server-side revocation is checked again by the
self endpoint. Rate limits apply to registration, claim preparation, completion and token exchange.

The design does not change Clarity contracts, custody rules, mainnet facilitator gates or the
security-review requirement. VPS signing keys and runtime configuration remain outside GitHub.
