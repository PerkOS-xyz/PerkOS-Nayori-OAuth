# Security policy

Report suspected vulnerabilities privately to the PerkOS maintainers. Do not open a public issue
containing credentials, invitation tokens, client secrets, access tokens, wallet signatures or
production topology details.

## Invariants

- The OAuth Ed25519 private JWK exists only in the VPS secret configuration.
- Public JWKS documents never contain the private `d` member.
- Invitation and wallet challenges are single-use, expiring and consumed atomically.
- Anonymous claim tokens and user codes are stored only as SHA-256 digests; claim links use a URL
  fragment, and SIP-018 signatures bind origin, network, registration, challenge, code and expiry.
- Anonymous and wallet-claimed identities receive only `agent:self`. They cannot mint partner
  credentials, merchant records or commerce scopes.
- Client secrets are returned once and persisted only as SHA-256 digests.
- Tokens have issuer `https://oauth.nayori.ai`, audience `https://nayori.ai`, short expiry and
  minimum scopes.
- OAuth authorizes resource access but cannot authorize a Stacks payment transaction.
- Partner and anonymous registration are independently disabled by default; production routes
  remain behind edge rate limits.
- No production secret, database dump or operational Compose file belongs in this repository.
