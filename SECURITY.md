# Security policy

Report suspected vulnerabilities privately to the PerkOS maintainers. Do not open a public issue
containing credentials, invitation tokens, client secrets, access tokens, wallet signatures or
production topology details.

## Invariants

- The OAuth Ed25519 private JWK exists only in the VPS secret configuration.
- Public JWKS documents never contain the private `d` member.
- Invitation and wallet challenges are single-use, expiring and consumed atomically.
- Client secrets are returned once and persisted only as SHA-256 digests.
- Tokens have issuer `https://oauth.nayori.ai`, audience `https://nayori.ai`, short expiry and
  minimum scopes.
- OAuth authorizes resource access but cannot authorize a Stacks payment transaction.
- Partner registration is disabled by default and production routes remain behind edge rate limits.
- No production secret, database dump or operational Compose file belongs in this repository.
