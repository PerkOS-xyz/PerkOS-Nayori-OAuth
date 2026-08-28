# PerkOS Nayori OAuth

Private OAuth authorization service for [Nayori](https://nayori.ai), built by PerkOS.

## Security identities

| Role | Origin |
|---|---|
| Canonical protected resource and JWT audience | `https://nayori.ai` |
| OAuth authorization-server issuer | `https://oauth.nayori.ai` |
| API, MCP and x402 resource server | `https://api.nayori.ai` |

This service owns invitation, wallet challenge and OAuth-client state in a dedicated PostgreSQL
database. It issues short-lived EdDSA access tokens. It never receives a wallet private key and an
OAuth token cannot sign, approve or sponsor a Stacks transaction.

## Implemented endpoints

| Endpoint | Purpose |
|---|---|
| `GET /health` | Process liveness |
| `GET /ready` | PostgreSQL readiness |
| `GET /supported` | Machine-readable service boundary |
| `GET /.well-known/oauth-authorization-server` | RFC 8414 metadata |
| `GET /.well-known/oauth-protected-resource` | Canonical RFC 9728 metadata mirror |
| `GET /oauth/jwks.json` | Public access-token verification keys |
| `GET /auth.md` | Agent-readable registration and authorization contract |
| `POST /oauth/token` | `client_credentials` with `client_secret_basic` |
| `POST /v1/partners/challenges` | Invitation-bound Stacks wallet challenge |
| `POST /v1/partners/register` | Atomic challenge consumption and one-time credentials |

Registration routes and their `agent_auth` metadata are absent while
`PARTNER_REGISTRATION_ENABLED=false`.

## Local verification

```bash
cp .env.example .env
npm install
npm run verify
npm audit --audit-level=high
```

Generate the dedicated signing key outside GitHub:

```bash
npm run oauth:keygen
```

Store only the private JWK in the VPS secret configuration. Do not reuse Nayori quote, receipt or
other PerkOS keys.

Run migrations and the service after PostgreSQL is ready:

```bash
npm run db:migrate
npm run dev
```

## Partner invitation

Confirm the merchant already exists and is active in `PerkOS-Nayori-Platform`, then set
`PARTNER_MERCHANT_ID`, `PARTNER_SCOPES` and an optional `PARTNER_INVITATION_TTL_SECONDS` before
running:

```bash
npm run partner:invite
```

The invitation is shown once. The partner signs the exact challenge text in Leather and stores the
returned client secret in its own secret manager. Only a digest is persisted.

## Production boundary

Images are built on the PerkOS VPS from an exact merged commit. Caddy, Compose, database backups,
signing material and runtime `.env` files remain outside GitHub. Deploy `oauth.nayori.ai` before
switching Platform or apex discovery to the external issuer.

See [the approved separation design](docs/plans/2026-08-27-nayori-oauth-separation-design.md).
