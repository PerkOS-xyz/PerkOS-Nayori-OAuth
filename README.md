# PerkOS Nayori OAuth

Private OAuth authorization service for [Nayori](https://nayori.ai), built by PerkOS.

## Security identities

| Role | Origin |
|---|---|
| Canonical protected resource and JWT audience | `https://nayori.ai` |
| OAuth authorization-server issuer | `https://oauth.nayori.ai` |
| API, MCP and x402 resource server | `https://api.nayori.ai` |

This service owns anonymous agent registrations, wallet claims, invitations and OAuth-client state
in a dedicated PostgreSQL database. It issues short-lived EdDSA assertions and access tokens. It
never receives a wallet private key and an OAuth token cannot sign, approve or sponsor a Stacks
transaction.

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
| `POST /agent/identity` | Anonymous agent registration and short-lived identity assertion |
| `POST /agent/identity/claim` | Validate a claim token plus separate user code and return SIP-018 data |
| `POST /agent/identity/claim/complete` | Atomically bind a Leather signature and Stacks wallet |
| `GET /v1/agent-registrations/self` | Read the current `agent:self` registration |
| `POST /v1/partners/challenges` | Invitation-bound Stacks wallet challenge |
| `POST /v1/partners/register` | Atomic challenge consumption and one-time credentials |

Anonymous routes and `agent_auth` metadata are absent while `AGENT_REGISTRATION_ENABLED=false`.
Invite-only merchant routes are independently absent while `PARTNER_REGISTRATION_ENABLED=false`.

## Anonymous agent boundary

`POST /agent/identity` requires no invitation and returns an assertion, opaque claim token, separate
user code and claim link. The link carries the token in its URL fragment so it is not sent in the
initial HTTP request. The owner signs a SIP-018 structured message in Leather; the service derives
the Stacks address from the public key and consumes the claim atomically.

Both unclaimed and claimed agents receive exactly `agent:self`. The claim adds accountable wallet
ownership only. It cannot create a merchant, request commerce scopes, settle a payment, invoke the
partner MCP surface or act as a partner invitation. Claim and assertion grants have no refresh
tokens and expire according to `.env`.

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

See [the approved separation design](docs/plans/2026-08-27-nayori-oauth-separation-design.md) and
[the anonymous claim design](docs/plans/2026-08-28-anonymous-wallet-claim-design.md).
