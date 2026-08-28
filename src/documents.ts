import type { AppConfig } from "./config.js";
import { agentScopes, oauthScopes } from "./store.js";

export const SERVICE_NAME = "nayori-oauth";
export const SERVICE_VERSION = "0.1.0";

export function createSupportedDocument(config: AppConfig) {
  return {
    service: SERVICE_NAME,
    version: SERVICE_VERSION,
    release: config.releaseSha,
    issuer: config.issuerOrigin,
    resource: config.resourceOrigin,
    api: config.apiOrigin,
    partnerRegistrationEnabled: config.partnerRegistrationEnabled,
    agentRegistrationEnabled: config.agentRegistrationEnabled,
    stacksNetwork: config.stacksNetwork,
    grantTypes: ["client_credentials", ...(config.agentRegistrationEnabled ? [
      "urn:ietf:params:oauth:grant-type:jwt-bearer",
      "urn:workos:agent-auth:grant-type:claim"
    ] : [])],
    tokenEndpointAuthMethods: ["client_secret_basic", ...(config.agentRegistrationEnabled ? ["none"] : [])],
    scopes: [...oauthScopes, ...(config.agentRegistrationEnabled ? agentScopes : [])],
    custody: "OAuth never requests a private key and cannot sign a Stacks payment."
  } as const;
}

export function createAuthorizationServerMetadata(config: AppConfig) {
  const agentGrantTypes = ["urn:ietf:params:oauth:grant-type:jwt-bearer",
    "urn:workos:agent-auth:grant-type:claim"] as const;
  return {
    issuer: config.issuerOrigin,
    token_endpoint: `${config.issuerOrigin}/oauth/token`,
    jwks_uri: `${config.issuerOrigin}/oauth/jwks.json`,
    grant_types_supported: ["client_credentials", ...(config.agentRegistrationEnabled ? agentGrantTypes : [])],
    response_types_supported: [],
    token_endpoint_auth_methods_supported: ["client_secret_basic", ...(config.agentRegistrationEnabled ? ["none"] : [])],
    scopes_supported: [...oauthScopes, ...(config.agentRegistrationEnabled ? agentScopes : [])],
    service_documentation: `${config.resourceOrigin}/auth.md`,
    ...(config.agentRegistrationEnabled ? {
      agent_auth: {
        skill: `${config.resourceOrigin}/auth.md`,
        register_uri: `${config.issuerOrigin}/agent/identity`,
        identity_endpoint: `${config.issuerOrigin}/agent/identity`,
        claim_uri: `${config.issuerOrigin}/agent/identity/claim`,
        claim_endpoint: `${config.issuerOrigin}/agent/identity/claim`,
        identity_types_supported: ["anonymous"],
        anonymous: {
          credential_types_supported: ["urn:ietf:params:oauth:token-type:jwt"],
          grant_types_supported: agentGrantTypes
        },
        token_endpoint: `${config.issuerOrigin}/oauth/token`,
        documentation: `${config.resourceOrigin}/auth.md`
      }
    } : {})
  } as const;
}

export function createProtectedResourceMetadata(config: AppConfig) {
  return {
    resource: config.resourceOrigin,
    authorization_servers: [config.issuerOrigin],
    scopes_supported: [...oauthScopes, ...(config.agentRegistrationEnabled ? agentScopes : [])],
    bearer_methods_supported: ["header"],
    resource_documentation: `${config.resourceOrigin}/auth.md`
  } as const;
}

export function createAuthMarkdown(config: AppConfig): string {
  return `# Auth.md — Nayori agent authentication

Nayori supports anonymous agent registration with optional ownership claims and invite-only partner
OAuth. An agent receives only \`agent:self\`; claiming it with Leather adds accountable wallet
ownership but never grants quote, payment, settlement, MCP or merchant access. Nayori never
requests or stores a wallet private key.

## Discovery

- Protected resource: ${config.resourceOrigin}/.well-known/oauth-protected-resource
- Authorization server: ${config.issuerOrigin}/.well-known/oauth-authorization-server
- Token endpoint: ${config.issuerOrigin}/oauth/token
- OAuth JWKS: ${config.issuerOrigin}/oauth/jwks.json
- API and MCP resource server: ${config.apiOrigin}

## Pick a method

- Anonymous agent: POST \`{"type":"anonymous","label":"optional"}\` to
  ${config.issuerOrigin}/agent/identity. No invitation or wallet is required.
- Invited commerce partner: use the separately issued partner invitation. This remains operator
  controlled and uses \`client_credentials\`.

## Register an anonymous agent

The response contains \`registration_id\`, a short-lived \`identity_assertion\`, an opaque
\`claim_token\`, \`user_code\`, \`claim_url\`, expiry and polling interval. Store the claim token as
a secret. Exchange the assertion at the token endpoint using grant type
\`urn:ietf:params:oauth:grant-type:jwt-bearer\` and form field \`assertion\`.

The resulting bearer token has exactly \`agent:self\`. Use it at
${config.issuerOrigin}/v1/agent-registrations/self. It cannot call merchant commerce APIs.

## Claim with a Stacks wallet

1. Give the human the \`claim_url\` and display the separate \`user_code\`.
2. The page sends the token and code to ${config.issuerOrigin}/agent/identity/claim to obtain the
   exact SIP-018 payload.
3. Leather signs the structured \`Nayori Agent Claim\` domain on Stacks ${config.stacksNetwork}.
4. The page submits the signature to ${config.issuerOrigin}/agent/identity/claim/complete.
5. Poll the token endpoint no faster than the returned interval with grant type
   \`urn:workos:agent-auth:grant-type:claim\` and form field \`claim_token\`.

The token endpoint returns \`authorization_pending\`, \`slow_down\` or \`expired_token\` until the
claim is usable. A successful claim still has only \`agent:self\`.

## Invited partner registration

Registration is invite-only. An operator supplies a one-time invitation through a private channel.

1. POST the invitation token and Stacks address to ${config.issuerOrigin}/v1/partners/challenges.
2. Sign the returned message verbatim with the same wallet.
3. POST challengeId, recoverable signature and compressed public key to
   ${config.issuerOrigin}/v1/partners/register.
4. Store the returned client secret once. Nayori stores only its SHA-256 digest.
5. Exchange client credentials at the token endpoint using client_secret_basic and the minimum
   required scope.

Partner registration is a different trust path. Anonymous registrations and their assertions are
never accepted as partner invitations or OAuth client credentials.

## Expiry and revocation

Identity assertions, access tokens and claim ceremonies expire. There is no refresh token and no
public revocation endpoint in this release. If an unclaimed ceremony expires, register again. Nayori
can disable a compromised registration server-side; subsequent self lookups then fail.

## Authorization boundary

OAuth authorizes API and MCP calls. It cannot sign, sponsor or approve an STX, sBTC or USDCx
payment. Each payment remains a separate transaction reviewed and signed by the payer's wallet.

Tokens have audience ${config.resourceOrigin}, use EdDSA and expire in no more than 15 minutes.
Automatic agent scope: ${agentScopes.join(", ")}. Invite-only partner scopes:
${oauthScopes.join(", ")}.
`;
}
