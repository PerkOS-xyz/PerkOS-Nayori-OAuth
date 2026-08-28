import type { AppConfig } from "./config.js";
import { oauthScopes } from "./store.js";

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
    stacksNetwork: config.stacksNetwork,
    grantTypes: ["client_credentials"],
    tokenEndpointAuthMethods: ["client_secret_basic"],
    scopes: oauthScopes,
    custody: "OAuth never requests a private key and cannot sign a Stacks payment."
  } as const;
}

export function createAuthorizationServerMetadata(config: AppConfig) {
  return {
    issuer: config.issuerOrigin,
    token_endpoint: `${config.issuerOrigin}/oauth/token`,
    jwks_uri: `${config.issuerOrigin}/oauth/jwks.json`,
    grant_types_supported: ["client_credentials"],
    response_types_supported: [],
    token_endpoint_auth_methods_supported: ["client_secret_basic"],
    scopes_supported: oauthScopes,
    service_documentation: `${config.resourceOrigin}/auth.md`,
    ...(config.partnerRegistrationEnabled ? {
      agent_auth: {
        identity_endpoint: `${config.issuerOrigin}/v1/partners/challenges`,
        register_uri: `${config.issuerOrigin}/v1/partners/register`,
        identity_types_supported: ["wallet"],
        credential_types: ["stacks-wallet-signature"],
        token_endpoint: `${config.issuerOrigin}/oauth/token`,
        grant_type: "client_credentials",
        skill: `${config.resourceOrigin}/auth.md`,
        documentation: `${config.resourceOrigin}/auth.md`
      }
    } : {})
  } as const;
}

export function createProtectedResourceMetadata(config: AppConfig) {
  return {
    resource: config.resourceOrigin,
    authorization_servers: [config.issuerOrigin],
    scopes_supported: oauthScopes,
    bearer_methods_supported: ["header"],
    resource_documentation: `${config.resourceOrigin}/auth.md`
  } as const;
}

export function createAuthMarkdown(config: AppConfig): string {
  return `# Auth.md — Nayori agent authentication

Nayori uses OAuth 2.0 client credentials for invited partners. Enrollment is bound to a Stacks
wallet by an exact plaintext message signed in Leather. Nayori never requests or stores a wallet
private key.

## Discovery

- Protected resource: ${config.resourceOrigin}/.well-known/oauth-protected-resource
- Authorization server: ${config.issuerOrigin}/.well-known/oauth-authorization-server
- Token endpoint: ${config.issuerOrigin}/oauth/token
- OAuth JWKS: ${config.issuerOrigin}/oauth/jwks.json
- API and MCP resource server: ${config.apiOrigin}

## Registration

Registration is invite-only. An operator supplies a one-time invitation through a private channel.

1. POST the invitation token and Stacks address to ${config.issuerOrigin}/v1/partners/challenges.
2. Sign the returned message verbatim with the same wallet.
3. POST challengeId, recoverable signature and compressed public key to
   ${config.issuerOrigin}/v1/partners/register.
4. Store the returned client secret once. Nayori stores only its SHA-256 digest.
5. Exchange client credentials at the token endpoint using client_secret_basic and the minimum
   required scope.

The supported identity type is wallet and the credential is a Stacks wallet signature. There is no
claim or anonymous-registration ceremony in this release.

## Authorization boundary

OAuth authorizes API and MCP calls. It cannot sign, sponsor or approve an STX, sBTC or USDCx
payment. Each payment remains a separate transaction reviewed and signed by the payer's wallet.

Tokens have audience ${config.resourceOrigin}, use EdDSA and expire in no more than 15 minutes.
Supported scopes: ${oauthScopes.join(", ")}.
`;
}
