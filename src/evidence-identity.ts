import { validateStacksAddress } from "@stacks/transactions";
import { createLocalJWKSet, jwtVerify, type JWK } from "jose";
import type { AppConfig } from "./config.js";
import type { OAuthStore } from "./store.js";

export type EvidenceScope = "evidence:read" | "evidence:write";
export class EvidenceIdentityDenied extends Error {
  constructor() { super("evidence_identity_denied"); }
}
function requireValid(value: unknown): asserts value { if (!value) throw new EvidenceIdentityDenied(); }

/** Self-only identity check, not general token introspection or job authorization. */
export function createEvidenceIdentityCheck(options: {
  config: AppConfig; store: Pick<OAuthStore, "findActiveOAuthClient">;
  publicJwks: { readonly keys: readonly JWK[] }; now?: () => number;
}) {
  const { config, store } = options;
  const keys = createLocalJWKSet({ keys: [...options.publicJwks.keys] });
  const now = options.now ?? Date.now;
  return async (authorization: string | undefined, scope: string | undefined) => {
    try {
      requireValid(config.privateEvidenceIdentityEnabled);
      requireValid(scope === "evidence:read" || scope === "evidence:write");
      requireValid(typeof authorization === "string" && authorization.startsWith("Bearer ") && authorization.length <= 8192);
      const token = authorization.slice(7);
      requireValid(token.split(".").length === 3);
      const { payload: p, protectedHeader: h } = await jwtVerify(token, keys, {
        algorithms: ["EdDSA"], issuer: config.issuerOrigin, audience: config.resourceOrigin,
        requiredClaims: ["exp", "iat", "sub", "client_id", "wallet_address", "scope"],
        maxTokenAge: "15 minutes", currentDate: new Date(now()),
      });
      requireValid(h.typ === "at+jwt" && !h.jku && !h.jwk);
      requireValid(typeof p.exp === "number" && typeof p.iat === "number" && p.exp > p.iat && p.exp - p.iat <= 900);
      requireValid(typeof p.client_id === "string" && /^ny_oc_[A-Za-z0-9_-]{24}$/.test(p.client_id));
      requireValid(typeof p.sub === "string" && /^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$/.test(p.sub));
      requireValid(typeof p.wallet_address === "string" && validateStacksAddress(p.wallet_address) &&
        (config.stacksNetwork === "testnet" ? /^(ST|SN)/ : /^(SP|SM)/).test(p.wallet_address));
      requireValid(typeof p.scope === "string");
      const scopes = p.scope.split(" ");
      requireValid(scopes.every(Boolean) && new Set(scopes).size === scopes.length && scopes.includes(scope));
      // Never cache: current client status, wallet, tenant and grants are authoritative.
      const client = await store.findActiveOAuthClient(p.client_id);
      requireValid(client && client.clientId === p.client_id && client.walletAddress === p.wallet_address &&
        client.merchantId === p.sub && scopes.every(item => client.scopes.some(grant => grant === item)));
      requireValid(p.exp > Math.floor(now() / 1000));
      return { active: true as const, clientId: client.clientId, walletAddress: client.walletAddress,
        merchantId: client.merchantId, scope: scope as EvidenceScope, expiresAt: p.exp };
    } catch { throw new EvidenceIdentityDenied(); }
  };
}
