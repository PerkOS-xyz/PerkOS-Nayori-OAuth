import { describe, expect, it } from "vitest";
import { createApp } from "../src/app.js";
import type { AppLogger } from "../src/logger.js";
import type { OAuthService } from "../src/oauth.js";
import type { RateLimiter } from "../src/rate-limit.js";
import { MemoryStore, testConfig } from "./helpers.js";

const logger: AppLogger = { info() {}, error() {} };
const oauth: OAuthService = {
  publicJwks: { keys: [] },
  async issueChallenge() { return { challengeId: `nc_${"a".repeat(32)}`, message: "sign me",
    expiresAt: new Date(2_000_000_000_000).toISOString(), walletAddress: "ST000000000000000000002AMW42H",
    network: "testnet" }; },
  async register() { return { clientId: `ny_oc_${"A".repeat(24)}`, clientSecret: `ny_cs_${"A".repeat(43)}`,
    tokenEndpoint: "https://oauth.nayori.ai/oauth/token", scopes: ["mcp:invoke"],
    walletAddress: "ST000000000000000000002AMW42H" }; },
  async issueToken() { return { access_token: "signed", token_type: "Bearer", expires_in: 300, scope: "mcp:invoke" }; },
  async createAgentIdentity() { return { registration_id: `ny_ar_${"A".repeat(24)}`,
    identity_assertion: "assertion", assertion_expires: new Date(2_000_000_000_000).toISOString(),
    pre_claim_scopes: ["agent:self"] as const, post_claim_scopes: ["agent:self"] as const,
    claim_token: `ny_ct_${"A".repeat(43)}`, claim_url: `https://nayori.ai/agents/claim#ny_ct_${"A".repeat(43)}`,
    user_code: "ABCD-EFGH", expires_at: new Date(2_000_000_000_000).toISOString(), interval: 5 }; },
  async prepareAgentClaim() { return { status: "pending" as const, claim: {
    registrationId: `ny_ar_${"A".repeat(24)}`, challengeId: `ny_ac_${"a".repeat(32)}`,
    userCode: "ABCD-EFGH", expiresAt: new Date(2_000_000_000_000).toISOString(), network: "testnet" as const,
    domain: { name: "Nayori Agent Claim" as const, version: "1" as const, chainId: 2_147_483_648 },
    message: { action: "claim-agent" as const, origin: "https://oauth.nayori.ai",
      registrationId: `ny_ar_${"A".repeat(24)}`, challengeId: `ny_ac_${"a".repeat(32)}`,
      userCode: "ABCD-EFGH", expiresAt: 2_000_000_000 } } }; },
  async completeAgentClaim() { return { status: "claimed" as const,
    registration_id: `ny_ar_${"A".repeat(24)}`, wallet_address: "ST000000000000000000002AMW42H",
    scopes: ["agent:self"] as const }; },
  async getAgentSelf() { return { registration_id: `ny_ar_${"A".repeat(24)}`, label: null,
    claimed: false, wallet_address: null, scopes: ["agent:self"] as const }; }
};

describe("OAuth HTTP contract", () => {
  it("publishes distinct issuer and protected-resource identities with truthful registration", async () => {
    const config = await testConfig();
    const app = createApp({ config, store: new MemoryStore(), oauth, logger });
    const authorization = await app.request("/.well-known/oauth-authorization-server");
    const resource = await app.request("/.well-known/oauth-protected-resource");
    const authGuide = await app.request("/auth.md");
    expect(await authorization.json()).toMatchObject({ issuer: "https://oauth.nayori.ai",
      token_endpoint: "https://oauth.nayori.ai/oauth/token",
      agent_auth: { register_uri: "https://oauth.nayori.ai/agent/identity",
        identity_types_supported: ["anonymous"] } });
    expect(await resource.json()).toEqual(expect.objectContaining({ resource: "https://nayori.ai",
      authorization_servers: ["https://oauth.nayori.ai"] }));
    expect(authGuide.headers.get("content-type")).toContain("text/markdown");
    expect(await authGuide.text()).toMatch(/^# Auth\.md — Nayori agent authentication/);
  });

  it("does not advertise or route registration while the fail-closed flag is off", async () => {
    const config = await testConfig({ PARTNER_REGISTRATION_ENABLED: "false", AGENT_REGISTRATION_ENABLED: "false" });
    const app = createApp({ config, store: new MemoryStore(), oauth, logger });
    expect(await (await app.request("/.well-known/oauth-authorization-server")).json()).not.toHaveProperty("agent_auth");
    expect((await app.request("/v1/partners/challenges", { method: "POST" })).status).toBe(404);
    expect((await app.request("/agent/identity", { method: "POST" })).status).toBe(404);
  });

  it("routes anonymous registration, wallet claim preparation and agent self independently", async () => {
    const config = await testConfig({ PARTNER_REGISTRATION_ENABLED: "false" });
    const app = createApp({ config, store: new MemoryStore(), oauth, logger });
    const identity = await app.request("/agent/identity", { method: "POST",
      headers: { "content-type": "application/json" }, body: JSON.stringify({ type: "anonymous" }) });
    const claim = await app.request("/agent/identity/claim", { method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ claim_token: `ny_ct_${"A".repeat(43)}`, user_code: "ABCD-EFGH" }) });
    const self = await app.request("/v1/agent-registrations/self",
      { headers: { authorization: "Bearer agent-token" } });
    expect(identity.status).toBe(201);
    expect(claim.status).toBe(200);
    expect(self.status).toBe(200);
    expect((await identity.json() as { pre_claim_scopes: string[] }).pre_claim_scopes).toEqual(["agent:self"]);
  });

  it("returns readiness failure without leaking the database error and enforces rate limits", async () => {
    const config = await testConfig();
    const store = new MemoryStore();
    store.ready = false;
    const denied: RateLimiter = { consume: () => false };
    const app = createApp({ config, store, oauth, logger, tokenLimiter: denied });
    const ready = await app.request("/ready");
    const token = await app.request("/oauth/token", { method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" } });
    expect(ready.status).toBe(503);
    expect(await ready.json()).toEqual(expect.objectContaining({ status: "not_ready", database: "unavailable" }));
    expect(token.status).toBe(429);
    expect(token.headers.get("retry-after")).toBe("60");
  });

  it("keys rate limits only from the proxy-overwritten address", async () => {
    const config = await testConfig();
    const keys: string[] = [];
    const limiter: RateLimiter = { consume: (key) => { keys.push(key); return true; } };
    const app = createApp({ config, store: new MemoryStore(), oauth, logger, tokenLimiter: limiter });
    const request = (headers: Record<string, string>) => app.request("/oauth/token", {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded", ...headers },
      body: "grant_type=client_credentials",
    });

    await request({ "x-real-ip": "203.0.113.8", "cf-connecting-ip": "198.51.100.10" });
    await request({ "cf-connecting-ip": "198.51.100.11" });
    await request({ "x-real-ip": "not-an-ip", "cf-connecting-ip": "198.51.100.12" });

    expect(keys).toEqual(["203.0.113.8", "unknown", "unknown"]);
  });

  it("allows configured browser origins and rejects unconfigured preflight origins", async () => {
    const config = await testConfig({ CORS_ALLOWED_ORIGINS: "https://nayori.ai" });
    const app = createApp({ config, store: new MemoryStore(), oauth, logger });
    const allowed = await app.request("/supported", { headers: { origin: "https://nayori.ai" } });
    const denied = await app.request("/oauth/token", { method: "OPTIONS", headers: { origin: "https://evil.example" } });
    expect(allowed.headers.get("access-control-allow-origin")).toBe("https://nayori.ai");
    expect(denied.status).toBe(403);
  });
});
