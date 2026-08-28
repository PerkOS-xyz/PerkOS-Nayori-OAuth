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
  async issueToken() { return { access_token: "signed", token_type: "Bearer", expires_in: 300, scope: "mcp:invoke" }; }
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
      agent_auth: { register_uri: "https://oauth.nayori.ai/v1/partners/register" } });
    expect(await resource.json()).toEqual(expect.objectContaining({ resource: "https://nayori.ai",
      authorization_servers: ["https://oauth.nayori.ai"] }));
    expect(authGuide.headers.get("content-type")).toContain("text/markdown");
    expect(await authGuide.text()).toMatch(/^# Auth\.md — Nayori agent authentication/);
  });

  it("does not advertise or route registration while the fail-closed flag is off", async () => {
    const config = await testConfig({ PARTNER_REGISTRATION_ENABLED: "false" });
    const app = createApp({ config, store: new MemoryStore(), oauth, logger });
    expect(await (await app.request("/.well-known/oauth-authorization-server")).json()).not.toHaveProperty("agent_auth");
    expect((await app.request("/v1/partners/challenges", { method: "POST" })).status).toBe(404);
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

  it("allows configured browser origins and rejects unconfigured preflight origins", async () => {
    const config = await testConfig({ CORS_ALLOWED_ORIGINS: "https://nayori.ai" });
    const app = createApp({ config, store: new MemoryStore(), oauth, logger });
    const allowed = await app.request("/supported", { headers: { origin: "https://nayori.ai" } });
    const denied = await app.request("/oauth/token", { method: "OPTIONS", headers: { origin: "https://evil.example" } });
    expect(allowed.headers.get("access-control-allow-origin")).toBe("https://nayori.ai");
    expect(denied.status).toBe(403);
  });
});
