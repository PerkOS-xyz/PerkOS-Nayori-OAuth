import { createHash } from "node:crypto";
import { SignJWT, importJWK } from "jose";
import { describe, expect, it, vi } from "vitest";
import { createApp } from "../src/app.js";
import { createEvidenceIdentityCheck } from "../src/evidence-identity.js";
import { createOAuthService, createOAuthSigner } from "../src/oauth.js";
import { MemoryStore, testConfig } from "./helpers.js";

const now = 1_800_000_000_000;
const wallet = "ST16EWRC01S1SFWGBP63MW47VY8P3AYFA8VGEBGE5";
async function fixture(enabled = true) {
  const config = await testConfig({ PRIVATE_EVIDENCE_IDENTITY_ENABLED: String(enabled) });
  const signer = await createOAuthSigner(config), store = new MemoryStore();
  const secret = `ny_cs_${"A".repeat(43)}`;
  store.client = { clientId: `ny_oc_${"B".repeat(24)}`, merchantId: "fixture-merchant", walletAddress: wallet,
    scopes: ["evidence:read", "evidence:write"], secretDigest: createHash("sha256").update(secret).digest("hex") };
  const service = createOAuthService({ config, store, signer, now: () => now });
  const basic = `Basic ${Buffer.from(`${store.client.clientId}:${secret}`).toString("base64")}`;
  const token = await signer.sign({ client: store.client, scopes: ["evidence:read", "evidence:write"], issuedAt: now / 1000, expiresAt: now / 1000 + 120 });
  const logger = { info: vi.fn(), error: vi.fn() };
  const app = createApp({ config, store, oauth: service, logger, now: () => now });
  const check = createEvidenceIdentityCheck({ config, store, publicJwks: signer.publicJwks, now: () => now });
  const headers = { authorization: `Bearer ${token}`, "x-nayori-evidence-scope": "evidence:read" };
  return { config, signer, store, service, basic, token, app, check, logger, headers };
}
describe("private evidence identity and explicit grants", () => {
  it("issues only an explicitly granted scope and checks current identity", async () => {
    const f = await fixture();
    const response = await f.service.issueToken(f.basic, new URLSearchParams({ grant_type: "client_credentials", scope: "evidence:read" }));
    expect(await f.check(`Bearer ${response.access_token}`, "evidence:read")).toMatchObject({ active: true, walletAddress: wallet, merchantId: "fixture-merchant", scope: "evidence:read" });
    await expect(f.check(`Bearer ${response.access_token}`, "evidence:write")).rejects.toThrow();
    f.store.client = { ...f.store.client!, scopes: ["mcp:invoke"] };
    await expect(f.service.issueToken(f.basic, new URLSearchParams({ grant_type: "client_credentials", scope: "evidence:read" }))).rejects.toMatchObject({ code: "invalid_scope" });
  });
  it("does not emit, advertise, or route evidence capability while disabled", async () => {
    const f = await fixture(false);
    await expect(f.service.issueToken(f.basic, new URLSearchParams({ grant_type: "client_credentials", scope: "evidence:read" }))).rejects.toMatchObject({ code: "invalid_scope" });
    expect((await f.app.request("/oauth/evidence/identity", { method: "POST", headers: f.headers })).status).toBe(404);
    expect((await (await f.app.request("/.well-known/oauth-authorization-server")).json() as { scopes_supported: string[] }).scopes_supported).not.toContain("evidence:read");
    await expect(f.check(f.headers.authorization, "evidence:read")).rejects.toThrow();
  });
  it.each(["revoked", "wallet", "tenant", "scope", "unavailable"])("denies current identity change: %s", async change => {
    const f = await fixture();
    expect((await f.check(f.headers.authorization, "evidence:read")).active).toBe(true);
    if (change === "revoked") f.store.client = null;
    if (change === "wallet") f.store.client = { ...f.store.client!, walletAddress: "STBTXHXFXFGMNPXST7A6XQ1WNGC0V6TB6CDDQZB4" };
    if (change === "tenant") f.store.client = { ...f.store.client!, merchantId: "other" };
    if (change === "scope") f.store.client = { ...f.store.client!, scopes: ["evidence:write"] };
    if (change === "unavailable") f.store.findActiveOAuthClient = async () => { throw Error("PRIVATE SQL DATA"); };
    await expect(f.check(f.headers.authorization, "evidence:read")).rejects.toThrow("evidence_identity_denied");
  });
  it.each([
    { iss: "https://wrong.example" }, { aud: "https://wrong.example" }, { exp: now / 1000 - 1 },
    { exp: now / 1000 + 901 }, { iat: now / 1000 + 10 }, { iat: undefined },
    { scope: "agent:self" }, { scope: "evidence:read evidence:read" }, { client_id: "another" },
    { wallet_address: "SP000000000000000000002Q6VF78" }, { sub: undefined },
  ])("rejects invalid claims %# before SQL", async override => {
    const f = await fixture();
    const payload: Record<string, unknown> = { iss: f.config.issuerOrigin, aud: f.config.resourceOrigin, sub: "fixture-merchant",
      client_id: f.store.client!.clientId, wallet_address: wallet, scope: "evidence:read", iat: now / 1000, exp: now / 1000 + 120, ...override };
    for (const name of Object.keys(payload)) if (payload[name] === undefined) delete payload[name];
    const key = JSON.parse(f.config.oauthSigningPrivateJwkJson);
    const token = await new SignJWT(payload).setProtectedHeader({ alg: "EdDSA", typ: "at+jwt", kid: key.kid }).sign(await importJWK(key, "EdDSA"));
    const lookup = vi.spyOn(f.store, "findActiveOAuthClient");
    await expect(f.check(`Bearer ${token}`, "evidence:read")).rejects.toThrow();
    expect(lookup).not.toHaveBeenCalled();
  });
  it("returns a minimal no-store identity without logging token or key", async () => {
    const f = await fixture();
    const response = await f.app.request("/oauth/evidence/identity", { method: "POST", headers: f.headers });
    expect(response.status).toBe(200); expect(response.headers.get("cache-control")).toBe("no-store");
    expect(Object.keys(await response.json() as object).sort()).toEqual(["active", "clientId", "expiresAt", "merchantId", "scope", "walletAddress"]);
    expect(JSON.stringify(f.logger.info.mock.calls)).not.toContain(f.token);
    expect(JSON.stringify(f.logger.info.mock.calls)).not.toContain(f.store.client!.secretDigest);
  });
  it.each(["query", "body", "missing-token", "api-key", "wrong-scope", "oversized-header"])("rejects unsafe HTTP request %s", async change => {
    const f = await fixture();
    const headers = { ...f.headers };
    if (change === "missing-token") headers.authorization = "";
    if (change === "api-key") headers.authorization = "Bearer ny_mk_" + "a".repeat(43);
    if (change === "wrong-scope") headers["x-nayori-evidence-scope"] = "agent:self";
    if (change === "oversized-header") headers.authorization = "Bearer " + "a".repeat(8192);
    const response = await f.app.request("/oauth/evidence/identity" + (change === "query" ? "?token=fixture" : ""), {
      method: "POST", headers, ...(change === "body" ? { body: "fixture" } : {}),
    });
    expect(response.status).toBe(401); expect(await response.json()).toEqual({ error: "evidence_identity_denied" });
  });
  it("applies rate limits before cryptographic or database checks", async () => {
    const f = await fixture(); const lookup = vi.spyOn(f.store, "findActiveOAuthClient");
    const app = createApp({ config: f.config, store: f.store, oauth: f.service, logger: f.logger,
      tokenLimiter: { consume: () => false } });
    expect((await app.request("/oauth/evidence/identity", { method: "POST", headers: f.headers })).status).toBe(429);
    expect(lookup).not.toHaveBeenCalled();
  });
});
