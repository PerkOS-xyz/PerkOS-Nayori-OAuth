import { exportJWK, generateKeyPair } from "jose";
import { describe, expect, it } from "vitest";
import { loadConfig } from "../src/config.js";

async function key() {
  const { privateKey } = await generateKeyPair("EdDSA", { crv: "Ed25519", extractable: true });
  return JSON.stringify({ ...(await exportJWK(privateKey)), kid: "test" });
}

describe("configuration gates", () => {
  it("requires separate service identities", async () => {
    const signingKey = await key();
    expect(() => loadConfig({ DATABASE_URL: "postgresql://test:test@localhost/test",
      ISSUER_ORIGIN: "https://api.nayori.ai", RESOURCE_ORIGIN: "https://nayori.ai",
      API_ORIGIN: "https://api.nayori.ai", OAUTH_SIGNING_PRIVATE_JWK_JSON: signingKey })).toThrow(/separate/);
  });

  it("requires HTTPS for every production origin", async () => {
    const signingKey = await key();
    expect(() => loadConfig({ NODE_ENV: "production", DATABASE_URL: "postgresql://test:test@localhost/test",
      ISSUER_ORIGIN: "http://oauth.nayori.ai", RESOURCE_ORIGIN: "https://nayori.ai",
      API_ORIGIN: "https://api.nayori.ai", OAUTH_SIGNING_PRIVATE_JWK_JSON: signingKey })).toThrow(/HTTPS/);
  });

  it("requires signing material", () => {
    expect(() => loadConfig({ DATABASE_URL: "postgresql://test:test@localhost/test" })).toThrow();
  });
});
