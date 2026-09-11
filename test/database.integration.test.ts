import { fileURLToPath } from "node:url";
import { randomBytes } from "node:crypto";
import { Pool } from "pg";
import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";
import { PostgresOAuthStore } from "../src/database.js";
import { runMigrations } from "../src/migrations.js";
import type { AgentRegistrationRecord } from "../src/store.js";
import { testConfig } from "./helpers.js";
import { createOAuthSigner } from "../src/oauth.js";
import { createEvidenceIdentityCheck } from "../src/evidence-identity.js";

const databaseUrl = process.env.TEST_DATABASE_URL;
const integration = describe.skipIf(!databaseUrl);

integration("PostgreSQL agent claim concurrency", () => {
  const pool = new Pool({ connectionString: databaseUrl });
  let store: PostgresOAuthStore;

  beforeAll(async () => {
    const config = await testConfig({ DATABASE_URL: databaseUrl });
    await runMigrations(pool, fileURLToPath(new URL("../migrations/", import.meta.url)));
    store = new PostgresOAuthStore(config);
  });

  beforeEach(async () => {
    await pool.query("TRUNCATE agent_registrations");
  });

  afterAll(async () => {
    if (store) await store.close();
    await pool.end();
  });

  it("allows exactly one wallet to win a simultaneous claim", async () => {
    const registration: AgentRegistrationRecord = {
      registrationId: `ny_ar_${"A".repeat(24)}`,
      label: "Concurrency agent",
      challengeId: `ny_ac_${"a".repeat(32)}`,
      claimExpiresAt: new Date(Date.now() + 60_000),
      claimedAt: null,
      walletAddress: null,
      publicKey: null,
      revokedAt: null,
      lastPolledAt: null,
    };
    await store.insertAgentRegistration({ ...registration,
      claimTokenDigest: "1".repeat(64), userCodeDigest: "2".repeat(64) });
    const claimedAt = new Date();
    const results = await Promise.all([
      store.claimAgentRegistration({ challengeId: registration.challengeId,
        walletAddress: "ST2CY5V39NHDPWSXMW9QDT3HC3GD6Q6XX4XFRK9AG",
        publicKey: `02${"1".repeat(64)}`, claimedAt }),
      store.claimAgentRegistration({ challengeId: registration.challengeId,
        walletAddress: "ST3AM1A56AK2C1XAFJ4115ZSV26EB49BVQ10MGCS0",
        publicKey: `03${"2".repeat(64)}`, claimedAt }),
    ]);
    expect(results.filter(Boolean)).toHaveLength(1);
    const persisted = await store.findAgentRegistration(registration.registrationId);
    expect(persisted?.claimedAt).not.toBeNull();
    expect([results[0]?.walletAddress, results[1]?.walletAddress]).toContain(persisted?.walletAddress);
  });

  it("rejects a still-signed token after PostgreSQL scope removal or client disable", async () => {
    const config = await testConfig({ PRIVATE_EVIDENCE_IDENTITY_ENABLED: "true", DATABASE_URL: databaseUrl });
    const signer = await createOAuthSigner(config);
    const client = { clientId: `ny_oc_${randomBytes(18).toString("base64url")}`, merchantId: "evidence-fixture",
      walletAddress: "ST16EWRC01S1SFWGBP63MW47VY8P3AYFA8VGEBGE5", secretDigest: "1".repeat(64), scopes: ["evidence:read" as const] };
    try {
      await pool.query("INSERT INTO oauth_clients(client_id,merchant_id,wallet_address,secret_digest,scopes) VALUES($1,$2,$3,$4,$5)",
        [client.clientId, client.merchantId, client.walletAddress, client.secretDigest, client.scopes]);
      const now = Math.floor(Date.now() / 1000);
      const token = await signer.sign({ client, scopes: client.scopes, issuedAt: now, expiresAt: now + 120 });
      const check = createEvidenceIdentityCheck({ config, store, publicJwks: signer.publicJwks });
      expect((await check(`Bearer ${token}`, "evidence:read")).active).toBe(true);
      await pool.query("UPDATE oauth_clients SET scopes=$2 WHERE client_id=$1", [client.clientId, ["mcp:invoke"]]);
      await expect(check(`Bearer ${token}`, "evidence:read")).rejects.toThrow();
      await pool.query("UPDATE oauth_clients SET scopes=$2,status='disabled' WHERE client_id=$1", [client.clientId, client.scopes]);
      await expect(check(`Bearer ${token}`, "evidence:read")).rejects.toThrow();
    } finally { await pool.query("DELETE FROM oauth_clients WHERE client_id=$1", [client.clientId]); }
  });
});
