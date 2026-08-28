import { hashMessage } from "@stacks/encryption";
import { privateKeyToPublic, publicKeyToAddressSingleSig, randomPrivateKey, signMessageHashRsv,
  signStructuredData } from "@stacks/transactions";
import { createLocalJWKSet, jwtVerify } from "jose";
import { describe, expect, it } from "vitest";
import { buildAgentClaimClarity, createInvitationRecord, createOAuthService, createOAuthSigner,
  hashPartnerInvitationToken } from "../src/oauth.js";
import type { OAuthScope } from "../src/store.js";
import { MemoryStore, testConfig } from "./helpers.js";

const NOW = 1_800_000_000_000;

async function context(scopes: OAuthScope[] = ["quotes:create", "mcp:invoke"]) {
  const config = await testConfig();
  const signer = await createOAuthSigner(config);
  const store = new MemoryStore();
  const invitation = createInvitationRecord({ merchantId: "partner-merchant", scopes,
    expiresAt: new Date(NOW + 60_000) });
  store.invitation = { ...invitation.record, tokenDigest: hashPartnerInvitationToken(invitation.token) };
  return { config, invitation, signer, store,
    service: createOAuthService({ config, store, signer, now: () => NOW }) };
}

async function registerWallet(service: Awaited<ReturnType<typeof context>>["service"], token: string) {
  const privateKey = randomPrivateKey();
  const publicKey = privateKeyToPublic(privateKey);
  const publicKeyHex = typeof publicKey === "string" ? publicKey : Buffer.from(publicKey).toString("hex");
  const walletAddress = publicKeyToAddressSingleSig(publicKey, "testnet");
  const challenge = await service.issueChallenge({ invitationToken: token, walletAddress });
  const signature = signMessageHashRsv({ messageHash: Buffer.from(hashMessage(challenge.message)).toString("hex"), privateKey });
  const client = await service.register({ challengeId: challenge.challengeId,
    signature: `0x${signature}`, publicKey: `0x${publicKeyHex}` });
  return { challenge, client, walletAddress, signature, publicKeyHex };
}

describe("wallet-linked partner OAuth", () => {
  it("consumes an invitation and issues a scoped token for the canonical resource", async () => {
    const { config, invitation, service, signer, store } = await context();
    const registration = await registerWallet(service, invitation.token);
    const basic = Buffer.from(`${registration.client.clientId}:${registration.client.clientSecret}`).toString("base64");
    const token = await service.issueToken(`Basic ${basic}`,
      new URLSearchParams({ grant_type: "client_credentials", scope: "quotes:create" }));
    const verified = await jwtVerify(token.access_token, createLocalJWKSet({ keys: [...signer.publicJwks.keys] }), {
      algorithms: ["EdDSA"], issuer: config.issuerOrigin, audience: config.resourceOrigin,
      currentDate: new Date(NOW)
    });
    expect(registration.client).toMatchObject({ walletAddress: registration.walletAddress,
      tokenEndpoint: "https://oauth.nayori.ai/oauth/token", scopes: ["quotes:create", "mcp:invoke"] });
    expect(token).toMatchObject({ token_type: "Bearer", expires_in: 120, scope: "quotes:create" });
    expect(verified.payload).toMatchObject({ sub: "partner-merchant",
      client_id: registration.client.clientId, wallet_address: registration.walletAddress,
      scope: "quotes:create", aud: "https://nayori.ai", iss: "https://oauth.nayori.ai" });
    expect(verified.protectedHeader.typ).toBe("at+jwt");
    expect(store.tokenIssuedAt?.toISOString()).toBe(new Date(NOW).toISOString());
  });

  it("rejects challenge replay and a signature from another wallet", async () => {
    const first = await context();
    const registered = await registerWallet(first.service, first.invitation.token);
    await expect(first.service.register({ challengeId: registered.challenge.challengeId,
      signature: registered.signature, publicKey: registered.publicKeyHex }))
      .rejects.toMatchObject({ code: "invalid_challenge" });

    const second = await context();
    const requestedKey = randomPrivateKey();
    const walletAddress = publicKeyToAddressSingleSig(privateKeyToPublic(requestedKey), "testnet");
    const challenge = await second.service.issueChallenge({ invitationToken: second.invitation.token, walletAddress });
    const attacker = randomPrivateKey();
    await expect(second.service.register({ challengeId: challenge.challengeId,
      signature: signMessageHashRsv({ messageHash: Buffer.from(hashMessage(challenge.message)).toString("hex"), privateKey: attacker }),
      publicKey: privateKeyToPublic(attacker) })).rejects.toMatchObject({ code: "invalid_wallet_signature" });
  });

  it("rejects invalid credentials, grant and excessive scopes", async () => {
    const { invitation, service } = await context(["quotes:create"]);
    const { client } = await registerWallet(service, invitation.token);
    const wrong = Buffer.from(`${client.clientId}:ny_cs_${"A".repeat(43)}`).toString("base64");
    await expect(service.issueToken(`Basic ${wrong}`, new URLSearchParams({ grant_type: "client_credentials" })))
      .rejects.toMatchObject({ code: "invalid_client" });
    const basic = Buffer.from(`${client.clientId}:${client.clientSecret}`).toString("base64");
    await expect(service.issueToken(`Basic ${basic}`, new URLSearchParams({ grant_type: "authorization_code" })))
      .rejects.toMatchObject({ code: "invalid_request" });
    await expect(service.issueToken(`Basic ${basic}`,
      new URLSearchParams({ grant_type: "client_credentials", scope: "payments:settle" })))
      .rejects.toMatchObject({ code: "invalid_scope" });
  });
});

describe("anonymous agent registration and wallet claim", () => {
  it("keeps agent:self before and after an atomic SIP-018 wallet claim", async () => {
    let currentTime = NOW;
    const config = await testConfig();
    const signer = await createOAuthSigner(config);
    const store = new MemoryStore();
    const service = createOAuthService({ config, store, signer, now: () => currentTime });

    const identity = await service.createAgentIdentity({ type: "anonymous", label: "Research agent" });
    expect(identity).toMatchObject({ pre_claim_scopes: ["agent:self"],
      post_claim_scopes: ["agent:self"], interval: 5 });
    expect(identity.claim_url).toBe(`https://nayori.ai/agents/claim#${identity.claim_token}`);

    const anonymousToken = await service.issueToken(undefined, new URLSearchParams({
      grant_type: "urn:ietf:params:oauth:grant-type:jwt-bearer",
      assertion: identity.identity_assertion
    }));
    const anonymousSelf = await service.getAgentSelf(`Bearer ${anonymousToken.access_token}`);
    expect(anonymousSelf).toEqual({ registration_id: identity.registration_id, label: "Research agent",
      claimed: false, wallet_address: null, scopes: ["agent:self"] });

    const prepared = await service.prepareAgentClaim({ claim_token: identity.claim_token,
      user_code: identity.user_code });
    const privateKey = randomPrivateKey();
    const publicKey = privateKeyToPublic(privateKey);
    const publicKeyHex = typeof publicKey === "string" ? publicKey : Buffer.from(publicKey).toString("hex");
    const walletAddress = publicKeyToAddressSingleSig(publicKey, "testnet");
    const signature = signStructuredData({ ...buildAgentClaimClarity(prepared.claim), privateKey });
    const claimed = await service.completeAgentClaim({ claim_token: identity.claim_token,
      user_code: identity.user_code, challenge_id: prepared.claim.challengeId,
      wallet_address: walletAddress, public_key: publicKeyHex, signature });
    expect(claimed).toEqual({ status: "claimed", registration_id: identity.registration_id,
      wallet_address: walletAddress, scopes: ["agent:self"] });

    currentTime += 6_000;
    const claimedToken = await service.issueToken(undefined, new URLSearchParams({
      grant_type: "urn:workos:agent-auth:grant-type:claim", claim_token: identity.claim_token
    }));
    const claimedSelf = await service.getAgentSelf(`Bearer ${claimedToken.access_token}`);
    expect(claimedToken.scope).toBe("agent:self");
    expect(claimedToken.identity_assertion).toBeTypeOf("string");
    expect(claimedSelf).toMatchObject({ claimed: true, wallet_address: walletAddress,
      scopes: ["agent:self"] });
  });

  it("rejects a wrong code, wallet mismatch, claim replay and fast polling", async () => {
    let currentTime = NOW;
    const config = await testConfig();
    const signer = await createOAuthSigner(config);
    const store = new MemoryStore();
    const service = createOAuthService({ config, store, signer, now: () => currentTime });
    const identity = await service.createAgentIdentity({ type: "anonymous" });

    await expect(service.prepareAgentClaim({ claim_token: identity.claim_token, user_code: "AAAA-BBBB" }))
      .rejects.toMatchObject({ code: "invalid_grant" });
    await expect(service.issueToken(undefined, new URLSearchParams({
      grant_type: "urn:workos:agent-auth:grant-type:claim", claim_token: identity.claim_token
    }))).rejects.toMatchObject({ code: "authorization_pending" });
    currentTime += 1_000;
    await expect(service.issueToken(undefined, new URLSearchParams({
      grant_type: "urn:workos:agent-auth:grant-type:claim", claim_token: identity.claim_token
    }))).rejects.toMatchObject({ code: "slow_down" });

    const prepared = await service.prepareAgentClaim({ claim_token: identity.claim_token,
      user_code: identity.user_code });
    const privateKey = randomPrivateKey();
    const publicKey = privateKeyToPublic(privateKey);
    const publicKeyHex = typeof publicKey === "string" ? publicKey : Buffer.from(publicKey).toString("hex");
    const signature = signStructuredData({ ...buildAgentClaimClarity(prepared.claim), privateKey });
    const otherWalletAddress = publicKeyToAddressSingleSig(privateKeyToPublic(randomPrivateKey()), "testnet");
    await expect(service.completeAgentClaim({ claim_token: identity.claim_token,
      user_code: identity.user_code, challenge_id: prepared.claim.challengeId,
      wallet_address: otherWalletAddress, public_key: publicKeyHex, signature }))
      .rejects.toMatchObject({ code: "invalid_wallet_signature" });

    const walletAddress = publicKeyToAddressSingleSig(publicKey, "testnet");
    await service.completeAgentClaim({ claim_token: identity.claim_token, user_code: identity.user_code,
      challenge_id: prepared.claim.challengeId, wallet_address: walletAddress,
      public_key: publicKeyHex, signature });
    await expect(service.completeAgentClaim({ claim_token: identity.claim_token, user_code: identity.user_code,
      challenge_id: prepared.claim.challengeId, wallet_address: walletAddress,
      public_key: publicKeyHex, signature }))
      .rejects.toMatchObject({ code: "invalid_grant" });
  });
});
