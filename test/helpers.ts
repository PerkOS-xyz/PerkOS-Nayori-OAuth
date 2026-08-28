import { exportJWK, generateKeyPair } from "jose";
import { loadConfig, type AppConfig } from "../src/config.js";
import type {
  AgentRegistrationRecord,
  OAuthClientRecord,
  OAuthStore,
  PartnerInvitationRecord,
  WalletAuthChallengeRecord
} from "../src/store.js";

export class MemoryStore implements OAuthStore {
  invitation: (PartnerInvitationRecord & { tokenDigest: string; used?: boolean }) | null = null;
  challenge: (WalletAuthChallengeRecord & { used?: boolean }) | null = null;
  client: OAuthClientRecord | null = null;
  tokenIssuedAt: Date | null = null;
  ready = true;
  agent: (AgentRegistrationRecord & { claimTokenDigest: string; userCodeDigest: string }) | null = null;
  agentTokenIssuedAt: Date | null = null;

  async ping(): Promise<void> { if (!this.ready) throw new Error("not ready"); }
  async close(): Promise<void> {}
  async insertPartnerInvitation(input: PartnerInvitationRecord & { tokenDigest: string }): Promise<void> {
    this.invitation = input;
  }
  async findActivePartnerInvitation(tokenDigest: string, now: Date) {
    return this.invitation && !this.invitation.used && this.invitation.tokenDigest === tokenDigest &&
      this.invitation.expiresAt >= now ? this.invitation : null;
  }
  async insertWalletAuthChallenge(input: WalletAuthChallengeRecord): Promise<void> { this.challenge = input; }
  async findActiveWalletAuthChallenge(challengeId: string, now: Date) {
    return this.challenge && !this.challenge.used && this.challenge.challengeId === challengeId &&
      this.challenge.challengeExpiresAt >= now && this.challenge.expiresAt >= now ? this.challenge : null;
  }
  async consumeChallengeAndCreateOAuthClient(input: {
    challengeId: string; clientId: string; secretDigest: string; usedAt: Date;
  }) {
    if (!this.challenge || this.challenge.used || this.challenge.challengeId !== input.challengeId) return null;
    this.challenge.used = true;
    if (this.invitation) this.invitation.used = true;
    this.client = { clientId: input.clientId, merchantId: this.challenge.merchantId,
      walletAddress: this.challenge.walletAddress, secretDigest: input.secretDigest,
      scopes: this.challenge.scopes };
    return this.client;
  }
  async findActiveOAuthClient(clientId: string) { return this.client?.clientId === clientId ? this.client : null; }
  async recordOAuthTokenIssued(_clientId: string, issuedAt: Date): Promise<void> { this.tokenIssuedAt = issuedAt; }
  async insertAgentRegistration(input: AgentRegistrationRecord & {
    claimTokenDigest: string; userCodeDigest: string;
  }): Promise<void> { this.agent = input; }
  async findAgentRegistration(registrationId: string) {
    return this.agent?.registrationId === registrationId ? this.agent : null;
  }
  async findAgentRegistrationForClaim(input: {
    claimTokenDigest: string; userCodeDigest: string; now: Date;
  }) {
    return this.agent && this.agent.claimTokenDigest === input.claimTokenDigest &&
      this.agent.userCodeDigest === input.userCodeDigest && this.agent.claimExpiresAt >= input.now &&
      !this.agent.revokedAt ? this.agent : null;
  }
  async claimAgentRegistration(input: {
    challengeId: string; walletAddress: string; publicKey: string; claimedAt: Date;
  }) {
    if (!this.agent || this.agent.challengeId !== input.challengeId || this.agent.claimedAt ||
        this.agent.revokedAt || this.agent.claimExpiresAt < input.claimedAt) return null;
    this.agent = { ...this.agent, claimedAt: input.claimedAt,
      walletAddress: input.walletAddress, publicKey: input.publicKey };
    return this.agent;
  }
  async pollAgentClaim(input: {
    claimTokenDigest: string; now: Date; minimumIntervalSeconds: number;
  }) {
    if (!this.agent || this.agent.claimTokenDigest !== input.claimTokenDigest || this.agent.revokedAt ||
        this.agent.claimExpiresAt < input.now) return { status: "expired" as const, registration: this.agent };
    if (this.agent.lastPolledAt && input.now.getTime() - this.agent.lastPolledAt.getTime() <
        input.minimumIntervalSeconds * 1_000) return { status: "slow_down" as const, registration: this.agent };
    this.agent = { ...this.agent, lastPolledAt: input.now };
    return { status: this.agent.claimedAt ? "claimed" as const : "pending" as const,
      registration: this.agent };
  }
  async recordAgentAccessTokenIssued(_registrationId: string, issuedAt: Date): Promise<void> {
    this.agentTokenIssuedAt = issuedAt;
  }
}

export async function testConfig(overrides: NodeJS.ProcessEnv = {}): Promise<AppConfig> {
  const { privateKey } = await generateKeyPair("EdDSA", { crv: "Ed25519", extractable: true });
  const key = { ...(await exportJWK(privateKey)), kid: "oauth-test", alg: "EdDSA", use: "sig" };
  return loadConfig({
    DATABASE_URL: "postgresql://nayori:test@localhost:5432/nayori_oauth_test",
    NODE_ENV: "test",
    ISSUER_ORIGIN: "https://oauth.nayori.ai",
    RESOURCE_ORIGIN: "https://nayori.ai",
    API_ORIGIN: "https://api.nayori.ai",
    STACKS_NETWORK: "testnet",
    PARTNER_REGISTRATION_ENABLED: "true",
    AGENT_REGISTRATION_ENABLED: "true",
    OAUTH_SIGNING_PRIVATE_JWK_JSON: JSON.stringify(key),
    OAUTH_ACCESS_TOKEN_TTL_SECONDS: "120",
    ...overrides
  });
}
