export const oauthScopes = [
  "catalog:read",
  "quotes:create",
  "payments:verify",
  "payments:settle",
  "payments:read",
  "mcp:invoke"
] as const;

export type OAuthScope = (typeof oauthScopes)[number];

export type PartnerInvitationRecord = {
  readonly invitationId: string;
  readonly merchantId: string;
  readonly scopes: readonly OAuthScope[];
  readonly expiresAt: Date;
};

export type WalletAuthChallengeRecord = PartnerInvitationRecord & {
  readonly challengeId: string;
  readonly walletAddress: string;
  readonly network: "testnet" | "mainnet";
  readonly message: string;
  readonly challengeExpiresAt: Date;
};

export type OAuthClientRecord = {
  readonly clientId: string;
  readonly merchantId: string;
  readonly walletAddress: string;
  readonly secretDigest: string;
  readonly scopes: readonly OAuthScope[];
};

export const agentScopes = ["agent:self"] as const;
export type AgentScope = (typeof agentScopes)[number];

export type AgentRegistrationRecord = {
  readonly registrationId: string;
  readonly label: string | null;
  readonly challengeId: string;
  readonly claimExpiresAt: Date;
  readonly claimedAt: Date | null;
  readonly walletAddress: string | null;
  readonly publicKey: string | null;
  readonly revokedAt: Date | null;
  readonly lastPolledAt: Date | null;
};

export interface OAuthStore {
  ping(): Promise<void>;
  close(): Promise<void>;
  insertPartnerInvitation(input: PartnerInvitationRecord & { readonly tokenDigest: string }): Promise<void>;
  findActivePartnerInvitation(tokenDigest: string, now: Date): Promise<PartnerInvitationRecord | null>;
  insertWalletAuthChallenge(input: WalletAuthChallengeRecord): Promise<void>;
  findActiveWalletAuthChallenge(challengeId: string, now: Date): Promise<WalletAuthChallengeRecord | null>;
  consumeChallengeAndCreateOAuthClient(input: {
    readonly challengeId: string;
    readonly clientId: string;
    readonly secretDigest: string;
    readonly usedAt: Date;
  }): Promise<OAuthClientRecord | null>;
  findActiveOAuthClient(clientId: string): Promise<OAuthClientRecord | null>;
  recordOAuthTokenIssued(clientId: string, issuedAt: Date): Promise<void>;
  insertAgentRegistration(input: AgentRegistrationRecord & {
    readonly claimTokenDigest: string;
    readonly userCodeDigest: string;
  }): Promise<void>;
  findAgentRegistration(registrationId: string): Promise<AgentRegistrationRecord | null>;
  findAgentRegistrationForClaim(input: {
    readonly claimTokenDigest: string;
    readonly userCodeDigest: string;
    readonly now: Date;
  }): Promise<AgentRegistrationRecord | null>;
  claimAgentRegistration(input: {
    readonly challengeId: string;
    readonly walletAddress: string;
    readonly publicKey: string;
    readonly claimedAt: Date;
  }): Promise<AgentRegistrationRecord | null>;
  pollAgentClaim(input: {
    readonly claimTokenDigest: string;
    readonly now: Date;
    readonly minimumIntervalSeconds: number;
  }): Promise<{ readonly status: "pending" | "claimed" | "expired" | "slow_down";
    readonly registration: AgentRegistrationRecord | null }>;
  recordAgentAccessTokenIssued(registrationId: string, issuedAt: Date): Promise<void>;
}
