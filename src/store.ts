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
}
