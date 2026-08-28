import { createHash, randomBytes, randomUUID, timingSafeEqual } from "node:crypto";
import { verifyMessageSignatureRsv } from "@stacks/encryption";
import { publicKeyToAddressSingleSig } from "@stacks/transactions";
import { SignJWT, importJWK, type JWK } from "jose";
import { z } from "zod";
import type { AppConfig } from "./config.js";
import { oauthScopes, type OAuthClientRecord, type OAuthScope, type OAuthStore, type PartnerInvitationRecord } from "./store.js";

const invitationTokenPattern = /^ny_pi_[A-Za-z0-9_-]{43}$/;
const clientIdPattern = /^ny_oc_[A-Za-z0-9_-]{24}$/;
const clientSecretPattern = /^ny_cs_[A-Za-z0-9_-]{43}$/;
const challengeIdPattern = /^nc_[0-9a-f]{32}$/;
const publicKeyPattern = /^(?:0x)?(02|03)[0-9a-f]{64}$/i;
const signaturePattern = /^(?:0x)?[0-9a-f]{130}$/i;
const base64Url = z.string().regex(/^[A-Za-z0-9_-]+$/);

const challengeRequest = z.object({
  invitationToken: z.string().regex(invitationTokenPattern),
  walletAddress: z.string().min(38).max(64)
}).strict();
const registrationRequest = z.object({
  challengeId: z.string().regex(challengeIdPattern),
  signature: z.string().regex(signaturePattern),
  publicKey: z.string().regex(publicKeyPattern)
}).strict();
const privateJwk = z.object({
  kty: z.literal("OKP"), crv: z.literal("Ed25519"), x: base64Url, d: base64Url,
  kid: z.string().min(1).max(128)
}).passthrough();
const publicJwk = z.object({
  kty: z.literal("OKP"), crv: z.literal("Ed25519"), x: base64Url,
  kid: z.string().min(1).max(128)
}).passthrough().refine((value) => !("d" in value), "Public JWKS entries must not contain d.");
const publicJwks = z.object({ keys: z.array(publicJwk).max(16) }).strict();

export class OAuthServiceError extends Error {
  constructor(
    readonly code: "invalid_request" | "invalid_invitation" | "invalid_challenge" |
      "invalid_wallet_signature" | "invalid_client" | "invalid_scope",
    readonly publicMessage: string,
    readonly status: 400 | 401 | 409
  ) { super(publicMessage); this.name = "OAuthServiceError"; }
}

export type OAuthSigner = {
  readonly publicJwks: { readonly keys: readonly JWK[] };
  sign(input: {
    readonly client: OAuthClientRecord;
    readonly scopes: readonly OAuthScope[];
    readonly issuedAt: number;
    readonly expiresAt: number;
  }): Promise<string>;
};

function parseJson(value: string, name: string): unknown {
  try { return JSON.parse(value) as unknown; }
  catch { throw new Error(`${name} must contain valid JSON.`); }
}

export async function createOAuthSigner(config: AppConfig): Promise<OAuthSigner> {
  const key = privateJwk.parse(parseJson(config.oauthSigningPrivateJwkJson, "OAUTH_SIGNING_PRIVATE_JWK_JSON"));
  const previous = publicJwks.parse(parseJson(config.oauthPreviousPublicJwksJson, "OAUTH_PREVIOUS_PUBLIC_JWKS_JSON"));
  const current: JWK = { kty: "OKP", crv: "Ed25519", x: key.x, kid: key.kid, alg: "EdDSA", use: "sig" };
  const signingKey = await importJWK(key as JWK, "EdDSA");
  return {
    publicJwks: { keys: [current, ...previous.keys.map((item) => ({ ...item, alg: "EdDSA", use: "sig" }))] },
    async sign(input) {
      return new SignJWT({
        client_id: input.client.clientId,
        wallet_address: input.client.walletAddress,
        scope: input.scopes.join(" ")
      })
        .setProtectedHeader({ alg: "EdDSA", kid: key.kid, typ: "at+jwt" })
        .setIssuer(config.issuerOrigin)
        .setAudience(config.resourceOrigin)
        .setSubject(input.client.merchantId)
        .setJti(randomUUID())
        .setIssuedAt(input.issuedAt)
        .setExpirationTime(input.expiresAt)
        .sign(signingKey);
    }
  };
}

function digest(value: string): string { return createHash("sha256").update(value, "utf8").digest("hex"); }
function normalizeHex(value: string): string { return /^0x/i.test(value) ? value.slice(2) : value; }
function safeDigestEqual(left: string, right: string): boolean {
  return /^[0-9a-f]{64}$/.test(left) && /^[0-9a-f]{64}$/.test(right) &&
    timingSafeEqual(Buffer.from(left, "hex"), Buffer.from(right, "hex"));
}

function parseBasic(value: string | undefined): { clientId: string; secret: string } {
  if (!value?.startsWith("Basic ")) throw new OAuthServiceError("invalid_client", "Client authentication failed.", 401);
  let decoded = "";
  try { decoded = Buffer.from(value.slice(6), "base64").toString("utf8"); } catch { /* rejected below */ }
  const separator = decoded.indexOf(":");
  const clientId = decoded.slice(0, separator);
  const secret = decoded.slice(separator + 1);
  if (separator < 1 || !clientIdPattern.test(clientId) || !clientSecretPattern.test(secret)) {
    throw new OAuthServiceError("invalid_client", "Client authentication failed.", 401);
  }
  return { clientId, secret };
}

function requestedScopes(value: string | undefined, allowed: readonly OAuthScope[]): OAuthScope[] {
  const requested = value ? value.split(" ").filter(Boolean) : [...allowed];
  if (requested.length === 0 || new Set(requested).size !== requested.length ||
      requested.some((scope) => !oauthScopes.includes(scope as OAuthScope) || !allowed.includes(scope as OAuthScope))) {
    throw new OAuthServiceError("invalid_scope", "The requested OAuth scope is not allowed.", 400);
  }
  return requested as OAuthScope[];
}

export type OAuthService = {
  readonly publicJwks: OAuthSigner["publicJwks"];
  issueChallenge(input: unknown): Promise<{
    readonly challengeId: string; readonly message: string; readonly expiresAt: string;
    readonly walletAddress: string; readonly network: "testnet" | "mainnet";
  }>;
  register(input: unknown): Promise<{
    readonly clientId: string; readonly clientSecret: string; readonly tokenEndpoint: string;
    readonly scopes: readonly string[]; readonly walletAddress: string;
  }>;
  issueToken(authorization: string | undefined, form: URLSearchParams): Promise<{
    readonly access_token: string; readonly token_type: "Bearer"; readonly expires_in: number; readonly scope: string;
  }>;
};

export function createOAuthService(options: {
  readonly config: AppConfig; readonly store: OAuthStore; readonly signer: OAuthSigner; readonly now?: () => number;
}): OAuthService {
  const { config, store, signer } = options;
  const now = options.now ?? (() => Date.now());
  return {
    publicJwks: signer.publicJwks,
    async issueChallenge(input) {
      const parsed = challengeRequest.safeParse(input);
      if (!parsed.success) throw new OAuthServiceError("invalid_request", "The partner challenge request is invalid.", 400);
      const current = new Date(now());
      const invitation = await store.findActivePartnerInvitation(hashPartnerInvitationToken(parsed.data.invitationToken), current);
      if (!invitation) throw new OAuthServiceError("invalid_invitation", "The partner invitation is invalid or expired.", 409);
      const challengeId = `nc_${randomBytes(16).toString("hex")}`;
      const expiresAt = new Date(now() + config.partnerChallengeTtlSeconds * 1_000);
      const message = [
        "Nayori partner registration", "Version: 1", `Origin: ${config.issuerOrigin}`,
        `Resource: ${config.resourceOrigin}`, `Network: ${config.stacksNetwork}`,
        `Merchant: ${invitation.merchantId}`, `Wallet: ${parsed.data.walletAddress}`,
        `Challenge: ${challengeId}`, `Expires at: ${expiresAt.toISOString()}`
      ].join("\n");
      await store.insertWalletAuthChallenge({ ...invitation, challengeId,
        walletAddress: parsed.data.walletAddress, network: config.stacksNetwork, message,
        challengeExpiresAt: expiresAt });
      return { challengeId, message, expiresAt: expiresAt.toISOString(),
        walletAddress: parsed.data.walletAddress, network: config.stacksNetwork };
    },
    async register(input) {
      const parsed = registrationRequest.safeParse(input);
      if (!parsed.success) throw new OAuthServiceError("invalid_request", "The partner registration request is invalid.", 400);
      const current = new Date(now());
      const challenge = await store.findActiveWalletAuthChallenge(parsed.data.challengeId, current);
      if (!challenge) throw new OAuthServiceError("invalid_challenge", "The wallet challenge is invalid, expired or consumed.", 409);
      let address = "";
      let valid = false;
      try {
        const publicKey = normalizeHex(parsed.data.publicKey);
        address = publicKeyToAddressSingleSig(publicKey, config.stacksNetwork);
        valid = verifyMessageSignatureRsv({ message: challenge.message, publicKey,
          signature: normalizeHex(parsed.data.signature) });
      } catch { /* normalized to a public error */ }
      if (!valid || address !== challenge.walletAddress) {
        throw new OAuthServiceError("invalid_wallet_signature", "The wallet signature does not authorize this registration.", 401);
      }
      const clientId = `ny_oc_${randomBytes(18).toString("base64url")}`;
      const clientSecret = `ny_cs_${randomBytes(32).toString("base64url")}`;
      const client = await store.consumeChallengeAndCreateOAuthClient({
        challengeId: challenge.challengeId, clientId, secretDigest: digest(clientSecret), usedAt: current
      });
      if (!client) throw new OAuthServiceError("invalid_challenge", "The wallet challenge is invalid, expired or consumed.", 409);
      return { clientId, clientSecret, tokenEndpoint: `${config.issuerOrigin}/oauth/token`,
        scopes: client.scopes, walletAddress: client.walletAddress };
    },
    async issueToken(authorization, form) {
      if (form.get("grant_type") !== "client_credentials") {
        throw new OAuthServiceError("invalid_request", "Only client_credentials is supported.", 400);
      }
      const credentials = parseBasic(authorization);
      const client = await store.findActiveOAuthClient(credentials.clientId);
      if (!client || !safeDigestEqual(digest(credentials.secret), client.secretDigest)) {
        throw new OAuthServiceError("invalid_client", "Client authentication failed.", 401);
      }
      const scopes = requestedScopes(form.get("scope") ?? undefined, client.scopes);
      const issuedAt = Math.floor(now() / 1_000);
      const expiresAt = issuedAt + config.oauthAccessTokenTtlSeconds;
      const token = await signer.sign({ client, scopes, issuedAt, expiresAt });
      await store.recordOAuthTokenIssued(client.clientId, new Date(issuedAt * 1_000));
      return { access_token: token, token_type: "Bearer", expires_in: config.oauthAccessTokenTtlSeconds,
        scope: scopes.join(" ") };
    }
  };
}

export function generateInvitationToken(): string { return `ny_pi_${randomBytes(32).toString("base64url")}`; }
export function hashPartnerInvitationToken(token: string): string {
  if (!invitationTokenPattern.test(token)) throw new Error("Partner invitation token has an invalid format.");
  return digest(token);
}
export function createInvitationRecord(input: {
  readonly merchantId: string; readonly scopes: readonly OAuthScope[]; readonly expiresAt: Date;
}): { readonly token: string; readonly record: PartnerInvitationRecord & { readonly tokenDigest: string } } {
  const token = generateInvitationToken();
  return { token, record: { invitationId: `ni_${randomBytes(16).toString("hex")}`,
    merchantId: input.merchantId, scopes: input.scopes, expiresAt: input.expiresAt,
    tokenDigest: hashPartnerInvitationToken(token) } };
}
