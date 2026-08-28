import { createHash, randomBytes, randomUUID, timingSafeEqual } from "node:crypto";
import { verifyMessageSignatureRsv } from "@stacks/encryption";
import { Cl, encodeStructuredDataBytes, publicKeyToAddressSingleSig } from "@stacks/transactions";
import { SignJWT, createLocalJWKSet, importJWK, jwtVerify, type JWK, type JWTPayload } from "jose";
import { z } from "zod";
import type { AppConfig } from "./config.js";
import { agentScopes, oauthScopes, type AgentRegistrationRecord, type OAuthClientRecord,
  type OAuthScope, type OAuthStore, type PartnerInvitationRecord } from "./store.js";

const invitationTokenPattern = /^ny_pi_[A-Za-z0-9_-]{43}$/;
const clientIdPattern = /^ny_oc_[A-Za-z0-9_-]{24}$/;
const clientSecretPattern = /^ny_cs_[A-Za-z0-9_-]{43}$/;
const challengeIdPattern = /^nc_[0-9a-f]{32}$/;
const publicKeyPattern = /^(?:0x)?(02|03)[0-9a-f]{64}$/i;
const signaturePattern = /^(?:0x)?[0-9a-f]{130}$/i;
const agentRegistrationIdPattern = /^ny_ar_[A-Za-z0-9_-]{24}$/;
const agentClaimTokenPattern = /^ny_ct_[A-Za-z0-9_-]{43}$/;
const agentChallengeIdPattern = /^ny_ac_[0-9a-f]{32}$/;
const userCodePattern = /^[A-Z2-9]{4}-[A-Z2-9]{4}$/;
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
const agentIdentityRequest = z.object({
  type: z.literal("anonymous"),
  label: z.string().trim().min(1).max(80).optional()
}).strict();
const agentClaimRequest = z.object({
  claim_token: z.string().regex(agentClaimTokenPattern),
  user_code: z.string().trim().toUpperCase().regex(userCodePattern)
}).strict();
const agentClaimCompletionRequest = agentClaimRequest.extend({
  challenge_id: z.string().regex(agentChallengeIdPattern),
  wallet_address: z.string().min(38).max(64),
  signature: z.string().regex(signaturePattern),
  public_key: z.string().regex(publicKeyPattern)
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
      "invalid_wallet_signature" | "invalid_client" | "invalid_scope" | "invalid_grant" |
      "authorization_pending" | "slow_down" | "expired_token" | "invalid_token",
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
  signAgentAssertion(input: {
    readonly registration: AgentRegistrationRecord;
    readonly issuedAt: number;
    readonly expiresAt: number;
  }): Promise<string>;
  signAgentAccessToken(input: {
    readonly registration: AgentRegistrationRecord;
    readonly issuedAt: number;
    readonly expiresAt: number;
  }): Promise<string>;
  verifyAgentAssertion(token: string, now: Date): Promise<JWTPayload>;
  verifyAgentAccessToken(token: string, now: Date): Promise<JWTPayload>;
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
  const publicKeys = { keys: [current, ...previous.keys.map((item) => ({ ...item, alg: "EdDSA", use: "sig" }))] };
  const verificationKeySet = createLocalJWKSet(publicKeys);
  return {
    publicJwks: publicKeys,
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
    },
    async signAgentAssertion(input) {
      return new SignJWT({
        token_kind: "identity_assertion",
        registration_id: input.registration.registrationId,
        claimed: Boolean(input.registration.claimedAt),
        wallet_address: input.registration.walletAddress ?? undefined,
        scope: agentScopes.join(" ")
      })
        .setProtectedHeader({ alg: "EdDSA", kid: key.kid, typ: "nayori-agent-assertion+jwt" })
        .setIssuer(config.issuerOrigin)
        .setAudience(`${config.issuerOrigin}/oauth/token`)
        .setSubject(`agent:${input.registration.registrationId}`)
        .setJti(randomUUID())
        .setIssuedAt(input.issuedAt)
        .setExpirationTime(input.expiresAt)
        .sign(signingKey);
    },
    async signAgentAccessToken(input) {
      return new SignJWT({
        token_kind: "agent_access_token",
        principal_type: "agent",
        registration_id: input.registration.registrationId,
        claimed: Boolean(input.registration.claimedAt),
        wallet_address: input.registration.walletAddress ?? undefined,
        scope: agentScopes.join(" ")
      })
        .setProtectedHeader({ alg: "EdDSA", kid: key.kid, typ: "at+jwt" })
        .setIssuer(config.issuerOrigin)
        .setAudience(config.resourceOrigin)
        .setSubject(`agent:${input.registration.registrationId}`)
        .setJti(randomUUID())
        .setIssuedAt(input.issuedAt)
        .setExpirationTime(input.expiresAt)
        .sign(signingKey);
    },
    async verifyAgentAssertion(token, currentDate) {
      const verified = await jwtVerify(token, verificationKeySet, {
        algorithms: ["EdDSA"], issuer: config.issuerOrigin,
        audience: `${config.issuerOrigin}/oauth/token`, currentDate
      });
      if (verified.protectedHeader.typ !== "nayori-agent-assertion+jwt" ||
          verified.payload.token_kind !== "identity_assertion") throw new Error("invalid assertion type");
      return verified.payload;
    },
    async verifyAgentAccessToken(token, currentDate) {
      const verified = await jwtVerify(token, verificationKeySet, {
        algorithms: ["EdDSA"], issuer: config.issuerOrigin,
        audience: config.resourceOrigin, currentDate
      });
      if (verified.protectedHeader.typ !== "at+jwt" ||
          verified.payload.token_kind !== "agent_access_token") throw new Error("invalid access token type");
      return verified.payload;
    }
  };
}

function digest(value: string): string { return createHash("sha256").update(value, "utf8").digest("hex"); }
function normalizeHex(value: string): string { return /^0x/i.test(value) ? value.slice(2) : value; }
function safeDigestEqual(left: string, right: string): boolean {
  return /^[0-9a-f]{64}$/.test(left) && /^[0-9a-f]{64}$/.test(right) &&
    timingSafeEqual(Buffer.from(left, "hex"), Buffer.from(right, "hex"));
}

function claimCode(): string {
  const alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
  const bytes = randomBytes(8);
  const value = Array.from(bytes, (byte) => alphabet[byte % alphabet.length]).join("");
  return `${value.slice(0, 4)}-${value.slice(4)}`;
}

export type AgentClaimPayload = {
  readonly registrationId: string;
  readonly challengeId: string;
  readonly userCode: string;
  readonly expiresAt: string;
  readonly network: "testnet" | "mainnet";
  readonly domain: { readonly name: "Nayori Agent Claim"; readonly version: "1"; readonly chainId: number };
  readonly message: { readonly action: "claim-agent"; readonly origin: string;
    readonly registrationId: string; readonly challengeId: string; readonly userCode: string;
    readonly expiresAt: number };
};

function createAgentClaimPayload(config: AppConfig, registration: AgentRegistrationRecord, userCode: string): AgentClaimPayload {
  const expiresAt = Math.floor(registration.claimExpiresAt.getTime() / 1_000);
  return {
    registrationId: registration.registrationId,
    challengeId: registration.challengeId,
    userCode,
    expiresAt: registration.claimExpiresAt.toISOString(),
    network: config.stacksNetwork,
    domain: { name: "Nayori Agent Claim", version: "1",
      chainId: config.stacksNetwork === "mainnet" ? 1 : 2_147_483_648 },
    message: { action: "claim-agent", origin: config.issuerOrigin,
      registrationId: registration.registrationId, challengeId: registration.challengeId,
      userCode, expiresAt }
  };
}

export function buildAgentClaimClarity(payload: AgentClaimPayload) {
  return {
    domain: Cl.tuple({ name: Cl.stringAscii(payload.domain.name),
      version: Cl.stringAscii(payload.domain.version), "chain-id": Cl.uint(payload.domain.chainId) }),
    message: Cl.tuple({ action: Cl.stringAscii(payload.message.action),
      origin: Cl.stringAscii(payload.message.origin),
      "registration-id": Cl.stringAscii(payload.message.registrationId),
      "challenge-id": Cl.stringAscii(payload.message.challengeId),
      "user-code": Cl.stringAscii(payload.message.userCode),
      "expires-at": Cl.uint(payload.message.expiresAt) })
  };
}

function bearerToken(value: string | undefined): string {
  if (!value?.startsWith("Bearer ") || value.length < 10) {
    throw new OAuthServiceError("invalid_token", "Bearer authentication failed.", 401);
  }
  return value.slice(7);
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
    readonly identity_assertion?: string;
  }>;
  createAgentIdentity(input: unknown): Promise<{
    readonly registration_id: string; readonly identity_assertion: string; readonly assertion_expires: string;
    readonly pre_claim_scopes: readonly ["agent:self"]; readonly post_claim_scopes: readonly ["agent:self"];
    readonly claim_token: string; readonly claim_url: string; readonly user_code: string;
    readonly expires_at: string; readonly interval: number;
  }>;
  prepareAgentClaim(input: unknown): Promise<{ readonly status: "pending" | "claimed";
    readonly claim: AgentClaimPayload; readonly wallet_address?: string }>;
  completeAgentClaim(input: unknown): Promise<{ readonly status: "claimed";
    readonly registration_id: string; readonly wallet_address: string; readonly scopes: readonly ["agent:self"] }>;
  getAgentSelf(authorization: string | undefined): Promise<{
    readonly registration_id: string; readonly label: string | null; readonly claimed: boolean;
    readonly wallet_address: string | null; readonly scopes: readonly ["agent:self"];
  }>;
};

export function createOAuthService(options: {
  readonly config: AppConfig; readonly store: OAuthStore; readonly signer: OAuthSigner; readonly now?: () => number;
}): OAuthService {
  const { config, store, signer } = options;
  const now = options.now ?? (() => Date.now());
  async function agentRegistrationFromAssertion(assertion: string, current: Date) {
    try {
      const payload = await signer.verifyAgentAssertion(assertion, current);
      const registrationId = typeof payload.registration_id === "string" ? payload.registration_id : "";
      if (!agentRegistrationIdPattern.test(registrationId) || payload.sub !== `agent:${registrationId}`) throw new Error("invalid subject");
      const registration = await store.findAgentRegistration(registrationId);
      if (!registration || registration.revokedAt) throw new Error("inactive registration");
      return registration;
    } catch {
      throw new OAuthServiceError("invalid_grant", "The identity assertion is invalid or expired.", 400);
    }
  }
  async function issueAgentAccessToken(registration: AgentRegistrationRecord, current: Date, includeAssertion = false) {
    const issuedAt = Math.floor(current.getTime() / 1_000);
    const expiresAt = issuedAt + config.oauthAccessTokenTtlSeconds;
    const token = await signer.signAgentAccessToken({ registration, issuedAt, expiresAt });
    await store.recordAgentAccessTokenIssued(registration.registrationId, current);
    const response: { access_token: string; token_type: "Bearer"; expires_in: number; scope: string;
      identity_assertion?: string } = {
      access_token: token, token_type: "Bearer", expires_in: config.oauthAccessTokenTtlSeconds,
      scope: agentScopes.join(" ")
    };
    if (includeAssertion) {
      response.identity_assertion = await signer.signAgentAssertion({ registration, issuedAt,
        expiresAt: issuedAt + config.agentAssertionTtlSeconds });
    }
    return response;
  }
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
      const grantType = form.get("grant_type");
      const current = new Date(now());
      if (grantType === "urn:ietf:params:oauth:grant-type:jwt-bearer") {
        const assertion = form.get("assertion") ?? "";
        return issueAgentAccessToken(await agentRegistrationFromAssertion(assertion, current), current);
      }
      if (grantType === "urn:workos:agent-auth:grant-type:claim") {
        const claimToken = form.get("claim_token") ?? "";
        if (!agentClaimTokenPattern.test(claimToken)) {
          throw new OAuthServiceError("invalid_grant", "The claim token is invalid.", 400);
        }
        const result = await store.pollAgentClaim({ claimTokenDigest: digest(claimToken), now: current,
          minimumIntervalSeconds: config.agentClaimPollIntervalSeconds });
        if (result.status === "pending") throw new OAuthServiceError("authorization_pending", "The wallet claim is still pending.", 400);
        if (result.status === "slow_down") throw new OAuthServiceError("slow_down", "Poll no faster than the advertised interval.", 400);
        if (result.status === "expired" || !result.registration) throw new OAuthServiceError("expired_token", "The claim token is invalid or expired.", 400);
        return issueAgentAccessToken(result.registration, current, true);
      }
      if (grantType !== "client_credentials") {
        throw new OAuthServiceError("invalid_request", "The OAuth grant type is not supported.", 400);
      }
      const credentials = parseBasic(authorization);
      const client = await store.findActiveOAuthClient(credentials.clientId);
      if (!client || !safeDigestEqual(digest(credentials.secret), client.secretDigest)) {
        throw new OAuthServiceError("invalid_client", "Client authentication failed.", 401);
      }
      const scopes = requestedScopes(form.get("scope") ?? undefined, client.scopes);
      const issuedAt = Math.floor(current.getTime() / 1_000);
      const expiresAt = issuedAt + config.oauthAccessTokenTtlSeconds;
      const token = await signer.sign({ client, scopes, issuedAt, expiresAt });
      await store.recordOAuthTokenIssued(client.clientId, new Date(issuedAt * 1_000));
      return { access_token: token, token_type: "Bearer", expires_in: config.oauthAccessTokenTtlSeconds,
        scope: scopes.join(" ") };
    },
    async createAgentIdentity(input) {
      const parsed = agentIdentityRequest.safeParse(input);
      if (!parsed.success) throw new OAuthServiceError("invalid_request", "The anonymous identity request is invalid.", 400);
      const current = new Date(now());
      const registrationId = `ny_ar_${randomBytes(18).toString("base64url")}`;
      const challengeId = `ny_ac_${randomBytes(16).toString("hex")}`;
      const claimToken = `ny_ct_${randomBytes(32).toString("base64url")}`;
      const userCode = claimCode();
      const claimExpiresAt = new Date(current.getTime() + config.agentClaimTtlSeconds * 1_000);
      const registration: AgentRegistrationRecord = { registrationId,
        label: parsed.data.label ?? null, challengeId, claimExpiresAt, claimedAt: null,
        walletAddress: null, publicKey: null, revokedAt: null, lastPolledAt: null };
      await store.insertAgentRegistration({ ...registration, claimTokenDigest: digest(claimToken),
        userCodeDigest: digest(userCode) });
      const issuedAt = Math.floor(current.getTime() / 1_000);
      const assertionExpiresAt = issuedAt + config.agentAssertionTtlSeconds;
      return { registration_id: registrationId,
        identity_assertion: await signer.signAgentAssertion({ registration, issuedAt, expiresAt: assertionExpiresAt }),
        assertion_expires: new Date(assertionExpiresAt * 1_000).toISOString(),
        pre_claim_scopes: agentScopes, post_claim_scopes: agentScopes,
        claim_token: claimToken, claim_url: `${config.resourceOrigin}/agents/claim#${claimToken}`,
        user_code: userCode, expires_at: claimExpiresAt.toISOString(),
        interval: config.agentClaimPollIntervalSeconds };
    },
    async prepareAgentClaim(input) {
      const parsed = agentClaimRequest.safeParse(input);
      if (!parsed.success) throw new OAuthServiceError("invalid_request", "The claim request is invalid.", 400);
      const registration = await store.findAgentRegistrationForClaim({
        claimTokenDigest: digest(parsed.data.claim_token), userCodeDigest: digest(parsed.data.user_code),
        now: new Date(now())
      });
      if (!registration) throw new OAuthServiceError("invalid_grant", "The claim token or user code is invalid or expired.", 400);
      return { status: registration.claimedAt ? "claimed" : "pending",
        claim: createAgentClaimPayload(config, registration, parsed.data.user_code),
        ...(registration.walletAddress ? { wallet_address: registration.walletAddress } : {}) };
    },
    async completeAgentClaim(input) {
      const parsed = agentClaimCompletionRequest.safeParse(input);
      if (!parsed.success) throw new OAuthServiceError("invalid_request", "The signed claim request is invalid.", 400);
      const current = new Date(now());
      const registration = await store.findAgentRegistrationForClaim({
        claimTokenDigest: digest(parsed.data.claim_token), userCodeDigest: digest(parsed.data.user_code), now: current
      });
      if (!registration || registration.challengeId !== parsed.data.challenge_id || registration.claimedAt) {
        throw new OAuthServiceError("invalid_grant", "The wallet claim is invalid, expired or already completed.", 409);
      }
      let address = "";
      let valid = false;
      const publicKey = normalizeHex(parsed.data.public_key);
      try {
        address = publicKeyToAddressSingleSig(publicKey, config.stacksNetwork);
        const clarity = buildAgentClaimClarity(createAgentClaimPayload(config, registration, parsed.data.user_code));
        valid = verifyMessageSignatureRsv({ message: createHash("sha256").update(encodeStructuredDataBytes(clarity)).digest(),
          publicKey, signature: normalizeHex(parsed.data.signature) });
      } catch { /* normalized below */ }
      if (!valid || address !== parsed.data.wallet_address) {
        throw new OAuthServiceError("invalid_wallet_signature", "The SIP-018 signature does not authorize this agent claim.", 401);
      }
      const claimed = await store.claimAgentRegistration({ challengeId: registration.challengeId,
        walletAddress: address, publicKey, claimedAt: current });
      if (!claimed) throw new OAuthServiceError("invalid_grant", "The wallet claim is invalid, expired or already completed.", 409);
      return { status: "claimed", registration_id: claimed.registrationId,
        wallet_address: address, scopes: agentScopes };
    },
    async getAgentSelf(authorization) {
      try {
        const current = new Date(now());
        const payload = await signer.verifyAgentAccessToken(bearerToken(authorization), current);
        const registrationId = typeof payload.registration_id === "string" ? payload.registration_id : "";
        if (!agentRegistrationIdPattern.test(registrationId) || payload.sub !== `agent:${registrationId}` ||
            payload.scope !== "agent:self") throw new Error("invalid principal");
        const registration = await store.findAgentRegistration(registrationId);
        if (!registration || registration.revokedAt) throw new Error("inactive registration");
        return { registration_id: registration.registrationId, label: registration.label,
          claimed: Boolean(registration.claimedAt), wallet_address: registration.walletAddress,
          scopes: agentScopes };
      } catch (error) {
        if (error instanceof OAuthServiceError) throw error;
        throw new OAuthServiceError("invalid_token", "Bearer authentication failed.", 401);
      }
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
