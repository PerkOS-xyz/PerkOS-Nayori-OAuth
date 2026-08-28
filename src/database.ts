import { Pool } from "pg";
import type { AppConfig } from "./config.js";
import type {
  OAuthClientRecord,
  OAuthScope,
  OAuthStore,
  AgentRegistrationRecord,
  PartnerInvitationRecord,
  WalletAuthChallengeRecord
} from "./store.js";

export class PostgresOAuthStore implements OAuthStore {
  readonly #pool: Pool;

  constructor(config: AppConfig) {
    this.#pool = new Pool({
      application_name: "nayori-oauth",
      connectionString: config.databaseUrl,
      connectionTimeoutMillis: config.databaseConnectTimeoutMs,
      max: config.databasePoolMax,
      query_timeout: config.databaseQueryTimeoutMs,
      ssl: config.databaseSsl === "require" ? { rejectUnauthorized: true } : false,
      statement_timeout: config.databaseQueryTimeoutMs
    });
  }

  async ping(): Promise<void> { await this.#pool.query("SELECT 1"); }
  async close(): Promise<void> { await this.#pool.end(); }

  async insertPartnerInvitation(input: PartnerInvitationRecord & { readonly tokenDigest: string }): Promise<void> {
    await this.#pool.query(
      `INSERT INTO partner_invitations (invitation_id, merchant_id, token_digest, scopes, expires_at)
       VALUES ($1, $2, $3, $4, $5)`,
      [input.invitationId, input.merchantId, input.tokenDigest, input.scopes, input.expiresAt]
    );
  }

  async findActivePartnerInvitation(tokenDigest: string, now: Date): Promise<PartnerInvitationRecord | null> {
    const result = await this.#pool.query(
      `SELECT invitation_id AS "invitationId", merchant_id AS "merchantId", scopes,
              expires_at AS "expiresAt"
       FROM partner_invitations
       WHERE token_digest = $1 AND used_at IS NULL AND expires_at >= $2 LIMIT 1`,
      [tokenDigest, now]
    );
    return (result.rows[0] as PartnerInvitationRecord | undefined) ?? null;
  }

  async insertWalletAuthChallenge(input: WalletAuthChallengeRecord): Promise<void> {
    await this.#pool.query(
      `INSERT INTO wallet_auth_challenges
       (challenge_id, invitation_id, merchant_id, wallet_address, network, message, expires_at)
       VALUES ($1, $2, $3, $4, $5, $6, $7)`,
      [input.challengeId, input.invitationId, input.merchantId, input.walletAddress,
        input.network, input.message, input.challengeExpiresAt]
    );
  }

  async findActiveWalletAuthChallenge(challengeId: string, now: Date): Promise<WalletAuthChallengeRecord | null> {
    const result = await this.#pool.query(
      `SELECT c.challenge_id AS "challengeId", c.invitation_id AS "invitationId",
              c.merchant_id AS "merchantId", c.wallet_address AS "walletAddress", c.network,
              c.message, c.expires_at AS "challengeExpiresAt", i.scopes,
              i.expires_at AS "expiresAt"
       FROM wallet_auth_challenges c
       JOIN partner_invitations i ON i.invitation_id = c.invitation_id
       WHERE c.challenge_id = $1 AND c.used_at IS NULL AND c.expires_at >= $2
         AND i.used_at IS NULL AND i.expires_at >= $2 LIMIT 1`,
      [challengeId, now]
    );
    return (result.rows[0] as WalletAuthChallengeRecord | undefined) ?? null;
  }

  async consumeChallengeAndCreateOAuthClient(input: {
    readonly challengeId: string;
    readonly clientId: string;
    readonly secretDigest: string;
    readonly usedAt: Date;
  }): Promise<OAuthClientRecord | null> {
    const connection = await this.#pool.connect();
    try {
      await connection.query("BEGIN");
      const locked = await connection.query<{
        invitationId: string;
        merchantId: string;
        walletAddress: string;
        scopes: OAuthScope[];
      }>(
        `SELECT c.invitation_id AS "invitationId", c.merchant_id AS "merchantId",
                c.wallet_address AS "walletAddress", i.scopes
         FROM wallet_auth_challenges c
         JOIN partner_invitations i ON i.invitation_id = c.invitation_id
         WHERE c.challenge_id = $1 AND c.used_at IS NULL AND c.expires_at >= $2
           AND i.used_at IS NULL AND i.expires_at >= $2 FOR UPDATE OF c, i`,
        [input.challengeId, input.usedAt]
      );
      const row = locked.rows[0];
      if (!row) { await connection.query("ROLLBACK"); return null; }
      await connection.query("UPDATE wallet_auth_challenges SET used_at = $2 WHERE challenge_id = $1", [input.challengeId, input.usedAt]);
      await connection.query("UPDATE partner_invitations SET used_at = $2 WHERE invitation_id = $1", [row.invitationId, input.usedAt]);
      await connection.query(
        `INSERT INTO oauth_clients (client_id, merchant_id, wallet_address, secret_digest, scopes)
         VALUES ($1, $2, $3, $4, $5)`,
        [input.clientId, row.merchantId, row.walletAddress, input.secretDigest, row.scopes]
      );
      await connection.query("COMMIT");
      return { clientId: input.clientId, merchantId: row.merchantId, walletAddress: row.walletAddress,
        secretDigest: input.secretDigest, scopes: row.scopes };
    } catch (error) {
      await connection.query("ROLLBACK");
      throw error;
    } finally { connection.release(); }
  }

  async findActiveOAuthClient(clientId: string): Promise<OAuthClientRecord | null> {
    const result = await this.#pool.query(
      `SELECT client_id AS "clientId", merchant_id AS "merchantId",
              wallet_address AS "walletAddress", secret_digest AS "secretDigest", scopes
       FROM oauth_clients WHERE client_id = $1 AND status = 'active' LIMIT 1`,
      [clientId]
    );
    return (result.rows[0] as OAuthClientRecord | undefined) ?? null;
  }

  async recordOAuthTokenIssued(clientId: string, issuedAt: Date): Promise<void> {
    await this.#pool.query(
      "UPDATE oauth_clients SET last_token_at = $2 WHERE client_id = $1 AND status = 'active'",
      [clientId, issuedAt]
    );
  }

  async insertAgentRegistration(input: AgentRegistrationRecord & {
    readonly claimTokenDigest: string;
    readonly userCodeDigest: string;
  }): Promise<void> {
    await this.#pool.query(
      `INSERT INTO agent_registrations
       (registration_id, label, challenge_id, claim_token_digest, user_code_digest, claim_expires_at)
       VALUES ($1, $2, $3, $4, $5, $6)`,
      [input.registrationId, input.label, input.challengeId, input.claimTokenDigest,
        input.userCodeDigest, input.claimExpiresAt]
    );
  }

  async findAgentRegistration(registrationId: string): Promise<AgentRegistrationRecord | null> {
    const result = await this.#pool.query(
      `SELECT registration_id AS "registrationId", label, challenge_id AS "challengeId",
              claim_expires_at AS "claimExpiresAt", claimed_at AS "claimedAt",
              wallet_address AS "walletAddress", public_key AS "publicKey",
              revoked_at AS "revokedAt", last_polled_at AS "lastPolledAt"
       FROM agent_registrations WHERE registration_id = $1 LIMIT 1`,
      [registrationId]
    );
    return (result.rows[0] as AgentRegistrationRecord | undefined) ?? null;
  }

  async findAgentRegistrationForClaim(input: {
    readonly claimTokenDigest: string;
    readonly userCodeDigest: string;
    readonly now: Date;
  }): Promise<AgentRegistrationRecord | null> {
    const result = await this.#pool.query(
      `SELECT registration_id AS "registrationId", label, challenge_id AS "challengeId",
              claim_expires_at AS "claimExpiresAt", claimed_at AS "claimedAt",
              wallet_address AS "walletAddress", public_key AS "publicKey",
              revoked_at AS "revokedAt", last_polled_at AS "lastPolledAt"
       FROM agent_registrations
       WHERE claim_token_digest = $1 AND user_code_digest = $2 AND claim_expires_at >= $3
         AND revoked_at IS NULL LIMIT 1`,
      [input.claimTokenDigest, input.userCodeDigest, input.now]
    );
    return (result.rows[0] as AgentRegistrationRecord | undefined) ?? null;
  }

  async claimAgentRegistration(input: {
    readonly challengeId: string;
    readonly walletAddress: string;
    readonly publicKey: string;
    readonly claimedAt: Date;
  }): Promise<AgentRegistrationRecord | null> {
    const result = await this.#pool.query(
      `UPDATE agent_registrations
       SET claimed_at = $2, wallet_address = $3, public_key = $4
       WHERE challenge_id = $1 AND claimed_at IS NULL AND revoked_at IS NULL
         AND claim_expires_at >= $2
       RETURNING registration_id AS "registrationId", label, challenge_id AS "challengeId",
                 claim_expires_at AS "claimExpiresAt", claimed_at AS "claimedAt",
                 wallet_address AS "walletAddress", public_key AS "publicKey",
                 revoked_at AS "revokedAt", last_polled_at AS "lastPolledAt"`,
      [input.challengeId, input.claimedAt, input.walletAddress, input.publicKey]
    );
    return (result.rows[0] as AgentRegistrationRecord | undefined) ?? null;
  }

  async pollAgentClaim(input: {
    readonly claimTokenDigest: string;
    readonly now: Date;
    readonly minimumIntervalSeconds: number;
  }): Promise<{ readonly status: "pending" | "claimed" | "expired" | "slow_down";
    readonly registration: AgentRegistrationRecord | null }> {
    const connection = await this.#pool.connect();
    try {
      await connection.query("BEGIN");
      const result = await connection.query<AgentRegistrationRecord>(
        `SELECT registration_id AS "registrationId", label, challenge_id AS "challengeId",
                claim_expires_at AS "claimExpiresAt", claimed_at AS "claimedAt",
                wallet_address AS "walletAddress", public_key AS "publicKey",
                revoked_at AS "revokedAt", last_polled_at AS "lastPolledAt"
         FROM agent_registrations WHERE claim_token_digest = $1 AND revoked_at IS NULL
         FOR UPDATE`,
        [input.claimTokenDigest]
      );
      const registration = result.rows[0] ?? null;
      if (!registration || registration.claimExpiresAt < input.now) {
        await connection.query("ROLLBACK");
        return { status: "expired", registration };
      }
      if (registration.lastPolledAt &&
          input.now.getTime() - registration.lastPolledAt.getTime() < input.minimumIntervalSeconds * 1_000) {
        await connection.query("ROLLBACK");
        return { status: "slow_down", registration };
      }
      await connection.query(
        "UPDATE agent_registrations SET last_polled_at = $2 WHERE registration_id = $1",
        [registration.registrationId, input.now]
      );
      await connection.query("COMMIT");
      return { status: registration.claimedAt ? "claimed" : "pending",
        registration: { ...registration, lastPolledAt: input.now } };
    } catch (error) {
      await connection.query("ROLLBACK");
      throw error;
    } finally { connection.release(); }
  }

  async recordAgentAccessTokenIssued(registrationId: string, issuedAt: Date): Promise<void> {
    await this.#pool.query(
      "UPDATE agent_registrations SET last_token_at = $2 WHERE registration_id = $1 AND revoked_at IS NULL",
      [registrationId, issuedAt]
    );
  }
}
