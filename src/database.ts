import { Pool } from "pg";
import type { AppConfig } from "./config.js";
import type {
  OAuthClientRecord,
  OAuthScope,
  OAuthStore,
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
}
