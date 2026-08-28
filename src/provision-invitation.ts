import { loadConfig } from "./config.js";
import { PostgresOAuthStore } from "./database.js";
import { createInvitationRecord } from "./oauth.js";
import { oauthScopes, type OAuthScope } from "./store.js";

const merchantId = process.env.PARTNER_MERCHANT_ID?.trim();
if (!merchantId || !/^[A-Za-z0-9._:-]{1,64}$/.test(merchantId)) {
  throw new Error("PARTNER_MERCHANT_ID must contain 1-64 safe identifier characters.");
}
const scopes = (process.env.PARTNER_SCOPES ?? "").split(" ").map((value) => value.trim()).filter(Boolean);
if (scopes.length === 0 || new Set(scopes).size !== scopes.length ||
    scopes.some((scope) => !oauthScopes.includes(scope as OAuthScope))) {
  throw new Error(`PARTNER_SCOPES must be a unique space-separated subset of: ${oauthScopes.join(" ")}`);
}
const ttl = Number(process.env.PARTNER_INVITATION_TTL_SECONDS ?? "86400");
if (!Number.isSafeInteger(ttl) || ttl < 300 || ttl > 604_800) {
  throw new Error("PARTNER_INVITATION_TTL_SECONDS must be an integer between 300 and 604800.");
}
const config = loadConfig();
const store = new PostgresOAuthStore(config);
try {
  const invitation = createInvitationRecord({ merchantId, scopes: scopes as OAuthScope[],
    expiresAt: new Date(Date.now() + ttl * 1_000) });
  await store.insertPartnerInvitation(invitation.record);
  console.log(JSON.stringify({
    warning: "This invitation is shown once. Confirm the merchant exists in Platform, then use a private channel.",
    invitationToken: invitation.token,
    merchantId,
    scopes,
    expiresAt: invitation.record.expiresAt.toISOString()
  }, null, 2));
} finally { await store.close(); }
