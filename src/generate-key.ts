import { randomBytes } from "node:crypto";
import { exportJWK, generateKeyPair } from "jose";

const keyId = process.env.OAUTH_KEY_ID?.trim() || `no_${Date.now()}_${randomBytes(6).toString("base64url")}`;
if (!/^[A-Za-z0-9._:-]{1,128}$/.test(keyId)) throw new Error("OAUTH_KEY_ID must contain 1-128 safe identifier characters.");
const { privateKey, publicKey } = await generateKeyPair("EdDSA", { crv: "Ed25519", extractable: true });
console.log(JSON.stringify({
  warning: "Store privateJwk only in the VPS OAuth secret configuration. Never commit it or reuse another Nayori key.",
  privateJwk: { ...(await exportJWK(privateKey)), kid: keyId, alg: "EdDSA", use: "sig" },
  publicJwk: { ...(await exportJWK(publicKey)), kid: keyId, alg: "EdDSA", use: "sig" }
}, null, 2));
