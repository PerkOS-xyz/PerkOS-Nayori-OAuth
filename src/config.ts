import { z } from "zod";

const postgresUrl = z.string().min(1).superRefine((value, context) => {
  try {
    const protocol = new URL(value).protocol;
    if (protocol !== "postgres:" && protocol !== "postgresql:") {
      context.addIssue({ code: "custom", message: "DATABASE_URL must use postgres:// or postgresql://." });
    }
  } catch {
    context.addIssue({ code: "custom", message: "DATABASE_URL must be a valid URL." });
  }
});

const origin = z.url().transform((value) => value.replace(/\/$/, ""));
const originList = z.string().default("https://nayori.ai,https://app.nayori.ai,https://docs.nayori.ai")
  .transform((value, context) => {
    const values = value.split(",").map((item) => item.trim().replace(/\/$/, "")).filter(Boolean);
    if (values.length === 0 || new Set(values).size !== values.length ||
        values.some((item) => { try { return !["http:", "https:"].includes(new URL(item).protocol); } catch { return true; } })) {
      context.addIssue({ code: "custom", message: "CORS_ALLOWED_ORIGINS must be a unique comma-separated URL list." });
      return z.NEVER;
    }
    return values;
  });
const flag = z.enum(["true", "false", "1", "0"]).default("false")
  .transform((value) => value === "true" || value === "1");

const schema = z.object({
  NODE_ENV: z.enum(["development", "test", "production"]).default("development"),
  HOST: z.string().min(1).default("0.0.0.0"),
  PORT: z.coerce.number().int().min(1).max(65_535).default(8080),
  ISSUER_ORIGIN: origin.default("https://oauth.nayori.ai"),
  RESOURCE_ORIGIN: origin.default("https://nayori.ai"),
  API_ORIGIN: origin.default("https://api.nayori.ai"),
  RELEASE_SHA: z.string().min(1).max(128).default("development"),
  LOG_LEVEL: z.enum(["debug", "info", "warn", "error"]).default("info"),
  CORS_ALLOWED_ORIGINS: originList,
  DATABASE_URL: postgresUrl,
  DATABASE_SSL: z.enum(["disable", "require"]).default("disable"),
  DATABASE_POOL_MAX: z.coerce.number().int().min(1).max(50).default(10),
  DATABASE_CONNECT_TIMEOUT_MS: z.coerce.number().int().min(250).max(30_000).default(5_000),
  DATABASE_QUERY_TIMEOUT_MS: z.coerce.number().int().min(250).max(60_000).default(10_000),
  STACKS_NETWORK: z.enum(["testnet", "mainnet"]).default("testnet"),
  PARTNER_REGISTRATION_ENABLED: flag,
  PARTNER_CHALLENGE_TTL_SECONDS: z.coerce.number().int().min(60).max(600).default(300),
  OAUTH_ACCESS_TOKEN_TTL_SECONDS: z.coerce.number().int().min(60).max(900).default(300),
  TOKEN_RATE_LIMIT_PER_MINUTE: z.coerce.number().int().min(1).max(10_000).default(60),
  REGISTRATION_RATE_LIMIT_PER_MINUTE: z.coerce.number().int().min(1).max(10_000).default(30),
  OAUTH_SIGNING_PRIVATE_JWK_JSON: z.string().min(1),
  OAUTH_PREVIOUS_PUBLIC_JWKS_JSON: z.string().min(1).default('{"keys":[]}')
}).superRefine((value, context) => {
  if (value.NODE_ENV === "production") {
    for (const [field, originValue] of [
      ["ISSUER_ORIGIN", value.ISSUER_ORIGIN],
      ["RESOURCE_ORIGIN", value.RESOURCE_ORIGIN],
      ["API_ORIGIN", value.API_ORIGIN]
    ] as const) {
      if (new URL(originValue).protocol !== "https:") {
        context.addIssue({ code: "custom", path: [field], message: `${field} must use HTTPS in production.` });
      }
    }
  }
  if (value.ISSUER_ORIGIN === value.RESOURCE_ORIGIN || value.ISSUER_ORIGIN === value.API_ORIGIN) {
    context.addIssue({
      code: "custom",
      path: ["ISSUER_ORIGIN"],
      message: "The OAuth issuer must be separate from the canonical resource and API origins."
    });
  }
});

export type AppConfig = {
  readonly nodeEnvironment: "development" | "test" | "production";
  readonly host: string;
  readonly port: number;
  readonly issuerOrigin: string;
  readonly resourceOrigin: string;
  readonly apiOrigin: string;
  readonly releaseSha: string;
  readonly logLevel: "debug" | "info" | "warn" | "error";
  readonly corsAllowedOrigins: readonly string[];
  readonly databaseUrl: string;
  readonly databaseSsl: "disable" | "require";
  readonly databasePoolMax: number;
  readonly databaseConnectTimeoutMs: number;
  readonly databaseQueryTimeoutMs: number;
  readonly stacksNetwork: "testnet" | "mainnet";
  readonly partnerRegistrationEnabled: boolean;
  readonly partnerChallengeTtlSeconds: number;
  readonly oauthAccessTokenTtlSeconds: number;
  readonly tokenRateLimitPerMinute: number;
  readonly registrationRateLimitPerMinute: number;
  readonly oauthSigningPrivateJwkJson: string;
  readonly oauthPreviousPublicJwksJson: string;
};

export function loadConfig(environment: NodeJS.ProcessEnv = process.env): AppConfig {
  const value = schema.parse(environment);
  return {
    nodeEnvironment: value.NODE_ENV,
    host: value.HOST,
    port: value.PORT,
    issuerOrigin: value.ISSUER_ORIGIN,
    resourceOrigin: value.RESOURCE_ORIGIN,
    apiOrigin: value.API_ORIGIN,
    releaseSha: value.RELEASE_SHA,
    logLevel: value.LOG_LEVEL,
    corsAllowedOrigins: value.CORS_ALLOWED_ORIGINS,
    databaseUrl: value.DATABASE_URL,
    databaseSsl: value.DATABASE_SSL,
    databasePoolMax: value.DATABASE_POOL_MAX,
    databaseConnectTimeoutMs: value.DATABASE_CONNECT_TIMEOUT_MS,
    databaseQueryTimeoutMs: value.DATABASE_QUERY_TIMEOUT_MS,
    stacksNetwork: value.STACKS_NETWORK,
    partnerRegistrationEnabled: value.PARTNER_REGISTRATION_ENABLED,
    partnerChallengeTtlSeconds: value.PARTNER_CHALLENGE_TTL_SECONDS,
    oauthAccessTokenTtlSeconds: value.OAUTH_ACCESS_TOKEN_TTL_SECONDS,
    tokenRateLimitPerMinute: value.TOKEN_RATE_LIMIT_PER_MINUTE,
    registrationRateLimitPerMinute: value.REGISTRATION_RATE_LIMIT_PER_MINUTE,
    oauthSigningPrivateJwkJson: value.OAUTH_SIGNING_PRIVATE_JWK_JSON,
    oauthPreviousPublicJwksJson: value.OAUTH_PREVIOUS_PUBLIC_JWKS_JSON
  };
}
