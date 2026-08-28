import { randomUUID } from "node:crypto";
import { Hono } from "hono";
import type { AppConfig } from "./config.js";
import {
  SERVICE_NAME,
  createAuthMarkdown,
  createAuthorizationServerMetadata,
  createProtectedResourceMetadata,
  createSupportedDocument
} from "./documents.js";
import type { AppLogger } from "./logger.js";
import { OAuthServiceError, type OAuthService } from "./oauth.js";
import { createFixedWindowRateLimiter, type RateLimiter } from "./rate-limit.js";
import type { OAuthStore } from "./store.js";

type Variables = { requestId: string };
const MAX_JSON_BYTES = 32_768;
const MAX_FORM_BYTES = 8_192;
const SAFE_REQUEST_ID = /^[A-Za-z0-9._:-]{1,64}$/;

function clientKey(headers: Headers): string {
  return headers.get("cf-connecting-ip") ?? headers.get("x-real-ip") ?? "unknown";
}

async function readBody(request: Request, maximum: number): Promise<string> {
  const declared = Number(request.headers.get("content-length") ?? "0");
  if (Number.isFinite(declared) && declared > maximum) throw new Error("body_too_large");
  const body = await request.text();
  if (Buffer.byteLength(body, "utf8") > maximum) throw new Error("body_too_large");
  return body;
}

function oauthError(error: OAuthServiceError, requestId: string) {
  return { error: error.code, error_description: error.publicMessage, request_id: requestId };
}

export function createApp(options: {
  readonly config: AppConfig;
  readonly store: OAuthStore;
  readonly oauth: OAuthService;
  readonly logger: AppLogger;
  readonly tokenLimiter?: RateLimiter;
  readonly registrationLimiter?: RateLimiter;
  readonly now?: () => number;
}) {
  const { config, store, oauth, logger } = options;
  const now = options.now ?? (() => Date.now());
  const tokenLimiter = options.tokenLimiter ?? createFixedWindowRateLimiter(config.tokenRateLimitPerMinute);
  const registrationLimiter = options.registrationLimiter ?? createFixedWindowRateLimiter(config.registrationRateLimitPerMinute);
  const app = new Hono<{ Variables: Variables }>();

  app.use("*", async (context, next) => {
    const suppliedRequestId = context.req.header("x-request-id");
    const requestId = suppliedRequestId && SAFE_REQUEST_ID.test(suppliedRequestId) ? suppliedRequestId : randomUUID();
    const startedAt = performance.now();
    context.set("requestId", requestId);
    context.header("x-request-id", requestId);
    context.header("x-content-type-options", "nosniff");
    context.header("x-frame-options", "DENY");
    context.header("referrer-policy", "no-referrer");
    context.header("cache-control", "no-store");
    if (config.nodeEnvironment === "production") {
      context.header("strict-transport-security", "max-age=31536000");
    }
    try { await next(); }
    finally {
      logger.info({ event: "http_request", requestId, method: context.req.method,
        path: context.req.path, status: context.res.status,
        durationMs: Math.round((performance.now() - startedAt) * 100) / 100 });
    }
  });

  app.use("*", async (context, next) => {
    const requestOrigin = context.req.header("origin");
    if (!requestOrigin) { await next(); return; }
    if (!config.corsAllowedOrigins.includes(requestOrigin)) {
      if (context.req.method === "OPTIONS") {
        context.res = context.json({ error: "origin_not_allowed", request_id: context.get("requestId") }, 403);
        return;
      }
      await next();
      return;
    }
    context.header("access-control-allow-origin", requestOrigin);
    context.header("vary", "Origin");
    context.header("access-control-expose-headers", "x-request-id");
    if (context.req.method === "OPTIONS") {
      context.header("access-control-allow-methods", "GET, POST, OPTIONS");
      context.header("access-control-allow-headers", "authorization, content-type, x-request-id");
      context.header("access-control-max-age", "600");
      context.res = new Response(null, { status: 204, headers: context.res.headers });
      return;
    }
    await next();
  });

  app.get("/health", (context) => context.json({ status: "ok", service: SERVICE_NAME, release: config.releaseSha }));
  app.get("/ready", async (context) => {
    try { await store.ping(); return context.json({ status: "ready", database: "available", release: config.releaseSha }); }
    catch { return context.json({ status: "not_ready", database: "unavailable", release: config.releaseSha }, 503); }
  });
  app.get("/supported", (context) => context.json(createSupportedDocument(config)));
  app.get("/.well-known/oauth-authorization-server", (context) => {
    context.header("cache-control", "public, max-age=300");
    return context.json(createAuthorizationServerMetadata(config));
  });
  app.get("/.well-known/oauth-protected-resource", (context) => {
    context.header("cache-control", "public, max-age=300");
    return context.json(createProtectedResourceMetadata(config));
  });
  app.get("/oauth/jwks.json", (context) => {
    context.header("cache-control", "public, max-age=300, stale-while-revalidate=3600");
    return context.json(oauth.publicJwks);
  });
  app.get("/auth.md", (context) => {
    context.header("cache-control", "public, max-age=300");
    return context.text(createAuthMarkdown(config), 200, { "content-type": "text/markdown; charset=UTF-8" });
  });

  app.post("/oauth/token", async (context) => {
    if (!tokenLimiter.consume(clientKey(context.req.raw.headers), now())) {
      context.header("retry-after", "60");
      return context.json({ error: "temporarily_unavailable", error_description: "Rate limit exceeded.",
        request_id: context.get("requestId") }, 429);
    }
    try {
      if (!context.req.header("content-type")?.toLowerCase().startsWith("application/x-www-form-urlencoded")) {
        throw new OAuthServiceError("invalid_request", "The token request must use application/x-www-form-urlencoded.", 400);
      }
      const body = await readBody(context.req.raw, MAX_FORM_BYTES);
      const token = await oauth.issueToken(context.req.header("authorization"), new URLSearchParams(body));
      logger.info({ event: "oauth_token_issued", requestId: context.get("requestId") });
      return context.json(token);
    } catch (error) {
      if (!(error instanceof OAuthServiceError)) {
        return context.json({ error: "invalid_request", error_description: "The token request is invalid.",
          request_id: context.get("requestId") }, 400);
      }
      if (error.status === 401) context.header("www-authenticate", 'Basic realm="nayori-oauth"');
      return context.json(oauthError(error, context.get("requestId")), error.status);
    }
  });

  if (config.partnerRegistrationEnabled) {
    app.post("/v1/partners/challenges", async (context) => {
      if (!registrationLimiter.consume(clientKey(context.req.raw.headers), now())) {
        context.header("retry-after", "60");
        return context.json({ error: "rate_limited", message: "Rate limit exceeded.", request_id: context.get("requestId") }, 429);
      }
      try {
        const input = JSON.parse(await readBody(context.req.raw, MAX_JSON_BYTES)) as unknown;
        return context.json({ challenge: await oauth.issueChallenge(input) }, 201);
      } catch (error) {
        if (!(error instanceof OAuthServiceError)) {
          return context.json({ error: "invalid_request", message: "The challenge request must be valid JSON.",
            request_id: context.get("requestId") }, 400);
        }
        return context.json({ error: error.code, message: error.publicMessage,
          request_id: context.get("requestId") }, error.status);
      }
    });
    app.post("/v1/partners/register", async (context) => {
      if (!registrationLimiter.consume(clientKey(context.req.raw.headers), now())) {
        context.header("retry-after", "60");
        return context.json({ error: "rate_limited", message: "Rate limit exceeded.", request_id: context.get("requestId") }, 429);
      }
      try {
        const input = JSON.parse(await readBody(context.req.raw, MAX_JSON_BYTES)) as unknown;
        return context.json({ client: await oauth.register(input) }, 201);
      } catch (error) {
        if (!(error instanceof OAuthServiceError)) {
          return context.json({ error: "invalid_request", message: "The registration request must be valid JSON.",
            request_id: context.get("requestId") }, 400);
        }
        return context.json({ error: error.code, message: error.publicMessage,
          request_id: context.get("requestId") }, error.status);
      }
    });
  }

  app.notFound((context) => context.json({ error: "not_found", request_id: context.get("requestId") }, 404));
  app.onError((error, context) => {
    logger.error({ event: "request_failed", requestId: context.get("requestId"), errorName: error.name });
    return context.json({ error: "internal_error", request_id: context.get("requestId") }, 500);
  });
  return app;
}
