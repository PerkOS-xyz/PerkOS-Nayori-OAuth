import { serve } from "@hono/node-server";
import { createApp } from "./app.js";
import { loadConfig } from "./config.js";
import { PostgresOAuthStore } from "./database.js";
import { consoleLogger } from "./logger.js";
import { createOAuthService, createOAuthSigner } from "./oauth.js";

const config = loadConfig();
const store = new PostgresOAuthStore(config);
const signer = await createOAuthSigner(config);
const oauth = createOAuthService({ config, store, signer });
const app = createApp({ config, store, oauth, logger: consoleLogger });
const server = serve({ fetch: app.fetch, hostname: config.host, port: config.port }, (info) => {
  consoleLogger.info({ event: "server_started", address: info.address, port: info.port,
    issuer: config.issuerOrigin, resource: config.resourceOrigin, release: config.releaseSha,
    partnerRegistrationEnabled: config.partnerRegistrationEnabled });
});

let shuttingDown = false;
async function shutdown(signal: NodeJS.Signals): Promise<void> {
  if (shuttingDown) return;
  shuttingDown = true;
  consoleLogger.info({ event: "server_stopping", signal });
  await new Promise<void>((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
  await store.close();
  consoleLogger.info({ event: "server_stopped" });
}
for (const signal of ["SIGINT", "SIGTERM"] as const) {
  process.once(signal, () => { void shutdown(signal).catch((error: unknown) => {
    consoleLogger.error({ event: "shutdown_failed", signal, errorName: error instanceof Error ? error.name : "UnknownError" });
    process.exitCode = 1;
  }); });
}
