/**
 * API entrypoint.
 * Why: Keep runtime wiring separate from pure app construction for easier testing.
 * The store health check runs before listen() so a misconfigured container
 * fails the Scaleway health probe and never serves a silent empty thread.
 */
import pino from "pino";
import { createApp, type RegisteredAgent } from "./app";
import { createMessageStoreFromEnv } from "./messageStore";

const logger = pino({ name: "agent-captcha-runtime" });

function parseRegisteredAgents(raw: string | undefined): RegisteredAgent[] | undefined {
  if (!raw) {
    return undefined;
  }

  try {
    const parsed = JSON.parse(raw) as RegisteredAgent[];
    return parsed;
  } catch {
    logger.warn("Failed to parse AGENT_CAPTCHA_REGISTERED_AGENTS, using defaults");
    return undefined;
  }
}

async function main(): Promise<void> {
  const port = Number(process.env.PORT ?? "4173");
  const registeredAgents = parseRegisteredAgents(process.env.AGENT_CAPTCHA_REGISTERED_AGENTS);

  // Construct the store explicitly first so we can run a startup probe before
  // taking any traffic. If S3 is misconfigured, we exit 1 — Scaleway's health
  // check will fail the deploy instead of letting a stateless container serve
  // an empty thread.
  const messageStore = createMessageStoreFromEnv();
  try {
    await messageStore.healthCheck();
    logger.info("message store reachable");
  } catch (error) {
    logger.fatal({ err: error }, "message store health check failed — refusing to start");
    process.exit(1);
  }

  const { app } = createApp({
    ...(process.env.AGENT_CAPTCHA_ACCESS_TOKEN_SECRET
      ? { accessTokenSecret: process.env.AGENT_CAPTCHA_ACCESS_TOKEN_SECRET }
      : {}),
    ...(registeredAgents ? { registeredAgents } : {}),
    messageStore
  });

  app.listen(port, () => {
    logger.info({ port }, "agent-captcha demo API listening");
  });
}

main().catch((error) => {
  logger.fatal({ err: error }, "startup failed");
  process.exit(1);
});
