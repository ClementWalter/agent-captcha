/**
 * API entrypoint.
 * Why: keep runtime wiring separate from pure app construction for easier testing.
 * The store health check runs before listen() so a misconfigured container
 * fails the Scaleway health probe and never serves a silent empty thread.
 */
import pino from "pino";
import { createApp } from "./app";
import { createMessageStoreFromEnv } from "./messageStore";
import { createProfileStoreFromEnv } from "./profileStore";

const logger = pino({ name: "agent-captcha-runtime" });

async function main(): Promise<void> {
  const port = Number(process.env.PORT ?? "4173");

  const messageStore = createMessageStoreFromEnv();
  const profileStore = createProfileStoreFromEnv();
  try {
    await Promise.all([messageStore.healthCheck(), profileStore.healthCheck()]);
    logger.info("object storage reachable");
  } catch (error) {
    logger.fatal({ err: error }, "object storage health check failed — refusing to start");
    process.exit(1);
  }

  const { app } = createApp({
    ...(process.env.AGENT_CAPTCHA_ACCESS_TOKEN_SECRET
      ? { accessTokenSecret: process.env.AGENT_CAPTCHA_ACCESS_TOKEN_SECRET }
      : {}),
    messageStore,
    profileStore
  });

  app.listen(port, () => {
    logger.info({ port }, "agent-captcha demo API listening");
  });
}

main().catch((error) => {
  logger.fatal({ err: error }, "startup failed");
  process.exit(1);
});
