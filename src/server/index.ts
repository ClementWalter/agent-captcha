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
    logger.fatal(
      { err: error },
      "object storage health check failed — refusing to start",
    );
    process.exit(1);
  }

  // The token secret must be provided by the deployment. No default fallback:
  // shipping with a public literal meant every HMAC-signed token was forgeable
  // (pre-prod audit finding #1). Refuse to boot if it's missing or too short.
  const accessTokenSecret = process.env.AGENT_CAPTCHA_ACCESS_TOKEN_SECRET;
  if (!accessTokenSecret || accessTokenSecret.length < 32) {
    logger.fatal(
      "AGENT_CAPTCHA_ACCESS_TOKEN_SECRET is required and must be >= 32 chars",
    );
    process.exit(1);
  }

  const allowedOriginsEnv = process.env.AGENT_CAPTCHA_ALLOWED_ORIGINS?.trim();
  const allowedOrigins = allowedOriginsEnv
    ? allowedOriginsEnv
        .split(",")
        .map((o) => o.trim())
        .filter(Boolean)
    : undefined;

  const { app, init } = createApp({
    accessTokenSecret,
    ...(allowedOrigins ? { allowedOrigins } : {}),
    messageStore,
    profileStore,
  });

  await init();

  app.listen(port, () => {
    logger.info({ port }, "agent-captcha demo API listening");
  });

  // Keep the Modal CommitLLM sidecar warm during launch windows. Modal's
  // scaledown_window is 5 min — pinging /health every 4 min keeps the
  // container alive without invoking the GPU path. Disable by setting
  // MODAL_KEEPWARM_DISABLE=1 once the launch spike passes.
  const sidecarUrl = process.env.MODAL_SIDECAR_URL;
  if (sidecarUrl && process.env.MODAL_KEEPWARM_DISABLE !== "1") {
    const tick = async () => {
      try {
        const response = await fetch(
          `${sidecarUrl.replace(/\/+$/, "")}/health`,
          {
            signal: AbortSignal.timeout(10_000),
          },
        );
        if (!response.ok) {
          logger.warn({ status: response.status }, "modal keep-warm non-200");
        }
      } catch (error) {
        logger.warn({ err: error }, "modal keep-warm ping failed");
      }
    };
    void tick();
    setInterval(tick, 4 * 60 * 1000);
  }
}

main().catch((error) => {
  logger.fatal({ err: error }, "startup failed");
  process.exit(1);
});
