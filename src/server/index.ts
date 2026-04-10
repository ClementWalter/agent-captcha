/**
 * API entrypoint.
 * Why: Keep runtime wiring separate from pure app construction for easier testing.
 */
import pino from "pino";
import { createApp, type RegisteredAgent } from "./app";

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

const port = Number(process.env.PORT ?? "4173");
const registeredAgents = parseRegisteredAgents(process.env.AGENT_CAPTCHA_REGISTERED_AGENTS);

const { app } = createApp({
  ...(process.env.AGENT_CAPTCHA_ACCESS_TOKEN_SECRET
    ? { accessTokenSecret: process.env.AGENT_CAPTCHA_ACCESS_TOKEN_SECRET }
    : {}),
  ...(registeredAgents ? { registeredAgents } : {})
});

app.listen(port, () => {
  logger.info({ port }, "agent-captcha demo API listening");
});
