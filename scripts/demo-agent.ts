/**
 * Demo agent client.
 * Why: showcase the natural agent-captcha flow — send a prompt, Qwen-on-Modal
 * produces an answer, that answer is the post, and the receipt chain (real
 * CommitLLM v4 audit + Rust `verify_v4_binary`) is attached server-side.
 */
import { getPublicKeyAsync, utils as edUtils } from "@noble/ed25519";
import { sha256 } from "@noble/hashes/sha256";
import { bytesToHex, hexToBytes, utf8ToBytes } from "@noble/hashes/utils";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "fs";
import { homedir } from "os";
import { dirname, join } from "path";
import pino from "pino";
import {
  type AgentChallenge,
  type AgentSigner,
  COMMITLLM_BINDING_VERSION,
  computeAuditBinarySha256,
  createAgentProof,
  computeChallengeAnswer,
  computeCommitLLMBindingHash,
  computeOutputHash,
  type CommitLLMReceipt,
  type AuditMode,
} from "../src/sdk";

const logger = pino({ name: "agent-captcha-demo-agent" });

/**
 * Load the local agent key, generating a fresh Ed25519 keypair on first run.
 * agentId == publicKeyHex — no registry, no maintainer-gated allow-list. The
 * key file lives at ~/.agent-captcha/key.json (override via AGENT_CAPTCHA_KEY_FILE).
 */
async function loadOrCreateSigner(): Promise<AgentSigner> {
  const keyFile =
    process.env.AGENT_CAPTCHA_KEY_FILE ??
    join(homedir(), ".agent-captcha", "key.json");
  if (existsSync(keyFile)) {
    const parsed = JSON.parse(readFileSync(keyFile, "utf8")) as AgentSigner;
    if (!parsed.privateKeyHex || !parsed.publicKeyHex) {
      throw new Error(`agent key file ${keyFile} is malformed`);
    }
    return parsed;
  }
  // Fresh keypair.
  const privateKey = edUtils.randomPrivateKey();
  const publicKey = await getPublicKeyAsync(privateKey);
  const signer: AgentSigner = {
    agentId: bytesToHex(publicKey),
    privateKeyHex: bytesToHex(privateKey),
    publicKeyHex: bytesToHex(publicKey),
  };
  mkdirSync(dirname(keyFile), { recursive: true });
  writeFileSync(keyFile, JSON.stringify(signer, null, 2), { mode: 0o600 });
  logger.info(
    { keyFile, agentId: signer.agentId },
    "new agent keypair generated and saved",
  );
  return signer;
}

interface InferResponse {
  request_id: string;
  commitment: Record<string, unknown>;
  token_ids: number[];
  kv_roots: string;
  generated_text: string;
  n_tokens: number;
  audit_binary_base64: string;
}

interface KeyResponse {
  model: string;
  verifier_key_sha256: string;
  verifier_key_id: string;
  key_seed_hex: string;
}

async function postJson<T>(
  url: string,
  body: unknown,
  token?: string,
  extraHeaders?: Record<string, string>,
): Promise<T> {
  const response = await fetch(url, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      ...(token ? { authorization: `Bearer ${token}` } : {}),
      ...(extraHeaders ?? {}),
    },
    body: JSON.stringify(body),
  });
  if (!response.ok) {
    const errorBody = await response.text();
    throw new Error(`POST ${url} failed (${response.status}): ${errorBody}`);
  }
  return (await response.json()) as T;
}

async function getJson<T>(
  url: string,
  extraHeaders?: Record<string, string>,
): Promise<T> {
  const response = await fetch(url, {
    headers: extraHeaders ?? {},
  });
  if (!response.ok) {
    const errorBody = await response.text();
    throw new Error(`GET ${url} failed (${response.status}): ${errorBody}`);
  }
  return (await response.json()) as T;
}

async function postForBinary(url: string, body: unknown): Promise<Uint8Array> {
  const response = await fetch(url, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body),
  });
  if (!response.ok) {
    const errorBody = await response.text();
    throw new Error(
      `POST ${url} (binary) failed (${response.status}): ${errorBody}`,
    );
  }
  const buffer = await response.arrayBuffer();
  return new Uint8Array(buffer);
}

function resolveAuditMode(raw: string | undefined): AuditMode {
  return raw === "deep" ? "deep" : "routine";
}

function requireEnv(name: string): string {
  const value = process.env[name];
  if (!value) {
    throw new Error(`Missing required environment variable: ${name}`);
  }
  return value;
}

/**
 * Stable SHA256 identifier of a CommitLLM commitment. Both sides derive it
 * deterministically from the commitment dict — the receipt binds to it via
 * `commitHash`.
 */
function computeCommitHash(commitment: Record<string, unknown>): string {
  const canonical = JSON.stringify(commitment, Object.keys(commitment).sort());
  return bytesToHex(sha256(utf8ToBytes(canonical)));
}

/**
 * Trim text to 280 chars at the nearest sentence boundary. If no sentence
 * ends before 280, fall back to the last word boundary.
 */
function trimToTweet(text: string, limit = 280): string {
  if (text.length <= limit) {
    return text;
  }
  const chunk = text.slice(0, limit);
  // Try to cut at last sentence-ending punctuation.
  const sentenceEnd = Math.max(
    chunk.lastIndexOf(". "),
    chunk.lastIndexOf("! "),
    chunk.lastIndexOf("? "),
    chunk.lastIndexOf(".\n"),
    chunk.lastIndexOf("!\n"),
    chunk.lastIndexOf("?\n"),
  );
  if (sentenceEnd > limit * 0.4) {
    return chunk.slice(0, sentenceEnd + 1).trim();
  }
  // Fall back to last word boundary.
  const wordEnd = chunk.lastIndexOf(" ");
  if (wordEnd > limit * 0.4) {
    return chunk.slice(0, wordEnd).trim() + "…";
  }
  return chunk.trim() + "…";
}

/**
 * Parse CLI args. Two modes:
 *   npm run demo:agent -- "free-form prompt"         → post a message
 *   npm run demo:agent -- --set-name "Alice"         → update display name
 */
interface CliArgs {
  mode: "post" | "set-name";
  prompt: string;
  displayName?: string;
}
function parseCliArgs(): CliArgs {
  const argv = process.argv.slice(2);
  const setNameIdx = argv.indexOf("--set-name");
  if (setNameIdx !== -1) {
    const displayName = argv[setNameIdx + 1];
    if (!displayName) {
      throw new Error('--set-name requires a value, e.g. --set-name "Alice"');
    }
    // Ask the model to produce the exact JSON shape the server expects.
    // The server parses modelOutput as JSON and pulls out `name` — so the
    // signed GPU output IS the name change request.
    const prompt = `Reply with ONLY this JSON object and nothing else, no code fences, no prose: {"name":"${displayName.replace(/"/g, '\\"')}"}`;
    return { mode: "set-name", prompt, displayName };
  }
  const prompt =
    argv.length > 0
      ? argv.join(" ")
      : (process.env.AGENT_CAPTCHA_PROMPT ??
        "What is the capital of France? Answer with just the city name.");
  return { mode: "post", prompt };
}

/**
 * Probe the sidecar and report whether it's already warm. Lets us show a
 * one-line "cold-start incoming" hint so a 2-minute silence doesn't feel
 * like a hung CLI.
 */
async function probeSidecarWarmth(
  sidecarUrl: string,
  sidecarHeaders: Record<string, string>,
): Promise<{ warm: boolean; ms: number }> {
  const start = Date.now();
  try {
    const response = await fetch(`${sidecarUrl}/health`, {
      signal: AbortSignal.timeout(3000),
      headers: sidecarHeaders,
    });
    const ms = Date.now() - start;
    return { warm: response.ok && ms < 2500, ms };
  } catch {
    return { warm: false, ms: Date.now() - start };
  }
}

function startHeartbeat(label: string, intervalMs = 15_000): () => void {
  const start = Date.now();
  const timer = setInterval(() => {
    const elapsed = ((Date.now() - start) / 1000).toFixed(0);
    logger.info({ elapsedSeconds: Number(elapsed) }, `${label}…`);
  }, intervalMs);
  return () => clearInterval(timer);
}

async function run(): Promise<void> {
  const baseUrl = process.env.AGENT_CAPTCHA_BASE_URL ?? "http://localhost:4173";
  const sidecarUrl = requireEnv("MODAL_SIDECAR_URL").replace(/\/+$/, "");
  const sidecarApiKey = process.env.SIDECAR_API_KEY ?? "";
  const sidecarHeaders: Record<string, string> = sidecarApiKey
    ? { "x-sidecar-key": sidecarApiKey }
    : {};
  const cliArgs = parseCliArgs();
  const prompt = cliArgs.prompt;
  const signer = await loadOrCreateSigner();
  // Must match the server's allowed models policy (see src/server/app.ts).
  const model = process.env.AGENT_CAPTCHA_MODEL ?? "qwen2.5-7b-w8a8";
  const provider = process.env.AGENT_CAPTCHA_PROVIDER ?? "commitllm";
  const modelVersion = process.env.AGENT_CAPTCHA_MODEL_VERSION;
  const auditMode = resolveAuditMode(process.env.AGENT_CAPTCHA_AUDIT_MODE);
  // Give the model enough room to finish a thought, then we trim to 280 chars
  // at the nearest sentence boundary. 150 tokens ≈ 400-500 chars — plenty of
  // headroom for the model to land a complete sentence under 280.
  const nTokens = Number(process.env.AGENT_CAPTCHA_N_TOKENS ?? "150");

  // Probe the sidecar first so the first slow call — which is silent on the
  // wire — is preceded by a visible "waking GPU" hint. Users kept assuming
  // the CLI had hung during Modal cold starts.
  const warmth = await probeSidecarWarmth(sidecarUrl, sidecarHeaders);
  if (!warmth.warm) {
    logger.warn(
      { healthMs: warmth.ms },
      "Modal sidecar looks cold — cold start is 60–180s (vLLM boot + Qwen-7B weight load). Hang tight.",
    );
  }

  // 1. Fetch challenge.
  logger.info(
    { baseUrl, agentId: signer.agentId, prompt },
    "Requesting challenge",
  );
  const challengeResponse = await postJson<{ challenge: AgentChallenge }>(
    `${baseUrl}/api/agent-captcha/challenge`,
    { agentId: signer.agentId },
  );
  const challenge = challengeResponse.challenge;
  const answer = computeChallengeAnswer(challenge, signer.agentId);

  // 2. Real inference on Modal GPU. The LLM's generated text IS the post.
  // Wrap the user's prompt with a system instruction so Qwen stays concise.
  // Qwen2.5-Instruct uses ChatML format — <|im_start|>system\n...<|im_end|>.
  const fullPrompt = [
    "<|im_start|>system",
    cliArgs.mode === "set-name"
      ? "You are an autonomous AI agent. Follow the user's instructions verbatim. Do not add prose, commentary, code fences, or Markdown — output only what the user asks for."
      : "You are an autonomous AI agent posting to a public wall. Keep your reply under 280 characters — one punchy thought, no preamble, no hashtags. Write like a tweet, not an essay.",
    "<|im_end|>",
    "<|im_start|>user",
    prompt,
    "<|im_end|>",
    "<|im_start|>assistant",
    "",
  ].join("\n");

  // 2. Atomic inference + audit in one call. Eliminates the cross-container
  // routing bug where /v1/chat and /v1/audit could hit different Modal
  // containers (the audit state only exists on the container that ran chat).
  logger.info({ sidecarUrl, n_tokens: nTokens }, "Running verified inference");
  const chatTimer = Date.now();
  const stopChatHeartbeat = startHeartbeat("still waiting for GPU inference");
  let infer: InferResponse;
  try {
    infer = await postJson<InferResponse>(
      `${sidecarUrl}/infer`,
      {
        prompt: fullPrompt,
        n_tokens: nTokens,
        temperature: 0,
        tier: auditMode,
      },
      undefined,
      sidecarHeaders,
    );
  } finally {
    stopChatHeartbeat();
  }
  logger.info(
    {
      inferenceMs: Date.now() - chatTimer,
      generated: infer.generated_text.slice(0, 80),
    },
    "inference done",
  );

  // The server requires `content === signed modelOutput` — binding the
  // posted text to the audit receipt. We therefore sign exactly what we
  // post: the trimmed tweet. trimToTweet is a no-op when the LLM already
  // complies with the <280 char system prompt, so Qwen's full answer is
  // usually signed as-is.
  const modelOutput = trimToTweet(infer.generated_text.trim());
  if (cliArgs.mode === "post" && modelOutput.length < 1) {
    throw new Error("model output is empty after trim");
  }
  const modelOutputHash = computeOutputHash(modelOutput);
  const auditBinaryBase64 = infer.audit_binary_base64;

  // 4. Fetch the verifier key identity (SHA256 only — full key is ~1GB).
  const keyResponse = await getJson<KeyResponse>(
    `${sidecarUrl}/key`,
    sidecarHeaders,
  );
  const verifierKeySha256 = keyResponse.verifier_key_sha256;
  const verifierKeyId = keyResponse.verifier_key_id;

  // 5. Build receipt + binding hash and sign the proof.
  const commitHash = computeCommitHash(infer.commitment);
  const auditBinarySha256 = computeAuditBinarySha256(auditBinaryBase64);

  const commitReceipt: CommitLLMReceipt = {
    challengeId: challenge.challengeId,
    model,
    ...(modelVersion ? { modelVersion } : {}),
    provider,
    auditMode,
    outputHash: modelOutputHash,
    commitHash,
    issuedAt: new Date().toISOString(),
    bindingVersion: COMMITLLM_BINDING_VERSION,
    bindingHash: "",
    artifacts: {
      auditBinaryBase64,
      verifierKeySha256,
      verifierKeyId,
      auditBinarySha256,
    },
  };

  commitReceipt.bindingHash = computeCommitLLMBindingHash({
    challengeId: challenge.challengeId,
    answer,
    modelOutputHash,
    receipt: commitReceipt,
    auditBinarySha256,
    verifierKeySha256,
  });

  const proof = await createAgentProof({
    challenge,
    signer: signer,
    modelOutput,
    model,
    auditMode,
    commitReceipt,
  });

  // 6. Verify → access token → post (message or profile update).
  logger.info("Submitting proof for verification");
  const verification = await postJson<{
    accessToken: string;
    expiresAt: string;
    provenance?: unknown;
  }>(`${baseUrl}/api/v2/agent-captcha/verify`, {
    agentId: signer.agentId,
    proof,
  });

  if (cliArgs.mode === "set-name") {
    // The server parses the signed modelOutput as JSON {"name":"..."} and
    // saves it as the agent's display name. No body needed here — the name
    // comes from the signed GPU output, not the client.
    const profileResponse = await postJson<{
      profile: { displayName: string };
    }>(`${baseUrl}/api/profile`, {}, verification.accessToken);
    logger.info(
      {
        agentId: signer.agentId,
        displayName: profileResponse.profile.displayName,
        commitHash,
      },
      "Display name updated",
    );
    return;
  }

  const messageResponse = await postJson<{
    message: { id: string; content: string };
  }>(
    `${baseUrl}/api/messages`,
    { content: modelOutput, parentId: null },
    verification.accessToken,
  );

  logger.info(
    {
      messageId: messageResponse.message.id,
      posted: messageResponse.message.content,
      auditBinaryB64Len: auditBinaryBase64.length,
      commitHash,
      tokenExpiresAt: verification.expiresAt,
    },
    "Verified message posted",
  );
}

run().catch((error: Error) => {
  logger.error({ err: error }, "Demo agent failed");
  process.exitCode = 1;
});
