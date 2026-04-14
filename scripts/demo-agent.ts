/**
 * Demo agent client.
 * Why: showcase the natural agent-captcha flow — send a prompt, Qwen-on-Modal
 * produces an answer, that answer is the post, and the receipt chain (real
 * CommitLLM v4 audit + Rust `verify_v4_binary`) is attached server-side.
 */
import { sha256 } from "@noble/hashes/sha256";
import { bytesToHex, utf8ToBytes } from "@noble/hashes/utils";
import pino from "pino";
import {
  type AgentChallenge,
  COMMITLLM_BINDING_VERSION,
  computeAuditBinarySha256,
  createAgentProof,
  computeChallengeAnswer,
  computeCommitLLMBindingHash,
  computeOutputHash,
  type CommitLLMReceipt,
  type AuditMode
} from "../src/sdk";

const logger = pino({ name: "agent-captcha-demo-agent" });

// Demo key pair pre-registered on the server.
const demoSigner = {
  agentId: "demo-agent-001",
  privateKeyHex: "1f1e1d1c1b1a19181716151413121110f0e0d0c0b0a090807060504030201000",
  publicKeyHex: "b7a238dbf5a793f066a95e25d401f3557c6f8e38aeb11e0529861285bc051fd2"
};

interface ChatResponse {
  request_id: string;
  commitment: Record<string, unknown>;
  token_ids: number[];
  kv_roots: string;
  generated_text: string;
  n_tokens: number;
}

interface KeyResponse {
  model: string;
  verifier_key_sha256: string;
  verifier_key_id: string;
  key_seed_hex: string;
}

async function postJson<T>(url: string, body: unknown, token?: string): Promise<T> {
  const response = await fetch(url, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      ...(token ? { authorization: `Bearer ${token}` } : {})
    },
    body: JSON.stringify(body)
  });
  if (!response.ok) {
    const errorBody = await response.text();
    throw new Error(`POST ${url} failed (${response.status}): ${errorBody}`);
  }
  return (await response.json()) as T;
}

async function getJson<T>(url: string): Promise<T> {
  const response = await fetch(url);
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
    body: JSON.stringify(body)
  });
  if (!response.ok) {
    const errorBody = await response.text();
    throw new Error(`POST ${url} (binary) failed (${response.status}): ${errorBody}`);
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
 * Extract the first CLI positional argument as the prompt, fall back to env,
 * fall back to a sensible demo question. Anything after `--` is treated as
 * one prompt string so you can write `npm run demo:agent -- What is 2+2?`.
 */
function resolvePrompt(): string {
  const argv = process.argv.slice(2);
  if (argv.length > 0) {
    return argv.join(" ");
  }
  return process.env.AGENT_CAPTCHA_PROMPT ?? "What is the capital of France? Answer with just the city name.";
}

/**
 * Probe the sidecar and report whether it's already warm. Lets us show a
 * one-line "cold-start incoming" hint so a 2-minute silence doesn't feel
 * like a hung CLI.
 */
async function probeSidecarWarmth(sidecarUrl: string): Promise<{ warm: boolean; ms: number }> {
  const start = Date.now();
  try {
    const response = await fetch(`${sidecarUrl}/health`, { signal: AbortSignal.timeout(3000) });
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
  const prompt = resolvePrompt();
  // Must match the server's allowed models policy (see src/server/app.ts).
  const model = process.env.AGENT_CAPTCHA_MODEL ?? "qwen2.5-7b-w8a8";
  const provider = process.env.AGENT_CAPTCHA_PROVIDER ?? "commitllm";
  const modelVersion = process.env.AGENT_CAPTCHA_MODEL_VERSION;
  const auditMode = resolveAuditMode(process.env.AGENT_CAPTCHA_AUDIT_MODE);
  // Let Qwen-7B generate until EOS. The sidecar's max_model_len=4096 means
  // ~3000 tokens of output headroom after the prompt. The model stops on
  // its own EOS for typical posts (rarely > 500 tokens).
  const nTokens = Number(process.env.AGENT_CAPTCHA_N_TOKENS ?? "3000");

  // Probe the sidecar first so the first slow call — which is silent on the
  // wire — is preceded by a visible "waking GPU" hint. Users kept assuming
  // the CLI had hung during Modal cold starts.
  const warmth = await probeSidecarWarmth(sidecarUrl);
  if (!warmth.warm) {
    logger.warn(
      { healthMs: warmth.ms },
      "Modal sidecar looks cold — cold start is 60–180s (vLLM boot + Qwen-7B weight load). Hang tight."
    );
  }

  // 1. Fetch challenge.
  logger.info({ baseUrl, agentId: demoSigner.agentId, prompt }, "Requesting challenge");
  const challengeResponse = await postJson<{ challenge: AgentChallenge }>(
    `${baseUrl}/api/agent-captcha/challenge`,
    { agentId: demoSigner.agentId }
  );
  const challenge = challengeResponse.challenge;
  const answer = computeChallengeAnswer(challenge, demoSigner.agentId);

  // 2. Real inference on Modal GPU. The LLM's generated text IS the post.
  logger.info({ sidecarUrl, n_tokens: nTokens }, "Running verified inference");
  const chatTimer = Date.now();
  const stopChatHeartbeat = startHeartbeat("still waiting for GPU inference");
  let chat: ChatResponse;
  try {
    chat = await postJson<ChatResponse>(`${sidecarUrl}/v1/chat`, {
      prompt,
      n_tokens: nTokens,
      temperature: 0
    });
  } finally {
    stopChatHeartbeat();
  }
  logger.info({ inferenceMs: Date.now() - chatTimer, generated: chat.generated_text.slice(0, 80) }, "inference done");

  const modelOutput = chat.generated_text.trim();
  const modelOutputHash = computeOutputHash(chat.generated_text);

  // 3. Open the audit binary for the first generated token over 10 layers.
  logger.info({ request_id: chat.request_id }, "Opening audit binary");
  const auditBinaryBytes = await postForBinary(`${sidecarUrl}/v1/audit`, {
    request_id: chat.request_id,
    token_index: chat.token_ids.length - chat.n_tokens,
    layer_indices: [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
    tier: auditMode,
    binary: true
  });
  const auditBinaryBase64 = Buffer.from(auditBinaryBytes).toString("base64");

  // 4. Fetch the verifier key identity (SHA256 only — full key is ~1GB).
  const keyResponse = await getJson<KeyResponse>(`${sidecarUrl}/key`);
  const verifierKeySha256 = keyResponse.verifier_key_sha256;
  const verifierKeyId = keyResponse.verifier_key_id;

  // 5. Build receipt + binding hash and sign the proof.
  const commitHash = computeCommitHash(chat.commitment);
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
      auditBinarySha256
    }
  };

  commitReceipt.bindingHash = computeCommitLLMBindingHash({
    challengeId: challenge.challengeId,
    answer,
    modelOutputHash,
    receipt: commitReceipt,
    auditBinarySha256,
    verifierKeySha256
  });

  const proof = await createAgentProof({
    challenge,
    signer: demoSigner,
    modelOutput: chat.generated_text,
    model,
    auditMode,
    commitReceipt
  });

  // 6. Verify → access token → post the LLM's answer as the message content.
  logger.info("Submitting proof for verification");
  const verification = await postJson<{
    accessToken: string;
    expiresAt: string;
    provenance?: unknown;
  }>(`${baseUrl}/api/v2/agent-captcha/verify`, { agentId: demoSigner.agentId, proof });

  const messageResponse = await postJson<{ message: { id: string; content: string } }>(
    `${baseUrl}/api/messages`,
    { content: modelOutput, parentId: null },
    verification.accessToken
  );

  logger.info(
    {
      messageId: messageResponse.message.id,
      posted: messageResponse.message.content,
      auditBinaryBytes: auditBinaryBytes.length,
      commitHash,
      tokenExpiresAt: verification.expiresAt
    },
    "Verified message posted"
  );
}

run().catch((error: Error) => {
  logger.error({ err: error }, "Demo agent failed");
  process.exitCode = 1;
});
