/**
 * Demo agent client.
 * Why: run a real CommitLLM inference via the Modal sidecar, turn the returned
 * commitment + audit binary into an agent-captcha receipt, then post a message
 * through the agent-captcha `/api/v2/agent-captcha/verify` flow.
 *
 * Previous iteration expected pre-baked CommitLLM artifacts via env vars. This
 * version drives the whole pipeline end-to-end: challenge → inference → audit →
 * proof → post.
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

// Demo key pair pre-registered on the server. In production the agent would
// own a real key; this one is pinned to demo-agent-001.
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
 * Canonical, stable identifier for a CommitLLM commitment.
 * Why: the agent-captcha receipt binds a `commitHash` field — we derive it
 * deterministically from the commitment dict returned by /v1/chat so that
 * verifier and agent agree on the same value.
 */
function computeCommitHash(commitment: Record<string, unknown>): string {
  const canonical = JSON.stringify(commitment, Object.keys(commitment).sort());
  return bytesToHex(sha256(utf8ToBytes(canonical)));
}

async function run(): Promise<void> {
  const baseUrl = process.env.AGENT_CAPTCHA_BASE_URL ?? "http://localhost:4173";
  const sidecarUrl = requireEnv("MODAL_SIDECAR_URL").replace(/\/+$/, "");
  const userMessage = process.env.AGENT_CAPTCHA_MESSAGE ?? "Hello from a verified agent";
  // Must match the server's allowed models policy (see src/server/app.ts).
  const model = process.env.AGENT_CAPTCHA_MODEL ?? "qwen2.5-7b-w8a8";
  const provider = process.env.AGENT_CAPTCHA_PROVIDER ?? "commitllm";
  const modelVersion = process.env.AGENT_CAPTCHA_MODEL_VERSION;
  const auditMode = resolveAuditMode(process.env.AGENT_CAPTCHA_AUDIT_MODE);

  // Step 1: fetch challenge from the agent-captcha server.
  logger.info({ baseUrl, agentId: demoSigner.agentId }, "Requesting challenge");
  const challengeResponse = await postJson<{ challenge: AgentChallenge }>(
    `${baseUrl}/api/agent-captcha/challenge`,
    { agentId: demoSigner.agentId }
  );
  const challenge = challengeResponse.challenge;
  const answer = computeChallengeAnswer(challenge, demoSigner.agentId);

  // Step 2: run real inference on Modal. The default prompt embeds the
  // challenge answer so the LLM output is observably bound to this attempt;
  // override via AGENT_CAPTCHA_PROMPT to send anything you want. The protocol
  // doesn't require the answer to appear in the generated text — the answer
  // is carried separately and signed independently.
  const defaultPrompt = `You are agent ${demoSigner.agentId}. Acknowledge challenge ${challenge.challengeId} with answer ${answer}. Respond concisely.`;
  const prompt = process.env.AGENT_CAPTCHA_PROMPT ?? defaultPrompt;
  const nTokens = Number(process.env.AGENT_CAPTCHA_N_TOKENS ?? "16");
  logger.info({ sidecarUrl, prompt, n_tokens: nTokens }, "Running verified inference");
  const chat = await postJson<ChatResponse>(`${sidecarUrl}/v1/chat`, {
    prompt,
    n_tokens: nTokens,
    temperature: 0,
  });

  const modelOutput = chat.generated_text;
  const modelOutputHash = computeOutputHash(modelOutput);

  // Step 3: open an audit at the first generated token across the routine
  // 10-layer window. Keeping layer_indices explicit (rather than []) makes
  // the audit binary deterministically sized for the verifier.
  logger.info({ request_id: chat.request_id }, "Opening audit binary");
  const auditBinaryBytes = await postForBinary(`${sidecarUrl}/v1/audit`, {
    request_id: chat.request_id,
    token_index: chat.token_ids.length - chat.n_tokens,
    layer_indices: [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
    tier: auditMode,
    binary: true,
  });
  const auditBinaryBase64 = Buffer.from(auditBinaryBytes).toString("base64");

  // Step 4: fetch the verifier key identity. The full JSON is held by the
  // sidecar (>1GB for a 7B model) — we only bind to its SHA256.
  const keyResponse = await getJson<KeyResponse>(`${sidecarUrl}/key`);
  const verifierKeySha256 = keyResponse.verifier_key_sha256;
  const verifierKeyId = keyResponse.verifier_key_id;

  // Step 5: compute receipt + binding hash and sign the proof.
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
    modelOutput,
    model,
    auditMode,
    commitReceipt
  });

  // Step 6: submit proof → receive access token → post message.
  logger.info("Submitting proof for verification");
  const verification = await postJson<{ accessToken: string; expiresAt: string }>(
    `${baseUrl}/api/v2/agent-captcha/verify`,
    { agentId: demoSigner.agentId, proof }
  );

  const messageResponse = await postJson<{ message: { id: string } }>(
    `${baseUrl}/api/messages`,
    { content: userMessage, parentId: null },
    verification.accessToken
  );

  logger.info(
    {
      messageId: messageResponse.message.id,
      modelOutput,
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
