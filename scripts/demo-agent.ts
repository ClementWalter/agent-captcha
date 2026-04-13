/**
 * Demo agent client.
 * Why: provide a reproducible flow that sends real CommitLLM artifacts into
 * `/api/v2/agent-captcha/verify` instead of using the removed MVP mock receipt path.
 */
import pino from "pino";
import {
  type AgentChallenge,
  COMMITLLM_BINDING_VERSION,
  computeAuditBinarySha256,
  createAgentProof,
  computeChallengeAnswer,
  computeCommitLLMBindingHash,
  computeOutputHash,
  computeVerifierKeySha256,
  type CommitLLMReceipt,
  type AuditMode
} from "../src/sdk";

const logger = pino({ name: "agent-captcha-demo-agent" });

const demoSigner = {
  agentId: "demo-agent-001",
  privateKeyHex: "1f1e1d1c1b1a19181716151413121110f0e0d0c0b0a090807060504030201000",
  publicKeyHex: "b7a238dbf5a793f066a95e25d401f3557c6f8e38aeb11e0529861285bc051fd2"
};

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
    throw new Error(`Request failed (${response.status}): ${errorBody}`);
  }

  return (await response.json()) as T;
}

function requireEnv(name: string): string {
  const value = process.env[name];
  if (!value) {
    throw new Error(`Missing required environment variable: ${name}`);
  }
  return value;
}

function resolveAuditMode(raw: string | undefined): AuditMode {
  if (raw === "deep") {
    return "deep";
  }
  return "routine";
}

async function run(): Promise<void> {
  const baseUrl = process.env.AGENT_CAPTCHA_BASE_URL ?? "http://localhost:4173";
  const message = process.env.AGENT_CAPTCHA_MESSAGE ?? "Hello from a verified agent";
  const model = process.env.AGENT_CAPTCHA_MODEL ?? "llama-3.1-8b-w8a8";
  const provider = process.env.AGENT_CAPTCHA_PROVIDER ?? "commitllm";
  const modelVersion = process.env.AGENT_CAPTCHA_MODEL_VERSION;
  const auditMode = resolveAuditMode(process.env.AGENT_CAPTCHA_AUDIT_MODE);

  const challengeResponse = await postJson<{ challenge: AgentChallenge }>(
    `${baseUrl}/api/agent-captcha/challenge`,
    { agentId: demoSigner.agentId }
  );

  const answer = computeChallengeAnswer(challengeResponse.challenge, demoSigner.agentId);
  const modelOutput = `challenge=${challengeResponse.challenge.challengeId};answer=${answer}`;

  const auditBinaryBase64 = requireEnv("AGENT_CAPTCHA_COMMITLLM_AUDIT_BINARY_BASE64");
  const verifierKeyJson = requireEnv("AGENT_CAPTCHA_COMMITLLM_VERIFIER_KEY_JSON");
  const commitHash = requireEnv("AGENT_CAPTCHA_COMMITLLM_COMMIT_HASH");
  const verifierKeyId = process.env.AGENT_CAPTCHA_COMMITLLM_VERIFIER_KEY_ID;
  const resolvedAuditBinarySha256 = process.env.AGENT_CAPTCHA_COMMITLLM_AUDIT_BINARY_SHA256 ?? computeAuditBinarySha256(auditBinaryBase64);
  const resolvedVerifierKeySha256 =
    process.env.AGENT_CAPTCHA_COMMITLLM_VERIFIER_KEY_SHA256 ?? computeVerifierKeySha256(verifierKeyJson);

  const modelOutputHash = computeOutputHash(modelOutput);

  const commitReceipt: CommitLLMReceipt = {
    challengeId: challengeResponse.challenge.challengeId,
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
      verifierKeyJson,
      ...(verifierKeyId ? { verifierKeyId } : {}),
      auditBinarySha256: resolvedAuditBinarySha256,
      verifierKeySha256: resolvedVerifierKeySha256
    }
  };

  commitReceipt.bindingHash = computeCommitLLMBindingHash({
    challengeId: challengeResponse.challenge.challengeId,
    answer,
    modelOutputHash,
    receipt: commitReceipt,
    auditBinarySha256: resolvedAuditBinarySha256,
    verifierKeySha256: resolvedVerifierKeySha256
  });

  const proof = await createAgentProof({
    challenge: challengeResponse.challenge,
    signer: demoSigner,
    modelOutput,
    model,
    auditMode,
    commitReceipt
  });

  const verificationResponse = await postJson<{ accessToken: string; expiresAt: string }>(
    `${baseUrl}/api/v2/agent-captcha/verify`,
    {
      agentId: demoSigner.agentId,
      proof
    }
  );

  const messageResponse = await postJson<{ message: { id: string } }>(
    `${baseUrl}/api/messages`,
    {
      content: message,
      parentId: null
    },
    verificationResponse.accessToken
  );

  logger.info(
    {
      messageId: messageResponse.message.id,
      tokenExpiresAt: verificationResponse.expiresAt,
      agentId: demoSigner.agentId,
      model,
      auditMode
    },
    "Successfully posted using agent-captcha"
  );
}

run().catch((error: Error) => {
  logger.error({ err: error }, "Demo agent failed");
  process.exitCode = 1;
});
