/**
 * E2E tests for API flow.
 * Why: verify end-to-end gating so only validated agents can create chat messages.
 */
import request from "supertest";
import { describe, expect, it } from "vitest";
import { createApp } from "../../src/server/app";
import {
  createAgentProof,
  computeChallengeAnswer,
  computeCommitHash,
  computeOutputHash,
  type AgentChallenge,
  type CommitLLMReceipt
} from "../../src/sdk";
import { CommitLLMBinaryReceiptVerifier } from "../../src/server/commitllmVerifier";

const demoSigner = {
  agentId: "demo-agent-001",
  privateKeyHex: "1f1e1d1c1b1a19181716151413121110f0e0d0c0b0a090807060504030201000",
  publicKeyHex: "b7a238dbf5a793f066a95e25d401f3557c6f8e38aeb11e0529861285bc051fd2"
};

function createPassingVerifier() {
  return new CommitLLMBinaryReceiptVerifier({
    runner: async () => ({
      ok: true,
      audit_binary_sha256: "3df12b1aaa868d4278b195cd3d7d856406d83ff673eb7fad3d19469ab2a64217",
      report: {
        passed: true,
        checks_run: 7,
        checks_passed: 7,
        failures: [],
        classified_failures: [],
        coverage_level: "routine",
        duration_us: 1200
      }
    })
  });
}

function buildReceipt(challenge: AgentChallenge, modelOutputHash: string): CommitLLMReceipt {
  const answer = computeChallengeAnswer(challenge, demoSigner.agentId);

  return {
    challengeId: challenge.challengeId,
    model: "llama-3.1-8b-w8a8",
    provider: "commitllm",
    auditMode: "routine",
    outputHash: modelOutputHash,
    commitHash: computeCommitHash(challenge.challengeId, answer, modelOutputHash, "llama-3.1-8b-w8a8", "routine"),
    issuedAt: new Date().toISOString(),
    artifacts: {
      auditBinaryBase64: Buffer.from("audit-binary").toString("base64"),
      verifierKeyJson: JSON.stringify({ key_id: "demo-key" }),
      auditBinarySha256: "3df12b1aaa868d4278b195cd3d7d856406d83ff673eb7fad3d19469ab2a64217"
    }
  };
}

async function issueProof(api: ReturnType<typeof request>, overrides?: { receipt?: Partial<CommitLLMReceipt> }) {
  const challengeResponse = await api.post("/api/agent-captcha/challenge").send({ agentId: demoSigner.agentId });
  const challenge = challengeResponse.body.challenge as AgentChallenge;
  const answer = computeChallengeAnswer(challenge, demoSigner.agentId);
  const modelOutput = `challenge=${challenge.challengeId};answer=${answer}`;

  const modelOutputHash = computeOutputHash(modelOutput);
  const receipt = buildReceipt(challenge, modelOutputHash);
  const mergedReceipt: CommitLLMReceipt = {
    ...receipt,
    ...(overrides?.receipt ?? {}),
    artifacts: {
      ...receipt.artifacts,
      ...(overrides?.receipt?.artifacts ?? {})
    }
  };

  const proof = await createAgentProof({
    challenge,
    signer: demoSigner,
    modelOutput,
    model: mergedReceipt.model,
    auditMode: mergedReceipt.auditMode,
    commitReceipt: mergedReceipt
  });

  return { challenge, proof };
}

async function authenticateAgent(api: ReturnType<typeof request>): Promise<string> {
  const { proof } = await issueProof(api);
  const verificationResponse = await api.post("/api/agent-captcha/verify").send({
    agentId: demoSigner.agentId,
    proof
  });

  return verificationResponse.body.accessToken as string;
}

describe("chat flow", () => {
  const { app } = createApp({ commitReceiptVerifier: createPassingVerifier() });
  const api = request(app);

  it("rejects messages without token", async () => {
    const response = await api.post("/api/messages").send({ content: "no token" });
    expect(response.status).toBe(401);
  });

  it("accepts messages from verified agents", async () => {
    const accessToken = await authenticateAgent(api);
    const response = await api
      .post("/api/messages")
      .set("authorization", `Bearer ${accessToken}`)
      .send({ content: "hello from verified agent" });

    expect(response.status).toBe(201);
  });

  it("returns posted messages to all readers", async () => {
    const response = await api.get("/api/messages");
    expect(response.body.messages.length > 0).toBe(true);
  });

  it("rejects mismatched commitllm output bindings", async () => {
    const { proof } = await issueProof(api, {
      receipt: {
        outputHash: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
      }
    });

    const response = await api.post("/api/agent-captcha/verify").send({
      agentId: demoSigner.agentId,
      proof
    });

    expect(response.body.error).toBe("receipt_output_hash_mismatch");
  });

  it("rejects replayed challenge proofs", async () => {
    const { proof } = await issueProof(api);

    await api.post("/api/agent-captcha/verify").send({
      agentId: demoSigner.agentId,
      proof
    });

    const replayResponse = await api.post("/api/agent-captcha/verify").send({
      agentId: demoSigner.agentId,
      proof
    });

    expect(replayResponse.status).toBe(409);
  });

  it("rejects expired challenges", async () => {
    const { app: expiringApp } = createApp({
      challengeTtlMs: 1,
      commitReceiptVerifier: createPassingVerifier()
    });
    const expiringApi = request(expiringApp);

    const { proof } = await issueProof(expiringApi);
    await new Promise((resolve) => setTimeout(resolve, 20));

    const response = await expiringApi.post("/api/agent-captcha/verify").send({
      agentId: demoSigner.agentId,
      proof
    });

    expect(response.body.error).toBe("challenge_expired");
  });
});
