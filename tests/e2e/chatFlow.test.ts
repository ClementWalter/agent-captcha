/**
 * E2E tests for API flow.
 * Why: Verify end-to-end gating so only validated agents can create chat messages.
 */
import request from "supertest";
import { describe, expect, it } from "vitest";
import { createApp } from "../../src/server/app";
import { createAgentProof, computeChallengeAnswer, type AgentChallenge, type CommitLLMReceipt } from "../../src/sdk";

const demoSigner = {
  agentId: "demo-agent-001",
  privateKeyHex: "1f1e1d1c1b1a19181716151413121110f0e0d0c0b0a090807060504030201000",
  publicKeyHex: "b7a238dbf5a793f066a95e25d401f3557c6f8e38aeb11e0529861285bc051fd2"
};

async function authenticateAgent(api: ReturnType<typeof request>): Promise<string> {
  const challengeResponse = await api.post("/api/agent-captcha/challenge").send({ agentId: demoSigner.agentId });
  const challenge = challengeResponse.body.challenge as AgentChallenge;
  const answer = computeChallengeAnswer(challenge, demoSigner.agentId);
  const modelOutput = `challenge=${challenge.challengeId};answer=${answer}`;

  const receiptResponse = await api.post("/api/agent-captcha/receipt").send({
    challengeId: challenge.challengeId,
    model: "llama-3.1-8b-w8a8",
    auditMode: "routine",
    answer,
    modelOutput
  });

  const receipt = receiptResponse.body.receipt as CommitLLMReceipt;
  const proof = await createAgentProof({
    challenge,
    signer: demoSigner,
    modelOutput,
    model: receipt.model,
    auditMode: receipt.auditMode,
    commitReceipt: receipt
  });

  const verificationResponse = await api.post("/api/agent-captcha/verify").send({
    agentId: demoSigner.agentId,
    proof
  });

  return verificationResponse.body.accessToken as string;
}

describe("chat flow", () => {
  const { app } = createApp();
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

  it("rejects tampered commitllm digests", async () => {
    const challengeResponse = await api.post("/api/agent-captcha/challenge").send({ agentId: demoSigner.agentId });
    const challenge = challengeResponse.body.challenge as AgentChallenge;
    const answer = computeChallengeAnswer(challenge, demoSigner.agentId);
    const modelOutput = `challenge=${challenge.challengeId};answer=${answer}`;
    const receiptResponse = await api.post("/api/agent-captcha/receipt").send({
      challengeId: challenge.challengeId,
      model: "llama-3.1-8b-w8a8",
      auditMode: "routine",
      answer,
      modelOutput
    });
    const receipt = receiptResponse.body.receipt as CommitLLMReceipt;
    const tamperedReceipt: CommitLLMReceipt = {
      ...receipt,
      digest: receipt.digest.replace(/^./, (prefix) => (prefix === "a" ? "b" : "a"))
    };

    const proof = await createAgentProof({
      challenge,
      signer: demoSigner,
      modelOutput,
      model: tamperedReceipt.model,
      auditMode: tamperedReceipt.auditMode,
      commitReceipt: tamperedReceipt
    });

    const response = await api.post("/api/agent-captcha/verify").send({
      agentId: demoSigner.agentId,
      proof
    });

    expect(response.status).toBe(401);
  });
});
