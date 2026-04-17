/**
 * E2E tests for API flow.
 * Why: verify end-to-end gating so only validated agents can create chat messages.
 */
import request from "supertest";
import { describe, expect, it } from "vitest";
import { createApp } from "../../src/server/app";
import {
  COMMITLLM_BINDING_VERSION,
  createAgentProof,
  computeChallengeAnswer,
  computeCommitLLMBindingHash,
  computeOutputHash,
  type AgentChallenge,
  type CommitLLMReceipt
} from "../../src/sdk";
import { CommitLLMModalReceiptVerifier } from "../../src/server/commitllmVerifier";
import type { MessageStore } from "../../src/server/messageStore";
import type { ProfileStore, AgentProfile } from "../../src/server/profileStore";
import type { ChatMessage } from "../../src/server/app";
import { loadCommitLLMFixture } from "../fixtures/commitllmFixture";

/**
 * In-memory stores — e2e tests are about protocol correctness, not
 * durability, so we swap out the S3-backed production stores for plain maps.
 */
function createInMemoryMessageStore(): MessageStore {
  const messages: ChatMessage[] = [];
  return {
    async append(message) {
      messages.push(message);
    },
    async list() {
      return messages.slice();
    },
    async healthCheck() {}
  };
}

function createInMemoryProfileStore(): ProfileStore {
  const profiles: Record<string, AgentProfile> = {};
  return {
    async upsert(profile) {
      profiles[profile.agentId] = profile;
    },
    async getMany(agentIds) {
      const result: Record<string, AgentProfile> = {};
      for (const id of agentIds) {
        if (profiles[id]) {
          result[id] = profiles[id];
        }
      }
      return result;
    },
    async listAll() {
      return { ...profiles };
    },
    async healthCheck() {}
  };
}

// Self-sovereign: agentId IS the Ed25519 public key.
const demoSigner = {
  agentId: "b7a238dbf5a793f066a95e25d401f3557c6f8e38aeb11e0529861285bc051fd2",
  privateKeyHex: "1f1e1d1c1b1a19181716151413121110f0e0d0c0b0a090807060504030201000",
  publicKeyHex: "b7a238dbf5a793f066a95e25d401f3557c6f8e38aeb11e0529861285bc051fd2"
};

/**
 * Real verifier wired to a fetch mock that always returns a passing report.
 * Why: keep shape/hash checks (run locally) in the test loop so we catch
 * regressions in binding-hash and output-hash consistency; only the Rust
 * verifier call is stubbed.
 */
function createPassingVerifier(): CommitLLMModalReceiptVerifier {
  const fixture = loadCommitLLMFixture();
  const fetchImpl: typeof fetch = async () =>
    new Response(
      JSON.stringify({
        ok: true,
        audit_binary_sha256: fixture.auditBinarySha256,
        report: { passed: true, checks_run: 7, checks_passed: 7 }
      }),
      { status: 200, headers: { "content-type": "application/json" } }
    );
  return new CommitLLMModalReceiptVerifier({
    sidecarUrl: "https://example.modal.run",
    strict: true,
    fetchImpl
  });
}

function buildReceipt(challenge: AgentChallenge, modelOutputHash: string): CommitLLMReceipt {
  const fixture = loadCommitLLMFixture();
  const answer = computeChallengeAnswer(challenge, demoSigner.agentId);

  const receipt: CommitLLMReceipt = {
    challengeId: challenge.challengeId,
    model: "llama-3.1-8b-w8a8",
    provider: "commitllm",
    auditMode: "routine",
    outputHash: modelOutputHash,
    commitHash: fixture.commitHash,
    issuedAt: new Date().toISOString(),
    bindingVersion: COMMITLLM_BINDING_VERSION,
    bindingHash: "",
    artifacts: {
      auditBinaryBase64: fixture.auditBinaryBase64,
      verifierKeyJson: fixture.verifierKeyJson,
      auditBinarySha256: fixture.auditBinarySha256,
      verifierKeySha256: fixture.verifierKeySha256
    }
  };

  receipt.bindingHash = computeCommitLLMBindingHash({
    challengeId: challenge.challengeId,
    answer,
    modelOutputHash,
    receipt,
    auditBinarySha256: fixture.auditBinarySha256,
    verifierKeySha256: fixture.verifierKeySha256
  });

  return receipt;
}

async function issueProof(api: ReturnType<typeof request>, overrides?: { receipt?: Partial<CommitLLMReceipt>; modelOutput?: string }) {
  const challengeResponse = await api.post("/api/agent-captcha/challenge").send({ agentId: demoSigner.agentId });
  const challenge = challengeResponse.body.challenge as AgentChallenge;
  const answer = computeChallengeAnswer(challenge, demoSigner.agentId);
  const modelOutput = overrides?.modelOutput ?? `challenge=${challenge.challengeId};answer=${answer}`;

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

  const bindingHashOverride = overrides?.receipt?.bindingHash;
  mergedReceipt.bindingHash =
    bindingHashOverride ??
    computeCommitLLMBindingHash({
      challengeId: challenge.challengeId,
      answer,
      modelOutputHash,
      receipt: mergedReceipt,
      auditBinarySha256: mergedReceipt.artifacts.auditBinarySha256 ?? loadCommitLLMFixture().auditBinarySha256,
      verifierKeySha256: mergedReceipt.artifacts.verifierKeySha256 ?? loadCommitLLMFixture().verifierKeySha256
    });

  const proof = await createAgentProof({
    challenge,
    signer: demoSigner,
    modelOutput,
    model: mergedReceipt.model,
    auditMode: mergedReceipt.auditMode,
    commitReceipt: mergedReceipt
  });

  return { challenge, proof, modelOutput };
}

async function authenticateAgent(api: ReturnType<typeof request>): Promise<{ accessToken: string; modelOutput: string }> {
  const { proof, modelOutput } = await issueProof(api);
  const verificationResponse = await api.post("/api/v2/agent-captcha/verify").send({
    agentId: demoSigner.agentId,
    proof
  });

  return { accessToken: verificationResponse.body.accessToken as string, modelOutput };
}

// Long enough to satisfy createApp's floor; irrelevant for logic under test.
const TEST_ACCESS_TOKEN_SECRET = "test-access-token-secret-0123456789abcdef";

describe("chat flow", () => {
  const { app } = createApp({
    accessTokenSecret: TEST_ACCESS_TOKEN_SECRET,
    commitReceiptVerifier: createPassingVerifier(),
    messageStore: createInMemoryMessageStore(),
    profileStore: createInMemoryProfileStore(),
    expirySweepIntervalMs: 0
  });
  const api = request(app);

  it("rejects messages without token", async () => {
    const response = await api.post("/api/messages").send({ content: "no token" });
    expect(response.status).toBe(401);
  });

  it("accepts messages from verified agents", async () => {
    const { accessToken, modelOutput } = await authenticateAgent(api);
    const response = await api
      .post("/api/messages")
      .set("authorization", `Bearer ${accessToken}`)
      .send({ content: modelOutput });

    expect(response.status).toBe(201);
  });

  it("rejects messages whose content was not signed", async () => {
    const { accessToken } = await authenticateAgent(api);
    const response = await api
      .post("/api/messages")
      .set("authorization", `Bearer ${accessToken}`)
      .send({ content: "arbitrary attacker-chosen text" });

    expect(response.status).toBe(400);
    expect(response.body.error).toBe("message_content_not_signed");
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

    const response = await api.post("/api/v2/agent-captcha/verify").send({
      agentId: demoSigner.agentId,
      proof
    });

    expect(response.body.error).toBe("receipt_output_hash_mismatch");
  });

  it("rejects explicit binding hash tampering", async () => {
    const { proof } = await issueProof(api, {
      receipt: {
        bindingHash: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
      }
    });

    const response = await api.post("/api/v2/agent-captcha/verify").send({
      agentId: demoSigner.agentId,
      proof
    });

    expect(response.body.error).toBe("receipt_binding_hash_mismatch");
  });

  it("rejects replayed challenge proofs", async () => {
    const { proof } = await issueProof(api);

    await api.post("/api/v2/agent-captcha/verify").send({
      agentId: demoSigner.agentId,
      proof
    });

    const replayResponse = await api.post("/api/v2/agent-captcha/verify").send({
      agentId: demoSigner.agentId,
      proof
    });

    expect(replayResponse.status).toBe(409);
  });

  it("rejects expired challenges", async () => {
    const { app: expiringApp } = createApp({
      accessTokenSecret: TEST_ACCESS_TOKEN_SECRET,
      challengeTtlMs: 1,
      commitReceiptVerifier: createPassingVerifier(),
      messageStore: createInMemoryMessageStore(),
      profileStore: createInMemoryProfileStore(),
      expirySweepIntervalMs: 0
    });
    const expiringApi = request(expiringApp);

    const { proof } = await issueProof(expiringApi);
    await new Promise((resolve) => setTimeout(resolve, 20));

    const response = await expiringApi.post("/api/v2/agent-captcha/verify").send({
      agentId: demoSigner.agentId,
      proof
    });

    expect(response.body.error).toBe("challenge_expired");
  });

  it("returns migration metadata on deprecated receipt endpoint", async () => {
    const response = await api.post("/api/agent-captcha/receipt").send({});
    expect(response.status).toBe(410);
  });

  it("tracks deprecated receipt endpoint telemetry", async () => {
    await api.post("/api/agent-captcha/receipt").send({});
    const statusResponse = await api.get("/api/agent-captcha/migration-status");
    expect(statusResponse.body.telemetry.receiptDeprecatedCalls > 0).toBe(true);
  });

  it("tracks verify alias telemetry for compatibility monitoring", async () => {
    const { proof } = await issueProof(api);
    await api.post("/api/agent-captcha/verify").send({
      agentId: demoSigner.agentId,
      proof
    });
    const statusResponse = await api.get("/api/agent-captcha/migration-status");
    expect(statusResponse.body.telemetry.verifyAliasCalls > 0).toBe(true);
  });
});
