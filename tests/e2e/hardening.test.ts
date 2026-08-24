/**
 * Hardening regressions for catch-all routing, per-IP challenge caps,
 * and the in-flight audit-binary sentinel surviving the expiry sweep.
 */
import { randomBytes } from "crypto";
import request from "supertest";
import { afterEach, describe, expect, it } from "vitest";
import { createApp } from "../../src/server/app";
import {
  COMMITLLM_BINDING_VERSION,
  computeAuditBinarySha256,
  computeChallengeAnswer,
  computeCommitLLMBindingHash,
  computeOutputHash,
  createAgentProof,
  type AgentChallenge,
  type CommitLLMReceipt,
  type CommitReceiptVerifier,
} from "../../src/sdk";
import type { MessageStore } from "../../src/server/messageStore";
import type { ProfileStore, AgentProfile } from "../../src/server/profileStore";
import type { ChatMessage } from "../../src/server/app";
import { loadCommitLLMFixture } from "../fixtures/commitllmFixture";

function createInMemoryMessageStore(): MessageStore {
  const messages: ChatMessage[] = [];
  return {
    async append(message) {
      messages.push(message);
    },
    async list() {
      return messages.slice();
    },
    async healthCheck() {},
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
    async healthCheck() {},
  };
}

const TEST_SECRET = "test-access-token-secret-0123456789abcdef";
const signer = {
  agentId: "b7a238dbf5a793f066a95e25d401f3557c6f8e38aeb11e0529861285bc051fd2",
  privateKeyHex:
    "1f1e1d1c1b1a19181716151413121110f0e0d0c0b0a090807060504030201000",
  publicKeyHex:
    "b7a238dbf5a793f066a95e25d401f3557c6f8e38aeb11e0529861285bc051fd2",
};

function passingVerifier(): CommitReceiptVerifier {
  return {
    async verifyReceipt() {
      return {
        valid: true,
        report: {
          passed: true,
          checksRun: 7,
          checksPassed: 7,
          failures: [],
        },
      };
    },
  };
}

function delayedVerifier(delayMs: number): CommitReceiptVerifier {
  return {
    async verifyReceipt() {
      await new Promise((resolve) => setTimeout(resolve, delayMs));
      return {
        valid: true,
        report: {
          passed: true,
          checksRun: 7,
          checksPassed: 7,
          failures: [],
        },
      };
    },
  };
}

function largeAuditBinary(): {
  auditBinaryBase64: string;
  auditBinarySha256: string;
} {
  const auditBinaryBase64 = randomBytes(1536).toString("base64");
  return {
    auditBinaryBase64,
    auditBinarySha256: computeAuditBinarySha256(auditBinaryBase64),
  };
}

async function proofForChallenge(
  challenge: AgentChallenge,
  audit: { auditBinaryBase64: string; auditBinarySha256: string },
) {
  const fixture = loadCommitLLMFixture();
  const modelOutput = "hardening-sentinel-test";
  const modelOutputHash = computeOutputHash(modelOutput);
  const answer = computeChallengeAnswer(challenge, signer.agentId);
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
      auditBinaryBase64: audit.auditBinaryBase64,
      verifierKeyJson: fixture.verifierKeyJson,
      auditBinarySha256: audit.auditBinarySha256,
      verifierKeySha256: fixture.verifierKeySha256,
    },
  };
  receipt.bindingHash = computeCommitLLMBindingHash({
    challengeId: challenge.challengeId,
    answer,
    modelOutputHash,
    receipt,
    auditBinarySha256: audit.auditBinarySha256,
    verifierKeySha256: fixture.verifierKeySha256,
  });
  const proof = await createAgentProof({
    challenge,
    signer,
    modelOutput,
    model: "llama-3.1-8b-w8a8",
    auditMode: "routine",
    commitReceipt: receipt,
  });
  return { agentId: signer.agentId, proof };
}

describe("unknown API and hidden paths", () => {
  const { app } = createApp({
    accessTokenSecret: TEST_SECRET,
    commitReceiptVerifier: passingVerifier(),
    messageStore: createInMemoryMessageStore(),
    profileStore: createInMemoryProfileStore(),
    expirySweepIntervalMs: 0,
    disableRateLimiting: true,
    disableAuditBinaryTracking: true,
  });
  const api = request(app);

  it("returns 404 JSON for a missing /api path", async () => {
    const response = await api.get("/api/nonexistent");
    expect(response.status).toBe(404);
  });

  it("returns JSON not HTML for a missing /api path", async () => {
    const response = await api.get("/api/nonexistent");
    expect(response.body.error).toBe("not_found");
  });

  it("returns 404 for /.config", async () => {
    const response = await api.get("/.config");
    expect(response.status).toBe(404);
  });

  it("returns 404 for /.claude", async () => {
    const response = await api.get("/.claude");
    expect(response.status).toBe(404);
  });
});

describe("per-IP pending challenge cap", () => {
  it("still issues a challenge at the 20th unique agentId from one IP", async () => {
    const { app } = createApp({
      accessTokenSecret: TEST_SECRET,
      commitReceiptVerifier: passingVerifier(),
      messageStore: createInMemoryMessageStore(),
      profileStore: createInMemoryProfileStore(),
      expirySweepIntervalMs: 0,
      disableRateLimiting: true,
      disableAuditBinaryTracking: true,
    });
    const api = request(app);
    let lastStatus = 0;
    for (let i = 0; i < 20; i++) {
      const res = await api
        .post("/api/agent-captcha/challenge")
        .send({ agentId: randomBytes(32).toString("hex") });
      lastStatus = res.status;
    }
    expect(lastStatus).toBe(200);
  });

  it("rejects the 21st pending challenge from the same IP", async () => {
    const { app } = createApp({
      accessTokenSecret: TEST_SECRET,
      commitReceiptVerifier: passingVerifier(),
      messageStore: createInMemoryMessageStore(),
      profileStore: createInMemoryProfileStore(),
      expirySweepIntervalMs: 0,
      disableRateLimiting: true,
      disableAuditBinaryTracking: true,
    });
    const api = request(app);
    for (let i = 0; i < 20; i++) {
      await api
        .post("/api/agent-captcha/challenge")
        .send({ agentId: randomBytes(32).toString("hex") });
    }
    const response = await api
      .post("/api/agent-captcha/challenge")
      .send({ agentId: randomBytes(32).toString("hex") });
    expect(response.status).toBe(429);
  });
});

describe("pending audit-binary sentinel survives the expiry sweep", () => {
  let stop: (() => void) | undefined;

  afterEach(() => {
    stop?.();
    stop = undefined;
  });

  it("rejects a second verify of the same binary while the first is in flight", async () => {
    const created = createApp({
      accessTokenSecret: TEST_SECRET,
      commitReceiptVerifier: delayedVerifier(250),
      messageStore: createInMemoryMessageStore(),
      profileStore: createInMemoryProfileStore(),
      expirySweepIntervalMs: 40,
      disableRateLimiting: true,
      disableAuditBinaryTracking: false,
    });
    stop = created.stop;
    const api = request(created.app);
    const audit = largeAuditBinary();

    const firstChallenge = (
      await api
        .post("/api/agent-captcha/challenge")
        .send({ agentId: signer.agentId })
    ).body.challenge as AgentChallenge;
    const secondChallenge = (
      await api
        .post("/api/agent-captcha/challenge")
        .send({ agentId: signer.agentId })
    ).body.challenge as AgentChallenge;

    const firstPayload = await proofForChallenge(firstChallenge, audit);
    const secondPayload = await proofForChallenge(secondChallenge, audit);
    const firstVerify = api
      .post("/api/v2/agent-captcha/verify")
      .send(firstPayload)
      .then((response) => response);
    await new Promise((resolve) => setTimeout(resolve, 90));
    const second = await api
      .post("/api/v2/agent-captcha/verify")
      .send(secondPayload);

    expect(second.status).toBe(409);
    await firstVerify;
  });
});
