/**
 * Unit tests for SDK primitives.
 * Why: lock deterministic hashing and proof verification invariants used by API and agents.
 */
import { describe, expect, it } from "vitest";
import {
  computeChallengeAnswer,
  computeCommitHash,
  computeOutputHash,
  createAgentProof,
  type AgentChallenge,
  type CommitLLMReceipt,
  verifyAgentProof
} from "../../src/sdk";

const challenge: AgentChallenge = {
  challengeId: "11111111-1111-4111-8111-111111111111",
  nonce: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  issuedAt: "2026-01-01T00:00:00.000Z",
  expiresAt: "2026-01-01T00:02:00.000Z",
  policy: {
    allowedModels: ["llama-3.1-8b-w8a8"],
    allowedAuditModes: ["routine"],
    requiresCommitReceipt: true,
    maxChallengeAgeMs: 120000
  }
};

const signer = {
  agentId: "demo-agent-001",
  privateKeyHex: "1f1e1d1c1b1a19181716151413121110f0e0d0c0b0a090807060504030201000",
  publicKeyHex: "b7a238dbf5a793f066a95e25d401f3557c6f8e38aeb11e0529861285bc051fd2"
};

function buildReceipt(modelOutputHash: string): CommitLLMReceipt {
  const answer = computeChallengeAnswer(challenge, signer.agentId);

  return {
    challengeId: challenge.challengeId,
    model: "llama-3.1-8b-w8a8",
    provider: "commitllm",
    auditMode: "routine",
    outputHash: modelOutputHash,
    commitHash: computeCommitHash(challenge.challengeId, answer, modelOutputHash, "llama-3.1-8b-w8a8", "routine"),
    issuedAt: "2026-01-01T00:00:20.000Z",
    artifacts: {
      auditBinaryBase64: Buffer.from("audit-binary").toString("base64"),
      verifierKeyJson: JSON.stringify({ key_id: "demo-key" })
    }
  };
}

describe("agent-captcha sdk", () => {
  it("computes stable challenge answers", () => {
    expect(computeChallengeAnswer(challenge, signer.agentId)).toBe(
      "a869260b0ef754a9663330557a06f0499638e854cf73f274fcb62a0d05a19be0"
    );
  });

  it("computes stable output hashes", () => {
    expect(computeOutputHash("hello")).toBe("2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824");
  });

  it("computes stable commit hashes", () => {
    expect(
      computeCommitHash(
        challenge.challengeId,
        "a869260b0ef754a9663330557a06f0499638e854cf73f274fcb62a0d05a19be0",
        "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824",
        "llama-3.1-8b-w8a8",
        "routine"
      )
    ).toBe("48d977dbc63a94833435df00d8c29d2cafd9a5f7b3ab84d44d3221863bc008e4");
  });

  it("verifies valid proofs", async () => {
    const modelOutput = "challenge=11111111-1111-4111-8111-111111111111;answer=ok";
    const modelOutputHash = computeOutputHash(modelOutput);

    const proof = await createAgentProof({
      challenge,
      signer,
      modelOutput,
      model: "llama-3.1-8b-w8a8",
      auditMode: "routine",
      commitReceipt: buildReceipt(modelOutputHash),
      now: new Date("2026-01-01T00:00:25.000Z")
    });

    const result = await verifyAgentProof({
      challenge,
      proof,
      expectedAgentId: signer.agentId,
      verifier: {
        verifyReceipt: async () => ({ valid: true })
      },
      now: new Date("2026-01-01T00:01:00.000Z")
    });

    expect(result.valid).toBe(true);
  });

  it("rejects expired challenges", async () => {
    const modelOutput = "challenge=expired";
    const modelOutputHash = computeOutputHash(modelOutput);

    const proof = await createAgentProof({
      challenge,
      signer,
      modelOutput,
      model: "llama-3.1-8b-w8a8",
      auditMode: "routine",
      commitReceipt: buildReceipt(modelOutputHash),
      now: new Date("2026-01-01T00:00:25.000Z")
    });

    const result = await verifyAgentProof({
      challenge,
      proof,
      expectedAgentId: signer.agentId,
      verifier: {
        verifyReceipt: async () => ({ valid: true })
      },
      now: new Date("2026-01-01T00:05:00.000Z")
    });

    expect(result.reason).toBe("challenge_expired");
  });

  it("rejects commit hash mismatch", async () => {
    const modelOutput = "challenge=11111111-1111-4111-8111-111111111111;answer=ok";
    const modelOutputHash = computeOutputHash(modelOutput);
    const receipt = buildReceipt(modelOutputHash);

    const proof = await createAgentProof({
      challenge,
      signer,
      modelOutput,
      model: "llama-3.1-8b-w8a8",
      auditMode: "routine",
      commitReceipt: {
        ...receipt,
        commitHash: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
      },
      now: new Date("2026-01-01T00:00:25.000Z")
    });

    const result = await verifyAgentProof({
      challenge,
      proof,
      expectedAgentId: signer.agentId,
      verifier: {
        verifyReceipt: async () => ({ valid: true })
      },
      now: new Date("2026-01-01T00:01:00.000Z")
    });

    expect(result.reason).toBe("commit_hash_mismatch");
  });
});
