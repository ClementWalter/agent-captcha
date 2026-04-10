/**
 * Unit tests for SDK primitives.
 * Why: Lock protocol determinism so API and clients agree on challenge and proof values.
 */
import { describe, expect, it } from "vitest";
import {
  computeChallengeAnswer,
  computeCommitLLMCommitment,
  computeCommitLLMDigest,
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

function buildReceipt(receiptId: string, modelOutputHash: string): CommitLLMReceipt {
  const answer = computeChallengeAnswer(challenge, signer.agentId);
  const commitHash = computeCommitHash(challenge.challengeId, answer, modelOutputHash, "llama-3.1-8b-w8a8", "routine");
  const commitment = computeCommitLLMCommitment({
    challengeId: challenge.challengeId,
    agentId: signer.agentId,
    answer,
    modelOutputHash,
    model: "llama-3.1-8b-w8a8",
    auditMode: "routine"
  });

  const receipt = {
    receiptId,
    challengeId: challenge.challengeId,
    model: "llama-3.1-8b-w8a8" as const,
    auditMode: "routine" as const,
    outputHash: modelOutputHash,
    commitHash,
    issuedAt: "2026-01-01T00:00:20.000Z",
    commitment
  };

  return {
    ...receipt,
    digest: computeCommitLLMDigest(receipt)
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

  it("computes stable commitllm commitment digests", () => {
    const modelOutputHash = computeOutputHash("hello");
    const commitment = computeCommitLLMCommitment({
      challengeId: challenge.challengeId,
      agentId: signer.agentId,
      answer: computeChallengeAnswer(challenge, signer.agentId),
      modelOutputHash,
      model: "llama-3.1-8b-w8a8",
      auditMode: "routine"
    });

    expect(commitment).toEqual({
      merkleRoot: "8513ba3fb885c8d560b33e6197906f85b862240f114375de08f104f76a9e4dfe",
      ioRoot: "e34b220cbdc1259f8df21a8892f06fcc7f43ba4c613ed02a736e34686f1209dc",
      manifestHash: "5d3ae9cc3d181b94e216e1067645d5498415b8e0132a3c95b4049d0b2114198e",
      inputSpecHash: "c0449f50277ba580e64584db1883b0fe42da553d30371f8f16790556eab696cc",
      modelSpecHash: "054725666a95c6bce7342f193a47324e1fe89cab79fcd1c1e7f654e6d1934ca4",
      decodeSpecHash: "18c39d622bb0ce256c20acd4bd3904a01ad8f92feee4aeab0454aeb6ae6ba290",
      outputSpecHash: "0f4604eb882144b9c0a2b66c8238811c5ba09d7b1c6bcbe97f3bccea84fb2b5d",
      promptHash: "01345e91fd6509802dd0ebe7b52b0818736a81469b5d9b484e8a6c2539eea0a2",
      seedCommitment: "97cb60084fcb13f4ead5eaa4d19b31ac75dfcb2ff46c204b6bf46371a9e8e7c1"
    });
  });

  it("computes stable commitllm receipt digests", () => {
    const digest = computeCommitLLMDigest({
      receiptId: "22222222-2222-4222-8222-222222222222",
      challengeId: challenge.challengeId,
      model: "llama-3.1-8b-w8a8",
      auditMode: "routine",
      outputHash: computeOutputHash("hello"),
      commitHash: computeCommitHash(
        challenge.challengeId,
        computeChallengeAnswer(challenge, signer.agentId),
        computeOutputHash("hello"),
        "llama-3.1-8b-w8a8",
        "routine"
      ),
      issuedAt: "2026-01-01T00:00:20.000Z",
      commitment: computeCommitLLMCommitment({
        challengeId: challenge.challengeId,
        agentId: signer.agentId,
        answer: computeChallengeAnswer(challenge, signer.agentId),
        modelOutputHash: computeOutputHash("hello"),
        model: "llama-3.1-8b-w8a8",
        auditMode: "routine"
      })
    });

    expect(digest).toBe("71243d87822bf4d0d880f2126f894923cc34ff5ade162ee2ef8fb7e8137e7351");
  });

  it("verifies valid proofs", async () => {
    const modelOutput = "challenge=11111111-1111-4111-8111-111111111111;answer=ok";
    const modelOutputHash = computeOutputHash(modelOutput);
    const receipt = buildReceipt("22222222-2222-4222-8222-222222222222", modelOutputHash);

    const proof = await createAgentProof({
      challenge,
      signer,
      modelOutput,
      model: "llama-3.1-8b-w8a8",
      auditMode: "routine",
      commitReceipt: receipt,
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
    const receipt = buildReceipt("33333333-3333-4333-8333-333333333333", modelOutputHash);

    const proof = await createAgentProof({
      challenge,
      signer,
      modelOutput,
      model: "llama-3.1-8b-w8a8",
      auditMode: "routine",
      commitReceipt: receipt,
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
});
