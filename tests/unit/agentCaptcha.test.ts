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
      merkleRoot: "a5111fb8358302a3c060b73b2e654d05a64f79a5a5742d2d0c2acf14febcf7a3",
      ioRoot: "708be5f6a9258f4ca8458410597c26d5f5a8b03b418987326ccec24bc210f353",
      manifestHash: "111603c7a5b5fba159868c2dfe07002f9d18c291490638a34a1ab4e138a8a587",
      inputSpecHash: "981a3d388d7a1531b69dfde52228cceb151e7cb251e8051e2433757c7ec32e87",
      modelSpecHash: "49123758933622aabfc120e8ca4e3dd8e0e8f4900e821d454c56d44011a8359c",
      decodeSpecHash: "01b1d3f8296e751f1868f2adada471455808caee897d04942f06db04668224b5",
      outputSpecHash: "ed0d905991a8ed7af63c9642dcaaefa401738194b0f1a3e5ce7acbff286d8159",
      promptHash: "1e1444cb187f6ad3adbe6a15e0025347a33e72f9502e84166c38ae8621ea4ebd",
      seedCommitment: "236c24f5b1e65795c6af18ae8d59a20d06eccbc5af5c87534477e95e462b09b9"
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

    expect(digest).toBe("6ee83fcbca21f3a2fb5a455fba8868307379c908bd09dc739a86c47ca911db78");
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
