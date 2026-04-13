/**
 * Unit tests for CommitLLM verifier bridge mapping.
 * Why: ensure bridge responses map to stable API error reasons.
 */
import request from "supertest";
import { describe, expect, it } from "vitest";
import { CommitLLMBinaryReceiptVerifier, type CommitLLMBridgeRunner } from "../../src/server/commitllmVerifier";
import { createApp } from "../../src/server/app";
import { type CommitLLMReceipt } from "../../src/sdk";

function buildReceipt(overrides?: Partial<CommitLLMReceipt>): CommitLLMReceipt {
  const baseReceipt: CommitLLMReceipt = {
    challengeId: "11111111-1111-4111-8111-111111111111",
    model: "llama-3.1-8b-w8a8",
    provider: "commitllm",
    auditMode: "routine",
    outputHash: "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824",
    commitHash: "48d977dbc63a94833435df00d8c29d2cafd9a5f7b3ab84d44d3221863bc008e4",
    issuedAt: "2026-01-01T00:00:20.000Z",
    artifacts: {
      auditBinaryBase64: Buffer.from("audit-binary").toString("base64"),
      verifierKeyJson: JSON.stringify({ key_id: "demo-key" })
    }
  };

  return {
    ...baseReceipt,
    ...overrides,
    artifacts: {
      ...baseReceipt.artifacts,
      ...(overrides?.artifacts ?? {})
    }
  };
}

function buildPassingRunner(): CommitLLMBridgeRunner {
  return async (bridgeRequest) => ({
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
  });
}

describe("commitllm bridge verifier", () => {
  it("accepts a passing bridge report", async () => {
    const verifier = new CommitLLMBinaryReceiptVerifier({ runner: buildPassingRunner() });

    const result = await verifier.verifyReceipt(buildReceipt(), {
      challengeId: "11111111-1111-4111-8111-111111111111",
      outputHash: "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824",
      commitHash: "48d977dbc63a94833435df00d8c29d2cafd9a5f7b3ab84d44d3221863bc008e4",
      agentId: "demo-agent-001",
      answer: "a869260b0ef754a9663330557a06f0499638e854cf73f274fcb62a0d05a19be0"
    });

    expect(result.valid).toBe(true);
  });

  it("rejects challenge mismatch before bridge execution", async () => {
    const verifier = new CommitLLMBinaryReceiptVerifier({ runner: buildPassingRunner() });

    const result = await verifier.verifyReceipt(buildReceipt(), {
      challengeId: "22222222-2222-4222-8222-222222222222",
      outputHash: "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824",
      commitHash: "48d977dbc63a94833435df00d8c29d2cafd9a5f7b3ab84d44d3221863bc008e4",
      agentId: "demo-agent-001",
      answer: "a869260b0ef754a9663330557a06f0499638e854cf73f274fcb62a0d05a19be0"
    });

    expect(result.reason).toBe("receipt_challenge_mismatch");
  });

  it("maps bridge errors into commitllm-prefixed reasons", async () => {
    const verifier = new CommitLLMBinaryReceiptVerifier({
      runner: async () => ({ ok: false, error: "verilm_rs_not_installed" })
    });

    const result = await verifier.verifyReceipt(buildReceipt(), {
      challengeId: "11111111-1111-4111-8111-111111111111",
      outputHash: "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824",
      commitHash: "48d977dbc63a94833435df00d8c29d2cafd9a5f7b3ab84d44d3221863bc008e4",
      agentId: "demo-agent-001",
      answer: "a869260b0ef754a9663330557a06f0499638e854cf73f274fcb62a0d05a19be0"
    });

    expect(result.reason).toBe("commitllm_verilm_rs_not_installed");
  });

  it("rejects failing verify_v4 reports", async () => {
    const verifier = new CommitLLMBinaryReceiptVerifier({
      runner: async () => ({
        ok: true,
        audit_binary_sha256: "3df12b1aaa868d4278b195cd3d7d856406d83ff673eb7fad3d19469ab2a64217",
        report: {
          passed: false,
          checks_run: 5,
          checks_passed: 3,
          failures: ["tampered"],
          classified_failures: [],
          coverage_level: "routine",
          duration_us: 1200
        }
      })
    });

    const result = await verifier.verifyReceipt(buildReceipt(), {
      challengeId: "11111111-1111-4111-8111-111111111111",
      outputHash: "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824",
      commitHash: "48d977dbc63a94833435df00d8c29d2cafd9a5f7b3ab84d44d3221863bc008e4",
      agentId: "demo-agent-001",
      answer: "a869260b0ef754a9663330557a06f0499638e854cf73f274fcb62a0d05a19be0"
    });

    expect(result.reason).toBe("commitllm_verify_v4_failed");
  });

  it("rejects empty check reports", async () => {
    const verifier = new CommitLLMBinaryReceiptVerifier({
      runner: async () => ({
        ok: true,
        audit_binary_sha256: "3df12b1aaa868d4278b195cd3d7d856406d83ff673eb7fad3d19469ab2a64217",
        report: {
          passed: true,
          checks_run: 0,
          checks_passed: 0,
          failures: [],
          classified_failures: [],
          coverage_level: "routine",
          duration_us: 1200
        }
      })
    });

    const result = await verifier.verifyReceipt(buildReceipt(), {
      challengeId: "11111111-1111-4111-8111-111111111111",
      outputHash: "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824",
      commitHash: "48d977dbc63a94833435df00d8c29d2cafd9a5f7b3ab84d44d3221863bc008e4",
      agentId: "demo-agent-001",
      answer: "a869260b0ef754a9663330557a06f0499638e854cf73f274fcb62a0d05a19be0"
    });

    expect(result.reason).toBe("commitllm_empty_report");
  });

  it("rejects mismatched audit binary hash", async () => {
    const verifier = new CommitLLMBinaryReceiptVerifier({
      runner: async () => ({
        ok: true,
        audit_binary_sha256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
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

    const result = await verifier.verifyReceipt(
      buildReceipt({
        artifacts: {
          auditBinaryBase64: Buffer.from("audit-binary").toString("base64"),
          verifierKeyJson: JSON.stringify({ key_id: "demo-key" }),
          auditBinarySha256: "3df12b1aaa868d4278b195cd3d7d856406d83ff673eb7fad3d19469ab2a64217"
        }
      }),
      {
        challengeId: "11111111-1111-4111-8111-111111111111",
        outputHash: "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824",
        commitHash: "48d977dbc63a94833435df00d8c29d2cafd9a5f7b3ab84d44d3221863bc008e4",
        agentId: "demo-agent-001",
        answer: "a869260b0ef754a9663330557a06f0499638e854cf73f274fcb62a0d05a19be0"
      }
    );

    expect(result.reason).toBe("commitllm_audit_binary_sha256_mismatch");
  });

  it("rejects invalid verify payload schema", async () => {
    const { app } = createApp({ commitReceiptVerifier: new CommitLLMBinaryReceiptVerifier({ runner: buildPassingRunner() }) });
    const api = request(app);

    const response = await api.post("/api/agent-captcha/verify").send({ agentId: "demo-agent-001" });

    expect(response.status).toBe(400);
  });
});
