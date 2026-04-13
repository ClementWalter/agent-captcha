/**
 * Unit tests for CommitLLM verifier bridge mapping.
 * Why: enforce deterministic failure reasons for bridge/runtime/artifact integrity checks.
 */
import path from "path";
import request from "supertest";
import { describe, expect, it } from "vitest";
import {
  CommitLLMBinaryReceiptVerifier,
  runCommitLLMBridgeWithUv,
  type CommitLLMBridgeRunner
} from "../../src/server/commitllmVerifier";
import { createApp } from "../../src/server/app";
import {
  COMMITLLM_BINDING_VERSION,
  computeCommitLLMBindingHash,
  type CommitLLMReceipt
} from "../../src/sdk";
import { loadCommitLLMFixture } from "../fixtures/commitllmFixture";

const challengeId = "11111111-1111-4111-8111-111111111111";
const answer = "a869260b0ef754a9663330557a06f0499638e854cf73f274fcb62a0d05a19be0";
const modelOutputHash = "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824";

function buildReceipt(overrides?: Partial<CommitLLMReceipt>): CommitLLMReceipt {
  const fixture = loadCommitLLMFixture();
  const baseReceipt: CommitLLMReceipt = {
    challengeId,
    model: "llama-3.1-8b-w8a8",
    provider: "commitllm",
    auditMode: "routine",
    outputHash: modelOutputHash,
    commitHash: fixture.commitHash,
    issuedAt: "2026-01-01T00:00:20.000Z",
    bindingVersion: COMMITLLM_BINDING_VERSION,
    bindingHash: "",
    artifacts: {
      auditBinaryBase64: fixture.auditBinaryBase64,
      verifierKeyJson: fixture.verifierKeyJson,
      auditBinarySha256: fixture.auditBinarySha256,
      verifierKeySha256: fixture.verifierKeySha256
    }
  };

  const merged: CommitLLMReceipt = {
    ...baseReceipt,
    ...overrides,
    artifacts: {
      ...baseReceipt.artifacts,
      ...(overrides?.artifacts ?? {})
    }
  };

  merged.bindingHash =
    overrides?.bindingHash ??
    computeCommitLLMBindingHash({
      challengeId,
      answer,
      modelOutputHash,
      receipt: merged,
      auditBinarySha256: merged.artifacts.auditBinarySha256 ?? fixture.auditBinarySha256,
      verifierKeySha256: merged.artifacts.verifierKeySha256 ?? fixture.verifierKeySha256
    });

  return merged;
}

function buildExpected(receipt: CommitLLMReceipt) {
  const fixture = loadCommitLLMFixture();
  return {
    challengeId,
    outputHash: modelOutputHash,
    commitHash: receipt.commitHash,
    bindingHash: receipt.bindingHash,
    bindingVersion: COMMITLLM_BINDING_VERSION,
    auditBinarySha256: receipt.artifacts.auditBinarySha256 ?? fixture.auditBinarySha256,
    verifierKeySha256: receipt.artifacts.verifierKeySha256 ?? fixture.verifierKeySha256,
    agentId: "demo-agent-001",
    answer
  };
}

function buildPassingRunner(): CommitLLMBridgeRunner {
  const fixture = loadCommitLLMFixture();
  return async () => ({
    ok: true,
    bridge_protocol_version: "agent-captcha-commitllm-bridge-v1",
    verilm_rs_version: "fixture",
    audit_binary_sha256: fixture.auditBinarySha256,
    verifier_key_sha256: fixture.verifierKeySha256,
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
    const receipt = buildReceipt();
    const verifier = new CommitLLMBinaryReceiptVerifier({ runner: buildPassingRunner() });

    const result = await verifier.verifyReceipt(receipt, buildExpected(receipt));

    expect(result.valid).toBe(true);
  });

  it("rejects challenge mismatch before bridge execution", async () => {
    const receipt = buildReceipt();
    const verifier = new CommitLLMBinaryReceiptVerifier({ runner: buildPassingRunner() });

    const result = await verifier.verifyReceipt(receipt, {
      ...buildExpected(receipt),
      challengeId: "22222222-2222-4222-8222-222222222222"
    });

    expect(result.reason).toBe("receipt_challenge_mismatch");
  });

  it("maps bridge errors into commitllm-prefixed reasons", async () => {
    const receipt = buildReceipt();
    const verifier = new CommitLLMBinaryReceiptVerifier({
      runner: async () => ({ ok: false, error: "verilm_rs_not_installed" })
    });

    const result = await verifier.verifyReceipt(receipt, buildExpected(receipt));

    expect(result.reason).toBe("commitllm_verilm_rs_not_installed");
  });

  it("rejects failing verify_v4 reports", async () => {
    const fixture = loadCommitLLMFixture();
    const receipt = buildReceipt();
    const verifier = new CommitLLMBinaryReceiptVerifier({
      runner: async () => ({
        ok: true,
        bridge_protocol_version: "agent-captcha-commitllm-bridge-v1",
        audit_binary_sha256: fixture.auditBinarySha256,
        verifier_key_sha256: fixture.verifierKeySha256,
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

    const result = await verifier.verifyReceipt(receipt, buildExpected(receipt));

    expect(result.reason).toBe("commitllm_verify_v4_failed");
  });

  it("rejects empty check reports", async () => {
    const fixture = loadCommitLLMFixture();
    const receipt = buildReceipt();
    const verifier = new CommitLLMBinaryReceiptVerifier({
      runner: async () => ({
        ok: true,
        bridge_protocol_version: "agent-captcha-commitllm-bridge-v1",
        audit_binary_sha256: fixture.auditBinarySha256,
        verifier_key_sha256: fixture.verifierKeySha256,
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

    const result = await verifier.verifyReceipt(receipt, buildExpected(receipt));

    expect(result.reason).toBe("commitllm_empty_report");
  });

  it("rejects mismatched audit binary hash", async () => {
    const fixture = loadCommitLLMFixture();
    const receipt = buildReceipt();
    const verifier = new CommitLLMBinaryReceiptVerifier({
      runner: async () => ({
        ok: true,
        bridge_protocol_version: "agent-captcha-commitllm-bridge-v1",
        audit_binary_sha256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        verifier_key_sha256: fixture.verifierKeySha256,
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

    const result = await verifier.verifyReceipt(receipt, buildExpected(receipt));

    expect(result.reason).toBe("commitllm_audit_binary_sha256_mismatch");
  });

  it("rejects malformed audit binary base64 without running bridge", async () => {
    const receipt = buildReceipt({
      artifacts: {
        auditBinaryBase64: "not-base64%%%",
        verifierKeyJson: loadCommitLLMFixture().verifierKeyJson
      }
    });
    const verifier = new CommitLLMBinaryReceiptVerifier({
      runner: async () => ({
        ok: true,
        bridge_protocol_version: "agent-captcha-commitllm-bridge-v1",
        audit_binary_sha256: "unused",
        verifier_key_sha256: "unused",
        report: {
          passed: true,
          checks_run: 1,
          checks_passed: 1,
          failures: [],
          classified_failures: [],
          duration_us: 1
        }
      })
    });

    const result = await verifier.verifyReceipt(receipt, buildExpected(receipt));

    expect(result.reason).toBe("receipt_audit_binary_base64_invalid");
  });

  it("returns structured invalid base64 errors from the real python bridge", async () => {
    const result = await runCommitLLMBridgeWithUv(
      {
        audit_binary_base64: "not-base64%%%",
        verifier_key_json: loadCommitLLMFixture().verifierKeyJson
      },
      {
        scriptPath: path.resolve(process.cwd(), "scripts/commitllm_verify_bridge.py"),
        timeoutMs: 5_000,
        stdoutMaxBytes: 500_000,
        maxAuditBinaryBytes: 10_000_000,
        maxVerifierKeyJsonBytes: 250_000,
        bridgeCpuLimitSeconds: 2,
        bridgeMemoryLimitBytes: 512_000_000
      }
    );

    expect(result.error).toBe("invalid_audit_binary_base64");
  });

  it("rejects invalid verify payload schema", async () => {
    const { app } = createApp({ commitReceiptVerifier: new CommitLLMBinaryReceiptVerifier({ runner: buildPassingRunner() }) });
    const api = request(app);

    const response = await api.post("/api/v2/agent-captcha/verify").send({ agentId: "demo-agent-001" });

    expect(response.status).toBe(400);
  });
});
