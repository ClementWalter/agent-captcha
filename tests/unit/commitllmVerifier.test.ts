/**
 * Unit tests for the Modal-backed CommitLLM verifier.
 * Why: shape/hash checks must fail locally before any wire trip, and bridge
 * errors must surface as deterministic reasons.
 */
import { describe, expect, it } from "vitest";
import {
  CommitLLMModalReceiptVerifier,
  type CommitLLMModalVerifyResponse
} from "../../src/server/commitllmVerifier";
import {
  COMMITLLM_BINDING_VERSION,
  computeCommitLLMBindingHash,
  type CommitLLMReceipt
} from "../../src/sdk";
import { loadCommitLLMFixture } from "../fixtures/commitllmFixture";

const challengeId = "11111111-1111-4111-8111-111111111111";
const answer = "4407d1437faaaef4076157f42119b9d34ea1d394bc3dfea40629e592999ea770";
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
    agentId: "b7a238dbf5a793f066a95e25d401f3557c6f8e38aeb11e0529861285bc051fd2",
    answer
  };
}

function fetchReturning(response: CommitLLMModalVerifyResponse, status = 200): typeof fetch {
  return (async () => {
    return new Response(JSON.stringify(response), {
      status,
      headers: { "content-type": "application/json" }
    });
  }) as typeof fetch;
}

function makeVerifier(fetchImpl: typeof fetch): CommitLLMModalReceiptVerifier {
  return new CommitLLMModalReceiptVerifier({
    sidecarUrl: "https://example.modal.run",
    fetchImpl
  });
}

describe("commitllm modal verifier", () => {
  it("accepts a passing report", async () => {
    const receipt = buildReceipt();
    const verifier = makeVerifier(fetchReturning({
      ok: true,
      audit_binary_sha256: receipt.artifacts.auditBinarySha256,
      report: { passed: true, checks_run: 7, checks_passed: 7 }
    }));

    const result = await verifier.verifyReceipt(receipt, buildExpected(receipt));

    expect(result.valid).toBe(true);
  });

  it("rejects challenge mismatch before hitting the sidecar", async () => {
    const receipt = buildReceipt();
    let called = false;
    const verifier = makeVerifier((() => {
      called = true;
      throw new Error("should not be called");
    }) as typeof fetch);

    const result = await verifier.verifyReceipt(receipt, {
      ...buildExpected(receipt),
      challengeId: "22222222-2222-4222-8222-222222222222"
    });

    expect(result.reason).toBe("receipt_challenge_mismatch");
    expect(called).toBe(false);
  });

  it("maps sidecar errors into commitllm_modal-prefixed reasons", async () => {
    const receipt = buildReceipt();
    const verifier = makeVerifier(fetchReturning({ ok: false, error: "verify_v4_binary_failed" }, 500));

    const result = await verifier.verifyReceipt(receipt, buildExpected(receipt));

    expect(result.reason).toBe("commitllm_modal_verify_v4_binary_failed");
  });

  it("rejects failing verify_v4 reports", async () => {
    const receipt = buildReceipt();
    const verifier = makeVerifier(fetchReturning({
      ok: true,
      audit_binary_sha256: receipt.artifacts.auditBinarySha256,
      report: { passed: false, checks_run: 5, checks_passed: 3, failures: ["tampered"] }
    }));

    const result = await verifier.verifyReceipt(receipt, buildExpected(receipt));

    expect(result.reason).toBe("commitllm_verify_v4_failed");
  });

  it("rejects reports with high pass rate but passed=false", async () => {
    const receipt = buildReceipt();
    const verifier = makeVerifier(fetchReturning({
      ok: true,
      audit_binary_sha256: receipt.artifacts.auditBinarySha256,
      report: { passed: false, checks_run: 100, checks_passed: 90, failures: ["attn-bound"] }
    }));

    const result = await verifier.verifyReceipt(receipt, buildExpected(receipt));

    expect(result.reason).toBe("commitllm_verify_v4_failed");
  });

  it("rejects empty reports", async () => {
    const receipt = buildReceipt();
    const verifier = makeVerifier(fetchReturning({
      ok: true,
      audit_binary_sha256: receipt.artifacts.auditBinarySha256,
      report: { passed: true, checks_run: 0, checks_passed: 0 }
    }));

    const result = await verifier.verifyReceipt(receipt, buildExpected(receipt));

    expect(result.reason).toBe("commitllm_verify_v4_empty_report");
  });

  it("rejects mismatched audit binary hash from the sidecar", async () => {
    const receipt = buildReceipt();
    const verifier = makeVerifier(fetchReturning({
      ok: true,
      audit_binary_sha256: "a".repeat(64),
      report: { passed: true, checks_run: 7, checks_passed: 7 }
    }));

    const result = await verifier.verifyReceipt(receipt, buildExpected(receipt));

    expect(result.reason).toBe("commitllm_audit_binary_sha256_mismatch");
  });

  it("rejects malformed audit binary base64 without running the sidecar", async () => {
    const fixture = loadCommitLLMFixture();
    const receipt = buildReceipt({
      artifacts: {
        auditBinaryBase64: "not-base64%%%",
        verifierKeyJson: fixture.verifierKeyJson,
        verifierKeySha256: fixture.verifierKeySha256
      }
    });
    let called = false;
    const verifier = makeVerifier((() => {
      called = true;
      throw new Error("should not be called");
    }) as typeof fetch);

    const result = await verifier.verifyReceipt(receipt, buildExpected(receipt));

    expect(result.reason).toBe("receipt_audit_binary_base64_invalid");
    expect(called).toBe(false);
  });

  it("surfaces unreachable sidecar as commitllm_modal_unreachable", async () => {
    const receipt = buildReceipt();
    const verifier = makeVerifier((async () => {
      throw new Error("ECONNREFUSED");
    }) as typeof fetch);

    const result = await verifier.verifyReceipt(receipt, buildExpected(receipt));

    expect(result.reason).toBe("commitllm_modal_unreachable");
  });
});
