/**
 * CommitLLM receipt verifier (HTTP bridge to Modal sidecar).
 * Why: we offload `verilm_rs.verify_v4_binary` execution to a Modal-hosted
 * sidecar so the Node API server stays a plain TypeScript deployment (no Rust
 * toolchain, no Python bridge, no PyO3). The server performs all shape/hash
 * checks locally and only hands the audit binary over the wire for the final
 * Rust verifier call.
 */
import pino from "pino";
import {
  COMMITLLM_BINDING_VERSION,
  computeAuditBinarySha256,
  type CommitLLMReceipt,
  type CommitLLMVerifyReport,
  type CommitReceiptVerifier
} from "../sdk";

const logger = pino({ name: "agent-captcha-commitllm-verifier" });

export interface CommitLLMModalVerifyReport {
  passed: boolean;
  checks_run?: number;
  checks_passed?: number;
  failures?: string[];
  [key: string]: unknown;
}

export interface CommitLLMModalVerifyResponse {
  ok: boolean;
  audit_binary_sha256?: string;
  verifier_key_sha256?: string;
  verifier_key_id?: string;
  report?: CommitLLMModalVerifyReport;
  error?: string;
  detail?: string;
}

export interface CommitLLMModalVerifierConfig {
  sidecarUrl: string;
  timeoutMs?: number;
  maxAuditBinaryBytes?: number;
  /**
   * Shared secret sent as `x-sidecar-key` header to authenticate calls to
   * the Modal sidecar. Without this, the sidecar's /key and /verify endpoints
   * are open — an attacker can probe crafted binaries offline.
   *
   * Default: reads SIDECAR_API_KEY env var.
   */
  sidecarApiKey?: string;
  // Override for tests.
  fetchImpl?: typeof fetch;
}

export class CommitLLMModalReceiptVerifier implements CommitReceiptVerifier {
  private readonly sidecarUrl: string;
  private readonly timeoutMs: number;
  private readonly maxAuditBinaryBytes: number;
  private readonly sidecarApiKey: string;
  private readonly fetchImpl: typeof fetch;

  public constructor(config: CommitLLMModalVerifierConfig) {
    if (!config.sidecarUrl) {
      throw new Error("commitllm_modal_verifier_sidecar_url_required");
    }
    this.sidecarUrl = config.sidecarUrl.replace(/\/+$/, "");
    this.timeoutMs = config.timeoutMs ?? 60_000;
    this.maxAuditBinaryBytes = config.maxAuditBinaryBytes ?? 10_000_000;
    this.sidecarApiKey = config.sidecarApiKey ?? process.env.SIDECAR_API_KEY ?? "";
    this.fetchImpl = config.fetchImpl ?? fetch;
  }

  public async verifyReceipt(
    receipt: CommitLLMReceipt,
    expected: {
      challengeId: string;
      outputHash: string;
      commitHash: string;
      bindingHash: string;
      bindingVersion: typeof COMMITLLM_BINDING_VERSION;
      auditBinarySha256: string;
      verifierKeySha256: string;
      agentId: string;
      answer: string;
    }
  ): Promise<{ valid: boolean; reason?: string; report?: CommitLLMVerifyReport }> {
    // Shape checks: keep these local so we never round-trip to Modal for
    // obviously-wrong receipts.
    if (receipt.challengeId !== expected.challengeId) {
      return { valid: false, reason: "receipt_challenge_mismatch" };
    }
    if (receipt.outputHash !== expected.outputHash) {
      return { valid: false, reason: "receipt_output_hash_mismatch" };
    }
    if (receipt.commitHash !== expected.commitHash) {
      return { valid: false, reason: "receipt_commit_hash_mismatch" };
    }
    if (receipt.bindingVersion !== expected.bindingVersion) {
      return { valid: false, reason: "receipt_binding_version_invalid" };
    }
    if (receipt.bindingHash !== expected.bindingHash) {
      return { valid: false, reason: "receipt_binding_hash_mismatch" };
    }

    // Recompute audit digest from payload bytes to defeat substitution.
    // The verifier key hash is cross-checked against the sidecar's response
    // (the sidecar holds the authoritative copy).
    let computedAuditBinarySha256: string;
    try {
      computedAuditBinarySha256 = computeAuditBinarySha256(receipt.artifacts.auditBinaryBase64);
    } catch (error) {
      return {
        valid: false,
        reason: error instanceof Error ? error.message : "receipt_artifact_digest_error"
      };
    }
    if (computedAuditBinarySha256 !== expected.auditBinarySha256) {
      return { valid: false, reason: "receipt_audit_binary_sha256_mismatch" };
    }

    // Payload size bound.
    const estimatedAuditBinaryBytes = Math.floor((receipt.artifacts.auditBinaryBase64.length * 3) / 4);
    if (estimatedAuditBinaryBytes > this.maxAuditBinaryBytes) {
      return { valid: false, reason: "receipt_audit_binary_too_large" };
    }

    const controller = new AbortController();
    const timeoutHandle = setTimeout(() => controller.abort(), this.timeoutMs);
    let response: Response;
    try {
      response = await this.fetchImpl(`${this.sidecarUrl}/verify`, {
        method: "POST",
        headers: {
          "content-type": "application/json",
          ...(this.sidecarApiKey ? { "x-sidecar-key": this.sidecarApiKey } : {}),
        },
        body: JSON.stringify({
          audit_binary_base64: receipt.artifacts.auditBinaryBase64,
          // Fix 3: pass expected output hash so the sidecar can cross-check
          // that the audit binary's internal commitments match the claimed
          // model output. Prevents rebinding a valid binary to arbitrary text.
          expected_output_hash: expected.outputHash,
        }),
        signal: controller.signal
      });
    } catch (error) {
      logger.warn(
        { err: error, sidecarUrl: this.sidecarUrl, challengeId: receipt.challengeId },
        "CommitLLM Modal sidecar request failed"
      );
      const reason = error instanceof Error && error.name === "AbortError"
        ? "commitllm_modal_timeout"
        : "commitllm_modal_unreachable";
      return { valid: false, reason };
    } finally {
      clearTimeout(timeoutHandle);
    }

    let bridgeResult: CommitLLMModalVerifyResponse;
    try {
      bridgeResult = (await response.json()) as CommitLLMModalVerifyResponse;
    } catch {
      return { valid: false, reason: "commitllm_modal_invalid_response" };
    }

    if (!response.ok || !bridgeResult.ok) {
      const code = bridgeResult.error ?? `http_${response.status}`;
      logger.warn({ code, detail: bridgeResult.detail }, "CommitLLM Modal rejected receipt");
      return { valid: false, reason: `commitllm_modal_${code}` };
    }

    const report = bridgeResult.report;
    if (!report || typeof report.passed !== "boolean") {
      return { valid: false, reason: "commitllm_verify_v4_invalid_report" };
    }
    const checksRun = report.checks_run ?? 0;
    const checksPassed = report.checks_passed ?? 0;

    if (checksRun === 0) {
      return { valid: false, reason: "commitllm_verify_v4_empty_report" };
    }

    if (!report.passed) {
      return { valid: false, reason: "commitllm_verify_v4_failed" };
    }

    if (bridgeResult.audit_binary_sha256 && bridgeResult.audit_binary_sha256 !== expected.auditBinarySha256) {
      return { valid: false, reason: "commitllm_audit_binary_sha256_mismatch" };
    }
    if (bridgeResult.verifier_key_sha256 && bridgeResult.verifier_key_sha256 !== expected.verifierKeySha256) {
      return { valid: false, reason: "commitllm_verifier_key_sha256_mismatch" };
    }

    const normalizedReport: CommitLLMVerifyReport = {
      passed: report.passed,
      checksRun: report.checks_run ?? 0,
      checksPassed: report.checks_passed ?? 0,
      failures: Array.isArray(report.failures) ? report.failures.slice(0, 32) : [],
      ...(bridgeResult.verifier_key_id ? { verifierKeyId: bridgeResult.verifier_key_id } : {})
    };
    return { valid: true, report: normalizedReport };
  }
}
