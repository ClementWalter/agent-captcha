/**
 * CommitLLM receipt verifier bridge.
 * Why: enforce real CommitLLM verification via audit binary + verify_v4_binary
 * instead of trusting synthetic digest fields from the MVP implementation.
 */
import path from "path";
import { spawn } from "child_process";
import pino from "pino";
import {
  COMMITLLM_BINDING_VERSION,
  computeAuditBinarySha256,
  computeVerifierKeySha256,
  type CommitLLMReceipt,
  type CommitReceiptVerifier
} from "../sdk";

const logger = pino({ name: "agent-captcha-commitllm-verifier" });
const BRIDGE_PROTOCOL_VERSION = "agent-captcha-commitllm-bridge-v1";

export interface CommitLLMBridgeRequest {
  audit_binary_base64: string;
  verifier_key_json: string;
  verifier_key_id?: string;
}

export interface CommitLLMBridgeFailure {
  code: string;
  category: string;
  message: string;
}

export interface CommitLLMBridgeReport {
  passed: boolean;
  checks_run: number;
  checks_passed: number;
  failures: string[];
  classified_failures: CommitLLMBridgeFailure[];
  coverage_level?: string;
  duration_us: number;
}

export interface CommitLLMBridgeResponse {
  ok: boolean;
  audit_binary_sha256?: string;
  verifier_key_sha256?: string;
  bridge_protocol_version?: string;
  verilm_rs_version?: string;
  report?: CommitLLMBridgeReport;
  error?: string;
  error_detail?: string;
}

export interface CommitLLMBridgeRuntimeOptions {
  scriptPath: string;
  timeoutMs: number;
  stdoutMaxBytes: number;
  maxAuditBinaryBytes: number;
  maxVerifierKeyJsonBytes: number;
  bridgeCpuLimitSeconds: number;
  bridgeMemoryLimitBytes: number;
}

export type CommitLLMBridgeRunner = (
  request: CommitLLMBridgeRequest,
  options: CommitLLMBridgeRuntimeOptions
) => Promise<CommitLLMBridgeResponse>;

export interface CommitLLMBinaryReceiptVerifierConfig {
  bridgeScriptPath?: string;
  timeoutMs?: number;
  stdoutMaxBytes?: number;
  maxAuditBinaryBytes?: number;
  maxVerifierKeyJsonBytes?: number;
  bridgeCpuLimitSeconds?: number;
  bridgeMemoryLimitBytes?: number;
  expectedBridgeProtocolVersion?: string;
  expectedVerilmRsVersion?: string;
  runner?: CommitLLMBridgeRunner;
}

function createReasonFromBridgeError(errorCode: string | undefined): string {
  if (!errorCode) {
    return "commitllm_bridge_error";
  }

  const normalized = errorCode.trim().replace(/[^a-zA-Z0-9_]+/g, "_").toLowerCase();
  return `commitllm_${normalized}`;
}

function parseBridgeResponse(payload: string): CommitLLMBridgeResponse {
  const parsed = JSON.parse(payload) as CommitLLMBridgeResponse;
  if (typeof parsed !== "object" || parsed === null || typeof parsed.ok !== "boolean") {
    throw new Error("invalid_bridge_response_shape");
  }

  if (parsed.ok && (!parsed.report || typeof parsed.report.passed !== "boolean")) {
    throw new Error("invalid_bridge_report_shape");
  }

  return parsed;
}

function createBridgeExecutionReason(error: unknown): string {
  const message = error instanceof Error ? error.message : String(error);
  if (message.includes("commitllm_bridge_timeout")) {
    return "commitllm_bridge_timeout";
  }
  if (message.includes("commitllm_bridge_stdout_limit_exceeded")) {
    return "commitllm_bridge_stdout_limit_exceeded";
  }
  if (message.includes("ENOENT")) {
    return "commitllm_bridge_runner_not_found";
  }
  return "commitllm_bridge_execution_failed";
}

export async function runCommitLLMBridgeWithUv(
  request: CommitLLMBridgeRequest,
  options: CommitLLMBridgeRuntimeOptions
): Promise<CommitLLMBridgeResponse> {
  // Why: apply deterministic input bounds before spawning python to prevent oversized payload abuse.
  const estimatedAuditBinaryBytes = Math.floor((request.audit_binary_base64.length * 3) / 4);
  if (estimatedAuditBinaryBytes > options.maxAuditBinaryBytes) {
    return {
      ok: false,
      error: "audit_binary_too_large",
      error_detail: `estimated=${estimatedAuditBinaryBytes}, limit=${options.maxAuditBinaryBytes}`
    };
  }

  const verifierKeyBytes = Buffer.byteLength(request.verifier_key_json, "utf8");
  if (verifierKeyBytes > options.maxVerifierKeyJsonBytes) {
    return {
      ok: false,
      error: "verifier_key_json_too_large",
      error_detail: `size=${verifierKeyBytes}, limit=${options.maxVerifierKeyJsonBytes}`
    };
  }

  return new Promise<CommitLLMBridgeResponse>((resolve, reject) => {
    const child = spawn("uv", ["run", options.scriptPath], {
      stdio: ["pipe", "pipe", "pipe"],
      env: {
        ...process.env,
        AGENT_CAPTCHA_BRIDGE_PROTOCOL_VERSION: BRIDGE_PROTOCOL_VERSION,
        AGENT_CAPTCHA_BRIDGE_MAX_AUDIT_BINARY_BYTES: String(options.maxAuditBinaryBytes),
        AGENT_CAPTCHA_BRIDGE_MAX_VERIFIER_KEY_JSON_BYTES: String(options.maxVerifierKeyJsonBytes),
        AGENT_CAPTCHA_BRIDGE_CPU_SECONDS: String(options.bridgeCpuLimitSeconds),
        AGENT_CAPTCHA_BRIDGE_MAX_MEMORY_BYTES: String(options.bridgeMemoryLimitBytes)
      }
    });

    let stdout = "";
    let stderr = "";
    let settled = false;

    const timeoutHandle = setTimeout(() => {
      if (!settled) {
        settled = true;
        child.kill("SIGKILL");
        reject(new Error("commitllm_bridge_timeout"));
      }
    }, options.timeoutMs);

    child.stdout.on("data", (chunk: Buffer) => {
      stdout += chunk.toString("utf8");
      if (!settled && Buffer.byteLength(stdout, "utf8") > options.stdoutMaxBytes) {
        settled = true;
        clearTimeout(timeoutHandle);
        child.kill("SIGKILL");
        reject(new Error("commitllm_bridge_stdout_limit_exceeded"));
      }
    });

    child.stderr.on("data", (chunk: Buffer) => {
      stderr += chunk.toString("utf8");
    });

    child.on("error", (error: Error) => {
      if (!settled) {
        settled = true;
        clearTimeout(timeoutHandle);
        reject(error);
      }
    });

    child.on("close", (code: number | null) => {
      if (settled) {
        return;
      }

      settled = true;
      clearTimeout(timeoutHandle);

      if (code !== 0) {
        if (stdout.trim()) {
          try {
            resolve(parseBridgeResponse(stdout));
            return;
          } catch {
            // Why: preserve deterministic non-JSON exit failure if bridge crashed before writing payload.
          }
        }

        reject(new Error(`commitllm_bridge_exit_${code ?? -1}: ${stderr.trim()}`));
        return;
      }

      try {
        resolve(parseBridgeResponse(stdout));
      } catch (error) {
        reject(error);
      }
    });

    child.stdin.end(JSON.stringify(request));
  });
}

export class CommitLLMBinaryReceiptVerifier implements CommitReceiptVerifier {
  private readonly bridgeScriptPath: string;
  private readonly timeoutMs: number;
  private readonly stdoutMaxBytes: number;
  private readonly maxAuditBinaryBytes: number;
  private readonly maxVerifierKeyJsonBytes: number;
  private readonly bridgeCpuLimitSeconds: number;
  private readonly bridgeMemoryLimitBytes: number;
  private readonly expectedBridgeProtocolVersion: string;
  private readonly expectedVerilmRsVersion: string | undefined;
  private readonly runner: CommitLLMBridgeRunner;

  public constructor(config?: CommitLLMBinaryReceiptVerifierConfig) {
    this.bridgeScriptPath = config?.bridgeScriptPath ?? path.resolve(process.cwd(), "scripts/commitllm_verify_bridge.py");
    this.timeoutMs = config?.timeoutMs ?? 30_000;
    this.stdoutMaxBytes = config?.stdoutMaxBytes ?? 1_000_000;
    this.maxAuditBinaryBytes = config?.maxAuditBinaryBytes ?? 10_000_000;
    this.maxVerifierKeyJsonBytes = config?.maxVerifierKeyJsonBytes ?? 250_000;
    this.bridgeCpuLimitSeconds = config?.bridgeCpuLimitSeconds ?? 2;
    this.bridgeMemoryLimitBytes = config?.bridgeMemoryLimitBytes ?? 512_000_000;
    this.expectedBridgeProtocolVersion = config?.expectedBridgeProtocolVersion ?? BRIDGE_PROTOCOL_VERSION;
    this.expectedVerilmRsVersion = config?.expectedVerilmRsVersion;
    this.runner = config?.runner ?? runCommitLLMBridgeWithUv;
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
  ): Promise<{ valid: boolean; reason?: string }> {
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

    let computedAuditBinarySha256: string;
    let computedVerifierKeySha256: string;
    try {
      computedAuditBinarySha256 = computeAuditBinarySha256(receipt.artifacts.auditBinaryBase64);
      computedVerifierKeySha256 = computeVerifierKeySha256(receipt.artifacts.verifierKeyJson);
    } catch (error) {
      return {
        valid: false,
        reason: error instanceof Error ? error.message : "receipt_artifact_digest_error"
      };
    }

    if (computedAuditBinarySha256 !== expected.auditBinarySha256) {
      return { valid: false, reason: "receipt_audit_binary_sha256_mismatch" };
    }

    if (computedVerifierKeySha256 !== expected.verifierKeySha256) {
      return { valid: false, reason: "receipt_verifier_key_sha256_mismatch" };
    }

    if (receipt.artifacts.auditBinarySha256 && receipt.artifacts.auditBinarySha256 !== expected.auditBinarySha256) {
      return { valid: false, reason: "receipt_artifact_audit_sha256_mismatch" };
    }

    if (receipt.artifacts.verifierKeySha256 && receipt.artifacts.verifierKeySha256 !== expected.verifierKeySha256) {
      return { valid: false, reason: "receipt_artifact_verifier_key_sha256_mismatch" };
    }

    const request: CommitLLMBridgeRequest = {
      audit_binary_base64: receipt.artifacts.auditBinaryBase64,
      verifier_key_json: receipt.artifacts.verifierKeyJson,
      ...(receipt.artifacts.verifierKeyId ? { verifier_key_id: receipt.artifacts.verifierKeyId } : {})
    };

    let bridgeResult: CommitLLMBridgeResponse;
    try {
      bridgeResult = await this.runner(request, {
        scriptPath: this.bridgeScriptPath,
        timeoutMs: this.timeoutMs,
        stdoutMaxBytes: this.stdoutMaxBytes,
        maxAuditBinaryBytes: this.maxAuditBinaryBytes,
        maxVerifierKeyJsonBytes: this.maxVerifierKeyJsonBytes,
        bridgeCpuLimitSeconds: this.bridgeCpuLimitSeconds,
        bridgeMemoryLimitBytes: this.bridgeMemoryLimitBytes
      });
    } catch (error) {
      logger.warn(
        {
          err: error,
          challengeId: receipt.challengeId,
          model: receipt.model,
          provider: receipt.provider
        },
        "CommitLLM bridge execution failed"
      );
      return { valid: false, reason: createBridgeExecutionReason(error) };
    }

    if (!bridgeResult.ok) {
      return { valid: false, reason: createReasonFromBridgeError(bridgeResult.error) };
    }

    if (!bridgeResult.report?.passed) {
      return { valid: false, reason: "commitllm_verify_v4_failed" };
    }

    if (bridgeResult.report.checks_run < 1) {
      return { valid: false, reason: "commitllm_empty_report" };
    }

    if (bridgeResult.bridge_protocol_version !== this.expectedBridgeProtocolVersion) {
      return { valid: false, reason: "commitllm_bridge_protocol_version_mismatch" };
    }

    if (this.expectedVerilmRsVersion && bridgeResult.verilm_rs_version !== this.expectedVerilmRsVersion) {
      return { valid: false, reason: "commitllm_verilm_rs_version_mismatch" };
    }

    if (bridgeResult.audit_binary_sha256 !== expected.auditBinarySha256) {
      return { valid: false, reason: "commitllm_audit_binary_sha256_mismatch" };
    }

    if (bridgeResult.verifier_key_sha256 !== expected.verifierKeySha256) {
      return { valid: false, reason: "commitllm_verifier_key_sha256_mismatch" };
    }

    return { valid: true };
  }
}
