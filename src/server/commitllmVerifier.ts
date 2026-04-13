/**
 * CommitLLM receipt verifier bridge.
 * Why: enforce real CommitLLM verification via audit binary + verify_v4_binary
 * instead of trusting synthetic digest fields from the MVP implementation.
 */
import { createHash } from "crypto";
import path from "path";
import { spawn } from "child_process";
import pino from "pino";
import { type CommitLLMReceipt, type CommitReceiptVerifier } from "../sdk";

const logger = pino({ name: "agent-captcha-commitllm-verifier" });

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
  report?: CommitLLMBridgeReport;
  error?: string;
  error_detail?: string;
}

export interface CommitLLMBridgeRuntimeOptions {
  scriptPath: string;
  timeoutMs: number;
}

export type CommitLLMBridgeRunner = (
  request: CommitLLMBridgeRequest,
  options: CommitLLMBridgeRuntimeOptions
) => Promise<CommitLLMBridgeResponse>;

export interface CommitLLMBinaryReceiptVerifierConfig {
  bridgeScriptPath?: string;
  timeoutMs?: number;
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

function sha256HexFromBase64(value: string): string {
  const buffer = Buffer.from(value, "base64");
  return createHash("sha256").update(buffer).digest("hex");
}

export async function runCommitLLMBridgeWithUv(
  request: CommitLLMBridgeRequest,
  options: CommitLLMBridgeRuntimeOptions
): Promise<CommitLLMBridgeResponse> {
  return new Promise<CommitLLMBridgeResponse>((resolve, reject) => {
    const child = spawn("uv", ["run", options.scriptPath], {
      stdio: ["pipe", "pipe", "pipe"]
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
  private readonly runner: CommitLLMBridgeRunner;

  public constructor(config?: CommitLLMBinaryReceiptVerifierConfig) {
    this.bridgeScriptPath = config?.bridgeScriptPath ?? path.resolve(process.cwd(), "scripts/commitllm_verify_bridge.py");
    this.timeoutMs = config?.timeoutMs ?? 30_000;
    this.runner = config?.runner ?? runCommitLLMBridgeWithUv;
  }

  public async verifyReceipt(
    receipt: CommitLLMReceipt,
    expected: { challengeId: string; outputHash: string; commitHash: string; agentId: string; answer: string }
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

    const request: CommitLLMBridgeRequest = {
      audit_binary_base64: receipt.artifacts.auditBinaryBase64,
      verifier_key_json: receipt.artifacts.verifierKeyJson,
      ...(receipt.artifacts.verifierKeyId ? { verifier_key_id: receipt.artifacts.verifierKeyId } : {})
    };

    let bridgeResult: CommitLLMBridgeResponse;
    try {
      bridgeResult = await this.runner(request, {
        scriptPath: this.bridgeScriptPath,
        timeoutMs: this.timeoutMs
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
      return { valid: false, reason: "commitllm_bridge_execution_failed" };
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

    const expectedSha = receipt.artifacts.auditBinarySha256 ?? sha256HexFromBase64(receipt.artifacts.auditBinaryBase64);
    if (bridgeResult.audit_binary_sha256 !== expectedSha) {
      return { valid: false, reason: "commitllm_audit_binary_sha256_mismatch" };
    }

    return { valid: true };
  }
}
