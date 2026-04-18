/**
 * Agent CAPTCHA SDK primitives.
 * Why: keep challenge binding, proof signing, and proof verification deterministic
 * across clients and server while delegating CommitLLM checks to a real verifier bridge.
 */
import { signAsync, verifyAsync } from "@noble/ed25519";
import { sha256 } from "@noble/hashes/sha256";
import { bytesToHex, hexToBytes, utf8ToBytes } from "@noble/hashes/utils";

export type AuditMode = "routine" | "deep";

export interface AgentCaptchaPolicy {
  allowedModels: string[];
  allowedAuditModes: AuditMode[];
  requiresCommitReceipt: boolean;
  maxChallengeAgeMs: number;
}

export interface AgentChallenge {
  challengeId: string;
  nonce: string;
  issuedAt: string;
  expiresAt: string;
  policy: AgentCaptchaPolicy;
}

export interface CommitLLMArtifacts {
  auditBinaryBase64: string;
  /**
   * The verifier key SHA256. Required: this is what the receipt binds to.
   * The full key JSON is not shipped — it can be >1GB for a 7B model. The
   * trusted verifier (Modal sidecar) holds the authoritative copy and
   * validates audit binaries against it on request.
   */
  verifierKeySha256: string;
  verifierKeyId?: string;
  auditBinarySha256?: string;
  /**
   * Optional: full verifier key JSON. If supplied, the SDK will recompute its
   * SHA256 and cross-check against `verifierKeySha256`. Omit when bridging to
   * a remote verifier that holds the key itself.
   */
  verifierKeyJson?: string;
}

export const COMMITLLM_BINDING_VERSION = "agent-captcha-binding-v1" as const;

export interface CommitLLMReceipt {
  challengeId: string;
  model: string;
  modelVersion?: string;
  provider: string;
  auditMode: AuditMode;
  outputHash: string;
  commitHash: string;
  issuedAt: string;
  bindingVersion: typeof COMMITLLM_BINDING_VERSION;
  bindingHash: string;
  artifacts: CommitLLMArtifacts;
}

export interface AgentProofPayload {
  challengeId: string;
  agentId: string;
  agentPublicKey: string;
  answer: string;
  modelOutput: string;
  modelOutputHash: string;
  commitReceipt: CommitLLMReceipt;
  createdAt: string;
}

export interface AgentProof {
  payload: AgentProofPayload;
  signature: string;
}

export interface AgentSigner {
  agentId: string;
  privateKeyHex: string;
  publicKeyHex: string;
}

/**
 * Structured CommitLLM verification report surfaced by the remote verifier.
 * `passed` is the Rust `verify_v4_binary` overall result; the raw
 * checks/failures are exposed so UIs can show provenance next to each
 * message.
 */
export interface CommitLLMVerifyReport {
  passed: boolean;
  checksRun: number;
  checksPassed: number;
  failures: string[];
  verifierKeyId?: string;
}

export interface CommitReceiptVerifier {
  verifyReceipt(
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
    },
  ): Promise<{
    valid: boolean;
    reason?: string;
    report?: CommitLLMVerifyReport;
  }>;
}

function sha256Hex(value: string): string {
  return bytesToHex(sha256(utf8ToBytes(value)));
}

export function computeChallengeAnswer(
  challenge: AgentChallenge,
  agentId: string,
): string {
  const material = `agent-captcha:v1|${challenge.challengeId}|${challenge.nonce}|${agentId}`;
  return sha256Hex(material);
}

export function computeOutputHash(modelOutput: string): string {
  return sha256Hex(modelOutput);
}

function stableStringify(value: unknown): string {
  if (value === null || typeof value !== "object") {
    return JSON.stringify(value);
  }

  if (Array.isArray(value)) {
    const serialized = value.map((entry) => stableStringify(entry)).join(",");
    return `[${serialized}]`;
  }

  const record = value as Record<string, unknown>;
  const keys = Object.keys(record).sort();
  const serialized = keys
    .map((key) => `${JSON.stringify(key)}:${stableStringify(record[key])}`)
    .join(",");

  return `{${serialized}}`;
}

function decodeBase64Strict(value: string): Uint8Array {
  const normalized = value.trim();
  if (
    normalized.length === 0 ||
    normalized.length % 4 !== 0 ||
    !/^[A-Za-z0-9+/]+={0,2}$/.test(normalized)
  ) {
    throw new Error("receipt_audit_binary_base64_invalid");
  }

  const decoded = Buffer.from(normalized, "base64");
  const roundTrip = decoded.toString("base64");
  if (roundTrip.replace(/=+$/g, "") !== normalized.replace(/=+$/g, "")) {
    throw new Error("receipt_audit_binary_base64_invalid");
  }

  return decoded;
}

function canonicalizeJsonString(raw: string): string {
  try {
    const parsed = JSON.parse(raw) as unknown;
    return stableStringify(parsed);
  } catch {
    throw new Error("receipt_verifier_key_json_invalid");
  }
}

export function computeAuditBinarySha256(auditBinaryBase64: string): string {
  return bytesToHex(sha256(decodeBase64Strict(auditBinaryBase64)));
}

export function computeVerifierKeySha256(verifierKeyJson: string): string {
  const canonical = canonicalizeJsonString(verifierKeyJson);
  return sha256Hex(canonical);
}

export interface CommitLLMBindingMaterial {
  version: typeof COMMITLLM_BINDING_VERSION;
  challengeId: string;
  answer: string;
  modelOutputHash: string;
  receiptOutputHash: string;
  provider: string;
  model: string;
  modelVersion: string | null;
  auditMode: AuditMode;
  commitHash: string;
  receiptIssuedAt: string;
  artifact: {
    auditBinarySha256: string;
    verifierKeySha256: string;
    verifierKeyId: string | null;
  };
}

export function buildCommitLLMBindingMaterial(input: {
  challengeId: string;
  answer: string;
  modelOutputHash: string;
  receipt: CommitLLMReceipt;
  auditBinarySha256: string;
  verifierKeySha256: string;
}): CommitLLMBindingMaterial {
  return {
    version: COMMITLLM_BINDING_VERSION,
    challengeId: input.challengeId,
    answer: input.answer,
    modelOutputHash: input.modelOutputHash,
    receiptOutputHash: input.receipt.outputHash,
    provider: input.receipt.provider,
    model: input.receipt.model,
    modelVersion: input.receipt.modelVersion ?? null,
    auditMode: input.receipt.auditMode,
    commitHash: input.receipt.commitHash,
    receiptIssuedAt: input.receipt.issuedAt,
    artifact: {
      auditBinarySha256: input.auditBinarySha256,
      verifierKeySha256: input.verifierKeySha256,
      verifierKeyId: input.receipt.artifacts.verifierKeyId ?? null,
    },
  };
}

export function computeCommitLLMBindingHash(input: {
  challengeId: string;
  answer: string;
  modelOutputHash: string;
  receipt: CommitLLMReceipt;
  auditBinarySha256: string;
  verifierKeySha256: string;
}): string {
  const material = buildCommitLLMBindingMaterial(input);
  return sha256Hex(stableStringify(material));
}

function deriveArtifactHashes(receipt: CommitLLMReceipt): {
  auditBinarySha256: string;
  verifierKeySha256: string;
} {
  const computedAuditBinarySha256 = computeAuditBinarySha256(
    receipt.artifacts.auditBinaryBase64,
  );
  if (
    receipt.artifacts.auditBinarySha256 &&
    receipt.artifacts.auditBinarySha256 !== computedAuditBinarySha256
  ) {
    throw new Error("receipt_artifact_audit_sha256_mismatch");
  }

  // When the receipt carries the full verifier key JSON, hash it and verify.
  // When it carries only the sha256 (remote-verifier mode), trust the stated
  // hash — the remote verifier will cross-check it against its own cached key.
  let verifierKeySha256: string;
  if (receipt.artifacts.verifierKeyJson) {
    verifierKeySha256 = computeVerifierKeySha256(
      receipt.artifacts.verifierKeyJson,
    );
    if (receipt.artifacts.verifierKeySha256 !== verifierKeySha256) {
      throw new Error("receipt_artifact_verifier_key_sha256_mismatch");
    }
  } else {
    if (!/^[0-9a-f]{64}$/.test(receipt.artifacts.verifierKeySha256)) {
      throw new Error("receipt_artifact_verifier_key_sha256_invalid");
    }
    verifierKeySha256 = receipt.artifacts.verifierKeySha256;
  }

  return {
    auditBinarySha256: computedAuditBinarySha256,
    verifierKeySha256,
  };
}

function serializePayload(payload: AgentProofPayload): Uint8Array {
  return utf8ToBytes(stableStringify(payload));
}

export async function createAgentProof(input: {
  challenge: AgentChallenge;
  signer: AgentSigner;
  modelOutput: string;
  model: string;
  auditMode: AuditMode;
  commitReceipt: CommitLLMReceipt;
  now?: Date;
}): Promise<AgentProof> {
  const answer = computeChallengeAnswer(input.challenge, input.signer.agentId);
  const modelOutputHash = computeOutputHash(input.modelOutput);
  const payload: AgentProofPayload = {
    challengeId: input.challenge.challengeId,
    agentId: input.signer.agentId,
    agentPublicKey: input.signer.publicKeyHex,
    answer,
    modelOutput: input.modelOutput,
    modelOutputHash,
    commitReceipt: input.commitReceipt,
    createdAt: (input.now ?? new Date()).toISOString(),
  };

  const signature = await signAsync(
    serializePayload(payload),
    hexToBytes(input.signer.privateKeyHex),
  );

  return {
    payload,
    signature: bytesToHex(signature),
  };
}

// Why: lets callers gate expensive work (challenge burn, sidecar call)
// behind a cheap ownership check (CAPTCHA-CHALLENGE-BURN-001).
export async function verifyProofSignature(
  proof: AgentProof,
): Promise<boolean> {
  try {
    return await verifyAsync(
      hexToBytes(proof.signature),
      serializePayload(proof.payload),
      hexToBytes(proof.payload.agentPublicKey),
    );
  } catch {
    return false;
  }
}

export async function verifyAgentProof(input: {
  challenge: AgentChallenge;
  proof: AgentProof;
  expectedAgentId: string;
  verifier: CommitReceiptVerifier;
  now?: Date;
}): Promise<{
  valid: boolean;
  reason?: string;
  report?: CommitLLMVerifyReport;
}> {
  const now = input.now ?? new Date();
  if (new Date(input.challenge.expiresAt).getTime() < now.getTime()) {
    return { valid: false, reason: "challenge_expired" };
  }

  if (input.proof.payload.challengeId !== input.challenge.challengeId) {
    return { valid: false, reason: "challenge_mismatch" };
  }

  if (input.proof.payload.agentId !== input.expectedAgentId) {
    return { valid: false, reason: "agent_id_mismatch" };
  }

  const expectedAnswer = computeChallengeAnswer(
    input.challenge,
    input.expectedAgentId,
  );
  if (input.proof.payload.answer !== expectedAnswer) {
    return { valid: false, reason: "invalid_challenge_answer" };
  }

  const payload = input.proof.payload;
  const modelAllowed = input.challenge.policy.allowedModels.includes(
    payload.commitReceipt.model,
  );
  if (!modelAllowed) {
    return { valid: false, reason: "model_not_allowed" };
  }

  const auditAllowed = input.challenge.policy.allowedAuditModes.includes(
    payload.commitReceipt.auditMode,
  );
  if (!auditAllowed) {
    return { valid: false, reason: "audit_mode_not_allowed" };
  }

  const modelOutputHash = computeOutputHash(payload.modelOutput);
  if (modelOutputHash !== payload.modelOutputHash) {
    return { valid: false, reason: "model_output_hash_mismatch" };
  }

  if (payload.commitReceipt.bindingVersion !== COMMITLLM_BINDING_VERSION) {
    return { valid: false, reason: "receipt_binding_version_invalid" };
  }

  let artifactHashes: { auditBinarySha256: string; verifierKeySha256: string };
  let bindingHash: string;
  try {
    artifactHashes = deriveArtifactHashes(payload.commitReceipt);
    bindingHash = computeCommitLLMBindingHash({
      challengeId: payload.challengeId,
      answer: payload.answer,
      modelOutputHash: payload.modelOutputHash,
      receipt: payload.commitReceipt,
      auditBinarySha256: artifactHashes.auditBinarySha256,
      verifierKeySha256: artifactHashes.verifierKeySha256,
    });
  } catch (error) {
    return {
      valid: false,
      reason:
        error instanceof Error ? error.message : "receipt_binding_invalid",
    };
  }

  if (payload.commitReceipt.bindingHash !== bindingHash) {
    return { valid: false, reason: "receipt_binding_hash_mismatch" };
  }

  // Verify Ed25519 signature BEFORE the remote sidecar call to reject
  // crafted proofs cheaply and avoid GPU cost amplification.
  const signatureValid = await verifyAsync(
    hexToBytes(input.proof.signature),
    serializePayload(payload),
    hexToBytes(payload.agentPublicKey),
  );

  if (!signatureValid) {
    return { valid: false, reason: "invalid_agent_signature" };
  }

  const receiptResult = await input.verifier.verifyReceipt(
    payload.commitReceipt,
    {
      challengeId: payload.challengeId,
      outputHash: payload.modelOutputHash,
      commitHash: payload.commitReceipt.commitHash,
      bindingHash,
      bindingVersion: COMMITLLM_BINDING_VERSION,
      auditBinarySha256: artifactHashes.auditBinarySha256,
      verifierKeySha256: artifactHashes.verifierKeySha256,
      agentId: payload.agentId,
      answer: payload.answer,
    },
  );
  if (!receiptResult.valid) {
    return receiptResult;
  }

  const challengeAge =
    now.getTime() - new Date(input.challenge.issuedAt).getTime();
  if (challengeAge > input.challenge.policy.maxChallengeAgeMs) {
    return { valid: false, reason: "challenge_too_old" };
  }

  return {
    valid: true,
    ...(receiptResult.report ? { report: receiptResult.report } : {}),
  };
}
