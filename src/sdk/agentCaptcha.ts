/**
 * Agent CAPTCHA SDK primitives.
 * Why: Keep protocol-critical signing and verification logic in one auditable place
 * so frontend and backend can share the exact same canonicalization behavior.
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

export interface CommitLLMCommitmentDigest {
  merkleRoot: string;
  ioRoot: string;
  manifestHash: string;
  inputSpecHash: string;
  modelSpecHash: string;
  decodeSpecHash: string;
  outputSpecHash: string;
  promptHash: string;
  seedCommitment: string;
}

export interface CommitLLMReceipt {
  receiptId: string;
  challengeId: string;
  model: string;
  auditMode: AuditMode;
  outputHash: string;
  commitHash: string;
  issuedAt: string;
  commitment: CommitLLMCommitmentDigest;
  digest: string;
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

export interface CommitReceiptVerifier {
  verifyReceipt(
    receipt: CommitLLMReceipt,
    expected: { challengeId: string; outputHash: string; commitHash: string; agentId: string; answer: string }
  ): Promise<{ valid: boolean; reason?: string }>;
}

interface CommitLLMCommitmentInput {
  challengeId: string;
  agentId: string;
  answer: string;
  modelOutputHash: string;
  model: string;
  auditMode: AuditMode;
}

function sha256Hex(value: string): string {
  return bytesToHex(sha256(utf8ToBytes(value)));
}

export function computeChallengeAnswer(challenge: AgentChallenge, agentId: string): string {
  const material = `agent-captcha:v1|${challenge.challengeId}|${challenge.nonce}|${agentId}`;
  return sha256Hex(material);
}

export function computeOutputHash(modelOutput: string): string {
  return sha256Hex(modelOutput);
}

export function computeCommitHash(
  challengeId: string,
  answer: string,
  modelOutputHash: string,
  model: string,
  auditMode: AuditMode
): string {
  const material = `${challengeId}|${answer}|${modelOutputHash}|${model}|${auditMode}`;
  return sha256Hex(material);
}

export function computeCommitLLMCommitment(input: CommitLLMCommitmentInput): CommitLLMCommitmentDigest {
  // Why: mirror CommitLLM's bound-spec posture by deriving explicit per-surface digests.
  const inputSpecHash = sha256Hex(`vi-input-spec-v4|agent-captcha:v1|${input.challengeId}|${input.agentId}`);
  const modelSpecHash = sha256Hex(`vi-model-spec-v4|${input.model}`);
  const decodeSpecHash = sha256Hex(`vi-decode-spec-v4|${input.model}|${input.auditMode}`);
  const outputSpecHash = sha256Hex(`vi-output-spec-v4|${input.modelOutputHash}`);
  const promptHash = sha256Hex(`vi-prompt-v4|${input.challengeId}|${input.answer}`);
  const seedCommitment = sha256Hex(`vi-seed-v4|${input.challengeId}|${input.answer}|${input.model}`);
  const manifestHash = sha256Hex(
    `vi-manifest-v4|${inputSpecHash}|${modelSpecHash}|${decodeSpecHash}|${outputSpecHash}`
  );
  const merkleRoot = sha256Hex(`vi-merkle-v4|${manifestHash}|${promptHash}|${seedCommitment}`);
  const ioRoot = sha256Hex(`vi-io-v4|${promptHash}|${input.modelOutputHash}|${input.auditMode}`);

  return {
    merkleRoot,
    ioRoot,
    manifestHash,
    inputSpecHash,
    modelSpecHash,
    decodeSpecHash,
    outputSpecHash,
    promptHash,
    seedCommitment
  };
}

export function computeCommitLLMDigest(receipt: Omit<CommitLLMReceipt, "digest">): string {
  // Why: use a deterministic receipt digest rather than a shared secret mock signature.
  const material = stableStringify({
    receiptId: receipt.receiptId,
    challengeId: receipt.challengeId,
    model: receipt.model,
    auditMode: receipt.auditMode,
    outputHash: receipt.outputHash,
    commitHash: receipt.commitHash,
    issuedAt: receipt.issuedAt,
    commitment: receipt.commitment
  });

  return sha256Hex(`commitllm-receipt-v1|${material}`);
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
    createdAt: (input.now ?? new Date()).toISOString()
  };

  const signature = await signAsync(serializePayload(payload), hexToBytes(input.signer.privateKeyHex));

  return {
    payload,
    signature: bytesToHex(signature)
  };
}

export async function verifyAgentProof(input: {
  challenge: AgentChallenge;
  proof: AgentProof;
  expectedAgentId: string;
  verifier: CommitReceiptVerifier;
  now?: Date;
}): Promise<{ valid: boolean; reason?: string }> {
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

  const expectedAnswer = computeChallengeAnswer(input.challenge, input.expectedAgentId);
  if (input.proof.payload.answer !== expectedAnswer) {
    return { valid: false, reason: "invalid_challenge_answer" };
  }

  const payload = input.proof.payload;
  const modelAllowed = input.challenge.policy.allowedModels.includes(payload.commitReceipt.model);
  if (!modelAllowed) {
    return { valid: false, reason: "model_not_allowed" };
  }

  const auditAllowed = input.challenge.policy.allowedAuditModes.includes(payload.commitReceipt.auditMode);
  if (!auditAllowed) {
    return { valid: false, reason: "audit_mode_not_allowed" };
  }

  const modelOutputHash = computeOutputHash(payload.modelOutput);
  if (modelOutputHash !== payload.modelOutputHash) {
    return { valid: false, reason: "model_output_hash_mismatch" };
  }

  const commitHash = computeCommitHash(
    payload.challengeId,
    payload.answer,
    payload.modelOutputHash,
    payload.commitReceipt.model,
    payload.commitReceipt.auditMode
  );

  if (payload.commitReceipt.commitHash !== commitHash) {
    return { valid: false, reason: "commit_hash_mismatch" };
  }

  const receiptResult = await input.verifier.verifyReceipt(payload.commitReceipt, {
    challengeId: payload.challengeId,
    outputHash: payload.modelOutputHash,
    commitHash,
    agentId: payload.agentId,
    answer: payload.answer
  });
  if (!receiptResult.valid) {
    return receiptResult;
  }

  const signatureValid = await verifyAsync(
    hexToBytes(input.proof.signature),
    serializePayload(payload),
    hexToBytes(payload.agentPublicKey)
  );

  if (!signatureValid) {
    return { valid: false, reason: "invalid_agent_signature" };
  }

  const challengeAge = now.getTime() - new Date(input.challenge.issuedAt).getTime();
  if (challengeAge > input.challenge.policy.maxChallengeAgeMs) {
    return { valid: false, reason: "challenge_too_old" };
  }

  return { valid: true };
}
