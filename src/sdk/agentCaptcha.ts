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

interface CommitLLMInputSpec {
  tokenizerHash: string;
  systemPromptHash?: string;
  chatTemplateHash?: string;
  bosEosPolicy?: string;
  truncationPolicy?: string;
  specialTokenPolicy?: string;
  paddingPolicy?: string;
}

interface CommitLLMModelSpec {
  weightHash?: string;
  quantHash?: string;
  ropeConfigHash?: string;
  rmsnormEps?: number;
  adapterHash?: string;
  nLayers?: number;
  hiddenDim?: number;
  vocabSize?: number;
  embeddingMerkleRoot?: string;
  quantFamily?: string;
  scaleDerivation?: string;
  quantBlockSize?: number;
  kvDim?: number;
  ffnDim?: number;
  dHead?: number;
  nQHeads?: number;
  nKVHeads?: number;
  ropeTheta?: number;
}

interface CommitLLMDecodeSpec {
  temperature: number;
  topK: number;
  topP: number;
  repetitionPenalty: number;
  frequencyPenalty: number;
  presencePenalty: number;
  logitBias: Array<{ tokenId: number; bias: number }>;
  badWordIds: number[];
  guidedDecoding: string;
  samplerVersion?: string;
  decodeMode?: string;
}

interface CommitLLMOutputSpec {
  eosPolicy: string;
  stopSequences: string[];
  maxTokens: number;
  minTokens: number;
  ignoreEos: boolean;
  detokenizationPolicy?: string;
  eosTokenId?: number;
}

interface CommitLLMModelProfile {
  nLayers: number;
  hiddenDim: number;
  vocabSize: number;
  kvDim: number;
  ffnDim: number;
  dHead: number;
  nQHeads: number;
  nKVHeads: number;
  ropeTheta: number;
  eosTokenId: number;
}

const DEFAULT_MODEL_PROFILE: CommitLLMModelProfile = {
  nLayers: 32,
  hiddenDim: 4096,
  vocabSize: 128256,
  kvDim: 1024,
  ffnDim: 14336,
  dHead: 128,
  nQHeads: 32,
  nKVHeads: 8,
  ropeTheta: 500000,
  eosTokenId: 128009
};

const MODEL_PROFILES: Record<string, CommitLLMModelProfile> = {
  "llama-3.1-8b-w8a8": DEFAULT_MODEL_PROFILE,
  "qwen2.5-7b-w8a8": {
    nLayers: 28,
    hiddenDim: 3584,
    vocabSize: 151936,
    kvDim: 512,
    ffnDim: 18944,
    dHead: 128,
    nQHeads: 28,
    nKVHeads: 4,
    ropeTheta: 1000000,
    eosTokenId: 151643
  }
};

function sha256Hex(value: string | Uint8Array): string {
  if (typeof value === "string") {
    return bytesToHex(sha256(utf8ToBytes(value)));
  }
  return bytesToHex(sha256(value));
}

function concatByteArrays(parts: Uint8Array[]): Uint8Array {
  const size = parts.reduce((sum, value) => sum + value.length, 0);
  const output = new Uint8Array(size);
  let cursor = 0;
  for (const part of parts) {
    output.set(part, cursor);
    cursor += part.length;
  }
  return output;
}

function numberToU32LE(value: number): Uint8Array {
  const buffer = new ArrayBuffer(4);
  new DataView(buffer).setUint32(0, value, true);
  return new Uint8Array(buffer);
}

function numberToF32LE(value: number): Uint8Array {
  const buffer = new ArrayBuffer(4);
  new DataView(buffer).setFloat32(0, value, true);
  return new Uint8Array(buffer);
}

function numberToF64LE(value: number): Uint8Array {
  const buffer = new ArrayBuffer(8);
  new DataView(buffer).setFloat64(0, value, true);
  return new Uint8Array(buffer);
}

function encodeOptionalHex(value: string | undefined): Uint8Array {
  if (!value) {
    return Uint8Array.of(0);
  }
  return concatByteArrays([Uint8Array.of(1), hexToBytes(value)]);
}

function encodeOptionalU32(value: number | undefined): Uint8Array {
  if (value === undefined) {
    return Uint8Array.of(0);
  }
  return concatByteArrays([Uint8Array.of(1), numberToU32LE(value)]);
}

function encodeOptionalF64(value: number | undefined): Uint8Array {
  if (value === undefined) {
    return Uint8Array.of(0);
  }
  return concatByteArrays([Uint8Array.of(1), numberToF64LE(value)]);
}

function encodeOptionalString(value: string | undefined): Uint8Array {
  if (value === undefined) {
    return Uint8Array.of(0);
  }
  const encoded = utf8ToBytes(value);
  return concatByteArrays([Uint8Array.of(1), numberToU32LE(encoded.length), encoded]);
}

function encodeSizedString(value: string): Uint8Array {
  const encoded = utf8ToBytes(value);
  return concatByteArrays([numberToU32LE(encoded.length), encoded]);
}

function computeInputSpecHash(spec: CommitLLMInputSpec): string {
  // Why: this mirrors CommitLLM `hash_input_spec` field ordering and encoding.
  return sha256Hex(
    concatByteArrays([
      utf8ToBytes("vi-input-v1"),
      hexToBytes(spec.tokenizerHash),
      encodeOptionalHex(spec.systemPromptHash),
      encodeOptionalHex(spec.chatTemplateHash),
      encodeOptionalString(spec.bosEosPolicy),
      encodeOptionalString(spec.truncationPolicy),
      encodeOptionalString(spec.specialTokenPolicy),
      encodeOptionalString(spec.paddingPolicy)
    ])
  );
}

function computeModelSpecHash(spec: CommitLLMModelSpec): string {
  const rmsnormBytes =
    spec.rmsnormEps === undefined
      ? Uint8Array.of(0)
      : concatByteArrays([Uint8Array.of(1), numberToF64LE(spec.rmsnormEps)]);

  // Why: this mirrors CommitLLM `hash_model_spec` optional field semantics.
  return sha256Hex(
    concatByteArrays([
      utf8ToBytes("vi-model-v1"),
      encodeOptionalHex(spec.weightHash),
      encodeOptionalHex(spec.quantHash),
      encodeOptionalHex(spec.ropeConfigHash),
      rmsnormBytes,
      encodeOptionalHex(spec.adapterHash),
      encodeOptionalU32(spec.nLayers),
      encodeOptionalU32(spec.hiddenDim),
      encodeOptionalU32(spec.vocabSize),
      encodeOptionalHex(spec.embeddingMerkleRoot),
      encodeOptionalString(spec.quantFamily),
      encodeOptionalString(spec.scaleDerivation),
      encodeOptionalU32(spec.quantBlockSize),
      encodeOptionalU32(spec.kvDim),
      encodeOptionalU32(spec.ffnDim),
      encodeOptionalU32(spec.dHead),
      encodeOptionalU32(spec.nQHeads),
      encodeOptionalU32(spec.nKVHeads),
      encodeOptionalF64(spec.ropeTheta)
    ])
  );
}

function computeDecodeSpecHash(spec: CommitLLMDecodeSpec): string {
  const logitBiasParts: Uint8Array[] = [numberToU32LE(spec.logitBias.length)];
  for (const entry of spec.logitBias) {
    logitBiasParts.push(numberToU32LE(entry.tokenId), numberToF32LE(entry.bias));
  }

  const badWordParts: Uint8Array[] = [numberToU32LE(spec.badWordIds.length)];
  for (const tokenId of spec.badWordIds) {
    badWordParts.push(numberToU32LE(tokenId));
  }

  const guidedBytes = utf8ToBytes(spec.guidedDecoding);
  const samplerBytes = spec.samplerVersion
    ? concatByteArrays([Uint8Array.of(1), encodeSizedString(spec.samplerVersion)])
    : Uint8Array.of(0);

  // Why: this mirrors CommitLLM `hash_decode_spec` canonical binary encoding.
  return sha256Hex(
    concatByteArrays([
      utf8ToBytes("vi-decode-v1"),
      numberToF32LE(spec.temperature),
      numberToU32LE(spec.topK),
      numberToF32LE(spec.topP),
      numberToF32LE(spec.repetitionPenalty),
      numberToF32LE(spec.frequencyPenalty),
      numberToF32LE(spec.presencePenalty),
      ...logitBiasParts,
      ...badWordParts,
      numberToU32LE(guidedBytes.length),
      guidedBytes,
      samplerBytes,
      encodeOptionalString(spec.decodeMode)
    ])
  );
}

function computeOutputSpecHash(spec: CommitLLMOutputSpec): string {
  const stopSequenceParts: Uint8Array[] = [numberToU32LE(spec.stopSequences.length)];
  for (const stopSequence of spec.stopSequences) {
    stopSequenceParts.push(encodeSizedString(stopSequence));
  }

  const eosTokenBytes =
    spec.eosTokenId === undefined
      ? Uint8Array.of(0)
      : concatByteArrays([Uint8Array.of(1), numberToU32LE(spec.eosTokenId)]);

  // Why: this mirrors CommitLLM `hash_output_spec` canonical binary encoding.
  return sha256Hex(
    concatByteArrays([
      utf8ToBytes("vi-output-v1"),
      utf8ToBytes(spec.eosPolicy),
      ...stopSequenceParts,
      numberToU32LE(spec.maxTokens),
      numberToU32LE(spec.minTokens),
      Uint8Array.of(spec.ignoreEos ? 1 : 0),
      encodeOptionalString(spec.detokenizationPolicy),
      eosTokenBytes
    ])
  );
}

function computeManifestHash(hashes: {
  inputSpecHash: string;
  modelSpecHash: string;
  decodeSpecHash: string;
  outputSpecHash: string;
}): string {
  // Why: CommitLLM composes the 4 spec hashes into a single manifest hash.
  return sha256Hex(
    concatByteArrays([
      utf8ToBytes("vi-manifest-v4"),
      hexToBytes(hashes.inputSpecHash),
      hexToBytes(hashes.modelSpecHash),
      hexToBytes(hashes.decodeSpecHash),
      hexToBytes(hashes.outputSpecHash)
    ])
  );
}

function computePromptHash(promptBytes: Uint8Array): string {
  return sha256Hex(concatByteArrays([utf8ToBytes("vi-prompt-v1"), promptBytes]));
}

function computeSeedCommitment(seed: Uint8Array): string {
  return sha256Hex(concatByteArrays([utf8ToBytes("vi-seed-v1"), seed]));
}

function computeIoGenesis(promptHash: string): Uint8Array {
  return sha256(concatByteArrays([utf8ToBytes("vi-io-genesis-v4"), hexToBytes(promptHash)]));
}

function computeSyntheticRetainedLeaf(modelOutputHash: string, challengeId: string, agentId: string): string {
  // Why: the MVP has no layer capture stream; this preserves the retained-state
  // domain separator while binding the leaf to request-specific material.
  return sha256Hex(
    concatByteArrays([
      utf8ToBytes("vi-retained-v3"),
      hexToBytes(modelOutputHash),
      utf8ToBytes(challengeId),
      utf8ToBytes(agentId)
    ])
  );
}

function resolveModelProfile(model: string): CommitLLMModelProfile {
  return MODEL_PROFILES[model] ?? DEFAULT_MODEL_PROFILE;
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
  const modelProfile = resolveModelProfile(input.model);
  const inputSpecHash = computeInputSpecHash({
    tokenizerHash: sha256Hex("agent-captcha-tokenizer-v1"),
    systemPromptHash: sha256Hex(`agent-captcha-system-prompt-v1|${input.challengeId}|${input.agentId}`),
    chatTemplateHash: sha256Hex("agent-captcha-chat-template-v1"),
    bosEosPolicy: "none",
    truncationPolicy: "error",
    specialTokenPolicy: "encode",
    paddingPolicy: "none"
  });

  const modelSpecHash = computeModelSpecHash({
    weightHash: sha256Hex(`agent-captcha-weight-hash-v1|${input.model}`),
    quantHash: sha256Hex(`agent-captcha-quant-hash-v1|${input.model}`),
    ropeConfigHash: sha256Hex(`agent-captcha-rope-config-v1|${input.model}`),
    rmsnormEps: 1e-5,
    adapterHash: undefined,
    nLayers: modelProfile.nLayers,
    hiddenDim: modelProfile.hiddenDim,
    vocabSize: modelProfile.vocabSize,
    embeddingMerkleRoot: undefined,
    quantFamily: "W8A8",
    scaleDerivation: "absmax",
    quantBlockSize: 32,
    kvDim: modelProfile.kvDim,
    ffnDim: modelProfile.ffnDim,
    dHead: modelProfile.dHead,
    nQHeads: modelProfile.nQHeads,
    nKVHeads: modelProfile.nKVHeads,
    ropeTheta: modelProfile.ropeTheta
  });

  const decodeSpecHash = computeDecodeSpecHash({
    temperature: input.auditMode === "deep" ? 0 : 0.7,
    topK: input.auditMode === "deep" ? 0 : 40,
    topP: input.auditMode === "deep" ? 1 : 0.95,
    repetitionPenalty: 1,
    frequencyPenalty: 0,
    presencePenalty: 0,
    logitBias: [],
    badWordIds: [],
    guidedDecoding: "",
    samplerVersion: "chacha20-vi-sample-v1",
    decodeMode: input.auditMode === "deep" ? "greedy" : "sampled"
  });

  const outputSpecHash = computeOutputSpecHash({
    eosPolicy: "stop",
    stopSequences: [],
    maxTokens: 0,
    minTokens: 0,
    ignoreEos: false,
    detokenizationPolicy: "default",
    eosTokenId: modelProfile.eosTokenId
  });

  const manifestHash = computeManifestHash({
    inputSpecHash,
    modelSpecHash,
    decodeSpecHash,
    outputSpecHash
  });

  const promptHash = computePromptHash(utf8ToBytes(`challenge=${input.challengeId};answer=${input.answer}`));
  const seedCommitment = computeSeedCommitment(
    sha256(utf8ToBytes(`agent-captcha-seed-v1|${input.challengeId}|${input.answer}|${input.model}`))
  );

  const retainedLeaf = computeSyntheticRetainedLeaf(input.modelOutputHash, input.challengeId, input.agentId);
  const merkleRoot = retainedLeaf;
  const tokenId = new DataView(hexToBytes(input.modelOutputHash).buffer).getUint32(0, true);
  const ioRoot = sha256Hex(
    concatByteArrays([
      utf8ToBytes("vi-io-v4"),
      hexToBytes(retainedLeaf),
      numberToU32LE(tokenId),
      computeIoGenesis(promptHash)
    ])
  );

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
  // Why: CommitLLM receipts are byte-level commitments; digesting the canonical
  // binary field order avoids JSON reordering ambiguities.
  return sha256Hex(
    concatByteArrays([
      utf8ToBytes("vi-receipt-v1"),
      encodeSizedString(receipt.receiptId),
      encodeSizedString(receipt.challengeId),
      encodeSizedString(receipt.model),
      encodeSizedString(receipt.auditMode),
      hexToBytes(receipt.outputHash),
      hexToBytes(receipt.commitHash),
      encodeSizedString(receipt.issuedAt),
      hexToBytes(receipt.commitment.merkleRoot),
      hexToBytes(receipt.commitment.ioRoot),
      hexToBytes(receipt.commitment.manifestHash),
      hexToBytes(receipt.commitment.inputSpecHash),
      hexToBytes(receipt.commitment.modelSpecHash),
      hexToBytes(receipt.commitment.decodeSpecHash),
      hexToBytes(receipt.commitment.outputSpecHash),
      hexToBytes(receipt.commitment.promptHash),
      hexToBytes(receipt.commitment.seedCommitment)
    ])
  );
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
