/**
 * Demo API for agent-gated posting.
 * Why: Centralize all protocol checks on the server to ensure chat writes are only
 * accepted after a successful agent-captcha verification round.
 */
import { createHmac, randomBytes, randomUUID, timingSafeEqual } from "crypto";
import path from "path";
import express, { type NextFunction, type Request, type Response } from "express";
import cors from "cors";
import pino from "pino";
import { z } from "zod";
import {
  type AgentChallenge,
  type AgentCaptchaPolicy,
  type AgentProof,
  type CommitLLMReceipt,
  type CommitReceiptVerifier,
  computeChallengeAnswer,
  computeCommitHash,
  computeCommitLLMCommitment,
  computeCommitLLMDigest,
  computeOutputHash,
  verifyAgentProof
} from "../sdk";

const logger = pino({ name: "agent-captcha-api" });

export interface RegisteredAgent {
  agentId: string;
  publicKeyHex: string;
}

export interface ChatMessage {
  id: string;
  parentId: string | null;
  content: string;
  authorAgentId: string;
  createdAt: string;
}

interface StoredChallenge {
  challenge: AgentChallenge;
  expectedAgentId: string;
  consumed: boolean;
}

interface AgentTokenPayload {
  agentId: string;
  exp: number;
}

export interface AppConfig {
  challengeTtlMs: number;
  tokenTtlMs: number;
  accessTokenSecret: string;
  policy: AgentCaptchaPolicy;
  registeredAgents: RegisteredAgent[];
}

interface AppState {
  challenges: Map<string, StoredChallenge>;
  messages: ChatMessage[];
}

const challengeRequestSchema = z.object({
  agentId: z.string().min(3).max(120)
});

const receiptRequestSchema = z.object({
  challengeId: z.string().uuid(),
  model: z.string().min(1),
  auditMode: z.enum(["routine", "deep"]),
  answer: z.string().regex(/^[a-f0-9]{64}$/),
  modelOutput: z.string().min(5).max(20_000)
});

const verifyRequestSchema = z.object({
  agentId: z.string(),
  proof: z.object({
    payload: z.object({
      challengeId: z.string().uuid(),
      agentId: z.string(),
      agentPublicKey: z.string().regex(/^[a-f0-9]{64}$/),
      answer: z.string().regex(/^[a-f0-9]{64}$/),
      modelOutput: z.string(),
      modelOutputHash: z.string().regex(/^[a-f0-9]{64}$/),
      commitReceipt: z.object({
        receiptId: z.string().uuid(),
        challengeId: z.string().uuid(),
        model: z.string(),
        auditMode: z.enum(["routine", "deep"]),
        outputHash: z.string().regex(/^[a-f0-9]{64}$/),
        commitHash: z.string().regex(/^[a-f0-9]{64}$/),
        issuedAt: z.string(),
        commitment: z.object({
          merkleRoot: z.string().regex(/^[a-f0-9]{64}$/),
          ioRoot: z.string().regex(/^[a-f0-9]{64}$/),
          manifestHash: z.string().regex(/^[a-f0-9]{64}$/),
          inputSpecHash: z.string().regex(/^[a-f0-9]{64}$/),
          modelSpecHash: z.string().regex(/^[a-f0-9]{64}$/),
          decodeSpecHash: z.string().regex(/^[a-f0-9]{64}$/),
          outputSpecHash: z.string().regex(/^[a-f0-9]{64}$/),
          promptHash: z.string().regex(/^[a-f0-9]{64}$/),
          seedCommitment: z.string().regex(/^[a-f0-9]{64}$/)
        }),
        digest: z.string().regex(/^[a-f0-9]{64}$/)
      }),
      createdAt: z.string()
    }),
    signature: z.string().regex(/^[a-f0-9]{128}$/)
  })
});

const messageSchema = z.object({
  content: z.string().min(1).max(2000),
  parentId: z.string().uuid().nullable().optional()
});

function base64UrlEncode(value: string): string {
  return Buffer.from(value, "utf8").toString("base64url");
}

function createToken(payload: AgentTokenPayload, secret: string): string {
  const encodedPayload = base64UrlEncode(JSON.stringify(payload));
  const signature = createHmac("sha256", secret).update(encodedPayload).digest("base64url");
  return `${encodedPayload}.${signature}`;
}

function verifyToken(token: string, secret: string): AgentTokenPayload | null {
  const [encodedPayload, signature] = token.split(".");
  if (!encodedPayload || !signature) {
    return null;
  }

  const expectedSignature = createHmac("sha256", secret).update(encodedPayload).digest("base64url");
  const providedBytes = Buffer.from(signature);
  const expectedBytes = Buffer.from(expectedSignature);
  if (providedBytes.length !== expectedBytes.length) {
    return null;
  }
  if (!timingSafeEqual(providedBytes, expectedBytes)) {
    return null;
  }

  try {
    const parsed = JSON.parse(Buffer.from(encodedPayload, "base64url").toString("utf8")) as AgentTokenPayload;
    if (parsed.exp * 1000 < Date.now()) {
      return null;
    }
    return parsed;
  } catch {
    return null;
  }
}

class DigestReceiptVerifier implements CommitReceiptVerifier {
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

    const expectedCommitment = computeCommitLLMCommitment({
      challengeId: expected.challengeId,
      agentId: expected.agentId,
      answer: expected.answer,
      modelOutputHash: expected.outputHash,
      model: receipt.model,
      auditMode: receipt.auditMode
    });

    if (receipt.commitment.merkleRoot !== expectedCommitment.merkleRoot) {
      return { valid: false, reason: "receipt_merkle_root_mismatch" };
    }

    if (receipt.commitment.ioRoot !== expectedCommitment.ioRoot) {
      return { valid: false, reason: "receipt_io_root_mismatch" };
    }

    if (receipt.commitment.manifestHash !== expectedCommitment.manifestHash) {
      return { valid: false, reason: "receipt_manifest_hash_mismatch" };
    }

    if (receipt.commitment.inputSpecHash !== expectedCommitment.inputSpecHash) {
      return { valid: false, reason: "receipt_input_spec_hash_mismatch" };
    }

    if (receipt.commitment.modelSpecHash !== expectedCommitment.modelSpecHash) {
      return { valid: false, reason: "receipt_model_spec_hash_mismatch" };
    }

    if (receipt.commitment.decodeSpecHash !== expectedCommitment.decodeSpecHash) {
      return { valid: false, reason: "receipt_decode_spec_hash_mismatch" };
    }

    if (receipt.commitment.outputSpecHash !== expectedCommitment.outputSpecHash) {
      return { valid: false, reason: "receipt_output_spec_hash_mismatch" };
    }

    if (receipt.commitment.promptHash !== expectedCommitment.promptHash) {
      return { valid: false, reason: "receipt_prompt_hash_mismatch" };
    }

    if (receipt.commitment.seedCommitment !== expectedCommitment.seedCommitment) {
      return { valid: false, reason: "receipt_seed_commitment_mismatch" };
    }

    const expectedDigest = computeCommitLLMDigest({
      receiptId: receipt.receiptId,
      challengeId: receipt.challengeId,
      model: receipt.model,
      auditMode: receipt.auditMode,
      outputHash: receipt.outputHash,
      commitHash: receipt.commitHash,
      issuedAt: receipt.issuedAt,
      commitment: receipt.commitment
    });

    if (receipt.digest !== expectedDigest) {
      return { valid: false, reason: "receipt_digest_invalid" };
    }

    return { valid: true };
  }
}

const defaultConfig: AppConfig = {
  challengeTtlMs: 2 * 60 * 1000,
  tokenTtlMs: 15 * 60 * 1000,
  accessTokenSecret: "demo-agent-token-secret",
  policy: {
    allowedModels: ["llama-3.1-8b-w8a8", "qwen2.5-7b-w8a8"],
    allowedAuditModes: ["routine", "deep"],
    requiresCommitReceipt: true,
    maxChallengeAgeMs: 2 * 60 * 1000
  },
  registeredAgents: [
    {
      agentId: "demo-agent-001",
      publicKeyHex: "b7a238dbf5a793f066a95e25d401f3557c6f8e38aeb11e0529861285bc051fd2"
    }
  ]
};

export function createApp(customConfig?: Partial<AppConfig>): { app: express.Express; config: AppConfig } {
  const config: AppConfig = {
    ...defaultConfig,
    ...customConfig,
    policy: {
      ...defaultConfig.policy,
      ...customConfig?.policy
    },
    registeredAgents: customConfig?.registeredAgents ?? defaultConfig.registeredAgents
  };

  const app = express();
  const state: AppState = {
    challenges: new Map<string, StoredChallenge>(),
    messages: []
  };
  const agentMap = new Map(config.registeredAgents.map((entry) => [entry.agentId, entry]));
  const receiptVerifier = new DigestReceiptVerifier();

  app.use(cors());
  app.use(express.json());
  app.use(express.static(path.resolve(process.cwd(), "public")));

  app.get("/api/health", (_req, res) => {
    res.json({ ok: true });
  });

  app.post("/api/agent-captcha/challenge", (req, res) => {
    const parsed = challengeRequestSchema.safeParse(req.body);
    if (!parsed.success) {
      return res.status(400).json({ error: "invalid_challenge_request" });
    }

    const agent = agentMap.get(parsed.data.agentId);
    if (!agent) {
      return res.status(404).json({ error: "unknown_agent" });
    }

    const now = new Date();
    const challenge: AgentChallenge = {
      challengeId: randomUUID(),
      nonce: randomBytes(16).toString("hex"),
      issuedAt: now.toISOString(),
      expiresAt: new Date(now.getTime() + config.challengeTtlMs).toISOString(),
      policy: config.policy
    };

    state.challenges.set(challenge.challengeId, {
      challenge,
      expectedAgentId: agent.agentId,
      consumed: false
    });

    return res.json({ challenge });
  });

  app.post("/api/agent-captcha/receipt", (req, res) => {
    const parsed = receiptRequestSchema.safeParse(req.body);
    if (!parsed.success) {
      return res.status(400).json({ error: "invalid_receipt_request" });
    }

    const stored = state.challenges.get(parsed.data.challengeId);
    if (!stored) {
      return res.status(404).json({ error: "unknown_challenge" });
    }

    if (new Date(stored.challenge.expiresAt).getTime() < Date.now()) {
      return res.status(400).json({ error: "challenge_expired" });
    }

    const expectedAnswer = computeChallengeAnswer(stored.challenge, stored.expectedAgentId);
    if (parsed.data.answer !== expectedAnswer) {
      return res.status(400).json({ error: "invalid_answer" });
    }

    if (!config.policy.allowedModels.includes(parsed.data.model)) {
      return res.status(400).json({ error: "model_not_allowed" });
    }

    if (!config.policy.allowedAuditModes.includes(parsed.data.auditMode)) {
      return res.status(400).json({ error: "audit_mode_not_allowed" });
    }

    const outputHash = computeOutputHash(parsed.data.modelOutput);
    const commitHash = computeCommitHash(
      parsed.data.challengeId,
      parsed.data.answer,
      outputHash,
      parsed.data.model,
      parsed.data.auditMode
    );

    const issuedAt = new Date().toISOString();
    const commitment = computeCommitLLMCommitment({
      challengeId: parsed.data.challengeId,
      agentId: stored.expectedAgentId,
      answer: parsed.data.answer,
      modelOutputHash: outputHash,
      model: parsed.data.model,
      auditMode: parsed.data.auditMode
    });

    const unsignedReceipt = {
      receiptId: randomUUID(),
      challengeId: parsed.data.challengeId,
      model: parsed.data.model,
      auditMode: parsed.data.auditMode,
      outputHash,
      commitHash,
      issuedAt,
      commitment
    };

    const receipt: CommitLLMReceipt = {
      ...unsignedReceipt,
      digest: computeCommitLLMDigest(unsignedReceipt)
    };

    return res.json({ receipt });
  });

  app.post("/api/agent-captcha/verify", async (req, res) => {
    const parsed = verifyRequestSchema.safeParse(req.body);
    if (!parsed.success) {
      return res.status(400).json({ error: "invalid_verify_request" });
    }

    const payload = parsed.data;
    const stored = state.challenges.get(payload.proof.payload.challengeId);
    if (!stored) {
      return res.status(404).json({ error: "unknown_challenge" });
    }

    if (stored.consumed) {
      return res.status(409).json({ error: "challenge_already_used" });
    }

    if (stored.expectedAgentId !== payload.agentId) {
      return res.status(400).json({ error: "agent_mismatch" });
    }

    const registered = agentMap.get(payload.agentId);
    if (!registered) {
      return res.status(404).json({ error: "unknown_agent" });
    }

    if (registered.publicKeyHex !== payload.proof.payload.agentPublicKey) {
      return res.status(400).json({ error: "agent_public_key_mismatch" });
    }

    const verification = await verifyAgentProof({
      challenge: stored.challenge,
      proof: payload.proof as AgentProof,
      expectedAgentId: payload.agentId,
      verifier: receiptVerifier
    });

    if (!verification.valid) {
      return res.status(401).json({ error: verification.reason ?? "verification_failed" });
    }

    stored.consumed = true;
    const expSeconds = Math.floor((Date.now() + config.tokenTtlMs) / 1000);
    const accessToken = createToken({ agentId: payload.agentId, exp: expSeconds }, config.accessTokenSecret);
    return res.json({ accessToken, expiresAt: new Date(expSeconds * 1000).toISOString() });
  });

  function requireAgentToken(req: Request, res: Response, next: NextFunction): void {
    const authHeader = req.header("authorization");
    if (!authHeader?.startsWith("Bearer ")) {
      res.status(401).json({ error: "missing_access_token" });
      return;
    }

    const token = authHeader.slice("Bearer ".length);
    const parsed = verifyToken(token, config.accessTokenSecret);
    if (!parsed) {
      res.status(401).json({ error: "invalid_access_token" });
      return;
    }

    (req as Request & { agentId: string }).agentId = parsed.agentId;
    next();
  }

  app.get("/api/messages", (_req, res) => {
    res.json({ messages: state.messages });
  });

  app.post("/api/messages", requireAgentToken, (req, res) => {
    const parsed = messageSchema.safeParse(req.body);
    if (!parsed.success) {
      return res.status(400).json({ error: "invalid_message" });
    }

    if (parsed.data.parentId && !state.messages.some((message) => message.id === parsed.data.parentId)) {
      return res.status(400).json({ error: "unknown_parent" });
    }

    const message: ChatMessage = {
      id: randomUUID(),
      parentId: parsed.data.parentId ?? null,
      content: parsed.data.content,
      authorAgentId: (req as Request & { agentId: string }).agentId,
      createdAt: new Date().toISOString()
    };

    state.messages.push(message);
    return res.status(201).json({ message });
  });

  app.get("*", (_req, res) => {
    res.sendFile(path.resolve(process.cwd(), "public/index.html"));
  });

  app.use((error: Error, _req: Request, res: Response, _next: NextFunction) => {
    logger.error({ err: error }, "Unhandled error");
    res.status(500).json({ error: "internal_error" });
  });

  return { app, config };
}
