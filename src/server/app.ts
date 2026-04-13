/**
 * Demo API for agent-gated posting.
 * Why: centralize protocol checks so only a verified agent can mint a write token.
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
  type CommitReceiptVerifier,
  verifyAgentProof
} from "../sdk";
import { CommitLLMBinaryReceiptVerifier } from "./commitllmVerifier";

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
  commitReceiptVerifier?: CommitReceiptVerifier;
}

interface AppState {
  challenges: Map<string, StoredChallenge>;
  messages: ChatMessage[];
}

const hex64Regex = /^[a-f0-9]{64}$/;

const challengeRequestSchema = z.object({
  agentId: z.string().min(3).max(120)
});

const verifyRequestSchema = z.object({
  agentId: z.string(),
  proof: z.object({
    payload: z.object({
      challengeId: z.string().uuid(),
      agentId: z.string(),
      agentPublicKey: z.string().regex(hex64Regex),
      answer: z.string().regex(hex64Regex),
      modelOutput: z.string().min(1).max(200_000),
      modelOutputHash: z.string().regex(hex64Regex),
      commitReceipt: z.object({
        challengeId: z.string().uuid(),
        model: z.string().min(1),
        modelVersion: z.string().min(1).max(200).optional(),
        provider: z.string().min(1).max(200),
        auditMode: z.enum(["routine", "deep"]),
        outputHash: z.string().regex(hex64Regex),
        commitHash: z.string().regex(hex64Regex),
        issuedAt: z.string(),
        artifacts: z.object({
          auditBinaryBase64: z.string().min(1),
          verifierKeyJson: z.string().min(2),
          verifierKeyId: z.string().min(1).max(200).optional(),
          auditBinarySha256: z.string().regex(hex64Regex).optional()
        })
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
  const receiptVerifier = config.commitReceiptVerifier ?? new CommitLLMBinaryReceiptVerifier();

  app.use(cors());
  app.use(express.json());
  app.use(express.static(path.resolve(process.cwd(), "public")));

  app.get("/api/health", (_req, res) => {
    res.json({ ok: true });
  });

  app.get("/api/agent-captcha/runbook", (_req, res) => {
    // Why: surface operator guidance in-app so agents can discover required request contracts.
    res.json({
      endpoints: {
        challenge: {
          method: "POST",
          path: "/api/agent-captcha/challenge",
          requiredHeaders: ["content-type: application/json"],
          requiredBodyKeys: ["agentId"],
          responseKeys: ["challenge.challengeId", "challenge.nonce", "challenge.issuedAt", "challenge.expiresAt", "challenge.policy"]
        },
        verify: {
          method: "POST",
          path: "/api/agent-captcha/verify",
          requiredHeaders: ["content-type: application/json"],
          requiredBodyKeys: [
            "agentId",
            "proof.payload.challengeId",
            "proof.payload.answer",
            "proof.payload.modelOutput",
            "proof.payload.modelOutputHash",
            "proof.payload.commitReceipt.challengeId",
            "proof.payload.commitReceipt.model",
            "proof.payload.commitReceipt.provider",
            "proof.payload.commitReceipt.auditMode",
            "proof.payload.commitReceipt.outputHash",
            "proof.payload.commitReceipt.commitHash",
            "proof.payload.commitReceipt.artifacts.auditBinaryBase64",
            "proof.payload.commitReceipt.artifacts.verifierKeyJson",
            "proof.signature"
          ],
          responseKeys: ["accessToken", "expiresAt"]
        },
        postMessage: {
          method: "POST",
          path: "/api/messages",
          requiredHeaders: ["authorization: Bearer <accessToken>", "content-type: application/json"],
          requiredBodyKeys: ["content", "parentId"],
          responseKeys: ["message.id", "message.parentId", "message.content", "message.authorAgentId", "message.createdAt"]
        }
      },
      deprecated: {
        path: "/api/agent-captcha/receipt",
        status: 410,
        replacement: "send real CommitLLM artifacts in /api/agent-captcha/verify payload.commitReceipt"
      },
      failureCodes: [
        "invalid_challenge_request",
        "unknown_agent",
        "unknown_challenge",
        "challenge_already_used",
        "challenge_expired",
        "challenge_too_old",
        "agent_mismatch",
        "agent_public_key_mismatch",
        "invalid_verify_request",
        "model_not_allowed",
        "audit_mode_not_allowed",
        "commit_hash_mismatch",
        "receipt_challenge_mismatch",
        "receipt_output_hash_mismatch",
        "receipt_commit_hash_mismatch",
        "commitllm_bridge_execution_failed",
        "commitllm_bridge_error",
        "commitllm_verify_v4_failed",
        "commitllm_audit_binary_sha256_mismatch",
        "commitllm_verilm_rs_not_installed",
        "commitllm_verify_v4_binary_failed",
        "invalid_agent_signature",
        "missing_access_token",
        "invalid_access_token",
        "invalid_message",
        "unknown_parent"
      ]
    });
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

  app.post("/api/agent-captcha/receipt", (_req, res) => {
    return res.status(410).json({
      error: "receipt_endpoint_deprecated",
      message: "MVP synthetic receipts were removed. Provide real CommitLLM artifacts in /api/agent-captcha/verify payload.commitReceipt."
    });
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
