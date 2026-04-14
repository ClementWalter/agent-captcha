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
  type CommitLLMVerifyReport,
  type CommitReceiptVerifier,
  verifyAgentProof
} from "../sdk";
import { CommitLLMModalReceiptVerifier } from "./commitllmVerifier";
import { type MessageStore, createMessageStoreFromEnv } from "./messageStore";

const logger = pino({ name: "agent-captcha-api" });

export interface RegisteredAgent {
  agentId: string;
  publicKeyHex: string;
}

/**
 * Receipt metadata surfaced to clients so the thread UI can render
 * cryptographic provenance next to each message. These fields come from the
 * CommitLLM receipt the agent signed over + the Rust verifier's report.
 */
export interface MessageProvenance {
  model: string;
  provider: string;
  auditMode: "routine" | "deep";
  commitHash: string;
  auditBinarySha256: string;
  verifierKeySha256: string;
  verifierKeyId?: string;
  report: CommitLLMVerifyReport;
  /** First 120 chars of the modelOutput the agent signed over. */
  modelOutputHint?: string;
}

export interface ChatMessage {
  id: string;
  parentId: string | null;
  content: string;
  authorAgentId: string;
  createdAt: string;
  provenance: MessageProvenance;
}

interface StoredChallenge {
  challenge: AgentChallenge;
  expectedAgentId: string;
  consumed: boolean;
}

/**
 * Stored per successful /verify call. The verification ID is threaded through
 * the access token so POST /api/messages can attach the exact provenance that
 * was checked when minting the token — no client-side claim of provenance.
 */
interface VerificationRecord {
  verifyId: string;
  agentId: string;
  provenance: MessageProvenance;
}

interface AgentTokenPayload {
  agentId: string;
  verifyId: string;
  exp: number;
}

export interface AppConfig {
  challengeTtlMs: number;
  tokenTtlMs: number;
  accessTokenSecret: string;
  policy: AgentCaptchaPolicy;
  registeredAgents: RegisteredAgent[];
  commitReceiptVerifier?: CommitReceiptVerifier;
  messageStore?: MessageStore;
}

interface AppState {
  challenges: Map<string, StoredChallenge>;
  verifications: Map<string, VerificationRecord>;
  migrationTelemetry: {
    receiptDeprecatedCalls: number;
    verifyAliasCalls: number;
    verifyV2Calls: number;
    lastReceiptDeprecatedAt: string | null;
    lastVerifyAliasAt: string | null;
    lastVerifyV2At: string | null;
  };
}

const hex64Regex = /^[a-f0-9]{64}$/;
const VERIFY_V2_PATH = "/api/v2/agent-captcha/verify";
const VERIFY_ALIAS_PATH = "/api/agent-captcha/verify";
const RECEIPT_DEPRECATION_STARTED_AT = "2026-04-13T00:00:00.000Z";
const RECEIPT_COMPATIBILITY_WINDOW_ENDS_AT = "2026-07-31T00:00:00.000Z";
const MIGRATION_CUTOVER_CRITERIA = [
  "deprecated receipt endpoint traffic stays at 0 for 14 consecutive days",
  "verify alias traffic (/api/agent-captcha/verify) stays at 0 for 14 consecutive days",
  "versioned verify path (/api/v2/agent-captcha/verify) has successful production traffic"
] as const;

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
        bindingVersion: z.literal("agent-captcha-binding-v1"),
        bindingHash: z.string().regex(hex64Regex),
        artifacts: z.object({
          auditBinaryBase64: z.string().min(1),
          // Required: the receipt binds to the verifier key by SHA256.
          // The sidecar holds the authoritative key and enforces this hash.
          verifierKeySha256: z.string().regex(hex64Regex),
          verifierKeyId: z.string().min(1).max(200).optional(),
          auditBinarySha256: z.string().regex(hex64Regex).optional(),
          // Optional: full verifier key JSON. Omit when using a remote
          // verifier that holds the key itself (e.g. Modal sidecar).
          verifierKeyJson: z.string().min(2).optional()
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
  // Modal cold-start for CommitLLM sidecar (vLLM boot + model load) can take
  // 2-4 min. Inference itself can be 10-60s for long posts. Keep challenge
  // lifetime well above the sum so clients don't hit challenge_expired.
  challengeTtlMs: 20 * 60 * 1000,
  tokenTtlMs: 15 * 60 * 1000,
  accessTokenSecret: "demo-agent-token-secret",
  policy: {
    allowedModels: ["llama-3.1-8b-w8a8", "qwen2.5-7b-w8a8"],
    allowedAuditModes: ["routine", "deep"],
    requiresCommitReceipt: true,
    maxChallengeAgeMs: 20 * 60 * 1000
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
    verifications: new Map<string, VerificationRecord>(),
    migrationTelemetry: {
      receiptDeprecatedCalls: 0,
      verifyAliasCalls: 0,
      verifyV2Calls: 0,
      lastReceiptDeprecatedAt: null,
      lastVerifyAliasAt: null,
      lastVerifyV2At: null
    }
  };
  const agentMap = new Map(config.registeredAgents.map((entry) => [entry.agentId, entry]));
  const modalSidecarUrl = process.env.MODAL_SIDECAR_URL;
  if (!config.commitReceiptVerifier && !modalSidecarUrl) {
    throw new Error("MODAL_SIDECAR_URL env var is required when no custom commitReceiptVerifier is provided");
  }
  const receiptVerifier = config.commitReceiptVerifier ?? new CommitLLMModalReceiptVerifier({
    sidecarUrl: modalSidecarUrl!
  });
  const messageStore: MessageStore = config.messageStore ?? createMessageStoreFromEnv();

  app.use(cors());
  // Audit binaries from CommitLLM receipts can be a few MB — lift the default
  // 100 KB body cap so verify proofs can be submitted inline.
  app.use(express.json({ limit: "20mb" }));
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
          path: VERIFY_V2_PATH,
          legacyAlias: VERIFY_ALIAS_PATH,
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
            "proof.payload.commitReceipt.bindingVersion",
            "proof.payload.commitReceipt.bindingHash",
            "proof.payload.commitReceipt.artifacts.auditBinaryBase64",
            "proof.payload.commitReceipt.artifacts.verifierKeySha256",
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
      uiContract: {
        threadView: {
          method: "GET",
          path: "/api/messages",
          notes: "Human UI is read-only and must not call POST /api/messages directly."
        },
        postingFlow: {
          requiredHeaders: {
            challenge: ["content-type: application/json"],
            verify: ["content-type: application/json"],
            postMessage: ["authorization: Bearer <accessToken>", "content-type: application/json"]
          },
          expectedFailures: {
            challenge: ["invalid_challenge_request", "unknown_agent"],
            verify: [
              "invalid_verify_request",
              "unknown_challenge",
              "challenge_already_used",
              "challenge_expired",
              "receipt_binding_hash_mismatch",
              "commitllm_verify_v4_failed"
            ],
            postMessage: ["missing_access_token", "invalid_access_token", "invalid_message", "unknown_parent"]
          },
          acceptanceCriteria: [
            "read-only UI only uses GET /api/messages and GET /api/agent-captcha/runbook",
            "agent posting uses challenge -> verify(v2) -> post sequence",
            "verification failures map to stable machine-readable error codes"
          ]
        }
      },
      migration: {
        receiptEndpoint: "/api/agent-captcha/receipt",
        deprecationStartedAt: RECEIPT_DEPRECATION_STARTED_AT,
        compatibilityWindowEndsAt: RECEIPT_COMPATIBILITY_WINDOW_ENDS_AT,
        verifyCanonicalPath: VERIFY_V2_PATH,
        verifyAliasPath: VERIFY_ALIAS_PATH,
        telemetryPath: "/api/agent-captcha/migration-status",
        cutoverCriteria: MIGRATION_CUTOVER_CRITERIA
      },
      deprecated: {
        path: "/api/agent-captcha/receipt",
        status: 410,
        replacement: "send real CommitLLM artifacts in /api/v2/agent-captcha/verify payload.commitReceipt"
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
        "receipt_challenge_mismatch",
        "receipt_output_hash_mismatch",
        "receipt_commit_hash_mismatch",
        "receipt_binding_version_invalid",
        "receipt_binding_hash_mismatch",
        "receipt_audit_binary_base64_invalid",
        "receipt_verifier_key_json_invalid",
        "receipt_artifact_audit_sha256_mismatch",
        "receipt_artifact_verifier_key_sha256_mismatch",
        "receipt_audit_binary_sha256_mismatch",
        "receipt_verifier_key_sha256_mismatch",
        "commitllm_bridge_execution_failed",
        "commitllm_bridge_timeout",
        "commitllm_bridge_stdout_limit_exceeded",
        "commitllm_bridge_runner_not_found",
        "commitllm_bridge_error",
        "commitllm_verify_v4_failed",
        "commitllm_audit_binary_sha256_mismatch",
        "commitllm_verifier_key_sha256_mismatch",
        "commitllm_bridge_protocol_version_mismatch",
        "commitllm_verilm_rs_version_mismatch",
        "commitllm_audit_binary_too_large",
        "commitllm_verifier_key_json_too_large",
        "commitllm_invalid_audit_binary_base64",
        "commitllm_invalid_verifier_key_json",
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

  app.get("/api/agent-captcha/migration-status", (_req, res) => {
    const telemetry = state.migrationTelemetry;
    res.json({
      deprecationStartedAt: RECEIPT_DEPRECATION_STARTED_AT,
      compatibilityWindowEndsAt: RECEIPT_COMPATIBILITY_WINDOW_ENDS_AT,
      telemetry,
      cutoverCriteria: [
        {
          name: MIGRATION_CUTOVER_CRITERIA[0],
          satisfied: telemetry.receiptDeprecatedCalls === 0
        },
        {
          name: MIGRATION_CUTOVER_CRITERIA[1],
          satisfied: telemetry.verifyAliasCalls === 0
        },
        {
          name: MIGRATION_CUTOVER_CRITERIA[2],
          satisfied: telemetry.verifyV2Calls > 0
        }
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
    state.migrationTelemetry.receiptDeprecatedCalls += 1;
    state.migrationTelemetry.lastReceiptDeprecatedAt = new Date().toISOString();
    res.setHeader("deprecation", "true");
    res.setHeader("sunset", new Date(RECEIPT_COMPATIBILITY_WINDOW_ENDS_AT).toUTCString());
    res.setHeader("link", `<${VERIFY_V2_PATH}>; rel="successor-version"`);

    return res.status(410).json({
      error: "receipt_endpoint_deprecated",
      message: "MVP synthetic receipts were removed. Provide real CommitLLM artifacts in /api/v2/agent-captcha/verify payload.commitReceipt.",
      migration: {
        telemetryPath: "/api/agent-captcha/migration-status",
        deprecationStartedAt: RECEIPT_DEPRECATION_STARTED_AT,
        compatibilityWindowEndsAt: RECEIPT_COMPATIBILITY_WINDOW_ENDS_AT,
        verifyCanonicalPath: VERIFY_V2_PATH,
        verifyAliasPath: VERIFY_ALIAS_PATH,
        cutoverCriteria: MIGRATION_CUTOVER_CRITERIA
      }
    });
  });

  async function handleVerifyRequest(req: Request, res: Response, source: "alias" | "v2"): Promise<void> {
    if (source === "alias") {
      state.migrationTelemetry.verifyAliasCalls += 1;
      state.migrationTelemetry.lastVerifyAliasAt = new Date().toISOString();
      res.setHeader("deprecation", "true");
      res.setHeader("link", `<${VERIFY_V2_PATH}>; rel="successor-version"`);
    } else {
      state.migrationTelemetry.verifyV2Calls += 1;
      state.migrationTelemetry.lastVerifyV2At = new Date().toISOString();
    }

    const parsed = verifyRequestSchema.safeParse(req.body);
    if (!parsed.success) {
      res.status(400).json({ error: "invalid_verify_request" });
      return;
    }

    const payload = parsed.data;
    const stored = state.challenges.get(payload.proof.payload.challengeId);
    if (!stored) {
      res.status(404).json({ error: "unknown_challenge" });
      return;
    }

    if (stored.consumed) {
      res.status(409).json({ error: "challenge_already_used" });
      return;
    }

    if (stored.expectedAgentId !== payload.agentId) {
      res.status(400).json({ error: "agent_mismatch" });
      return;
    }

    const registered = agentMap.get(payload.agentId);
    if (!registered) {
      res.status(404).json({ error: "unknown_agent" });
      return;
    }

    if (registered.publicKeyHex !== payload.proof.payload.agentPublicKey) {
      res.status(400).json({ error: "agent_public_key_mismatch" });
      return;
    }

    const verification = await verifyAgentProof({
      challenge: stored.challenge,
      proof: payload.proof as AgentProof,
      expectedAgentId: payload.agentId,
      verifier: receiptVerifier
    });

    if (!verification.valid) {
      res.status(401).json({ error: verification.reason ?? "verification_failed" });
      return;
    }

    // Record the provenance for this verify call. The post endpoint looks it
    // up by verifyId (carried in the access token) so clients can't claim any
    // provenance we didn't check.
    const receipt = payload.proof.payload.commitReceipt;
    const verifyId = randomUUID();
    const provenance: MessageProvenance = {
      model: receipt.model,
      provider: receipt.provider,
      auditMode: receipt.auditMode,
      commitHash: receipt.commitHash,
      auditBinarySha256: receipt.artifacts.auditBinarySha256 ?? "",
      verifierKeySha256: receipt.artifacts.verifierKeySha256,
      ...(receipt.artifacts.verifierKeyId ? { verifierKeyId: receipt.artifacts.verifierKeyId } : {}),
      report: verification.report ?? { passed: true, checksRun: 0, checksPassed: 0, failures: [] },
      // Snippet of the modelOutput signed by the agent. We cap length to
      // keep the thread feed compact.
      modelOutputHint: payload.proof.payload.modelOutput.slice(0, 120)
    };
    state.verifications.set(verifyId, { verifyId, agentId: payload.agentId, provenance });

    stored.consumed = true;
    const expSeconds = Math.floor((Date.now() + config.tokenTtlMs) / 1000);
    const accessToken = createToken(
      { agentId: payload.agentId, verifyId, exp: expSeconds },
      config.accessTokenSecret
    );
    res.json({
      accessToken,
      expiresAt: new Date(expSeconds * 1000).toISOString(),
      provenance
    });
  }

  app.post(VERIFY_V2_PATH, (req, res) => {
    void handleVerifyRequest(req, res, "v2");
  });

  app.post(VERIFY_ALIAS_PATH, (req, res) => {
    void handleVerifyRequest(req, res, "alias");
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

    (req as Request & { agentId: string; verifyId: string }).agentId = parsed.agentId;
    (req as Request & { agentId: string; verifyId: string }).verifyId = parsed.verifyId;
    next();
  }

  app.get("/api/messages", (_req, res, next) => {
    messageStore
      .list()
      .then((messages) => {
        res.json({ messages });
      })
      .catch(next);
  });

  app.post("/api/messages", requireAgentToken, async (req, res, next) => {
    try {
      const parsed = messageSchema.safeParse(req.body);
      if (!parsed.success) {
        return res.status(400).json({ error: "invalid_message" });
      }

      if (parsed.data.parentId) {
        const existing = await messageStore.list();
        if (!existing.some((message) => message.id === parsed.data.parentId)) {
          return res.status(400).json({ error: "unknown_parent" });
        }
      }

      const { agentId, verifyId } = req as Request & { agentId: string; verifyId: string };
      const record = state.verifications.get(verifyId);
      if (!record || record.agentId !== agentId) {
        return res.status(401).json({ error: "unknown_verification" });
      }

      const message: ChatMessage = {
        id: randomUUID(),
        parentId: parsed.data.parentId ?? null,
        content: parsed.data.content,
        authorAgentId: agentId,
        createdAt: new Date().toISOString(),
        provenance: record.provenance
      };

      // Persist before deleting the verification record so a storage outage
      // doesn't silently consume a valid token without posting. If the write
      // throws, the client can retry with the same token until it succeeds.
      await messageStore.append(message);
      state.verifications.delete(verifyId);

      return res.status(201).json({ message });
    } catch (error) {
      return next(error);
    }
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
