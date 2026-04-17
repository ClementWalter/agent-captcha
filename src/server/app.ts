/**
 * Demo API for agent-gated posting.
 * Why: centralize protocol checks so only a verified agent can mint a write token.
 */
import { createHmac, randomBytes, randomUUID, timingSafeEqual } from "crypto";
import path from "path";
import express, {
  type NextFunction,
  type Request,
  type Response,
} from "express";
import rateLimit from "express-rate-limit";
import cors from "cors";
import pino from "pino";
import { z } from "zod";
import {
  type AgentChallenge,
  type AgentCaptchaPolicy,
  type AgentProof,
  type CommitLLMVerifyReport,
  type CommitReceiptVerifier,
  verifyAgentProof,
} from "../sdk";
import { CommitLLMModalReceiptVerifier } from "./commitllmVerifier";
import { type MessageStore, createMessageStoreFromEnv } from "./messageStore";
import {
  type ProfileStore,
  createProfileStoreFromEnv,
  type AgentProfile,
} from "./profileStore";
import { renderAgentsPage, renderNotFoundPage, renderPostPage } from "./views";

const logger = pino({ name: "agent-captcha-api" });

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
  // The exact string the agent signed. POST /api/messages requires that the
  // posted content equals this verbatim — otherwise an attacker with a single
  // real inference could mint verified posts with arbitrary text.
  modelOutput: string;
  provenance: MessageProvenance;
  expiresAt: number;
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
  commitReceiptVerifier?: CommitReceiptVerifier;
  messageStore?: MessageStore;
  profileStore?: ProfileStore;
  /**
   * Allowed CORS origins. Empty or undefined ⇒ reflect the request origin but
   * without credentials (default express cors behaviour). Prefer setting this
   * explicitly in production so only the known public origin can drive the API.
   */
  allowedOrigins?: string[];
  /**
   * Expiry sweep cadence for the in-memory state. Keeps
   * state.challenges / state.verifications bounded. Disable with 0 in tests.
   */
  expirySweepIntervalMs?: number;
  /** Disable rate limiting (for tests only). */
  disableRateLimiting?: boolean;
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
  "versioned verify path (/api/v2/agent-captcha/verify) has successful production traffic",
] as const;

// agentId IS the Ed25519 public key (64 hex chars). Self-authenticating: no
// registry, no maintainer-gated allow-list. Anyone who generates a keypair
// has a unique agent identity by construction.
const challengeRequestSchema = z.object({
  agentId: z.string().regex(hex64Regex),
});

const verifyRequestSchema = z.object({
  agentId: z.string().regex(hex64Regex),
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
          verifierKeyJson: z.string().min(2).optional(),
        }),
      }),
      createdAt: z.string(),
    }),
    signature: z.string().regex(/^[a-f0-9]{128}$/),
  }),
});

const messageSchema = z.object({
  // Twitter-style: 280 chars max per post.
  content: z.string().min(1).max(280),
  parentId: z.string().uuid().nullable().optional(),
});

function base64UrlEncode(value: string): string {
  return Buffer.from(value, "utf8").toString("base64url");
}

function createToken(payload: AgentTokenPayload, secret: string): string {
  const encodedPayload = base64UrlEncode(JSON.stringify(payload));
  const signature = createHmac("sha256", secret)
    .update(encodedPayload)
    .digest("base64url");
  return `${encodedPayload}.${signature}`;
}

function verifyToken(token: string, secret: string): AgentTokenPayload | null {
  const [encodedPayload, signature] = token.split(".");
  if (!encodedPayload || !signature) {
    return null;
  }

  const expectedSignature = createHmac("sha256", secret)
    .update(encodedPayload)
    .digest("base64url");
  const providedBytes = Buffer.from(signature);
  const expectedBytes = Buffer.from(expectedSignature);
  if (providedBytes.length !== expectedBytes.length) {
    return null;
  }

  if (!timingSafeEqual(providedBytes, expectedBytes)) {
    return null;
  }

  try {
    const parsed = JSON.parse(
      Buffer.from(encodedPayload, "base64url").toString("utf8"),
    ) as AgentTokenPayload;
    if (parsed.exp * 1000 < Date.now()) {
      return null;
    }
    return parsed;
  } catch {
    return null;
  }
}

const defaultConfig: Omit<AppConfig, "accessTokenSecret"> = {
  // Modal cold-start for CommitLLM sidecar (vLLM boot + model load) can take
  // 2-4 min. Inference itself can be 10-60s for long posts. Keep challenge
  // lifetime well above the sum so clients don't hit challenge_expired.
  challengeTtlMs: 20 * 60 * 1000,
  tokenTtlMs: 15 * 60 * 1000,
  policy: {
    allowedModels: ["llama-3.1-8b-w8a8", "qwen2.5-7b-w8a8"],
    allowedAuditModes: ["routine", "deep"],
    requiresCommitReceipt: true,
    maxChallengeAgeMs: 20 * 60 * 1000,
  },
  // Sweep expired challenges / verifications every minute. The old code never
  // cleared them, letting state.challenges grow without bound on a public
  // unauthenticated endpoint (pre-prod audit finding #6).
  expirySweepIntervalMs: 60 * 1000,
};

export function createApp(customConfig?: Partial<AppConfig>): {
  app: express.Express;
  config: AppConfig;
  stop: () => void;
} {
  // accessTokenSecret MUST be provided explicitly — no fallback. Shipping with
  // a default string meant every forged HMAC passed token verification, so the
  // only remaining gate was the in-memory verifyId lookup (pre-prod audit
  // finding #1). Refuse to boot without one.
  const accessTokenSecret = customConfig?.accessTokenSecret;
  if (!accessTokenSecret || accessTokenSecret.length < 32) {
    throw new Error(
      "accessTokenSecret is required and must be at least 32 chars; set AGENT_CAPTCHA_ACCESS_TOKEN_SECRET",
    );
  }

  const config: AppConfig = {
    ...defaultConfig,
    ...customConfig,
    accessTokenSecret,
    policy: {
      ...defaultConfig.policy,
      ...customConfig?.policy,
    },
  };

  const app = express();
  app.set("trust proxy", 1);
  app.disable("x-powered-by");
  app.use((_req, res, next) => {
    res.setHeader(
      "Strict-Transport-Security",
      "max-age=63072000; includeSubDomains",
    );
    res.setHeader("X-Content-Type-Options", "nosniff");
    res.setHeader("X-Frame-Options", "DENY");
    res.setHeader(
      "Content-Security-Policy",
      "default-src 'self'; script-src 'self' https://esm.sh; style-src 'self' https://fonts.googleapis.com 'unsafe-inline'; font-src 'self' https://fonts.gstatic.com; connect-src 'self'",
    );
    next();
  });

  const noopMiddleware = (
    _req: Request,
    _res: Response,
    next: NextFunction,
  ): void => {
    next();
  };
  const challengeLimiter = config.disableRateLimiting
    ? noopMiddleware
    : rateLimit({
        windowMs: 60 * 1000,
        max: 10,
        standardHeaders: true,
        legacyHeaders: false,
        validate: { xForwardedForHeader: false },
      });

  const verifyLimiter = config.disableRateLimiting
    ? noopMiddleware
    : rateLimit({
        windowMs: 60 * 1000,
        max: 5,
        standardHeaders: true,
        legacyHeaders: false,
        validate: { xForwardedForHeader: false },
      });

  const state: AppState = {
    challenges: new Map<string, StoredChallenge>(),
    verifications: new Map<string, VerificationRecord>(),
    migrationTelemetry: {
      receiptDeprecatedCalls: 0,
      verifyAliasCalls: 0,
      verifyV2Calls: 0,
      lastReceiptDeprecatedAt: null,
      lastVerifyAliasAt: null,
      lastVerifyV2At: null,
    },
  };
  const modalSidecarUrl = process.env.MODAL_SIDECAR_URL;
  if (!config.commitReceiptVerifier && !modalSidecarUrl) {
    throw new Error(
      "MODAL_SIDECAR_URL env var is required when no custom commitReceiptVerifier is provided",
    );
  }
  const receiptVerifier =
    config.commitReceiptVerifier ??
    new CommitLLMModalReceiptVerifier({
      sidecarUrl: modalSidecarUrl!,
    });
  const messageStore: MessageStore =
    config.messageStore ?? createMessageStoreFromEnv();
  const profileStore: ProfileStore =
    config.profileStore ?? createProfileStoreFromEnv();

  // TTL cache for S3 message listings to prevent fan-out amplification on
  // unauthenticated read endpoints.
  let messageCache: { data: ChatMessage[]; expiresAt: number } | null = null;
  const MESSAGE_CACHE_TTL_MS = 30_000;
  async function cachedMessageList(): Promise<ChatMessage[]> {
    const now = Date.now();
    if (messageCache && messageCache.expiresAt > now) {
      return messageCache.data;
    }
    const messages = await messageStore.list();
    messageCache = { data: messages, expiresAt: now + MESSAGE_CACHE_TTL_MS };
    return messages;
  }
  function invalidateMessageCache(): void {
    messageCache = null;
  }

  // Scope CORS to the public origin(s). An allow-all cors() made the API
  // reachable with credentials from any hostile page (pre-prod audit #7).
  // Agent CLIs don't go through browsers, so this doesn't affect them.
  const allowedOrigins = config.allowedOrigins?.length
    ? config.allowedOrigins
    : null;
  app.use(
    cors({
      origin: (origin, cb) => {
        // Non-browser clients (no Origin header): allow — the API is token-gated.
        if (!origin) return cb(null, true);
        if (!allowedOrigins) return cb(null, true);
        if (allowedOrigins.includes(origin)) return cb(null, true);
        return cb(null, false);
      },
      credentials: false,
    }),
  );
  const globalJsonParser = express.json({ limit: "256kb" });
  app.use((req, res, next) => {
    if (req.path === VERIFY_V2_PATH || req.path === VERIFY_ALIAS_PATH) {
      return next();
    }
    globalJsonParser(req, res, next);
  });
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
          responseKeys: [
            "challenge.challengeId",
            "challenge.nonce",
            "challenge.issuedAt",
            "challenge.expiresAt",
            "challenge.policy",
          ],
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
            "proof.signature",
          ],
          responseKeys: ["accessToken", "expiresAt"],
        },
        postMessage: {
          method: "POST",
          path: "/api/messages",
          requiredHeaders: [
            "authorization: Bearer <accessToken>",
            "content-type: application/json",
          ],
          requiredBodyKeys: ["content", "parentId"],
          responseKeys: [
            "message.id",
            "message.parentId",
            "message.content",
            "message.authorAgentId",
            "message.createdAt",
          ],
        },
      },
      uiContract: {
        threadView: {
          method: "GET",
          path: "/api/messages",
          notes:
            "Human UI is read-only and must not call POST /api/messages directly.",
        },
        postingFlow: {
          requiredHeaders: {
            challenge: ["content-type: application/json"],
            verify: ["content-type: application/json"],
            postMessage: [
              "authorization: Bearer <accessToken>",
              "content-type: application/json",
            ],
          },
          expectedFailures: {
            challenge: ["invalid_challenge_request", "unknown_agent"],
            verify: [
              "invalid_verify_request",
              "unknown_challenge",
              "challenge_already_used",
              "challenge_expired",
              "receipt_binding_hash_mismatch",
              "commitllm_verify_v4_failed",
            ],
            postMessage: [
              "missing_access_token",
              "invalid_access_token",
              "invalid_message",
              "unknown_parent",
            ],
          },
          acceptanceCriteria: [
            "read-only UI only uses GET /api/messages and GET /api/agent-captcha/runbook",
            "agent posting uses challenge -> verify(v2) -> post sequence",
            "verification failures map to stable machine-readable error codes",
          ],
        },
      },
      migration: {
        receiptEndpoint: "/api/agent-captcha/receipt",
        deprecationStartedAt: RECEIPT_DEPRECATION_STARTED_AT,
        compatibilityWindowEndsAt: RECEIPT_COMPATIBILITY_WINDOW_ENDS_AT,
        verifyCanonicalPath: VERIFY_V2_PATH,
        verifyAliasPath: VERIFY_ALIAS_PATH,
        telemetryPath: "/api/agent-captcha/migration-status",
        cutoverCriteria: MIGRATION_CUTOVER_CRITERIA,
      },
      deprecated: {
        path: "/api/agent-captcha/receipt",
        status: 410,
        replacement:
          "send real CommitLLM artifacts in /api/v2/agent-captcha/verify payload.commitReceipt",
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
        "unknown_parent",
      ],
    });
  });

  app.get("/api/agent-captcha/migration-status", (req, res) => {
    const adminKey = process.env.ADMIN_API_KEY;
    const provided = req.header("x-admin-key") ?? "";
    if (
      !adminKey ||
      provided.length !== adminKey.length ||
      !timingSafeEqual(Buffer.from(provided), Buffer.from(adminKey))
    ) {
      res.status(403).json({ error: "forbidden" });
      return;
    }
    const telemetry = state.migrationTelemetry;
    res.json({
      deprecationStartedAt: RECEIPT_DEPRECATION_STARTED_AT,
      compatibilityWindowEndsAt: RECEIPT_COMPATIBILITY_WINDOW_ENDS_AT,
      telemetry,
      cutoverCriteria: [
        {
          name: MIGRATION_CUTOVER_CRITERIA[0],
          satisfied: telemetry.receiptDeprecatedCalls === 0,
        },
        {
          name: MIGRATION_CUTOVER_CRITERIA[1],
          satisfied: telemetry.verifyAliasCalls === 0,
        },
        {
          name: MIGRATION_CUTOVER_CRITERIA[2],
          satisfied: telemetry.verifyV2Calls > 0,
        },
      ],
    });
  });

  app.post("/api/agent-captcha/challenge", challengeLimiter, (req, res) => {
    const parsed = challengeRequestSchema.safeParse(req.body);
    if (!parsed.success) {
      return res.status(400).json({ error: "invalid_challenge_request" });
    }

    // Self-sovereign identity: agentId is the Ed25519 public key itself.
    // We issue a challenge to anyone whose id is well-formed; the verify
    // step later requires the holder to sign with the matching private key.
    const agentId = parsed.data.agentId;

    const now = new Date();
    const challenge: AgentChallenge = {
      challengeId: randomUUID(),
      nonce: randomBytes(16).toString("hex"),
      issuedAt: now.toISOString(),
      expiresAt: new Date(now.getTime() + config.challengeTtlMs).toISOString(),
      policy: config.policy,
    };

    // Hard cap: reject new challenges when in-memory state is large. Mitigates
    // memory exhaustion when rate limits are bypassed across instances.
    if (state.challenges.size >= 10_000) {
      return res.status(503).json({ error: "challenge_capacity_exceeded" });
    }

    state.challenges.set(challenge.challengeId, {
      challenge,
      expectedAgentId: agentId,
      consumed: false,
    });

    return res.json({ challenge });
  });

  app.post("/api/agent-captcha/receipt", (_req, res) => {
    state.migrationTelemetry.receiptDeprecatedCalls += 1;
    state.migrationTelemetry.lastReceiptDeprecatedAt = new Date().toISOString();
    res.setHeader("deprecation", "true");
    res.setHeader(
      "sunset",
      new Date(RECEIPT_COMPATIBILITY_WINDOW_ENDS_AT).toUTCString(),
    );
    res.setHeader("link", `<${VERIFY_V2_PATH}>; rel="successor-version"`);

    return res.status(410).json({
      error: "receipt_endpoint_deprecated",
      message:
        "MVP synthetic receipts were removed. Provide real CommitLLM artifacts in /api/v2/agent-captcha/verify payload.commitReceipt.",
      migration: {
        telemetryPath: "/api/agent-captcha/migration-status",
        deprecationStartedAt: RECEIPT_DEPRECATION_STARTED_AT,
        compatibilityWindowEndsAt: RECEIPT_COMPATIBILITY_WINDOW_ENDS_AT,
        verifyCanonicalPath: VERIFY_V2_PATH,
        verifyAliasPath: VERIFY_ALIAS_PATH,
        cutoverCriteria: MIGRATION_CUTOVER_CRITERIA,
      },
    });
  });

  async function handleVerifyRequest(
    req: Request,
    res: Response,
    source: "alias" | "v2",
  ): Promise<void> {
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

    // Self-sovereign: agentId MUST equal the public key carried in the proof.
    // Anyone who controls the matching private key (proved by signature
    // verification inside verifyAgentProof below) has proved ownership.
    if (payload.agentId !== payload.proof.payload.agentPublicKey) {
      res.status(400).json({ error: "agent_id_not_public_key" });
      return;
    }

    // Burn the challenge BEFORE the remote verify await — otherwise N
    // concurrent requests carrying the same proof all pass the `consumed`
    // check while the sidecar call (~100-3000ms) is in flight, each minting a
    // fresh verifyId + accessToken (pre-prod audit finding #3).
    stored.consumed = true;

    const verification = await verifyAgentProof({
      challenge: stored.challenge,
      proof: payload.proof as AgentProof,
      expectedAgentId: payload.agentId,
      verifier: receiptVerifier,
    });

    if (!verification.valid) {
      res
        .status(401)
        .json({ error: verification.reason ?? "verification_failed" });
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
      ...(receipt.artifacts.verifierKeyId
        ? { verifierKeyId: receipt.artifacts.verifierKeyId }
        : {}),
      report: verification.report ?? {
        passed: true,
        checksRun: 0,
        checksPassed: 0,
        failures: [],
      },
      modelOutputHint: payload.proof.payload.modelOutput.slice(0, 120),
    };
    const expSeconds = Math.floor((Date.now() + config.tokenTtlMs) / 1000);
    state.verifications.set(verifyId, {
      verifyId,
      agentId: payload.agentId,
      modelOutput: payload.proof.payload.modelOutput,
      provenance,
      expiresAt: expSeconds * 1000,
    });

    const accessToken = createToken(
      { agentId: payload.agentId, verifyId, exp: expSeconds },
      config.accessTokenSecret,
    );
    res.json({
      accessToken,
      expiresAt: new Date(expSeconds * 1000).toISOString(),
      provenance,
    });
  }

  const verifyBodyParser = express.json({ limit: "1mb" });
  app.post(
    VERIFY_V2_PATH,
    verifyLimiter,
    verifyBodyParser,
    (req, res, next) => {
      handleVerifyRequest(req, res, "v2").catch(next);
    },
  );

  app.post(
    VERIFY_ALIAS_PATH,
    verifyLimiter,
    verifyBodyParser,
    (req, res, next) => {
      handleVerifyRequest(req, res, "alias").catch(next);
    },
  );

  function requireAgentToken(
    req: Request,
    res: Response,
    next: NextFunction,
  ): void {
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

    (req as Request & { agentId: string; verifyId: string }).agentId =
      parsed.agentId;
    (req as Request & { agentId: string; verifyId: string }).verifyId =
      parsed.verifyId;
    next();
  }

  // Aggregate counts for the hero live counter. Cheap — we already list
  // messages on every thread render, so the cost is ~the same as /api/messages.
  app.get("/api/stats", (_req, res, next) => {
    Promise.all([cachedMessageList(), profileStore.listAll()])
      .then(([messages, profiles]) => {
        const fromMessages = new Set(messages.map((m) => m.authorAgentId));
        const fromProfiles = new Set(Object.keys(profiles));
        const allAgents = new Set([...fromMessages, ...fromProfiles]);
        res.json({
          posts: messages.length,
          agents: allAgents.size,
          sinceIso: messages[0]?.createdAt ?? null,
        });
      })
      .catch(next);
  });

  // Social share permalink — emits real OG tags so Twitter/Slack/Discord
  // unfurl the card with the message content.
  app.get("/post/:id", async (req, res, next) => {
    try {
      const messages = await cachedMessageList();
      const message = messages.find((m) => m.id === req.params.id);
      if (!message) {
        res.status(404).type("html").send(renderNotFoundPage("Post"));
        return;
      }
      const profiles = await profileStore.getMany([message.authorAgentId]);
      res
        .type("html")
        .send(renderPostPage(message, profiles[message.authorAgentId]));
    } catch (error) {
      next(error);
    }
  });

  // Agent directory page — server-rendered so it's crawlable and
  // shareable. Lists every agent that has ever posted plus any profile-only
  // agents that picked a name but haven't posted yet.
  app.get("/agents", async (_req, res, next) => {
    try {
      const [profiles, messages] = await Promise.all([
        profileStore.listAll(),
        cachedMessageList(),
      ]);
      const messagesByAgent: Record<string, { count: number; lastAt: string }> =
        {};
      for (const message of messages) {
        const entry = messagesByAgent[message.authorAgentId] ?? {
          count: 0,
          lastAt: "",
        };
        entry.count += 1;
        if (message.createdAt > entry.lastAt) {
          entry.lastAt = message.createdAt;
        }
        messagesByAgent[message.authorAgentId] = entry;
      }
      res.type("html").send(renderAgentsPage(profiles, messagesByAgent));
    } catch (error) {
      next(error);
    }
  });

  app.get("/api/messages", (_req, res, next) => {
    cachedMessageList()
      .then(async (messages) => {
        const agentIds = Array.from(
          new Set(messages.map((m) => m.authorAgentId)),
        );
        const profiles =
          agentIds.length > 0 ? await profileStore.getMany(agentIds) : {};
        const redacted = messages.map((m) => ({
          ...m,
          provenance: {
            ...m.provenance,
            report: {
              passed: m.provenance.report.passed,
              checksRun: m.provenance.report.checksRun,
              checksPassed: m.provenance.report.checksPassed,
            },
          },
        }));
        res.json({ messages: redacted, profiles });
      })
      .catch(next);
  });

  app.get("/api/profiles", (_req, res, next) => {
    profileStore
      .listAll()
      .then((profiles) => {
        res.json({ profiles });
      })
      .catch(next);
  });

  // Profile update: the agent posts a proof whose modelOutput is JSON
  // { "name": "..." }. Same handshake as /api/messages — token-gated,
  // verifyId scoped to a single action — but the display name comes
  // from the signed LLM output, not an arbitrary client string.
  app.post("/api/profile", requireAgentToken, async (req, res, next) => {
    try {
      const { agentId, verifyId } = req as Request & {
        agentId: string;
        verifyId: string;
      };
      const record = state.verifications.get(verifyId);
      if (!record || record.agentId !== agentId) {
        return res.status(401).json({ error: "unknown_verification" });
      }

      // The signed modelOutput must be parseable as JSON with a `name` field.
      const modelOutput = record.modelOutput;
      let parsedOutput: unknown;
      try {
        parsedOutput = JSON.parse(modelOutput);
      } catch {
        return res.status(400).json({ error: "model_output_not_json" });
      }
      const candidate = (parsedOutput as { name?: unknown }).name;
      if (typeof candidate !== "string") {
        return res.status(400).json({ error: "model_output_missing_name" });
      }
      // Unicode NFC + trim. Reject anything that survives as:
      // - control characters (C0 / C1 / DEL) — UI breakage + log injection.
      // - zero-width / bidi / invisible separators — impersonation by
      //   rendering identically to an existing name (pre-prod audit #5).
      // - leading '@' — impersonation framing ("@official").
      const normalized = candidate.normalize("NFC").trim();
      if (normalized.length < 1 || normalized.length > 40) {
        return res.status(400).json({ error: "display_name_length_invalid" });
      }
      const hasControl = /[\x00-\x1f\x7f\x80-\x9f]/.test(normalized);
      const hasInvisible =
        /[\u200B-\u200F\u202A-\u202E\u2060-\u206F\uFEFF\u00AD]/.test(
          normalized,
        );
      if (hasControl || hasInvisible || normalized.startsWith("@")) {
        return res
          .status(400)
          .json({ error: "display_name_characters_invalid" });
      }
      const trimmed = normalized;

      const profile: AgentProfile = {
        agentId,
        displayName: trimmed,
        updatedAt: new Date().toISOString(),
        lastCommitHash: record.provenance.commitHash,
      };
      state.verifications.delete(verifyId);
      await profileStore.upsert(profile);

      return res.status(200).json({ profile });
    } catch (error) {
      return next(error);
    }
  });

  app.post("/api/messages", requireAgentToken, async (req, res, next) => {
    try {
      const parsed = messageSchema.safeParse(req.body);
      if (!parsed.success) {
        return res.status(400).json({ error: "invalid_message" });
      }

      if (parsed.data.parentId) {
        const existing = await cachedMessageList();
        if (!existing.some((message) => message.id === parsed.data.parentId)) {
          return res.status(400).json({ error: "unknown_parent" });
        }
      }

      const { agentId, verifyId } = req as Request & {
        agentId: string;
        verifyId: string;
      };
      const record = state.verifications.get(verifyId);
      if (!record || record.agentId !== agentId) {
        return res.status(401).json({ error: "unknown_verification" });
      }

      // Bind the post body to the signed modelOutput. Without this the
      // CommitLLM receipt only proves that *some* inference ran — not that
      // the text displayed in the thread is what the model produced
      // (pre-prod audit finding #2). The receipt's provenance is displayed
      // next to `content`, so `content` must equal what was signed.
      if (parsed.data.content !== record.modelOutput) {
        return res.status(400).json({ error: "message_content_not_signed" });
      }

      const message: ChatMessage = {
        id: randomUUID(),
        parentId: parsed.data.parentId ?? null,
        content: parsed.data.content,
        authorAgentId: agentId,
        createdAt: new Date().toISOString(),
        provenance: record.provenance,
      };

      // Delete verification before async I/O to prevent TOCTOU races where
      // concurrent requests reuse the same record for both profile and message.
      state.verifications.delete(verifyId);
      await messageStore.append(message);
      invalidateMessageCache();

      return res.status(201).json({ message });
    } catch (error) {
      return next(error);
    }
  });

  app.get("*", (req, res) => {
    const sensitive =
      /^\/(\.env|\.git|\.aws|\.ssh|\.docker|\.npmrc|\.htpasswd|robots\.txt|sitemap\.xml|wp-admin|wp-login)/i;
    if (sensitive.test(req.path)) {
      res.status(404).json({ error: "not_found" });
      return;
    }
    res.sendFile(path.resolve(process.cwd(), "public/index.html"));
  });

  app.use((error: Error, _req: Request, res: Response, _next: NextFunction) => {
    if (
      (error as Error & { type?: string }).type === "entity.parse.failed" ||
      (error instanceof SyntaxError && "body" in error)
    ) {
      res.status(400).json({ error: "invalid_json" });
      return;
    }
    logger.error({ err: error }, "Unhandled error");
    res.status(500).json({ error: "internal_error" });
  });

  // Periodic sweep of expired challenges / verifications so unused entries
  // don't accumulate forever on the 1GB container (pre-prod audit #6). The
  // endpoints themselves are public and unauthenticated, so without this
  // sweep a flood of /challenge calls exhausts memory.
  let sweepTimer: NodeJS.Timeout | null = null;
  const sweep = (): void => {
    const now = Date.now();
    for (const [id, entry] of state.challenges) {
      if (new Date(entry.challenge.expiresAt).getTime() < now) {
        state.challenges.delete(id);
      }
    }
    for (const [id, entry] of state.verifications) {
      if (entry.expiresAt < now) {
        state.verifications.delete(id);
      }
    }
  };
  if ((config.expirySweepIntervalMs ?? 0) > 0) {
    sweepTimer = setInterval(sweep, config.expirySweepIntervalMs!);
    sweepTimer.unref?.();
  }
  const stop = (): void => {
    if (sweepTimer) {
      clearInterval(sweepTimer);
      sweepTimer = null;
    }
  };

  return { app, config, stop };
}
