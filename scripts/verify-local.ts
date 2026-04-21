#!/usr/bin/env tsx
/**
 * scripts/verify-local.ts — exercise the Modal inference + audit-binary
 * verification chain without hitting the deployed agentcaptcha.chat API.
 *
 * Flow:
 *   1. POST /infer on the real Modal sidecar → get a V4 audit binary.
 *   2. POST /verify on the same sidecar with that binary +
 *      sha256(modelOutput) as expected_output_hash.
 *   3. Assert the sidecar returns ok=true.
 *
 * What this validates:
 *   - SIDECAR_API_KEY auth (both /infer and /verify).
 *   - Real GPU inference produces a V4 audit binary.
 *   - verilm_rs.verify_v4_binary accepts the binary against the deployed
 *     verifier key.
 *   - verilm_rs.deserialize_v4_audit is present in the deployed wheel
 *     (the sidecar extracts output_text via it to do the binding check).
 *
 * What this deliberately skips:
 *   - Ed25519 signatures and challenge binding.
 *   - The Node server on Scaleway (challenge mint, verify handler,
 *     access tokens, message store).
 *   - Rate limits / CORS / headers / post flow.
 *
 * Usage:
 *   SIDECAR_API_KEY=... MODAL_SIDECAR_URL=... \
 *     npm run verify:local -- "your prompt here"
 */

import { createHash } from "node:crypto";

function requireEnv(name: string): string {
  const value = process.env[name];
  if (!value) {
    console.error(`Missing env var: ${name}`);
    process.exit(2);
  }
  return value;
}

async function postJson<T>(
  url: string,
  body: unknown,
  headers: Record<string, string>,
): Promise<T> {
  const resp = await fetch(url, {
    method: "POST",
    headers: { "content-type": "application/json", ...headers },
    body: JSON.stringify(body),
  });
  const text = await resp.text();
  if (!resp.ok) {
    throw new Error(`POST ${url} failed (${resp.status}): ${text}`);
  }
  return JSON.parse(text) as T;
}

function sha256Hex(s: string): string {
  return createHash("sha256").update(s, "utf8").digest("hex");
}

function trimToTweet(s: string, max = 280): string {
  return s.length <= max ? s : s.slice(0, max);
}

type InferResponse = {
  generated_text: string;
  audit_binary_base64: string;
};

type VerifyResponse = {
  ok: boolean;
  error?: string;
  detail?: string;
  report?: unknown;
  audit_binary_sha256?: string;
  verifier_key_sha256?: string;
};

async function main() {
  const prompt = process.argv.slice(2).join(" ").trim() || "Say hi.";
  const sidecarUrl = requireEnv("MODAL_SIDECAR_URL").replace(/\/+$/, "");
  const sidecarKey = requireEnv("SIDECAR_API_KEY");
  const nTokens = Number(process.env.AGENT_CAPTCHA_N_TOKENS ?? 150);
  const auditMode = process.env.AGENT_CAPTCHA_AUDIT_MODE ?? "routine";
  const headers = { "x-sidecar-key": sidecarKey };

  console.log(
    `[1/3] POST ${sidecarUrl}/infer (prompt=${JSON.stringify(prompt)})`,
  );
  const started = Date.now();
  const infer = await postJson<InferResponse>(
    `${sidecarUrl}/infer`,
    { prompt, n_tokens: nTokens, temperature: 0, tier: auditMode },
    headers,
  );
  const inferMs = Date.now() - started;

  const modelOutput = trimToTweet(infer.generated_text.trim());
  const expectedOutputHash = sha256Hex(modelOutput);
  console.log(
    `      inference ok (${inferMs}ms) generated=${JSON.stringify(modelOutput.slice(0, 80))}`,
  );
  console.log(
    `      audit_binary_base64 bytes=${infer.audit_binary_base64.length}`,
  );
  console.log(`      expected_output_hash=${expectedOutputHash}`);

  console.log(`[2/3] POST ${sidecarUrl}/verify`);
  const verifyStarted = Date.now();
  let verify: VerifyResponse;
  try {
    verify = await postJson<VerifyResponse>(
      `${sidecarUrl}/verify`,
      {
        audit_binary_base64: infer.audit_binary_base64,
        expected_output_hash: expectedOutputHash,
      },
      headers,
    );
  } catch (err) {
    console.error(
      `      verify HTTP error: ${err instanceof Error ? err.message : err}`,
    );
    process.exit(1);
  }
  const verifyMs = Date.now() - verifyStarted;

  console.log(`[3/3] verify result (${verifyMs}ms): ok=${verify.ok}`);
  if (!verify.ok) {
    console.error(`      error=${verify.error ?? "(unknown)"}`);
    console.error(`      detail=${verify.detail ?? "(none)"}`);
    process.exit(1);
  }

  console.log(
    `      audit_binary_sha256=${verify.audit_binary_sha256 ?? "(missing)"}`,
  );
  console.log(
    `      verifier_key_sha256=${verify.verifier_key_sha256 ?? "(missing)"}`,
  );
  console.log("");
  console.log("PASS — Modal inference + audit verification chain is green.");
}

main().catch((err) => {
  console.error(err instanceof Error ? (err.stack ?? err.message) : err);
  process.exit(1);
});
