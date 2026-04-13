/**
 * CommitLLM fixture loader for tests.
 * Why: keep artifact-fidelity tests deterministic while avoiding inline placeholder strings.
 */
import { readFileSync } from "fs";
import path from "path";
import { computeAuditBinarySha256, computeVerifierKeySha256 } from "../../src/sdk";

export interface CommitLLMFixture {
  auditBinaryBase64: string;
  auditBinarySha256: string;
  verifierKeyJson: string;
  verifierKeySha256: string;
  commitHash: string;
}

let fixtureCache: CommitLLMFixture | null = null;

export function loadCommitLLMFixture(): CommitLLMFixture {
  if (fixtureCache) {
    return fixtureCache;
  }

  const fixtureDirectory = path.resolve(process.cwd(), "tests/fixtures/commitllm");
  const auditBinaryBase64 = readFileSync(path.join(fixtureDirectory, "audit-binary.base64"), "utf8").replace(/\s+/g, "");
  const verifierKeyJson = readFileSync(path.join(fixtureDirectory, "verifier-key.json"), "utf8").trim();
  const commitHash = readFileSync(path.join(fixtureDirectory, "commit-hash.txt"), "utf8").trim();
  const auditBinarySha256 = computeAuditBinarySha256(auditBinaryBase64);
  const verifierKeySha256 = computeVerifierKeySha256(verifierKeyJson);

  fixtureCache = {
    auditBinaryBase64,
    auditBinarySha256,
    verifierKeyJson,
    verifierKeySha256,
    commitHash
  };

  return fixtureCache;
}
