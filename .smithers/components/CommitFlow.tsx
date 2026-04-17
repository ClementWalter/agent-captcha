// smithers-source: user
/** @jsxImportSource smithers-orchestrator */
//
// CommitFlow: deterministic git commit + trunk auto-fix + AI lint-fixer +
// second commit. Use after any task that may have mutated the working
// tree to land the change in two reviewable commits per iteration:
// "<iteration>: apply <message>" then "<iteration>: lint/fmt cleanup".
//
// The component owns the schemas; the consuming workflow re-exports them
// to its createSmithers() registry under the same keys.
import { Task, type AgentLike } from "smithers-orchestrator";
import { z } from "zod/v4";
import LintFixerPrompt from "../prompts/lint-fixer.mdx";

export const commitSchema = z.object({
  committed: z.boolean(),
  sha: z.string().nullable(),
  message: z.string().nullable(),
});

export const trunkSchema = z.object({
  clean: z.boolean(),
  remaining: z.string(),
});

export const lintFixSchema = z.object({
  fixes: z.array(
    z
      .object({
        location: z.string(),
        action: z.string(),
      })
      .loose(),
  ),
  summary: z.string(),
});

export type CommitFlowProps = {
  /** Namespace for task ids ("X:commit", "X:trunk", ...). */
  idPrefix: string;
  /** Tasks the first commit waits on (e.g. ["fixes", "canary"]). */
  dependsOn: string[];
  /** Iteration number — used in commit messages so history reads
      "loop iter 0: ...", "loop iter 1: ...". */
  iteration: number;
  /** Short label for the first commit; appears as
      "loop iter N: apply <commitMessage>". */
  commitMessage: string;
  /** Result of the most recent trunk run for this idPrefix; drives
      skipIf on the AI lint-fixer so we don't burn an LLM call when
      there's nothing left to fix. */
  latestTrunk?: { clean?: boolean; remaining?: string };
  /** When true, every step in this flow skips. Used to short-circuit
      after a failed canary so we don't commit a broken iteration. */
  skipIfBlocked?: boolean;
  /** Agents tried in order for the lint-fixer task. */
  lintAgents: AgentLike[];
  /** Heartbeat / total timeouts for the AI lint-fixer. */
  lintTimeoutMs?: number;
  lintHeartbeatTimeoutMs?: number;
};

function gitCommitStep(message: string) {
  return async () => {
    const { execSync } = await import("node:child_process");
    execSync("git add -A", { stdio: "pipe" });
    const dirty = execSync("git status --porcelain", {
      encoding: "utf8",
    }).trim();
    if (!dirty) return { committed: false, sha: null, message: null };
    execSync(`git commit -m ${JSON.stringify(message)}`, { stdio: "pipe" });
    execSync("git push", { stdio: "pipe" });
    const sha = execSync("git rev-parse HEAD", { encoding: "utf8" }).trim();
    return { committed: true, sha, message };
  };
}

async function runTrunkFix() {
  const { execSync } = await import("node:child_process");
  // trunk check exits non-zero when issues remain after --fix; treat that
  // as success for this task and surface the summary to the lint-fixer.
  let remaining = "";
  try {
    remaining = execSync(
      "trunk check --fix --no-progress -y --output=summary",
      { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] },
    );
  } catch (err) {
    const e = err as { stdout?: string; stderr?: string };
    remaining = (e.stdout ?? "") + "\n" + (e.stderr ?? "");
  }
  const clean = !/\b(issue|error|warning)s?\b/i.test(remaining);
  return { clean, remaining: remaining.trim().slice(-4000) };
}

export function CommitFlow({
  idPrefix,
  dependsOn,
  iteration,
  commitMessage,
  latestTrunk,
  skipIfBlocked = false,
  lintAgents,
  lintTimeoutMs = 1_800_000,
  lintHeartbeatTimeoutMs = 1_200_000,
}: CommitFlowProps) {
  const commitId = `${idPrefix}:commit`;
  const trunkId = `${idPrefix}:trunk`;
  const lintFixId = `${idPrefix}:lintFix`;
  const commitLintId = `${idPrefix}:commitLint`;
  const trunkClean = latestTrunk?.clean === true;

  return (
    <>
      <Task
        id={commitId}
        output={commitSchema}
        dependsOn={dependsOn}
        skipIf={skipIfBlocked}
      >
        {gitCommitStep(`loop iter ${iteration}: ${commitMessage}`)}
      </Task>

      <Task
        id={trunkId}
        output={trunkSchema}
        dependsOn={[commitId]}
        skipIf={skipIfBlocked}
      >
        {runTrunkFix}
      </Task>

      <Task
        id={lintFixId}
        output={lintFixSchema}
        agent={lintAgents}
        dependsOn={[trunkId]}
        skipIf={skipIfBlocked || trunkClean}
        timeoutMs={lintTimeoutMs}
        heartbeatTimeoutMs={lintHeartbeatTimeoutMs}
      >
        <LintFixerPrompt trunkOutput={latestTrunk?.remaining ?? ""} />
      </Task>

      <Task
        id={commitLintId}
        output={commitSchema}
        dependsOn={[trunkId, lintFixId]}
        skipIf={skipIfBlocked}
      >
        {gitCommitStep(`loop iter ${iteration}: lint/fmt cleanup`)}
      </Task>
    </>
  );
}
