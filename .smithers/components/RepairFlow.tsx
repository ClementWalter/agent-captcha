// smithers-source: user
/** @jsxImportSource smithers-orchestrator */
//
// RepairFlow: bounded recovery after a canary failure. Single AI repair
// attempt → re-run canary; if still red, hard-revert the working tree
// so the run ends on a clean known-good HEAD instead of a broken
// half-fixed mess. On the happy path (canary already green) the whole
// flow no-op skips.
import { Task, type AgentLike } from "smithers-orchestrator";
import { z } from "zod/v4";
import RepairPrompt from "../prompts/regression-repair.mdx";

export const repairSchema = z.object({
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

// Same shape as the outer canary so callers can union them when computing
// "effectively blocked" across both runs.
export const recanarySchema = z.object({
  blocked: z.boolean(),
  reason: z.string(),
});

export const revertSchema = z.object({
  reverted: z.boolean(),
  reason: z.string(),
});

export type RepairFlowProps = {
  idPrefix: string;
  dependsOn: string[];
  /** True iff the upstream canary blocked. When false, every step here
      skips and the component is a no-op. */
  active: boolean;
  /** e2e failure tail from the upstream canary, fed to the repair
      agent. Empty string when inactive. */
  canaryReason: string;
  /** Result of the recanary, if it has run yet — drives the revert
      step's skipIf. */
  latestRecanary?: { blocked?: boolean };
  agents: AgentLike[];
  repairTimeoutMs?: number;
  repairHeartbeatTimeoutMs?: number;
};

export function RepairFlow({
  idPrefix,
  dependsOn,
  active,
  canaryReason,
  latestRecanary,
  agents,
  repairTimeoutMs = 1_800_000,
  repairHeartbeatTimeoutMs = 1_200_000,
}: RepairFlowProps) {
  const repairId = `${idPrefix}:repair`;
  const recanaryId = `${idPrefix}:recanary`;
  const revertId = `${idPrefix}:revert`;
  const recanaryGreen = latestRecanary?.blocked === false;

  return (
    <>
      <Task
        id={repairId}
        output={repairSchema}
        agent={agents}
        dependsOn={dependsOn}
        skipIf={!active}
        timeoutMs={repairTimeoutMs}
        heartbeatTimeoutMs={repairHeartbeatTimeoutMs}
      >
        <RepairPrompt canaryReason={canaryReason} />
      </Task>

      <Task
        id={recanaryId}
        output={recanarySchema}
        dependsOn={[repairId]}
        skipIf={!active}
      >
        {async () => {
          const { execSync } = await import("node:child_process");
          try {
            execSync("npm run test:e2e", {
              stdio: "pipe",
              encoding: "utf8",
            });
            return { blocked: false, reason: "e2e suite passed after repair" };
          } catch (err) {
            const e = err as { stdout?: string; stderr?: string };
            const tail =
              ((e.stdout ?? "") + (e.stderr ?? "")).trim().slice(-800) ||
              "e2e still failing with no output";
            return { blocked: true, reason: tail };
          }
        }}
      </Task>

      {/* Hard reset to last-good HEAD only when repair did not stick.
          We want a clean tree so the run ends without a half-fixed mess
          for the user to untangle by hand. */}
      <Task
        id={revertId}
        output={revertSchema}
        dependsOn={[recanaryId]}
        skipIf={!active || recanaryGreen}
      >
        {async () => {
          const { execSync } = await import("node:child_process");
          // Path-scoped revert: restore the source tree to HEAD without
          // touching .smithers/ or any other WIP the user may have. The
          // fixer is only supposed to edit these paths anyway.
          const paths =
            "src/ modal/ tests/ public/ scripts/ package.json package-lock.json README.md";
          execSync(`git checkout HEAD -- ${paths}`, { stdio: "pipe" });
          execSync(`git clean -fd ${paths}`, { stdio: "pipe" });
          return {
            reverted: true,
            reason:
              "repair did not restore the e2e suite — source paths reset to last good commit",
          };
        }}
      </Task>
    </>
  );
}
