// smithers-source: user
/** @jsxImportSource smithers-orchestrator */
//
// DeployFlow: build + push + redeploy the prod container so the next
// iteration's finder probes a host that actually has the latest fixes,
// not the build from when the run started. Skips when nothing changed
// (e.g. canary blocked + RepairFlow reverted the tree, so commit
// produced no new SHA).
import { Task } from "smithers-orchestrator";
import { z } from "zod/v4";

export const deploySchema = z.object({
  deployed: z.boolean(),
  sha: z.string().nullable(),
  reason: z.string(),
});

export type DeployFlowProps = {
  idPrefix: string;
  dependsOn: string[];
  /** When true the whole flow skips — used to short-circuit after a
      failed canary + revert. */
  skipIfBlocked?: boolean;
  /** Total deploy timeout (build + push + rollout + health probe). */
  timeoutMs?: number;
  /** Heartbeat timeout — long enough for a slow docker push. */
  heartbeatTimeoutMs?: number;
};

export function DeployFlow({
  idPrefix,
  dependsOn,
  skipIfBlocked = false,
  timeoutMs = 1_800_000,
  heartbeatTimeoutMs = 1_200_000,
}: DeployFlowProps) {
  const deployId = `${idPrefix}:deploy`;
  return (
    <Task
      id={deployId}
      output={deploySchema}
      dependsOn={dependsOn}
      skipIf={skipIfBlocked}
      timeoutMs={timeoutMs}
      heartbeatTimeoutMs={heartbeatTimeoutMs}
    >
      {async () => {
        const { execSync } = await import("node:child_process");
        // Don't bother deploying if HEAD is unchanged from the last
        // deploy: this happens when a canary failure + revert leaves
        // the tree clean. We tag a marker ref after each successful
        // deploy and compare against it here.
        const sha = execSync("git rev-parse HEAD", {
          encoding: "utf8",
        }).trim();
        let lastDeployed = "";
        try {
          lastDeployed = execSync("git rev-parse refs/agent-captcha/deployed", {
            encoding: "utf8",
            stdio: ["ignore", "pipe", "pipe"],
          }).trim();
        } catch {
          lastDeployed = "";
        }
        if (sha === lastDeployed) {
          return {
            deployed: false,
            sha,
            reason: `HEAD ${sha} already marked deployed`,
          };
        }
        // Run the deploy script; surface stdout/stderr live so a long
        // docker push doesn't look like a hung task.
        execSync("uv run scripts/deploy.py", {
          stdio: "inherit",
          env: process.env,
        });
        // Move the marker ref forward so subsequent iterations skip if
        // nothing new landed.
        execSync(`git update-ref refs/agent-captcha/deployed ${sha}`, {
          stdio: "pipe",
        });
        return {
          deployed: true,
          sha,
          reason: "scripts/deploy.py succeeded and prod /api/health is OK",
        };
      }}
    </Task>
  );
}
