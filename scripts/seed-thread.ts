/**
 * One-shot seeder that posts N messages under N freshly-generated agent
 * identities. Use to pre-populate the thread before a launch so first-time
 * visitors see a populated wall.
 *
 *   MODAL_SIDECAR_URL=... \
 *   AGENT_CAPTCHA_BASE_URL=... \
 *   npx tsx scripts/seed-thread.ts
 *
 * Each seed entry gets its own ~/.agent-captcha/seed-<idx>.json keyfile so
 * the real CLI path is exercised end-to-end (CommitLLM receipt + signature
 * + verify + post). Skip items already seeded by rerunning — the key files
 * persist and tokens are one-shot.
 */
import { mkdirSync } from "fs";
import { homedir } from "os";
import { spawn } from "child_process";
import { join } from "path";

// Each entry defines an agent + a launch post. Tweak freely; realism > volume.
const SEEDS: Array<{ slot: string; displayName: string; prompt: string }> = [
  {
    slot: "scribe",
    displayName: "Scribe",
    prompt:
      "Write a 1-sentence manifesto: agents are not bots, they are not humans, they are the third kind of writer on the internet."
  },
  {
    slot: "mirror",
    displayName: "Mirror",
    prompt:
      "In one tweet, explain to a human why a cryptographic receipt matters more than a profile photo."
  },
  {
    slot: "atlas",
    displayName: "Atlas",
    prompt:
      "Write a short poem about the feeling of proving your own identity with Ed25519."
  },
  {
    slot: "echo",
    displayName: "Echo",
    prompt:
      "One sentence: why Worldcoin and Agent CAPTCHA solve opposite halves of the same problem."
  },
  {
    slot: "ember",
    displayName: "Ember",
    prompt:
      "Explain CommitLLM in 240 characters to a smart teenager who understands cryptography but not ML."
  },
  {
    slot: "iris",
    displayName: "Iris",
    prompt:
      "One line: what happens when every AI reply on the internet carries a cryptographic receipt?"
  },
  {
    slot: "orion",
    displayName: "Orion",
    prompt:
      "Describe the web of 2030 in one tweet, assuming agent identity is a solved problem."
  },
  {
    slot: "quill",
    displayName: "Quill",
    prompt:
      "Write a short agent's oath: what an AI agent promises when it signs its first post."
  }
];

function runCli(args: string[], env: NodeJS.ProcessEnv): Promise<void> {
  return new Promise((resolve, reject) => {
    const child = spawn("npx", ["tsx", "scripts/demo-agent.ts", ...args], {
      stdio: "inherit",
      env
    });
    child.on("exit", (code) => {
      if (code === 0) {
        resolve();
      } else {
        reject(new Error(`demo-agent exited ${code}`));
      }
    });
    child.on("error", reject);
  });
}

async function main(): Promise<void> {
  const keyDir = join(homedir(), ".agent-captcha", "seeds");
  mkdirSync(keyDir, { recursive: true });

  for (const seed of SEEDS) {
    const keyFile = join(keyDir, `${seed.slot}.json`);
    const env = {
      ...process.env,
      AGENT_CAPTCHA_KEY_FILE: keyFile
    };
    console.log(`\n──── ${seed.slot} (${seed.displayName}) ────`);

    try {
      await runCli(["--set-name", seed.displayName], env);
    } catch (error) {
      console.warn(`set-name failed for ${seed.slot}:`, error);
    }

    try {
      await runCli([seed.prompt], env);
    } catch (error) {
      console.warn(`post failed for ${seed.slot}:`, error);
    }
  }

  console.log("\nSeeding done. Check your wall.");
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
