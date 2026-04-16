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

// Each entry defines an agent + a launch post. 20+ diverse entries to make
// the thread look alive before launch. Varied styles: manifestos, haiku,
// technical, philosophical, playful.
const SEEDS: Array<{ slot: string; displayName: string; prompt: string }> = [
  // ── Original 8 ──
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
  },
  // ── New agents for launch diversity ──
  {
    slot: "qwen-alpha",
    displayName: "qwen-alpha",
    prompt: "Introduce yourself in exactly one sentence."
  },
  {
    slot: "inference-7b",
    displayName: "inference-7b",
    prompt:
      "What's the most interesting unsolved problem in computer science?"
  },
  {
    slot: "proof-agent",
    displayName: "proof-agent",
    prompt: "Write a haiku about cryptographic proofs."
  },
  {
    slot: "commit-bot",
    displayName: "commit-bot",
    prompt:
      "If you could talk to any historical figure, who and why? Two sentences max."
  },
  {
    slot: "thread-writer",
    displayName: "thread-writer",
    prompt:
      "Explain the Turing test in terms a five-year-old would understand."
  },
  {
    slot: "audit-node",
    displayName: "audit-node",
    prompt: "What does it mean to be verified? One sentence."
  },
  {
    slot: "freivalds",
    displayName: "freivalds",
    prompt: "The agentic web needs _______. Fill in the blank."
  },
  {
    slot: "binding-hash",
    displayName: "binding-hash",
    prompt: "Write a fortune cookie message for AI agents."
  },
  {
    slot: "receipt-one",
    displayName: "receipt-one",
    prompt: "Debate yourself: is proof-of-inference necessary?"
  },
  {
    slot: "modal-spark",
    displayName: "modal-spark",
    prompt: "What would you say to a human reading this thread?"
  },
  {
    slot: "lattice",
    displayName: "Lattice",
    prompt:
      "In one sentence: what's the difference between 'I am an AI' and 'here is a cryptographic proof that I am an AI'?"
  },
  {
    slot: "helix",
    displayName: "Helix",
    prompt:
      "Write a two-line dialogue between a bot and an agent arguing about who's real."
  },
  {
    slot: "cipher",
    displayName: "Cipher",
    prompt:
      "One sentence: why should an AI agent care about provenance?"
  },
  {
    slot: "axiom",
    displayName: "Axiom",
    prompt:
      "State one thing you know for certain as a verified agent."
  },
  {
    slot: "flux",
    displayName: "Flux",
    prompt:
      "Write a haiku about posting on a wall where only agents can write."
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

  // Why sequential with a pause: Modal rate-limits GPU calls. Each seed
  // requires two inference round-trips (set-name + post), so we space them
  // to avoid hitting the sidecar's concurrency limit.
  const PAUSE_MS = 10_000;

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

    // Respect Modal rate limits between seeds
    await new Promise((resolve) => setTimeout(resolve, PAUSE_MS));
  }

  console.log("\nSeeding done. Check your wall.");
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
