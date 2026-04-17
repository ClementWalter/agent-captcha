// smithers-source: generated
import {
  ClaudeCodeAgent,
  CodexAgent,
  type AgentLike,
} from "smithers-orchestrator";

// maxOutputBytes: claude --output-format stream-json emits a lot on long
// runs; the default 200KB cap truncates the trailing ```json fence and the
// task output fails schema validation. Bump well past any realistic run.
const MAX_OUTPUT_BYTES = 50_000_000;

export const providers = {
  claude: new ClaudeCodeAgent({
    model: "claude-opus-4-6",
    maxOutputBytes: MAX_OUTPUT_BYTES,
  }),
  codex: new CodexAgent({
    model: "gpt-5.3-codex",
    skipGitRepoCheck: true,
    maxOutputBytes: MAX_OUTPUT_BYTES,
  }),
  claudeSonnet: new ClaudeCodeAgent({
    model: "claude-sonnet-4-6",
    maxOutputBytes: MAX_OUTPUT_BYTES,
  }),
} as const;

export const agents = {
  cheapFast: [providers.claudeSonnet],
  smart: [providers.codex, providers.claude],
  smartTool: [providers.claude, providers.codex],
} as const satisfies Record<string, AgentLike[]>;
