# Sandbox runtime for <Sandbox> tasks.
# Includes: bun, git, node, smithers-orchestrator, claude-code CLI.
# Pass ANTHROPIC_API_KEY via the Sandbox `env` prop at runtime.
FROM oven/bun:1-debian

SHELL ["/bin/bash", "-o", "pipefail", "-c"]

# hadolint ignore=DL3008
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        git \
        ca-certificates \
        curl \
    && rm -rf /var/lib/apt/lists/*

# Node is needed for npm-distributed agent CLIs.
# hadolint ignore=DL3008
RUN curl -fsSL https://deb.nodesource.com/setup_20.x | bash - \
    && apt-get install -y --no-install-recommends nodejs \
    && rm -rf /var/lib/apt/lists/*

# Smithers CLI + agent CLI. Add @openai/codex or @google/gemini-cli here
# if your `agents.smart` fallback chain needs them.
RUN bun install -g smithers-orchestrator \
    && npm install -g @anthropic-ai/claude-code@2.1.112

RUN useradd --create-home --shell /bin/bash sandbox \
    && mkdir -p /workspace && chown sandbox:sandbox /workspace

WORKDIR /workspace

HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD bun --version || exit 1

USER sandbox
