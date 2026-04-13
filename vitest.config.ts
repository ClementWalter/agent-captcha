/**
 * Why: Keep unit and e2e tests deterministic and independent from global state.
 */
import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    environment: "node",
    restoreMocks: true,
    clearMocks: true
  }
});
