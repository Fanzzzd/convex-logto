import { defineConfig } from "vitest/config";

// convex-test runs your Convex functions in-process (no backend) using the
// edge-runtime environment. See convex/rbac.test.ts.
export default defineConfig({
  test: {
    environment: "edge-runtime",
    server: { deps: { inline: ["convex-test"] } },
  },
});
