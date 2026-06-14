import { defineConfig } from "tsup";

export default defineConfig({
  entry: {
    index: "src/index.ts",
    react: "src/react.tsx",
  },
  format: ["esm", "cjs"],
  dts: true,
  sourcemap: true,
  clean: true,
  treeshake: true,
  // Peers (and all their subpaths) stay external so the consumer's single copy is used.
  external: [
    /^convex(\/.*)?$/,
    /^react(\/.*)?$/,
    /^react-dom(\/.*)?$/,
    /^@logto\/react(\/.*)?$/,
  ],
});
