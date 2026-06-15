import { defineConfig } from "tsup";

// Peers (and all their subpaths) stay external so the consumer's single copy is used.
const external = [
  /^convex(\/.*)?$/,
  /^react(\/.*)?$/,
  /^react-dom(\/.*)?$/,
  /^@logto\/react(\/.*)?$/,
  /^@logto\/rn(\/.*)?$/,
  /^react-native(\/.*)?$/,
];

const shared = {
  dts: true,
  sourcemap: true,
  treeshake: true,
  external,
} as const;

export default defineConfig([
  // Root entry is dual ESM+CJS.
  {
    ...shared,
    entry: { index: "src/index.ts" },
    format: ["esm", "cjs"],
    clean: true,
  },
  // `@logto/react@4` is ESM-only, so `./react` is ESM-only too: emitting a
  // `react.cjs` that `require("@logto/react")` would be a runtime trap.
  {
    ...shared,
    entry: { react: "src/react.tsx" },
    format: ["esm"],
  },
  // `@logto/rn` is ESM-only (and React Native bundlers are ESM-first), so the
  // native entry is ESM-only too.
  {
    ...shared,
    entry: { native: "src/native.tsx" },
    format: ["esm"],
  },
]);
