import { defineConfig } from "tsup";

// Peers (and all their subpaths) stay external so the consumer's single copy is used.
const external = [
  /^convex(\/.*)?$/,
  /^react(\/.*)?$/,
  /^react-dom(\/.*)?$/,
  /^@logto\/react(\/.*)?$/,
  /^@logto\/rn(\/.*)?$/,
  /^expo-secure-store(\/.*)?$/,
  /^expo-web-browser(\/.*)?$/,
  /^react-native(\/.*)?$/,
];

// Never set `clean` on any config here. These configs run concurrently, and
// tsup's dts worker cleans `**/*.d.{ts,mts,cts}` across the whole outDir at
// rollup `buildStart` with no negation — so one config's cleaner silently
// deletes declarations its siblings have already emitted (egoist/tsup#1270).
// The build script deletes `dist` once, up front, instead.
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
  // Session mode on Expo uses ESM-only Expo modules and the same ESM-first
  // React Native toolchain as the bridge-mode native entry.
  {
    ...shared,
    entry: { "native-session": "src/native-session.tsx" },
    format: ["esm"],
  },
  // Session mode's React entry. No Logto SDK dependency; ESM-only like the
  // other React entries. (The session *component* itself is built by
  // `tsc -p tsconfig.component.json` into dist/component/, not by tsup — the
  // Convex CLI needs its file structure preserved.)
  {
    ...shared,
    entry: { "react-session": "src/react-session.tsx" },
    format: ["esm"],
  },
]);
