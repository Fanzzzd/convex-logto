import { tanstackStart } from "@tanstack/react-start/plugin/vite";
import react from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";
import mdx from "fumadocs-mdx/vite";
import { nitro } from "nitro/vite";
import { defineConfig } from "vite";
import tsconfigPaths from "vite-tsconfig-paths";

export default defineConfig({
  server: {
    port: 3000,
  },
  resolve: {
    alias: {
      // tslib ships a CJS default that breaks ESM interop during SSR/prerender
      // (e.g. Orama search emits `Cannot destructure '__extends'`). Pin its ESM build.
      tslib: "tslib/tslib.es6.js",
    },
  },
  plugins: [
    mdx(),
    tailwindcss(),
    tsconfigPaths(),
    tanstackStart({
      prerender: {
        enabled: true,
        crawlLinks: true,
      },
    }),
    react(),
    // see https://tanstack.com/start/latest/docs/framework/react/guide/hosting
    // "vercel" preset emits .vercel/output so Vercel auto-detects and deploys.
    nitro({ preset: "vercel" }),
  ],
});
