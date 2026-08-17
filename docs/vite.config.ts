import { tanstackStart } from "@tanstack/react-start/plugin/vite";
import react from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";
import mdx from "fumadocs-mdx/vite";
import { nitro } from "nitro/vite";
import { defineConfig } from "vite";

export default defineConfig({
  build: {
    rolldownOptions: {
      output: {
        codeSplitting: {
          groups: [
            {
              name: "react-vendor",
              test: /node_modules[\\/](react|react-dom|scheduler)[\\/]/,
              priority: 30,
            },
            {
              name: "tanstack-vendor",
              test: /node_modules[\\/]@tanstack[\\/]/,
              priority: 20,
            },
            {
              name: "fumadocs-vendor",
              test: /node_modules[\\/](fumadocs-core|fumadocs-ui)[\\/]/,
              priority: 10,
            },
          ],
        },
        // Manual groups can otherwise move side-effectful framework modules
        // ahead of their dependencies.
        strictExecutionOrder: true,
      },
    },
  },
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
