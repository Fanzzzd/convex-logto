import { tanstackStart } from "@tanstack/react-start/plugin/vite";
import react from "@vitejs/plugin-react";
import { defineConfig } from "vite";

export default defineConfig({
  // TanStack Start's dev server defaults to port 3000 — match the Logto redirect
  // URIs (`http://localhost:3000/callback` and post-sign-out `http://localhost:3000`).
  server: { port: 3000 },
  plugins: [tanstackStart(), react()],
});
