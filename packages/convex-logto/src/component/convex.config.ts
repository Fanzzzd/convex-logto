import { defineComponent } from "convex/server";

/**
 * The convex-logto session component. It holds Logto refresh tokens
 * server-side (confidential client), rotates application session tokens, and
 * pushes session revocation reactively. Install in `convex/convex.config.ts`:
 *
 * @example
 * import { defineApp } from "convex/server";
 * import logto from "convex-logto/convex.config";
 * const app = defineApp();
 * app.use(logto);
 * export default app;
 */
export default defineComponent("logto");
