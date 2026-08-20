// The cookie transport's server half, in one module so the route handler and
// middleware share exactly one configuration.
//
// This runs in Node (Next's server), not in Convex, so it reaches the
// deployment over HTTP with an admin-free client — the actions it calls are
// public, and the session cookie is what authenticates the caller.
import { ConvexHttpClient } from "convex/browser";
import { createLogtoSessionCookieHandler } from "convex-logto";
import { api } from "@/convex/_generated/api";

const client = new ConvexHttpClient(process.env.NEXT_PUBLIC_CONVEX_URL!);

export const logtoCookieHandler = createLogtoSessionCookieHandler({
  sessionApi: api.auth,
  action: (reference, args) => client.action(reference, args),
  // Exact origins only — never a wildcard. In a real deployment this is your
  // app's origin, not localhost.
  allowedOrigins: [
    process.env.NEXT_PUBLIC_APP_ORIGIN ?? "http://localhost:3000",
  ],
  basePath: "/api/logto",
  // The opt-in companion cookie that makes server rendering possible: the ID
  // token, HttpOnly, with Max-Age from its own `exp`. Nothing is minted and
  // nothing is rotated by reading it, which is the whole point — a Server
  // Component cannot set cookies, so it must not be handed anything that
  // rotates. See docs/adr/0002-token-custody.md for the trade-off.
  idTokenCookie: true,
});
