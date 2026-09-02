// The cookie transport's server half, in one module so the route handler and
// the proxy share exactly one configuration.
//
// This runs in Next's server, not in Convex, so it reaches the deployment over
// HTTP. The actions it calls are public; the session cookie is what
// authenticates the caller.
import { ConvexHttpClient } from "convex/browser";
import { createLogtoSessionCookieHandler } from "convex-logto";
import { api } from "@/convex/_generated/api";

const client = new ConvexHttpClient(process.env.NEXT_PUBLIC_CONVEX_URL!);

export const logtoCookieHandler = createLogtoSessionCookieHandler({
  sessionApi: api.auth,
  action: (reference, args) => client.action(reference, args),
  // Deliberately *not* a `NEXT_PUBLIC_` name. Next inlines those at build time,
  // so a `NEXT_PUBLIC_APP_ORIGIN` set in the production environment would lose
  // to whatever the build machine had, and this handler would answer every
  // request `403 Origin is not allowed`, with sign-in failing for everyone and
  // nothing in the build to explain it. The handler reads a plain server-side
  // variable when it runs.
  //
  // Exact origins only; the handler rejects wildcards.
  allowedOrigins: [process.env.APP_ORIGIN ?? "http://localhost:3000"],
  basePath: "/api/logto",
  // The opt-in companion cookie that makes server rendering possible. It holds
  // the ID token, HttpOnly, with Max-Age from its own `exp`. Reading it mints
  // nothing and rotates nothing, which is the point. A Server Component cannot
  // set cookies, so it must not be handed anything that rotates. See
  // docs/adr/0002-token-custody.md for the custody trade-off.
  idTokenCookie: true,
});
