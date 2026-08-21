import { readLogtoIdTokenCookie } from "convex-logto";
import { preloadQuery } from "convex/nextjs";
import { cookies } from "next/headers";
import { api } from "@/convex/_generated/api";
import { Dashboard } from "./dashboard";

/**
 * Rendered on the server, with the caller's identity.
 *
 * The token here is a bearer Convex validates — it proves nothing on its own,
 * and `null` just means "render the signed-out view and let the client take
 * over".
 *
 * What it is *not* is proof the session is still alive. An ID token stays
 * cryptographically valid until it expires, so between a revocation elsewhere
 * and this browser's next `/token` call, this render can still paint the
 * signed-in shell. `me` returns identity the token already carries, so that
 * costs nothing beyond a shell the client corrects on hydration. A query that
 * returns *data* must not rely on the token alone: enforce revocation inside the
 * function, the way `convex/me.ts`'s `sensitive` does with
 * `assertSubjectHasActiveSession`.
 */
export default async function Home() {
  const token = readLogtoIdTokenCookie(await cookies());
  const preloadedMe = await preloadQuery(api.me.me, {}, token ? { token } : {});
  return <Dashboard preloadedMe={preloadedMe} serverSawToken={token !== null} />;
}
