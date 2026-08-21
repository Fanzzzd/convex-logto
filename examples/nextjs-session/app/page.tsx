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
 * over". Revocation is enforced where it always is: inside the function being
 * called. A cookie whose token expired is gone with it, so the worst case is an
 * unauthenticated first paint, not a stale authenticated one.
 */
export default async function Home() {
  const token = readLogtoIdTokenCookie(await cookies());
  const preloadedMe = await preloadQuery(api.me.me, {}, token ? { token } : {});
  return <Dashboard preloadedMe={preloadedMe} serverSawToken={token !== null} />;
}
