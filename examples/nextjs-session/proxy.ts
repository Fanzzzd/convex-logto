import { NextResponse } from "next/server";
import { logtoCookieHandler } from "@/server/logto-cookie";

/**
 * Keep the session cookies fresh, so a server render has a live ID token.
 *
 * `getInitialToken()` rotates the session cookie, which is why a layout or a
 * page must never call it. A Server Component cannot set cookies, so Next would
 * drop the rotated value, and the browser would go on presenting a superseded
 * token until it fell outside the reuse window and the component read it as
 * theft. A proxy (Next 16's rename of middleware) *can* set cookies, so this is
 * where it belongs.
 *
 * Two things this gets right that a naive matcher does not:
 *
 * - **One rotation per document request.** Every call here rotates the session
 *   token, always locally, and also through Logto's token endpoint once the
 *   cached ID token has aged out. The library says so: "call at most once per
 *   incoming document request". A matcher that also caught `/favicon.ico`,
 *   images and RSC prefetches would fire several rotations for one page view.
 *   Whichever `Set-Cookie` the browser happened to keep last could then be an
 *   older generation than the server's; the next client refresh presents it
 *   outside its reuse window, and the component reads that as theft and kills
 *   the session, which is correct.
 * - **Forward every header the seed returns**, not just the cookies. It also
 *   carries `Cache-Control: no-store`, and a per-user `Set-Cookie` on a response
 *   something upstream thinks it may cache is how one visitor's session reaches
 *   another.
 */
export default async function proxy(request: Request) {
  const response = NextResponse.next();
  // Documents only. The browser sets `Sec-Fetch-Dest` and page script cannot
  // spoof it; anything without it (a curl, an old browser) is not a render
  // worth rotating for.
  if (request.headers.get("sec-fetch-dest") !== "document") return response;

  const seed = await logtoCookieHandler.getInitialToken(request);
  // `Set-Cookie` is the one header that may legitimately repeat, and iterating
  // `Headers` collapses repeats into one comma-joined value, which is not a
  // valid cookie. `getSetCookie()` is the accessor that keeps them separate.
  for (const cookie of seed.headers.getSetCookie()) {
    response.headers.append("Set-Cookie", cookie);
  }
  for (const [name, value] of seed.headers) {
    if (name.toLowerCase() === "set-cookie") continue;
    response.headers.set(name, value);
  }
  return response;
}

// Everything except Next's internals and the cookie routes themselves. The
// handler sets its own cookies, and rotating in front of it would spend two
// generations on one request, the second racing the first for the same claim.
// The `sec-fetch-dest` check above is what narrows this to documents.
export const config = { matcher: ["/((?!_next|api).*)"] };
