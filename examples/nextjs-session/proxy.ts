import { NextResponse } from "next/server";
import { logtoCookieHandler } from "@/server/logto-cookie";

/**
 * Keep the session cookies fresh, so a server render has a live ID token.
 *
 * `getInitialToken()` rotates the session cookie, which is why it must never be
 * called from a layout or a page: a Server Component cannot set cookies, the
 * rotated value would be dropped, and the browser would go on presenting a
 * superseded token until it fell outside the reuse window and was read as
 * theft. A proxy (Next 16's rename of middleware) *can* set cookies, so this is
 * where it belongs.
 *
 * Two things this gets right that a naive matcher does not:
 *
 * - **One rotation per document request.** Every call here is a real Logto
 *   token-endpoint round trip that rotates the session token, and the library
 *   says so: "call at most once per incoming document request". A matcher that
 *   also caught `/favicon.ico`, images and RSC prefetches would fire several
 *   rotations for one page view, and whichever `Set-Cookie` the browser happened
 *   to keep last could be an older generation than the server's — which the
 *   next client refresh presents outside its reuse window, and the component
 *   correctly reads as theft and kills the session.
 * - **Forward every header the seed returns**, not just the cookies. It also
 *   carries `Cache-Control: no-store`, and a per-user `Set-Cookie` on a response
 *   something upstream thinks it may cache is how one visitor's session reaches
 *   another.
 */
export default async function proxy(request: Request) {
  const response = NextResponse.next();
  // Documents only. `Sec-Fetch-Dest` is set by the browser and cannot be
  // spoofed by page script; anything without it (a curl, an old browser) is not
  // a render worth rotating for.
  if (request.headers.get("sec-fetch-dest") !== "document") return response;

  const seed = await logtoCookieHandler.getInitialToken(request);
  // `Set-Cookie` is the one header that may legitimately repeat, and iterating
  // `Headers` collapses repeats into one comma-joined value — which is not a
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

// Everything except Next's internals and the cookie routes themselves — the
// handler sets its own cookies, and rotating in front of it would spend two
// generations on one request, the second racing the first for the same claim.
// The `sec-fetch-dest` check above is what actually narrows this to documents.
export const config = { matcher: ["/((?!_next|api).*)"] };
