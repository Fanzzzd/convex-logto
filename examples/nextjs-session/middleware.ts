import { NextResponse } from "next/server";
import { logtoCookieHandler } from "@/server/logto-cookie";

/**
 * Keep the cookies fresh on navigations, so server renders have a live ID token.
 *
 * `getInitialToken()` rotates the session cookie, which is why it must never be
 * called from a layout or a page: a Server Component cannot set cookies, the
 * rotated value would be dropped, and the browser would go on presenting a
 * superseded token until it fell outside the reuse window and was read as
 * theft. Middleware *can* set cookies, so this is where it belongs.
 *
 * One honest limitation: cookies set here land on the *response*, so this
 * render still reads what the browser sent. That is fine — an ID token lives an
 * hour and this keeps it from ever getting close to the end of that — but it
 * does mean the fresh token is for the next navigation, not this one.
 */
export async function middleware(request: Request) {
  const response = NextResponse.next();
  try {
    const seed = await logtoCookieHandler.getInitialToken(request);
    for (const cookie of seed.headers.getSetCookie()) {
      response.headers.append("Set-Cookie", cookie);
    }
  } catch {
    // Defensive: the handler answers an empty seed rather than throwing for the
    // cases it expects (signed out, a concurrent refresh already holding the
    // claim). Turning an unexpected failure into a broken navigation would
    // trade a render optimisation for an outage — the client provider restores
    // auth on its own either way.
  }
  return response;
}

// Skip Next's internals and the cookie routes themselves: the handler sets its
// own cookies, and running this in front of it would rotate twice for one
// request — the second rotation racing the first for the same claim.
export const config = { matcher: ["/((?!_next|api).*)"] };
