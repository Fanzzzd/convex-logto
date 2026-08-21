"use client";

// The provider uses hooks and `window`, so it is the client boundary. Note what
// is *not* here: no Logto SDK, no Logto endpoint, no app id. Session mode keeps
// every Logto value on the Convex deployment, so the bundle carries none of it.
import { ConvexReactClient } from "convex/react";
import { ConvexLogtoSessionProvider } from "convex-logto/react-session";
import { useRouter } from "next/navigation";
import { api } from "@/convex/_generated/api";

const convex = new ConvexReactClient(process.env.NEXT_PUBLIC_CONVEX_URL!, {
  // Convex otherwise refetches a fresh token the instant it confirms the cached
  // one, which costs a Logto refresh grant on every page load — and in session
  // mode a session-token rotation with it. Experimental in convex@1.44.
  initialAuthTokenReuse: true,
});

/**
 * No `initialToken` here, deliberately.
 *
 * The provider takes an SSR seed, but it takes it as a *pair* —
 * `initialToken` **and** `initialSessionId`, or neither; passing one alone
 * throws. The session id comes only from `getInitialToken()`, which rotates the
 * session cookie and therefore belongs in the proxy, not in a render. So in the
 * App Router there is no supported way to hand a page's render the paired seed,
 * and the honest wiring is the one below: the *server* renders authenticated
 * content from the ID-token cookie (see `app/page.tsx`), and the client
 * establishes its own auth on mount.
 */
export function Providers({ children }: { children: React.ReactNode }) {
  const router = useRouter();
  return (
    <ConvexLogtoSessionProvider
      client={convex}
      sessionApi={api.auth}
      // With the cookie transport the session token never enters JavaScript at
      // all: it lives in an HttpOnly cookie and this same-origin route proxies
      // to the component.
      cookieTransport={{ endpoint: "/api/logto" }}
      clientDescriptor={{ platform: "web", browser: "this browser" }}
      navigate={(to) => router.replace(to)}
      onAuthError={(error) => {
        console.error("auth error", error);
      }}
    >
      {children}
    </ConvexLogtoSessionProvider>
  );
}
