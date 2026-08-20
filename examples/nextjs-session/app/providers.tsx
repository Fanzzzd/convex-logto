"use client";

// The provider uses hooks and `window`, so it is the client boundary. Note what
// is *not* here: no Logto SDK, no Logto endpoint, no app id. Session mode keeps
// every Logto value on the Convex deployment, so the bundle carries none of it.
import { ConvexReactClient } from "convex/react";
import { ConvexLogtoSessionProvider } from "convex-logto/react-session";
import { useRouter } from "next/navigation";
import { api } from "@/convex/_generated/api";

const convex = new ConvexReactClient(process.env.NEXT_PUBLIC_CONVEX_URL!);

export function Providers({
  children,
  initialToken,
}: {
  children: React.ReactNode;
  initialToken?: string;
}) {
  const router = useRouter();
  return (
    <ConvexLogtoSessionProvider
      client={convex}
      sessionApi={api.auth}
      // With the cookie transport the session token never enters JavaScript at
      // all: it lives in an HttpOnly cookie and this same-origin route proxies
      // to the component.
      cookieTransport={{ endpoint: "/api/logto" }}
      // The token the server already rendered with. Without it the client
      // starts in `restoring` and the first paint disagrees with the server's.
      initialToken={initialToken}
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
