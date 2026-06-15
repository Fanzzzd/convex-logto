// convex-logto's provider is SSR-safe: children render under Convex's <AuthLoading>
// while config loads, and nothing touches `window` on the server. So the boundary is
// just the provider plus a bridge that re-runs the route guards when auth changes.
import { useEffect } from "react";
import type { ConvexReactClient } from "convex/react";
import { ConvexLogtoProvider, useLogtoAuth } from "convex-logto/react";
import { type AnyRouter, useRouter } from "@tanstack/react-router";
import { api } from "../convex/_generated/api";
import type { AuthHolder } from "./router";

// `beforeLoad` guards run only on navigation. Start builds the router context once,
// so we keep a mutable holder pointed at the live auth and invalidate to re-run them.
function RouterAuthBridge({
  holder,
  router,
}: {
  holder: AuthHolder;
  router: AnyRouter;
}) {
  const auth = useLogtoAuth();
  // `auth` is memoized, so its identity already changes whenever isAuthenticated /
  // isLoading / user does — depending on it alone is enough (and listing the
  // primitives too would be redundant).
  useEffect(() => {
    holder.auth = auth;
    void router.invalidate();
  }, [holder, router, auth]);
  return null;
}

export function AuthBoundary({
  client,
  holder,
  children,
}: {
  client: ConvexReactClient;
  holder: AuthHolder;
  children: React.ReactNode;
}) {
  // `useRouter()` works inside the router's `InnerWrap`, on both server and client.
  const router = useRouter();
  return (
    <ConvexLogtoProvider
      client={client}
      configQuery={api.logto.config}
      // Soft-navigate after sign-in instead of a hard redirect.
      navigate={(to) => void router.navigate({ to })}
    >
      <RouterAuthBridge holder={holder} router={router} />
      {children}
    </ConvexLogtoProvider>
  );
}
