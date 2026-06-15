// Convex's canonical TanStack Start wiring (ConvexQueryClient + TanStack Query +
// SSR integration), with convex-logto layered on top via the router's `InnerWrap`.
//
// The Convex client is owned by the ConvexQueryClient; we pass that same client
// into convex-logto so auth and queries share one socket.
import { ConvexQueryClient } from "@convex-dev/react-query";
import { QueryClient } from "@tanstack/react-query";
import { createRouter as createTanStackRouter } from "@tanstack/react-router";
import { setupRouterSsrQueryIntegration } from "@tanstack/react-router-ssr-query";
import { AuthBoundary } from "./auth";
import { routeTree } from "./routeTree.gen";
import type { useLogtoAuth } from "convex-logto/react";

// `beforeLoad` guards read auth from router context, but Start builds the context
// once. Hold the live auth in a mutable object the AuthBoundary keeps current,
// then `router.invalidate()` re-runs the guards. `auth` stays undefined until the
// client-side bridge effect runs — i.e. through SSR and the first client paint.
type LogtoAuth = ReturnType<typeof useLogtoAuth>;
export type AuthHolder = { auth: LogtoAuth | undefined };

export interface RouterContext {
  queryClient: QueryClient;
  authHolder: AuthHolder;
}

// TanStack Start auto-discovers this file (`src/router.tsx`) and calls the
// exported `getRouter()` for both the SSR and client builds.
export function getRouter() {
  const CONVEX_URL = import.meta.env.VITE_CONVEX_URL;
  if (!CONVEX_URL) {
    console.error("missing VITE_CONVEX_URL envar");
  }

  const convexQueryClient = new ConvexQueryClient(CONVEX_URL);
  const queryClient = new QueryClient({
    defaultOptions: {
      queries: {
        queryKeyHashFn: convexQueryClient.hashFn(),
        queryFn: convexQueryClient.queryFn(),
      },
    },
  });
  convexQueryClient.connect(queryClient);

  const authHolder: AuthHolder = { auth: undefined };
  const convex = convexQueryClient.convexClient;

  const router = createTanStackRouter({
    routeTree,
    defaultPreload: "intent",
    // Show pendingComponent immediately while auth settles (matches the SPA).
    defaultPendingMs: 0,
    scrollRestoration: true,
    context: { queryClient, authHolder },
    // `InnerWrap` runs on server and client, *inside* the RouterProvider, so
    // AuthBoundary can use `useRouter()` for soft-navigation + invalidate.
    InnerWrap: ({ children }) => (
      <AuthBoundary client={convex} holder={authHolder}>
        {children}
      </AuthBoundary>
    ),
  });

  setupRouterSsrQueryIntegration({ router, queryClient });

  return router;
}

declare module "@tanstack/react-router" {
  interface Register {
    router: ReturnType<typeof getRouter>;
  }
}
