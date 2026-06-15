// Protected pathless layout. Two layers, because auth is a *client* fact (the token
// lives in the browser, so the server can't know it):
//   - `beforeLoad` redirects an unauthenticated user to /signin. It reads auth from
//     the router context's mutable `authHolder`, which the AuthBoundary keeps pointed
//     at the live useLogtoAuth() result and re-runs (via router.invalidate()) when
//     auth settles — the Start analog of the SPA's <RouterProvider context={{ auth }}>.
//   - `AuthedLayout` renders protected children only once the client confirms an
//     authenticated session, so an unauthenticated SSR request never server-renders
//     the protected component before the client redirect runs.
import { createFileRoute, Outlet, redirect } from "@tanstack/react-router";
import { useLogtoAuth } from "convex-logto/react";

function AuthedLayout() {
  const { isAuthenticated } = useLogtoAuth();
  // Not authenticated yet (SSR, first paint, or signed out): show the pending UI.
  // beforeLoad redirects the genuinely-unauthenticated once auth settles.
  return isAuthenticated ? <Outlet /> : <p>Checking access…</p>;
}

export const Route = createFileRoute("/_authed")({
  beforeLoad: ({ context }) => {
    const auth = context.authHolder.auth;
    // undefined during SSR / before convex-logto mounts, or still settling —
    // don't redirect yet; the invalidate() after auth settles re-runs this.
    if (!auth || auth.isLoading) return;
    if (!auth.isAuthenticated) throw redirect({ to: "/signin" });
  },
  pendingComponent: () => <p>Checking access…</p>,
  component: AuthedLayout,
});
