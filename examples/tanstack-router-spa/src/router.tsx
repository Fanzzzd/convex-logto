import {
  createRootRouteWithContext,
  createRoute,
  createRouter,
  redirect,
  Link,
  Outlet,
} from "@tanstack/react-router";
import type { useLogtoAuth } from "convex-logto/react";
import { AuthButton } from "./AuthButton";
import { DeclarativeGate } from "./DeclarativeGate";
import { SignInPage } from "./SignInPage";
import { Dashboard } from "./Dashboard";
import { AdminPage } from "./AdminPage";

// Auth lives in router context so `beforeLoad` guards can read it outside render.
export type RouterAuthContext = { auth: ReturnType<typeof useLogtoAuth> };

const rootRoute = createRootRouteWithContext<RouterAuthContext>()({
  component: RootLayout,
});

function RootLayout() {
  return (
    <div style={{ fontFamily: "system-ui", padding: 24, maxWidth: 720 }}>
      <nav style={{ display: "flex", gap: 12, alignItems: "center" }}>
        <Link to="/">Home</Link>
        <Link to="/dashboard">Dashboard (protected)</Link>
        <Link to="/admin">Admin (admin-only)</Link>
        <span style={{ marginLeft: "auto" }}>
          <AuthButton />
        </span>
      </nav>
      <main style={{ paddingTop: 16 }}>
        <Outlet />
      </main>
    </div>
  );
}

const indexRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/",
  component: () => (
    <section>
      <h1>convex-logto + TanStack Router</h1>
      <DeclarativeGate />
    </section>
  ),
});

const signinRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/signin",
  component: SignInPage,
});

// OIDC callback. The provider finishes the code exchange; this just renders.
const callbackRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/callback",
  component: () => <p>Finishing sign in…</p>,
});

// Protected layout: its `beforeLoad` redirects unauthenticated users to /signin.
const authedRoute = createRoute({
  getParentRoute: () => rootRoute,
  id: "_authed",
  beforeLoad: ({ context }) => {
    if (context.auth.isLoading) return; // still settling — don't redirect yet
    if (!context.auth.isAuthenticated) throw redirect({ to: "/signin" });
  },
  pendingComponent: () => <p>Checking access…</p>,
  component: () => <Outlet />,
});

const dashboardRoute = createRoute({
  getParentRoute: () => authedRoute,
  path: "/dashboard",
  component: Dashboard,
});

// Also behind `_authed` (must be signed in). The role check (authz) happens in
// the component + on the server; the guard here only enforces authentication.
const adminRoute = createRoute({
  getParentRoute: () => authedRoute,
  path: "/admin",
  component: AdminPage,
});

export const router = createRouter({
  routeTree: rootRoute.addChildren([
    indexRoute,
    signinRoute,
    callbackRoute,
    authedRoute.addChildren([dashboardRoute, adminRoute]),
  ]),
  // Real auth is injected via <RouterProvider context>; this only satisfies the type.
  context: { auth: undefined! },
  // Show pendingComponent immediately while auth settles.
  defaultPendingMs: 0,
});

declare module "@tanstack/react-router" {
  interface Register {
    router: typeof router;
  }
}
