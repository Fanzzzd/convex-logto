// The SSR document shell + the nav layout. This renders on the server
// (unauthenticated) and hydrates on the client where auth settles.
import {
  createRootRouteWithContext,
  HeadContent,
  Link,
  Outlet,
  Scripts,
} from "@tanstack/react-router";
import type { RouterContext } from "../router";
import { AuthButton } from "../AuthButton";

export const Route = createRootRouteWithContext<RouterContext>()({
  head: () => ({
    meta: [
      { charSet: "utf-8" },
      { name: "viewport", content: "width=device-width, initial-scale=1" },
      { title: "convex-logto + TanStack Start" },
    ],
  }),
  component: RootComponent,
});

function RootComponent() {
  return (
    <RootDocument>
      <div style={{ fontFamily: "system-ui", padding: 24, maxWidth: 720 }}>
        <nav style={{ display: "flex", gap: 12, alignItems: "center" }}>
          <Link to="/">Home</Link>
          <Link to="/dashboard">Dashboard (protected)</Link>
          <span style={{ marginLeft: "auto" }}>
            <AuthButton />
          </span>
        </nav>
        <main style={{ paddingTop: 16 }}>
          <Outlet />
        </main>
      </div>
    </RootDocument>
  );
}

function RootDocument({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <head>
        <HeadContent />
      </head>
      <body>
        {children}
        <Scripts />
      </body>
    </html>
  );
}
