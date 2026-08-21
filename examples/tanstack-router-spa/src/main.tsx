import { StrictMode, useEffect } from "react";
import { createRoot } from "react-dom/client";
import { ConvexReactClient } from "convex/react";
import { ConvexLogtoProvider, useLogtoAuth } from "convex-logto/react";
import { RouterProvider } from "@tanstack/react-router";
import { router } from "./router";

const convex = new ConvexReactClient(import.meta.env.VITE_CONVEX_URL as string, {
  // Convex otherwise refetches a fresh token the instant it confirms the cached
  // one, which costs a Logto refresh grant on every page load — and in session
  // mode a session-token rotation with it. Experimental in convex@1.44.
  initialAuthTokenReuse: true,
});

// Inside <ConvexLogtoProvider> so useLogtoAuth() has its context.
function RouterWithAuth() {
  const auth = useLogtoAuth();
  // beforeLoad only runs on navigation — re-run the guards when auth changes.
  useEffect(() => {
    router.invalidate();
  }, [auth.isLoading, auth.isAuthenticated]);
  return <RouterProvider router={router} context={{ auth }} />;
}

createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <ConvexLogtoProvider
      client={convex}
      // Static public config (endpoint + app id are not secrets): no config
      // round-trip before sign-in is interactive.
      config={{
        endpoint: import.meta.env.VITE_LOGTO_ENDPOINT as string,
        appId: import.meta.env.VITE_LOGTO_APP_ID as string,
      }}
      // Soft-navigate via the router instead of a hard redirect after sign-in.
      navigate={(to) => void router.navigate({ to })}
    >
      <RouterWithAuth />
    </ConvexLogtoProvider>
  </StrictMode>,
);
