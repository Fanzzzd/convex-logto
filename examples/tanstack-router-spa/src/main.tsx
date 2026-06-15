import { StrictMode, useEffect } from "react";
import { createRoot } from "react-dom/client";
import { ConvexReactClient } from "convex/react";
import { ConvexLogtoProvider, useLogtoAuth } from "convex-logto/react";
import { RouterProvider } from "@tanstack/react-router";
import { api } from "../convex/_generated/api";
import { router } from "./router";

const convex = new ConvexReactClient(import.meta.env.VITE_CONVEX_URL as string);

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
      configQuery={api.logto.config}
      // Soft-navigate via the router instead of a hard redirect after sign-in.
      navigate={(to) => void router.navigate({ to })}
    >
      <RouterWithAuth />
    </ConvexLogtoProvider>
  </StrictMode>,
);
