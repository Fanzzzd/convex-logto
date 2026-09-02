import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { ConvexReactClient } from "convex/react";
import { ConvexLogtoProvider } from "convex-logto/react";
import { App } from "./App";

const convex = new ConvexReactClient(import.meta.env.VITE_CONVEX_URL as string, {
  // Convex otherwise refetches a fresh token the instant it confirms the cached
  // one, which costs a Logto refresh grant on every page load, and in session
  // mode a session-token rotation with it. Experimental in convex@1.44.
  initialAuthTokenReuse: true,
});

// Static public config (endpoint + app id are not secrets), so no config
// round-trip before sign-in is interactive. Runtime-resolved config is still
// available via the `configQuery` prop if you need it (multi-tenant setups).
createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <ConvexLogtoProvider
      client={convex}
      config={{
        endpoint: import.meta.env.VITE_LOGTO_ENDPOINT as string,
        appId: import.meta.env.VITE_LOGTO_APP_ID as string,
      }}
    >
      <App />
    </ConvexLogtoProvider>
  </StrictMode>,
);
