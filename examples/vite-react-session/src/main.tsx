import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { ConvexReactClient } from "convex/react";
import { ConvexLogtoSessionProvider } from "convex-logto/react-session";
import { api } from "../convex/_generated/api";
import { App } from "./App";

const convex = new ConvexReactClient(import.meta.env.VITE_CONVEX_URL as string);

// Session mode: no Logto SDK, no Logto config in the bundle. The provider
// talks to your Convex functions (api.auth = logtoSessionApi re-exports);
// Convex holds the Logto refresh token server-side, the browser holds only a
// short-lived ID token and a rotating application session token.
createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <ConvexLogtoSessionProvider
      client={convex}
      sessionApi={api.auth}
      // Advisory, app-supplied device description shown by listSessions(). The
      // library never sniffs a User-Agent — this is exactly what you pass.
      clientDescriptor={{ platform: "web", browser: "this browser" }}
    >
      <App />
    </ConvexLogtoSessionProvider>
  </StrictMode>,
);
