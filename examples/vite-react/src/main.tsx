import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { ConvexReactClient } from "convex/react";
import { ConvexLogtoProvider } from "convex-logto/react";
import { api } from "../convex/_generated/api";
import { App } from "./App";

const convex = new ConvexReactClient(import.meta.env.VITE_CONVEX_URL as string);

// The frontend carries no Logto config — `configQuery` pulls { endpoint, appId }
// from the Convex deployment, so it's set in exactly one place per environment.
createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <ConvexLogtoProvider client={convex} configQuery={api.logto.config}>
      <App />
    </ConvexLogtoProvider>
  </StrictMode>,
);
