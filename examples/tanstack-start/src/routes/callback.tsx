// The provider completes the OIDC code exchange; this route just renders.
import { createFileRoute } from "@tanstack/react-router";

export const Route = createFileRoute("/callback")({
  component: () => <p>Finishing sign in…</p>,
});
