// Declarative gating with Convex's <AuthLoading>/<Unauthenticated>/<Authenticated>.
// convex-logto uses ConvexProviderWithAuth internally, so these work unchanged.
// The `me` query runs only inside <Authenticated>, so it never flashes null first.
import {
  Authenticated,
  AuthLoading,
  Unauthenticated,
  useQuery,
} from "convex/react";
import { api } from "../convex/_generated/api";

function Me() {
  const me = useQuery(api.me.me);
  return <pre>{me ? JSON.stringify(me, null, 2) : "…"}</pre>;
}

export function DeclarativeGate() {
  return (
    <>
      <AuthLoading>
        <p>Auth loading…</p>
      </AuthLoading>
      <Unauthenticated>
        <p>You are signed out.</p>
      </Unauthenticated>
      <Authenticated>
        <p>Signed in — your Convex identity:</p>
        <Me />
      </Authenticated>
    </>
  );
}
