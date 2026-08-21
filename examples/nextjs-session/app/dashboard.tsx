"use client";

import { Authenticated, AuthLoading, Unauthenticated } from "convex/react";
import { usePreloadedQuery, type Preloaded } from "convex/react";
import { useState } from "react";
import { useLogtoAuth } from "convex-logto/react-session";
import type { api } from "@/convex/_generated/api";

function AuthButton() {
  const { isAuthenticated, isLoading, user, signIn, signOut } = useLogtoAuth();
  if (isLoading) return <span style={{ color: "#888" }}>Loading…</span>;
  return isAuthenticated ? (
    <button onClick={() => void signOut()}>
      Sign out ({user?.email ?? user?.sub ?? "user"})
    </button>
  ) : (
    <button onClick={() => void signIn()}>Sign in</button>
  );
}

/** The "where am I signed in" list, plus live revocation of another device. */
function Devices() {
  const { listSessions, revokeSession } = useLogtoAuth();
  const [state, setState] = useState<string>("");
  return (
    <div style={{ marginTop: 16 }}>
      <button
        onClick={() => {
          void listSessions()
            .then((result) => setState(JSON.stringify(result, null, 2)))
            .catch((error: unknown) => setState(String(error)));
        }}
      >
        List my sessions
      </button>{" "}
      <button
        onClick={() => {
          // Revoking the *current* session leaves this browser's cookie in
          // place — signOut() is what clears it. The other device drops on its
          // next reactive revocation tick.
          void listSessions()
            .then(async ({ sessions }) => {
              const other = sessions.find((entry) => !entry.current);
              if (!other) return setState("no other session to revoke");
              await revokeSession(other.sessionId);
              setState(`revoked ${other.sessionId}`);
            })
            .catch((error: unknown) => setState(String(error)));
        }}
      >
        Revoke another device
      </button>
      {state && <pre>{state}</pre>}
    </div>
  );
}

/** Organization permissions and the live Logto profile — both server-minted. */
function Tokens() {
  const { getOrganizationTokenClaims, fetchUserInfo, user } = useLogtoAuth();
  const [state, setState] = useState<string>("");
  // Membership and roles are already in the ID token; no round trip for these.
  const organizations = (user?.organizations as string[] | undefined) ?? [];
  return (
    <div style={{ marginTop: 16 }}>
      <p>
        Organizations from the ID token (free):{" "}
        <code>{JSON.stringify(organizations)}</code>
      </p>
      <button
        disabled={organizations.length === 0}
        onClick={() => {
          // Only fine-grained *permissions* need this. The token itself never
          // reaches the browser unless the deployment set exposeAccessTokens.
          void getOrganizationTokenClaims(organizations[0]!)
            .then((claims) => setState(JSON.stringify(claims, null, 2)))
            .catch((error: unknown) => setState(String(error)));
        }}
      >
        Organization permissions
      </button>{" "}
      <button
        onClick={() => {
          void fetchUserInfo()
            .then((info) => setState(JSON.stringify(info, null, 2)))
            .catch((error: unknown) => setState(String(error)));
        }}
      >
        Fetch live profile
      </button>
      {state && <pre>{state}</pre>}
    </div>
  );
}

export function Dashboard({
  preloadedMe,
  serverSawToken,
}: {
  preloadedMe: Preloaded<typeof api.me.me>;
  serverSawToken: boolean;
}) {
  // The server's result until the client's own subscription resolves, then the
  // live one — so this is *the client's* view of the identity, not the
  // server's, from the moment auth is restored.
  const me = usePreloadedQuery(preloadedMe);
  return (
    <main style={{ maxWidth: 720, margin: "48px auto", padding: "0 16px" }}>
      <h1>convex-logto + Next.js, session mode</h1>
      <AuthButton />
      <p style={{ color: "#888" }}>
        The server {serverSawToken ? "had" : "did not have"} an ID token for this
        request, so this page was rendered{" "}
        {serverSawToken ? "signed in" : "signed out"}.
      </p>
      <pre>{me ? JSON.stringify(me, null, 2) : "signed out"}</pre>
      <AuthLoading>
        <p>Auth loading…</p>
      </AuthLoading>
      <Unauthenticated>
        <p>You are signed out.</p>
      </Unauthenticated>
      <Authenticated>
        <Devices />
        <Tokens />
      </Authenticated>
    </main>
  );
}
