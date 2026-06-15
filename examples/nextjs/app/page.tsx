"use client";

import {
  Authenticated,
  AuthLoading,
  Unauthenticated,
  useQuery,
} from "convex/react";
import { useLogtoAuth } from "convex-logto/react";
import { api } from "../convex/_generated/api";

// Auth state comes from Convex (via useConvexAuth), so the button never flashes the wrong state.
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

// The `me` query runs only inside <Authenticated>, so it never flashes null.
function Me() {
  const me = useQuery(api.me.me);
  return <pre>{me ? JSON.stringify(me, null, 2) : "loading identity…"}</pre>;
}

export default function Home() {
  return (
    <main style={{ maxWidth: 640, margin: "48px auto", padding: "0 16px" }}>
      <h1>convex-logto + Next.js</h1>
      <AuthButton />
      <div style={{ marginTop: 24 }}>
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
      </div>
    </main>
  );
}
