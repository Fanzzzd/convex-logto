import {
  Authenticated,
  AuthLoading,
  Unauthenticated,
  useQuery,
} from "convex/react";
import { useLogtoAuth } from "convex-logto/react";
import { api } from "../convex/_generated/api";
import { Callback } from "./Callback";

function Me() {
  const me = useQuery(api.me.me);
  return <pre>{me ? JSON.stringify(me, null, 2) : "loading identity…"}</pre>;
}

function SignedIn() {
  const { user, signOut } = useLogtoAuth();
  return (
    <>
      <button onClick={() => void signOut()}>
        Sign out ({user?.email ?? user?.sub ?? "user"})
      </button>
      <Me />
    </>
  );
}

function SignIn() {
  const { signIn } = useLogtoAuth();
  return <button onClick={() => void signIn()}>Sign in</button>;
}

export function App() {
  // On /callback the provider auto-finishes the OIDC exchange; just render.
  if (window.location.pathname === "/callback") return <Callback />;

  // Gate on Convex's own auth state so queries never run before auth settles.
  return (
    <main style={{ fontFamily: "system-ui", padding: 24 }}>
      <h1>convex-logto + Vite</h1>
      <AuthLoading>
        <p>Loading…</p>
      </AuthLoading>
      <Unauthenticated>
        <SignIn />
      </Unauthenticated>
      <Authenticated>
        <SignedIn />
      </Authenticated>
    </main>
  );
}
