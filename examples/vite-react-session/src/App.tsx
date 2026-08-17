import {
  Authenticated,
  AuthLoading,
  Unauthenticated,
  useQuery,
} from "convex/react";
import { useLogtoAuth } from "convex-logto/react-session";
import { Component, type ReactNode } from "react";
import { api } from "../convex/_generated/api";

// A query gated by `assertSubjectHasActiveSession` throws once the authenticated
// subject has no active component session. Catch the reactive query error so
// revocation renders as a clean sign-out instead of crashing the tree.
class SessionBoundary extends Component<
  { children: ReactNode },
  { revoked: boolean }
> {
  state = { revoked: false };
  static getDerivedStateFromError() {
    return { revoked: true };
  }
  render() {
    return this.state.revoked ? <p>Session ended.</p> : this.props.children;
  }
}

function Me() {
  const me = useQuery(api.me.me);
  const sensitive = useQuery(api.me.sensitive);
  return (
    <pre>
      {me ? JSON.stringify({ ...me, ...sensitive }, null, 2) : "loading identity…"}
    </pre>
  );
}

function SignedIn() {
  const { user, signOut } = useLogtoAuth();
  return (
    <>
      <button onClick={() => void signOut()}>
        Sign out ({String(user?.email ?? user?.sub ?? "user")})
      </button>
      <SessionBoundary>
        <Me />
      </SessionBoundary>
    </>
  );
}

function SignIn() {
  const { signIn } = useLogtoAuth();
  return <button onClick={() => void signIn()}>Sign in</button>;
}

export function App() {
  // No callback component needed: the provider finishes the exchange on
  // /callback and replace-navigates back into the app by itself.
  // Gate on Convex's own auth state so queries never run before auth settles.
  return (
    <main style={{ fontFamily: "system-ui", padding: 24 }}>
      <h1>convex-logto session mode + Vite</h1>
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
