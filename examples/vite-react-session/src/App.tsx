import {
  Authenticated,
  AuthLoading,
  Unauthenticated,
  useQuery,
} from "convex/react";
import type { LogtoSessionSummary } from "convex-logto";
import { useLogtoAuth } from "convex-logto/react-session";
import { Component, useCallback, useEffect, useState, type ReactNode } from "react";
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

// "Where am I signed in": a snapshot, not a subscription — the session token it
// authenticates with rotates, so reload it after every mutation instead.
function Sessions() {
  const { listSessions, renameSession, revokeSession } = useLogtoAuth();
  const [sessions, setSessions] = useState<LogtoSessionSummary[] | null>(null);
  const [truncated, setTruncated] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [draft, setDraft] = useState<{ id: string; label: string } | null>(null);

  const reload = useCallback(async () => {
    try {
      const result = await listSessions();
      setSessions(result.sessions);
      setTruncated(result.truncated);
      setError(null);
    } catch (failure) {
      setError(failure instanceof Error ? failure.message : String(failure));
    }
  }, [listSessions]);

  useEffect(() => {
    void reload();
  }, [reload]);

  const run = (work: Promise<unknown>) => {
    void work.then(reload, (failure: unknown) => {
      setError(failure instanceof Error ? failure.message : String(failure));
    });
  };

  if (error) return <p>Sessions unavailable: {error}</p>;
  if (sessions === null) return <p>Loading sessions…</p>;
  return (
    <section>
      <h2>Your sessions{truncated ? " (first 16)" : ""}</h2>
      <ul>
        {sessions.map((session) => (
          <li key={session.sessionId}>
            {session.label ?? "Unnamed"}
            {session.current ? " — this device" : ""}
            {session.client
              ? ` — ${Object.values(session.client).join(" / ")}`
              : ""}{" "}
            <small>
              last used {new Date(session.lastRefreshedAt).toLocaleString()}
            </small>{" "}
            {draft?.id === session.sessionId ? (
              <>
                <input
                  value={draft.label}
                  onChange={(event) =>
                    setDraft({ id: draft.id, label: event.target.value })
                  }
                />
                <button
                  onClick={() => {
                    const label = draft.label.trim();
                    setDraft(null);
                    run(
                      renameSession(
                        session.sessionId,
                        label === "" ? undefined : label,
                      ),
                    );
                  }}
                >
                  Save
                </button>
              </>
            ) : (
              <button
                onClick={() =>
                  setDraft({
                    id: session.sessionId,
                    label: session.label ?? "",
                  })
                }
              >
                Rename
              </button>
            )}{" "}
            {/* Revoking the current session leaves this browser's credentials
                in place — "Sign out" is the button for that. */}
            <button onClick={() => run(revokeSession(session.sessionId))}>
              Revoke
            </button>
          </li>
        ))}
      </ul>
    </section>
  );
}

function SignedIn() {
  const { user, signOut, signOutEverywhere } = useLogtoAuth();
  return (
    <>
      <button onClick={() => void signOut()}>
        Sign out ({String(user?.email ?? user?.sub ?? "user")})
      </button>{" "}
      <button onClick={() => void signOutEverywhere()}>
        Sign out everywhere
      </button>
      <SessionBoundary>
        <Me />
        <Sessions />
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
