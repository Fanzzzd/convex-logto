import {
  ConvexLogtoSessionProvider,
  useLogtoAuth,
  type LogtoSessionSummary,
} from "convex-logto/native-session";
import {
  Authenticated,
  AuthLoading,
  ConvexReactClient,
  Unauthenticated,
  useQuery,
} from "convex/react";
import * as Linking from "expo-linking";
import { StatusBar } from "expo-status-bar";
import { Component, useCallback, useEffect, useState } from "react";
import type { ReactNode } from "react";
import {
  ActivityIndicator,
  Button,
  Platform,
  SafeAreaView,
  ScrollView,
  StyleSheet,
  Text,
  TextInput,
  View,
} from "react-native";
import { api } from "./convex/_generated/api";

// Session mode carries no Logto config in the app bundle at all — not even the
// endpoint. The deployment is the OAuth client; this client only ever holds a
// short-lived ID token and a rotating session token, both in SecureStore.
const convex = new ConvexReactClient(process.env.EXPO_PUBLIC_CONVEX_URL!, {
  unsavedChangesWarning: false,
  // Convex otherwise refetches a fresh token the instant it confirms the cached
  // one, which costs a Logto refresh grant on every page load — and in session
  // mode a session-token rotation with it. Experimental in convex@1.44.
  initialAuthTokenReuse: true,
});

function Spinner({ label }: { label: string }) {
  return (
    <View style={styles.row}>
      <ActivityIndicator />
      <Text>{label}</Text>
    </View>
  );
}

// A query gated by `assertSubjectHasActiveSession` throws once the authenticated
// subject has no active component session. Catching the reactive query error
// renders revocation as a clean sign-out instead of crashing the tree.
class SessionBoundary extends Component<
  { children: ReactNode },
  { revoked: boolean }
> {
  state = { revoked: false };
  static getDerivedStateFromError() {
    return { revoked: true };
  }
  render() {
    return this.state.revoked ? (
      <Text>Session ended.</Text>
    ) : (
      this.props.children
    );
  }
}

function Me() {
  const me = useQuery(api.me.me);
  const sensitive = useQuery(api.me.sensitive);
  return (
    <ScrollView style={styles.code}>
      <Text>
        {me
          ? JSON.stringify({ ...me, ...sensitive }, null, 2)
          : "loading identity…"}
      </Text>
    </ScrollView>
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

  if (error) return <Text>Sessions unavailable: {error}</Text>;
  if (sessions === null) return <Spinner label="Loading sessions…" />;
  return (
    <View style={styles.stack}>
      <Text style={styles.heading}>
        Your sessions{truncated ? " (first 16)" : ""}
      </Text>
      {sessions.map((session) => (
        <View key={session.sessionId} style={styles.session}>
          <Text>
            {session.label ?? "Unnamed"}
            {session.current ? " — this device" : ""}
            {session.client
              ? ` — ${Object.values(session.client).join(" / ")}`
              : ""}
          </Text>
          <Text style={styles.muted}>
            last used {new Date(session.lastRefreshedAt).toLocaleString()}
          </Text>
          {draft?.id === session.sessionId ? (
            <View style={styles.row}>
              <TextInput
                style={styles.input}
                value={draft.label}
                autoFocus
                onChangeText={(label) => setDraft({ id: draft.id, label })}
              />
              <Button
                title="Save"
                onPress={() => {
                  const label = draft.label.trim();
                  setDraft(null);
                  run(
                    renameSession(
                      session.sessionId,
                      label === "" ? undefined : label,
                    ),
                  );
                }}
              />
            </View>
          ) : (
            <View style={styles.row}>
              <Button
                title="Rename"
                onPress={() =>
                  setDraft({
                    id: session.sessionId,
                    label: session.label ?? "",
                  })
                }
              />
              {/* Revoking the current session leaves this device's credentials
                  in place — "Sign out" is the button for that. */}
              <Button
                title="Revoke"
                onPress={() => run(revokeSession(session.sessionId))}
              />
            </View>
          )}
        </View>
      ))}
    </View>
  );
}

function SignedIn() {
  const { user, signOut, signOutEverywhere } = useLogtoAuth();
  return (
    <View style={styles.stack}>
      <Button
        title={`Sign out (${user?.email ?? user?.sub ?? "user"})`}
        onPress={() => void signOut().catch(() => {})}
      />
      <Button
        title="Sign out everywhere"
        onPress={() => void signOutEverywhere().catch(() => {})}
      />
      <SessionBoundary>
        <Me />
        <Sessions />
      </SessionBoundary>
    </View>
  );
}

function SignIn() {
  // No callback route: `signIn()` opens the system browser and resolves when the
  // deep link returns to the provider's `redirectUri`.
  const { signIn } = useLogtoAuth();
  // The provider's `onAuthError` reports the failure; swallowing the rejection
  // here just keeps it from also surfacing unhandled.
  return <Button title="Sign in" onPress={() => void signIn().catch(() => {})} />;
}

// The sign-in flow lives in one in-memory promise. If the OS reclaims the app
// while Logto has the browser — routine on a low-memory Android device — that
// promise dies with the process and the redirect arrives as a cold-start deep
// link instead. Handing every link to `completeSignIn` finishes the exchange;
// anything that is not this app's redirect, or carries no OIDC response, is
// ignored without disturbing a sign-in already in progress.
function DeepLinkBridge() {
  const { completeSignIn } = useLogtoAuth();
  useEffect(() => {
    void Linking.getInitialURL().then((url) => {
      if (url) void completeSignIn(url);
    });
    const subscription = Linking.addEventListener("url", ({ url }) => {
      void completeSignIn(url);
    });
    return () => subscription.remove();
  }, [completeSignIn]);
  return null;
}

export default function App() {
  return (
    <ConvexLogtoSessionProvider
      client={convex}
      sessionApi={api.auth}
      redirectUri="io.logto.session://callback"
      // Advisory, app-supplied device description shown by listSessions(). The
      // library never inspects the device — this is exactly what you pass.
      clientDescriptor={{ platform: "native", os: Platform.OS }}
      // `signIn` / `signOut` reject rather than storing the error, so without
      // this a dismissed browser sheet or an offline sign-out is an unhandled
      // rejection and nothing else.
      onAuthError={(error) => {
        console.error("auth error", error);
      }}
    >
      <DeepLinkBridge />
      <SafeAreaView style={styles.screen}>
        <Text style={styles.title}>convex-logto native session mode</Text>
        {/* Convex's own auth state: a cold start with a live SecureStore ID
            token authenticates with no round-trip at all. */}
        <AuthLoading>
          <Spinner label="Restoring session…" />
        </AuthLoading>
        <Unauthenticated>
          <SignIn />
        </Unauthenticated>
        <Authenticated>
          <SignedIn />
        </Authenticated>
      </SafeAreaView>
      <StatusBar style="auto" />
    </ConvexLogtoSessionProvider>
  );
}

const styles = StyleSheet.create({
  screen: { flex: 1, padding: 24, gap: 16 },
  title: { fontSize: 20, fontWeight: "600" },
  heading: { fontSize: 16, fontWeight: "600" },
  stack: { gap: 12, flex: 1 },
  row: { flexDirection: "row", alignItems: "center", gap: 8 },
  session: { gap: 4 },
  muted: { opacity: 0.6 },
  input: { borderWidth: 1, borderColor: "#999", padding: 6, flexGrow: 1 },
  code: { flexGrow: 0 },
});
