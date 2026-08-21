import { ConvexLogtoProvider, useLogtoAuth } from "convex-logto/native";
import {
  Authenticated,
  AuthLoading,
  ConvexReactClient,
  Unauthenticated,
  useQuery,
} from "convex/react";
import { StatusBar } from "expo-status-bar";
import {
  ActivityIndicator,
  Alert,
  Button,
  SafeAreaView,
  ScrollView,
  StyleSheet,
  Text,
  View,
} from "react-native";
import { api } from "./convex/_generated/api";

// The frontend carries no Logto config — `configQuery` pulls { endpoint, appId }
// from the Convex deployment, so it's set in exactly one place per environment.
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

function Me() {
  const me = useQuery(api.me.me);
  return (
    <ScrollView style={styles.code}>
      <Text>{me ? JSON.stringify(me, null, 2) : "loading identity…"}</Text>
    </ScrollView>
  );
}

function SignedIn() {
  const { user, signOut } = useLogtoAuth();
  return (
    <View style={styles.stack}>
      <Button
        title={`Sign out (${user?.email ?? user?.sub ?? "user"})`}
        // The provider's `onAuthError` reports the failure; swallowing the
        // rejection here just keeps it from also surfacing unhandled. A sign-out
        // that fails leaves the user signed in — worth telling them about.
        onPress={() => void signOut().catch(() => {})}
      />
      <Me />
    </View>
  );
}

function SignIn() {
  // `signIn()` defaults to the provider's `redirectUri` ("io.logto://callback").
  const { signIn } = useLogtoAuth();
  return (
    <Button title="Sign in" onPress={() => void signIn().catch(() => {})} />
  );
}

export default function App() {
  return (
    // No callback route on native: `signIn` opens the system browser and resolves
    // when the deep link returns. `fallback` covers the one-time config fetch;
    // Convex's <AuthLoading> covers the subsequent token handshake.
    <ConvexLogtoProvider
      client={convex}
      configQuery={api.logto.config}
      redirectUri="io.logto://callback"
      fallback={<Spinner label="Loading config…" />}
      // `@logto/rn` rejects instead of storing the error, and the two failures
      // an app actually sees — the user dismissing the system browser, and a
      // sign-out that could not reach Logto — are both invisible without this.
      onAuthError={(error) => Alert.alert("Logto", error.message)}
    >
      <SafeAreaView style={styles.screen}>
        <Text style={styles.title}>convex-logto + Expo</Text>
        <AuthLoading>
          <Spinner label="Signing in…" />
        </AuthLoading>
        <Unauthenticated>
          <SignIn />
        </Unauthenticated>
        <Authenticated>
          <SignedIn />
        </Authenticated>
      </SafeAreaView>
      <StatusBar style="auto" />
    </ConvexLogtoProvider>
  );
}

const styles = StyleSheet.create({
  screen: { flex: 1, padding: 24, gap: 16 },
  title: { fontSize: 20, fontWeight: "600" },
  stack: { gap: 12, flex: 1 },
  row: { flexDirection: "row", alignItems: "center", gap: 8 },
  code: { flexGrow: 0 },
});
