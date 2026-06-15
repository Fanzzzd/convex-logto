// Auth state comes from Convex (via useConvexAuth), so the button never flashes the wrong state.
import { useLogtoAuth } from "convex-logto/react";

export function AuthButton() {
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
