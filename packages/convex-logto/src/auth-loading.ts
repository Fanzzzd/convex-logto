import { useEffect, useState } from "react";

/**
 * Loading-state latch for the Logto→Convex auth bridge — shared by the web
 * (`react.tsx`) and native (`native.tsx`) entries.
 *
 * `authFlowPending` means "a sign-in handshake is underway and the IdP has not
 * authenticated yet" (web: a `/callback?code=` exchange in flight; native: a
 * `signIn()` in flight). While it's true we keep reporting `isLoading: true`, so
 * Convex's `ConvexProviderWithAuth` holds its internal auth state at `null`
 * (validating) instead of pinning it to `false` (logged out). That pin is what
 * produced a transient `{ isLoading: false, isAuthenticated: false }` — read by
 * route guards as a clean logout — right after the IdP authenticated but before
 * Convex validated the token (issue #11).
 *
 * `settled` latches on the first non-loading, non-pending render and stays true,
 * which also rides out the `isLoading` churn `@logto/react` emits around every
 * SDK call after login (native's `@logto/rn` has no such churn, so there the
 * latch is just harmless consistency).
 */
export function nextAuthLoading(
  prevSettled: boolean,
  providerLoading: boolean,
  authFlowPending: boolean,
): { settled: boolean; isLoading: boolean } {
  const settled = prevSettled || (!providerLoading && !authFlowPending);
  return { settled, isLoading: !settled || authFlowPending };
}

/**
 * Native (`@logto/rn`) auth state for the Convex bridge.
 *
 * Native has no `isLoading` churn and flips `isAuthenticated` straight to true the
 * instant `signIn()` resolves — and with Convex's auth pinned `false` from being
 * logged out, that flip surfaced the transient `{ isLoading:false,
 * isAuthenticated:false }` tick (issue #11). There's no pre-auth signal to latch on
 * (no `/callback` URL, no in-flight flag we can rely on across React scheduling), so
 * instead we detect the transition: `seenAuthenticated` lags `isAuthenticated` by
 * one committed render, so `isAuthenticated && !seenAuthenticated` is true on exactly
 * the render Logto first authenticates.
 *
 * On that one render we report loading — but as **not-yet-authenticated**. That makes
 * Convex reset its pinned `false` to `null` (validating) without starting `setAuth()`
 * during the loading pulse, so the settled frame does a single clean validation
 * instead of a `clearAuth()`+`setAuth()` churn cycle. The returned `isAuthenticated`
 * is therefore never true while loading — there's never a `{ loading:true, auth:true }`
 * frame.
 */
export function nativeAuthState(
  isInitialized: boolean,
  isAuthenticated: boolean,
  seenAuthenticated: boolean,
): { isLoading: boolean; isAuthenticated: boolean } {
  const isLoading = !isInitialized || (isAuthenticated && !seenAuthenticated);
  return { isLoading, isAuthenticated: isAuthenticated && !isLoading };
}

/**
 * The native bridge's loading state (`native.tsx`), as a hook so it's unit-testable
 * without mocking `@logto/rn`. `seenAuthenticated` is state, not a ref, so committing
 * it drives the settle re-render after the one-frame loading pulse (see
 * `nativeAuthState`). The effect only writes when the value actually changes, so it
 * converges in one extra render and never loops.
 */
export function useNativeAuthState(
  isInitialized: boolean,
  isAuthenticated: boolean,
): { isLoading: boolean; isAuthenticated: boolean } {
  const [seenAuthenticated, setSeenAuthenticated] = useState(false);
  useEffect(() => {
    if (seenAuthenticated !== isAuthenticated)
      setSeenAuthenticated(isAuthenticated);
  }, [isAuthenticated, seenAuthenticated]);
  return nativeAuthState(isInitialized, isAuthenticated, seenAuthenticated);
}
