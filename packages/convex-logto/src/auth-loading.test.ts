import { describe, expect, it } from "vitest";
import { nativeAuthState, nextAuthLoading } from "./auth-loading";
import { classifySignInSearch } from "./callback";

// The whole point of both helpers: the bridge must never report
// `{ isLoading:false, isAuthenticated:false }` (a settled logged-out state) during
// the window between "IdP authenticated" and "Convex validated" — that frame is
// what Convex turns into the transient tick that bounced route guards (issue #11).

describe("nextAuthLoading — web latch (issue #11)", () => {
  // Drive a scripted @logto/react sequence through the latch; track reported loading.
  function reportLoading(
    steps: Array<{ providerLoading: boolean; authFlowPending: boolean }>,
  ): boolean[] {
    let settled = false;
    return steps.map((s) => {
      const next = nextAuthLoading(
        settled,
        s.providerLoading,
        s.authFlowPending,
      );
      settled = next.settled;
      return next.isLoading;
    });
  }

  it("holds loading across the /callback?code= exchange, no logged-out tick", () => {
    // Frames on a callback landing: boot → settles-but-not-authed *before* the
    // exchange (the old early-latch trap) → exchange → authed → soft-nav home.
    const code = "?code=abc&state=xyz";
    const pending = (search: string, isAuthenticated: boolean) =>
      !isAuthenticated && classifySignInSearch(search).kind === "pending";
    const loading = reportLoading([
      { providerLoading: true, authFlowPending: pending(code, false) },
      { providerLoading: false, authFlowPending: pending(code, false) }, // ← old bug latched here
      { providerLoading: true, authFlowPending: pending(code, false) },
      { providerLoading: false, authFlowPending: pending(code, true) }, // authed
      { providerLoading: false, authFlowPending: pending("", true) }, // soft-navved home
    ]);
    expect(loading).toEqual([true, true, true, false, false]);
  });

  it("settles to not-loading for a genuine logged-out visit (nothing pending)", () => {
    expect(nextAuthLoading(false, true, false)).toEqual({
      settled: false,
      isLoading: true,
    }); // still booting
    expect(nextAuthLoading(false, false, false)).toEqual({
      settled: true,
      isLoading: false,
    }); // settled signed-out
  });

  it("does not flicker once settled (post-login provider-loading churn)", () => {
    // Authenticated and settled; @logto/react blips providerLoading true. The latch
    // holds — we keep reporting not-loading instead of dropping back to loading.
    expect(nextAuthLoading(true, true, false)).toEqual({
      settled: true,
      isLoading: false,
    });
  });
});

describe("nativeAuthState — native transition pulse (issue #11)", () => {
  // [isInitialized, isAuthenticated, seenAuthenticated] over a sign-in.
  const seq: Array<[boolean, boolean, boolean]> = [
    [false, false, false], // booting (!isInitialized)
    [true, false, false], // initialized, logged out
    [true, true, false], // signIn just resolved: auth-flip render (seen lags)
    [true, true, true], // settled: effect committed seenAuthenticated
  ];

  it("pulses exactly one loading frame on the auth flip, reported NOT authenticated", () => {
    const frames = seq.map(([init, auth, seen]) =>
      nativeAuthState(init, auth, seen),
    );
    expect(frames).toEqual([
      { isLoading: true, isAuthenticated: false }, // boot
      { isLoading: false, isAuthenticated: false }, // logged out (real state)
      { isLoading: true, isAuthenticated: false }, // pulse: loading, NOT yet authed
      { isLoading: false, isAuthenticated: true }, // settled authed
    ]);
    // The auth-flip frame (index 2) reports loading, not a logged-out tick: a guard
    // sees loading and waits instead of bouncing the just-signed-in user.
    expect(frames[2]).toEqual({ isLoading: true, isAuthenticated: false });
  });

  it("never reports authenticated while loading (no churn-causing frame)", () => {
    for (const [init, auth, seen] of [
      [false, true, false],
      [true, true, false],
      [false, false, true],
    ] as Array<[boolean, boolean, boolean]>) {
      const f = nativeAuthState(init, auth, seen);
      if (f.isLoading) expect(f.isAuthenticated).toBe(false);
    }
  });

  it("re-arms after logout so the next login pulses again", () => {
    // signed out from an authed state: isAuthenticated false, seen still true.
    expect(nativeAuthState(true, false, true)).toEqual({
      isLoading: false,
      isAuthenticated: false,
    });
    // next login flip: seen back to false → pulses loading again.
    expect(nativeAuthState(true, true, false)).toEqual({
      isLoading: true,
      isAuthenticated: false,
    });
  });
});
