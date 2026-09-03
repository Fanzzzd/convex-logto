// @vitest-environment happy-dom
//
// The contract this library's loading latch (`auth-loading.ts`, issue #11)
// depends on, checked against the real `ConvexProviderWithAuth` rather than a
// mock. `ConvexProviderWithAuth` pins its own state to "logged out" the moment
// the auth hook reports not-loading and not-authenticated, and a later flip to
// authenticated does not lift that pin until the backend validates a token. In
// between, every `useConvexAuth()` consumer sees a settled logged-out frame.
//
// Two assertions, so a Convex release that changes either side shows up here:
// the frame exists when the hook flips without a loading pulse (the reason the
// latch exists), and the latch's one-frame loading pulse removes it.
import { act, useEffect, useState } from "react";
import { createRoot, type Root } from "react-dom/client";
import { ConvexProviderWithAuth, useConvexAuth } from "convex/react";
import { afterEach, expect, it } from "vitest";

(
  globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }
).IS_REACT_ACT_ENVIRONMENT = true;

type Frame = { isLoading: boolean; isAuthenticated: boolean };

// The slice of `ConvexReactClient` the provider calls. `setAuth` hands back the
// callback the backend would invoke once it has validated a token.
function fakeClient() {
  let reportValidated: ((ok: boolean) => void) | null = null;
  return {
    client: {
      setAuth(
        _fetch: unknown,
        onChange: (ok: boolean) => void,
        _onRefreshing: (refreshing: boolean) => void,
      ) {
        reportValidated = onChange;
      },
      clearAuth() {
        reportValidated = null;
      },
    },
    validate() {
      reportValidated?.(true);
    },
  };
}

let root: Root | null = null;
afterEach(() => {
  act(() => root?.unmount());
  root = null;
});

// Mount the real provider around a consumer that records every frame it sees,
// with an auth hook whose reported state the test drives from outside.
async function mount(client: unknown) {
  const frames: Frame[] = [];
  let setReported: ((state: Frame) => void) | null = null;
  // Stable on purpose: a new `fetchAccessToken` identity is Convex's signal to
  // re-run authentication, and this library's hooks keep theirs stable.
  const fetchAccessToken = async () => "token";
  function useAuth() {
    const [state, setState] = useState<Frame>({
      isLoading: false,
      isAuthenticated: false,
    });
    setReported = setState;
    return { ...state, fetchAccessToken };
  }
  let latest: Frame | null = null;
  function Consumer() {
    const { isLoading, isAuthenticated } = useConvexAuth();
    latest = { isLoading, isAuthenticated };
    useEffect(() => {
      frames.push({ isLoading, isAuthenticated });
    }, [isLoading, isAuthenticated]);
    return null;
  }
  root = createRoot(document.createElement("div"));
  await act(async () => {
    root!.render(
      <ConvexProviderWithAuth client={client as never} useAuth={useAuth}>
        <Consumer />
      </ConvexProviderWithAuth>,
    );
  });
  return {
    frames,
    /** What every `useConvexAuth()` consumer sees right now. */
    now: () => latest,
    report: async (state: Frame) => {
      await act(async () => {
        setReported!(state);
      });
    },
  };
}

it("a flip to authenticated with no loading pulse shows a settled logged-out frame first", async () => {
  const { client, validate } = fakeClient();
  const { frames, now, report } = await mount(client);
  expect(now()).toEqual({ isLoading: false, isAuthenticated: false });

  // What `@logto/rn` does the instant `signIn()` resolves, and what the web SDK
  // does mid-callback: authenticated, not loading, token not yet validated.
  await report({ isLoading: false, isAuthenticated: true });

  // The #11 bug. The app is signed in at the IdP, and every `<Unauthenticated>`
  // still renders, because Convex keeps its "logged out" pin until the backend
  // validates a token. Nothing distinguishes this frame from a real sign-out.
  expect(now()).toEqual({ isLoading: false, isAuthenticated: false });

  await act(async () => validate());
  expect(now()).toEqual({ isLoading: false, isAuthenticated: true });
  expect(frames).not.toContainEqual({
    isLoading: true,
    isAuthenticated: false,
  });
});

it("the latch's one-frame loading pulse turns that into a loading frame", async () => {
  const { client, validate } = fakeClient();
  const { frames, now, report } = await mount(client);

  // What `nativeAuthState` / `nextAuthLoading` report on the render the IdP
  // first authenticates: loading, and not yet authenticated.
  await report({ isLoading: true, isAuthenticated: false });
  expect(now()).toEqual({ isLoading: true, isAuthenticated: false });

  // The pulse lifted the pin, so the flip lands as "validating", not "logged
  // out", and stays there until the backend answers.
  await report({ isLoading: false, isAuthenticated: true });
  expect(now()).toEqual({ isLoading: true, isAuthenticated: false });

  await act(async () => validate());
  expect(now()).toEqual({ isLoading: false, isAuthenticated: true });
  expect(frames).toEqual([
    { isLoading: false, isAuthenticated: false },
    { isLoading: true, isAuthenticated: false },
    { isLoading: false, isAuthenticated: true },
  ]);
});
