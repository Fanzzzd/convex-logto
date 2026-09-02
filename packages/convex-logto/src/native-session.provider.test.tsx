// @vitest-environment happy-dom
//
// Native sign-in lives entirely in one in-memory promise from
// `openAuthSessionAsync`. When the OS reclaims the app mid-flow that promise
// dies with the process and the redirect arrives as a cold-start deep link
// instead. `completeSignIn` is the only way back into the exchange.
import { act } from "react";
import { createRoot, type Root } from "react-dom/client";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import {
  getFunctionName,
  makeFunctionReference,
  type FunctionReference,
} from "convex/server";
import type { LogtoSessionApi } from "./session";
import { ConvexLogtoSessionProvider, useLogtoAuth } from "./native-session";

(
  globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }
).IS_REACT_ACT_ENVIRONMENT = true;

const store = new Map<string, string>();
// Held open to model a cold start. SecureStore reads are two bridge round
// trips, and `Linking.getInitialURL()` is one, so the deep link normally
// arrives first.
let readGate: Promise<void> | null = null;
vi.mock("expo-secure-store", () => ({
  isAvailableAsync: () => Promise.resolve(true),
  getItemAsync: async (key: string) => {
    if (readGate) await readGate;
    return store.get(key) ?? null;
  },
  setItemAsync: (key: string, value: string) => {
    store.set(key, value);
    return Promise.resolve();
  },
  deleteItemAsync: (key: string) => {
    store.delete(key);
    return Promise.resolve();
  },
}));

// Never resolves, because the OS reclaimed the app while Logto had the browser.
const openAuthSessionAsync = vi.fn(
  (_url: string, _returnUrl: string) => new Promise<never>(() => {}),
);
vi.mock("expo-web-browser", () => ({
  openAuthSessionAsync: (url: string, returnUrl: string) =>
    openAuthSessionAsync(url, returnUrl),
}));

vi.mock("convex/react", () => ({
  ConvexProviderWithAuth: ({ children }: { children: unknown }) => children,
  useConvexAuth: () => ({ isLoading: false, isAuthenticated: false }),
  useQueries: () => ({}),
}));

const signInAction = vi.fn(() =>
  Promise.resolve({ url: "https://logto.example.com/oidc/auth?state=st" }),
);
const callbackAction = vi.fn((_args: unknown) =>
  Promise.resolve({
    idToken: "id-token",
    sessionToken: "session-token",
    sessionId: "session-1",
  }),
);
vi.mock("convex/browser", () => ({
  ConvexHttpClient: class {
    action(reference: FunctionReference<"action">, args: unknown) {
      const name = getFunctionName(reference);
      if (name === "auth:signIn") return signInAction();
      if (name === "auth:callback") return callbackAction(args);
      return Promise.resolve({});
    }
  },
}));

const api = {
  signIn: makeFunctionReference<"action">("auth:signIn"),
  callback: makeFunctionReference<"action">("auth:callback"),
  refresh: makeFunctionReference<"action">("auth:refresh"),
  signOut: makeFunctionReference<"action">("auth:signOut"),
  signOutEverywhere: makeFunctionReference<"action">("auth:signOutEverywhere"),
  listSessions: makeFunctionReference<"action">("auth:listSessions"),
  renameSession: makeFunctionReference<"action">("auth:renameSession"),
  revokeSession: makeFunctionReference<"action">("auth:revokeSession"),
  sessionValid: makeFunctionReference<"query">("auth:sessionValid"),
} as unknown as LogtoSessionApi;

const client = { url: "https://example.convex.cloud" } as never;

type AuthApi = ReturnType<typeof useLogtoAuth>;
let capturedApi: AuthApi | null = null;
function Probe() {
  capturedApi = useLogtoAuth();
  return null;
}

let root: Root | null = null;
async function render() {
  root ??= createRoot(document.createElement("div"));
  await act(async () => {
    root!.render(
      <ConvexLogtoSessionProvider
        client={client}
        sessionApi={api}
        redirectUri="myapp://callback"
      >
        <Probe />
      </ConvexLogtoSessionProvider>,
    );
  });
}

beforeEach(() => {
  store.clear();
  readGate = null;
  signInAction.mockClear();
  callbackAction.mockClear();
  openAuthSessionAsync.mockClear();
});

afterEach(async () => {
  if (root) await act(async () => root!.unmount());
  root = null;
  capturedApi = null;
});

it("finishes a sign-in whose deep link outlived the browser promise", async () => {
  await render();
  await act(async () => {
    void capturedApi!.signIn();
  });
  await vi.waitFor(() => expect(openAuthSessionAsync).toHaveBeenCalled());

  await act(async () => {
    await capturedApi!.completeSignIn("myapp://callback?code=c&state=st");
  });

  expect(callbackAction).toHaveBeenCalledWith(
    expect.objectContaining({ code: "c", state: "st" }),
  );
});

it("completes a cold-start deep link that beats storage preparation", async () => {
  // The stash lives in SecureStore and reads as absent until `prepare()` has
  // run, so without awaiting it this deletes the transaction it came to spend.
  await render();
  await act(async () => {
    void capturedApi!.signIn();
  });
  await vi.waitFor(() => expect(openAuthSessionAsync).toHaveBeenCalled());
  await act(async () => root!.unmount());
  root = null;

  // A new process. The engine is fresh, SecureStore still holds the stash.
  let release = () => {};
  readGate = new Promise<void>((resolve) => {
    release = resolve;
  });
  await render();
  let completed: Promise<void>;
  await act(async () => {
    completed = capturedApi!.completeSignIn("myapp://callback?code=c&state=st");
  });
  await act(async () => {
    release();
    await completed;
  });

  expect(callbackAction).toHaveBeenCalledWith(
    expect.objectContaining({ code: "c", state: "st" }),
  );
});

it("leaves the stash alone for a deep link carrying no OIDC response", async () => {
  // Apps forward every link they receive, and the guard is a prefix match, so
  // `myapp://callback/done` must not destroy an in-flight sign-in.
  await render();
  await act(async () => {
    void capturedApi!.signIn();
  });
  await vi.waitFor(() => expect(openAuthSessionAsync).toHaveBeenCalled());

  await act(async () => {
    await capturedApi!.completeSignIn("myapp://callback/done");
  });
  await act(async () => {
    await capturedApi!.completeSignIn("myapp://callback?code=c&state=st");
  });

  expect(callbackAction).toHaveBeenCalledWith(
    expect.objectContaining({ code: "c", state: "st" }),
  );
});

it("ignores a deep link that is not this app's redirect", async () => {
  await render();
  await act(async () => {
    void capturedApi!.signIn();
  });
  await vi.waitFor(() => expect(openAuthSessionAsync).toHaveBeenCalled());

  await act(async () => {
    await capturedApi!.completeSignIn("myapp://posts/42?code=c&state=st");
  });

  expect(callbackAction).not.toHaveBeenCalled();
});
