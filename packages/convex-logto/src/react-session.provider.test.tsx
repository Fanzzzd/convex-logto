// @vitest-environment happy-dom
//
// Provider-level tests for session mode: the engine identity contract. The
// engine owns the whole mount state machine (callback exchange, restore,
// refresh) and `engine.start()` has no cancellation, so rebuilding it mid-mount
// abandons an in-flight sign-in while its replacement reports a failed one.
// `convex/react` is mocked at the module boundary; the engine is real.
import { act, type ReactNode } from "react";
import { createRoot, type Root } from "react-dom/client";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import {
  getFunctionName,
  makeFunctionReference,
  type FunctionReference,
} from "convex/server";
import type { LogtoSessionApi } from "./session";
import {
  ConvexLogtoSessionProvider,
  useLogtoAuth,
  type ConvexLogtoSessionProviderProps,
  type LogtoAuthEvent,
  type LogtoSessionClientDescriptor,
} from "./react-session";

(
  globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }
).IS_REACT_ACT_ENVIRONMENT = true;

let convexAuthenticated = false;
let sessionValidResult: unknown = undefined;
vi.mock("convex/react", () => ({
  ConvexProviderWithAuth: ({ children }: { children: ReactNode }) => children,
  useConvexAuth: () => ({
    isLoading: false,
    isAuthenticated: convexAuthenticated,
  }),
  // Mirrors the real hooks: `useQuery` rethrows a query error during render,
  // `useQueries` hands it back as a value.
  useQuery: () => {
    if (sessionValidResult instanceof Error) throw sessionValidResult;
    return sessionValidResult;
  },
  useQueries: (queries: Record<string, unknown>) =>
    "valid" in queries ? { valid: sessionValidResult } : {},
}));

// Session actions must reach the deployment over HTTP, never over the app's
// WebSocket client — see `session-transport.ts`.
const httpClientUrls: string[] = [];
vi.mock("convex/browser", () => ({
  ConvexHttpClient: class {
    constructor(url: string) {
      httpClientUrls.push(url);
    }
    action(reference: FunctionReference<"action">, args: unknown) {
      if (getFunctionName(reference) === "auth:callback") return callback(args);
      return Promise.resolve({});
    }
  },
}));

const callback = vi.fn();
// Real references, not stubs: the cookie transport maps every one of them
// through `getFunctionName`.
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

const client = {
  url: "https://example.convex.cloud",
  action: () => {
    throw new Error("session action ran on the app's WebSocket client");
  },
} as never;

// `signIn` is stable per engine instance, so its identity is a proxy for the
// engine's: a new function object means a new engine.
let capturedSignIn: unknown = null;
function Probe() {
  capturedSignIn = useLogtoAuth().signIn;
  return null;
}

let root: Root | null = null;
let authEvents: LogtoAuthEvent[] = [];
let authErrors: Error[] = [];
async function render(
  clientDescriptor?: LogtoSessionClientDescriptor,
  onAuthEvent?: (event: LogtoAuthEvent) => void,
  extra?: Partial<ConvexLogtoSessionProviderProps>,
) {
  root ??= createRoot(document.createElement("div"));
  await act(async () => {
    root!.render(
      <ConvexLogtoSessionProvider
        client={client}
        sessionApi={api}
        clientDescriptor={clientDescriptor}
        onAuthEvent={onAuthEvent}
        onAuthError={(error) => authErrors.push(error)}
        {...extra}
      >
        <Probe />
      </ConvexLogtoSessionProvider>,
    );
  });
}

beforeEach(() => {
  (
    window as unknown as { happyDOM: { setURL: (url: string) => void } }
  ).happyDOM.setURL("http://localhost:5173/");
  localStorage.clear();
  sessionStorage.clear();
  convexAuthenticated = false;
  sessionValidResult = undefined;
  authEvents = [];
  httpClientUrls.length = 0;
  authErrors = [];
  callback.mockReset().mockResolvedValue({
    idToken: "id-token",
    sessionToken: "session-token",
    sessionId: "session-1",
  });
});

afterEach(async () => {
  if (root) await act(async () => root!.unmount());
  root = null;
  capturedSignIn = null;
});

it("keeps one engine when the client descriptor arrives late", async () => {
  // Apps learn the description asynchronously — an effect, a `useState`, or
  // `navigator.userAgentData.getHighEntropyValues()`. A rebuilt engine would
  // restart the mount state machine underneath an in-flight sign-in.
  await render(undefined);
  const first = capturedSignIn;

  await render({ platform: "web", browser: "Firefox" });

  expect(capturedSignIn).toBe(first);
});

it("keeps one engine across an inline descriptor's fresh object identity", async () => {
  await render({ platform: "web" });
  const first = capturedSignIn;

  await render({ platform: "web" });

  expect(capturedSignIn).toBe(first);
});

it("keeps one engine when the SSR seed is re-issued", async () => {
  // `getInitialToken()` rotates the cookie and mints a fresh ID token per call,
  // so every re-run of the root loader (`router.invalidate()`, a reload) hands
  // back a different string. That is a new seed, not a new session.
  const cookieFetch = vi.fn(() => Promise.resolve(new Response("{}")));
  const cookieTransport = { endpoint: "/api/logto", fetch: cookieFetch };
  await render(undefined, undefined, {
    cookieTransport,
    initialToken: "seed-1",
    initialSessionId: "session-1",
  });
  const first = capturedSignIn;

  await render(undefined, undefined, {
    cookieTransport,
    initialToken: "seed-2",
    initialSessionId: "session-1",
  });

  expect(capturedSignIn).toBe(first);
});

it("keeps one engine across an inline cookieTransport fetch", async () => {
  // `cookieTransport={{ endpoint, fetch: (u, i) => fetch(u, i) }}` is a
  // documented option; an inline arrow changes identity on every render.
  await render(undefined, undefined, {
    cookieTransport: {
      endpoint: "/api/logto",
      fetch: () => Promise.resolve(new Response("{}")),
    },
  });
  const first = capturedSignIn;

  await render(undefined, undefined, {
    cookieTransport: {
      endpoint: "/api/logto",
      fetch: () => Promise.resolve(new Response("{}")),
    },
  });

  expect(capturedSignIn).toBe(first);
});

it("passes the descriptor through to the exchange", async () => {
  sessionStorage.setItem(
    "convex-logto:https://example.convex.cloud:txn",
    JSON.stringify({ state: "st" }),
  );
  (
    window as unknown as { happyDOM: { setURL: (url: string) => void } }
  ).happyDOM.setURL("http://localhost:5173/callback?code=c&state=st");

  await render({ platform: "web", browser: "Firefox" });
  await vi.waitFor(() => expect(callback).toHaveBeenCalled());

  expect(callback).toHaveBeenCalledWith(
    expect.objectContaining({
      client: { platform: "web", browser: "Firefox" },
    }),
  );
});

it("runs session actions off the app's WebSocket client", async () => {
  // Convex stops the socket *before* asking for a fresh token, so an action
  // sent on that client during reauthentication parks forever and the socket is
  // never restarted. `client.action` throws here to catch a regression.
  sessionStorage.setItem(
    "convex-logto:https://example.convex.cloud:txn",
    JSON.stringify({ state: "st" }),
  );
  (
    window as unknown as { happyDOM: { setURL: (url: string) => void } }
  ).happyDOM.setURL("http://localhost:5173/callback?code=c&state=st");

  await render(undefined);
  await vi.waitFor(() => expect(callback).toHaveBeenCalled());

  expect(httpClientUrls).toEqual(["https://example.convex.cloud"]);
});

it("survives a sessionValid query error instead of blanking the app", async () => {
  // The watcher is a sibling of `{children}`, above every error boundary an app
  // can install, so a deployment that has not caught up with the bundle would
  // take the whole page down. Reactive revocation degrades; sign-in does not.
  sessionStorage.setItem(
    "convex-logto:https://example.convex.cloud:txn",
    JSON.stringify({ state: "st" }),
  );
  (
    window as unknown as { happyDOM: { setURL: (url: string) => void } }
  ).happyDOM.setURL("http://localhost:5173/callback?code=c&state=st");
  await render(undefined);
  await vi.waitFor(() => expect(callback).toHaveBeenCalled());

  sessionValidResult = new Error(
    "Could not find public function for 'auth:sessionValid'",
  );
  await render(undefined);

  expect(capturedSignIn).not.toBeNull();
  const reports = authErrors.filter((error) =>
    error.message.includes("reactive revocation is off"),
  );
  // Exactly once. The wrapper is rebuilt inside the effect, so the engine's
  // identity dedupe cannot cover it; the watcher tracks the query error itself.
  expect(reports).toHaveLength(1);
});

it("reports convex_authenticated once Convex accepts the token, and only once", async () => {
  // The phase an app actually measures against: the first authenticated query.
  await render(undefined, (event) => authEvents.push(event));
  expect(authEvents.map((event) => event.phase)).not.toContain(
    "convex_authenticated",
  );

  convexAuthenticated = true;
  await render(undefined, (event) => authEvents.push(event));
  // Convex drops and regains auth on a reconnect or a forced token refresh;
  // that is not a second bootstrap, so it must not look like one.
  convexAuthenticated = false;
  await render(undefined, (event) => authEvents.push(event));
  convexAuthenticated = true;
  await render(undefined, (event) => authEvents.push(event));

  expect(
    authEvents.filter((event) => event.phase === "convex_authenticated"),
  ).toHaveLength(1);
});

it("stays silent until a handler exists, then reports from that point", async () => {
  // Opting out has to cost nothing, so the engine reads the handler per event
  // rather than wrapping one that may never arrive. A handler passed later then
  // sees the phases from then on — never a replayed bootstrap it missed.
  await render(undefined, undefined);
  expect(authEvents).toHaveLength(0);

  convexAuthenticated = true;
  await render(undefined, (event) => authEvents.push(event));

  expect(authEvents.map((event) => event.phase)).toEqual([
    "convex_authenticated",
  ]);
});

it("keeps one engine when only the event handler's identity changes", async () => {
  await render(undefined, () => {});
  const first = capturedSignIn;

  await render(undefined, () => {});

  expect(capturedSignIn).toBe(first);
});
