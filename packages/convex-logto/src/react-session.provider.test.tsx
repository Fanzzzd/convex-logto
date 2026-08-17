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
import type { LogtoSessionApi } from "./session";
import {
  ConvexLogtoSessionProvider,
  useLogtoAuth,
  type LogtoSessionClientDescriptor,
} from "./react-session";

(
  globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }
).IS_REACT_ACT_ENVIRONMENT = true;

vi.mock("convex/react", () => ({
  ConvexProviderWithAuth: ({ children }: { children: ReactNode }) => children,
  useConvexAuth: () => ({ isLoading: false, isAuthenticated: false }),
  useQuery: () => undefined,
}));

const callback = vi.fn();
const api = {
  signIn: { fn: "signIn" },
  callback: { fn: "callback" },
  refresh: { fn: "refresh" },
  signOut: { fn: "signOut" },
  signOutEverywhere: { fn: "signOutEverywhere" },
  listSessions: { fn: "listSessions" },
  renameSession: { fn: "renameSession" },
  revokeSession: { fn: "revokeSession" },
  sessionValid: { fn: "sessionValid" },
} as unknown as LogtoSessionApi;

const client = {
  url: "https://example.convex.cloud",
  action: (reference: unknown, args: unknown) => {
    if ((reference as { fn: string }).fn === "callback") return callback(args);
    return Promise.resolve({});
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
async function render(clientDescriptor?: LogtoSessionClientDescriptor) {
  root ??= createRoot(document.createElement("div"));
  await act(async () => {
    root!.render(
      <ConvexLogtoSessionProvider
        client={client}
        sessionApi={api}
        clientDescriptor={clientDescriptor}
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
