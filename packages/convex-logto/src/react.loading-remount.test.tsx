// @vitest-environment happy-dom
import { act } from "react";
import { createRoot } from "react-dom/client";
import { useLogto } from "@logto/react";
import { afterEach, expect, it, vi } from "vitest";
import { ConvexLogtoProvider } from "./react";

// React's act() needs this flag when driven without a test-framework integration.
(
  globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }
).IS_REACT_ACT_ENVIRONMENT = true;

// The bug and its fix live entirely in this package's <LogtoProvider> keying, so we
// stub Convex out — ConvexProviderWithAuth just renders children (keeping the probe
// under the real <LogtoProvider>), and useConvexAuth is never reached in this path.
vi.mock("convex/react", () => ({
  ConvexProviderWithAuth: ({ children }: { children: unknown }) => children,
  useConvexAuth: () => ({ isLoading: true, isAuthenticated: false }),
}));

// The "real" Logto client used once config is ready. isAuthenticated resolves false
// (no network, no storage) so the provider's mount effect decrements loadingCount;
// the rest is the minimal surface @logto/react may touch after the swap.
vi.mock("@logto/browser", () => ({
  default: class {
    async isAuthenticated() {
      return false;
    }
    async signIn() {}
    async isSignInRedirected() {
      return false;
    }
    async handleSignInCallback() {}
    async getIdTokenClaims() {
      return undefined;
    }
  },
}));

let captured: {
  isLoading: boolean;
  signIn: (uri: string) => Promise<void>;
} | null = null;
function Probe() {
  const { isLoading, signIn } = useLogto();
  captured = { isLoading, signIn };
  return null;
}

afterEach(() => {
  captured = null;
});

const flush = () => act(async () => void (await Promise.resolve()));

// Regression for the "stuck on the login button" report: calling signIn() while the
// inert loading-client is mounted poisons @logto/react's loadingCount (signIn never
// resets it and the inert method doesn't navigate). That count is provider state, so
// without remounting on the loading→ready swap it pins isLoading true forever. The
// `key` on <LogtoProvider> drops it. Fails on the un-keyed provider, passes with it.
it("recovers isLoading after a signIn during config load", async () => {
  let resolveConfig!: (c: { endpoint: string; appId: string }) => void;
  const configPromise = new Promise<{ endpoint: string; appId: string }>(
    (r) => {
      resolveConfig = r;
    },
  );
  const fakeClient = { query: () => configPromise } as never;

  const root = createRoot(document.createElement("div"));
  await act(async () => {
    root.render(
      <ConvexLogtoProvider client={fakeClient} configQuery={"cfg" as never}>
        <Probe />
      </ConvexLogtoProvider>,
    );
  });

  // Config still loading: the inert client holds isLoading true.
  expect(captured?.isLoading).toBe(true);

  // Poison: signIn while the inert client is up (a no-op that never navigates here).
  await act(async () => {
    await captured!.signIn("http://localhost/callback");
  });
  expect(captured?.isLoading).toBe(true);

  // Config arrives → the keyed provider remounts with the real client, dropping the
  // poisoned loadingCount, so isLoading must recover.
  await act(async () => {
    resolveConfig({
      endpoint: "https://example.logto.app",
      appId: "app1234567890",
    });
    await configPromise;
  });
  // Let the remount's mount effect run isAuthenticated() and decrement loadingCount.
  for (let i = 0; i < 10; i++) await flush();

  expect(captured?.isLoading).toBe(false);

  await act(async () => {
    root.unmount();
  });
});
