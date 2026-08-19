// @vitest-environment happy-dom
//
// `@logto/rn` does not proxy its errors the way the web SDK does — `signIn` and
// `signOut` reject — and the documented pattern is `void signIn()` in an
// `onPress`. These cover what an app can observe when either one fails.
import { act } from "react";
import { createRoot, type Root } from "react-dom/client";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { ConvexLogtoProvider, useLogtoAuth } from "./native";

(
  globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }
).IS_REACT_ACT_ENVIRONMENT = true;

const mockLogto = {
  isAuthenticated: false,
  isInitialized: true,
  getIdToken: vi.fn<() => Promise<string | undefined>>(async () => undefined),
  getAccessToken: vi.fn<() => Promise<string | undefined>>(
    async () => undefined,
  ),
  getIdTokenClaims: vi.fn<() => Promise<undefined>>(async () => undefined),
  signIn: vi.fn<(redirectUri: string) => Promise<void>>(async () => {}),
  signOut: vi.fn<() => Promise<void>>(async () => {}),
  client: { clearAccessToken: vi.fn<() => Promise<void>>(async () => {}) },
};

vi.mock("@logto/rn", () => ({
  LogtoProvider: ({ children }: { children: unknown }) => children,
  useLogto: () => mockLogto,
  UserScope: { Email: "email" },
}));
vi.mock("convex/react", () => ({
  ConvexProviderWithAuth: ({ children }: { children: unknown }) => children,
  useConvexAuth: () => ({ isLoading: false, isAuthenticated: false }),
}));

type AuthApi = ReturnType<typeof useLogtoAuth>;
let capturedApi: AuthApi | null = null;
function ApiProbe() {
  capturedApi = useLogtoAuth();
  return null;
}

let root: Root | null = null;
async function renderProvider(onAuthError?: (error: Error) => void) {
  root = createRoot(document.createElement("div"));
  await act(async () => {
    root!.render(
      <ConvexLogtoProvider
        client={{} as never}
        config={{ endpoint: "https://example.logto.app", appId: "app123" }}
        redirectUri="io.logto://callback"
        {...(onAuthError ? { onAuthError } : {})}
      >
        <ApiProbe />
      </ConvexLogtoProvider>,
    );
  });
}

beforeEach(() => {
  mockLogto.signIn.mockReset().mockResolvedValue(undefined);
  mockLogto.signOut.mockReset().mockResolvedValue(undefined);
});

afterEach(async () => {
  if (root) {
    const r = root;
    root = null;
    await act(async () => {
      r.unmount();
    });
  }
  capturedApi = null;
});

it("reports a dismissed sign-in instead of leaving an unhandled rejection", async () => {
  const failure = new Error("auth_session_failed");
  mockLogto.signIn.mockRejectedValue(failure);
  const onAuthError = vi.fn<(error: Error) => void>();
  const consoleError = vi.spyOn(console, "error").mockImplementation(() => {});
  try {
    await renderProvider(onAuthError);

    await expect(capturedApi!.signIn()).rejects.toBe(failure);
    expect(onAuthError).toHaveBeenCalledTimes(1);
    expect(onAuthError).toHaveBeenCalledWith(failure);
    expect(consoleError).toHaveBeenCalledTimes(1);
  } finally {
    consoleError.mockRestore();
  }
});

it("reports a sign-out that left the user signed in", async () => {
  // `@logto/client` reaches OIDC discovery before it clears tokens, so an
  // offline sign-out throws with the session fully intact.
  const failure = new Error("failed to fetch openid-configuration");
  mockLogto.signOut.mockRejectedValue(failure);
  const onAuthError = vi.fn<(error: Error) => void>();
  const consoleError = vi.spyOn(console, "error").mockImplementation(() => {});
  try {
    await renderProvider(onAuthError);

    await expect(capturedApi!.signOut()).rejects.toBe(failure);
    expect(onAuthError).toHaveBeenCalledTimes(1);
    expect(onAuthError).toHaveBeenCalledWith(failure);
  } finally {
    consoleError.mockRestore();
  }
});

it("still logs when no onAuthError is provided", async () => {
  mockLogto.signOut.mockRejectedValue(new Error("offline"));
  const consoleError = vi.spyOn(console, "error").mockImplementation(() => {});
  try {
    await renderProvider();

    await expect(capturedApi!.signOut()).rejects.toThrow("offline");
    expect(consoleError).toHaveBeenCalledTimes(1);
  } finally {
    consoleError.mockRestore();
  }
});
