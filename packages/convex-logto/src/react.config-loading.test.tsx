// @vitest-environment happy-dom
import { act, useEffect } from "react";
import { createRoot } from "react-dom/client";
import { afterEach, expect, it, vi } from "vitest";
import { ConvexLogtoProvider as NativeConvexLogtoProvider } from "./native";
import { ConvexLogtoProvider } from "./react";

// React's act() needs this flag when driven without a test-framework integration.
(
  globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }
).IS_REACT_ACT_ENVIRONMENT = true;

// These tests cover the provider's config phases only, so both neighbors are
// stubbed to passthroughs — the Logto and Convex internals are irrelevant here.
vi.mock("@logto/react", () => ({
  LogtoProvider: ({ children }: { children: unknown }) => children,
  useLogto: () => ({
    isAuthenticated: false,
    isLoading: false,
    getIdToken: async () => undefined,
    getAccessToken: async () => undefined,
    clearAccessToken: async () => {},
  }),
  useHandleSignInCallback: () => ({
    isLoading: false,
    isAuthenticated: false,
    error: undefined,
  }),
  UserScope: { Email: "email" },
}));
vi.mock("@logto/rn", () => ({
  LogtoProvider: ({ children }: { children: unknown }) => children,
  useLogto: () => ({
    isAuthenticated: false,
    isInitialized: true,
    getIdToken: async () => undefined,
    getAccessToken: async () => undefined,
    client: { clearAccessToken: async () => {} },
  }),
  UserScope: { Email: "email" },
}));
vi.mock("convex/react", () => ({
  ConvexProviderWithAuth: ({ children }: { children: unknown }) => children,
  useConvexAuth: () => ({ isLoading: true, isAuthenticated: false }),
}));

let mountCount = 0;
let renderedProbe = false;
function Probe() {
  renderedProbe = true;
  useEffect(() => {
    mountCount += 1;
  }, []);
  return <span>CHILDREN</span>;
}

afterEach(() => {
  mountCount = 0;
  renderedProbe = false;
});

const config = { endpoint: "https://example.logto.app", appId: "app123" };

it("configQuery mode: renders fallback while loading, then mounts children exactly once", async () => {
  let resolveConfig!: (c: typeof config) => void;
  const configPromise = new Promise<typeof config>((r) => {
    resolveConfig = r;
  });
  const fakeClientValue = { query: () => configPromise };
  const fakeClient = fakeClientValue as never;

  const container = document.createElement("div");
  const root = createRoot(container);
  await act(async () => {
    root.render(
      <ConvexLogtoProvider
        client={fakeClient}
        configQuery={"cfg" as never}
        fallback={<span>SPLASH</span>}
      >
        <Probe />
      </ConvexLogtoProvider>,
    );
  });

  // Loading: the fallback shows and the auth tree does not exist yet — so
  // nothing (like a signIn call) can build Logto state against a half-ready
  // provider, which is the class of bug the old inert-client remount guarded.
  expect(container.textContent).toBe("SPLASH");
  expect(renderedProbe).toBe(false);

  await act(async () => {
    resolveConfig(config);
    await configPromise;
  });

  expect(container.textContent).toBe("CHILDREN");
  expect(mountCount).toBe(1);

  // Re-render with fresh prop identities: children must not remount.
  await act(async () => {
    root.render(
      <ConvexLogtoProvider
        client={fakeClient}
        configQuery={"cfg" as never}
        fallback={<span>SPLASH</span>}
        scopes={[]}
      >
        <Probe />
      </ConvexLogtoProvider>,
    );
  });
  expect(mountCount).toBe(1);

  await act(async () => {
    root.unmount();
  });
});

it("static config mode: children mount immediately, no fallback frame", async () => {
  const fakeClientValue = {
    query: () => {
      throw new Error("must not query in static config mode");
    },
  };
  const fakeClient = fakeClientValue as never;

  const container = document.createElement("div");
  const root = createRoot(container);
  await act(async () => {
    root.render(
      <ConvexLogtoProvider
        client={fakeClient}
        config={config}
        fallback={<span>SPLASH</span>}
      >
        <Probe />
      </ConvexLogtoProvider>,
    );
  });

  expect(container.textContent).toBe("CHILDREN");
  expect(mountCount).toBe(1);

  await act(async () => {
    root.unmount();
  });
});

it("static config mode rejects an unsafe endpoint before mounting Logto", async () => {
  const container = document.createElement("div");
  const root = createRoot(container);
  const consoleError = vi.spyOn(console, "error").mockImplementation(() => {});
  try {
    expect(() => {
      act(() => {
        root.render(
          <ConvexLogtoProvider
            client={{} as never}
            config={{ endpoint: "javascript:alert(1)", appId: "app123" }}
          >
            <Probe />
          </ConvexLogtoProvider>,
        );
      });
    }).toThrow(/https?:/i);
    expect(renderedProbe).toBe(false);
  } finally {
    consoleError.mockRestore();
    await act(async () => {
      root.unmount();
    });
  }
});

it("native static config rejects an unsafe endpoint before mounting Logto", async () => {
  const container = document.createElement("div");
  const root = createRoot(container);
  const consoleError = vi.spyOn(console, "error").mockImplementation(() => {});
  try {
    expect(() => {
      act(() => {
        root.render(
          <NativeConvexLogtoProvider
            client={{} as never}
            redirectUri="io.logto://callback"
            config={{
              endpoint: "https://alice@auth.example.com",
              appId: "app123",
            }}
          >
            <span>CHILDREN</span>
          </NativeConvexLogtoProvider>,
        );
      });
    }).toThrow(/credentials/i);
    expect(container.textContent).toBe("");
  } finally {
    consoleError.mockRestore();
    await act(async () => {
      root.unmount();
    });
  }
});

it("native static config permits explicitly opted-in self-hosted HTTP", async () => {
  const container = document.createElement("div");
  const root = createRoot(container);
  await act(async () => {
    root.render(
      <NativeConvexLogtoProvider
        client={{} as never}
        redirectUri="io.logto://callback"
        config={{
          endpoint: "http://logto.internal/prefix/",
          appId: "app123",
          allowInsecureHttp: true,
        }}
      >
        <span>CHILDREN</span>
      </NativeConvexLogtoProvider>,
    );
  });
  expect(container.textContent).toBe("CHILDREN");
  await act(async () => {
    root.unmount();
  });
});

// The union makes "neither prop" unrepresentable in TS; plain-JS callers can
// still do it, so exercise the runtime guard through a loosened component type.
const LooseProvider = ConvexLogtoProvider as unknown as (props: {
  client: unknown;
  children?: unknown;
}) => ReturnType<typeof ConvexLogtoProvider>;

it("throws when neither config nor configQuery is passed (plain-JS misuse)", async () => {
  const container = document.createElement("div");
  const root = createRoot(container);
  const consoleError = vi.spyOn(console, "error").mockImplementation(() => {});
  try {
    expect(() => {
      act(() => {
        root.render(
          <LooseProvider client={{}}>
            <Probe />
          </LooseProvider>,
        );
      });
    }).toThrow(/pass either `config`/);
  } finally {
    consoleError.mockRestore();
    await act(async () => {
      root.unmount();
    });
  }
});
