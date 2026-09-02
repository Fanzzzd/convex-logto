import { describe, expect, it, vi } from "vitest";
import { ORGANIZATIONS_SCOPE } from "./claims";
import {
  assertSubjectHasActiveSession,
  assertUserHasActiveSession,
  logtoSessionApi,
  type LogtoSessionComponent,
} from "./session";

it("keeps the legacy assertion name as a deprecated compatibility alias", () => {
  expect(assertUserHasActiveSession).toBe(assertSubjectHasActiveSession);
});

describe("assertSubjectHasActiveSession", () => {
  it("allows a bearer when another active session remains for its subject", async () => {
    const query = { fn: "hasActiveSessionForSubject" };
    const component = {
      lib: { hasActiveSessionForSubject: query },
    } as unknown as LogtoSessionComponent;
    const runQuery = vi.fn().mockResolvedValue(true);
    const ctx = {
      auth: {
        getUserIdentity: vi.fn().mockResolvedValue({ subject: "user-1" }),
      },
      runQuery,
    };

    await expect(
      assertSubjectHasActiveSession(ctx, component),
    ).resolves.toBeUndefined();
    expect(runQuery).toHaveBeenCalledWith(query, { subject: "user-1" });
  });

  it("rejects when no active session remains for the subject", async () => {
    const component = {
      lib: { hasActiveSessionForSubject: { fn: "active" } },
    } as unknown as LogtoSessionComponent;
    const ctx = {
      auth: {
        getUserIdentity: vi.fn().mockResolvedValue({ subject: "user-1" }),
      },
      runQuery: vi.fn().mockResolvedValue(false),
    };

    await expect(
      assertSubjectHasActiveSession(ctx, component),
    ).rejects.toMatchObject({
      data: { kind: "terminal", code: "session_revoked" },
    });
  });
});

describe("logtoSessionApi signOutEverywhere", () => {
  it("passes the default reuse policy and builds logout without an ID-token hint", async () => {
    const action = { fn: "killSubjectSessionsByToken" };
    const component = {
      lib: { killSubjectSessionsByToken: action },
    } as unknown as LogtoSessionComponent;
    const api = logtoSessionApi(component, {
      endpoint: "https://auth.example.com",
      appId: "app-1",
      clientSecret: "secret",
    });
    const runAction = vi.fn().mockResolvedValue({
      outcome: "signed-out",
      count: 3,
      subject: "subject-from-session",
    });
    const now = vi.spyOn(Date, "now").mockReturnValue(1_234_567);
    type Handler = (
      ctx: { runAction: typeof runAction },
      args: {
        sessionToken: string;
        deviceProof?: string;
        postLogoutRedirectUri?: string;
      },
    ) => Promise<{ endSessionUrl?: string; count: number }>;
    const handler = (
      api.signOutEverywhere as unknown as Record<string, Handler>
    )["_handler"]!;

    const result = await handler(
      { runAction },
      {
        sessionToken: "caller-session-token",
        deviceProof: "device-proof",
        postLogoutRedirectUri: "https://app.example.com/signed-out",
      },
    );

    expect(runAction).toHaveBeenCalledWith(action, {
      sessionToken: "caller-session-token",
      deviceProof: "device-proof",
      now: 1_234_567,
      reuseWindowMs: 10_000,
    });
    now.mockRestore();
    expect(result.count).toBe(3);
    const endSessionUrl = new URL(result.endSessionUrl!);
    expect(endSessionUrl.origin).toBe("https://auth.example.com");
    expect(endSessionUrl.pathname).toBe("/oidc/session/end");
    expect(endSessionUrl.searchParams.get("client_id")).toBe("app-1");
    expect(endSessionUrl.searchParams.get("post_logout_redirect_uri")).toBe(
      "https://app.example.com/signed-out",
    );
    expect(endSessionUrl.searchParams.get("id_token_hint")).toBeNull();
  });

  it("turns committed stale-token containment into the terminal reuse error", async () => {
    const action = { fn: "killSubjectSessionsByToken" };
    const component = {
      lib: { killSubjectSessionsByToken: action },
    } as unknown as LogtoSessionComponent;
    const api = logtoSessionApi(component, {
      endpoint: "https://auth.example.com",
      appId: "app-1",
      clientSecret: "secret",
      reuseWindowMs: 321,
    });
    const runAction = vi.fn().mockResolvedValue({ outcome: "reuse" });
    type Handler = (
      ctx: { runAction: typeof runAction },
      args: { sessionToken: string },
    ) => Promise<{ endSessionUrl?: string; count: number }>;
    const handler = (
      api.signOutEverywhere as unknown as Record<string, Handler>
    )["_handler"]!;

    await expect(
      handler({ runAction }, { sessionToken: "stale-token" }),
    ).rejects.toMatchObject({
      data: {
        kind: "terminal",
        code: "session_reuse_detected",
      },
    });
    expect(runAction).toHaveBeenCalledWith(action, {
      sessionToken: "stale-token",
      deviceProof: undefined,
      now: expect.any(Number),
      reuseWindowMs: 321,
    });
  });
});

describe("logtoSessionApi signOut", () => {
  it("passes the configured legacy reuse window to the component", async () => {
    const action = { fn: "signOut" };
    const component = {
      lib: { signOut: action },
    } as unknown as LogtoSessionComponent;
    const api = logtoSessionApi(component, {
      endpoint: "https://auth.example.com",
      appId: "app-1",
      clientSecret: "secret",
      reuseWindowMs: 321,
    });
    const runAction = vi.fn().mockResolvedValue({});
    type Handler = (
      ctx: { runAction: typeof runAction },
      args: { sessionToken: string; deviceProof?: string },
    ) => Promise<{ endSessionUrl?: string }>;
    const handler = (api.signOut as unknown as Record<string, Handler>)[
      "_handler"
    ]!;

    await handler(
      { runAction },
      { sessionToken: "session-token", deviceProof: "device-proof" },
    );

    expect(runAction).toHaveBeenCalledWith(action, {
      endpoint: "https://auth.example.com",
      appId: "app-1",
      clientSecret: "secret",
      sessionToken: "session-token",
      deviceProof: "device-proof",
      postLogoutRedirectUri: undefined,
      reuseWindowMs: 321,
    });
  });
});

describe("logtoSessionApi exchangeToken", () => {
  const action = { fn: "exchangeToken" };
  const component = {
    lib: { exchangeToken: action },
  } as unknown as LogtoSessionComponent;

  type Handler = (
    ctx: { runAction: ReturnType<typeof vi.fn> },
    args: {
      sessionToken: string;
      deviceProof?: string;
      organizationId?: string;
      resource?: string;
      scopes?: string[];
      includeToken?: boolean;
    },
  ) => Promise<{
    claims: { audience: string; scopes: string[]; expiresAt: number };
    accessToken?: string;
    minted: boolean;
  }>;

  /**
   * `scopes` carries the organization scope by default because the handler
   * refuses an organization exchange without it. Logto answers
   * `403 insufficient_scope`, and no retry can fix a grant that is already
   * signed. Tests about *that* rule pass their own `scopes`.
   */
  function handlerFor(options: Record<string, unknown> = {}) {
    const api = logtoSessionApi(component, {
      endpoint: "https://auth.example.com",
      appId: "app-1",
      clientSecret: "secret",
      scopes: [ORGANIZATIONS_SCOPE],
      ...options,
    });
    return (api.exchangeToken as unknown as Record<string, Handler>)[
      "_handler"
    ]!;
  }

  it("forwards the target and the deployment's reuse policy", async () => {
    const runAction = vi.fn().mockResolvedValue({
      claims: {
        audience: "organization:org-1",
        scopes: ["manage"],
        expiresAt: 5_000_000,
      },
      minted: true,
    });

    await handlerFor({ reuseWindowMs: 321 })(
      { runAction },
      {
        sessionToken: "session-token",
        deviceProof: "proof",
        organizationId: "org-1",
        scopes: ["manage"],
      },
    );

    expect(runAction).toHaveBeenCalledWith(action, {
      endpoint: "https://auth.example.com",
      appId: "app-1",
      clientSecret: "secret",
      sessionToken: "session-token",
      deviceProof: "proof",
      organizationId: "org-1",
      resource: undefined,
      scopes: ["manage"],
      includeToken: undefined,
      reuseWindowMs: 321,
    });
  });

  it("refuses an organization token the grant can never satisfy", async () => {
    // Measured against a real Logto. Without `urn:logto:scope:organizations`
    // the token endpoint answers `403 insufficient_scope`. Scopes are fixed at
    // authorization time, so no retry and no `forceRefresh` can rescue an
    // existing session, and letting it through spends a refresh claim on a
    // request that cannot work.
    const runAction = vi.fn();
    await expect(
      handlerFor({ scopes: [] })(
        { runAction },
        { sessionToken: "session-token", organizationId: "org-1" },
      ),
    ).rejects.toMatchObject({
      data: { kind: "terminal", code: "organizations_scope_missing" },
    });
    expect(runAction).not.toHaveBeenCalled();
  });

  it("does not require that scope for a resource token", async () => {
    // Resources are named by `resources`, not by the organization scope.
    const runAction = vi.fn().mockResolvedValue({
      claims: {
        audience: "resource:https://api.example.com",
        scopes: [],
        expiresAt: 5_000_000,
      },
      minted: true,
    });
    await handlerFor({ scopes: [] })(
      { runAction },
      { sessionToken: "session-token", resource: "https://api.example.com" },
    );
    expect(runAction).toHaveBeenCalled();
  });

  it("refuses to hand back a token string unless the deployment opted in", async () => {
    // Refusing beats silently returning claims. The caller is about to put the
    // value in an Authorization header, and `undefined` would appear as an
    // authorization failure somewhere else entirely.
    const runAction = vi.fn();
    await expect(
      handlerFor()(
        { runAction },
        {
          sessionToken: "session-token",
          organizationId: "org-1",
          includeToken: true,
        },
      ),
    ).rejects.toMatchObject({
      data: { kind: "terminal", code: "access_tokens_not_exposed" },
    });
    expect(runAction).not.toHaveBeenCalled();
  });

  it("allows the token string once exposeAccessTokens is set", async () => {
    const runAction = vi.fn().mockResolvedValue({
      claims: {
        audience: "resource:https://api.example.com",
        scopes: ["read"],
        expiresAt: 5_000_000,
      },
      accessToken: "minted",
      minted: true,
    });

    const result = await handlerFor({ exposeAccessTokens: true })(
      { runAction },
      {
        sessionToken: "session-token",
        resource: "https://api.example.com",
        includeToken: true,
      },
    );

    expect(result.accessToken).toBe("minted");
    expect(runAction).toHaveBeenCalledWith(
      action,
      expect.objectContaining({ includeToken: true }),
    );
  });

  it("serves claims without the opt-in, which is the default custody", async () => {
    const runAction = vi.fn().mockResolvedValue({
      claims: {
        audience: "organization:org-1",
        scopes: ["manage"],
        expiresAt: 5_000_000,
      },
      minted: false,
    });

    const result = await handlerFor()(
      { runAction },
      { sessionToken: "session-token", organizationId: "org-1" },
    );

    expect(result).toEqual({
      claims: {
        audience: "organization:org-1",
        scopes: ["manage"],
        expiresAt: 5_000_000,
      },
      minted: false,
    });
  });
});

describe("logtoSessionApi exchangeToken targets", () => {
  it("refuses a target-free call before it becomes a component round trip", async () => {
    const action = { fn: "exchangeToken" };
    const component = {
      lib: { exchangeToken: action },
    } as unknown as LogtoSessionComponent;
    const api = logtoSessionApi(component, {
      endpoint: "https://auth.example.com",
      appId: "app-1",
      clientSecret: "secret",
    });
    const runAction = vi.fn();
    type Handler = (
      ctx: { runAction: typeof runAction },
      args: { sessionToken: string },
    ) => Promise<unknown>;
    const handler = (api.exchangeToken as unknown as Record<string, Handler>)[
      "_handler"
    ]!;

    await expect(
      handler({ runAction }, { sessionToken: "session-token" }),
    ).rejects.toMatchObject({
      data: { kind: "terminal", code: "missing_token_target" },
    });
    expect(runAction).not.toHaveBeenCalled();
  });
});
