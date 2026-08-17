import { describe, expect, it, vi } from "vitest";
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
