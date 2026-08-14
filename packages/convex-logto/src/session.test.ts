import { describe, expect, it, vi } from "vitest";
import { hashToken } from "./component/core";
import { logtoSessionApi, type LogtoSessionComponent } from "./session";

describe("logtoSessionApi signOutEverywhere", () => {
  it("passes the default reuse policy and builds logout without an ID-token hint", async () => {
    const mutation = { fn: "killSubjectSessionsByToken" };
    const component = {
      lib: { killSubjectSessionsByToken: mutation },
    } as unknown as LogtoSessionComponent;
    const api = logtoSessionApi(component, {
      endpoint: "https://auth.example.com",
      appId: "app-1",
      clientSecret: "secret",
    });
    const runMutation = vi.fn().mockResolvedValue({
      outcome: "signed-out",
      count: 3,
      subject: "subject-from-session",
    });
    const now = vi.spyOn(Date, "now").mockReturnValue(1_234_567);
    type Handler = (
      ctx: { runMutation: typeof runMutation },
      args: { sessionToken: string; postLogoutRedirectUri?: string },
    ) => Promise<{ endSessionUrl?: string; count: number }>;
    const handler = (
      api.signOutEverywhere as unknown as Record<string, Handler>
    )["_handler"]!;

    const result = await handler(
      { runMutation },
      {
        sessionToken: "caller-session-token",
        postLogoutRedirectUri: "https://app.example.com/signed-out",
      },
    );

    expect(runMutation).toHaveBeenCalledWith(mutation, {
      presentedHash: await hashToken("caller-session-token"),
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
    const mutation = { fn: "killSubjectSessionsByToken" };
    const component = {
      lib: { killSubjectSessionsByToken: mutation },
    } as unknown as LogtoSessionComponent;
    const api = logtoSessionApi(component, {
      endpoint: "https://auth.example.com",
      appId: "app-1",
      clientSecret: "secret",
      reuseWindowMs: 321,
    });
    const runMutation = vi.fn().mockResolvedValue({ outcome: "reuse" });
    type Handler = (
      ctx: { runMutation: typeof runMutation },
      args: { sessionToken: string },
    ) => Promise<{ endSessionUrl?: string; count: number }>;
    const handler = (
      api.signOutEverywhere as unknown as Record<string, Handler>
    )["_handler"]!;

    await expect(
      handler({ runMutation }, { sessionToken: "stale-token" }),
    ).rejects.toMatchObject({
      data: {
        kind: "terminal",
        code: "session_reuse_detected",
      },
    });
    expect(runMutation).toHaveBeenCalledWith(mutation, {
      presentedHash: await hashToken("stale-token"),
      now: expect.any(Number),
      reuseWindowMs: 321,
    });
  });
});
