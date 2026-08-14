import { describe, expect, it, vi } from "vitest";
import { hashToken } from "./component/core";
import { logtoSessionApi, type LogtoSessionComponent } from "./session";

describe("logtoSessionApi signOutEverywhere", () => {
  it("hashes the caller token, delegates subject derivation, and builds federated logout", async () => {
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
      count: 3,
      subject: "subject-from-session",
      idTokenHint: "last-id-token",
    });
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
    });
    expect(result.count).toBe(3);
    const endSessionUrl = new URL(result.endSessionUrl!);
    expect(endSessionUrl.origin).toBe("https://auth.example.com");
    expect(endSessionUrl.pathname).toBe("/oidc/session/end");
    expect(endSessionUrl.searchParams.get("client_id")).toBe("app-1");
    expect(endSessionUrl.searchParams.get("post_logout_redirect_uri")).toBe(
      "https://app.example.com/signed-out",
    );
    expect(endSessionUrl.searchParams.get("id_token_hint")).toBe(
      "last-id-token",
    );
  });
});
