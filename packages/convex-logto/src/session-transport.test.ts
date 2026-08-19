import { afterEach, expect, it, vi } from "vitest";
import { ConvexError } from "convex/values";
import { makeFunctionReference } from "convex/server";
import type { ConvexReactClient } from "convex/react";
import { defaultSessionTransport } from "./session-transport";

const refresh = makeFunctionReference<"action">("auth:refresh");

function jsonResponse(body: unknown) {
  return new Response(JSON.stringify(body), {
    status: 200,
    headers: { "Content-Type": "application/json" },
  });
}

afterEach(() => vi.unstubAllGlobals());

it("sends actions over HTTP instead of the app's client", async () => {
  // Convex stops the WebSocket before asking for a fresh token; an action sent
  // on that client parks forever and the socket is never restarted.
  const fetchStub = vi.fn(() =>
    Promise.resolve(jsonResponse({ status: "success", value: { ok: true } })),
  );
  vi.stubGlobal("fetch", fetchStub);
  const clientAction = vi.fn();
  const client = {
    url: "https://example.convex.cloud",
    action: clientAction,
  } as unknown as ConvexReactClient;

  const result = await defaultSessionTransport(client).action(refresh, {
    sessionToken: "st",
  });

  expect(result).toEqual({ ok: true });
  expect(clientAction).not.toHaveBeenCalled();
  const [url, init] = fetchStub.mock.calls[0] as unknown as [
    string,
    { method: string; body: string },
  ];
  expect(url).toBe("https://example.convex.cloud/api/action");
  expect(init.method).toBe("POST");
  expect(JSON.parse(init.body)).toMatchObject({
    path: "auth:refresh",
    args: [{ sessionToken: "st" }],
  });
});

it("keeps the ConvexError payload the session error taxonomy reads", async () => {
  // `terminal` vs `transient` is decided from `error.data`, so the HTTP channel
  // has to reconstruct it the way the WebSocket client does.
  vi.stubGlobal("fetch", () =>
    Promise.resolve(
      jsonResponse({
        status: "error",
        errorMessage: "session revoked",
        errorData: { kind: "terminal" },
      }),
    ),
  );
  const client = {
    url: "https://example.convex.cloud",
    action: vi.fn(),
  } as unknown as ConvexReactClient;

  const error = await defaultSessionTransport(client)
    .action(refresh, { sessionToken: "st" })
    .catch((thrown: unknown) => thrown);

  expect(error).toBeInstanceOf(ConvexError);
  expect((error as ConvexError<{ kind: string }>).data).toEqual({
    kind: "terminal",
  });
});

it("falls back to the client when it exposes no deployment URL", async () => {
  // `ConvexReactClient.url` exists on every supported version — a client-shaped
  // stub should still mount rather than throw.
  const clientAction = vi.fn(() => Promise.resolve("client"));
  const client = { action: clientAction } as unknown as ConvexReactClient;

  const result = await defaultSessionTransport(client).action(refresh, {
    sessionToken: "st",
  });

  expect(result).toBe("client");
  expect(clientAction).toHaveBeenCalledWith(refresh, { sessionToken: "st" });
});
