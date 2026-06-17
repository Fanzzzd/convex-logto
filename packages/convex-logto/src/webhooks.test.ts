import { createHmac } from "node:crypto";
import { httpRouter } from "convex/server";
import { describe, expect, it, vi } from "vitest";
import { registerLogtoWebhook, verifyLogtoSignature } from "./webhooks";

const signingKey = "whsec_test_signing_key_1234567890";
const body = JSON.stringify({
  hookId: "h1",
  event: "User.Created",
  createdAt: "2026-06-14T00:00:00.000Z",
  data: { id: "user_abc", primaryEmail: "a@b.com", name: "Ada" },
});

const sign = (key: string, payload: Buffer | string) =>
  createHmac("sha256", key).update(payload).digest("hex");

describe("verifyLogtoSignature", () => {
  it("accepts a correct signature", async () => {
    expect(
      await verifyLogtoSignature(signingKey, body, sign(signingKey, body)),
    ).toBe(true);
  });

  it("accepts uppercase hex (Web Crypto emits lowercase)", async () => {
    expect(
      await verifyLogtoSignature(
        signingKey,
        body,
        sign(signingKey, body).toUpperCase(),
      ),
    ).toBe(true);
  });

  it("accepts a valid signature with surrounding whitespace (trimmed)", async () => {
    expect(
      await verifyLogtoSignature(
        signingKey,
        body,
        `  ${sign(signingKey, body)}\n`,
      ),
    ).toBe(true);
  });

  it("verifies non-ASCII bodies over the exact bytes", async () => {
    // The webhook route hands raw bytes (request.arrayBuffer()); Logto signs
    // those bytes, so re-encoding a decoded string must not change the result.
    const unicode = JSON.stringify({
      event: "User.Created",
      data: { id: "u1", name: "测试🚀" },
    });
    const bytes = Buffer.from(unicode, "utf8");
    const arrayBuffer = new Uint8Array(bytes).buffer; // exact bytes, as request.arrayBuffer() yields
    expect(
      await verifyLogtoSignature(
        signingKey,
        arrayBuffer,
        sign(signingKey, bytes),
      ),
    ).toBe(true);
  });

  it("rejects a tampered body", async () => {
    expect(
      await verifyLogtoSignature(
        signingKey,
        body + " ",
        sign(signingKey, body),
      ),
    ).toBe(false);
  });

  it("rejects a wrong signing key", async () => {
    expect(
      await verifyLogtoSignature(signingKey, body, sign("other_key", body)),
    ).toBe(false);
  });

  it("rejects an empty signature", async () => {
    expect(await verifyLogtoSignature(signingKey, body, "")).toBe(false);
  });

  it("rejects a too-short hex signature", async () => {
    expect(await verifyLogtoSignature(signingKey, body, "abc123")).toBe(false);
  });

  it("rejects a 64-char signature with a non-hex character", async () => {
    // Same length as a real digest, so only the hex-shape guard can reject it.
    const nonHex = `g${sign(signingKey, body).slice(1)}`;
    expect(await verifyLogtoSignature(signingKey, body, nonHex)).toBe(false);
  });
});

// `registerLogtoWebhook` calls `http.route` with an `httpActionGeneric` wrapper.
// We register it on a real `httpRouter()` and resolve it back with `http.lookup`
// — the same path + method matching Convex's runtime uses — so a route registered
// at the wrong path or method fails these tests, not just a status-code regression.
// Convex attaches the raw `(ctx, request) => Response` as `._handler`, which lets
// us drive the handler directly without a Convex runtime.
type RouteHandler = (
  ctx: { runMutation: (ref: unknown, args: unknown) => Promise<unknown> },
  request: Request,
) => Promise<Response>;

function captureWebhookRoute(options?: {
  path?: string;
  signingKey?: string;
}): RouteHandler {
  const http = httpRouter();
  // `sync` is only forwarded to `ctx.runMutation`; an opaque ref is enough here.
  registerLogtoWebhook(http, {} as never, options);
  const path = options?.path ?? "/logto/webhook";
  const match = http.lookup(path, "POST");
  if (!match) throw new Error(`no POST route registered at ${path}`);
  // Bracket access: `_handler` is convex's internal, not part of its public type.
  const handler = (match[0] as unknown as Record<string, RouteHandler>)[
    "_handler"
  ];
  if (!handler) throw new Error("webhook route handler was not captured");
  return handler;
}

const post = (signature: string, payload: string) =>
  new Request("http://convex.test/logto/webhook", {
    method: "POST",
    headers: signature ? { "logto-signature-sha-256": signature } : {},
    body: payload,
  });

describe("registerLogtoWebhook route", () => {
  it("returns 500 when the signing key is empty/unset", async () => {
    const handler = captureWebhookRoute({ signingKey: "" });
    const runMutation = vi.fn();
    const res = await handler(
      { runMutation },
      post(sign(signingKey, body), body),
    );
    expect(res.status).toBe(500);
    expect(runMutation).not.toHaveBeenCalled();
  });

  it("returns 401 on a bad signature, without dispatching", async () => {
    const handler = captureWebhookRoute({ signingKey });
    const runMutation = vi.fn();
    const res = await handler(
      { runMutation },
      post(sign("wrong_key", body), body),
    );
    expect(res.status).toBe(401);
    expect(runMutation).not.toHaveBeenCalled();
  });

  it("returns 400 on a malformed JSON body (valid signature)", async () => {
    const handler = captureWebhookRoute({ signingKey });
    const malformed = "{not json";
    const runMutation = vi.fn();
    const res = await handler(
      { runMutation },
      post(sign(signingKey, malformed), malformed),
    );
    expect(res.status).toBe(400);
    expect(runMutation).not.toHaveBeenCalled();
  });

  it("returns 400 on an unknown event (valid signature)", async () => {
    const handler = captureWebhookRoute({ signingKey });
    const unknown = JSON.stringify({
      event: "Organization.Created",
      data: { id: "org_1" },
    });
    const runMutation = vi.fn();
    const res = await handler(
      { runMutation },
      post(sign(signingKey, unknown), unknown),
    );
    expect(res.status).toBe(400);
    expect(runMutation).not.toHaveBeenCalled();
  });

  it("returns 200 and dispatches the parsed payload on a valid delivery", async () => {
    const handler = captureWebhookRoute({ signingKey });
    const runMutation = vi.fn().mockResolvedValue(null);
    const res = await handler(
      { runMutation },
      post(sign(signingKey, body), body),
    );
    expect(res.status).toBe(200);
    expect(runMutation).toHaveBeenCalledTimes(1);
    expect(runMutation).toHaveBeenCalledWith(expect.anything(), {
      payload: expect.objectContaining({ event: "User.Created" }),
    });
  });

  it("honors a custom path and dispatches there", async () => {
    // captureWebhookRoute looks up this exact path, so it already asserts the
    // `path` option is wired through; confirm the handler then works end-to-end.
    const handler = captureWebhookRoute({ signingKey, path: "/hooks/logto" });
    const runMutation = vi.fn().mockResolvedValue(null);
    const res = await handler(
      { runMutation },
      post(sign(signingKey, body), body),
    );
    expect(res.status).toBe(200);
    expect(runMutation).toHaveBeenCalledTimes(1);
  });
});
