import { createHmac } from "node:crypto";
import { httpRouter } from "convex/server";
import { describe, expect, it, vi } from "vitest";
import {
  logtoSync,
  registerLogtoWebhook,
  verifyLogtoSignature,
} from "./webhooks";

const signingKey = "whsec_test_signing_key_1234567890";
// The route now enforces freshness on `createdAt`, so route-level tests build
// their payloads with a current timestamp.
const freshPayload = (overrides: Record<string, unknown> = {}) => ({
  hookId: "h1",
  event: "User.Created",
  createdAt: new Date().toISOString(),
  data: { id: "user_abc", primaryEmail: "a@b.com", name: "Ada" },
  ...overrides,
});
const body = JSON.stringify(freshPayload());

const sign = (key: string, payload: Uint8Array | string) =>
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
  ctx: {
    runMutation: (ref: unknown, args: unknown) => Promise<unknown>;
    runAction?: (ref: unknown, args: unknown) => Promise<unknown>;
  },
  request: Request,
) => Promise<Response>;

function captureWebhookRoute(
  options?: Parameters<typeof registerLogtoWebhook>[2],
): RouteHandler {
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

const post = (signature: string, payload: BodyInit, contentLength?: string) => {
  const headers = new Headers();
  if (signature) headers.set("logto-signature-sha-256", signature);
  if (contentLength !== undefined) {
    headers.set("Content-Length", contentLength);
  }
  return new Request("http://convex.test/logto/webhook", {
    method: "POST",
    headers,
    body: payload,
  });
};

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

  it.each([
    ["missing hookId", { hookId: undefined }],
    ["wrong profile field type", { data: { id: "u1", primaryEmail: 42 } }],
    [
      "wrong suspension flag type",
      {
        event: "User.SuspensionStatus.Updated",
        data: { id: "u1", isSuspended: "true" },
      },
    ],
  ])("returns 400 on a malformed known payload (%s)", async (_name, patch) => {
    const handler = captureWebhookRoute({ signingKey });
    const malformed = JSON.stringify(freshPayload(patch));
    const runMutation = vi.fn();
    const res = await handler(
      { runMutation },
      post(sign(signingKey, malformed), malformed),
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

  it.each([
    ["without Content-Length", undefined],
    ["with a falsely small Content-Length", "1"],
  ])(
    "returns 413 on an oversized body %s without touching handlers",
    async (_name, contentLength) => {
      const handler = captureWebhookRoute({ signingKey });
      const huge = JSON.stringify(
        freshPayload({ padding: "x".repeat(1024 * 1024) }),
      );
      const runMutation = vi.fn();
      const res = await handler(
        { runMutation },
        post(sign(signingKey, huge), huge, contentLength),
      );
      expect(res.status).toBe(413);
      expect(runMutation).not.toHaveBeenCalled();
    },
  );

  it("returns 400 when the request body stream fails", async () => {
    const handler = captureWebhookRoute({ signingKey });
    const stream = new ReadableStream<Uint8Array>({
      start(controller) {
        controller.error(new Error("read failed"));
      },
    });
    const failingRequest = new Request("http://convex.test/logto/webhook", {
      method: "POST",
      body: stream,
      duplex: "half",
    } as RequestInit);
    const runMutation = vi.fn();

    const response = await handler({ runMutation }, failingRequest);

    expect(response.status).toBe(400);
    expect(runMutation).not.toHaveBeenCalled();
  });

  it.each([
    ["6 minutes old", new Date(Date.now() - 6 * 60 * 1000).toISOString()],
    [
      "2 minutes in the future",
      new Date(Date.now() + 2 * 60 * 1000).toISOString(),
    ],
    ["not a date", "yesterday-ish"],
    ["missing", undefined],
  ])(
    "returns 400 on a stale/invalid createdAt (%s), even correctly signed",
    async (_name, createdAt) => {
      const handler = captureWebhookRoute({ signingKey });
      const payload = freshPayload();
      if (createdAt === undefined) {
        delete (payload as Record<string, unknown>).createdAt;
      } else {
        payload.createdAt = createdAt;
      }
      const stale = JSON.stringify(payload);
      const runMutation = vi.fn();
      const res = await handler(
        { runMutation },
        post(sign(signingKey, stale), stale),
      );
      expect(res.status).toBe(400);
      expect(runMutation).not.toHaveBeenCalled();
    },
  );

  it("accepts small clock skew (30s in the future)", async () => {
    const handler = captureWebhookRoute({ signingKey });
    const skewed = JSON.stringify(
      freshPayload({
        createdAt: new Date(Date.now() + 30 * 1000).toISOString(),
      }),
    );
    const runMutation = vi.fn().mockResolvedValue(null);
    const res = await handler(
      { runMutation },
      post(sign(signingKey, skewed), skewed),
    );
    expect(res.status).toBe(200);
  });
});

// --- the `sessions` option: dedupe + revocation wiring ----------------------

// Sentinel refs; the fake ctx dispatches runMutation calls on ref identity.
const SYNC_REF = { fn: "sync" };
const sessionsComponent = {
  lib: {
    recordWebhookDelivery: { fn: "record" },
    forgetWebhookDelivery: { fn: "forget" },
    killSubjectSessions: { fn: "kill" },
  },
} as never;

function sessionsHarness(overrides?: {
  record?: ReturnType<typeof vi.fn>;
  sync?: ReturnType<typeof vi.fn>;
}) {
  const calls: Array<{ fn: string; args: unknown }> = [];
  const handlers: Record<string, ReturnType<typeof vi.fn>> = {
    record: overrides?.record ?? vi.fn().mockResolvedValue(true),
    forget: vi.fn().mockResolvedValue(null),
    kill: vi.fn().mockResolvedValue(0),
    sync: overrides?.sync ?? vi.fn().mockResolvedValue(null),
  };
  const runMutation = vi.fn((ref: unknown, args: unknown) => {
    const fn = (ref as { fn?: string }).fn ?? "sync";
    calls.push({ fn, args });
    return handlers[fn]!(args);
  });
  const runAction = vi.fn((ref: unknown, args: unknown) => {
    const fn = (ref as { fn?: string }).fn ?? "kill";
    calls.push({ fn, args });
    return handlers[fn]!(args);
  });
  const http = httpRouter();
  registerLogtoWebhook(http, SYNC_REF as never, {
    signingKey,
    sessions: sessionsComponent,
  });
  const handler = (
    http.lookup("/logto/webhook", "POST")![0] as unknown as Record<
      string,
      RouteHandler
    >
  )["_handler"]!;
  return { handler, runMutation, runAction, handlers, calls };
}

describe("registerLogtoWebhook with sessions", () => {
  it("claims the delivery by body hash, then dispatches", async () => {
    const { handler, runMutation, runAction, handlers, calls } =
      sessionsHarness();
    const res = await handler(
      { runMutation, runAction },
      post(sign(signingKey, body), body),
    );
    expect(res.status).toBe(200);
    expect(handlers.record).toHaveBeenCalledWith(
      expect.objectContaining({
        bodyHash: expect.stringMatching(/^[0-9a-f]{64}$/),
      }),
    );
    expect(calls.map((c) => c.fn)).toEqual(["record", "sync"]);
  });

  it("answers 200 on a duplicate delivery WITHOUT re-running sync", async () => {
    const { handler, runMutation, runAction, handlers } = sessionsHarness({
      record: vi.fn().mockResolvedValue(false),
    });
    const res = await handler(
      { runMutation, runAction },
      post(sign(signingKey, body), body),
    );
    expect(res.status).toBe(200);
    expect(handlers.sync).not.toHaveBeenCalled();
    expect(handlers.kill).not.toHaveBeenCalled();
  });

  it("User.Deleted kills the subject's sessions before sync runs", async () => {
    const { handler, runMutation, runAction, handlers, calls } =
      sessionsHarness();
    const deleted = JSON.stringify(
      freshPayload({
        event: "User.Deleted",
        data: null,
        params: { userId: "u9" },
      }),
    );
    const res = await handler(
      { runMutation, runAction },
      post(sign(signingKey, deleted), deleted),
    );
    expect(res.status).toBe(200);
    expect(handlers.kill).toHaveBeenCalledWith({ subject: "u9" });
    expect(calls.map((c) => c.fn)).toEqual(["record", "kill", "sync"]);
  });

  it("accepts current User.Deleted payloads with matching entity and route ids", async () => {
    const { handler, runMutation, runAction, handlers, calls } =
      sessionsHarness();
    const deleted = JSON.stringify(
      freshPayload({
        event: "User.Deleted",
        data: {
          id: "u-current",
          primaryEmail: "former@example.com",
          name: "Former User",
        },
        params: { userId: "u-current" },
      }),
    );

    const response = await handler(
      { runMutation, runAction },
      post(sign(signingKey, deleted), deleted),
    );

    expect(response.status).toBe(200);
    expect(handlers.kill).toHaveBeenCalledWith({ subject: "u-current" });
    expect(calls.map((c) => c.fn)).toEqual(["record", "kill", "sync"]);
  });

  it("rejects User.Deleted when data.id and params.userId disagree", async () => {
    const { handler, runMutation, runAction, handlers } = sessionsHarness();
    const contradictoryDelete = JSON.stringify(
      freshPayload({
        event: "User.Deleted",
        data: { id: "data-user" },
        params: { userId: "params-user" },
      }),
    );

    const response = await handler(
      { runMutation, runAction },
      post(sign(signingKey, contradictoryDelete), contradictoryDelete),
    );

    expect(response.status).toBe(400);
    expect(handlers.record).not.toHaveBeenCalled();
    expect(handlers.kill).not.toHaveBeenCalled();
    expect(handlers.sync).not.toHaveBeenCalled();
  });

  it("suspension ON kills sessions; suspension OFF does not", async () => {
    for (const [isSuspended, killed] of [
      [true, true],
      [false, false],
    ] as const) {
      const { handler, runMutation, runAction, handlers } = sessionsHarness();
      const suspended = JSON.stringify(
        freshPayload({
          event: "User.SuspensionStatus.Updated",
          data: { id: "u5", isSuspended },
        }),
      );
      const res = await handler(
        { runMutation, runAction },
        post(sign(signingKey, suspended), suspended),
      );
      expect(res.status).toBe(200);
      if (killed) expect(handlers.kill).toHaveBeenCalledWith({ subject: "u5" });
      else expect(handlers.kill).not.toHaveBeenCalled();
    }
  });

  it("releases the dedupe claim when sync fails, so Logto's retry re-runs it", async () => {
    const { handler, runMutation, runAction, handlers } = sessionsHarness({
      sync: vi.fn().mockRejectedValue(new Error("handler exploded")),
    });
    await expect(
      handler({ runMutation, runAction }, post(sign(signingKey, body), body)),
    ).rejects.toThrow("handler exploded");
    expect(handlers.forget).toHaveBeenCalledWith(
      expect.objectContaining({
        bodyHash: expect.stringMatching(/^[0-9a-f]{64}$/),
      }),
    );
  });
});

// `logtoSync` returns an internal mutation; Convex attaches the raw handler as
// `._handler`, which lets us drive the dispatch logic directly with a fake ctx
// (no Convex runtime). Type-level coverage of the `ctx.db` cast lives in
// webhooks.test-d.ts (checked by `tsc`, not vitest).
type SyncHandler = (
  ctx: unknown,
  args: { payload: unknown },
) => Promise<unknown>;
const callSync = (
  sync: unknown,
  ctx: unknown,
  payload: unknown,
): Promise<unknown> =>
  // Bracket access: `_handler` is convex's internal, not part of its public type.
  (sync as unknown as Record<string, SyncHandler>)["_handler"](ctx, {
    payload,
  });

describe("Logto payload shapes", () => {
  it("accepts a User.Created whose lastSignInAt is null", async () => {
    // `users.last_sign_in_at` is nullable: a user who has never signed in
    // serialises as null. Rejecting it would drop a signed, authentic delivery.
    const handler = captureWebhookRoute({ signingKey });
    const payload = JSON.stringify(
      freshPayload({
        data: {
          id: "user_abc",
          primaryEmail: "a@b.com",
          lastSignInAt: null,
          createdAt: 1_700_000_000_000,
        },
      }),
    );
    const runMutation = vi.fn();
    const res = await handler(
      { runMutation },
      post(sign(signingKey, payload), payload),
    );

    expect(res.status).toBe(200);
    expect(runMutation).toHaveBeenCalledTimes(1);
  });

  it("accepts a User.Deleted with no data key, using the route params", async () => {
    // A 204 delete route serialises no `data` at all. Dropping it would skip
    // the session revocation that deletion is supposed to trigger.
    const handler = captureWebhookRoute({ signingKey });
    const payload = JSON.stringify({
      hookId: "h1",
      event: "User.Deleted",
      createdAt: new Date().toISOString(),
      path: "/users/:userId",
      method: "DELETE",
      status: 204,
      params: { userId: "user_abc" },
      matchedRoute: "/users/:userId",
    });
    const runMutation = vi.fn();
    const res = await handler(
      { runMutation },
      post(sign(signingKey, payload), payload),
    );

    expect(res.status).toBe(200);
    expect(runMutation).toHaveBeenCalledTimes(1);
  });
});

describe("logtoSync dispatch", () => {
  it("dispatches an event to its handler with (ctx, user, payload)", async () => {
    const seen: Array<{ ctx: unknown; user: unknown; payload: unknown }> = [];
    const { sync } = logtoSync({
      "User.Data.Updated": async (ctx, user, payload) => {
        seen.push({ ctx, user, payload });
      },
    });
    const ctx = { db: {} };
    const payload = {
      event: "User.Data.Updated",
      hookId: "h",
      createdAt: "t",
      data: { id: "u1", primaryEmail: "a@b.com" },
    };
    await callSync(sync, ctx, payload);
    expect(seen).toHaveLength(1);
    expect(seen[0]?.ctx).toBe(ctx); // ctx forwarded verbatim (the `as` cast is identity at runtime)
    expect(seen[0]?.user).toEqual({ id: "u1", primaryEmail: "a@b.com" });
    expect(seen[0]?.payload).toBe(payload);
  });

  it("synthesizes { id } from params.userId for User.Deleted (data: null)", async () => {
    let got: unknown;
    const { sync } = logtoSync({
      "User.Deleted": async (_ctx, user) => {
        got = user;
      },
    });
    await callSync(
      sync,
      { db: {} },
      {
        event: "User.Deleted",
        hookId: "h",
        createdAt: "t",
        data: null,
        params: { userId: "u2" },
      },
    );
    expect(got).toEqual({ id: "u2" });
  });

  it("passes the pre-deletion User through when its id matches route params", async () => {
    let got: unknown;
    const { sync } = logtoSync({
      "User.Deleted": async (_ctx, user) => {
        got = user;
      },
    });
    const user = {
      id: "u-current",
      primaryEmail: "former@example.com",
      name: "Former User",
    };

    await callSync(
      sync,
      { db: {} },
      {
        event: "User.Deleted",
        hookId: "h",
        createdAt: "t",
        data: user,
        params: { userId: "u-current" },
      },
    );

    expect(got).toBe(user);
  });

  it("rejects contradictory User.Deleted ids before dispatching", async () => {
    const handler = vi.fn();
    const { sync } = logtoSync({ "User.Deleted": handler });

    await expect(
      callSync(
        sync,
        { db: {} },
        {
          event: "User.Deleted",
          hookId: "h",
          createdAt: "t",
          data: { id: "data-user" },
          params: { userId: "params-user" },
        },
      ),
    ).rejects.toThrow(/known Logto User\.\* event/);
    expect(handler).not.toHaveBeenCalled();
  });

  it("is a no-op (resolves null) when no handler is mapped for the event", async () => {
    const { sync } = logtoSync({});
    await expect(
      callSync(
        sync,
        { db: {} },
        {
          event: "User.Created",
          hookId: "h",
          createdAt: "t",
          data: { id: "u3" },
        },
      ),
    ).resolves.toBeNull();
  });

  it("throws on a payload that isn't a known User.* event", async () => {
    const { sync } = logtoSync({ "User.Created": async () => {} });
    await expect(
      callSync(
        sync,
        { db: {} },
        {
          event: "Organization.Created",
          data: { id: "o1" },
        },
      ),
    ).rejects.toThrow(/known Logto User\.\* event/);
  });

  it("throws before dispatching a known event with a malformed user", async () => {
    const handler = vi.fn();
    const { sync } = logtoSync({ "User.Created": handler });
    await expect(
      callSync(
        sync,
        { db: {} },
        {
          event: "User.Created",
          hookId: "h",
          createdAt: "t",
          data: { id: "u1", primaryEmail: 42 },
        },
      ),
    ).rejects.toThrow(/known Logto User\.\* event/);
    expect(handler).not.toHaveBeenCalled();
  });
});
