import { httpRouter } from "convex/server";
import { afterEach, beforeAll, describe, expect, it, vi } from "vitest";
import { registerLogtoBackchannelLogout } from "./backchannel-logout";
import type { LogtoSessionComponent } from "./session";

type SupportedAlgorithm = "RS256" | "PS256";
type SigningFixture = {
  privateKey: CryptoKey;
  publicJwk: JsonWebKey & { kid: string };
};

const encoder = new TextEncoder();
const appId = "app-1";
let rs256: SigningFixture;
let ps256: SigningFixture;
let harnessNumber = 0;

function base64Url(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary)
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

function encodedJson(value: unknown): string {
  return base64Url(encoder.encode(JSON.stringify(value)));
}

async function signingFixture(
  algorithm: SupportedAlgorithm,
  kid: string,
): Promise<SigningFixture> {
  const webCryptoAlgorithm =
    algorithm === "RS256"
      ? {
          name: "RSASSA-PKCS1-v1_5",
          modulusLength: 2048,
          publicExponent: new Uint8Array([1, 0, 1]),
          hash: "SHA-256",
        }
      : {
          name: "RSA-PSS",
          modulusLength: 2048,
          publicExponent: new Uint8Array([1, 0, 1]),
          hash: "SHA-256",
        };
  const pair = (await crypto.subtle.generateKey(webCryptoAlgorithm, true, [
    "sign",
    "verify",
  ])) as CryptoKeyPair;
  const publicJwk = (await crypto.subtle.exportKey(
    "jwk",
    pair.publicKey,
  )) as JsonWebKey & { kid: string };
  publicJwk.kid = kid;
  publicJwk.alg = algorithm;
  publicJwk.use = "sig";
  return { privateKey: pair.privateKey, publicJwk };
}

beforeAll(async () => {
  [rs256, ps256] = await Promise.all([
    signingFixture("RS256", "rsa-signing-key"),
    signingFixture("PS256", "pss-signing-key"),
  ]);
});

afterEach(() => {
  vi.unstubAllGlobals();
});

function validPayload(endpoint: string): Record<string, unknown> {
  const now = Math.floor(Date.now() / 1000);
  return {
    iss: `${endpoint}/oidc`,
    sub: "user-1",
    aud: appId,
    iat: now,
    exp: now + 120,
    jti: `logout-${harnessNumber}`,
    sid: "logto-session-1",
    events: {
      "http://schemas.openid.net/event/backchannel-logout": {},
    },
  };
}

async function logoutToken(options: {
  endpoint: string;
  payload?: Record<string, unknown>;
  algorithm?: SupportedAlgorithm;
  headerAlgorithm?: string;
  signingAlgorithm?: SupportedAlgorithm;
}): Promise<string> {
  const algorithm = options.algorithm ?? "RS256";
  const signingAlgorithm = options.signingAlgorithm ?? algorithm;
  const fixture = signingAlgorithm === "RS256" ? rs256 : ps256;
  const header = encodedJson({
    alg: options.headerAlgorithm ?? algorithm,
    kid: algorithm === "RS256" ? rs256.publicJwk.kid : ps256.publicJwk.kid,
    typ: "logout+jwt",
  });
  const payload = encodedJson(
    options.payload ?? validPayload(options.endpoint),
  );
  const signature = await crypto.subtle.sign(
    signingAlgorithm === "RS256"
      ? { name: "RSASSA-PKCS1-v1_5" }
      : { name: "RSA-PSS", saltLength: 32 },
    fixture.privateKey,
    encoder.encode(`${header}.${payload}`),
  );
  return `${header}.${payload}.${base64Url(new Uint8Array(signature))}`;
}

const refs = {
  record: { fn: "record" },
  forget: { fn: "forget" },
  killSid: { fn: "killSid" },
  killSubject: { fn: "killSubject" },
};

const sessions = {
  lib: {
    recordWebhookDelivery: refs.record,
    forgetWebhookDelivery: refs.forget,
    killSessionsBySid: refs.killSid,
    killSubjectSessions: refs.killSubject,
  },
} as unknown as LogtoSessionComponent;

type RouteHandler = (
  ctx: { runMutation: (ref: unknown, args: unknown) => Promise<unknown> },
  request: Request,
) => Promise<Response>;

function harness(options?: {
  record?: boolean;
  killSidError?: Error;
  customPath?: string;
}) {
  harnessNumber += 1;
  const endpoint = `https://auth-${harnessNumber}.example.com`;
  const fetchMock = vi
    .fn<typeof globalThis.fetch>()
    .mockResolvedValue(
      new Response(
        JSON.stringify({ keys: [rs256.publicJwk, ps256.publicJwk] }),
        { status: 200, headers: { "Content-Type": "application/json" } },
      ),
    );
  vi.stubGlobal("fetch", fetchMock);
  const handlers: Record<string, ReturnType<typeof vi.fn>> = {
    record: vi.fn().mockResolvedValue(options?.record ?? true),
    forget: vi.fn().mockResolvedValue(null),
    killSid: options?.killSidError
      ? vi.fn().mockRejectedValue(options.killSidError)
      : vi.fn().mockResolvedValue(1),
    killSubject: vi.fn().mockResolvedValue(2),
  };
  const calls: Array<{ fn: string; args: unknown }> = [];
  const runMutation = vi.fn((ref: unknown, args: unknown) => {
    const fn = (ref as { fn: string }).fn;
    calls.push({ fn, args });
    return handlers[fn]!(args);
  });
  const http = httpRouter();
  registerLogtoBackchannelLogout(http, {
    sessions,
    endpoint,
    appId,
    path: options?.customPath,
  });
  const path = options?.customPath ?? "/logto/backchannel-logout";
  const match = http.lookup(path, "POST");
  if (!match) throw new Error(`No POST route at ${path}`);
  const handler = (match[0] as unknown as Record<string, RouteHandler>)[
    "_handler"
  ];
  if (!handler) throw new Error("Back-channel route handler was not captured");
  return { endpoint, fetchMock, handlers, calls, runMutation, handler };
}

function post(
  body: BodyInit,
  contentType = "application/x-www-form-urlencoded",
) {
  return new Request("https://convex.example/logto/backchannel-logout", {
    method: "POST",
    headers: { "Content-Type": contentType },
    body,
  });
}

function logoutRequest(token: string): Request {
  return post(new URLSearchParams({ logout_token: token }));
}

async function expectInvalid(
  tokenFactory: (endpoint: string) => string | Promise<string>,
): Promise<void> {
  const { endpoint, handler, runMutation } = harness();
  const response = await handler(
    { runMutation },
    logoutRequest(await tokenFactory(endpoint)),
  );
  expect(response.status).toBe(400);
  expect(response.headers.get("Cache-Control")).toBe("no-store");
  await expect(response.json()).resolves.toMatchObject({
    error: "invalid_request",
  });
  expect(runMutation).not.toHaveBeenCalled();
}

describe("Logto back-channel logout", () => {
  it("kills only sessions with the valid token's sid", async () => {
    const { endpoint, handler, handlers, calls, runMutation } = harness({
      customPath: "/oidc/logout",
    });
    const token = await logoutToken({ endpoint });

    const response = await handler({ runMutation }, logoutRequest(token));

    expect(response.status).toBe(200);
    expect(response.headers.get("Cache-Control")).toBe("no-store");
    expect(handlers.killSid).toHaveBeenCalledWith({
      sid: "logto-session-1",
    });
    expect(handlers.killSubject).not.toHaveBeenCalled();
    expect(calls.map((call) => call.fn)).toEqual(["record", "killSid"]);
  });

  it("kills every subject session when sid is absent", async () => {
    const { endpoint, handler, handlers, runMutation } = harness();
    const payload = validPayload(endpoint);
    delete payload.sid;
    const token = await logoutToken({ endpoint, payload });

    const response = await handler({ runMutation }, logoutRequest(token));

    expect(response.status).toBe(200);
    expect(handlers.killSubject).toHaveBeenCalledWith({ subject: "user-1" });
    expect(handlers.killSid).not.toHaveBeenCalled();
  });

  it("accepts PS256 logout tokens", async () => {
    const { endpoint, handler, handlers, runMutation } = harness();
    const token = await logoutToken({ endpoint, algorithm: "PS256" });

    const response = await handler({ runMutation }, logoutRequest(token));

    expect(response.status).toBe(200);
    expect(handlers.killSid).toHaveBeenCalledTimes(1);
  });

  it("answers 200 and performs no revocation for a replayed jti", async () => {
    const { endpoint, handler, handlers, calls, runMutation } = harness({
      record: false,
    });
    const token = await logoutToken({ endpoint });

    const response = await handler({ runMutation }, logoutRequest(token));

    expect(response.status).toBe(200);
    expect(handlers.killSid).not.toHaveBeenCalled();
    expect(handlers.killSubject).not.toHaveBeenCalled();
    expect(calls.map((call) => call.fn)).toEqual(["record"]);
  });

  it.each([
    [
      "wrong issuer",
      async (endpoint: string) =>
        logoutToken({
          endpoint,
          payload: { ...validPayload(endpoint), iss: "https://other/oidc" },
        }),
    ],
    [
      "wrong audience",
      async (endpoint: string) =>
        logoutToken({
          endpoint,
          payload: { ...validPayload(endpoint), aud: "other-app" },
        }),
    ],
    [
      "HS256 algorithm",
      (endpoint: string) => logoutToken({ endpoint, headerAlgorithm: "HS256" }),
    ],
    [
      "missing events",
      async (endpoint: string) => {
        const payload = validPayload(endpoint);
        delete payload.events;
        return logoutToken({ endpoint, payload });
      },
    ],
    [
      "present nonce",
      async (endpoint: string) =>
        logoutToken({
          endpoint,
          payload: { ...validPayload(endpoint), nonce: "forbidden" },
        }),
    ],
    [
      "stale iat",
      async (endpoint: string) =>
        logoutToken({
          endpoint,
          payload: {
            ...validPayload(endpoint),
            iat: Math.floor(Date.now() / 1000) - 301,
          },
        }),
    ],
    [
      "expired token",
      async (endpoint: string) =>
        logoutToken({
          endpoint,
          payload: {
            ...validPayload(endpoint),
            exp: Math.floor(Date.now() / 1000) - 61,
          },
        }),
    ],
    [
      "missing sub and sid",
      async (endpoint: string) => {
        const payload = validPayload(endpoint);
        delete payload.sub;
        delete payload.sid;
        return logoutToken({ endpoint, payload });
      },
    ],
    [
      "missing jti",
      async (endpoint: string) => {
        const payload = validPayload(endpoint);
        delete payload.jti;
        return logoutToken({ endpoint, payload });
      },
    ],
    ["garbage JWT", async () => "not-a-jwt"],
  ])("rejects %s", async (_name, tokenFactory) => {
    await expectInvalid(tokenFactory);
  });

  it("rejects an RSA-PSS signature presented as RS256", async () => {
    await expectInvalid((endpoint) =>
      logoutToken({
        endpoint,
        algorithm: "RS256",
        signingAlgorithm: "PS256",
      }),
    );
  });

  it("rejects a non-form request", async () => {
    const { handler, runMutation } = harness();
    const response = await handler(
      { runMutation },
      post("{}", "application/json"),
    );
    expect(response.status).toBe(400);
    expect(runMutation).not.toHaveBeenCalled();
  });

  it("rejects a non-POST request when the handler factory is mounted directly", async () => {
    const { handler, runMutation } = harness();
    const response = await handler(
      { runMutation },
      new Request("https://convex.example/logto/backchannel-logout"),
    );
    expect(response.status).toBe(400);
    expect(runMutation).not.toHaveBeenCalled();
  });

  it("rejects a body larger than 1 MB before verification", async () => {
    const { handler, fetchMock, runMutation } = harness();
    const response = await handler(
      { runMutation },
      post(new URLSearchParams({ logout_token: "x".repeat(1024 * 1024) })),
    );
    expect(response.status).toBe(413);
    expect(fetchMock).not.toHaveBeenCalled();
    expect(runMutation).not.toHaveBeenCalled();
  });

  it("releases the jti claim when session revocation fails", async () => {
    const { endpoint, handler, handlers, calls, runMutation } = harness({
      killSidError: new Error("mutation failed"),
    });
    const token = await logoutToken({ endpoint });

    const response = await handler({ runMutation }, logoutRequest(token));

    expect(response.status).toBe(400);
    expect(handlers.forget).toHaveBeenCalledWith({
      bodyHash: expect.stringMatching(/^[0-9a-f]{64}$/),
    });
    expect(calls.map((call) => call.fn)).toEqual([
      "record",
      "killSid",
      "forget",
    ]);
  });
});
