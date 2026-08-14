// Pure-logic tests for the session component's core: the rotation decision
// state machine (the heart of reuse handling), URL builders, token helpers,
// and the error taxonomy.
import { ConvexError } from "convex/values";
import { describe, expect, it } from "vitest";
import {
  DEFAULT_REUSE_WINDOW_MS,
  buildAuthorizeUrl,
  buildEndSessionUrl,
  classifyTokenEndpointFailure,
  decideRefresh,
  decodeIdToken,
  generatePkce,
  generateToken,
  hashToken,
  rotateTokenHashes,
  terminal,
  toBase64Url,
  transient,
} from "./core";

// --- token helpers -----------------------------------------------------------

it("generateToken produces distinct 43-char base64url tokens", () => {
  const a = generateToken();
  const b = generateToken();
  expect(a).not.toBe(b);
  // 32 bytes → ceil(32 * 4 / 3) = 43 chars unpadded.
  expect(a).toMatch(/^[A-Za-z0-9_-]{43}$/);
});

it("hashToken is a stable SHA-256 hex", async () => {
  // Fixed vector: sha256("test")
  expect(await hashToken("test")).toBe(
    "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
  );
  expect(await hashToken("test")).toBe(await hashToken("test"));
});

it("generatePkce produces an S256 challenge of the verifier", async () => {
  const { verifier, challenge } = await generatePkce();
  const digest = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(verifier),
  );
  expect(challenge).toBe(toBase64Url(new Uint8Array(digest)));
});

// --- URL builders ------------------------------------------------------------

it("buildAuthorizeUrl carries PKCE, state, prompt=consent, and base scopes", () => {
  const url = new URL(
    buildAuthorizeUrl({
      endpoint: "https://auth.example.com",
      appId: "app1",
      redirectUri: "https://app.example.com/callback",
      state: "st",
      challenge: "ch",
      scopes: ["custom:scope"],
      resources: ["https://api.example.com"],
    }),
  );
  expect(url.origin + url.pathname).toBe("https://auth.example.com/oidc/auth");
  const p = url.searchParams;
  expect(p.get("client_id")).toBe("app1");
  expect(p.get("redirect_uri")).toBe("https://app.example.com/callback");
  expect(p.get("response_type")).toBe("code");
  expect(p.get("state")).toBe("st");
  expect(p.get("code_challenge")).toBe("ch");
  expect(p.get("code_challenge_method")).toBe("S256");
  // Required for offline_access to actually issue a refresh token.
  expect(p.get("prompt")).toBe("consent");
  expect(p.get("scope")).toBe(
    "openid offline_access profile email custom:scope",
  );
  expect(p.getAll("resource")).toEqual(["https://api.example.com"]);
});

it("buildEndSessionUrl includes the post-logout redirect only when given", () => {
  const bare = new URL(
    buildEndSessionUrl({ endpoint: "https://auth.example.com", appId: "app1" }),
  );
  expect(bare.pathname).toBe("/oidc/session/end");
  expect(bare.searchParams.get("client_id")).toBe("app1");
  expect(bare.searchParams.has("post_logout_redirect_uri")).toBe(false);

  const withUri = new URL(
    buildEndSessionUrl({
      endpoint: "https://auth.example.com",
      appId: "app1",
      postLogoutRedirectUri: "https://app.example.com",
    }),
  );
  expect(withUri.searchParams.get("post_logout_redirect_uri")).toBe(
    "https://app.example.com",
  );
});

// --- ID token decoding -------------------------------------------------------

function fakeIdToken(payload: Record<string, unknown>): string {
  const enc = (o: unknown) =>
    btoa(JSON.stringify(o))
      .replace(/\+/g, "-")
      .replace(/\//g, "_")
      .replace(/=+$/, "");
  return `${enc({ alg: "ES384" })}.${enc(payload)}.sig`;
}

const expected = { endpoint: "https://auth.example.com", appId: "app1" };

it("decodeIdToken extracts sub and exp (ms)", () => {
  const token = fakeIdToken({
    iss: "https://auth.example.com/oidc",
    aud: "app1",
    sub: "user1",
    exp: 1_700_000_000,
  });
  expect(decodeIdToken(token, expected)).toEqual({
    subject: "user1",
    expiresAtMs: 1_700_000_000_000,
  });
});

it.each([
  ["malformed", "not-a-jwt"],
  [
    "wrong issuer",
    fakeIdToken({ iss: "https://other/oidc", aud: "app1", sub: "u", exp: 1 }),
  ],
  [
    "wrong audience",
    fakeIdToken({
      iss: "https://auth.example.com/oidc",
      aud: "other",
      sub: "u",
      exp: 1,
    }),
  ],
  [
    "missing sub",
    fakeIdToken({ iss: "https://auth.example.com/oidc", aud: "app1", exp: 1 }),
  ],
])("decodeIdToken rejects %s terminally", (_name, token) => {
  let data: { kind?: string } | undefined;
  try {
    decodeIdToken(token, expected);
  } catch (error) {
    data = (error as ConvexError<{ kind: string }>).data;
  }
  expect(data?.kind).toBe("terminal");
});

// --- the rotation decision ---------------------------------------------------

const NOW = 1_000_000;
const base = {
  tokenHash: "current",
  prevTokenHash: "previous",
  rotatedAt: NOW - 1_000,
  refreshingSince: undefined as number | undefined,
  lastIdTokenExp: NOW + 3_600_000,
};

function decide(
  presentedHash: string,
  session: Partial<typeof base>,
  now = NOW,
) {
  return decideRefresh({
    presentedHash,
    session: { ...base, ...session },
    now,
    reuseWindowMs: DEFAULT_REUSE_WINDOW_MS,
  });
}

describe("decideRefresh", () => {
  it("current token → refresh", () => {
    expect(decide("current", {})).toEqual({ outcome: "refresh" });
  });

  it("current token while a fresh claim is held → in-flight", () => {
    expect(decide("current", { refreshingSince: NOW - 1_000 })).toEqual({
      outcome: "in-flight",
    });
  });

  it("current token with a STALE claim → refresh (crashed action doesn't wedge the session)", () => {
    expect(decide("current", { refreshingSince: NOW - 16_000 })).toEqual({
      outcome: "refresh",
    });
  });

  it("previous token inside the window with a fresh cached ID token → cached", () => {
    expect(decide("previous", {})).toEqual({ outcome: "cached" });
  });

  it("rotation via a previous match keeps the superseded current token valid", () => {
    expect(decide("previous", {})).toEqual({ outcome: "cached" });
    const rotated = rotateTokenHashes(base.tokenHash, "candidate");
    expect(rotated).toEqual({
      tokenHash: "candidate",
      prevTokenHash: "current",
    });
    expect(
      decideRefresh({
        presentedHash: "current",
        session: { ...base, ...rotated, rotatedAt: NOW },
        now: NOW,
        reuseWindowMs: DEFAULT_REUSE_WINDOW_MS,
      }),
    ).toEqual({ outcome: "cached" });
  });

  it("previous token inside the window but cached ID token near expiry → refresh-previous", () => {
    expect(decide("previous", { lastIdTokenExp: NOW + 30_000 })).toEqual({
      outcome: "refresh-previous",
    });
  });

  it("previous token inside the window while a claim is held → in-flight", () => {
    expect(decide("previous", { refreshingSince: NOW - 1_000 })).toEqual({
      outcome: "in-flight",
    });
  });

  it("previous token OUTSIDE the window → reuse (kill the session)", () => {
    expect(
      decide("previous", { rotatedAt: NOW - DEFAULT_REUSE_WINDOW_MS - 1 }),
    ).toEqual({
      outcome: "reuse",
    });
  });

  it("previous token with no recorded rotation time → reuse", () => {
    expect(decide("previous", { rotatedAt: undefined })).toEqual({
      outcome: "reuse",
    });
  });

  it("window boundary is exclusive: exactly reuseWindowMs after rotation → reuse", () => {
    expect(
      decide("previous", { rotatedAt: NOW - DEFAULT_REUSE_WINDOW_MS }),
    ).toEqual({
      outcome: "reuse",
    });
  });
});

// --- error taxonomy ----------------------------------------------------------

it("terminal/transient build ConvexErrors with the crossing data shape", () => {
  expect(terminal("code_a", "msg").data).toEqual({
    kind: "terminal",
    code: "code_a",
    message: "msg",
  });
  expect(transient("code_b", "msg").data).toEqual({
    kind: "transient",
    code: "code_b",
    message: "msg",
  });
});

it.each([
  [400, "terminal"],
  [401, "terminal"],
  [500, "transient"],
  [502, "transient"],
  [429, "transient"],
])("classifyTokenEndpointFailure(%i) → %s", (status, kind) => {
  expect(classifyTokenEndpointFailure(status, {}).data.kind).toBe(kind);
});

it("classifyTokenEndpointFailure surfaces Logto's error code", () => {
  expect(
    classifyTokenEndpointFailure(400, { error: "invalid_grant" }).data.code,
  ).toBe("invalid_grant");
});
