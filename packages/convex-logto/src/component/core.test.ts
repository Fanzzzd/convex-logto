// Pure-logic tests for the session component's core: the rotation decision
// state machine (the heart of reuse handling), URL builders, token helpers,
// and the error taxonomy.
import { ConvexError } from "convex/values";
import { describe, expect, it } from "vitest";
import {
  DEFAULT_REUSE_WINDOW_MS,
  assertDeviceProof,
  assertUsableDevicePublicKey,
  buildAuthorizeUrl,
  buildEndSessionUrl,
  classifyTokenEndpointFailure,
  decideRefresh,
  asDeploymentFault,
  decodeIdToken,
  decodeJwtSegment,
  generatePkce,
  generateToken,
  hashToken,
  isOutcomeUnknownError,
  normalizeClientDescriptor,
  normalizeSignInTargets,
  normalizeSessionLabel,
  sessionReadCost,
  rotateTokenHashes,
  terminal,
  toBase64Url,
  transient,
  verifyDeviceProof,
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

async function deviceProofFixture(sessionToken: string) {
  const pair = (await crypto.subtle.generateKey(
    { name: "ECDSA", namedCurve: "P-256" },
    false,
    ["sign", "verify"],
  )) as CryptoKeyPair;
  const jwk = await crypto.subtle.exportKey("jwk", pair.publicKey);
  if (jwk.kty !== "EC" || !jwk.x || !jwk.y) throw new Error("invalid JWK");
  const publicKey = {
    kty: "EC" as const,
    crv: "P-256" as const,
    x: jwk.x,
    y: jwk.y,
  };
  const signature = await crypto.subtle.sign(
    { name: "ECDSA", hash: "SHA-256" },
    pair.privateKey,
    new TextEncoder().encode(sessionToken),
  );
  return { publicKey, proof: toBase64Url(new Uint8Array(signature)) };
}

describe("device proof", () => {
  it("signs and verifies the presented one-time session token", async () => {
    const sessionToken = "session-token-1";
    const { publicKey, proof } = await deviceProofFixture(sessionToken);
    await expect(
      verifyDeviceProof({ publicKey, sessionToken, proof }),
    ).resolves.toBe(true);
    await expect(
      verifyDeviceProof({
        publicKey,
        sessionToken: "session-token-2",
        proof,
      }),
    ).resolves.toBe(false);
    await expect(
      assertDeviceProof({ publicKey, sessionToken, proof }),
    ).resolves.toBeUndefined();
  });

  it("rejects a proof from the wrong key terminally", async () => {
    const sessionToken = "session-token-1";
    const [{ publicKey }, { proof }] = await Promise.all([
      deviceProofFixture(sessionToken),
      deviceProofFixture(sessionToken),
    ]);
    await expect(
      assertDeviceProof({ publicKey, sessionToken, proof }),
    ).rejects.toMatchObject({
      data: { kind: "terminal", code: "device_proof_invalid" },
    });
  });

  it("rejects a missing proof for a bound session terminally", async () => {
    const { publicKey } = await deviceProofFixture("session-token-1");
    await expect(
      assertDeviceProof({ publicKey, sessionToken: "session-token-1" }),
    ).rejects.toMatchObject({
      data: { kind: "terminal", code: "device_proof_required" },
    });
  });

  it("leaves the existing unbound refresh path unchanged", async () => {
    await expect(
      assertDeviceProof({ sessionToken: "session-token-1" }),
    ).resolves.toBeUndefined();
  });
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

it("URL builders preserve a reverse-proxy endpoint path prefix", () => {
  const authorize = new URL(
    buildAuthorizeUrl({
      endpoint: "https://auth.example.com/logto",
      appId: "app1",
      redirectUri: "https://app.example.com/callback",
      state: "state-1",
      challenge: "challenge-1",
    }),
  );
  expect(authorize.pathname).toBe("/logto/oidc/auth");

  const endSession = new URL(
    buildEndSessionUrl({
      endpoint: "https://auth.example.com/logto",
      appId: "app1",
    }),
  );
  expect(endSession.pathname).toBe("/logto/oidc/session/end");
});

it("URL builders reject an endpoint that bypassed public config validation", () => {
  expect(() =>
    buildAuthorizeUrl({
      endpoint: "javascript:globalThis.compromised=true//x",
      appId: "app1",
      redirectUri: "https://app.example.com/callback",
      state: "state-1",
      challenge: "challenge-1",
    }),
  ).toThrow(/https?:/i);
  expect(() =>
    buildEndSessionUrl({
      endpoint: "https://alice@auth.example.com",
      appId: "app1",
    }),
  ).toThrow(/credentials/i);
});

// --- ID token decoding -------------------------------------------------------

function fakeIdToken(payload: Record<string, unknown>): string {
  const enc = (o: unknown) => {
    // A real payload is base64url over UTF-8 bytes; `btoa` alone cannot even
    // represent a non-ASCII claim.
    let binary = "";
    for (const byte of new TextEncoder().encode(JSON.stringify(o)))
      binary += String.fromCharCode(byte);
    return btoa(binary)
      .replace(/\+/g, "-")
      .replace(/\//g, "_")
      .replace(/=+$/, "");
  };
  return `${enc({ alg: "ES384" })}.${enc(payload)}.sig`;
}

const expected = { endpoint: "https://auth.example.com", appId: "app1" };

it("decodeIdToken accepts an array aud containing the app id", () => {
  // OIDC Core §2 allows it, Convex accepts it, and this library's own
  // back-channel-logout verifier always has.
  const token = fakeIdToken({
    iss: "https://auth.example.com/oidc",
    aud: ["app-1"],
    sub: "u1",
    exp: 2_000_000_000,
  });

  expect(
    decodeIdToken(token, {
      endpoint: "https://auth.example.com",
      appId: "app-1",
    }),
  ).toMatchObject({ subject: "u1" });
});

it("decodeIdToken still rejects an array aud without the app id", () => {
  const token = fakeIdToken({
    iss: "https://auth.example.com/oidc",
    aud: ["other-app"],
    sub: "u1",
    exp: 2_000_000_000,
  });

  expect(() =>
    decodeIdToken(token, {
      endpoint: "https://auth.example.com",
      appId: "app-1",
    }),
  ).toThrow(/don't match/);
});

it("asDeploymentFault keeps the code but drops the terminal intent", () => {
  const fault = asDeploymentFault(
    new ConvexError({
      kind: "terminal",
      code: "id_token_mismatch",
      message: "ID token iss/aud don't match.",
    }),
  );

  expect(fault.data).toMatchObject({
    kind: "transient",
    code: "id_token_mismatch",
  });
  expect(fault.data.message).toMatch(/session was kept/);
});

it("asDeploymentFault survives an error that is not ours", () => {
  expect(asDeploymentFault(new Error("boom")).data).toMatchObject({
    kind: "transient",
    code: "logto_response_unusable",
  });
});

describe("normalizeSignInTargets", () => {
  it("passes an ordinary web redirect and returnTo through", () => {
    expect(
      normalizeSignInTargets({
        redirectUri: "http://localhost:5173/callback",
        returnTo: "/dashboard",
      }),
    ).toEqual({
      redirectUri: "http://localhost:5173/callback",
      returnTo: "/dashboard",
    });
  });

  it("accepts a native custom scheme", () => {
    // Logto rejects any redirect URI the app has not registered, so being
    // stricter than "absolute URI" here would break native rather than protect it.
    expect(
      normalizeSignInTargets({ redirectUri: "io.logto://callback" }),
    ).toEqual({ redirectUri: "io.logto://callback" });
  });

  it("bounds both strings, which an unauthenticated caller controls", () => {
    expect(() =>
      normalizeSignInTargets({
        redirectUri: `https://app.example.com/${"a".repeat(2048)}`,
      }),
    ).toThrow(/redirect URI exceeds/);
    expect(() =>
      normalizeSignInTargets({
        redirectUri: "https://app.example.com/callback",
        returnTo: "/".repeat(2049),
      }),
    ).toThrow(/exceeds/);
  });

  it("rejects a relative URI and one that embeds credentials", () => {
    expect(() => normalizeSignInTargets({ redirectUri: "/callback" })).toThrow(
      /absolute URI/,
    );
    expect(() =>
      normalizeSignInTargets({
        redirectUri: "https://alice:pw@app.example.com/callback",
      }),
    ).toThrow(/credentials/);
  });
});

it("decodeJwtSegment reads a segment as UTF-8, not one char per byte", () => {
  // `atob` alone turns a `name` of 王小明 into ç\u008e\u008bå°\u008fæ\u0098\u008e.
  const claims = { name: "王小明", family_name: "Müller", emoji: "🔐" };
  const segment = fakeIdToken(claims).split(".")[1]!;

  expect(decodeJwtSegment(segment)).toEqual(claims);
});

it("decodeJwtSegment refuses a segment it cannot decode", () => {
  expect(decodeJwtSegment("not base64url!")).toBeUndefined();
  expect(decodeJwtSegment("bm90IGpzb24")).toBeUndefined();
});

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

it("decodeIdToken captures an optional Logto sid", () => {
  const token = fakeIdToken({
    iss: "https://auth.example.com/oidc",
    aud: "app1",
    sub: "user1",
    sid: "logto-session-1",
    exp: 1_700_000_000,
  });
  expect(decodeIdToken(token, expected)).toEqual({
    subject: "user1",
    sid: "logto-session-1",
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

  it("current token with an expired claim → require reauthentication instead of double-spending the refresh token", () => {
    expect(decide("current", { refreshingSince: NOW - 16_000 })).toEqual({
      outcome: "claim-expired",
    });
  });

  it("recent superseded generation with a fresh cached ID token → cached", () => {
    expect(decide("previous", {})).toEqual({ outcome: "cached" });
  });

  it("indexed generation uses its stored expiry instead of the legacy rotation timestamp", () => {
    expect(
      decideRefresh({
        presentedHash: "older-generation",
        session: { ...base, rotatedAt: undefined },
        now: NOW,
        reuseWindowMs: DEFAULT_REUSE_WINDOW_MS,
        presentedTokenExpiresAt: NOW + 1,
      }),
    ).toEqual({ outcome: "cached" });
  });

  it("indexed generation expiry boundary is exclusive", () => {
    expect(
      decideRefresh({
        presentedHash: "older-generation",
        session: base,
        now: NOW,
        reuseWindowMs: DEFAULT_REUSE_WINDOW_MS,
        presentedTokenExpiresAt: NOW,
      }),
    ).toEqual({ outcome: "reuse" });
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

  it("recent superseded token with a stale cache → refresh-superseded", () => {
    expect(decide("previous", { lastIdTokenExp: NOW + 30_000 })).toEqual({
      outcome: "refresh-superseded",
    });
  });

  it("recent superseded generation while a claim is held → in-flight", () => {
    expect(decide("previous", { refreshingSince: NOW - 1_000 })).toEqual({
      outcome: "in-flight",
    });
  });

  it("superseded generation outside the Reuse window → reuse", () => {
    expect(
      decide("previous", { rotatedAt: NOW - DEFAULT_REUSE_WINDOW_MS - 1 }),
    ).toEqual({
      outcome: "reuse",
    });
  });

  it("legacy previous field with no rotation time → reuse", () => {
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
  // Only a rejected *grant* is terminal. Everything else keeps the session.
  [400, "invalid_grant", "terminal"],
  [400, "invalid_request", "transient"],
  [400, "unsupported_grant_type", "transient"],
  [401, "invalid_client", "transient"],
  [401, "unauthorized_client", "transient"],
  // 403 is not in RFC 6749 §5.2, but Logto answers it — and it is a decision,
  // not an unknown outcome. The dedicated test below is the one that proves it.
  [403, "invalid_grant", "terminal"],
  [429, undefined, "transient"],
  [500, undefined, "transient"],
  [502, undefined, "transient"],
])("classifyTokenEndpointFailure(%i, %s) → %s", (status, error, kind) => {
  expect(
    classifyTokenEndpointFailure(status, error === undefined ? {} : { error })
      .data.kind,
  ).toBe(kind);
});

it.each([400, 401, 403])(
  "classifyTokenEndpointFailure(%i) without an error code keeps the session",
  (status) => {
    // Deleting every session of a deployment is irreversible; an answer we
    // cannot attribute must not trigger it.
    expect(classifyTokenEndpointFailure(status, {}).data.kind).toBe(
      "transient",
    );
  },
);

it("does not read a 403 as an unknown outcome, which would delete the session", () => {
  // The whole chain this prevents, measured live before it was fixed: an
  // Organization token requested without `urn:logto:scope:organizations`
  // answers `403 insufficient_scope`; read as "outcome unknown" the component
  // keeps the refresh claim, every later refresh answers `refresh_in_flight`,
  // and when the claim ages out the session is *deleted*. One missing scope in
  // a deployment's config, every user signed out.
  const error = classifyTokenEndpointFailure(403, {
    error: "insufficient_scope",
    scope: "urn:logto:scope:organizations",
  });
  expect(error.data.kind).toBe("transient");
  expect(error.data.code).toBe("insufficient_scope");
  expect(error.data.code).not.toBe("logto_outcome_unknown");
  // And it names the scope Logto asked for, because "insufficient_scope"
  // alone does not tell a reader which option to add.
  expect(error.data.message).toContain("urn:logto:scope:organizations");
  expect(error.data.message).toContain("scopes");
});

it("does not blame the client credentials for a scope Logto refused", () => {
  // `invalid_scope` shares the configuration-fault branch with
  // `invalid_client`, whose message names LOGTO_APP_ID / LOGTO_CLIENT_SECRET /
  // LOGTO_ENDPOINT. For a scope that is the wrong three things to check.
  const error = classifyTokenEndpointFailure(400, {
    error: "invalid_scope",
    scope: "e2e:manage",
  });
  expect(error.data.kind).toBe("transient");
  expect(error.data.message).toContain("e2e:manage");
  expect(error.data.message).not.toContain("LOGTO_CLIENT_SECRET");
});

it("classifyTokenEndpointFailure surfaces Logto's error code", () => {
  expect(
    classifyTokenEndpointFailure(400, { error: "invalid_grant" }).data.code,
  ).toBe("invalid_grant");
  expect(
    classifyTokenEndpointFailure(401, { error: "invalid_client" }).data.code,
  ).toBe("invalid_client");
});

it.each([500, 502, 503])(
  "classifyTokenEndpointFailure(%i) marks the refresh outcome unknown",
  (status) => {
    // The request reached Logto, which may have rotated the grant already.
    expect(
      isOutcomeUnknownError(classifyTokenEndpointFailure(status, {})),
    ).toBe(true);
  },
);

// --- session labels ----------------------------------------------------------

describe("session labels and client descriptors", () => {
  it("collapses whitespace and drops control and bidi characters", () => {
    expect(normalizeSessionLabel("  Ada's\n  laptop  ")).toBe("Ada's laptop");
    // A bidi override would let one label render as though it were another
    // entry in the session list.
    expect(normalizeSessionLabel("work\u202Ephone")).toBe("workphone");
    expect(normalizeSessionLabel("   ")).toBeUndefined();
    expect(normalizeSessionLabel(undefined)).toBeUndefined();
  });

  it.each([
    ["RLM", "\u200f"],
    ["LRM", "\u200e"],
    ["ALM", "\u061c"],
    ["RLO", "\u202e"],
    ["isolate", "\u2066"],
    ["zero-width space", "\u200b"],
    ["soft hyphen", "\u00ad"],
    ["word joiner", "\u2060"],
    ["line separator", "\u2028"],
  ])(
    "strips %s, which could reorder or hide part of a label",
    (_name, char) => {
      // The session list is where a user picks which device to revoke; a label
      // that renders as another one is a way to steer that choice.
      expect(normalizeSessionLabel(`12${char}34`)).toBe("1234");
    },
  );

  it("keeps the zero-width joiner so emoji sequences survive", () => {
    expect(normalizeSessionLabel("👨\u200d💻")).toBe("👨\u200d💻");
  });

  it("rejects an over-long label instead of truncating it", () => {
    // The user is naming a device they need to recognise later; a silently
    // shortened name is worse than a clear error.
    expect(() => normalizeSessionLabel("x".repeat(65))).toThrow(
      /at most 64 characters/,
    );
    expect(normalizeSessionLabel("x".repeat(64))).toHaveLength(64);
  });

  it("counts code points, not UTF-16 units", () => {
    expect(normalizeSessionLabel("😀".repeat(64))).toBeDefined();
    expect(() => normalizeSessionLabel("😀".repeat(65))).toThrow(
      /at most 64 characters/,
    );
  });

  it("trims advisory client fields and drops empty ones", () => {
    expect(
      normalizeClientDescriptor({
        platform: "web",
        os: "  ",
        browser: "y".repeat(40),
      }),
    ).toEqual({ platform: "web", browser: "y".repeat(32) });
    expect(normalizeClientDescriptor({})).toBeUndefined();
    expect(normalizeClientDescriptor(undefined)).toBeUndefined();
  });
});

describe("assertUsableDevicePublicKey", () => {
  // `x` and `y` are the only caller-supplied strings the component stores
  // without a bound of their own, and the key is otherwise parsed only at verify
  // time inside a try/catch — so nothing on the write path would notice.
  const coordinate = "a".repeat(43);

  it("accepts a real P-256 coordinate pair", () => {
    expect(() =>
      assertUsableDevicePublicKey({
        kty: "EC",
        crv: "P-256",
        x: coordinate,
        y: coordinate,
      }),
    ).not.toThrow();
  });

  it("rejects a coordinate that is not 43 base64url characters", () => {
    for (const bad of [
      "a".repeat(500_000),
      "a".repeat(42),
      `${"a".repeat(42)}+`,
    ]) {
      expect(() =>
        assertUsableDevicePublicKey({
          kty: "EC",
          crv: "P-256",
          x: bad,
          y: coordinate,
        }),
      ).toThrow(ConvexError);
    }
  });

  it("counts the key against the list scan budget", () => {
    const row = {
      logtoRefreshToken: "r",
      lastIdToken: "i",
    };
    expect(
      sessionReadCost({
        ...row,
        devicePublicKey: { x: coordinate, y: coordinate },
      }),
    ).toBe(sessionReadCost(row) + coordinate.length * 2);
  });
});
