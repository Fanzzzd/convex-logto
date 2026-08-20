import { ConvexError } from "convex/values";
import { describe, expect, it } from "vitest";
import {
  beginTokenExchange,
  cachedResourceToken,
  completeTokenExchange,
} from "./lib";
import {
  RESOURCE_TOKEN_CACHE_LIMIT,
  RESOURCE_TOKEN_SKEW_MS,
  TOKEN_AUDIENCE_MAX_LENGTH,
  accessTokenExpiresAt,
  decideExchange,
  tokenAudienceKey,
  tokenScopeKey,
} from "./core";

function handlerOf<Args, Result>(
  value: unknown,
  _types?: (args: Args) => Result,
): (ctx: unknown, args: Args) => Promise<Result> {
  return (
    value as Record<string, (ctx: unknown, args: Args) => Promise<Result>>
  )["_handler"]!;
}

// --- pure logic --------------------------------------------------------------

describe("decideExchange", () => {
  const session = {
    tokenHash: "current",
    rotatedAt: 1_000_000,
  };

  it("exchanges on the current token when nothing holds the claim", () => {
    expect(
      decideExchange({
        presentedHash: "current",
        session,
        now: 1_000_100,
        reuseWindowMs: 10_000,
      }),
    ).toEqual({ outcome: "exchange" });
  });

  it("queues behind an in-flight refresh rather than spending the token twice", () => {
    expect(
      decideExchange({
        presentedHash: "current",
        session: { ...session, refreshingSince: 1_000_000 },
        now: 1_000_100,
        reuseWindowMs: 10_000,
      }),
    ).toEqual({ outcome: "in-flight" });
  });

  it("reports claim-expired once the claim ages out, exactly like a refresh", () => {
    expect(
      decideExchange({
        presentedHash: "current",
        session: { ...session, refreshingSince: 1_000_000 },
        now: 1_100_000,
        reuseWindowMs: 10_000,
      }),
    ).toEqual({ outcome: "claim-expired" });
  });

  it("lets a superseded generation inside its reuse window exchange", () => {
    // Nothing rotates, so nothing can be orphaned by it — the reason this is
    // not `decideRefresh`, which would have to choose between cache and rotate.
    expect(
      decideExchange({
        presentedHash: "previous",
        session,
        now: 1_005_000,
        reuseWindowMs: 10_000,
      }),
    ).toEqual({ outcome: "exchange" });
  });

  it("treats a superseded generation past its window as reuse", () => {
    expect(
      decideExchange({
        presentedHash: "previous",
        session,
        now: 1_020_000,
        reuseWindowMs: 10_000,
      }),
    ).toEqual({ outcome: "reuse" });
  });

  it("prefers the generation row's own expiry over the rotation clock", () => {
    expect(
      decideExchange({
        presentedHash: "previous",
        session,
        now: 1_020_000,
        reuseWindowMs: 10_000,
        presentedTokenExpiresAt: 1_030_000,
      }),
    ).toEqual({ outcome: "exchange" });
  });
});

describe("tokenAudienceKey", () => {
  it("namespaces organizations and resources so ids cannot collide", () => {
    expect(tokenAudienceKey({ organizationId: "abc" })).toBe(
      "organization:abc",
    );
    expect(tokenAudienceKey({ resource: "https://api.example.com" })).toBe(
      "resource:https://api.example.com",
    );
    expect(tokenAudienceKey({})).toBe("default");
  });

  it("refuses an ambiguous target rather than silently preferring one", () => {
    expect(() =>
      tokenAudienceKey({ organizationId: "abc", resource: "https://x" }),
    ).toThrow(ConvexError);
  });

  it("bounds the audience so a caller cannot park a large document", () => {
    expect(() => tokenAudienceKey({ organizationId: "" })).toThrow(ConvexError);
    expect(() =>
      tokenAudienceKey({ resource: "x".repeat(TOKEN_AUDIENCE_MAX_LENGTH + 1) }),
    ).toThrow(ConvexError);
    expect(
      tokenAudienceKey({ resource: "x".repeat(TOKEN_AUDIENCE_MAX_LENGTH) }),
    ).toContain("resource:");
  });
});

describe("tokenScopeKey", () => {
  it("is order- and duplicate-insensitive, so the same ask is one cache entry", () => {
    expect(tokenScopeKey(["b", "a", "b", " a "])).toBe("a b");
    expect(tokenScopeKey(["a", "b"])).toBe(tokenScopeKey(["b", "a"]));
  });

  it("keeps a narrower ask distinct from a wider one", () => {
    // Logto issues exactly what was asked for, so serving the narrow key from
    // the wide token would hand back something missing a requested scope.
    expect(tokenScopeKey(["read"])).not.toBe(tokenScopeKey(["read", "write"]));
  });

  it("collapses empty and whitespace-only asks to the same key", () => {
    expect(tokenScopeKey()).toBe("");
    expect(tokenScopeKey([])).toBe("");
    expect(tokenScopeKey(["  "])).toBe("");
  });
});

describe("accessTokenExpiresAt", () => {
  function jwt(payload: Record<string, unknown>): string {
    const encode = (value: unknown) =>
      btoa(JSON.stringify(value))
        .replace(/\+/g, "-")
        .replace(/\//g, "_")
        .replace(/=+$/, "");
    return `${encode({ alg: "RS256" })}.${encode(payload)}.signature`;
  }

  it("prefers the token's own exp over a relative expires_in", () => {
    // `expires_in` is relative to a clock we did not read it on; `exp` is not.
    expect(
      accessTokenExpiresAt({
        accessToken: jwt({ exp: 2_000 }),
        expiresIn: 9_999,
        now: 1_000_000,
      }),
    ).toBe(2_000_000);
  });

  it("falls back to expires_in for an opaque token", () => {
    expect(
      accessTokenExpiresAt({
        accessToken: "opaque",
        expiresIn: 60,
        now: 1_000_000,
      }),
    ).toBe(1_060_000);
  });

  it("falls back to a short life when Logto reports neither", () => {
    expect(
      accessTokenExpiresAt({ accessToken: "opaque", now: 1_000_000 }),
    ).toBe(1_060_000);
  });
});

// --- mutations ---------------------------------------------------------------

type ExchangeSession = {
  _id: string;
  subject: string;
  sid?: string;
  tokenHash: string;
  prevTokenHash?: string;
  rotatedAt?: number;
  refreshingSince?: number;
  refreshClaimId?: string;
  logtoRefreshToken: string;
  lastIdToken: string;
  lastIdTokenExp: number;
  createdAt: number;
  lastRefreshedAt: number;
};

type ResourceTokenRow = {
  _id: string;
  sessionId: string;
  audience: string;
  scopeKey: string;
  accessToken: string;
  expiresAt: number;
  grantedScope: string;
  mintedAt: number;
};

function sessionFixture(
  overrides: Partial<ExchangeSession> = {},
): ExchangeSession {
  return {
    _id: "session-1",
    subject: "user-1",
    tokenHash: "current",
    rotatedAt: 1_000_000,
    logtoRefreshToken: "refresh-token",
    lastIdToken: "id-token",
    lastIdTokenExp: 3_000_000,
    createdAt: 500_000,
    lastRefreshedAt: 900_000,
    ...overrides,
  };
}

/**
 * A database double that filters on *every* `eq` in the index chain, which the
 * three-field `by_session_audience_scope` lookup needs.
 */
function exchangeHarness(
  initialSession: ExchangeSession | null,
  initialTokens: ResourceTokenRow[] = [],
  revocations: {
    subject?: { subject: string; revokedAt: number };
    sids?: Array<{ sid: string; revokedAt: number }>;
  } = {},
) {
  let session = initialSession === null ? null : { ...initialSession };
  let tokens = initialTokens.map((row) => ({ ...row }));
  const subjectRevocations =
    revocations.subject === undefined
      ? []
      : [{ _id: "subject-marker", ...revocations.subject }];
  const sidRevocations = (revocations.sids ?? []).map((row, index) => ({
    _id: `sid-marker-${index}`,
    ...row,
  }));
  const deleted: string[] = [];
  const inserted: Array<{ table: string; doc: Record<string, unknown> }> = [];
  let nextId = initialTokens.length + 1;

  const rowsFor = (table: string): Array<Record<string, unknown>> => {
    if (table === "sessions") return session === null ? [] : [session];
    if (table === "resourceTokens") return tokens;
    if (table === "subjectRevocations") return subjectRevocations;
    if (table === "sidRevocations") return sidRevocations;
    return [];
  };

  const db = {
    query: (table: string) => ({
      withIndex: (
        _index: string,
        configure?: (query: {
          eq(field: string, value: unknown): unknown;
          lt(field: string, value: number): unknown;
        }) => unknown,
      ) => {
        const equals: Array<[string, unknown]> = [];
        const lessThan: Array<[string, number]> = [];
        configure?.({
          eq(field, value) {
            equals.push([field, value]);
            return this;
          },
          lt(field, value) {
            lessThan.push([field, value]);
            return this;
          },
        });
        let direction: "asc" | "desc" = "asc";
        const matching = () => {
          const filtered = rowsFor(table).filter(
            (row) =>
              equals.every(([field, value]) => row[field] === value) &&
              lessThan.every(([field, value]) => {
                const actual = row[field];
                return typeof actual === "number" && actual < value;
              }),
          );
          return filtered.toSorted((left, right) => {
            const difference =
              Number(left["mintedAt"] ?? 0) - Number(right["mintedAt"] ?? 0);
            return direction === "desc" ? -difference : difference;
          });
        };
        const result = {
          unique: () => Promise.resolve(matching()[0] ?? null),
          collect: () => Promise.resolve(matching()),
          take: (count: number) => Promise.resolve(matching().slice(0, count)),
          order: (next: "asc" | "desc") => {
            direction = next;
            return result;
          },
        };
        return result;
      },
    }),
    normalizeId: (_table: string, id: string) => id,
    get: (id: string) =>
      Promise.resolve(session !== null && session._id === id ? session : null),
    patch: (id: string, fields: Record<string, unknown>) => {
      if (session !== null && session._id === id) {
        session = { ...session, ...fields } as ExchangeSession;
      }
      tokens = tokens.map((row) =>
        row._id === id ? ({ ...row, ...fields } as ResourceTokenRow) : row,
      );
      return Promise.resolve();
    },
    insert: (table: string, doc: Record<string, unknown>) => {
      inserted.push({ table, doc });
      const id = `${table}-${nextId++}`;
      if (table === "resourceTokens") {
        tokens.push({ _id: id, ...doc } as unknown as ResourceTokenRow);
      }
      return Promise.resolve(id);
    },
    delete: (id: string) => {
      deleted.push(id);
      if (session !== null && session._id === id) session = null;
      tokens = tokens.filter((row) => row._id !== id);
      return Promise.resolve();
    },
  };

  return {
    db,
    deleted,
    inserted,
    session: () => session,
    tokens: () => tokens,
  };
}

const beginHandler = handlerOf<
  {
    presentedHash: string;
    claimId: string;
    now: number;
    reuseWindowMs: number;
  },
  { outcome: string; sessionId?: string; refreshToken?: string }
>(beginTokenExchange);

const completeHandler = handlerOf<
  Record<string, unknown>,
  { outcome: string; expiresAt?: number; grantedScope?: string }
>(completeTokenExchange);

const cachedHandler = handlerOf<
  { presentedHash: string; audience: string; scopeKey: string; now: number },
  { accessToken: string; expiresAt: number; grantedScope: string } | null
>(cachedResourceToken);

describe("beginTokenExchange", () => {
  it("takes the same claim a refresh would, before Logto is touched", async () => {
    const harness = exchangeHarness(sessionFixture());
    await expect(
      beginHandler(
        { db: harness.db },
        {
          presentedHash: "current",
          claimId: "claim-a",
          now: 1_000_100,
          reuseWindowMs: 10_000,
        },
      ),
    ).resolves.toEqual({
      outcome: "exchange",
      sessionId: "session-1",
      refreshToken: "refresh-token",
    });
    expect(harness.session()).toMatchObject({
      refreshingSince: 1_000_100,
      refreshClaimId: "claim-a",
    });
  });

  it("does not rotate the session token", async () => {
    // The distinguishing property against `beginRefresh`: an exchange has no
    // candidate, so a caller mid-exchange keeps presenting the same token.
    const harness = exchangeHarness(sessionFixture());
    await beginHandler(
      { db: harness.db },
      {
        presentedHash: "current",
        claimId: "claim-a",
        now: 1_000_100,
        reuseWindowMs: 10_000,
      },
    );
    expect(harness.session()?.tokenHash).toBe("current");
    expect(harness.session()).not.toHaveProperty("prevTokenHash");
  });

  it("is transient while a refresh holds the claim", async () => {
    const harness = exchangeHarness(
      sessionFixture({ refreshingSince: 1_000_000, refreshClaimId: "other" }),
    );
    await expect(
      beginHandler(
        { db: harness.db },
        {
          presentedHash: "current",
          claimId: "claim-a",
          now: 1_000_100,
          reuseWindowMs: 10_000,
        },
      ),
    ).rejects.toMatchObject({
      data: { kind: "transient", code: "refresh_in_flight" },
    });
    expect(harness.deleted).toEqual([]);
  });

  it("deletes the session when a previous claim's outcome is unknown", async () => {
    const harness = exchangeHarness(
      sessionFixture({
        refreshingSince: 900_000,
        refreshClaimId: "abandoned",
      }),
    );
    await expect(
      beginHandler(
        { db: harness.db },
        {
          presentedHash: "current",
          claimId: "claim-a",
          now: 1_000_000,
          reuseWindowMs: 10_000,
        },
      ),
    ).resolves.toEqual({ outcome: "claim-expired" });
    expect(harness.deleted).toEqual(["session-1"]);
  });

  it("refuses a logically revoked session even before its rows are gone", async () => {
    const harness = exchangeHarness(sessionFixture(), [], {
      subject: { subject: "user-1", revokedAt: 600_000 },
    });
    await expect(
      beginHandler(
        { db: harness.db },
        {
          presentedHash: "current",
          claimId: "claim-a",
          now: 1_000_100,
          reuseWindowMs: 10_000,
        },
      ),
    ).rejects.toMatchObject({
      data: { kind: "terminal", code: "session_revoked" },
    });
  });
});

describe("completeTokenExchange", () => {
  const baseArgs = {
    sessionId: "session-1",
    claimId: "claim-a",
    audience: "organization:org-1",
    scopeKey: "read",
    accessToken: "minted-token",
    expiresAt: 4_000_000,
    grantedScope: "read",
    now: 1_000_200,
  };

  function claimed(overrides: Partial<ExchangeSession> = {}) {
    return sessionFixture({
      refreshingSince: 1_000_100,
      refreshClaimId: "claim-a",
      ...overrides,
    });
  }

  it("caches the token, persists rotation, and releases the claim together", async () => {
    const harness = exchangeHarness(claimed());
    await expect(
      completeHandler(
        { db: harness.db },
        {
          ...baseArgs,
          newRefreshToken: "rotated",
          refreshedIdToken: {
            idToken: "fresh-id-token",
            exp: 5_000_000,
            sid: "sid-1",
          },
        },
      ),
    ).resolves.toEqual({
      outcome: "committed",
      expiresAt: 4_000_000,
      grantedScope: "read",
    });
    expect(harness.tokens()).toHaveLength(1);
    expect(harness.tokens()[0]).toMatchObject({
      audience: "organization:org-1",
      scopeKey: "read",
      accessToken: "minted-token",
    });
    expect(harness.session()).toMatchObject({
      logtoRefreshToken: "rotated",
      lastIdToken: "fresh-id-token",
      lastIdTokenExp: 5_000_000,
      sid: "sid-1",
      refreshingSince: undefined,
      refreshClaimId: undefined,
    });
  });

  it("keeps the stored refresh token when Logto rotated nothing", async () => {
    const harness = exchangeHarness(claimed());
    await completeHandler({ db: harness.db }, baseArgs);
    expect(harness.session()).toMatchObject({
      logtoRefreshToken: "refresh-token",
      lastIdToken: "id-token",
    });
  });

  it("replaces the row for a repeat of the same audience and scope", async () => {
    const harness = exchangeHarness(claimed(), [
      {
        _id: "resourceTokens-0",
        sessionId: "session-1",
        audience: "organization:org-1",
        scopeKey: "read",
        accessToken: "older-token",
        expiresAt: 2_000_000,
        grantedScope: "read",
        mintedAt: 900_000,
      },
    ]);
    await completeHandler({ db: harness.db }, baseArgs);
    expect(harness.tokens()).toHaveLength(1);
    expect(harness.tokens()[0]).toMatchObject({
      accessToken: "minted-token",
      expiresAt: 4_000_000,
    });
  });

  it("evicts the least recently minted rows to stay inside the cache bound", async () => {
    // The bound is what keeps deleting a session a bounded amount of work.
    const existing = Array.from(
      { length: RESOURCE_TOKEN_CACHE_LIMIT },
      (_, index) => ({
        _id: `resourceTokens-${index}`,
        sessionId: "session-1",
        audience: `resource:api-${index}`,
        scopeKey: "",
        accessToken: `token-${index}`,
        expiresAt: 4_000_000,
        grantedScope: "",
        mintedAt: 100_000 + index,
      }),
    );
    const harness = exchangeHarness(claimed(), existing);
    await completeHandler({ db: harness.db }, baseArgs);
    expect(harness.tokens()).toHaveLength(RESOURCE_TOKEN_CACHE_LIMIT);
    expect(harness.tokens().map((row) => row.audience)).toContain(
      "organization:org-1",
    );
    expect(harness.tokens().map((row) => row.audience)).not.toContain(
      "resource:api-0",
    );
  });

  it("fences a completion whose claim was taken over", async () => {
    const harness = exchangeHarness(
      claimed({ refreshClaimId: "someone-else" }),
    );
    await expect(
      completeHandler({ db: harness.db }, baseArgs),
    ).resolves.toEqual({ outcome: "stale-owner" });
    expect(harness.tokens()).toEqual([]);
  });

  it("deletes rather than caches a token minted under withdrawn authority", async () => {
    const harness = exchangeHarness(claimed(), [], {
      subject: { subject: "user-1", revokedAt: 600_000 },
    });
    await expect(
      completeHandler({ db: harness.db }, baseArgs),
    ).resolves.toEqual({ outcome: "revoked" });
    expect(harness.deleted).toEqual(["session-1"]);
    expect(harness.tokens()).toEqual([]);
  });

  it("reports a missing session rather than inventing one", async () => {
    const harness = exchangeHarness(null);
    await expect(
      completeHandler({ db: harness.db }, baseArgs),
    ).resolves.toEqual({ outcome: "missing" });
  });
});

describe("cachedResourceToken", () => {
  const row: ResourceTokenRow = {
    _id: "resourceTokens-0",
    sessionId: "session-1",
    audience: "organization:org-1",
    scopeKey: "read",
    accessToken: "cached-token",
    expiresAt: 2_000_000,
    grantedScope: "read manage",
    mintedAt: 1_000_000,
  };
  const args = {
    presentedHash: "current",
    audience: "organization:org-1",
    scopeKey: "read",
    now: 1_500_000,
  };

  it("serves a fresh row without touching Logto", async () => {
    const harness = exchangeHarness(sessionFixture(), [row]);
    await expect(cachedHandler({ db: harness.db }, args)).resolves.toEqual({
      audience: "organization:org-1",
      grantedScope: "read manage",
      expiresAt: 2_000_000,
      accessToken: "cached-token",
    });
  });

  it("does not serve a row inside the expiry skew", async () => {
    const harness = exchangeHarness(sessionFixture(), [row]);
    await expect(
      cachedHandler(
        { db: harness.db },
        { ...args, now: row.expiresAt - RESOURCE_TOKEN_SKEW_MS },
      ),
    ).resolves.toBeNull();
  });

  it("does not serve a different scope's token", async () => {
    const harness = exchangeHarness(sessionFixture(), [row]);
    await expect(
      cachedHandler({ db: harness.db }, { ...args, scopeKey: "read write" }),
    ).resolves.toBeNull();
  });

  it("is blind to a logically revoked session's cache", async () => {
    // The row may still be waiting for a bounded cleanup batch. Until it is
    // gone it must retain no authority — the same rule every other read follows.
    const harness = exchangeHarness(sessionFixture(), [row], {
      subject: { subject: "user-1", revokedAt: 600_000 },
    });
    await expect(cachedHandler({ db: harness.db }, args)).resolves.toBeNull();
  });

  it("answers null for a token that resolves to no session at all", async () => {
    const harness = exchangeHarness(null, [row]);
    await expect(cachedHandler({ db: harness.db }, args)).resolves.toBeNull();
  });
});
