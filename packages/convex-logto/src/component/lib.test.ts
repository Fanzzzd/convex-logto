import { getFunctionName, type FunctionReference } from "convex/server";
import { describe, expect, it, vi } from "vitest";
import {
  beginRefresh,
  beginSubjectRevocationByToken,
  completeRefresh,
  consumeSessionForSignOut,
  devicePublicKeyForToken,
  gc,
  killSession,
  killSubjectSessionsByToken,
  deleteOwnedSession,
  listSubjectSessions,
  refresh,
  releaseClaim,
  resolveCallerSession,
  setSessionLabel,
  signOut,
} from "./lib";
import {
  SESSION_LIST_LIMIT,
  SESSION_LIST_SCAN_BYTES,
  SESSION_LIST_SCAN_LIMIT,
  SESSION_TOKEN_GENERATION_LIMIT,
  toBase64Url,
} from "./core";

type SubjectSession = {
  _id: string;
  subject: string;
  tokenHash: string;
  prevTokenHash?: string;
  rotatedAt?: number;
  lastIdToken: string;
  createdAt: number;
};

function subjectSessionHarness(
  initial: SubjectSession[],
  initialMarkers: Array<{ subject: string; revokedAt: number }> = [],
) {
  const sessions = [...initial];
  const deleted: string[] = [];
  const markers: Array<Record<string, unknown>> = initialMarkers.map(
    (marker, index) => ({ _id: `subject-marker-${index}`, ...marker }),
  );
  const db = {
    query: (table: string) => ({
      withIndex: (
        index: string,
        configure: (query: {
          eq(field: string, value: string): unknown;
        }) => unknown,
      ) => {
        let field = "";
        let value = "";
        configure({
          eq(nextField, nextValue) {
            field = nextField;
            value = nextValue;
            return this;
          },
        });
        const matching = () =>
          table === "sessions"
            ? sessions.filter(
                (session) =>
                  (session as unknown as Record<string, unknown>)[field] ===
                  value,
              )
            : table === "subjectRevocations"
              ? markers
              : [];
        return {
          unique: () => Promise.resolve(matching()[0] ?? null),
          collect: () => Promise.resolve(matching()),
          order: () => ({
            first: () =>
              Promise.resolve(
                [...matching()].toSorted(
                  (left, right) => right.createdAt - left.createdAt,
                )[0] ?? null,
              ),
          }),
          index,
        };
      },
    }),
    delete: (id: string) => {
      deleted.push(id);
      const index = sessions.findIndex((session) => session._id === id);
      if (index >= 0) sessions.splice(index, 1);
      return Promise.resolve();
    },
    insert: (table: string, value: Record<string, unknown>) => {
      expect(table).toBe("subjectRevocations");
      markers.push({ _id: "subject-marker", ...value });
      return Promise.resolve("subject-marker");
    },
    patch: () => Promise.resolve(),
  };
  type Handler = (
    ctx: { db: typeof db },
    args: { presentedHash: string; now: number; reuseWindowMs: number },
  ) => Promise<
    | {
        outcome: "signed-out";
        subject: string;
        callerSessionId: string;
        revokedAt: number;
      }
    | { outcome: "reuse" }
  >;
  const handler = (
    beginSubjectRevocationByToken as unknown as Record<string, Handler>
  )["_handler"]!;
  return { db, deleted, markers, sessions, handler };
}

describe("killSubjectSessionsByToken", () => {
  const now = 1_000_000;
  const reuseWindowMs = 10_000;
  const fixture = (rotatedAt = now - 1_000): SubjectSession[] => [
    {
      _id: "subject-a-caller",
      subject: "subject-a",
      tokenHash: "caller-current",
      prevTokenHash: "caller-previous",
      rotatedAt,
      lastIdToken: "caller-id-token",
      createdAt: 900_000,
    },
    {
      _id: "subject-a-other",
      subject: "subject-a",
      tokenHash: "other-current",
      lastIdToken: "other-id-token",
      createdAt: 900_001,
    },
    {
      _id: "subject-b",
      subject: "subject-b",
      tokenHash: "subject-b-current",
      lastIdToken: "subject-b-id-token",
      createdAt: 900_002,
    },
  ];

  it("derives the subject from the current token and deletes all of only that subject", async () => {
    const { db, deleted, markers, sessions, handler } = subjectSessionHarness(
      fixture(now - reuseWindowMs - 1),
    );

    await expect(
      handler({ db }, { presentedHash: "caller-current", now, reuseWindowMs }),
    ).resolves.toEqual({
      outcome: "signed-out",
      subject: "subject-a",
      callerSessionId: "subject-a-caller",
      revokedAt: now,
    });
    expect(markers).toEqual([
      { _id: "subject-marker", subject: "subject-a", revokedAt: now },
    ]);
    expect(deleted).toEqual([]);
    expect(sessions).toHaveLength(3);
  });

  it("accepts a recent superseded token hash inside the Reuse window", async () => {
    const { db, deleted, handler } = subjectSessionHarness(fixture());

    await expect(
      handler({ db }, { presentedHash: "caller-previous", now, reuseWindowMs }),
    ).resolves.toEqual({
      outcome: "signed-out",
      subject: "subject-a",
      callerSessionId: "subject-a-caller",
      revokedAt: now,
    });
    expect(deleted).toEqual([]);
  });

  it("contains previous-token reuse outside the window to only that session", async () => {
    const { db, deleted, sessions, handler } = subjectSessionHarness(
      fixture(now - reuseWindowMs),
    );

    await expect(
      handler({ db }, { presentedHash: "caller-previous", now, reuseWindowMs }),
    ).resolves.toEqual({ outcome: "reuse" });
    expect(deleted).toEqual(["subject-a-caller"]);
    expect(sessions.map((session) => session._id)).toEqual([
      "subject-a-other",
      "subject-b",
    ]);
  });

  it("refuses a logically revoked session's token", async () => {
    // The row is dead but its bounded physical cleanup has not reached it yet.
    // Accepting it would raise the subject watermark past sessions created
    // after it died and delete them.
    const { db, deleted, sessions, handler } = subjectSessionHarness(
      fixture(),
      [{ subject: "subject-a", revokedAt: 900_000 }],
    );

    await expect(
      handler({ db }, { presentedHash: "caller-current", now, reuseWindowMs }),
    ).rejects.toMatchObject({
      data: { kind: "terminal", code: "session_revoked" },
    });
    expect(deleted).toEqual([]);
    expect(sessions).toHaveLength(3);
  });

  it("rejects an unknown token terminally", async () => {
    const { db, handler } = subjectSessionHarness(fixture());

    await expect(
      handler({ db }, { presentedHash: "unknown", now, reuseWindowMs }),
    ).rejects.toMatchObject({
      data: { kind: "terminal", code: "session_not_found" },
    });
  });
});

type RefreshSession = {
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

type TokenGeneration = {
  _id: string;
  sessionId: string;
  tokenHash: string;
  rotatedAt: number;
  expiresAt: number;
};

function sessionMutationHarness(
  initial: RefreshSession | null,
  initialGenerations: TokenGeneration[] = [],
  initialRevocations: {
    subject?: { subject: string; revokedAt: number };
    sids?: Array<{ sid: string; revokedAt: number }>;
  } = {},
) {
  let session = initial === null ? null : { ...initial };
  const generations = initialGenerations.map((generation) => ({
    ...generation,
  }));
  const subjectRevocations =
    initialRevocations.subject === undefined
      ? []
      : [{ _id: "subject-revocation", ...initialRevocations.subject }];
  const sidRevocations = (initialRevocations.sids ?? []).map(
    (revocation, index) => ({
      _id: `sid-revocation-${index}`,
      ...revocation,
    }),
  );
  let nextGenerationId = generations.length + 1;
  const patches: Array<Record<string, unknown>> = [];
  const deleted: string[] = [];
  const db = {
    query: (table: string) => ({
      withIndex: (
        _index: string,
        configure: (query: {
          eq(field: string, value: string): unknown;
          lt(field: string, value: number): unknown;
        }) => unknown,
      ) => {
        let field = "";
        let value: string | number = "";
        let operator: "eq" | "lt" = "eq";
        configure({
          eq(nextField, nextValue) {
            field = nextField;
            value = nextValue;
            operator = "eq";
            return this;
          },
          lt(nextField, nextValue) {
            field = nextField;
            value = nextValue;
            operator = "lt";
            return this;
          },
        });
        let direction: "asc" | "desc" = "asc";
        const matching = () => {
          const rows: Array<
            | RefreshSession
            | TokenGeneration
            | (typeof subjectRevocations)[number]
            | (typeof sidRevocations)[number]
          > = (() => {
            if (table === "sessions") return session === null ? [] : [session];
            if (table === "sessionTokenGenerations") return generations;
            if (table === "subjectRevocations") return subjectRevocations;
            if (table === "sidRevocations") return sidRevocations;
            return [];
          })();
          const filtered = rows.filter((row) => {
            const actual = (row as unknown as Record<string, unknown>)[field];
            return operator === "eq"
              ? actual === value
              : typeof actual === "number" &&
                  typeof value === "number" &&
                  actual < value;
          });
          return filtered.toSorted((left, right) => {
            const difference =
              (left as TokenGeneration).rotatedAt -
              (right as TokenGeneration).rotatedAt;
            return direction === "desc" ? -difference : difference;
          });
        };
        const result = {
          unique: () => Promise.resolve(matching()[0] ?? null),
          collect: () => Promise.resolve(matching()),
          take: (count: number) => Promise.resolve(matching().slice(0, count)),
          order: (nextDirection: "asc" | "desc") => {
            direction = nextDirection;
            return result;
          },
        };
        return result;
      },
    }),
    normalizeId: (_table: string, id: string) =>
      session?._id === id ? id : null,
    get: (id: string) =>
      Promise.resolve(
        session?._id === id
          ? session
          : (generations.find((generation) => generation._id === id) ?? null),
      ),
    insert: (table: string, value: Omit<TokenGeneration, "_id">) => {
      if (table !== "sessionTokenGenerations") {
        throw new Error(`Unexpected insert into ${table}.`);
      }
      const id = `generation-${nextGenerationId++}`;
      generations.push({ _id: id, ...value });
      return Promise.resolve(id);
    },
    patch: (_id: string, patch: Record<string, unknown>) => {
      patches.push(patch);
      if (session) session = { ...session, ...patch } as RefreshSession;
      return Promise.resolve();
    },
    delete: (id: string) => {
      deleted.push(id);
      if (session?._id === id) session = null;
      const generationIndex = generations.findIndex(
        (generation) => generation._id === id,
      );
      if (generationIndex >= 0) generations.splice(generationIndex, 1);
      return Promise.resolve();
    },
  };
  return {
    db,
    patches,
    deleted,
    session: () => session,
    generations: () => generations.map((generation) => ({ ...generation })),
  };
}

function internalHandler<Args, Result>(
  value: unknown,
  _types?: (args: Args) => Result,
): (ctx: unknown, args: Args) => Promise<Result> {
  return (
    value as Record<string, (ctx: unknown, args: Args) => Promise<Result>>
  )["_handler"]!;
}

const refreshFixture = (): RefreshSession => ({
  _id: "session-1",
  subject: "subject-1",
  sid: "persisted-sid",
  tokenHash: "current",
  prevTokenHash: "previous",
  rotatedAt: 900_000,
  logtoRefreshToken: "refresh-token",
  lastIdToken: "id-token",
  lastIdTokenExp: 2_000_000,
  createdAt: 900_000,
  lastRefreshedAt: 900_000,
});

type BeginRefreshArgs = {
  presentedHash: string;
  candidateHash: string;
  claimId: string;
  now: number;
  reuseWindowMs: number;
};
type CompleteRefreshArgs = {
  sessionId: string;
  claimId: string;
  candidateHash: string;
  newRefreshToken?: string;
  idToken: string;
  idTokenExp: number;
  sid?: string;
  now: number;
  reuseWindowMs: number;
};
type CompleteRefreshResult = {
  outcome: "committed" | "missing" | "stale-owner" | "revoked";
};
type ClaimArgs = { sessionId: string; claimId: string };
type ConsumeSessionForSignOutArgs = {
  tokenHash: string;
  now: number;
  reuseWindowMs: number;
};
type SignOutConsumptionResult =
  | { outcome: "taken" | "reuse" }
  | { outcome: "not-found" };

const beginRefreshHandler = internalHandler<BeginRefreshArgs, unknown>(
  beginRefresh,
);
const completeRefreshHandler = internalHandler<
  CompleteRefreshArgs,
  CompleteRefreshResult
>(completeRefresh);
const releaseClaimHandler = internalHandler<ClaimArgs, boolean>(releaseClaim);
const killSessionHandler = internalHandler<ClaimArgs, boolean>(killSession);
const consumeSessionForSignOutHandler = internalHandler<
  ConsumeSessionForSignOutArgs,
  SignOutConsumptionResult
>(consumeSessionForSignOut);
const gcHandler = internalHandler<Record<string, never>, null>(gc);

type SignOutArgs = {
  endpoint: string;
  appId: string;
  clientSecret: string;
  sessionToken: string;
  deviceProof?: string;
  postLogoutRedirectUri?: string;
  federated?: boolean;
  reuseWindowMs?: number;
};
const signOutHandler = internalHandler<SignOutArgs, { endSessionUrl?: string }>(
  signOut,
);
const refreshActionHandler = internalHandler<
  SignOutArgs,
  { idToken: string; sessionToken: string; sessionId: string }
>(refresh);
const killSubjectSessionsByTokenHandler = internalHandler<
  Pick<SignOutArgs, "sessionToken" | "deviceProof" | "reuseWindowMs"> & {
    now: number;
  },
  | { outcome: "signed-out"; count: number; subject: string }
  | { outcome: "reuse" }
>(killSubjectSessionsByToken);
const devicePublicKeyForTokenHandler = internalHandler<
  { presentedHash: string },
  {
    kty: "EC";
    crv: "P-256";
    x: string;
    y: string;
  } | null
>(devicePublicKeyForToken);

async function deviceProofFixture(sessionToken: string) {
  const pair = (await crypto.subtle.generateKey(
    { name: "ECDSA", namedCurve: "P-256" },
    false,
    ["sign", "verify"],
  )) as CryptoKeyPair;
  const jwk = await crypto.subtle.exportKey("jwk", pair.publicKey);
  if (jwk.kty !== "EC" || !jwk.x || !jwk.y) throw new Error("invalid JWK");
  const signature = await crypto.subtle.sign(
    { name: "ECDSA", hash: "SHA-256" },
    pair.privateKey,
    new TextEncoder().encode(sessionToken),
  );
  return {
    publicKey: {
      kty: "EC" as const,
      crv: "P-256" as const,
      x: jwk.x,
      y: jwk.y,
    },
    proof: toBase64Url(new Uint8Array(signature)),
  };
}

function idToken(overrides: Record<string, unknown> = {}) {
  const payload = toBase64Url(
    new TextEncoder().encode(
      JSON.stringify({
        iss: "https://auth.example.com/oidc",
        aud: "app-1",
        sub: "subject-1",
        exp: 2_000_000_000,
        ...overrides,
      }),
    ),
  );
  return `header.${payload}.signature`;
}

const refreshArgs = {
  endpoint: "https://auth.example.com",
  appId: "app-1",
  clientSecret: "secret",
  sessionToken: "caller-token",
} as const;

function tokenEndpointRefreshHarness() {
  const runMutation = vi
    .fn()
    .mockResolvedValueOnce({
      outcome: "refresh" as const,
      sessionId: "caller-session",
      refreshToken: "refresh-token",
    })
    .mockResolvedValueOnce({ outcome: "committed" as const });
  const promise = refreshActionHandler(
    { runQuery: () => Promise.resolve(null), runMutation },
    refreshArgs,
  );
  return { promise, runMutation };
}

function expectRefreshClaimReleased(
  runMutation: ReturnType<typeof vi.fn>,
): void {
  expect(runMutation).toHaveBeenCalledTimes(2);
  const reference = runMutation.mock.calls[1]?.[0] as FunctionReference<
    "mutation",
    "internal"
  >;
  expect(getFunctionName(reference)).toBe("lib:releaseClaim");
  expect(runMutation.mock.calls[1]?.[1]).toMatchObject({
    sessionId: "caller-session",
    claimId: expect.any(String),
  });
  expect(runMutation.mock.calls[1]?.[1]).not.toHaveProperty("idToken");
}

/**
 * The refresh token may already have been rotated remotely, so the claim must
 * stay in place: the next presentation then ages into `claim-expired` instead
 * of spending the same token a second time.
 */
function expectRefreshClaimRetained(
  runMutation: ReturnType<typeof vi.fn>,
): void {
  expect(runMutation).toHaveBeenCalledTimes(1);
  const reference = runMutation.mock.calls[0]?.[0] as FunctionReference<
    "mutation",
    "internal"
  >;
  expect(getFunctionName(reference)).toBe("lib:beginRefresh");
}

describe("bounded token endpoint", () => {
  it("aborts while waiting for token response headers after 10 seconds", async () => {
    vi.useFakeTimers();
    let observedSignal: AbortSignal | undefined;
    let markFetchStarted = () => {};
    const fetchStarted = new Promise<void>((resolve) => {
      markFetchStarted = resolve;
    });
    const fetchSpy = vi.spyOn(globalThis, "fetch").mockImplementation(
      (_input, init) =>
        new Promise<Response>((_resolve, reject) => {
          observedSignal = init?.signal ?? undefined;
          markFetchStarted();
          observedSignal?.addEventListener(
            "abort",
            () => reject(new DOMException("aborted", "AbortError")),
            { once: true },
          );
          setTimeout(() => reject(new Error("test fallback")), 10_001);
        }),
    );
    const { promise, runMutation } = tokenEndpointRefreshHarness();
    void promise.catch(() => {});
    try {
      await fetchStarted;
      await vi.advanceTimersByTimeAsync(10_000);
      expect(observedSignal?.aborted).toBe(true);
      await expect(promise).rejects.toMatchObject({
        data: { kind: "transient", code: "logto_outcome_unknown" },
      });
      expectRefreshClaimRetained(runMutation);
    } finally {
      await vi.advanceTimersByTimeAsync(1);
      await promise.catch(() => {});
      fetchSpy.mockRestore();
      vi.useRealTimers();
    }
  });

  it("keeps the timeout active while streaming the token response body", async () => {
    vi.useFakeTimers();
    let observedSignal: AbortSignal | undefined;
    let markFetchStarted = () => {};
    const fetchStarted = new Promise<void>((resolve) => {
      markFetchStarted = resolve;
    });
    const fetchSpy = vi
      .spyOn(globalThis, "fetch")
      .mockImplementation((_input, init) => {
        observedSignal = init?.signal ?? undefined;
        markFetchStarted();
        const stream = new ReadableStream<Uint8Array>({
          start(controller) {
            observedSignal?.addEventListener(
              "abort",
              () => controller.error(new DOMException("aborted", "AbortError")),
              { once: true },
            );
            setTimeout(
              () => controller.error(new Error("test fallback")),
              10_001,
            );
          },
        });
        return Promise.resolve(new Response(stream));
      });
    const { promise, runMutation } = tokenEndpointRefreshHarness();
    void promise.catch(() => {});
    try {
      await fetchStarted;
      await vi.advanceTimersByTimeAsync(10_000);
      expect(observedSignal?.aborted).toBe(true);
      await expect(promise).rejects.toMatchObject({
        data: { kind: "transient", code: "logto_outcome_unknown" },
      });
      expectRefreshClaimRetained(runMutation);
    } finally {
      await vi.advanceTimersByTimeAsync(1);
      await promise.catch(() => {});
      fetchSpy.mockRestore();
      vi.useRealTimers();
    }
  });

  it("cancels an unknown-length token response above 256 KiB", async () => {
    const cancel = vi.fn();
    const responseJson = JSON.stringify({
      id_token: idToken(),
      padding: "x".repeat(256 * 1024),
    });
    const bytes = new TextEncoder().encode(responseJson);
    const chunks = [bytes.slice(0, 256 * 1024), bytes.slice(256 * 1024)];
    let chunkIndex = 0;
    const stream = new ReadableStream<Uint8Array>({
      pull(controller) {
        const chunk = chunks[chunkIndex];
        if (chunk === undefined) return;
        chunkIndex += 1;
        controller.enqueue(chunk);
      },
      cancel,
    });
    const response = new Response(stream, {
      headers: { "Content-Length": "1" },
    });
    const fetchSpy = vi.spyOn(globalThis, "fetch").mockResolvedValue(response);
    const { promise, runMutation } = tokenEndpointRefreshHarness();
    try {
      await expect(promise).rejects.toMatchObject({
        data: { kind: "transient", code: "logto_outcome_unknown" },
      });
      expect(cancel).toHaveBeenCalledTimes(1);
      expectRefreshClaimRetained(runMutation);
    } finally {
      fetchSpy.mockRestore();
    }
  });

  it("treats a token response stream error as an unknown outcome and keeps the claim", async () => {
    const stream = new ReadableStream<Uint8Array>({
      start(controller) {
        controller.error(new Error("stream failed"));
      },
    });
    const fetchSpy = vi
      .spyOn(globalThis, "fetch")
      .mockResolvedValue(new Response(stream));
    const { promise, runMutation } = tokenEndpointRefreshHarness();
    try {
      await expect(promise).rejects.toMatchObject({
        data: { kind: "transient", code: "logto_outcome_unknown" },
      });
      expectRefreshClaimRetained(runMutation);
    } finally {
      fetchSpy.mockRestore();
    }
  });

  it("keeps sessions alive when Logto rejects this deployment's credentials", async () => {
    // 401 invalid_client means LOGTO_CLIENT_SECRET is wrong, not that the
    // user's grant died. Treating it as terminal would delete every session in
    // the deployment on a secret rotation.
    const fetchSpy = vi.spyOn(globalThis, "fetch").mockResolvedValue(
      new Response(JSON.stringify({ error: "invalid_client" }), {
        status: 401,
        headers: { "Content-Type": "application/json" },
      }),
    );
    const { promise, runMutation } = tokenEndpointRefreshHarness();
    try {
      await expect(promise).rejects.toMatchObject({
        data: { kind: "transient", code: "invalid_client" },
      });
      expectRefreshClaimReleased(runMutation);
    } finally {
      fetchSpy.mockRestore();
    }
  });

  it("kills the session only when Logto rejects the grant itself", async () => {
    const fetchSpy = vi.spyOn(globalThis, "fetch").mockResolvedValue(
      new Response(JSON.stringify({ error: "invalid_grant" }), {
        status: 400,
        headers: { "Content-Type": "application/json" },
      }),
    );
    const { promise, runMutation } = tokenEndpointRefreshHarness();
    try {
      await expect(promise).rejects.toMatchObject({
        data: { kind: "terminal", code: "invalid_grant" },
      });
      expect(runMutation).toHaveBeenCalledTimes(2);
      expect(
        getFunctionName(
          runMutation.mock.calls[1]?.[0] as FunctionReference<
            "mutation",
            "internal"
          >,
        ),
      ).toBe("lib:killSession");
    } finally {
      fetchSpy.mockRestore();
    }
  });

  it("keeps every session when LOGTO_ENDPOINT drifts from Logto's issuer", async () => {
    // The operator repointed the deployment at a new custom domain while Logto
    // still issues the old `iss`. Credentials are fine, so Logto refreshes and
    // rotates happily — deleting the row here would destroy every session in
    // the deployment, one refresh at a time.
    const fetchSpy = vi.spyOn(globalThis, "fetch").mockResolvedValue(
      new Response(
        JSON.stringify({
          id_token: idToken({ iss: "https://old.example.com/oidc" }),
          refresh_token: "rotated-token",
        }),
        { headers: { "Content-Type": "application/json" } },
      ),
    );
    const { promise, runMutation } = tokenEndpointRefreshHarness();
    try {
      await expect(promise).rejects.toMatchObject({
        data: { kind: "transient", code: "id_token_mismatch" },
      });
      expect(runMutation).toHaveBeenCalledTimes(2);
      expect(
        getFunctionName(
          runMutation.mock.calls[1]?.[0] as FunctionReference<
            "mutation",
            "internal"
          >,
        ),
      ).toBe("lib:persistRotatedRefreshToken");
      // The rotation must be stored: presenting the superseded token again
      // would trip Logto's reuse detection and destroy the whole grant.
      expect(runMutation.mock.calls[1]?.[1]).toMatchObject({
        refreshToken: "rotated-token",
      });
    } finally {
      fetchSpy.mockRestore();
    }
  });

  it("accepts the spec-legal array form of aud", async () => {
    const fetchSpy = vi.spyOn(globalThis, "fetch").mockResolvedValue(
      new Response(JSON.stringify({ id_token: idToken({ aud: ["app-1"] }) }), {
        headers: { "Content-Type": "application/json" },
      }),
    );
    const { promise, runMutation } = tokenEndpointRefreshHarness();
    try {
      await expect(promise).resolves.toMatchObject({
        idToken: expect.any(String),
      });
      expect(
        getFunctionName(
          runMutation.mock.calls[1]?.[0] as FunctionReference<
            "mutation",
            "internal"
          >,
        ),
      ).toBe("lib:completeRefresh");
    } finally {
      fetchSpy.mockRestore();
    }
  });

  it("keeps the session when a 2xx body is not the JSON we expected", async () => {
    // A proxy or WAF interstitial in front of the token endpoint. An unreadable
    // 2xx already preserved the row; a readable non-JSON one used to delete it.
    const fetchSpy = vi.spyOn(globalThis, "fetch").mockResolvedValue(
      new Response("<html>checking your browser</html>", {
        headers: { "Content-Type": "text/html" },
      }),
    );
    const { promise, runMutation } = tokenEndpointRefreshHarness();
    try {
      await expect(promise).rejects.toMatchObject({
        data: { kind: "transient", code: "no_id_token" },
      });
      expectRefreshClaimRetained(runMutation);
    } finally {
      fetchSpy.mockRestore();
    }
  });

  it("clears the token endpoint timer after a successful response", async () => {
    vi.useFakeTimers();
    const fetchSpy = vi.spyOn(globalThis, "fetch").mockResolvedValue(
      new Response(JSON.stringify({ id_token: idToken() }), {
        headers: { "Content-Type": "application/json" },
      }),
    );
    const { promise } = tokenEndpointRefreshHarness();
    try {
      await expect(promise).resolves.toMatchObject({
        idToken: expect.any(String),
      });
      expect(vi.getTimerCount()).toBe(0);
    } finally {
      await promise.catch(() => {});
      fetchSpy.mockRestore();
      vi.useRealTimers();
    }
  });
});

describe("refresh claim ownership", () => {
  it("records the opaque claim id before allowing an action to call Logto", async () => {
    const harness = sessionMutationHarness(refreshFixture());

    await expect(
      beginRefreshHandler(
        { db: harness.db },
        {
          presentedHash: "current",
          candidateHash: "candidate",
          claimId: "claim-a",
          now: 1_000_000,
          reuseWindowMs: 10_000,
        },
      ),
    ).resolves.toMatchObject({ outcome: "refresh" });
    expect(harness.patches).toEqual([
      { refreshingSince: 1_000_000, refreshClaimId: "claim-a" },
    ]);
  });

  it("expires a session instead of taking over a claim whose remote outcome is unknown", async () => {
    const harness = sessionMutationHarness({
      ...refreshFixture(),
      refreshingSince: 900_000,
      refreshClaimId: "abandoned-claim",
    });
    await expect(
      beginRefreshHandler(
        { db: harness.db },
        {
          presentedHash: "current",
          candidateHash: "candidate",
          claimId: "claim-b",
          now: 1_000_000,
          reuseWindowMs: 10_000,
        },
      ),
    ).resolves.toEqual({
      outcome: "claim-expired",
    });
    expect(harness.deleted).toEqual(["session-1"]);
    expect(harness.patches).toEqual([]);
  });

  it("rejects a late completion that no longer owns the refresh claim", async () => {
    const session = {
      ...refreshFixture(),
      refreshingSince: 999_000,
      refreshClaimId: "current-owner",
    };
    const harness = sessionMutationHarness(session, [], {
      subject: {
        subject: session.subject,
        revokedAt: session.createdAt,
      },
    });
    await expect(
      completeRefreshHandler(
        { db: harness.db },
        {
          sessionId: "session-1",
          claimId: "stale-owner",
          candidateHash: "candidate",
          newRefreshToken: "rotated-refresh-token",
          idToken: "new-id-token",
          idTokenExp: 3_000_000,
          now: 1_000_000,
          reuseWindowMs: 10_000,
        },
      ),
    ).resolves.toEqual({ outcome: "stale-owner" });
    expect(harness.patches).toEqual([]);
    expect(harness.deleted).toEqual([]);
    expect(harness.session()?.tokenHash).toBe("current");
  });

  it("lets the owner complete exactly once and clears its claim", async () => {
    const harness = sessionMutationHarness({
      ...refreshFixture(),
      refreshingSince: 999_000,
      refreshClaimId: "claim-a",
    });
    const args = {
      sessionId: "session-1",
      claimId: "claim-a",
      candidateHash: "candidate",
      newRefreshToken: "rotated-refresh-token",
      idToken: "new-id-token",
      idTokenExp: 3_000_000,
      now: 1_000_000,
      reuseWindowMs: 10_000,
    };

    await expect(
      completeRefreshHandler({ db: harness.db }, args),
    ).resolves.toEqual({ outcome: "committed" });
    expect(harness.session()).toMatchObject({
      tokenHash: "candidate",
      prevTokenHash: "current",
      refreshingSince: undefined,
      refreshClaimId: undefined,
      logtoRefreshToken: "rotated-refresh-token",
      lastIdToken: "new-id-token",
    });
    await expect(
      completeRefreshHandler({ db: harness.db }, args),
    ).resolves.toEqual({ outcome: "stale-owner" });
    expect(harness.patches).toHaveLength(1);
  });

  it("distinguishes a missing session from stale claim ownership", async () => {
    const harness = sessionMutationHarness(null);

    await expect(
      completeRefreshHandler(
        { db: harness.db },
        {
          sessionId: "session-1",
          claimId: "claim-a",
          candidateHash: "candidate",
          idToken: "new-id-token",
          idTokenExp: 3_000_000,
          now: 1_000_000,
          reuseWindowMs: 10_000,
        },
      ),
    ).resolves.toEqual({ outcome: "missing" });
    expect(harness.patches).toEqual([]);
  });

  it("contains a subject revocation committed while the refresh action was remote", async () => {
    const session = {
      ...refreshFixture(),
      refreshingSince: 899_000,
      refreshClaimId: "claim-a",
    };
    const harness = sessionMutationHarness(
      session,
      [
        {
          _id: "generation-1",
          sessionId: session._id,
          tokenHash: "older-generation",
          rotatedAt: 898_000,
          expiresAt: 908_000,
        },
      ],
      {
        subject: {
          subject: session.subject,
          // The revocation watermark is inclusive at the Session's creation.
          revokedAt: session.createdAt,
        },
      },
    );

    await expect(
      completeRefreshHandler(
        { db: harness.db },
        {
          sessionId: session._id,
          claimId: "claim-a",
          candidateHash: "candidate",
          idToken: "new-id-token",
          idTokenExp: 3_000_000,
          now: 1_000_000,
          reuseWindowMs: 10_000,
        },
      ),
    ).resolves.toEqual({ outcome: "revoked" });
    expect(harness.session()).toBeNull();
    expect(harness.generations()).toEqual([]);
    expect(harness.patches).toEqual([]);
  });

  it("contains a persisted-sid revocation committed while the refresh action was remote", async () => {
    const session = {
      ...refreshFixture(),
      refreshingSince: 899_000,
      refreshClaimId: "claim-a",
    };
    const harness = sessionMutationHarness(session, [], {
      sids: [{ sid: session.sid!, revokedAt: session.createdAt }],
    });

    await expect(
      completeRefreshHandler(
        { db: harness.db },
        {
          sessionId: session._id,
          claimId: "claim-a",
          candidateHash: "candidate",
          idToken: "new-id-token",
          idTokenExp: 3_000_000,
          sid: "incoming-sid",
          now: 1_000_000,
          reuseWindowMs: 10_000,
        },
      ),
    ).resolves.toEqual({ outcome: "revoked" });
    expect(harness.session()).toBeNull();
    expect(harness.generations()).toEqual([]);
    expect(harness.patches).toEqual([]);
  });

  it("contains an incoming-sid revocation learned from the remote refresh response", async () => {
    const session = {
      ...refreshFixture(),
      refreshingSince: 899_000,
      refreshClaimId: "claim-a",
    };
    const harness = sessionMutationHarness(session, [], {
      sids: [{ sid: "incoming-sid", revokedAt: session.createdAt }],
    });

    await expect(
      completeRefreshHandler(
        { db: harness.db },
        {
          sessionId: session._id,
          claimId: "claim-a",
          candidateHash: "candidate",
          idToken: "new-id-token",
          idTokenExp: 3_000_000,
          sid: "incoming-sid",
          now: 1_000_000,
          reuseWindowMs: 10_000,
        },
      ),
    ).resolves.toEqual({ outcome: "revoked" });
    expect(harness.session()).toBeNull();
    expect(harness.generations()).toEqual([]);
    expect(harness.patches).toEqual([]);
  });

  it("commits when every revocation cutoff is strictly older than the Session", async () => {
    const session = {
      ...refreshFixture(),
      refreshingSince: 899_000,
      refreshClaimId: "claim-a",
    };
    const harness = sessionMutationHarness(session, [], {
      subject: {
        subject: session.subject,
        revokedAt: session.createdAt - 1,
      },
      sids: [
        { sid: session.sid!, revokedAt: session.createdAt - 1 },
        { sid: "incoming-sid", revokedAt: session.createdAt - 1 },
      ],
    });

    await expect(
      completeRefreshHandler(
        { db: harness.db },
        {
          sessionId: session._id,
          claimId: "claim-a",
          candidateHash: "candidate",
          idToken: "new-id-token",
          idTokenExp: 3_000_000,
          sid: "incoming-sid",
          now: 1_000_000,
          reuseWindowMs: 10_000,
        },
      ),
    ).resolves.toEqual({ outcome: "committed" });
    expect(harness.session()).toMatchObject({
      tokenHash: "candidate",
      sid: "incoming-sid",
      refreshClaimId: undefined,
    });
  });

  it("keeps three successful out-of-order token generations recognizable", async () => {
    const harness = sessionMutationHarness({
      ...refreshFixture(),
      refreshingSince: 999_000,
      refreshClaimId: "claim-a",
    });
    await completeRefreshHandler(
      { db: harness.db },
      {
        sessionId: "session-1",
        claimId: "claim-a",
        candidateHash: "candidate-1",
        idToken: "new-id-token",
        idTokenExp: 3_000_000,
        now: 1_000_000,
        reuseWindowMs: 10_000,
      },
    );

    for (const candidateHash of ["candidate-2", "candidate-3"]) {
      await expect(
        beginRefreshHandler(
          { db: harness.db },
          {
            presentedHash: "current",
            candidateHash,
            claimId: `claim-${candidateHash}`,
            now: 1_000_001,
            reuseWindowMs: 10_000,
          },
        ),
      ).resolves.toMatchObject({ outcome: "cached" });
    }

    expect(harness.session()?.tokenHash).toBe("candidate-3");
    expect(
      harness.generations().map((generation) => generation.tokenHash),
    ).toEqual(["current", "candidate-1", "candidate-2"]);
  });

  it("bounds indexed token history while retaining the newest generations", async () => {
    const harness = sessionMutationHarness(refreshFixture());
    let currentHash = "current";
    for (let index = 1; index <= SESSION_TOKEN_GENERATION_LIMIT + 2; index++) {
      const claimId = `claim-${index}`;
      await beginRefreshHandler(
        { db: harness.db },
        {
          presentedHash: currentHash,
          candidateHash: `unused-${index}`,
          claimId,
          now: 1_000_000 + index,
          reuseWindowMs: 10_000,
        },
      );
      const candidateHash = `token-${index}`;
      await completeRefreshHandler(
        { db: harness.db },
        {
          sessionId: "session-1",
          claimId,
          candidateHash,
          idToken: `id-token-${index}`,
          idTokenExp: 3_000_000,
          now: 1_000_000 + index,
          reuseWindowMs: 10_000,
        },
      );
      currentHash = candidateHash;
    }

    expect(harness.generations()).toHaveLength(SESSION_TOKEN_GENERATION_LIMIT);
    expect(
      harness.generations().map((generation) => generation.tokenHash),
    ).toEqual(
      Array.from(
        { length: SESSION_TOKEN_GENERATION_LIMIT },
        (_, index) => `token-${index + 2}`,
      ),
    );
    await expect(
      beginRefreshHandler(
        { db: harness.db },
        {
          presentedHash: "current",
          candidateHash: "candidate-old",
          claimId: "claim-old",
          now: 1_000_020,
          reuseWindowMs: 10_000,
        },
      ),
    ).rejects.toMatchObject({
      data: { kind: "terminal", code: "session_not_found" },
    });
    await expect(
      beginRefreshHandler(
        { db: harness.db },
        {
          presentedHash: "token-2",
          candidateHash: "candidate-recent",
          claimId: "claim-recent",
          now: 1_000_020,
          reuseWindowMs: 10_000,
        },
      ),
    ).resolves.toMatchObject({ outcome: "cached" });
  });

  it("prevents a stale action from releasing or killing another owner's claim", async () => {
    const claimed = {
      ...refreshFixture(),
      refreshingSince: 999_000,
      refreshClaimId: "current-owner",
    };
    const releaseHarness = sessionMutationHarness(claimed);
    await expect(
      releaseClaimHandler(
        { db: releaseHarness.db },
        { sessionId: "session-1", claimId: "stale-owner" },
      ),
    ).resolves.toBe(false);
    expect(releaseHarness.patches).toEqual([]);

    const killHarness = sessionMutationHarness(claimed);
    await expect(
      killSessionHandler(
        { db: killHarness.db },
        { sessionId: "session-1", claimId: "stale-owner" },
      ),
    ).resolves.toBe(false);
    expect(killHarness.deleted).toEqual([]);
  });

  it("allows only the owner to release or terminally kill its claim", async () => {
    const claimed = {
      ...refreshFixture(),
      refreshingSince: 999_000,
      refreshClaimId: "claim-a",
    };
    const releaseHarness = sessionMutationHarness(claimed);
    await expect(
      releaseClaimHandler(
        { db: releaseHarness.db },
        { sessionId: "session-1", claimId: "claim-a" },
      ),
    ).resolves.toBe(true);
    expect(releaseHarness.session()).toMatchObject({
      refreshingSince: undefined,
      refreshClaimId: undefined,
    });

    const killHarness = sessionMutationHarness(claimed);
    await expect(
      killSessionHandler(
        { db: killHarness.db },
        { sessionId: "session-1", claimId: "claim-a" },
      ),
    ).resolves.toBe(true);
    expect(killHarness.deleted).toEqual(["session-1"]);
  });
});

describe("consumeSessionForSignOut", () => {
  it("keeps an unknown token idempotent without deleting another session", async () => {
    const harness = sessionMutationHarness(refreshFixture());

    await expect(
      consumeSessionForSignOutHandler(
        { db: harness.db },
        { tokenHash: "unknown", now: 1_000_000, reuseWindowMs: 10_000 },
      ),
    ).resolves.toEqual({ outcome: "not-found" });
    expect(harness.session()).not.toBeNull();
    expect(harness.deleted).toEqual([]);
  });

  it("signs out with a recent superseded token inside its Reuse window", async () => {
    const harness = sessionMutationHarness({
      ...refreshFixture(),
      rotatedAt: 995_000,
      refreshingSince: 999_000,
      refreshClaimId: "refresh-owner",
    });
    await expect(
      consumeSessionForSignOutHandler(
        { db: harness.db },
        { tokenHash: "previous", now: 1_000_000, reuseWindowMs: 10_000 },
      ),
    ).resolves.toEqual({
      outcome: "taken",
    });
    expect(harness.deleted).toEqual(["session-1"]);
  });

  it("contains an expired known token without exposing its refresh token", async () => {
    const harness = sessionMutationHarness({
      ...refreshFixture(),
      rotatedAt: 990_000,
    });
    await expect(
      consumeSessionForSignOutHandler(
        { db: harness.db },
        { tokenHash: "previous", now: 1_000_000, reuseWindowMs: 10_000 },
      ),
    ).resolves.toEqual({
      outcome: "reuse",
    });
    expect(harness.deleted).toEqual(["session-1"]);
  });

  it("lets current-token sign-out win safely over an in-flight refresh", async () => {
    const harness = sessionMutationHarness(
      {
        ...refreshFixture(),
        refreshingSince: 999_000,
        refreshClaimId: "refresh-owner",
      },
      [
        {
          _id: "generation-1",
          sessionId: "session-1",
          tokenHash: "older-token",
          rotatedAt: 998_000,
          expiresAt: 1_008_000,
        },
      ],
    );
    await expect(
      consumeSessionForSignOutHandler(
        { db: harness.db },
        { tokenHash: "current", now: 1_000_000, reuseWindowMs: 10_000 },
      ),
    ).resolves.toEqual({
      outcome: "taken",
    });
    expect(harness.deleted).toEqual(["generation-1", "session-1"]);
    expect(harness.generations()).toEqual([]);
  });

  it("signs out with any indexed recent generation and removes the whole history", async () => {
    const harness = sessionMutationHarness(refreshFixture(), [
      {
        _id: "generation-1",
        sessionId: "session-1",
        tokenHash: "older-token",
        rotatedAt: 998_000,
        expiresAt: 1_008_000,
      },
      {
        _id: "generation-2",
        sessionId: "session-1",
        tokenHash: "oldest-token",
        rotatedAt: 997_000,
        expiresAt: 1_007_000,
      },
    ]);

    await expect(
      consumeSessionForSignOutHandler(
        { db: harness.db },
        { tokenHash: "oldest-token", now: 1_000_000, reuseWindowMs: 10_000 },
      ),
    ).resolves.toEqual({
      outcome: "taken",
    });
    expect(harness.session()).toBeNull();
    expect(harness.generations()).toEqual([]);
  });
});

describe("bound sign-out", () => {
  it("still discovers a bound key after logical revocation so cleanup cannot bypass proof", async () => {
    const publicKey = {
      kty: "EC" as const,
      crv: "P-256" as const,
      x: "x-coordinate",
      y: "y-coordinate",
    };
    const session = {
      ...refreshFixture(),
      subject: "subject-1",
      createdAt: 1_000,
      devicePublicKey: publicKey,
    };
    const db = {
      query: (table: string) => ({
        withIndex: (
          _index: string,
          configure: (query: {
            eq(field: string, value: string): unknown;
          }) => unknown,
        ) => {
          configure({
            eq() {
              return this;
            },
          });
          return {
            unique: () =>
              Promise.resolve(
                table === "sessions"
                  ? session
                  : table === "subjectRevocations"
                    ? { revokedAt: session.createdAt }
                    : null,
              ),
            order: () => ({
              first: () =>
                Promise.resolve(
                  table === "subjectRevocations"
                    ? { revokedAt: session.createdAt }
                    : null,
                ),
            }),
          };
        },
      }),
    };

    await expect(
      devicePublicKeyForTokenHandler(
        { db },
        { presentedHash: session.tokenHash },
      ),
    ).resolves.toEqual(publicKey);
  });

  it("rejects a missing proof before any session mutation", async () => {
    let mutations = 0;
    const ctx = {
      runQuery: () =>
        Promise.resolve({
          kty: "EC" as const,
          crv: "P-256" as const,
          x: "unused",
          y: "unused",
        }),
      runMutation: () => {
        mutations += 1;
        return Promise.resolve({ outcome: "not-found" as const });
      },
    };

    await expect(
      signOutHandler(ctx, {
        endpoint: "https://auth.example.com",
        appId: "app-1",
        clientSecret: "secret",
        sessionToken: "copied-token",
      }),
    ).rejects.toMatchObject({
      data: { kind: "terminal", code: "device_proof_required" },
    });
    expect(mutations).toBe(0);
  });

  it("rejects an invalid proof before any session mutation", async () => {
    const { publicKey } = await deviceProofFixture("copied-token");
    let mutations = 0;
    const ctx = {
      runQuery: () => Promise.resolve(publicKey),
      runMutation: () => {
        mutations += 1;
        return Promise.resolve({ outcome: "not-found" as const });
      },
    };

    await expect(
      signOutHandler(ctx, {
        endpoint: "https://auth.example.com",
        appId: "app-1",
        clientSecret: "secret",
        sessionToken: "copied-token",
        deviceProof: "invalid",
      }),
    ).rejects.toMatchObject({
      data: { kind: "terminal", code: "device_proof_invalid" },
    });
    expect(mutations).toBe(0);
  });

  it("accepts a valid proof before deleting the bound session", async () => {
    const sessionToken = "bound-token";
    const { publicKey, proof } = await deviceProofFixture(sessionToken);
    const runMutation = vi
      .fn()
      .mockResolvedValue({ outcome: "not-found" as const });

    await expect(
      signOutHandler(
        { runQuery: () => Promise.resolve(publicKey), runMutation },
        {
          endpoint: "https://auth.example.com",
          appId: "app-1",
          clientSecret: "secret",
          sessionToken,
          deviceProof: proof,
          federated: false,
        },
      ),
    ).resolves.toEqual({});
    expect(runMutation).toHaveBeenCalledTimes(1);
  });
});

describe("grant-safe local containment", () => {
  it("deletes only the selected component session without revoking a sibling's shared grant", async () => {
    const siblingSessions = new Set(["caller-session", "sibling-session"]);
    const runMutation = vi.fn().mockImplementation(() => {
      siblingSessions.delete("caller-session");
      return Promise.resolve({ outcome: "taken" as const });
    });
    const fetchSpy = vi
      .spyOn(globalThis, "fetch")
      .mockResolvedValue(new Response(null, { status: 200 }));
    try {
      await signOutHandler(
        { runQuery: () => Promise.resolve(null), runMutation },
        {
          endpoint: "https://auth.example.com",
          appId: "app-1",
          clientSecret: "secret",
          sessionToken: "caller-token",
          federated: false,
        },
      );

      expect(siblingSessions).toEqual(new Set(["sibling-session"]));
      expect(fetchSpy).not.toHaveBeenCalled();
    } finally {
      fetchSpy.mockRestore();
    }
  });

  it("reports late sign-out reuse terminally without revoking a sibling's shared grant", async () => {
    const fetchSpy = vi
      .spyOn(globalThis, "fetch")
      .mockResolvedValue(new Response(null, { status: 200 }));
    try {
      await expect(
        signOutHandler(
          {
            runQuery: () => Promise.resolve(null),
            runMutation: () => Promise.resolve({ outcome: "reuse" as const }),
          },
          {
            endpoint: "https://auth.example.com",
            appId: "app-1",
            clientSecret: "secret",
            sessionToken: "expired-known-token",
            federated: false,
          },
        ),
      ).rejects.toMatchObject({
        data: { kind: "terminal", code: "session_reuse_detected" },
      });
      expect(fetchSpy).not.toHaveBeenCalled();
    } finally {
      fetchSpy.mockRestore();
    }
  });

  it.each(["reuse", "claim-expired"] as const)(
    "abandons local state for %s without revoking associated remote grant state",
    async (outcome) => {
      const fetchSpy = vi
        .spyOn(globalThis, "fetch")
        .mockResolvedValue(new Response(null, { status: 200 }));
      try {
        await expect(
          refreshActionHandler(
            {
              runQuery: () => Promise.resolve(null),
              runMutation: () =>
                Promise.resolve({
                  outcome,
                }),
            },
            {
              endpoint: "https://auth.example.com",
              appId: "app-1",
              clientSecret: "secret",
              sessionToken: "stale-token",
            },
          ),
        ).rejects.toMatchObject({ data: { kind: "terminal" } });
        expect(fetchSpy).not.toHaveBeenCalled();
      } finally {
        fetchSpy.mockRestore();
      }
    },
  );

  it.each([
    ["missing", "refresh_claim_lost"],
    ["stale-owner", "refresh_claim_lost"],
    ["revoked", "session_revoked"],
  ] as const)(
    "never returns credentials after completion reports %s",
    async (outcome, errorCode) => {
      const fetchSpy = vi.spyOn(globalThis, "fetch").mockResolvedValue(
        new Response(JSON.stringify({ id_token: idToken() }), {
          status: 200,
          headers: { "Content-Type": "application/json" },
        }),
      );
      const runMutation = vi
        .fn()
        .mockResolvedValueOnce({
          outcome: "refresh" as const,
          sessionId: "caller-session",
          refreshToken: "shared-grant-refresh-token",
        })
        .mockResolvedValueOnce({ outcome });
      try {
        await expect(
          refreshActionHandler(
            { runQuery: () => Promise.resolve(null), runMutation },
            {
              endpoint: "https://auth.example.com",
              appId: "app-1",
              clientSecret: "secret",
              sessionToken: "caller-token",
            },
          ),
        ).rejects.toMatchObject({
          data: { kind: "terminal", code: errorCode },
        });
        // Only the necessary token exchange ran; no RFC 7009 request followed.
        expect(fetchSpy).toHaveBeenCalledTimes(1);
        expect(fetchSpy.mock.calls[0]?.[0]).toBe(
          "https://auth.example.com/oidc/token",
        );
      } finally {
        fetchSpy.mockRestore();
      }
    },
  );
});

describe("bound sign-out everywhere", () => {
  it.each([
    [undefined, "device_proof_required"],
    ["invalid", "device_proof_invalid"],
  ] as const)(
    "rejects proof %s before creating a revocation marker",
    async (deviceProof, code) => {
      const { publicKey } = await deviceProofFixture("copied-token");
      const runMutation = vi.fn();

      await expect(
        killSubjectSessionsByTokenHandler(
          { runQuery: () => Promise.resolve(publicKey), runMutation },
          {
            sessionToken: "copied-token",
            deviceProof,
            now: 1_000_000,
            reuseWindowMs: 10_000,
          },
        ),
      ).rejects.toMatchObject({ data: { kind: "terminal", code } });
      expect(runMutation).not.toHaveBeenCalled();
    },
  );

  it("accepts a valid proof before marking and deleting the subject's sessions", async () => {
    const sessionToken = "bound-token";
    const { publicKey, proof } = await deviceProofFixture(sessionToken);
    const runMutation = vi
      .fn()
      .mockResolvedValueOnce({
        outcome: "signed-out" as const,
        subject: "subject-1",
        callerSessionId: "session-1",
        revokedAt: 1_000_000,
      })
      .mockResolvedValueOnce({ deleted: 2, done: true });

    await expect(
      killSubjectSessionsByTokenHandler(
        { runQuery: () => Promise.resolve(publicKey), runMutation },
        {
          sessionToken,
          deviceProof: proof,
          now: 1_000_000,
          reuseWindowMs: 10_000,
        },
      ),
    ).resolves.toEqual({
      outcome: "signed-out",
      count: 2,
      subject: "subject-1",
    });
    expect(runMutation).toHaveBeenCalledTimes(2);
  });
});

describe("gc token generations", () => {
  it("removes generations with dead sessions and expired legacy orphans", async () => {
    const harness = sessionMutationHarness(
      { ...refreshFixture(), lastRefreshedAt: 0 },
      [
        {
          _id: "owned-generation",
          sessionId: "session-1",
          tokenHash: "owned-token",
          rotatedAt: 0,
          expiresAt: 0,
        },
        {
          _id: "orphan-generation",
          sessionId: "missing-session",
          tokenHash: "orphan-token",
          rotatedAt: 0,
          expiresAt: 0,
        },
      ],
    );

    await expect(gcHandler({ db: harness.db }, {})).resolves.toBeNull();
    expect(harness.session()).toBeNull();
    expect(harness.generations()).toEqual([]);
    expect(harness.deleted).toEqual([
      "owned-generation",
      "session-1",
      "orphan-generation",
    ]);
  });
});

// --- session management ------------------------------------------------------

type ListSession = {
  _id: string;
  subject: string;
  sid?: string;
  createdAt: number;
  lastRefreshedAt: number;
  label?: string;
  client?: { platform?: string; os?: string; browser?: string };
  devicePublicKey?: { kty: "EC"; crv: "P-256"; x: string; y: string };
  // The large fields the scan's byte budget is measured against; every real row
  // carries them, so the fixtures do too.
  logtoRefreshToken: string;
  lastIdToken: string;
};

const listRow = (
  row: Omit<ListSession, "logtoRefreshToken" | "lastIdToken"> &
    Partial<Pick<ListSession, "logtoRefreshToken" | "lastIdToken">>,
): ListSession => ({
  logtoRefreshToken: "refresh-token",
  lastIdToken: "id-token",
  ...row,
});

/**
 * Index-aware fake for the session-management handlers: `by_subject_createdAt`
 * needs `gt` plus descending order, and the revocation markers must be
 * queryable so a logically-revoked row can be proven invisible.
 */
function sessionListHarness(
  initial: ListSession[],
  markers: {
    subjects?: Array<{ subject: string; revokedAt: number }>;
    sids?: Array<{ sid: string; revokedAt: number }>;
  } = {},
) {
  let sessions = [...initial];
  const scannedRows: Array<Record<string, unknown>> = [];
  const generations = [
    { _id: "generation-1", sessionId: "session-b", rotatedAt: 1 },
  ];
  const deleted: string[] = [];
  const patches: Array<{ id: string; patch: Record<string, unknown> }> = [];
  const rowsFor = (table: string): Array<Record<string, unknown>> => {
    if (table === "sessions") return sessions as never;
    if (table === "sessionTokenGenerations") return generations as never;
    if (table === "subjectRevocations")
      return (markers.subjects ?? []) as never;
    if (table === "sidRevocations") return (markers.sids ?? []) as never;
    return [];
  };
  const db = {
    query: (table: string) => ({
      withIndex: (
        _index: string,
        configure: (query: {
          eq(field: string, value: unknown): unknown;
          gt(field: string, value: unknown): unknown;
        }) => unknown,
      ) => {
        const constraints: Array<{
          op: "eq" | "gt";
          field: string;
          value: unknown;
        }> = [];
        const builder = {
          eq(field: string, value: unknown) {
            constraints.push({ op: "eq", field, value });
            return this;
          },
          gt(field: string, value: unknown) {
            constraints.push({ op: "gt", field, value });
            return this;
          },
        };
        configure(builder);
        let direction: "asc" | "desc" = "asc";
        const matching = () => {
          const filtered = rowsFor(table).filter((row) =>
            constraints.every(({ op, field, value }) =>
              op === "eq"
                ? row[field] === value
                : typeof row[field] === "number" &&
                  typeof value === "number" &&
                  (row[field] as number) > value,
            ),
          );
          return filtered.toSorted((left, right) => {
            const difference =
              ((left.createdAt as number) ?? 0) -
              ((right.createdAt as number) ?? 0);
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
          // Convex query streams are async-iterable, and `listSubjectSessions`
          // relies on that to stop reading as soon as its page is full.
          async *[Symbol.asyncIterator]() {
            for (const row of matching()) {
              scannedRows.push(row);
              yield row;
            }
          },
        };
        return result;
      },
    }),
    normalizeId: (_table: string, id: string) =>
      // Only ids this deployment could have minted normalize — a foreign id is
      // rejected before any read, exactly as Convex does.
      id.startsWith("session-") ? id : null,
    get: (id: string) =>
      Promise.resolve(sessions.find((session) => session._id === id) ?? null),
    patch: (id: string, patch: Record<string, unknown>) => {
      patches.push({ id, patch });
      sessions = sessions.map((session) =>
        session._id === id
          ? ({ ...session, ...patch } as ListSession)
          : session,
      );
      return Promise.resolve();
    },
    delete: (id: string) => {
      deleted.push(id);
      sessions = sessions.filter((session) => session._id !== id);
      return Promise.resolve();
    },
  };
  return {
    db,
    deleted,
    patches,
    sessions: () => sessions,
    scanned: () => scannedRows.length,
  };
}

const listSubjectSessionsHandler = internalHandler(
  listSubjectSessions,
  (_args: { subject: string; callerSessionId: string }) =>
    ({}) as { sessions: unknown[]; truncated: boolean },
);
const setSessionLabelHandler = internalHandler(
  setSessionLabel,
  (_args: { subject: string; targetSessionId: string; label?: string }) =>
    true as boolean,
);
const deleteOwnedSessionHandler = internalHandler(
  deleteOwnedSession,
  (_args: { subject: string; targetSessionId: string }) => true as boolean,
);
const resolveCallerSessionHandler = internalHandler(
  resolveCallerSession,
  (_args: { presentedHash: string; now: number; reuseWindowMs: number }) =>
    ({}) as { sessionId: string; subject: string },
);

const listFixture = (): ListSession[] => [
  listRow({
    _id: "session-a",
    subject: "subject-1",
    createdAt: 1_000,
    lastRefreshedAt: 1_500,
    label: "Laptop",
    client: { browser: "Firefox" },
  }),
  listRow({
    _id: "session-b",
    subject: "subject-1",
    sid: "sid-b",
    createdAt: 2_000,
    lastRefreshedAt: 2_500,
    devicePublicKey: { kty: "EC", crv: "P-256", x: "x", y: "y" },
  }),
  listRow({
    _id: "session-other",
    subject: "subject-2",
    createdAt: 3_000,
    lastRefreshedAt: 3_000,
  }),
];

describe("listSubjectSessions", () => {
  it("returns only the caller's sessions, newest first, flagging the current one", async () => {
    const harness = sessionListHarness(listFixture());

    const result = await listSubjectSessionsHandler(
      { db: harness.db },
      { subject: "subject-1", callerSessionId: "session-b" },
    );

    expect(result).toEqual({
      truncated: false,
      sessions: [
        {
          sessionId: "session-b",
          current: true,
          createdAt: 2_000,
          lastRefreshedAt: 2_500,
          deviceBound: true,
        },
        {
          sessionId: "session-a",
          current: false,
          createdAt: 1_000,
          lastRefreshedAt: 1_500,
          label: "Laptop",
          client: { browser: "Firefox" },
          deviceBound: false,
        },
      ],
    });
  });

  it("hides sessions a revocation watermark already killed", async () => {
    const harness = sessionListHarness(listFixture(), {
      subjects: [{ subject: "subject-1", revokedAt: 1_000 }],
      sids: [{ sid: "sid-b", revokedAt: 2_000 }],
    });

    const result = await listSubjectSessionsHandler(
      { db: harness.db },
      { subject: "subject-1", callerSessionId: "session-b" },
    );

    expect(result).toEqual({ sessions: [], truncated: false });
  });

  it("keeps live sessions visible behind a page-full of revoked rows", async () => {
    // The sid watermark kills the newest SESSION_LIST_LIMIT rows while their
    // physical rows wait for a cleanup batch. A fixed page read would spend
    // every slot on them and hide the one device the user can still act on.
    const harness = sessionListHarness(
      [
        ...Array.from({ length: SESSION_LIST_LIMIT }, (_unused, index) =>
          listRow({
            _id: `session-dead-${index}`,
            subject: "subject-1",
            sid: "sid-dead",
            createdAt: 1_000 + index,
            lastRefreshedAt: 1_000 + index,
          }),
        ),
        listRow({
          _id: "session-live",
          subject: "subject-1",
          createdAt: 500,
          lastRefreshedAt: 500,
        }),
      ],
      { sids: [{ sid: "sid-dead", revokedAt: 2_000 }] },
    );

    const result = await listSubjectSessionsHandler(
      { db: harness.db },
      { subject: "subject-1", callerSessionId: "session-live" },
    );

    expect(result.sessions.map((session) => session.sessionId)).toEqual([
      "session-live",
    ]);
    expect(result.truncated).toBe(false);
  });

  it("stops at the scan limit and says so rather than reading unboundedly", async () => {
    const harness = sessionListHarness(
      Array.from({ length: SESSION_LIST_SCAN_LIMIT + 10 }, (_unused, index) =>
        listRow({
          _id: `session-dead-${index}`,
          subject: "subject-1",
          sid: "sid-dead",
          createdAt: index,
          lastRefreshedAt: index,
        }),
      ),
      { sids: [{ sid: "sid-dead", revokedAt: Number.MAX_SAFE_INTEGER }] },
    );

    const result = await listSubjectSessionsHandler(
      { db: harness.db },
      { subject: "subject-1", callerSessionId: "session-dead-0" },
    );

    expect(result).toEqual({ sessions: [], truncated: true });
    // The cap plus the one row whose existence proves more remain.
    expect(harness.scanned()).toBe(SESSION_LIST_SCAN_LIMIT + 1);
  });

  it("stops on the byte budget before a page of huge rows blows the read limit", async () => {
    // A session row can approach Convex's 1 MiB document limit, so a row count
    // alone does not bound the read.
    const fatIdToken = "x".repeat(SESSION_LIST_SCAN_BYTES / 4);
    const harness = sessionListHarness(
      Array.from({ length: SESSION_LIST_LIMIT }, (_unused, index) =>
        listRow({
          _id: `session-${index}`,
          subject: "subject-1",
          sid: "sid-dead",
          createdAt: index,
          lastRefreshedAt: index,
          lastIdToken: fatIdToken,
        }),
      ),
      { sids: [{ sid: "sid-dead", revokedAt: Number.MAX_SAFE_INTEGER }] },
    );

    const result = await listSubjectSessionsHandler(
      { db: harness.db },
      { subject: "subject-1", callerSessionId: "session-0" },
    );

    expect(result.truncated).toBe(true);
    // Four rows fill the budget; the fifth is the one already in hand when the
    // check fires, and nothing past it is read.
    expect(harness.scanned()).toBe(5);
  });

  it("reads no further than the page it fills", async () => {
    const harness = sessionListHarness(
      Array.from({ length: SESSION_LIST_LIMIT + 20 }, (_unused, index) =>
        listRow({
          _id: `session-${index}`,
          subject: "subject-1",
          createdAt: index,
          lastRefreshedAt: index,
        }),
      ),
    );

    const result = await listSubjectSessionsHandler(
      { db: harness.db },
      { subject: "subject-1", callerSessionId: "session-0" },
    );

    expect(result.sessions).toHaveLength(SESSION_LIST_LIMIT);
    expect(result.truncated).toBe(true);
    // One row past the page proves truncation; nothing beyond it is read.
    expect(harness.scanned()).toBe(SESSION_LIST_LIMIT + 1);
  });

  it("reports truncation past the page limit", async () => {
    const harness = sessionListHarness(
      Array.from({ length: SESSION_LIST_LIMIT + 1 }, (_unused, index) =>
        listRow({
          _id: `session-${index}`,
          subject: "subject-1",
          createdAt: index,
          lastRefreshedAt: index,
        }),
      ),
    );

    const result = await listSubjectSessionsHandler(
      { db: harness.db },
      { subject: "subject-1", callerSessionId: "session-0" },
    );

    expect(result.sessions).toHaveLength(SESSION_LIST_LIMIT);
    expect(result.truncated).toBe(true);
  });
});

describe("owned-session mutations", () => {
  it("labels and clears a label on the caller's own session", async () => {
    const harness = sessionListHarness(listFixture());

    await expect(
      setSessionLabelHandler(
        { db: harness.db },
        { subject: "subject-1", targetSessionId: "session-b", label: "Phone" },
      ),
    ).resolves.toBe(true);
    expect(harness.patches).toEqual([
      { id: "session-b", patch: { label: "Phone" } },
    ]);

    await setSessionLabelHandler(
      { db: harness.db },
      { subject: "subject-1", targetSessionId: "session-b" },
    );
    expect(harness.patches[1]).toEqual({
      id: "session-b",
      patch: { label: undefined },
    });
  });

  it("revokes the caller's own session together with its generations", async () => {
    const harness = sessionListHarness(listFixture());

    await expect(
      deleteOwnedSessionHandler(
        { db: harness.db },
        { subject: "subject-1", targetSessionId: "session-b" },
      ),
    ).resolves.toBe(true);
    expect(harness.deleted).toEqual(["generation-1", "session-b"]);
  });

  it.each([
    ["another subject's session", "session-other"],
    ["an id this deployment never minted", "foreign-id"],
  ])("refuses to touch %s", async (_name, targetSessionId) => {
    const harness = sessionListHarness(listFixture());

    for (const handler of [setSessionLabelHandler, deleteOwnedSessionHandler]) {
      await expect(
        handler({ db: harness.db }, { subject: "subject-1", targetSessionId }),
      ).rejects.toThrow(/no longer exists/);
    }
    expect(harness.deleted).toEqual([]);
    expect(harness.patches).toEqual([]);
  });

  it("refuses a session a watermark already killed", async () => {
    const harness = sessionListHarness(listFixture(), {
      sids: [{ sid: "sid-b", revokedAt: 2_000 }],
    });

    await expect(
      deleteOwnedSessionHandler(
        { db: harness.db },
        { subject: "subject-1", targetSessionId: "session-b" },
      ),
    ).rejects.toThrow(/no longer exists/);
  });
});

describe("resolveCallerSession", () => {
  it("resolves a live token to its owner", async () => {
    const harness = sessionMutationHarness({
      ...refreshFixture(),
      tokenHash: "current",
    });

    await expect(
      resolveCallerSessionHandler(
        { db: harness.db },
        { presentedHash: "current", now: 1_000_000, reuseWindowMs: 30_000 },
      ),
    ).resolves.toEqual({ sessionId: "session-1", subject: "subject-1" });
  });

  it("rejects a superseded token once the reuse window closes", async () => {
    const harness = sessionMutationHarness({
      ...refreshFixture(),
      rotatedAt: 900_000,
    });

    await expect(
      resolveCallerSessionHandler(
        { db: harness.db },
        { presentedHash: "previous", now: 1_000_000, reuseWindowMs: 30_000 },
      ),
    ).rejects.toThrow(/No active session/);
  });

  it("rejects an unknown token", async () => {
    const harness = sessionMutationHarness(refreshFixture());

    await expect(
      resolveCallerSessionHandler(
        { db: harness.db },
        { presentedHash: "stolen", now: 1_000_000, reuseWindowMs: 30_000 },
      ),
    ).rejects.toThrow(/No active session/);
  });
});
