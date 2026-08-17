import { describe, expect, it } from "vitest";
import {
  REVOCATION_BATCH_SIZE,
  beginRefresh,
  beginSidRevocation,
  createSession,
  deleteSidSessionsBatch,
  deleteSubjectSessionsBatch,
  gc,
  hasActiveSessionForSubject,
  killSessionsBySid,
  killSubjectSessions,
  sessionValid,
} from "./lib";

function handlerOf<Args, Result>(
  value: unknown,
  _types?: (args: Args) => Result,
): (ctx: unknown, args: Args) => Promise<Result> {
  return (
    value as Record<string, (ctx: unknown, args: Args) => Promise<Result>>
  )["_handler"]!;
}

type LivenessSession = {
  subject: string;
  sid?: string;
  createdAt: number;
};

function subjectLivenessHarness(
  sessions: LivenessSession[],
  sidRevocations: ReadonlyMap<string, number>,
) {
  let takeLimit: number | undefined;
  const sidQueryCounts = new Map<string, number>();
  const db = {
    query: (table: string) => ({
      withIndex: (
        _index: string,
        configure: (query: {
          eq(field: string, value: string): unknown;
          gt(field: string, value: number): unknown;
        }) => unknown,
      ) => {
        let equalityValue: string | undefined;
        const query = {
          eq(_field: string, value: string) {
            equalityValue = value;
            return query;
          },
          gt() {
            return query;
          },
        };
        configure(query);
        if (table === "subjectRevocations") {
          return { unique: () => Promise.resolve({ revokedAt: 1_000 }) };
        }
        if (table === "sidRevocations") {
          const sid = equalityValue!;
          sidQueryCounts.set(sid, (sidQueryCounts.get(sid) ?? 0) + 1);
          const revokedAt = sidRevocations.get(sid);
          return {
            unique: () =>
              Promise.resolve(revokedAt === undefined ? null : { revokedAt }),
          };
        }
        return {
          order: () => ({
            take: (limit: number) => {
              takeLimit = limit;
              return Promise.resolve(sessions.slice(0, limit));
            },
          }),
        };
      },
    }),
  };
  return {
    db,
    get takeLimit() {
      return takeLimit;
    },
    sidQueryCount(sid: string) {
      return sidQueryCounts.get(sid) ?? 0;
    },
  };
}

describe("bounded session revocation", () => {
  it("returns an exact count after draining multiple sid batches", async () => {
    const results: unknown[] = [
      1_000_000,
      { deleted: 8, done: false },
      { deleted: 3, done: false },
      { deleted: 0, done: true },
    ];
    const calls: unknown[] = [];
    const runMutation = (reference: unknown, args: unknown) => {
      calls.push({ reference, args });
      return Promise.resolve(results.shift());
    };
    const handler = handlerOf<{ sid: string }, number>(killSessionsBySid);

    await expect(
      handler({ runMutation }, { sid: "logto-session" }),
    ).resolves.toBe(11);
    expect(calls).toHaveLength(4);
  });

  it("returns an exact count after draining multiple subject batches", async () => {
    const results: unknown[] = [
      1_000_000,
      { deleted: 8, done: false },
      { deleted: 2, done: true },
    ];
    const calls: unknown[] = [];
    const runMutation = (reference: unknown, args: unknown) => {
      calls.push({ reference, args });
      return Promise.resolve(results.shift());
    };
    const handler = handlerOf<{ subject: string }, number>(killSubjectSessions);

    await expect(
      handler({ runMutation }, { subject: "logto-subject" }),
    ).resolves.toBe(10);
    expect(calls).toHaveLength(3);
  });

  it("stops with a retryable error instead of looping without a work bound", async () => {
    let calls = 0;
    const runMutation = () => {
      calls += 1;
      return Promise.resolve(
        calls === 1 ? 1_000_000 : { deleted: 8, done: false },
      );
    };
    const handler = handlerOf<{ sid: string }, number>(killSessionsBySid);

    await expect(
      handler({ runMutation }, { sid: "pathological-session" }),
    ).rejects.toMatchObject({
      data: {
        kind: "transient",
        code: "revocation_cleanup_incomplete",
      },
    });
    expect(calls).toBe(513);
  });

  it.each([
    {
      scope: "sid",
      mutation: deleteSidSessionsBatch,
      args: { sid: "logto-session", revokedAt: 1_000_000 },
    },
    {
      scope: "subject",
      mutation: deleteSubjectSessionsBatch,
      args: { subject: "logto-subject", revokedAt: 1_000_000 },
    },
  ])(
    "never reads or deletes more than one fixed $scope batch",
    async (test) => {
      const sessions = Array.from(
        { length: REVOCATION_BATCH_SIZE + 1 },
        (_, index) => ({
          _id: `session-${index}`,
          sid: "logto-session",
          createdAt: index,
        }),
      );
      const deleted: string[] = [];
      let takeLimit: number | undefined;
      const db = {
        query: (table: string) => ({
          withIndex: () => {
            if (table === "sessions") {
              return {
                take: (limit: number) => {
                  takeLimit = limit;
                  return Promise.resolve(sessions.slice(0, limit));
                },
              };
            }
            if (table === "sessionTokenGenerations") {
              return { collect: () => Promise.resolve([]) };
            }
            return {
              unique: () =>
                Promise.resolve({ _id: "marker", revokedAt: 1_000_000 }),
            };
          },
        }),
        delete: (id: string) => {
          deleted.push(id);
          return Promise.resolve();
        },
      };
      const handler = handlerOf<
        Record<string, string | number>,
        { deleted: number; done: boolean }
      >(test.mutation);

      await expect(handler({ db }, test.args)).resolves.toEqual({
        deleted: REVOCATION_BATCH_SIZE,
        done: false,
      });
      expect(takeLimit).toBe(REVOCATION_BATCH_SIZE + 1);
      expect(deleted).toHaveLength(REVOCATION_BATCH_SIZE);
    },
  );

  it("keeps GC large-document reads inside one transaction budget", async () => {
    const sessions = Array.from(
      { length: REVOCATION_BATCH_SIZE + 1 },
      (_, index) => ({ _id: `session-${index}` }),
    );
    const deleted: string[] = [];
    const scheduled: Array<{ delay: number; args: unknown }> = [];
    let transactionTakeLimit: number | undefined;
    let sessionTakeLimit: number | undefined;
    const db = {
      query: (table: string) => ({
        withIndex: (index: string) => {
          if (table === "transactions") {
            return {
              take: (limit: number) => {
                transactionTakeLimit = limit;
                return Promise.resolve([]);
              },
            };
          }
          if (table === "sessions") {
            return {
              take: (limit: number) => {
                sessionTakeLimit = limit;
                return Promise.resolve(sessions.slice(0, limit));
              },
            };
          }
          if (
            table === "sessionTokenGenerations" &&
            index === "by_sessionId_rotatedAt"
          ) {
            return { collect: () => Promise.resolve([]) };
          }
          return { take: () => Promise.resolve([]) };
        },
      }),
      delete: (id: string) => {
        deleted.push(id);
        return Promise.resolve();
      },
    };
    const handler = handlerOf<Record<string, never>, null>(gc);

    const scheduler = {
      runAfter: (delay: number, _reference: unknown, args: unknown) => {
        scheduled.push({ delay, args });
        return Promise.resolve("scheduled-gc");
      },
    };

    await expect(handler({ db, scheduler }, {})).resolves.toBeNull();
    expect(transactionTakeLimit).toBe(4);
    expect(sessionTakeLimit).toBe(REVOCATION_BATCH_SIZE);
    expect(deleted).toHaveLength(REVOCATION_BATCH_SIZE);
    expect(scheduled).toEqual([{ delay: 0, args: {} }]);
  });

  it("includes a session committed after the action sampled its clock", async () => {
    let inserted: Record<string, unknown> | undefined;
    const db = {
      query: (table: string) => ({
        withIndex: () => {
          if (table === "sidRevocations") {
            return { unique: () => Promise.resolve(null) };
          }
          return {
            order: () => ({
              first: () => Promise.resolve({ createdAt: 1_001 }),
            }),
          };
        },
      }),
      insert: (_table: string, value: Record<string, unknown>) => {
        inserted = value;
        return Promise.resolve("marker");
      },
      patch: () => Promise.resolve(),
    };
    const handler = handlerOf<{ sid: string; now: number }, number>(
      beginSidRevocation,
    );

    await expect(
      handler({ db }, { sid: "logto-session", now: 1_000 }),
    ).resolves.toBe(1_001);
    expect(inserted).toEqual({ sid: "logto-session", revokedAt: 1_001 });
  });

  it("makes marker-old sessions invalid before physical cleanup", async () => {
    const handler = handlerOf<{ sessionId: string }, boolean>(sessionValid);
    const session = {
      _id: "session-1",
      subject: "subject-1",
      sid: "sid-1",
      createdAt: 1_000,
    };
    const db = {
      normalizeId: () => "session-1",
      get: () => Promise.resolve(session),
      query: (table: string) => ({
        withIndex: () => ({
          unique: () =>
            Promise.resolve(
              table === "subjectRevocations"
                ? { revokedAt: 1_000 }
                : { revokedAt: 900 },
            ),
        }),
      }),
    };

    await expect(handler({ db }, { sessionId: "session-1" })).resolves.toBe(
      false,
    );
  });

  it("rejects refresh while a matching revocation marker is active", async () => {
    const session = {
      _id: "session-1",
      subject: "subject-1",
      tokenHash: "current-hash",
      createdAt: 1_000,
    };
    const db = {
      query: (table: string) => ({
        withIndex: () => ({
          unique: () => {
            if (table === "sessions") return Promise.resolve(session);
            if (table === "subjectRevocations") {
              return Promise.resolve({ revokedAt: 1_000 });
            }
            return Promise.resolve(null);
          },
        }),
      }),
    };
    const handler = handlerOf<
      {
        presentedHash: string;
        candidateHash: string;
        claimId: string;
        now: number;
        reuseWindowMs: number;
      },
      unknown
    >(beginRefresh);

    await expect(
      handler(
        { db },
        {
          presentedHash: "current-hash",
          candidateHash: "candidate-hash",
          claimId: "claim-1",
          now: 1_100,
          reuseWindowMs: 10_000,
        },
      ),
    ).rejects.toMatchObject({
      data: { kind: "terminal", code: "session_revoked" },
    });
  });

  it("finds an active session at the end of the bounded liveness window", async () => {
    const sessions = [
      ...Array.from({ length: REVOCATION_BATCH_SIZE - 1 }, (_, index) => ({
        subject: "subject-1",
        sid: "revoked-sid",
        createdAt: 2_008 - index,
      })),
      { subject: "subject-1", sid: "active-sid", createdAt: 2_001 },
    ];
    const harness = subjectLivenessHarness(
      sessions,
      new Map([["revoked-sid", 3_000]]),
    );
    const handler = handlerOf<{ subject: string }, boolean>(
      hasActiveSessionForSubject,
    );

    await expect(
      handler({ db: harness.db }, { subject: "subject-1" }),
    ).resolves.toBe(true);
    expect(harness.takeLimit).toBe(REVOCATION_BATCH_SIZE + 1);
    expect(harness.sidQueryCount("revoked-sid")).toBe(1);
  });

  it("returns false after checking exactly one full revoked window", async () => {
    const sessions = Array.from(
      { length: REVOCATION_BATCH_SIZE },
      (_, index) => ({
        subject: "subject-1",
        sid: "revoked-sid",
        createdAt: 2_008 - index,
      }),
    );
    const harness = subjectLivenessHarness(
      sessions,
      new Map([["revoked-sid", 3_000]]),
    );
    const handler = handlerOf<{ subject: string }, boolean>(
      hasActiveSessionForSubject,
    );

    await expect(
      handler({ db: harness.db }, { subject: "subject-1" }),
    ).resolves.toBe(false);
    expect(harness.sidQueryCount("revoked-sid")).toBe(1);
  });

  it("reports an incomplete liveness scan instead of a false negative", async () => {
    const sessions = [
      ...Array.from({ length: REVOCATION_BATCH_SIZE }, (_, index) => ({
        subject: "subject-1",
        sid: "revoked-sid",
        createdAt: 2_009 - index,
      })),
      { subject: "subject-1", sid: "active-sid", createdAt: 2_001 },
    ];
    const harness = subjectLivenessHarness(
      sessions,
      new Map([["revoked-sid", 3_000]]),
    );
    const handler = handlerOf<{ subject: string }, boolean>(
      hasActiveSessionForSubject,
    );

    await expect(
      handler({ db: harness.db }, { subject: "subject-1" }),
    ).rejects.toMatchObject({
      data: {
        kind: "transient",
        code: "session_liveness_scan_incomplete",
      },
    });
    expect(harness.takeLimit).toBe(REVOCATION_BATCH_SIZE + 1);
    expect(harness.sidQueryCount("revoked-sid")).toBe(1);
    expect(harness.sidQueryCount("active-sid")).toBe(0);
  });

  it("lets a new login land strictly after active revocation markers", async () => {
    let inserted: Record<string, unknown> | undefined;
    const db = {
      query: (table: string) => ({
        withIndex: () => ({
          unique: () =>
            Promise.resolve({
              revokedAt: table === "subjectRevocations" ? 1_000 : 1_100,
            }),
        }),
      }),
      insert: (_table: string, value: Record<string, unknown>) => {
        inserted = value;
        return Promise.resolve("new-session");
      },
    };
    const handler = handlerOf<
      {
        subject: string;
        sid?: string;
        tokenHash: string;
        logtoRefreshToken: string;
        lastIdToken: string;
        lastIdTokenExp: number;
        now: number;
      },
      string
    >(createSession);

    await handler(
      { db },
      {
        subject: "subject-1",
        sid: "sid-1",
        tokenHash: "hash",
        logtoRefreshToken: "refresh",
        lastIdToken: "id-token",
        lastIdTokenExp: 2_000,
        now: 950,
      },
    );

    expect(inserted).toMatchObject({
      createdAt: 1_101,
      lastRefreshedAt: 1_101,
    });
  });
});
