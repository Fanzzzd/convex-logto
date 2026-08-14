import { describe, expect, it, vi } from "vitest";
import { killSessionsBySid, killSubjectSessionsByToken } from "./lib";

type Session = { _id: string; sid?: string };

describe("killSessionsBySid", () => {
  it("uses the sid index and deletes only matching sessions", async () => {
    const sessions: Session[] = [
      { _id: "session-1", sid: "sid-a" },
      { _id: "session-2", sid: "sid-a" },
      { _id: "session-3", sid: "sid-b" },
      { _id: "legacy-session" },
    ];
    let indexedSid: string | undefined;
    const deleted: string[] = [];
    const db = {
      query: vi.fn(() => ({
        withIndex: vi.fn(
          (
            index: string,
            configure: (query: {
              eq(field: string, value: string): unknown;
            }) => unknown,
          ) => {
            expect(index).toBe("by_sid");
            configure({
              eq(field, value) {
                expect(field).toBe("sid");
                indexedSid = value;
                return this;
              },
            });
            return {
              collect: () =>
                Promise.resolve(
                  sessions.filter((session) => session.sid === indexedSid),
                ),
            };
          },
        ),
      })),
      delete: vi.fn((id: string) => {
        deleted.push(id);
        return Promise.resolve();
      }),
    };
    type Handler = (
      ctx: { db: typeof db },
      args: { sid: string },
    ) => Promise<number>;
    const handler = (killSessionsBySid as unknown as Record<string, Handler>)[
      "_handler"
    ]!;

    await expect(handler({ db }, { sid: "sid-a" })).resolves.toBe(2);
    expect(deleted).toEqual(["session-1", "session-2"]);
  });
});

type SubjectSession = {
  _id: string;
  subject: string;
  tokenHash: string;
  prevTokenHash?: string;
  lastIdToken: string;
};

function subjectSessionHarness(initial: SubjectSession[]) {
  const sessions = [...initial];
  const deleted: string[] = [];
  const db = {
    query: vi.fn(() => ({
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
          sessions.filter(
            (session) =>
              (session as unknown as Record<string, unknown>)[field] === value,
          );
        return {
          unique: () => Promise.resolve(matching()[0] ?? null),
          collect: () => Promise.resolve(matching()),
          index,
        };
      },
    })),
    delete: vi.fn((id: string) => {
      deleted.push(id);
      const index = sessions.findIndex((session) => session._id === id);
      if (index >= 0) sessions.splice(index, 1);
      return Promise.resolve();
    }),
  };
  type Handler = (
    ctx: { db: typeof db },
    args: { presentedHash: string },
  ) => Promise<{ count: number; subject: string; idTokenHint: string }>;
  const handler = (
    killSubjectSessionsByToken as unknown as Record<string, Handler>
  )["_handler"]!;
  return { db, deleted, sessions, handler };
}

describe("killSubjectSessionsByToken", () => {
  const fixture = (): SubjectSession[] => [
    {
      _id: "subject-a-caller",
      subject: "subject-a",
      tokenHash: "caller-current",
      prevTokenHash: "caller-previous",
      lastIdToken: "caller-id-token",
    },
    {
      _id: "subject-a-other",
      subject: "subject-a",
      tokenHash: "other-current",
      lastIdToken: "other-id-token",
    },
    {
      _id: "subject-b",
      subject: "subject-b",
      tokenHash: "subject-b-current",
      lastIdToken: "subject-b-id-token",
    },
  ];

  it("derives the subject from the current token and deletes all of only that subject", async () => {
    const { db, deleted, sessions, handler } = subjectSessionHarness(fixture());

    await expect(
      handler({ db }, { presentedHash: "caller-current" }),
    ).resolves.toEqual({
      count: 2,
      subject: "subject-a",
      idTokenHint: "caller-id-token",
    });
    expect(deleted).toEqual(["subject-a-caller", "subject-a-other"]);
    expect(sessions.map((session) => session._id)).toEqual(["subject-b"]);
  });

  it("accepts the immediately previous token hash", async () => {
    const { db, handler } = subjectSessionHarness(fixture());

    await expect(
      handler({ db }, { presentedHash: "caller-previous" }),
    ).resolves.toMatchObject({ count: 2, subject: "subject-a" });
  });

  it("rejects an unknown token terminally", async () => {
    const { db, handler } = subjectSessionHarness(fixture());

    await expect(
      handler({ db }, { presentedHash: "unknown" }),
    ).rejects.toMatchObject({
      data: { kind: "terminal", code: "session_not_found" },
    });
  });
});
