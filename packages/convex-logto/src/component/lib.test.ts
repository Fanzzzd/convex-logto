import { describe, expect, it, vi } from "vitest";
import { killSessionsBySid } from "./lib";

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
