import { describe, expect, it, vi } from "vitest";
import {
  createAuthEventEmitter,
  NO_AUTH_EVENTS,
  type LogtoAuthEvent,
  type LogtoAuthEventHandler,
} from "./auth-events";

describe("auth event emitter", () => {
  it("measures elapsed time from bootstrap_start, not from construction", () => {
    const events: LogtoAuthEvent[] = [];
    let clock = 1_000;
    const emit = createAuthEventEmitter(
      (event) => events.push(event),
      () => clock,
    );

    // A React commit (or a manual `start()`) can land long after the emitter is
    // built; that gap is not part of anyone's bootstrap.
    clock = 1_040;
    emit("bootstrap_start");
    clock = 1_310;
    emit("session_restored", { source: "cache" });

    expect(events).toEqual([
      { phase: "bootstrap_start", elapsedMs: 0 },
      { phase: "session_restored", elapsedMs: 270, source: "cache" },
    ]);
  });

  it("rebaselines on a second bootstrap_start", () => {
    const events: LogtoAuthEvent[] = [];
    let clock = 0;
    const emit = createAuthEventEmitter(
      (event) => events.push(event),
      () => clock,
    );

    emit("bootstrap_start");
    clock = 500;
    emit("bootstrap_start");
    clock = 560;
    emit("unauthenticated");

    expect(events.at(-1)).toEqual({ phase: "unauthenticated", elapsedMs: 60 });
  });

  it("counts from the first event a late handler sees", () => {
    const events: LogtoAuthEvent[] = [];
    let clock = 0;
    const emit = createAuthEventEmitter(
      (event) => events.push(event),
      () => clock,
    );

    // No bootstrap_start at all (an engine already past it): the only honest
    // baseline is the first event.
    clock = 900;
    emit("refresh_started");
    clock = 1_100;
    emit("refresh_succeeded");

    expect(events).toEqual([
      { phase: "refresh_started", elapsedMs: 0 },
      { phase: "refresh_succeeded", elapsedMs: 200 },
    ]);
  });

  it("does nothing at all without a handler", () => {
    const now = vi.fn(() => 0);
    const emit = createAuthEventEmitter(undefined, now);

    emit("bootstrap_start");

    expect(emit).toBe(NO_AUTH_EVENTS);
    expect(now).not.toHaveBeenCalled();
  });

  it("reads no clock while a handler slot is empty", () => {
    const now = vi.fn(() => 0);
    const slot: { current: LogtoAuthEventHandler | undefined } = {
      current: undefined,
    };
    const emit = createAuthEventEmitter(slot, now);

    // Opting out of telemetry must not cost a measurement, and a provider that
    // wires a slot cannot know at mount whether a handler will ever arrive.
    emit("bootstrap_start");
    emit("session_restored");

    expect(now).not.toHaveBeenCalled();
  });

  it("picks up a handler the slot receives later", () => {
    const events: LogtoAuthEvent[] = [];
    let clock = 0;
    const slot: { current: LogtoAuthEventHandler | undefined } = {
      current: undefined,
    };
    const emit = createAuthEventEmitter(slot, () => clock);

    emit("bootstrap_start");
    slot.current = (event) => events.push(event);
    clock = 25;
    emit("convex_authenticated");
    slot.current = undefined;
    clock = 90;
    emit("signed_out");

    expect(events).toEqual([{ phase: "convex_authenticated", elapsedMs: 0 }]);
  });

  it("contains a throwing handler instead of failing the sign-in", () => {
    const consoleError = vi
      .spyOn(console, "error")
      .mockImplementation(() => {});
    const emit = createAuthEventEmitter(() => {
      throw new Error("analytics is down");
    });

    // Telemetry must never be able to break authentication.
    expect(() => emit("convex_authenticated")).not.toThrow();
    expect(consoleError).toHaveBeenCalledWith(
      "convex-logto: an onAuthEvent handler threw.",
      expect.objectContaining({ message: "analytics is down" }),
    );
    consoleError.mockRestore();
  });
});
