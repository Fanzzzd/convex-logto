import { describe, expect, it, vi } from "vitest";
import {
  createAuthEventEmitter,
  NO_AUTH_EVENTS,
  type LogtoAuthEvent,
} from "./auth-events";

describe("auth event emitter", () => {
  it("measures elapsed time from the moment it was created", () => {
    const events: LogtoAuthEvent[] = [];
    let clock = 1_000;
    const emit = createAuthEventEmitter(
      (event) => events.push(event),
      () => clock,
    );

    clock = 1_040;
    emit("bootstrap_start");
    clock = 1_310;
    emit("session_restored", { source: "cache" });

    expect(events).toEqual([
      { phase: "bootstrap_start", elapsedMs: 40 },
      { phase: "session_restored", elapsedMs: 310, source: "cache" },
    ]);
  });

  it("does nothing at all without a handler", () => {
    const now = vi.fn(() => 0);
    const emit = createAuthEventEmitter(undefined, now);

    emit("bootstrap_start");

    expect(emit).toBe(NO_AUTH_EVENTS);
    expect(now).not.toHaveBeenCalled();
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
