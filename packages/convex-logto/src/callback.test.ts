import { describe, expect, it } from "vitest";
import { callbackResolved, classifySignInSearch } from "./callback";

describe("classifySignInSearch", () => {
  it("ignores URLs without a `state` param (not a sign-in redirect)", () => {
    expect(classifySignInSearch("")).toEqual({ kind: "none" });
    expect(classifySignInSearch("?foo=bar")).toEqual({ kind: "none" });
    // A stray ?error= on an ordinary app route must NOT be read as a sign-in failure.
    expect(classifySignInSearch("?error=invalid_scope")).toEqual({
      kind: "none",
    });
    expect(classifySignInSearch("?code=abc")).toEqual({ kind: "none" });
  });

  it("is 'pending' only for a real code redirect (both code and state)", () => {
    expect(classifySignInSearch("?code=abc&state=xyz")).toEqual({
      kind: "pending",
    });
    // state without a code is not a callback we should try to exchange.
    expect(classifySignInSearch("?state=xyz")).toEqual({ kind: "none" });
  });

  it("treats 'no session' errors (e.g. the user cancelled) as benign", () => {
    for (const error of [
      "access_denied",
      "login_required",
      "interaction_required",
      "consent_required",
    ]) {
      expect(classifySignInSearch(`?error=${error}&state=xyz`)).toEqual({
        kind: "benign",
      });
    }
  });

  it("surfaces a setup error with its description and a hint", () => {
    const outcome = classifySignInSearch(
      "?error=invalid_scope&error_description=bad%20scope&state=xyz",
    );
    expect(outcome.kind).toBe("error");
    if (outcome.kind === "error") {
      expect(outcome.message).toContain("invalid_scope");
      expect(outcome.message).toContain("bad scope");
      expect(outcome.message).toContain("scope"); // the hint mentions scopes
    }
  });

  it("surfaces an unknown error without inventing a hint", () => {
    const outcome = classifySignInSearch("?error=server_error&state=xyz");
    expect(outcome.kind).toBe("error");
    if (outcome.kind === "error") {
      expect(outcome.message).toContain("server_error");
      expect(outcome.message).not.toContain("Single-page app");
    }
  });
});

describe("callbackResolved (#14: a /callback URL must never wait forever)", () => {
  it("keeps waiting only while not authenticated and not timed out", () => {
    // The genuine in-flight exchange: hold the page until one signal arrives.
    expect(callbackResolved({ isAuthenticated: false, timedOut: false })).toBe(
      false,
    );
  });

  it("resolves as soon as the client is authenticated", () => {
    // Covers BOTH a successful first-time exchange (SDK flips this true as it
    // finishes) AND a stale/replayed callback URL where the user is already
    // authenticated and no exchange — hence no SDK callback — will ever run.
    expect(callbackResolved({ isAuthenticated: true, timedOut: false })).toBe(
      true,
    );
  });

  it("resolves on the timeout safety net even if never authenticated", () => {
    // The rare lost-session case: no exchange, no error, no auth — leave anyway.
    expect(callbackResolved({ isAuthenticated: false, timedOut: true })).toBe(
      true,
    );
    expect(callbackResolved({ isAuthenticated: true, timedOut: true })).toBe(
      true,
    );
  });
});
