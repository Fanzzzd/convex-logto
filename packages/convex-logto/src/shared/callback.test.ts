import { describe, expect, it } from "vitest";
import {
  callbackResolved,
  classifySignInSearch,
  isSafeReturnTo,
} from "./callback";

describe("classifySignInSearch", () => {
  it("ignores URLs without a `state` param (not a sign-in redirect)", () => {
    expect(classifySignInSearch("")).toEqual({ kind: "none" });
    expect(classifySignInSearch("?foo=bar")).toEqual({ kind: "none" });
    // A stray ?error= on an ordinary app route must NOT read as a sign-in
    // failure.
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

  it("reports a setup error with its description and a hint", () => {
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

  it("reports an unknown error without inventing a hint", () => {
    const outcome = classifySignInSearch("?error=server_error&state=xyz");
    expect(outcome.kind).toBe("error");
    if (outcome.kind === "error") {
      expect(outcome.message).toContain("server_error");
      expect(outcome.message).not.toContain("Single-page app");
    }
  });

  it("does not find a hint on Object.prototype", () => {
    // `error` comes straight off the query string. Looked up on a plain object,
    // `constructor` resolves through the prototype chain and the message the
    // app shows the user ends with a function's source.
    for (const error of [
      "constructor",
      "toString",
      "hasOwnProperty",
      "__proto__",
    ]) {
      const outcome = classifySignInSearch(`?error=${error}&state=xyz`);
      expect(outcome.kind).toBe("error");
      if (outcome.kind === "error") {
        expect(outcome.message).toBe(`Logto sign-in failed with "${error}".`);
      }
    }
  });
});

describe("callbackResolved (#14: a /callback URL must never wait forever)", () => {
  it("keeps waiting only while not authenticated, not timed out, and not errored", () => {
    // The genuine in-flight exchange. Hold the page until one signal arrives.
    expect(
      callbackResolved({
        isAuthenticated: false,
        timedOut: false,
        errored: false,
      }),
    ).toBe(false);
  });

  it("resolves as soon as the client is authenticated", () => {
    // Covers BOTH a successful first-time exchange (SDK flips this true as it
    // finishes) AND a stale/replayed callback URL where the user is already
    // authenticated and no exchange, and so no SDK callback, will ever run.
    expect(
      callbackResolved({
        isAuthenticated: true,
        timedOut: false,
        errored: false,
      }),
    ).toBe(true);
  });

  it("resolves on the timeout safety net even if never authenticated", () => {
    // The rare lost-session case. No exchange, no error, no auth. Leave anyway.
    expect(
      callbackResolved({
        isAuthenticated: false,
        timedOut: true,
        errored: false,
      }),
    ).toBe(true);
  });

  it("resolves (returns to the app) on a failed exchange instead of crashing", () => {
    // A stale/replayed callback. The SDK ran the exchange and it failed (state
    // mismatch / spent code / lost sign-in session). Must resolve, not throw,
    // matching react-oidc-context / @auth0/auth0-react, which never crash the
    // app on a callback failure. The provider logs it and returns to the app.
    expect(
      callbackResolved({
        isAuthenticated: false,
        timedOut: false,
        errored: true,
      }),
    ).toBe(true);
  });
});

describe("isSafeReturnTo (open-redirect guard)", () => {
  it("accepts same-origin paths, with or without query/hash", () => {
    expect(isSafeReturnTo("/")).toBe(true);
    expect(isSafeReturnTo("/dashboard")).toBe(true);
    expect(isSafeReturnTo("/deep/page?tab=1#anchor")).toBe(true);
  });

  it("rejects anything that could leave the origin", () => {
    // Protocol-relative, the classic open-redirect attack.
    expect(isSafeReturnTo("//evil.example.com")).toBe(false);
    // Absolute URLs.
    expect(isSafeReturnTo("https://evil.example.com")).toBe(false);
    // Backslash variants. Some parsers fold `\` into `/`, so `/\evil.com`
    // becomes `//evil.com`.
    expect(isSafeReturnTo("/\\evil.example.com")).toBe(false);
    expect(isSafeReturnTo("/ok\\..\\evil")).toBe(false);
    // Not a path at all.
    expect(isSafeReturnTo("dashboard")).toBe(false);
    expect(isSafeReturnTo("")).toBe(false);
  });

  it("rejects raw control characters the URL parser strips", () => {
    // The WHATWG URL parser removes ASCII tab, LF and CR *before* parsing, so
    // each of these inspects as a same-origin path and then resolves to
    // `//evil.example.com`.
    expect(isSafeReturnTo("/\t/evil.example.com")).toBe(false);
    expect(isSafeReturnTo("/\n/evil.example.com")).toBe(false);
    expect(isSafeReturnTo("/\r/evil.example.com")).toBe(false);
    expect(isSafeReturnTo("/\r\n/evil.example.com")).toBe(false);
    // The rest of the C0 range and DEL go with them.
    expect(isSafeReturnTo("/page\u0000")).toBe(false);
    expect(isSafeReturnTo("/page\u007f")).toBe(false);
    // Percent-encoded control characters stay a legitimate path.
    expect(isSafeReturnTo("/%09/not-a-host")).toBe(true);
  });

  it("blocks the tab bypass end to end", () => {
    // Every caller navigates with the string unmodified, so what the browser
    // resolves is what matters.
    const smuggled = "/\t/evil.example.com";
    expect(new URL(smuggled, "https://app.example.com").origin).toBe(
      "https://evil.example.com",
    );
    expect(isSafeReturnTo(smuggled)).toBe(false);
  });
});
