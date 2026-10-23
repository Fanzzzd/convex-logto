import { describe, expect, it } from "vitest";
import {
  decodeBase64Url,
  decodeJwtPayload,
  decodeJwtSegment,
  isRecord,
} from "./decode";

function segment(value: unknown): string {
  const bytes = new TextEncoder().encode(JSON.stringify(value));
  return btoa(String.fromCharCode(...bytes))
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

describe("isRecord", () => {
  it("accepts plain objects only", () => {
    expect(isRecord({})).toBe(true);
    expect(isRecord([])).toBe(false);
    expect(isRecord(null)).toBe(false);
    expect(isRecord("x")).toBe(false);
  });
});

describe("decodeBase64Url", () => {
  it("rejects padding, the base64 alphabet, and impossible lengths", () => {
    expect(decodeBase64Url("")).toBeNull();
    expect(decodeBase64Url("YQ==")).toBeNull();
    expect(decodeBase64Url("a+b/")).toBeNull();
    expect(decodeBase64Url("abcde")).toBeNull();
    expect(Array.from(decodeBase64Url("YQ") ?? [])).toEqual([0x61]);
  });
});

describe("decodeJwtSegment", () => {
  it("reads a segment as UTF-8, not one char per byte", () => {
    // `atob` alone turns a `name` of 王小明 into ç\u008e\u008bå°\u008fæ\u0098\u008e.
    const claims = { name: "王小明", family_name: "Müller", emoji: "🔐" };
    expect(decodeJwtSegment(segment(claims))).toEqual(claims);
  });

  it("refuses a segment it cannot decode", () => {
    expect(decodeJwtSegment("not base64url!")).toBeUndefined();
    expect(decodeJwtSegment("bm90IGpzb24")).toBeUndefined();
  });
});

describe("decodeJwtPayload", () => {
  it("returns the payload object of a three-segment token", () => {
    expect(decodeJwtPayload(`h.${segment({ sub: "u1" })}.s`)).toEqual({
      sub: "u1",
    });
  });

  it("returns null for a non-object payload or the wrong segment count", () => {
    expect(decodeJwtPayload(`h.${segment([1])}.s`)).toBeNull();
    expect(decodeJwtPayload(segment({ sub: "u1" }))).toBeNull();
  });
});
