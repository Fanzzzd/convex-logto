// Organization authorization reads the ID token Convex already validated:
// Logto maps `urn:logto:scope:organizations` to an `organizations` claim and
// `urn:logto:scope:organization_roles` to an `organization_roles` claim, both in
// the ID token, and Convex's `UserIdentity` passes unrecognised claims through.
// These cover the two ways that goes wrong — a missing scope, and a role entry
// whose organization half does not match.
import { ConvexError } from "convex/values";
import { describe, expect, it } from "vitest";
import { asUserClaims, parseOrganizationRole } from "./claims";
import {
  assertOrganizationMember,
  assertOrganizationRole,
  logtoOrganizationRoles,
  logtoOrganizations,
  type LogtoIdentityCtx,
} from "./organizations";

function ctxWith(identity: Record<string, unknown> | null): LogtoIdentityCtx {
  return { auth: { getUserIdentity: () => Promise.resolve(identity) } };
}

const signedIn = (extra: Record<string, unknown> = {}) =>
  ctxWith({ subject: "user-1", ...extra });

describe("organization membership", () => {
  it("reads the organizations claim", async () => {
    const ctx = signedIn({ organizations: ["org-a", "org-b"] });
    expect(await logtoOrganizations(ctx)).toEqual(["org-a", "org-b"]);
    await expect(
      assertOrganizationMember(ctx, "org-b"),
    ).resolves.toBeUndefined();
  });

  it("a missing scope authorizes nothing rather than everything", async () => {
    // Absent and empty are deliberately the same answer: a deployment that never
    // requested the scope looks exactly like a user who belongs to nothing, and
    // only one of the two readings is safe.
    const ctx = signedIn();
    expect(await logtoOrganizations(ctx)).toEqual([]);
    await expect(assertOrganizationMember(ctx, "org-a")).rejects.toBeInstanceOf(
      ConvexError,
    );
  });

  it("names the scope in the failure, because a config gap looks like a denial", async () => {
    await expect(assertOrganizationMember(signedIn(), "org-a")).rejects.toThrow(
      /urn:logto:scope:organizations/,
    );
  });

  it("ignores a claim that is not an array of strings", async () => {
    const ctx = signedIn({ organizations: ["org-a", 7, null] });
    expect(await logtoOrganizations(ctx)).toEqual(["org-a"]);
  });

  it("refuses an unauthenticated caller", async () => {
    await expect(logtoOrganizations(ctxWith(null))).rejects.toBeInstanceOf(
      ConvexError,
    );
  });
});

describe("organization roles", () => {
  const ctx = signedIn({
    organization_roles: ["org-a:admin", "org-b:viewer", "org-a:billing"],
  });

  it("returns only the roles held in the organization asked about", async () => {
    expect(await logtoOrganizationRoles(ctx, "org-a")).toEqual([
      "admin",
      "billing",
    ]);
    expect(await logtoOrganizationRoles(ctx, "org-b")).toEqual(["viewer"]);
    expect(await logtoOrganizationRoles(ctx, "org-c")).toEqual([]);
  });

  it("does not let one organization's role authorize another", async () => {
    // The failure this exists to prevent: matching on the role name alone would
    // make `org-b:viewer` satisfy a viewer check in `org-a`.
    await expect(
      assertOrganizationRole(ctx, "org-a", "viewer"),
    ).rejects.toBeInstanceOf(ConvexError);
    await expect(
      assertOrganizationRole(ctx, "org-a", "admin"),
    ).resolves.toBeUndefined();
  });

  it("accepts any one of several roles", async () => {
    await expect(
      assertOrganizationRole(ctx, "org-b", ["admin", "viewer"]),
    ).resolves.toBeUndefined();
  });

  it("names the scope when the claim is missing entirely", async () => {
    await expect(
      assertOrganizationRole(signedIn(), "org-a", "admin"),
    ).rejects.toThrow(/urn:logto:scope:organization_roles/);
  });
});

describe("parseOrganizationRole", () => {
  it("splits on the first colon, so a role name may contain one", () => {
    expect(parseOrganizationRole("org-a:billing:read")).toEqual({
      organizationId: "org-a",
      role: "billing:read",
    });
  });

  it("rejects entries with no usable split", () => {
    expect(parseOrganizationRole("org-a")).toBeNull();
    expect(parseOrganizationRole(":admin")).toBeNull();
    expect(parseOrganizationRole("org-a:")).toBeNull();
  });
});

describe("asUserClaims", () => {
  it("requires the one claim an ID token cannot omit", () => {
    expect(asUserClaims({ email: "a@b.c" })).toBeUndefined();
    expect(asUserClaims({ sub: 7 })).toBeUndefined();
    expect(asUserClaims(null)).toBeUndefined();
  });

  it("keeps every other claim reachable", () => {
    const claims = asUserClaims({
      sub: "user-1",
      email: "a@b.c",
      organizations: ["org-a"],
      tenant_custom: { seat: 3 },
    });
    expect(claims?.sub).toBe("user-1");
    expect(claims?.email).toBe("a@b.c");
    expect(claims?.organizations).toEqual(["org-a"]);
    expect(claims?.tenant_custom).toEqual({ seat: 3 });
  });
});
