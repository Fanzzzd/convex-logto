import { defineSchema, defineTable } from "convex/server";
import { v } from "convex/values";

/**
 * Component-private tables — app code cannot read them (component isolation),
 * which is the trust boundary that lets `logtoRefreshToken` live here in
 * plaintext while browsers only ever hold a one-time rotating session token
 * (stored hashed). The short-lived ID token is cached alongside for the
 * reuse-window path; it shares the refresh token's trust boundary.
 *
 * Schema evolution rule: new fields must be `v.optional(...)` — component
 * tables have no dedicated migration mechanism; the schema ships with the npm
 * package and is validated against existing rows on the app's next push.
 */
export default defineSchema({
  // One row per sign-in round-trip: server-held state + PKCE verifier between
  // building the sign-in URL and the code exchange. Consumed exactly once.
  transactions: defineTable({
    state: v.string(),
    codeVerifier: v.string(),
    redirectUri: v.string(),
    returnTo: v.optional(v.string()),
    expiresAt: v.number(),
  })
    .index("by_state", ["state"])
    .index("by_expiresAt", ["expiresAt"]),

  // One row per browser sign-in. Owns exactly one Logto grant and one rotating
  // chain of session tokens; killed as a unit (reuse handling, sign-out,
  // webhook-driven revocation).
  // SHA-256 hashes of processed webhook delivery bodies — exactly-once handling
  // for Logto's retries (a delivery whose 200 got lost in transit is re-sent
  // with the identical signed body). Swept by the GC cron after 24h.
  webhookDeliveries: defineTable({
    bodyHash: v.string(),
    seenAt: v.number(),
  })
    .index("by_bodyHash", ["bodyHash"])
    .index("by_seenAt", ["seenAt"]),

  sessions: defineTable({
    /** Logto user id (the ID token's `sub`). */
    subject: v.string(),
    /** SHA-256 (hex) of the current session token — never the token itself. */
    tokenHash: v.string(),
    /** Hash of the immediately-previous token, accepted inside the reuse window. */
    prevTokenHash: v.optional(v.string()),
    /** When the last rotation happened — the reuse window counts from here. */
    rotatedAt: v.optional(v.number()),
    /** Optimistic claim so concurrent refreshes can't double-hit Logto's token endpoint. */
    refreshingSince: v.optional(v.number()),
    /** Optional ECDSA P-256 public key required to refresh a bound session. */
    devicePublicKey: v.optional(
      v.object({
        kty: v.literal("EC"),
        crv: v.literal("P-256"),
        x: v.string(),
        y: v.string(),
      }),
    ),
    /** The Logto refresh token (confidential client). Never leaves the component. */
    logtoRefreshToken: v.string(),
    /** Cached current ID token + expiry, served on the reuse-window path. */
    lastIdToken: v.string(),
    lastIdTokenExp: v.number(),
    createdAt: v.number(),
    lastRefreshedAt: v.number(),
  })
    .index("by_tokenHash", ["tokenHash"])
    .index("by_prevTokenHash", ["prevTokenHash"])
    .index("by_subject", ["subject"])
    .index("by_lastRefreshedAt", ["lastRefreshedAt"]),
});
