import { defineSchema, defineTable } from "convex/server";
import { v } from "convex/values";

/**
 * Component-private tables — app code cannot read them (component isolation),
 * which is the trust boundary that lets `logtoRefreshToken` live here in
 * plaintext while browsers only ever hold a rotating application session token
 * (stored hashed). The short-lived ID token is cached alongside for the
 * reuse-window path; it shares the refresh token's trust boundary.
 *
 * Schema evolution rule: new fields on existing tables must be
 * `v.optional(...)` — component tables have no dedicated migration mechanism;
 * fields in a brand-new table may be required. The schema ships with the npm
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

  // SHA-256 delivery claims — raw webhook bodies and back-channel logout jtis.
  // Exactly-once handling absorbs a Logto retry whose 200 got lost. Swept by
  // the GC cron after 24h.
  webhookDeliveries: defineTable({
    bodyHash: v.string(),
    seenAt: v.number(),
    // Set once the delivery's work committed. A claim proves a delivery
    // *started*; only this proves it finished, which is what lets a caller whose
    // work is idempotent redo an abandoned one instead of answering for it.
    completedAt: v.optional(v.number()),
  })
    .index("by_bodyHash", ["bodyHash"])
    .index("by_seenAt", ["seenAt"]),

  // One row per application sign-in context. It owns one rotating sequence of
  // session-token generations and holds one Logto refresh token. Multiple rows
  // may be associated with the same Logto SSO session or remote grant.
  sessions: defineTable({
    /** Logto user id (the ID token's `sub`). */
    subject: v.string(),
    /** Logto OP session id (the ID token's optional `sid`). */
    sid: v.optional(v.string()),
    /** SHA-256 (hex) of the current session token — never the token itself. */
    tokenHash: v.string(),
    /** Legacy single-generation grace field retained for pre-history-table rows. */
    prevTokenHash: v.optional(v.string()),
    /** When the last rotation happened — the reuse window counts from here. */
    rotatedAt: v.optional(v.number()),
    /** Optimistic claim so concurrent refreshes can't double-hit Logto's token endpoint. */
    refreshingSince: v.optional(v.number()),
    /** Opaque owner token fencing late action completions after a claim is lost. */
    refreshClaimId: v.optional(v.string()),
    /** Optional ECDSA P-256 public key required to refresh a bound session. */
    devicePublicKey: v.optional(
      v.object({
        kty: v.literal("EC"),
        crv: v.literal("P-256"),
        x: v.string(),
        y: v.string(),
      }),
    ),
    /**
     * User-chosen name for this session, shown in a "where am I signed in"
     * list. Normalized and length-limited on write.
     */
    label: v.optional(v.string()),
    /**
     * Coarse, **self-reported** description of the client that signed in, so a
     * user can recognise their own devices. The app supplies it; the library
     * never reads a User-Agent or IP. It is not authenticated and must never
     * be used for a security decision.
     */
    client: v.optional(
      v.object({
        platform: v.optional(v.string()),
        os: v.optional(v.string()),
        browser: v.optional(v.string()),
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
    .index("by_subject_createdAt", ["subject", "createdAt"])
    .index("by_sid", ["sid"])
    .index("by_sid_createdAt", ["sid", "createdAt"])
    .index("by_lastRefreshedAt", ["lastRefreshedAt"]),

  // Logical revocation commits before physical cleanup begins. A session at
  // or before the marker is dead even while its row is waiting for a bounded
  // cleanup batch; a later sign-in receives a strictly newer `createdAt`.
  // Watermarks remain after cleanup so a delayed create mutation can never
  // reuse an older timestamp and accidentally reactivate revoked state. GC
  // collects one only once it governs no surviving session and is older than
  // any session that could still bind it — `by_revokedAt` is how it finds
  // candidates without scanning, since back-channel logout writes one row per
  // OP session that ever ends.
  subjectRevocations: defineTable({
    subject: v.string(),
    revokedAt: v.number(),
  })
    .index("by_subject", ["subject"])
    .index("by_revokedAt", ["revokedAt"]),

  sidRevocations: defineTable({
    sid: v.string(),
    revokedAt: v.number(),
  })
    .index("by_sid", ["sid"])
    .index("by_revokedAt", ["revokedAt"]),

  // Organization / API-resource access tokens minted from a Session's Logto
  // refresh token, cached so that an authorization check does not cost a grant
  // per render. Server-held like the refresh token: the token string leaves the
  // component only when the deployment set `exposeAccessTokens`.
  //
  // Rows are bounded per session (`RESOURCE_TOKEN_CACHE_LIMIT`) so the
  // transaction that deletes a session can delete them with it. A minted token
  // that outlived its session would keep authority the session no longer has.
  resourceTokens: defineTable({
    sessionId: v.id("sessions"),
    /** `organization:<id>`, `resource:<indicator>`, or `default`. */
    audience: v.string(),
    /** Sorted, space-joined requested scopes — a narrower ask is a different key. */
    scopeKey: v.string(),
    accessToken: v.string(),
    /** From the token's own `exp` where it has one, else `expires_in`. */
    expiresAt: v.number(),
    /** What Logto actually granted, which may be less than what was asked. */
    grantedScope: v.string(),
    mintedAt: v.number(),
  })
    .index("by_session_audience_scope", ["sessionId", "audience", "scopeKey"])
    .index("by_sessionId_mintedAt", ["sessionId", "mintedAt"])
    .index("by_expiresAt", ["expiresAt"]),

  // Bounded, indexed grace history for responses that arrive out of order.
  // `prevTokenHash` remains on sessions as a legacy adapter for rows created
  // before this table existed.
  sessionTokenGenerations: defineTable({
    sessionId: v.id("sessions"),
    tokenHash: v.string(),
    rotatedAt: v.number(),
    expiresAt: v.number(),
  })
    .index("by_tokenHash", ["tokenHash"])
    .index("by_sessionId_rotatedAt", ["sessionId", "rotatedAt"])
    .index("by_expiresAt", ["expiresAt"]),
});
