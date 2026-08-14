import { ConvexError, v } from "convex/values";
import {
  action,
  internalMutation,
  internalQuery,
  mutation,
  query,
} from "./_generated/server.js";
import { internal } from "./_generated/api.js";
import {
  DEFAULT_REUSE_WINDOW_MS,
  SESSION_GC_AFTER_MS,
  TRANSACTION_TTL_MS,
  WEBHOOK_DELIVERY_GC_AFTER_MS,
  assertDeviceProof,
  buildAuthorizeUrl,
  buildEndSessionUrl,
  classifyTokenEndpointFailure,
  decideRefresh,
  decodeIdToken,
  generatePkce,
  generateToken,
  hashToken,
  isPreviousTokenWithinReuseWindow,
  rotateTokenHashes,
  sessionReuseDetectedError,
  terminal,
  transient,
  type DevicePublicKey,
} from "./core.js";

// The confidential-client config every OIDC-touching call needs. The values are
// read from the APP's env by the `logtoSessionApi()` wrappers and passed in as
// arguments (components can't read the app's process.env) — the workos-authkit
// pattern. The secret crosses the component boundary as an argument only.
const oidcArgs = {
  endpoint: v.string(),
  appId: v.string(),
  clientSecret: v.string(),
};

const devicePublicKeyValidator = v.object({
  kty: v.literal("EC"),
  crv: v.literal("P-256"),
  x: v.string(),
  y: v.string(),
});

type OidcConfig = { endpoint: string; appId: string; clientSecret: string };

// Explicit result types for same-file `ctx.runMutation(internal.lib.*)` calls —
// without them TypeScript's inference goes circular (action ↔ generated api).
type ConsumedTransaction = { codeVerifier: string; returnTo?: string };
type BeginRefreshResult =
  | { outcome: "refresh"; sessionId: string; refreshToken: string }
  | { outcome: "cached"; sessionId: string; idToken: string }
  | { outcome: "reuse"; refreshToken: string };

function basicAuth(config: OidcConfig): string {
  return `Basic ${btoa(`${config.appId}:${config.clientSecret}`)}`;
}

/** POST to Logto's token endpoint; classify failures terminal vs transient. */
async function tokenEndpoint(
  config: OidcConfig,
  params: Record<string, string>,
): Promise<{
  id_token: string;
  refresh_token?: string;
  access_token?: string;
}> {
  let res: Response;
  try {
    res = await fetch(`${config.endpoint}/oidc/token`, {
      method: "POST",
      headers: {
        Authorization: basicAuth(config),
        "Content-Type": "application/x-www-form-urlencoded",
      },
      body: new URLSearchParams(params),
    });
  } catch {
    throw transient(
      "logto_unreachable",
      "Could not reach the Logto token endpoint.",
    );
  }
  const body = (await res.json().catch(() => ({}))) as {
    error?: string;
    id_token?: string;
    refresh_token?: string;
    access_token?: string;
  };
  if (!res.ok) throw classifyTokenEndpointFailure(res.status, body);
  if (!body.id_token) {
    throw terminal(
      "no_id_token",
      "Logto's token response carried no id_token — is `openid` scope enabled?",
    );
  }
  return body as { id_token: string; refresh_token?: string };
}

/** Best-effort RFC 7009 revocation — revoking one refresh token cascades to the whole grant. */
async function revokeGrant(
  config: OidcConfig,
  refreshToken: string,
): Promise<void> {
  try {
    await fetch(`${config.endpoint}/oidc/token/revocation`, {
      method: "POST",
      headers: {
        Authorization: basicAuth(config),
        "Content-Type": "application/x-www-form-urlencoded",
      },
      body: new URLSearchParams({
        token: refreshToken,
        token_type_hint: "refresh_token",
      }),
    });
  } catch {
    // Best effort: the local session row is already gone; the grant dies at
    // its own TTL if Logto was unreachable.
  }
}

// --- sign-in ----------------------------------------------------------------

export const createSignInUrl = action({
  args: {
    endpoint: v.string(),
    appId: v.string(),
    redirectUri: v.string(),
    returnTo: v.optional(v.string()),
    scopes: v.optional(v.array(v.string())),
    resources: v.optional(v.array(v.string())),
  },
  returns: v.object({ url: v.string() }),
  handler: async (ctx, args) => {
    const state = generateToken();
    const { verifier, challenge } = await generatePkce();
    await ctx.runMutation(internal.lib.createTransaction, {
      state,
      codeVerifier: verifier,
      redirectUri: args.redirectUri,
      returnTo: args.returnTo,
      expiresAt: Date.now() + TRANSACTION_TTL_MS,
    });
    return {
      url: buildAuthorizeUrl({
        endpoint: args.endpoint,
        appId: args.appId,
        redirectUri: args.redirectUri,
        state,
        challenge,
        scopes: args.scopes,
        resources: args.resources,
      }),
    };
  },
});

export const createTransaction = internalMutation({
  args: {
    state: v.string(),
    codeVerifier: v.string(),
    redirectUri: v.string(),
    returnTo: v.optional(v.string()),
    expiresAt: v.number(),
  },
  returns: v.null(),
  handler: async (ctx, args) => {
    await ctx.db.insert("transactions", args);
    return null;
  },
});

// --- exchange ---------------------------------------------------------------

export const exchange = action({
  args: {
    ...oidcArgs,
    code: v.string(),
    state: v.string(),
    redirectUri: v.string(),
    devicePublicKey: v.optional(devicePublicKeyValidator),
  },
  returns: v.object({
    idToken: v.string(),
    sessionToken: v.string(),
    sessionId: v.string(),
    returnTo: v.optional(v.string()),
  }),
  handler: async (ctx, args) => {
    const transaction: ConsumedTransaction = await ctx.runMutation(
      internal.lib.consumeTransaction,
      {
        state: args.state,
        redirectUri: args.redirectUri,
        now: Date.now(),
      },
    );
    const tokens = await tokenEndpoint(args, {
      grant_type: "authorization_code",
      code: args.code,
      redirect_uri: args.redirectUri,
      code_verifier: transaction.codeVerifier,
    });
    if (!tokens.refresh_token) {
      throw terminal(
        "no_refresh_token",
        "Logto issued no refresh token — the session can't be maintained. " +
          "Check the app is a Traditional Web application.",
      );
    }
    const claims = decodeIdToken(tokens.id_token, args);
    const sessionToken = generateToken();
    const now = Date.now();
    const sessionId: string = await ctx.runMutation(
      internal.lib.createSession,
      {
        subject: claims.subject,
        sid: claims.sid,
        tokenHash: await hashToken(sessionToken),
        logtoRefreshToken: tokens.refresh_token,
        lastIdToken: tokens.id_token,
        lastIdTokenExp: claims.expiresAtMs,
        devicePublicKey: args.devicePublicKey,
        now,
      },
    );
    return {
      idToken: tokens.id_token,
      sessionToken,
      sessionId,
      returnTo: transaction.returnTo,
    };
  },
});

export const consumeTransaction = internalMutation({
  args: { state: v.string(), redirectUri: v.string(), now: v.number() },
  returns: v.object({
    codeVerifier: v.string(),
    returnTo: v.optional(v.string()),
  }),
  handler: async (ctx, args) => {
    const transaction = await ctx.db
      .query("transactions")
      .withIndex("by_state", (q) => q.eq("state", args.state))
      .unique();
    // Deleting inside the same mutation makes consumption one-time: a replayed
    // callback with the same state finds nothing and fails terminally.
    if (transaction) await ctx.db.delete(transaction._id);
    if (!transaction || transaction.expiresAt < args.now) {
      throw terminal(
        "transaction_not_found",
        "No pending sign-in for this state — the callback is stale, replayed, or the sign-in expired. Start sign-in again.",
      );
    }
    if (transaction.redirectUri !== args.redirectUri) {
      throw terminal(
        "redirect_uri_mismatch",
        "The callback's redirect URI doesn't match the one sign-in started with.",
      );
    }
    return {
      codeVerifier: transaction.codeVerifier,
      returnTo: transaction.returnTo,
    };
  },
});

export const createSession = internalMutation({
  args: {
    subject: v.string(),
    sid: v.optional(v.string()),
    tokenHash: v.string(),
    logtoRefreshToken: v.string(),
    lastIdToken: v.string(),
    lastIdTokenExp: v.number(),
    devicePublicKey: v.optional(devicePublicKeyValidator),
    now: v.number(),
  },
  returns: v.string(),
  handler: async (ctx, args) => {
    const { now, ...session } = args;
    return await ctx.db.insert("sessions", {
      ...session,
      createdAt: now,
      lastRefreshedAt: now,
    });
  },
});

// --- refresh ----------------------------------------------------------------

export const refresh = action({
  args: {
    ...oidcArgs,
    sessionToken: v.string(),
    deviceProof: v.optional(v.string()),
    reuseWindowMs: v.optional(v.number()),
  },
  returns: v.object({
    idToken: v.string(),
    sessionToken: v.string(),
    sessionId: v.string(),
  }),
  handler: async (
    ctx,
    args,
  ): Promise<{ idToken: string; sessionToken: string; sessionId: string }> => {
    const presentedHash = await hashToken(args.sessionToken);
    const devicePublicKey: DevicePublicKey | null = await ctx.runQuery(
      internal.lib.devicePublicKeyForToken,
      { presentedHash },
    );
    await assertDeviceProof({
      publicKey: devicePublicKey ?? undefined,
      sessionToken: args.sessionToken,
      proof: args.deviceProof,
    });
    // The next token is generated in the action (mutations have deterministic
    // randomness); the mutation adopts it only where rotation happens.
    const candidate = generateToken();
    const begin: BeginRefreshResult = await ctx.runMutation(
      internal.lib.beginRefresh,
      {
        presentedHash,
        candidateHash: await hashToken(candidate),
        now: Date.now(),
        reuseWindowMs: args.reuseWindowMs ?? DEFAULT_REUSE_WINDOW_MS,
      },
    );

    switch (begin.outcome) {
      case "cached":
        // Previous token inside the reuse window, cached ID token still fresh:
        // rotated locally without touching Logto.
        return {
          idToken: begin.idToken,
          sessionToken: candidate,
          sessionId: begin.sessionId,
        };
      case "reuse": {
        // Reuse handling: the session died in beginRefresh; revoke its grant.
        await revokeGrant(args, begin.refreshToken);
        throw sessionReuseDetectedError();
      }
      case "refresh": {
        let tokens: Awaited<ReturnType<typeof tokenEndpoint>>;
        try {
          tokens = await tokenEndpoint(args, {
            grant_type: "refresh_token",
            refresh_token: begin.refreshToken,
          });
        } catch (error) {
          const terminalFailure =
            error instanceof ConvexError &&
            (error.data as { kind?: string }).kind === "terminal";
          await ctx.runMutation(
            terminalFailure
              ? internal.lib.killSession
              : internal.lib.releaseClaim,
            { sessionId: begin.sessionId },
          );
          throw error;
        }
        const claims = decodeIdToken(tokens.id_token, args);
        await ctx.runMutation(internal.lib.completeRefresh, {
          sessionId: begin.sessionId,
          presentedHash,
          candidateHash: await hashToken(candidate),
          // Logto rotates the confidential-client refresh token only at ≥70%
          // TTL; persist the new one atomically whenever it arrives.
          newRefreshToken: tokens.refresh_token,
          idToken: tokens.id_token,
          idTokenExp: claims.expiresAtMs,
          sid: claims.sid,
          now: Date.now(),
        });
        return {
          idToken: tokens.id_token,
          sessionToken: candidate,
          sessionId: begin.sessionId,
        };
      }
    }
  },
});

export const devicePublicKeyForToken = internalQuery({
  args: { presentedHash: v.string() },
  returns: v.union(devicePublicKeyValidator, v.null()),
  handler: async (ctx, args) => {
    const byCurrent = await ctx.db
      .query("sessions")
      .withIndex("by_tokenHash", (q) => q.eq("tokenHash", args.presentedHash))
      .unique();
    const session =
      byCurrent ??
      (await ctx.db
        .query("sessions")
        .withIndex("by_prevTokenHash", (q) =>
          q.eq("prevTokenHash", args.presentedHash),
        )
        .unique());
    return session?.devicePublicKey ?? null;
  },
});

export const beginRefresh = internalMutation({
  args: {
    presentedHash: v.string(),
    candidateHash: v.string(),
    now: v.number(),
    reuseWindowMs: v.number(),
  },
  returns: v.union(
    // Rotate against Logto: the claim is set; the action must complete or release.
    v.object({
      outcome: v.literal("refresh"),
      sessionId: v.string(),
      refreshToken: v.string(),
    }),
    // Rotated locally off the reuse window — the cached ID token is still fresh.
    v.object({
      outcome: v.literal("cached"),
      sessionId: v.string(),
      idToken: v.string(),
    }),
    // The session was killed; the action revokes this grant.
    v.object({ outcome: v.literal("reuse"), refreshToken: v.string() }),
  ),
  handler: async (ctx, args) => {
    const byCurrent = await ctx.db
      .query("sessions")
      .withIndex("by_tokenHash", (q) => q.eq("tokenHash", args.presentedHash))
      .unique();
    const session =
      byCurrent ??
      (await ctx.db
        .query("sessions")
        .withIndex("by_prevTokenHash", (q) =>
          q.eq("prevTokenHash", args.presentedHash),
        )
        .unique());
    if (!session) {
      throw terminal(
        "session_not_found",
        "No session for this token — it was signed out or revoked. Sign in again.",
      );
    }

    const decision = decideRefresh({
      presentedHash: args.presentedHash,
      session,
      now: args.now,
      reuseWindowMs: args.reuseWindowMs,
    });
    switch (decision.outcome) {
      case "in-flight":
        throw transient(
          "refresh_in_flight",
          "Another refresh for this session is mid-flight — retry shortly.",
        );
      case "reuse": {
        // A token older than the reuse window: assume theft, kill the session.
        // The victim's next refresh finds nothing and cleanly re-authenticates.
        await ctx.db.delete(session._id);
        return {
          outcome: "reuse" as const,
          refreshToken: session.logtoRefreshToken,
        };
      }
      case "cached": {
        // Rotate locally while retaining the superseded current generation as
        // the grace token. The presented token may itself be the older grace
        // generation, so retaining it would orphan a concurrent response.
        await ctx.db.patch(session._id, {
          ...rotateTokenHashes(session.tokenHash, args.candidateHash),
          rotatedAt: args.now,
        });
        return {
          outcome: "cached" as const,
          sessionId: session._id,
          idToken: session.lastIdToken,
        };
      }
      case "refresh":
      case "refresh-previous": {
        // Claim before the action touches Logto's token endpoint, so a
        // concurrent replay can't double-spend the refresh token at the
        // rotation boundary (Logto has zero reuse tolerance).
        await ctx.db.patch(session._id, { refreshingSince: args.now });
        return {
          outcome: "refresh" as const,
          sessionId: session._id,
          refreshToken: session.logtoRefreshToken,
        };
      }
    }
  },
});

export const completeRefresh = internalMutation({
  args: {
    sessionId: v.string(),
    presentedHash: v.string(),
    candidateHash: v.string(),
    newRefreshToken: v.optional(v.string()),
    idToken: v.string(),
    idTokenExp: v.number(),
    sid: v.optional(v.string()),
    now: v.number(),
  },
  returns: v.null(),
  handler: async (ctx, args) => {
    const id = ctx.db.normalizeId("sessions", args.sessionId);
    const session = id && (await ctx.db.get(id));
    if (!session) return null; // killed concurrently (webhook revocation) — nothing to write
    await ctx.db.patch(session._id, {
      // The refresh claim prevents any other rotation before completion, so
      // this is the generation superseded by the candidate even when refresh
      // began by presenting the previous generation.
      ...rotateTokenHashes(session.tokenHash, args.candidateHash),
      rotatedAt: args.now,
      refreshingSince: undefined,
      lastIdToken: args.idToken,
      lastIdTokenExp: args.idTokenExp,
      ...(args.sid === undefined ? {} : { sid: args.sid }),
      lastRefreshedAt: args.now,
      ...(args.newRefreshToken
        ? { logtoRefreshToken: args.newRefreshToken }
        : {}),
    });
    return null;
  },
});

export const releaseClaim = internalMutation({
  args: { sessionId: v.string() },
  returns: v.null(),
  handler: async (ctx, args) => {
    const id = ctx.db.normalizeId("sessions", args.sessionId);
    const session = id && (await ctx.db.get(id));
    if (session)
      await ctx.db.patch(session._id, { refreshingSince: undefined });
    return null;
  },
});

export const killSession = internalMutation({
  args: { sessionId: v.string() },
  returns: v.null(),
  handler: async (ctx, args) => {
    const id = ctx.db.normalizeId("sessions", args.sessionId);
    const session = id && (await ctx.db.get(id));
    if (session) await ctx.db.delete(session._id);
    return null;
  },
});

// --- sign-out ---------------------------------------------------------------

export const signOut = action({
  args: {
    ...oidcArgs,
    sessionToken: v.string(),
    postLogoutRedirectUri: v.optional(v.string()),
    federated: v.optional(v.boolean()),
  },
  returns: v.object({ endSessionUrl: v.optional(v.string()) }),
  handler: async (ctx, args) => {
    const tokenHash = await hashToken(args.sessionToken);
    const refreshToken: string | null = await ctx.runMutation(
      internal.lib.takeSession,
      { tokenHash },
    );
    // RP-initiated logout does NOT revoke offline_access grants in Logto, so
    // revoke explicitly — one call cascades to the whole grant.
    if (refreshToken) await revokeGrant(args, refreshToken);
    return {
      endSessionUrl:
        args.federated === false
          ? undefined
          : buildEndSessionUrl({
              endpoint: args.endpoint,
              appId: args.appId,
              postLogoutRedirectUri: args.postLogoutRedirectUri,
            }),
    };
  },
});

export const takeSession = internalMutation({
  args: { tokenHash: v.string() },
  returns: v.union(v.string(), v.null()),
  handler: async (ctx, args) => {
    const session = await ctx.db
      .query("sessions")
      .withIndex("by_tokenHash", (q) => q.eq("tokenHash", args.tokenHash))
      .unique();
    if (!session) return null; // already gone — sign-out is idempotent
    await ctx.db.delete(session._id);
    return session.logtoRefreshToken;
  },
});

// --- session liveness -------------------------------------------------------

export const sessionValid = query({
  args: { sessionId: v.string() },
  returns: v.boolean(),
  handler: async (ctx, args) => {
    // Keyed on the stable (non-credential) session id so the browser's
    // subscription survives token rotation; the row deletion pushes `false`
    // to every subscribed tab the instant the session is revoked.
    const id = ctx.db.normalizeId("sessions", args.sessionId);
    if (!id) return false;
    return (await ctx.db.get(id)) !== null;
  },
});

export const hasActiveSessionForSubject = query({
  args: { subject: v.string() },
  returns: v.boolean(),
  handler: async (ctx, args) => {
    const session = await ctx.db
      .query("sessions")
      .withIndex("by_subject", (q) => q.eq("subject", args.subject))
      .first();
    return session !== null;
  },
});

/**
 * Authenticate with a live session token, derive its subject server-side, and
 * delete every session for that subject atomically. The immediately-previous
 * token hash is accepted so a caller racing a normal rotation keeps the same
 * grace behavior as refresh. Never accept a client-supplied subject here.
 */
export const killSubjectSessionsByToken = mutation({
  args: {
    presentedHash: v.string(),
    now: v.number(),
    reuseWindowMs: v.number(),
  },
  returns: v.union(
    v.object({
      outcome: v.literal("signed-out"),
      count: v.number(),
      subject: v.string(),
    }),
    v.object({ outcome: v.literal("reuse") }),
  ),
  handler: async (ctx, args) => {
    const byCurrent = await ctx.db
      .query("sessions")
      .withIndex("by_tokenHash", (q) => q.eq("tokenHash", args.presentedHash))
      .unique();
    let caller = byCurrent;
    if (caller === null) {
      const byPrevious = await ctx.db
        .query("sessions")
        .withIndex("by_prevTokenHash", (q) =>
          q.eq("prevTokenHash", args.presentedHash),
        )
        .unique();
      if (
        byPrevious !== null &&
        !isPreviousTokenWithinReuseWindow({
          rotatedAt: byPrevious.rotatedAt,
          now: args.now,
          reuseWindowMs: args.reuseWindowMs,
        })
      ) {
        // Commit this theft response before the app action raises the terminal
        // error. Throwing inside this mutation would roll the deletion back.
        await ctx.db.delete(byPrevious._id);
        return { outcome: "reuse" as const };
      }
      caller = byPrevious;
    }
    if (!caller) {
      throw terminal(
        "session_not_found",
        "No session for this token — it was signed out or revoked. Sign in again.",
      );
    }

    const sessions = await ctx.db
      .query("sessions")
      .withIndex("by_subject", (q) => q.eq("subject", caller.subject))
      .collect();
    for (const session of sessions) {
      await ctx.db.delete(session._id);
    }
    // Deleting the rows also makes every stored Logto refresh token
    // unreachable. We intentionally avoid an N-request RFC 7009 loop here;
    // those now-unusable grants expire at their own Logto TTL.
    return {
      outcome: "signed-out" as const,
      count: sessions.length,
      subject: caller.subject,
    };
  },
});

/** Kill every session of a subject — webhook revocation (User.Deleted / suspension) and "sign out everywhere". */
export const killSubjectSessions = mutation({
  args: { subject: v.string() },
  returns: v.number(),
  handler: async (ctx, args) => {
    const sessions = await ctx.db
      .query("sessions")
      .withIndex("by_subject", (q) => q.eq("subject", args.subject))
      .collect();
    for (const session of sessions) {
      await ctx.db.delete(session._id);
    }
    // Grants: Logto has already revoked them itself for suspension/deletion
    // (signOutUser); for app-initiated "sign out everywhere" the grants die at
    // their own TTL. Callers needing eager grant revocation can do it per
    // session at sign-out time instead.
    return sessions.length;
  },
});

/** Kill only component sessions mapped to one Logto OP session (`sid`). */
export const killSessionsBySid = mutation({
  args: { sid: v.string() },
  returns: v.number(),
  handler: async (ctx, args) => {
    const sessions = await ctx.db
      .query("sessions")
      .withIndex("by_sid", (q) => q.eq("sid", args.sid))
      .collect();
    for (const session of sessions) {
      await ctx.db.delete(session._id);
    }
    return sessions.length;
  },
});

// --- webhook delivery dedupe -------------------------------------------------

/**
 * Claim a verified Logto delivery by a SHA-256 key (webhook body or issuer+jti).
 * Returns `true` the first time; `false` on a retry whose original 200 was lost.
 */
export const recordWebhookDelivery = mutation({
  args: { bodyHash: v.string(), now: v.number() },
  returns: v.boolean(),
  handler: async (ctx, args) => {
    const existing = await ctx.db
      .query("webhookDeliveries")
      .withIndex("by_bodyHash", (q) => q.eq("bodyHash", args.bodyHash))
      .unique();
    if (existing) return false;
    await ctx.db.insert("webhookDeliveries", {
      bodyHash: args.bodyHash,
      seenAt: args.now,
    });
    return true;
  },
});

/**
 * Release a claimed delivery after processing failed, so Logto's retry isn't
 * deduplicated into a lost event.
 */
export const forgetWebhookDelivery = mutation({
  args: { bodyHash: v.string() },
  returns: v.null(),
  handler: async (ctx, args) => {
    const existing = await ctx.db
      .query("webhookDeliveries")
      .withIndex("by_bodyHash", (q) => q.eq("bodyHash", args.bodyHash))
      .unique();
    if (existing) await ctx.db.delete(existing._id);
    return null;
  },
});

// --- GC ---------------------------------------------------------------------

export const gc = internalMutation({
  args: {},
  returns: v.null(),
  handler: async (ctx) => {
    const now = Date.now();
    const expiredTransactions = await ctx.db
      .query("transactions")
      .withIndex("by_expiresAt", (q) => q.lt("expiresAt", now))
      .take(500);
    for (const t of expiredTransactions) await ctx.db.delete(t._id);
    // Logto's grant chain caps at 180 days; sessions idle longer can never
    // refresh again and are dead rows.
    const deadSessions = await ctx.db
      .query("sessions")
      .withIndex("by_lastRefreshedAt", (q) =>
        q.lt("lastRefreshedAt", now - SESSION_GC_AFTER_MS),
      )
      .take(500);
    for (const s of deadSessions) await ctx.db.delete(s._id);
    const staleDeliveries = await ctx.db
      .query("webhookDeliveries")
      .withIndex("by_seenAt", (q) =>
        q.lt("seenAt", now - WEBHOOK_DELIVERY_GC_AFTER_MS),
      )
      .take(500);
    for (const d of staleDeliveries) await ctx.db.delete(d._id);
    return null;
  },
});
