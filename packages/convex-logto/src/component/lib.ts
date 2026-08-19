import type { GenericActionCtx } from "convex/server";
import { ConvexError, v } from "convex/values";
import {
  action,
  type DatabaseReader,
  type DatabaseWriter,
  internalMutation,
  internalQuery,
  mutation,
  query,
} from "./_generated/server.js";
import { internal } from "./_generated/api.js";
import type { DataModel, Doc, Id } from "./_generated/dataModel.js";
import {
  DEFAULT_REUSE_WINDOW_MS,
  SESSION_GC_AFTER_MS,
  SESSION_TOKEN_GENERATION_LIMIT,
  TRANSACTION_TTL_MS,
  WEBHOOK_DELIVERY_GC_AFTER_MS,
  asDeploymentFault,
  assertDeviceProof,
  buildAuthorizeUrl,
  buildEndSessionUrl,
  classifyTokenEndpointFailure,
  decideRefresh,
  decodeIdToken,
  generatePkce,
  generateToken,
  normalizeSignInTargets,
  hashToken,
  SESSION_LIST_LIMIT,
  SESSION_LIST_SCAN_BYTES,
  SESSION_LIST_SCAN_LIMIT,
  isOutcomeUnknownError,
  isPreviousTokenWithinReuseWindow,
  normalizeClientDescriptor,
  normalizeSessionLabel,
  outcomeUnknown,
  rotateTokenHashes,
  sessionReadCost,
  sessionReuseDetectedError,
  terminal,
  transient,
  type DevicePublicKey,
} from "./core.js";
import { buildLogtoEndpointUrl } from "./endpoint.js";
import { readBoundedBody } from "./http_body.js";

// The confidential-client config every OIDC-touching call needs. The values are
// read from the APP's env by the `logtoSessionApi()` wrappers and passed in as
// arguments (components can't read the app's process.env) — the workos-authkit
// pattern. The secret crosses the component boundary as an argument only.
const oidcArgs = {
  endpoint: v.string(),
  appId: v.string(),
  clientSecret: v.string(),
};

const TOKEN_ENDPOINT_TIMEOUT_MS = 10 * 1000;
const MAX_TOKEN_RESPONSE_BYTES = 256 * 1024;
const tokenResponseDecoder = /* @__PURE__ */ new TextDecoder("utf-8", {
  fatal: true,
});

const clientDescriptorValidator = v.object({
  platform: v.optional(v.string()),
  os: v.optional(v.string()),
  browser: v.optional(v.string()),
});

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
  | { outcome: "reuse" | "claim-expired" };
type CompleteRefreshResult = {
  outcome: "committed" | "missing" | "stale-owner" | "revoked";
};

type RevocationBatchResult = { deleted: number; done: boolean };
type RevocationTarget =
  | { kind: "subject"; value: string }
  | { kind: "sid"; value: string };
type SubjectRevocationStart =
  | {
      outcome: "signed-out";
      subject: string;
      callerSessionId: string;
      revokedAt: number;
    }
  | { outcome: "reuse" };
type SignOutConsumptionResult =
  | { outcome: "taken" | "reuse" }
  | { outcome: "not-found" };

// A session document may be as large as Convex's 1 MiB document limit.
// Ordinary batches delete eight aggregate roots; a batch takes two extra rows to
// see whether more remain, and the authenticated final batch also reads its
// separately preserved caller — eleven session documents at worst. That plus
// their tiny, bounded generation rows stays below the 16 MiB transaction limits.
export const REVOCATION_BATCH_SIZE = 8;
const MAX_REVOCATION_BATCHES = 512;
// Transactions contain caller-provided redirect URLs and, like sessions, can
// approach Convex's 1 MiB document limit. GC processes both in one mutation,
// so reserve four of the 16 MiB read/write budget for transaction documents.
const GC_TRANSACTION_BATCH_SIZE = 4;
const GC_SMALL_DOCUMENT_BATCH_SIZE = 500;

type SessionTokenMatch =
  | { source: "current"; session: Doc<"sessions"> }
  | {
      source: "generation";
      session: Doc<"sessions">;
      rotatedAt: number;
      expiresAt: number;
    }
  | {
      source: "legacy";
      session: Doc<"sessions">;
      rotatedAt?: number;
    };

/** Resolve current, indexed recent, then legacy previous token generations. */
async function resolveSessionToken(
  db: DatabaseReader,
  tokenHash: string,
): Promise<SessionTokenMatch | null> {
  const current = await db
    .query("sessions")
    .withIndex("by_tokenHash", (q) => q.eq("tokenHash", tokenHash))
    .unique();
  if (current) return { source: "current", session: current };

  const generation = await db
    .query("sessionTokenGenerations")
    .withIndex("by_tokenHash", (q) => q.eq("tokenHash", tokenHash))
    .unique();
  if (generation) {
    const session = await db.get(generation.sessionId);
    if (session) {
      return {
        source: "generation",
        session,
        rotatedAt: generation.rotatedAt,
        expiresAt: generation.expiresAt,
      };
    }
  }

  const legacy = await db
    .query("sessions")
    .withIndex("by_prevTokenHash", (q) => q.eq("prevTokenHash", tokenHash))
    .unique();
  return legacy
    ? { source: "legacy", session: legacy, rotatedAt: legacy.rotatedAt }
    : null;
}

function tokenMatchIsWithinReuseWindow(
  match: SessionTokenMatch,
  now: number,
  reuseWindowMs: number,
): boolean {
  if (match.source === "current") return true;
  if (match.source === "generation") return now < match.expiresAt;
  return isPreviousTokenWithinReuseWindow({
    rotatedAt: match.rotatedAt,
    now,
    reuseWindowMs,
  });
}

/**
 * Retain the superseded current token behind one indexed, bounded seam. The
 * newest generation is inserted after old/expired rows are pruned, so the
 * table can never exceed the documented per-session limit.
 */
async function rememberSupersededToken(
  db: DatabaseWriter,
  session: Doc<"sessions">,
  now: number,
  reuseWindowMs: number,
): Promise<void> {
  const generations = await db
    .query("sessionTokenGenerations")
    .withIndex("by_sessionId_rotatedAt", (q) => q.eq("sessionId", session._id))
    .order("desc")
    .collect();
  let retained = 0;
  for (const generation of generations) {
    if (
      generation.expiresAt <= now ||
      retained >= SESSION_TOKEN_GENERATION_LIMIT - 1
    ) {
      await db.delete(generation._id);
    } else {
      retained += 1;
    }
  }
  if (reuseWindowMs > 0) {
    await db.insert("sessionTokenGenerations", {
      sessionId: session._id,
      tokenHash: session.tokenHash,
      rotatedAt: now,
      expiresAt: now + reuseWindowMs,
    });
  }
}

/** Delete the aggregate root and every token generation in one transaction. */
async function deleteSessionWithGenerations(
  db: DatabaseWriter,
  sessionId: Id<"sessions">,
): Promise<void> {
  const generations = await db
    .query("sessionTokenGenerations")
    .withIndex("by_sessionId_rotatedAt", (q) => q.eq("sessionId", sessionId))
    .collect();
  for (const generation of generations) await db.delete(generation._id);
  await db.delete(sessionId);
}

async function subjectRevokedAt(
  db: DatabaseReader,
  subject: string,
): Promise<number | undefined> {
  const marker = await db
    .query("subjectRevocations")
    .withIndex("by_subject", (q) => q.eq("subject", subject))
    .unique();
  return marker?.revokedAt;
}

async function sidRevokedAt(
  db: DatabaseReader,
  sid: string | undefined,
): Promise<number | undefined> {
  if (sid === undefined) return undefined;
  const marker = await db
    .query("sidRevocations")
    .withIndex("by_sid", (q) => q.eq("sid", sid))
    .unique();
  return marker?.revokedAt;
}

async function sessionIsLogicallyRevoked(
  db: DatabaseReader,
  session: Pick<Doc<"sessions">, "subject" | "sid" | "createdAt">,
): Promise<boolean> {
  const subjectCutoff = await subjectRevokedAt(db, session.subject);
  if (subjectCutoff !== undefined && session.createdAt <= subjectCutoff) {
    return true;
  }
  const sidCutoff = await sidRevokedAt(db, session.sid);
  return sidCutoff !== undefined && session.createdAt <= sidCutoff;
}

async function markSubjectRevoked(
  db: DatabaseWriter,
  subject: string,
  now: number,
): Promise<number> {
  const marker = await db
    .query("subjectRevocations")
    .withIndex("by_subject", (q) => q.eq("subject", subject))
    .unique();
  const newestSession = await db
    .query("sessions")
    .withIndex("by_subject_createdAt", (q) => q.eq("subject", subject))
    .order("desc")
    .first();
  const revokedAt = Math.max(
    now,
    marker?.revokedAt ?? now,
    newestSession?.createdAt ?? now,
  );
  if (marker) {
    if (marker.revokedAt !== revokedAt) {
      await db.patch(marker._id, { revokedAt });
    }
  } else {
    await db.insert("subjectRevocations", { subject, revokedAt });
  }
  return revokedAt;
}

async function markSidRevoked(
  db: DatabaseWriter,
  sid: string,
  now: number,
): Promise<number> {
  const marker = await db
    .query("sidRevocations")
    .withIndex("by_sid", (q) => q.eq("sid", sid))
    .unique();
  const newestSession = await db
    .query("sessions")
    .withIndex("by_sid_createdAt", (q) => q.eq("sid", sid))
    .order("desc")
    .first();
  const revokedAt = Math.max(
    now,
    marker?.revokedAt ?? now,
    newestSession?.createdAt ?? now,
  );
  if (marker) {
    if (marker.revokedAt !== revokedAt) {
      await db.patch(marker._id, { revokedAt });
    }
  } else {
    await db.insert("sidRevocations", { sid, revokedAt });
  }
  return revokedAt;
}

async function drainRevocationBatches(
  deleteNext: () => Promise<RevocationBatchResult>,
): Promise<number> {
  let deleted = 0;
  for (let batch = 0; batch < MAX_REVOCATION_BATCHES; batch += 1) {
    const result = await deleteNext();
    deleted += result.deleted;
    if (result.done) return deleted;
  }
  throw transient(
    "revocation_cleanup_incomplete",
    `Revocation is active and ${deleted} sessions were removed, but cleanup exceeded one action's bounded work budget. Retry to continue.`,
  );
}

async function deleteRevokedSessionsBatch(
  db: DatabaseWriter,
  target: RevocationTarget,
  revokedAt: number,
): Promise<RevocationBatchResult> {
  // Keep each concrete query explicit so Convex preserves the relationship
  // between its index and indexed field in the generated database types.
  const sessions =
    target.kind === "subject"
      ? await db
          .query("sessions")
          .withIndex("by_subject_createdAt", (q) =>
            q.eq("subject", target.value).lte("createdAt", revokedAt),
          )
          .take(REVOCATION_BATCH_SIZE + 1)
      : await db
          .query("sessions")
          .withIndex("by_sid_createdAt", (q) =>
            q.eq("sid", target.value).lte("createdAt", revokedAt),
          )
          .take(REVOCATION_BATCH_SIZE + 1);
  const batch = sessions.slice(0, REVOCATION_BATCH_SIZE);
  for (const session of batch) {
    await deleteSessionWithGenerations(db, session._id);
  }
  return {
    deleted: batch.length,
    done: sessions.length <= REVOCATION_BATCH_SIZE,
  };
}

function isTerminalSessionError(error: unknown): boolean {
  if (!(error instanceof ConvexError)) return false;
  const data: unknown = error.data;
  return (
    typeof data === "object" &&
    data !== null &&
    "kind" in data &&
    data.kind === "terminal"
  );
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function basicAuth(config: OidcConfig): string {
  return `Basic ${btoa(`${config.appId}:${config.clientSecret}`)}`;
}

/**
 * POST to Logto's token endpoint; classify failures terminal vs transient.
 *
 * A 2xx that does not carry usable tokens is *not* classified here, because the
 * two callers need opposite answers. Sign-in has no session to lose and cannot
 * retry a spent authorization code, so it fails terminally; a refresh has to
 * weigh what Logto may already have done to the grant. Both get the facts —
 * whether the body was a token response at all, and which tokens it held.
 */
async function tokenEndpoint(
  config: OidcConfig,
  params: Record<string, string>,
): Promise<{
  /** False when a 2xx body was not JSON at all — e.g. a proxy or WAF interstitial. */
  tokenResponse: boolean;
  id_token?: string;
  refresh_token?: string;
  access_token?: string;
}> {
  const controller = new AbortController();
  const timeout = setTimeout(() => {
    controller.abort();
  }, TOKEN_ENDPOINT_TIMEOUT_MS);
  try {
    let res: Response;
    try {
      res = await fetch(buildLogtoEndpointUrl(config.endpoint, "token"), {
        method: "POST",
        headers: {
          Authorization: basicAuth(config),
          "Content-Type": "application/x-www-form-urlencoded",
        },
        body: new URLSearchParams(params),
        signal: controller.signal,
      });
    } catch (error) {
      // Our own timeout fired: the request was on the wire, so Logto may have
      // rotated the grant already. Everything else that fails without any
      // response (DNS, connection refused, Logto down) overwhelmingly fails
      // before the grant is processed, and treating those as unknown would
      // force a full reauthentication on every Logto outage.
      if (controller.signal.aborted) {
        throw outcomeUnknown(
          "Logto's token endpoint did not answer in time — the refresh outcome is unknown.",
        );
      }
      throw error;
    }
    const bodyResult = await readBoundedBody(res, MAX_TOKEN_RESPONSE_BYTES);
    if (!bodyResult.ok) {
      if (!res.ok) throw classifyTokenEndpointFailure(res.status, {});
      // A 2xx we could not read means Logto *did* issue (and rotate) tokens.
      throw outcomeUnknown(
        bodyResult.reason === "too_large"
          ? "Logto's token response exceeded the safe size limit — the refresh outcome is unknown."
          : "Could not read the Logto token response — the refresh outcome is unknown.",
      );
    }
    let body: unknown;
    let parsed = true;
    try {
      body = JSON.parse(tokenResponseDecoder.decode(bodyResult.bytes));
    } catch {
      body = {};
      parsed = false;
    }
    const error =
      isRecord(body) && typeof body.error === "string" ? body.error : undefined;
    if (!res.ok) throw classifyTokenEndpointFailure(res.status, { error });
    if (!parsed || !isRecord(body)) return { tokenResponse: false };
    return {
      tokenResponse: true,
      ...(typeof body.id_token === "string" ? { id_token: body.id_token } : {}),
      ...(typeof body.refresh_token === "string"
        ? { refresh_token: body.refresh_token }
        : {}),
      ...(typeof body.access_token === "string"
        ? { access_token: body.access_token }
        : {}),
    };
  } catch (error) {
    if (error instanceof ConvexError) throw error;
    throw transient(
      "logto_unreachable",
      "Could not reach the Logto token endpoint.",
    );
  } finally {
    clearTimeout(timeout);
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
    // `signIn` is unauthenticated by necessity, and both strings are stored for
    // the transaction TTL — bound them before anything is written.
    const targets = normalizeSignInTargets({
      redirectUri: args.redirectUri,
      returnTo: args.returnTo,
    });
    const state = generateToken();
    const { verifier, challenge } = await generatePkce();
    await ctx.runMutation(internal.lib.createTransaction, {
      state,
      codeVerifier: verifier,
      redirectUri: targets.redirectUri,
      returnTo: targets.returnTo,
      expiresAt: Date.now() + TRANSACTION_TTL_MS,
    });
    return {
      url: buildAuthorizeUrl({
        endpoint: args.endpoint,
        appId: args.appId,
        redirectUri: targets.redirectUri,
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
    label: v.optional(v.string()),
    client: v.optional(clientDescriptorValidator),
  },
  returns: v.object({
    idToken: v.string(),
    sessionToken: v.string(),
    sessionId: v.string(),
    returnTo: v.optional(v.string()),
  }),
  handler: async (ctx, args) => {
    // Normalize the display fields before anything is spent: an over-long label
    // rejects here, not after the authorization code has been exchanged for a
    // grant no one would ever hold.
    const label = normalizeSessionLabel(args.label);
    const client = normalizeClientDescriptor(args.client);
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
    if (!tokens.tokenResponse || tokens.id_token === undefined) {
      // Sign-in cannot retry: the authorization code is spent either way, so
      // there is nothing to gain by calling this transient.
      throw terminal(
        "no_id_token",
        tokens.tokenResponse
          ? "Logto's token response carried no id_token — is `openid` scope enabled?"
          : "Logto's token endpoint answered with something that is not a token response.",
      );
    }
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
        label,
        client,
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
    label: v.optional(v.string()),
    client: v.optional(clientDescriptorValidator),
    now: v.number(),
  },
  returns: v.string(),
  handler: async (ctx, args) => {
    const { now, ...session } = args;
    const subjectCutoff = await subjectRevokedAt(ctx.db, args.subject);
    const sidCutoff = await sidRevokedAt(ctx.db, args.sid);
    const createdAt = Math.max(
      now,
      subjectCutoff === undefined ? now : subjectCutoff + 1,
      sidCutoff === undefined ? now : sidCutoff + 1,
    );
    return await ctx.db.insert("sessions", {
      ...session,
      createdAt,
      lastRefreshedAt: createdAt,
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
    const claimId = generateToken();
    const begin: BeginRefreshResult = await ctx.runMutation(
      internal.lib.beginRefresh,
      {
        presentedHash,
        candidateHash: await hashToken(candidate),
        claimId,
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
        // Reuse handling: the session and its server-held refresh token were
        // deleted atomically. Do not RFC 7009-revoke here: Logto may associate
        // sibling component sessions with the same grant.
        throw sessionReuseDetectedError();
      }
      case "claim-expired": {
        // We cannot tell whether the abandoned action reached Logto. Never
        // spend the stored refresh token again. Its row is gone, so the remote
        // token is unreachable and expires naturally without harming siblings.
        throw terminal(
          "refresh_claim_expired",
          "A previous refresh did not finish safely. Sign in again.",
        );
      }
      case "refresh": {
        let tokens: Awaited<ReturnType<typeof tokenEndpoint>>;
        try {
          tokens = await tokenEndpoint(args, {
            grant_type: "refresh_token",
            refresh_token: begin.refreshToken,
          });
        } catch (error) {
          // Releasing the claim makes the stored refresh token spendable again.
          // That is only safe when the failure proves Logto never processed it;
          // otherwise leave the claim in place so the next presentation ages
          // into `claim-expired` instead of re-spending a rotated token.
          if (!isOutcomeUnknownError(error)) {
            await ctx.runMutation(
              isTerminalSessionError(error)
                ? internal.lib.killSession
                : internal.lib.releaseClaim,
              { sessionId: begin.sessionId, claimId },
            );
          }
          throw error;
        }
        if (!tokens.tokenResponse) {
          // A 2xx that is not a token response at all — a proxy or WAF
          // interstitial where JSON was expected. Whether Logto processed (and
          // rotated) the grant is genuinely unknown, exactly like a 2xx we could
          // not read, so the claim is deliberately left to age into
          // `claim-expired` rather than guessing.
          throw outcomeUnknown(
            "Logto's token endpoint answered with something that is not a token response — " +
              "the refresh outcome is unknown.",
          );
        }
        let claims: ReturnType<typeof decodeIdToken>;
        let idToken: string;
        try {
          if (tokens.id_token === undefined) {
            throw terminal(
              "no_id_token",
              "Logto's token response carried no id_token — is `openid` scope enabled?",
            );
          }
          idToken = tokens.id_token;
          claims = decodeIdToken(idToken, args);
        } catch (error) {
          // Logto answered with a well-formed token response, so this is a
          // *deployment* fault — an `iss`/`aud` drift after an endpoint change,
          // a missing `openid` scope — and not a dead session. Deleting the row
          // here is how one wrong env var takes out every session in the
          // deployment, one refresh at a time.
          //
          // The rotation state is *known* here, which is what makes releasing
          // the claim safe: either Logto returned a new refresh token, stored in
          // the same transaction that releases, or it returned none and the
          // stored one is still current. Retaining the claim instead would age
          // into `claim-expired` — and that path deletes the session, so the
          // operator could never recover it by fixing the configuration.
          await ctx.runMutation(internal.lib.abandonRefreshWithRotation, {
            sessionId: begin.sessionId,
            claimId,
            ...(tokens.refresh_token === undefined
              ? {}
              : { refreshToken: tokens.refresh_token }),
          });
          throw asDeploymentFault(error);
        }
        const completed: CompleteRefreshResult = await ctx.runMutation(
          internal.lib.completeRefresh,
          {
            sessionId: begin.sessionId,
            claimId,
            candidateHash: await hashToken(candidate),
            // Logto rotates the confidential-client refresh token only at ≥70%
            // TTL; persist the new one atomically whenever it arrives.
            newRefreshToken: tokens.refresh_token,
            idToken,
            idTokenExp: claims.expiresAtMs,
            sid: claims.sid,
            now: Date.now(),
            reuseWindowMs: args.reuseWindowMs ?? DEFAULT_REUSE_WINDOW_MS,
          },
        );
        if (completed.outcome === "revoked") {
          throw terminal(
            "session_revoked",
            "This session was revoked while refresh was in progress. Sign in again.",
          );
        }
        if (completed.outcome !== "committed") {
          throw terminal(
            "refresh_claim_lost",
            "This refresh no longer owns the session. Sign in again.",
          );
        }
        return {
          idToken,
          sessionToken: candidate,
          sessionId: begin.sessionId,
        };
      }
    }
    throw new Error("Unreachable refresh outcome.");
  },
});

export const devicePublicKeyForToken = internalQuery({
  args: { presentedHash: v.string() },
  returns: v.union(devicePublicKeyValidator, v.null()),
  handler: async (ctx, args) => {
    const match = await resolveSessionToken(ctx.db, args.presentedHash);
    // Return the binding even after logical revocation. A pending cleanup may
    // still delete the aggregate, and that write must not become proofless
    // merely because a subject/sid marker already made the session unusable.
    if (match === null) return null;
    return match.session.devicePublicKey ?? null;
  },
});

export const beginRefresh = internalMutation({
  args: {
    presentedHash: v.string(),
    candidateHash: v.string(),
    claimId: v.string(),
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
    // The session was killed and its server-held refresh token made
    // unreachable. The action must not revoke a possibly shared Logto grant.
    v.object({ outcome: v.literal("reuse") }),
    // A timed-out remote call has an unknown outcome, so its stored refresh
    // token must not be spent by a successor.
    v.object({ outcome: v.literal("claim-expired") }),
  ),
  handler: async (ctx, args) => {
    const match = await resolveSessionToken(ctx.db, args.presentedHash);
    if (!match) {
      throw terminal(
        "session_not_found",
        "No session for this token — it was signed out or revoked. Sign in again.",
      );
    }
    const { session } = match;
    if (await sessionIsLogicallyRevoked(ctx.db, session)) {
      throw terminal(
        "session_revoked",
        "This session has been revoked. Sign in again.",
      );
    }

    const decision = decideRefresh({
      presentedHash: args.presentedHash,
      session,
      now: args.now,
      reuseWindowMs: args.reuseWindowMs,
      presentedTokenExpiresAt:
        match.source === "generation" ? match.expiresAt : undefined,
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
        await deleteSessionWithGenerations(ctx.db, session._id);
        return { outcome: "reuse" as const };
      }
      case "claim-expired": {
        await deleteSessionWithGenerations(ctx.db, session._id);
        return { outcome: "claim-expired" as const };
      }
      case "cached": {
        // Rotate locally while retaining the superseded current generation as
        // the grace token. The presented token may itself be the older grace
        // generation, so retaining it would orphan a concurrent response.
        await rememberSupersededToken(
          ctx.db,
          session,
          args.now,
          args.reuseWindowMs,
        );
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
      case "refresh-superseded": {
        // Claim before the action touches Logto's token endpoint, so a
        // concurrent replay can't double-spend the refresh token at the
        // rotation boundary (Logto has zero reuse tolerance).
        await ctx.db.patch(session._id, {
          refreshingSince: args.now,
          refreshClaimId: args.claimId,
        });
        return {
          outcome: "refresh" as const,
          sessionId: session._id,
          refreshToken: session.logtoRefreshToken,
        };
      }
    }
    throw new Error("Unreachable refresh decision.");
  },
});

export const completeRefresh = internalMutation({
  args: {
    sessionId: v.string(),
    claimId: v.string(),
    candidateHash: v.string(),
    newRefreshToken: v.optional(v.string()),
    idToken: v.string(),
    idTokenExp: v.number(),
    sid: v.optional(v.string()),
    now: v.number(),
    reuseWindowMs: v.number(),
  },
  returns: v.union(
    v.object({ outcome: v.literal("committed") }),
    v.object({ outcome: v.literal("missing") }),
    v.object({ outcome: v.literal("stale-owner") }),
    v.object({ outcome: v.literal("revoked") }),
  ),
  handler: async (ctx, args) => {
    const id = ctx.db.normalizeId("sessions", args.sessionId);
    const session = id && (await ctx.db.get(id));
    if (!session) return { outcome: "missing" as const };
    if (session.refreshClaimId !== args.claimId) {
      return { outcome: "stale-owner" as const };
    }
    const subjectCutoff = await subjectRevokedAt(ctx.db, session.subject);
    if (subjectCutoff !== undefined && session.createdAt <= subjectCutoff) {
      await deleteSessionWithGenerations(ctx.db, session._id);
      return { outcome: "revoked" as const };
    }
    const persistedSidCutoff = await sidRevokedAt(ctx.db, session.sid);
    if (
      persistedSidCutoff !== undefined &&
      session.createdAt <= persistedSidCutoff
    ) {
      await deleteSessionWithGenerations(ctx.db, session._id);
      return { outcome: "revoked" as const };
    }
    const incomingSidCutoff =
      args.sid === session.sid
        ? persistedSidCutoff
        : await sidRevokedAt(ctx.db, args.sid);
    if (
      incomingSidCutoff !== undefined &&
      session.createdAt <= incomingSidCutoff
    ) {
      await deleteSessionWithGenerations(ctx.db, session._id);
      return { outcome: "revoked" as const };
    }
    await rememberSupersededToken(
      ctx.db,
      session,
      args.now,
      args.reuseWindowMs,
    );
    await ctx.db.patch(session._id, {
      // The refresh claim prevents any other rotation before completion, so
      // this is the generation superseded by the candidate even when refresh
      // began by presenting a recently superseded generation.
      ...rotateTokenHashes(session.tokenHash, args.candidateHash),
      rotatedAt: args.now,
      refreshingSince: undefined,
      refreshClaimId: undefined,
      lastIdToken: args.idToken,
      lastIdTokenExp: args.idTokenExp,
      ...(args.sid === undefined ? {} : { sid: args.sid }),
      lastRefreshedAt: args.now,
      ...(args.newRefreshToken
        ? { logtoRefreshToken: args.newRefreshToken }
        : {}),
    });
    return { outcome: "committed" as const };
  },
});

/**
 * Finish a refresh whose response Logto answered but we could not use: store any
 * rotation and release the claim, in **one** transaction.
 *
 * Both halves have to commit together. Persisting the rotation without
 * releasing would leave the row holding a claim that ages into `claim-expired`
 * — which deletes the session this path exists to preserve — and releasing
 * without persisting would leave the next refresh presenting a token Logto has
 * already superseded, tripping reuse detection on a grant sibling sessions
 * share. An action interrupted between two mutations would land in exactly one
 * of those states, so there is only one mutation.
 */
export const abandonRefreshWithRotation = internalMutation({
  args: {
    sessionId: v.string(),
    claimId: v.string(),
    refreshToken: v.optional(v.string()),
  },
  returns: v.boolean(),
  handler: async (ctx, args) => {
    const id = ctx.db.normalizeId("sessions", args.sessionId);
    const session = id && (await ctx.db.get(id));
    // Ownership fencing: a concurrent sign-out or a re-claim means this response
    // is no longer the one the row is waiting for.
    if (!session || session.refreshClaimId !== args.claimId) return false;
    await ctx.db.patch(session._id, {
      refreshingSince: undefined,
      refreshClaimId: undefined,
      ...(args.refreshToken === undefined
        ? {}
        : { logtoRefreshToken: args.refreshToken }),
    });
    return true;
  },
});

export const releaseClaim = internalMutation({
  args: { sessionId: v.string(), claimId: v.string() },
  returns: v.boolean(),
  handler: async (ctx, args) => {
    const id = ctx.db.normalizeId("sessions", args.sessionId);
    const session = id && (await ctx.db.get(id));
    if (!session || session.refreshClaimId !== args.claimId) return false;
    await ctx.db.patch(session._id, {
      refreshingSince: undefined,
      refreshClaimId: undefined,
    });
    return true;
  },
});

export const killSession = internalMutation({
  args: { sessionId: v.string(), claimId: v.string() },
  returns: v.boolean(),
  handler: async (ctx, args) => {
    const id = ctx.db.normalizeId("sessions", args.sessionId);
    const session = id && (await ctx.db.get(id));
    if (!session || session.refreshClaimId !== args.claimId) return false;
    await deleteSessionWithGenerations(ctx.db, session._id);
    return true;
  },
});

// --- sign-out ---------------------------------------------------------------

export const signOut = action({
  args: {
    ...oidcArgs,
    sessionToken: v.string(),
    deviceProof: v.optional(v.string()),
    postLogoutRedirectUri: v.optional(v.string()),
    federated: v.optional(v.boolean()),
    reuseWindowMs: v.optional(v.number()),
  },
  returns: v.object({ endSessionUrl: v.optional(v.string()) }),
  handler: async (ctx, args) => {
    const tokenHash = await hashToken(args.sessionToken);
    const devicePublicKey: DevicePublicKey | null = await ctx.runQuery(
      internal.lib.devicePublicKeyForToken,
      { presentedHash: tokenHash },
    );
    await assertDeviceProof({
      publicKey: devicePublicKey ?? undefined,
      sessionToken: args.sessionToken,
      proof: args.deviceProof,
    });
    const taken: SignOutConsumptionResult = await ctx.runMutation(
      internal.lib.consumeSessionForSignOut,
      {
        tokenHash,
        now: Date.now(),
        reuseWindowMs: args.reuseWindowMs ?? DEFAULT_REUSE_WINDOW_MS,
      },
    );
    if (taken.outcome === "reuse") throw sessionReuseDetectedError();
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

export const consumeSessionForSignOut = internalMutation({
  args: {
    tokenHash: v.string(),
    now: v.number(),
    reuseWindowMs: v.number(),
  },
  returns: v.union(
    v.object({ outcome: v.literal("taken") }),
    v.object({ outcome: v.literal("reuse") }),
    v.object({ outcome: v.literal("not-found") }),
  ),
  handler: async (ctx, args) => {
    const match = await resolveSessionToken(ctx.db, args.tokenHash);
    if (!match) return { outcome: "not-found" as const };
    if (!tokenMatchIsWithinReuseWindow(match, args.now, args.reuseWindowMs)) {
      await deleteSessionWithGenerations(ctx.db, match.session._id);
      return { outcome: "reuse" as const };
    }
    // Sign-out wins over an in-flight refresh. The claim id fences the late
    // action, so it cannot recreate the deleted row or return new credentials.
    await deleteSessionWithGenerations(ctx.db, match.session._id);
    return { outcome: "taken" as const };
  },
});

// --- session liveness -------------------------------------------------------

export const sessionValid = query({
  args: { sessionId: v.string() },
  returns: v.boolean(),
  handler: async (ctx, args) => {
    // Keyed on the stable (non-credential) session id so the browser's
    // subscription survives token rotation; the row deletion pushes `false`
    // to every subscribed tab. Revocation markers make it false atomically,
    // before bounded physical cleanup reaches this particular row.
    const id = ctx.db.normalizeId("sessions", args.sessionId);
    if (!id) return false;
    const session = await ctx.db.get(id);
    return (
      session !== null && !(await sessionIsLogicallyRevoked(ctx.db, session))
    );
  },
});

export const hasActiveSessionForSubject = query({
  args: { subject: v.string() },
  returns: v.boolean(),
  handler: async (ctx, args) => {
    const cutoff = await subjectRevokedAt(ctx.db, args.subject);
    const sessions = await ctx.db
      .query("sessions")
      .withIndex("by_subject_createdAt", (q) =>
        q
          .eq("subject", args.subject)
          .gt("createdAt", cutoff ?? Number.MIN_SAFE_INTEGER),
      )
      .order("desc")
      .take(REVOCATION_BATCH_SIZE + 1);
    // The ninth row is only a sentinel: inspect at most eight potentially
    // 1 MiB sessions, and never claim `false` while unchecked rows remain.
    const sidCutoffs = new Map<string, number | undefined>();
    for (const session of sessions.slice(0, REVOCATION_BATCH_SIZE)) {
      let sidCutoff: number | undefined;
      if (session.sid === undefined) {
        sidCutoff = undefined;
      } else if (sidCutoffs.has(session.sid)) {
        sidCutoff = sidCutoffs.get(session.sid);
      } else {
        sidCutoff = await sidRevokedAt(ctx.db, session.sid);
        sidCutoffs.set(session.sid, sidCutoff);
      }
      if (sidCutoff === undefined || session.createdAt > sidCutoff) return true;
    }
    if (sessions.length > REVOCATION_BATCH_SIZE) {
      throw transient(
        "session_liveness_scan_incomplete",
        "Could not establish subject session liveness within the bounded scan. Retry after revocation cleanup progresses.",
      );
    }
    return false;
  },
});

/**
 * Authenticate with a live session token, derive its subject server-side, and
 * atomically mark every existing session for that subject revoked, then drain
 * the physical rows in bounded transactions. Any bounded recent token
 * generation is accepted so a caller racing multiple rotations keeps the same
 * grace behavior as refresh. Never accept a client-supplied subject here.
 */
export const killSubjectSessionsByToken = action({
  args: {
    sessionToken: v.string(),
    deviceProof: v.optional(v.string()),
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
  handler: async (
    ctx,
    args,
  ): Promise<
    | { outcome: "signed-out"; count: number; subject: string }
    | { outcome: "reuse" }
  > => {
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
    const start: SubjectRevocationStart = await ctx.runMutation(
      internal.lib.beginSubjectRevocationByToken,
      {
        presentedHash,
        now: args.now,
        reuseWindowMs: args.reuseWindowMs,
      },
    );
    if (start.outcome === "reuse") return start;
    const count = await drainRevocationBatches(async () => {
      const result: RevocationBatchResult = await ctx.runMutation(
        internal.lib.deleteSubjectSessionsByTokenBatch,
        {
          subject: start.subject,
          callerSessionId: start.callerSessionId,
          revokedAt: start.revokedAt,
        },
      );
      return result;
    });
    return { outcome: "signed-out", count, subject: start.subject };
  },
});

export const beginSubjectRevocationByToken = internalMutation({
  args: {
    presentedHash: v.string(),
    now: v.number(),
    reuseWindowMs: v.number(),
  },
  returns: v.union(
    v.object({
      outcome: v.literal("signed-out"),
      subject: v.string(),
      callerSessionId: v.string(),
      revokedAt: v.number(),
    }),
    v.object({ outcome: v.literal("reuse") }),
  ),
  handler: async (ctx, args) => {
    const match = await resolveSessionToken(ctx.db, args.presentedHash);
    if (!match) {
      throw terminal(
        "session_not_found",
        "No session for this token — it was signed out or revoked. Sign in again.",
      );
    }
    if (!tokenMatchIsWithinReuseWindow(match, args.now, args.reuseWindowMs)) {
      // Commit this theft response before the app action raises the terminal
      // error. Throwing inside this mutation would roll the deletion back.
      await deleteSessionWithGenerations(ctx.db, match.session._id);
      return { outcome: "reuse" as const };
    }
    const caller = match.session;
    // A row that is logically revoked but not yet physically cleaned up is an
    // expected intermediate state. It must not retain destructive authority:
    // otherwise a dead token could raise the watermark past sessions created
    // after it died and delete them.
    if (await sessionIsLogicallyRevoked(ctx.db, caller)) {
      throw terminal(
        "session_revoked",
        "This session has been revoked. Sign in again.",
      );
    }
    const revokedAt = await markSubjectRevoked(
      ctx.db,
      caller.subject,
      Math.max(args.now, caller.createdAt),
    );
    return {
      outcome: "signed-out" as const,
      subject: caller.subject,
      callerSessionId: caller._id,
      revokedAt,
    };
  },
});

export const deleteSubjectSessionsByTokenBatch = internalMutation({
  args: {
    subject: v.string(),
    callerSessionId: v.string(),
    revokedAt: v.number(),
  },
  returns: v.object({ deleted: v.number(), done: v.boolean() }),
  handler: async (ctx, args) => {
    const rows = await ctx.db
      .query("sessions")
      .withIndex("by_subject_createdAt", (q) =>
        q.eq("subject", args.subject).lte("createdAt", args.revokedAt),
      )
      .take(REVOCATION_BATCH_SIZE + 2);
    const callerId = ctx.db.normalizeId("sessions", args.callerSessionId);
    const otherSessions = rows.filter((session) => session._id !== callerId);
    const batch = otherSessions.slice(0, REVOCATION_BATCH_SIZE);
    const hasMore = otherSessions.length > REVOCATION_BATCH_SIZE;
    for (const session of batch) {
      await deleteSessionWithGenerations(ctx.db, session._id);
    }
    if (hasMore) return { deleted: batch.length, done: false };

    let deleted = batch.length;
    const caller = callerId === null ? null : await ctx.db.get(callerId);
    if (
      caller !== null &&
      caller.subject === args.subject &&
      caller.createdAt <= args.revokedAt
    ) {
      await deleteSessionWithGenerations(ctx.db, caller._id);
      deleted += 1;
    }
    return { deleted, done: true };
  },
});

// --- session management -----------------------------------------------------

type SessionSummary = {
  sessionId: string;
  current: boolean;
  createdAt: number;
  lastRefreshedAt: number;
  label?: string;
  client?: { platform?: string; os?: string; browser?: string };
  deviceBound: boolean;
};

const sessionSummaryValidator = v.object({
  sessionId: v.string(),
  /** True for the session whose token authenticated this call. */
  current: v.boolean(),
  createdAt: v.number(),
  lastRefreshedAt: v.number(),
  label: v.optional(v.string()),
  client: v.optional(clientDescriptorValidator),
  /** Whether this session requires a device proof to refresh or sign out. */
  deviceBound: v.boolean(),
});

/**
 * Resolve a session token to its owner, applying the same authentication rules
 * as the destructive paths: a superseded generation inside the reuse window is
 * accepted, a logically revoked session is not, and a bound session needs its
 * proof. Never accepts a client-supplied subject.
 *
 * Unlike `signOut` and `signOutEverywhere`, presenting a superseded token from
 * outside the window here does not contain the session: this is a query, which
 * cannot write, and the token it rejected already grants nothing. Reuse
 * detection still fires on the first refresh or sign-out that token is used for.
 */
export const resolveCallerSession = internalQuery({
  args: {
    presentedHash: v.string(),
    now: v.number(),
    reuseWindowMs: v.number(),
  },
  returns: v.object({ sessionId: v.string(), subject: v.string() }),
  handler: async (ctx, args) => {
    const match = await resolveSessionToken(ctx.db, args.presentedHash);
    if (
      !match ||
      !tokenMatchIsWithinReuseWindow(match, args.now, args.reuseWindowMs) ||
      (await sessionIsLogicallyRevoked(ctx.db, match.session))
    ) {
      throw terminal(
        "session_not_found",
        "No active session for this token — it was signed out or revoked. Sign in again.",
      );
    }
    return { sessionId: match.session._id, subject: match.session.subject };
  },
});

export const listSubjectSessions = internalQuery({
  args: { subject: v.string(), callerSessionId: v.string() },
  returns: v.object({
    sessions: v.array(sessionSummaryValidator),
    truncated: v.boolean(),
  }),
  handler: async (ctx, args) => {
    const cutoff = await subjectRevokedAt(ctx.db, args.subject);
    // Stream rather than `take(LIMIT + 1)`: sid-revoked rows are dropped after
    // the read, so a fixed page could spend every slot on rows awaiting cleanup
    // and hide the live devices behind them. Scanning is bounded instead.
    const rows = ctx.db
      .query("sessions")
      .withIndex("by_subject_createdAt", (q) =>
        q
          .eq("subject", args.subject)
          .gt("createdAt", cutoff ?? Number.MIN_SAFE_INTEGER),
      )
      .order("desc");
    const sidCutoffs = new Map<string, number | undefined>();
    const sessions: SessionSummary[] = [];
    let scanned = 0;
    let scannedBytes = 0;
    let truncated = false;
    for await (const session of rows) {
      if (
        scanned === SESSION_LIST_SCAN_LIMIT ||
        scannedBytes >= SESSION_LIST_SCAN_BYTES
      ) {
        // Stopped early with rows left: there may be more live sessions, and
        // saying so beats an unbounded scan or a silent omission.
        truncated = true;
        break;
      }
      scanned += 1;
      scannedBytes += sessionReadCost(session);
      let sidCutoff: number | undefined;
      if (session.sid === undefined) {
        sidCutoff = undefined;
      } else if (sidCutoffs.has(session.sid)) {
        sidCutoff = sidCutoffs.get(session.sid);
      } else {
        sidCutoff = await sidRevokedAt(ctx.db, session.sid);
        sidCutoffs.set(session.sid, sidCutoff);
      }
      // A row awaiting bounded cleanup is already dead; it must not appear in a
      // list whose entire purpose is telling the user where they are signed in.
      if (sidCutoff !== undefined && session.createdAt <= sidCutoff) continue;
      if (sessions.length === SESSION_LIST_LIMIT) {
        truncated = true;
        break;
      }
      sessions.push({
        sessionId: session._id,
        current: session._id === args.callerSessionId,
        createdAt: session.createdAt,
        lastRefreshedAt: session.lastRefreshedAt,
        ...(session.label === undefined ? {} : { label: session.label }),
        ...(session.client === undefined ? {} : { client: session.client }),
        deviceBound: session.devicePublicKey !== undefined,
      });
    }
    return { sessions, truncated };
  },
});

export const setSessionLabel = internalMutation({
  args: {
    subject: v.string(),
    targetSessionId: v.string(),
    label: v.optional(v.string()),
  },
  returns: v.boolean(),
  handler: async (ctx, args) => {
    const target = await loadOwnedSession(ctx.db, args);
    await ctx.db.patch(target._id, { label: args.label });
    return true;
  },
});

export const deleteOwnedSession = internalMutation({
  args: { subject: v.string(), targetSessionId: v.string() },
  returns: v.boolean(),
  handler: async (ctx, args) => {
    const target = await loadOwnedSession(ctx.db, args);
    await deleteSessionWithGenerations(ctx.db, target._id);
    return true;
  },
});

/**
 * Load a session the caller's subject owns. The subject is always derived from
 * the caller's own token, so a target id from another user resolves to
 * `session_not_found` rather than leaking that it exists.
 */
async function loadOwnedSession(
  db: DatabaseReader,
  args: { subject: string; targetSessionId: string },
): Promise<Doc<"sessions">> {
  const id = db.normalizeId("sessions", args.targetSessionId);
  const target = id === null ? null : await db.get(id);
  if (
    target === null ||
    target.subject !== args.subject ||
    (await sessionIsLogicallyRevoked(db, target))
  ) {
    throw terminal("session_not_found", "That session no longer exists.");
  }
  return target;
}

/**
 * The caller's own sessions. Authenticated by session token, so the subject is
 * never client-supplied. A snapshot rather than a reactive query: the token
 * rotates roughly every ID-token lifetime, and a subscription keyed on a
 * rotating credential would resubscribe on every rotation.
 */
export const listSessions = action({
  args: {
    sessionToken: v.string(),
    deviceProof: v.optional(v.string()),
    now: v.number(),
    reuseWindowMs: v.number(),
  },
  returns: v.object({
    sessions: v.array(sessionSummaryValidator),
    truncated: v.boolean(),
  }),
  handler: async (
    ctx,
    args,
  ): Promise<{ sessions: SessionSummary[]; truncated: boolean }> => {
    const caller = await authenticateCaller(ctx, args);
    return await ctx.runQuery(internal.lib.listSubjectSessions, {
      subject: caller.subject,
      callerSessionId: caller.sessionId,
    });
  },
});

/** Rename one of the caller's own sessions. */
export const renameSession = action({
  args: {
    sessionToken: v.string(),
    deviceProof: v.optional(v.string()),
    targetSessionId: v.string(),
    label: v.optional(v.string()),
    now: v.number(),
    reuseWindowMs: v.number(),
  },
  returns: v.boolean(),
  handler: async (ctx, args): Promise<boolean> => {
    const caller = await authenticateCaller(ctx, args);
    return await ctx.runMutation(internal.lib.setSessionLabel, {
      subject: caller.subject,
      targetSessionId: args.targetSessionId,
      label: normalizeSessionLabel(args.label),
    });
  },
});

/**
 * Revoke one of the caller's own sessions — the "sign out that other device"
 * operation. The proof requirement applies to the *caller's* session, not the
 * target: requiring the target's key would make it impossible to revoke a lost
 * device, which is the main reason this exists.
 */
export const revokeSession = action({
  args: {
    sessionToken: v.string(),
    deviceProof: v.optional(v.string()),
    targetSessionId: v.string(),
    now: v.number(),
    reuseWindowMs: v.number(),
  },
  returns: v.boolean(),
  handler: async (ctx, args): Promise<boolean> => {
    const caller = await authenticateCaller(ctx, args);
    return await ctx.runMutation(internal.lib.deleteOwnedSession, {
      subject: caller.subject,
      targetSessionId: args.targetSessionId,
    });
  },
});

/** Hash, verify the device proof, and resolve the caller's session and subject. */
async function authenticateCaller(
  ctx: GenericActionCtx<DataModel>,
  args: {
    sessionToken: string;
    deviceProof?: string;
    now: number;
    reuseWindowMs: number;
  },
): Promise<{ sessionId: string; subject: string }> {
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
  return await ctx.runQuery(internal.lib.resolveCallerSession, {
    presentedHash,
    now: args.now,
    reuseWindowMs: args.reuseWindowMs,
  });
}

/** Kill every session of a subject — webhook revocation (User.Deleted / suspension). */
export const killSubjectSessions = action({
  args: { subject: v.string() },
  returns: v.number(),
  handler: async (ctx, args): Promise<number> => {
    const revokedAt: number = await ctx.runMutation(
      internal.lib.beginSubjectRevocation,
      { subject: args.subject, now: Date.now() },
    );
    return await drainRevocationBatches(async () => {
      const result: RevocationBatchResult = await ctx.runMutation(
        internal.lib.deleteSubjectSessionsBatch,
        { subject: args.subject, revokedAt },
      );
      return result;
    });
  },
});

export const beginSubjectRevocation = internalMutation({
  args: { subject: v.string(), now: v.number() },
  returns: v.number(),
  handler: async (ctx, args) => {
    return await markSubjectRevoked(ctx.db, args.subject, args.now);
  },
});

export const deleteSubjectSessionsBatch = internalMutation({
  args: { subject: v.string(), revokedAt: v.number() },
  returns: v.object({ deleted: v.number(), done: v.boolean() }),
  handler: async (ctx, args) => {
    return await deleteRevokedSessionsBatch(
      ctx.db,
      { kind: "subject", value: args.subject },
      args.revokedAt,
    );
  },
});

/** Kill only component sessions mapped to one Logto OP session (`sid`). */
export const killSessionsBySid = action({
  args: { sid: v.string() },
  returns: v.number(),
  handler: async (ctx, args): Promise<number> => {
    const revokedAt: number = await ctx.runMutation(
      internal.lib.beginSidRevocation,
      { sid: args.sid, now: Date.now() },
    );
    return await drainRevocationBatches(async () => {
      const result: RevocationBatchResult = await ctx.runMutation(
        internal.lib.deleteSidSessionsBatch,
        { sid: args.sid, revokedAt },
      );
      return result;
    });
  },
});

export const beginSidRevocation = internalMutation({
  args: { sid: v.string(), now: v.number() },
  returns: v.number(),
  handler: async (ctx, args) => {
    return await markSidRevoked(ctx.db, args.sid, args.now);
  },
});

export const deleteSidSessionsBatch = internalMutation({
  args: { sid: v.string(), revokedAt: v.number() },
  returns: v.object({ deleted: v.number(), done: v.boolean() }),
  handler: async (ctx, args) => {
    return await deleteRevokedSessionsBatch(
      ctx.db,
      { kind: "sid", value: args.sid },
      args.revokedAt,
    );
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
      .take(GC_TRANSACTION_BATCH_SIZE);
    for (const t of expiredTransactions) await ctx.db.delete(t._id);
    // Logto's grant chain caps at 180 days; sessions idle longer can never
    // refresh again and are dead rows.
    const deadSessions = await ctx.db
      .query("sessions")
      .withIndex("by_lastRefreshedAt", (q) =>
        q.lt("lastRefreshedAt", now - SESSION_GC_AFTER_MS),
      )
      .take(REVOCATION_BATCH_SIZE);
    for (const s of deadSessions) {
      await deleteSessionWithGenerations(ctx.db, s._id);
    }
    // Also collect expired orphan generations left by deployments that
    // predate aggregate deletion. Normal writes clean these eagerly.
    const expiredGenerations = await ctx.db
      .query("sessionTokenGenerations")
      .withIndex("by_expiresAt", (q) => q.lt("expiresAt", now))
      .take(GC_SMALL_DOCUMENT_BATCH_SIZE);
    for (const generation of expiredGenerations) {
      await ctx.db.delete(generation._id);
    }
    const staleDeliveries = await ctx.db
      .query("webhookDeliveries")
      .withIndex("by_seenAt", (q) =>
        q.lt("seenAt", now - WEBHOOK_DELIVERY_GC_AFTER_MS),
      )
      .take(GC_SMALL_DOCUMENT_BATCH_SIZE);
    for (const d of staleDeliveries) await ctx.db.delete(d._id);
    // A full batch might have more rows behind it. Continue durably instead of
    // reducing a daily cron to four abandoned sign-ins or eight dead sessions.
    if (
      expiredTransactions.length === GC_TRANSACTION_BATCH_SIZE ||
      deadSessions.length === REVOCATION_BATCH_SIZE ||
      expiredGenerations.length === GC_SMALL_DOCUMENT_BATCH_SIZE ||
      staleDeliveries.length === GC_SMALL_DOCUMENT_BATCH_SIZE
    ) {
      await ctx.scheduler.runAfter(0, internal.lib.gc, {});
    }
    return null;
  },
});
