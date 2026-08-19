import {
  type FunctionReference,
  type GenericDataModel,
  type GenericMutationCtx,
  type HttpRouter,
  type MutationBuilder,
  httpActionGeneric,
  internalMutationGeneric,
} from "convex/server";
import { v } from "convex/values";
import { readBoundedBody } from "./component/http_body.js";
import type { LogtoSessionComponent } from "./session";

/** Subset of Logto's data-mutation User entity carried in webhook payloads. */
export type LogtoUserEntity = {
  id: string;
  username?: string | null;
  primaryEmail?: string | null;
  primaryPhone?: string | null;
  name?: string | null;
  avatar?: string | null;
  customData?: Record<string, unknown>;
  identities?: Record<string, unknown>;
  isSuspended?: boolean;
  lastSignInAt?: number | null;
  createdAt?: number | null;
  applicationId?: string | null;
};

/** The known User.* data-mutation events. */
const LOGTO_USER_EVENTS = [
  "User.Created",
  "User.Data.Updated",
  "User.Deleted",
  "User.SuspensionStatus.Updated",
] as const;

/** Supported Logto User data-mutation events. */
export type LogtoUserEvent = (typeof LOGTO_USER_EVENTS)[number];

/** Shape of a Logto data-mutation webhook delivery (User family). */
export type LogtoWebhookPayload = {
  /**
   * Identifies the webhook **configuration** in Logto, not this delivery —
   * every delivery from the same hook carries the same `hookId`, so it is NOT
   * an idempotency key. Deliveries are deduplicated by raw-body hash instead
   * (the `sessions` option of {@link registerLogtoWebhook}). Optional because
   * nothing here reads it: a delivery is never refused over a field the
   * library does not consume.
   */
  hookId?: string;
  event: LogtoUserEvent;
  /** ISO 8601 creation time of the event — bounds the accepted delivery age. */
  createdAt: string;
  userAgent?: string;
  ip?: string;
  /**
   * The affected User entity, **verbatim as delivered**. Current Logto versions
   * include the pre-deletion entity for `User.Deleted`; older versions and
   * Logto's documented payload shape use `null` and put the deleted id in
   * Management API `params.userId`. A sync handler's second argument is the
   * normalized entity; this one is where the raw value of a field that drifted
   * out of its declared type is still reachable.
   */
  data: LogtoUserEntity | null;
  /** Management API context, present for admin-triggered changes (e.g. deletion). */
  path?: string;
  method?: string;
  status?: number;
  params?: Record<string, unknown>;
  matchedRoute?: string;
  [key: string]: unknown;
};

const encoder = /* @__PURE__ */ new TextEncoder();

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function isNullableString(value: unknown): boolean {
  return value === null || typeof value === "string";
}

function isNullableFiniteNumber(value: unknown): boolean {
  return (
    value === null || (typeof value === "number" && Number.isFinite(value))
  );
}

/**
 * The fields this library never reads, each with the runtime type the published
 * type declares for it.
 *
 * A delivery is never *refused* over one of these. Logto retries a 5xx and not
 * a 4xx, so rejecting a signature-verified delivery turns one drifted field
 * into permanent, first-attempt event loss — and because the same handler
 * revokes sessions for deleted and suspended users, it would silently disable
 * that too. A drifted field is dropped from the entity handed to sync handlers
 * instead, which keeps the declared type honest while the raw value stays
 * reachable on the payload those handlers also receive.
 */
const ADVISORY_PAYLOAD_FIELDS: Record<string, (value: unknown) => boolean> = {
  hookId: (value) => typeof value === "string",
  userAgent: (value) => typeof value === "string",
  ip: (value) => typeof value === "string",
  path: (value) => typeof value === "string",
  method: (value) => typeof value === "string",
  status: (value) => typeof value === "number" && Number.isFinite(value),
  params: isRecord,
  matchedRoute: (value) => typeof value === "string",
};

/** See {@link ADVISORY_PAYLOAD_FIELDS} — the same rule for the User entity. */
const ADVISORY_ENTITY_FIELDS: Record<string, (value: unknown) => boolean> = {
  username: isNullableString,
  primaryEmail: isNullableString,
  primaryPhone: isNullableString,
  name: isNullableString,
  avatar: isNullableString,
  applicationId: isNullableString,
  customData: isRecord,
  identities: isRecord,
  isSuspended: (value) => typeof value === "boolean",
  // `users.last_sign_in_at` is nullable in Logto: a user who has never signed
  // in serialises as `null`.
  lastSignInAt: isNullableFiniteNumber,
  createdAt: isNullableFiniteNumber,
};

/**
 * Copy `raw` without the declared fields whose value drifted out of its type.
 * Fields absent from `declared` — including ones Logto adds later — pass
 * through untouched, and an undrifted payload is returned as-is.
 */
function withoutDriftedFields<Shape extends Record<string, unknown>>(
  raw: Shape,
  declared: Record<string, (value: unknown) => boolean>,
): Shape {
  let pruned: Shape | undefined;
  for (const [field, matchesDeclaredType] of Object.entries(declared)) {
    if (!Object.hasOwn(raw, field)) continue;
    const value = raw[field];
    if (value === undefined || matchesDeclaredType(value)) continue;
    pruned ??= { ...raw };
    delete pruned[field];
  }
  return pruned ?? raw;
}

function isLogtoUserEvent(value: unknown): value is LogtoUserEvent {
  return LOGTO_USER_EVENTS.some((event) => event === value);
}

function toHex(buffer: ArrayBuffer): string {
  let hex = "";
  for (const b of new Uint8Array(buffer))
    hex += b.toString(16).padStart(2, "0");
  return hex;
}

/** Constant-time comparison of two equal-length hex strings. */
function timingSafeEqual(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let mismatch = 0;
  for (let i = 0; i < a.length; i++) {
    mismatch |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }
  return mismatch === 0;
}

/**
 * Verify a Logto `logto-signature-sha-256` header (hex HMAC-SHA256). Prefer the
 * raw request bytes (`BufferSource`), since Logto signs the bytes it sent, not a
 * re-encoded string. Uses Web Crypto so it runs in the Convex (V8) runtime.
 */
export async function verifyLogtoSignature(
  signingKey: string,
  rawBody: string | BufferSource,
  expectedSignature: string,
): Promise<boolean> {
  if (!signingKey || !expectedSignature) return false;
  // Normalize to lowercase, then reject anything that isn't a 64-char hex SHA-256
  // digest, so a malformed header can never be (length-)matched by accident.
  const expected = expectedSignature.trim().toLowerCase();
  if (!/^[0-9a-f]{64}$/.test(expected)) return false;
  const body = typeof rawBody === "string" ? encoder.encode(rawBody) : rawBody;
  const key = await crypto.subtle.importKey(
    "raw",
    encoder.encode(signingKey),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  const signature = await crypto.subtle.sign("HMAC", key, body);
  return timingSafeEqual(toHex(signature), expected);
}

/** The id from the User entity in `data`, when that event carries an entity. */
function entityId(payload: Record<string, unknown>): string | undefined {
  const data = payload.data;
  if (isRecord(data) && typeof data.id === "string") return data.id;
  return undefined;
}

/**
 * Did the entity bring an `id` this library cannot read? Distinct from "no
 * entity": a `User.Deleted` naming no user in `data` is the documented 204
 * shape and the route params are authoritative, but one whose id is present and
 * unreadable could be naming a *different* user than the route params, and a
 * destructive event must not be executed on a guess.
 */
function hasUnreadableEntityId(payload: Record<string, unknown>): boolean {
  const data = payload.data;
  return (
    isRecord(data) && Object.hasOwn(data, "id") && typeof data.id !== "string"
  );
}

/** The deleted user's id from the Management API route params (`DELETE /users/:userId`). */
function paramsUserId(payload: Record<string, unknown>): string | undefined {
  const params = payload.params;
  if (isRecord(params) && typeof params.userId === "string") {
    return params.userId;
  }
  return undefined;
}

/**
 * Accept a delivery on exactly the fields this library consumes: the event it
 * dispatches on, the `createdAt` it bounds the delivery age with, and the user
 * id it revokes sessions by. Everything else is advisory — see
 * {@link ADVISORY_PAYLOAD_FIELDS} for why widening this predicate is how schema
 * drift becomes silent event loss.
 */
function isLogtoWebhookPayload(value: unknown): value is LogtoWebhookPayload {
  if (!isRecord(value)) return false;
  const candidate = value;
  const event = candidate.event;
  // Only accept the known User.* events; an unknown event would otherwise 200
  // silently with no handler, hiding a misconfigured hook.
  if (!isLogtoUserEvent(event)) {
    return false;
  }
  // Read by the replay window below; `isFreshDelivery` parses it.
  if (typeof candidate.createdAt !== "string") return false;
  const dataUserId = entityId(candidate);
  const routeUserId = paramsUserId(candidate);
  // Current Logto versions send the pre-deletion User; older/documented payloads
  // send `data: null` with the id in route params (a 204 delete route serialises
  // no `data` key at all). Accept both, but never accept contradictory ids for a
  // destructive event.
  if (event === "User.Deleted") {
    return (
      !hasUnreadableEntityId(candidate) &&
      (dataUserId !== undefined || routeUserId !== undefined) &&
      (dataUserId === undefined ||
        routeUserId === undefined ||
        dataUserId === routeUserId)
    );
  }
  // Every other event hands a sync handler an entity, so it needs one.
  return dataUserId !== undefined;
}

/**
 * A per-event sync handler. Runs in a Convex mutation, so `ctx.db` is available.
 *
 * `user` is normalized: a field whose type drifted out of the declared
 * {@link LogtoUserEntity} shape is absent rather than surprising, and the raw
 * delivery is still reachable on `payload`. See
 * {@link ADVISORY_PAYLOAD_FIELDS}.
 */
export type LogtoSyncHandler<DataModel extends GenericDataModel> = (
  ctx: GenericMutationCtx<DataModel>,
  user: LogtoUserEntity,
  payload: LogtoWebhookPayload,
) => void | Promise<void>;

export type LogtoSyncHandlers<DataModel extends GenericDataModel> = Partial<
  Record<LogtoUserEvent, LogtoSyncHandler<DataModel>>
>;

/** The internal mutation produced by {@link logtoSync}. */
export type LogtoSyncReference = FunctionReference<
  "mutation",
  "internal",
  { payload: unknown },
  null
>;

/**
 * Define how Logto user events map onto your tables. Returns an internal
 * mutation you export; {@link registerLogtoWebhook} calls it after verifying the
 * signature. Handlers get a mutation `ctx`, so you write to `ctx.db` directly.
 * Pass your generated `DataModel` for a typed `ctx.db`.
 *
 * Sync rows here; don't create them. `User.Created` doesn't fire for users who
 * already existed in Logto, so create rows from an authenticated mutation and let
 * these handlers keep them in sync. See the Webhook sync guide for the ownership
 * rules (which fields the webhook may write, and which are app-owned).
 *
 * @example
 * // convex/logto.ts — keep an existing user's profile in sync (never create here)
 * import { logtoSync } from "convex-logto";
 * import type { DataModel } from "./_generated/dataModel";
 *
 * export const { sync } = logtoSync<DataModel>({
 *   "User.Data.Updated": async (ctx, u) => {
 *     const row = await ctx.db
 *       .query("users")
 *       .withIndex("by_authId", (q) => q.eq("authId", u.id))
 *       .unique();
 *     // Mirror only fields the event carries (present → set, absent → leave).
 *     if (row && u.primaryEmail !== undefined) {
 *       await ctx.db.patch(row._id, { email: u.primaryEmail ?? undefined });
 *     }
 *   },
 * });
 */
export function logtoSync<
  DataModel extends GenericDataModel = GenericDataModel,
>(handlers: LogtoSyncHandlers<DataModel>) {
  const internalMutation: MutationBuilder<DataModel, "internal"> =
    internalMutationGeneric;
  return {
    sync: internalMutation({
      args: { payload: v.any() },
      returns: v.null(),
      handler: async (ctx, args) => {
        // registerLogtoWebhook validates before calling, but this is an exported
        // internal mutation — reject anything that isn't a known User.* event.
        if (!isLogtoWebhookPayload(args.payload)) {
          throw new Error(
            "convex-logto: logtoSync received a payload that isn't a known Logto User.* event.",
          );
        }
        const payload = withoutDriftedFields(
          args.payload,
          ADVISORY_PAYLOAD_FIELDS,
        );
        const handler = handlers[payload.event];
        if (handler) {
          // Current Logto sends the pre-deletion entity; for the older/documented
          // `data: null` shape, synthesize the minimal entity from route params.
          const entity = payload.data;
          let user: LogtoUserEntity;
          if (isRecord(entity) && typeof entity.id === "string") {
            user = withoutDriftedFields(entity, ADVISORY_ENTITY_FIELDS);
          } else {
            const id = paramsUserId(payload);
            if (id === undefined) {
              throw new Error(
                "convex-logto: verified User.Deleted payload has no user id.",
              );
            }
            user = { id };
          }
          await handler(ctx, user, payload);
        }
        return null;
      },
    }),
  };
}

export type RegisterLogtoWebhookOptions = {
  /** HTTP route path. Default `/logto/webhook`. */
  path?: string;
  /** Signing key. Defaults to `LOGTO_WEBHOOK_SIGNING_KEY`. */
  signingKey?: string;
  /**
   * The session component (`components.logto`), if you use
   * [session mode](https://convex-logto-docs.vercel.app/docs/session-mode). Enables:
   *
   * - **exactly-once handling** — deliveries are deduplicated by raw-body
   *   SHA-256, so a Logto retry whose 200 got lost doesn't re-run your sync
   *   handlers;
   * - **session revocation** — `User.Deleted`, and
   *   `User.SuspensionStatus.Updated` with `isSuspended: true`, kill all of
   *   that user's sessions immediately (reactive clients drop live).
   */
  sessions?: LogtoSessionComponent;
};

const SIGNATURE_HEADER = "logto-signature-sha-256";

/**
 * Reject bodies larger than this before doing any crypto or parsing. Real
 * Logto User.* payloads are a few KB; 1 MB is a generous ceiling.
 */
const MAX_BODY_BYTES = 1024 * 1024;

// Freshness bounds on `createdAt`: Logto's own delivery retries land within
// seconds, so minutes of allowance covers them plus clock drift — while a
// captured delivery can't be replayed indefinitely (the signature scheme has
// no timestamp binding of its own).
const MAX_DELIVERY_AGE_MS = 5 * 60 * 1000;
const MAX_DELIVERY_FUTURE_SKEW_MS = 60 * 1000;

/** True when `createdAt` parses and lies within the accepted freshness window. */
function isFreshDelivery(createdAt: unknown, now: number): boolean {
  if (typeof createdAt !== "string") return false;
  const t = Date.parse(createdAt);
  if (Number.isNaN(t)) return false;
  return (
    now - t <= MAX_DELIVERY_AGE_MS && t - now <= MAX_DELIVERY_FUTURE_SKEW_MS
  );
}

/**
 * The subject whose sessions a delivery revokes, if any: a deleted user (id in
 * `data` or, for an older/documented `data: null` deletion, in route params), or a
 * user whose suspension just flipped ON. Un-suspension revokes nothing.
 */
function subjectToRevoke(payload: LogtoWebhookPayload): string | undefined {
  if (payload.event === "User.Deleted") {
    return entityId(payload) ?? paramsUserId(payload);
  }
  if (
    payload.event === "User.SuspensionStatus.Updated" &&
    payload.data?.isSuspended === true
  ) {
    return entityId(payload);
  }
  return undefined;
}

/**
 * Register the Logto webhook route in one line: verify the signature, check
 * freshness, then dispatch to the mutation returned by {@link logtoSync}.
 * Responds 401 on a bad signature, 400 on a malformed/stale body, 413 on an
 * oversized body, 500 if the signing key is unset, else 200.
 *
 * With the `sessions` option (session mode), deliveries are additionally
 * deduplicated by raw-body hash, and user deletion/suspension revokes the
 * user's sessions before your sync handlers run.
 *
 * @example
 * // convex/http.ts
 * import { httpRouter } from "convex/server";
 * import { registerLogtoWebhook } from "convex-logto";
 * import { components, internal } from "./_generated/api";
 *
 * const http = httpRouter();
 * registerLogtoWebhook(http, internal.logto.sync, { sessions: components.logto });
 * export default http;
 */
export function registerLogtoWebhook(
  http: HttpRouter,
  sync: LogtoSyncReference,
  options: RegisterLogtoWebhookOptions = {},
): void {
  const { sessions } = options;
  http.route({
    path: options.path ?? "/logto/webhook",
    method: "POST",
    handler: httpActionGeneric(async (ctx, request) => {
      const signingKey =
        options.signingKey ?? process.env.LOGTO_WEBHOOK_SIGNING_KEY;
      if (!signingKey) {
        return new Response(
          "convex-logto: LOGTO_WEBHOOK_SIGNING_KEY is not set",
          { status: 500 },
        );
      }
      const bodyResult = await readBoundedBody(request, MAX_BODY_BYTES);
      if (!bodyResult.ok && bodyResult.reason === "too_large") {
        return new Response("Payload too large", { status: 413 });
      }
      if (!bodyResult.ok) {
        return new Response("Could not read webhook payload", { status: 400 });
      }
      const rawBody = bodyResult.bytes;
      const signature = request.headers.get(SIGNATURE_HEADER) ?? "";
      if (!(await verifyLogtoSignature(signingKey, rawBody, signature))) {
        return new Response("Invalid Logto webhook signature", { status: 401 });
      }

      let parsed: unknown;
      try {
        parsed = JSON.parse(new TextDecoder().decode(rawBody));
      } catch {
        return new Response("Malformed JSON payload", { status: 400 });
      }
      if (!isLogtoWebhookPayload(parsed)) {
        return new Response("Unexpected webhook payload shape", {
          status: 400,
        });
      }
      // An authentic but old delivery is a replay: the signature scheme has no
      // timestamp binding, so bounded freshness is what retires captured
      // deliveries. (Logto's own retries land within seconds.)
      if (!isFreshDelivery(parsed.createdAt, Date.now())) {
        return new Response("Stale webhook delivery", { status: 400 });
      }

      // Exactly-once: claim the delivery by its raw-body hash. Logto retries a
      // delivery (same signed bytes) when it doesn't see the 200 — without
      // this, a lost 200 would re-run the sync handlers.
      let bodyHash: string | undefined;
      if (sessions) {
        bodyHash = toHex(await crypto.subtle.digest("SHA-256", rawBody));
        const delivery = await ctx.runMutation(
          sessions.lib.recordWebhookDelivery,
          { bodyHash, now: Date.now() },
        );
        // Unlike back-channel logout, this route deliberately answers a claimed
        // delivery without redoing anything, finished or not: an app's sync
        // handlers write to its own tables and are not idempotent, so running
        // them twice is worse than answering slightly early for one still in
        // flight. A delivery whose work failed releases its claim below.
        if (!delivery.claimed) return new Response(null, { status: 200 });
      }

      try {
        // Revocation before sync: a deleted/suspended user's sessions die even
        // if the app's own sync handler goes on to fail.
        const subject = sessions && subjectToRevoke(parsed);
        if (sessions && subject !== undefined) {
          await ctx.runAction(sessions.lib.killSubjectSessions, { subject });
        }
        await ctx.runMutation(sync, { payload: parsed });
      } catch (error) {
        // Release the dedupe claim so Logto's retry re-runs the failed work
        // instead of being swallowed as a duplicate.
        if (sessions && bodyHash !== undefined) {
          await ctx
            .runMutation(sessions.lib.forgetWebhookDelivery, { bodyHash })
            .catch(() => {});
        }
        throw error;
      }
      return new Response(null, { status: 200 });
    }),
  });
}
