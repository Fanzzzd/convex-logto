import {
  type FunctionReference,
  type GenericDataModel,
  type GenericMutationCtx,
  type HttpRouter,
  httpActionGeneric,
  internalMutationGeneric,
} from "convex/server";
import { v } from "convex/values";

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
  lastSignInAt?: number;
  createdAt?: number;
  applicationId?: string | null;
};

/** Logto data-mutation events that carry a User entity. */
export type LogtoUserEvent =
  | "User.Created"
  | "User.Data.Updated"
  | "User.Deleted"
  | "User.SuspensionStatus.Updated";

/** Shape of a Logto data-mutation webhook delivery (User family). */
export type LogtoWebhookPayload = {
  hookId: string;
  event: string;
  createdAt: string;
  userAgent?: string;
  ip?: string;
  data: LogtoUserEntity;
  [key: string]: unknown;
};

const encoder = /* @__PURE__ */ new TextEncoder();

function toHex(buffer: ArrayBuffer): string {
  let hex = "";
  for (const b of new Uint8Array(buffer)) hex += b.toString(16).padStart(2, "0");
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
 * raw request bytes (`ArrayBuffer`), since Logto signs the bytes it sent, not a
 * re-encoded string. Uses Web Crypto so it runs in the Convex (V8) runtime.
 */
export async function verifyLogtoSignature(
  signingKey: string,
  rawBody: string | ArrayBuffer,
  expectedSignature: string,
): Promise<boolean> {
  if (!signingKey || !expectedSignature) return false;
  const body = typeof rawBody === "string" ? encoder.encode(rawBody) : rawBody;
  const key = await crypto.subtle.importKey(
    "raw",
    encoder.encode(signingKey),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  const signature = await crypto.subtle.sign("HMAC", key, body);
  return timingSafeEqual(toHex(signature), expectedSignature.trim().toLowerCase());
}

function isLogtoWebhookPayload(value: unknown): value is LogtoWebhookPayload {
  if (typeof value !== "object" || value === null) return false;
  const { event, data } = value as Record<string, unknown>;
  if (typeof event !== "string") return false;
  // Every User.* data-mutation event carries an entity with a string id;
  // requiring it keeps a malformed body from reaching handlers as `id: undefined`.
  return (
    typeof data === "object" &&
    data !== null &&
    typeof (data as Record<string, unknown>).id === "string"
  );
}

/** A per-event sync handler. Runs in a Convex mutation, so `ctx.db` is available. */
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
  { event: string; payload: unknown },
  null
>;

/**
 * Define how Logto user events map onto your tables. Returns an internal
 * mutation you export; {@link registerLogtoWebhook} calls it after verifying the
 * signature. Handlers get a mutation `ctx`, so you write to `ctx.db` directly.
 * Pass your generated `DataModel` for a typed `ctx.db`.
 *
 * @example
 * // convex/logto.ts
 * import { logtoSync } from "convex-logto";
 * import type { DataModel } from "./_generated/dataModel";
 *
 * export const { sync } = logtoSync<DataModel>({
 *   "User.Created": (ctx, u) =>
 *     ctx.db.insert("users", { authId: u.id, email: u.primaryEmail ?? "" }),
 * });
 */
export function logtoSync<DataModel extends GenericDataModel = GenericDataModel>(
  handlers: LogtoSyncHandlers<DataModel>,
) {
  return {
    sync: internalMutationGeneric({
      args: { event: v.string(), payload: v.any() },
      returns: v.null(),
      handler: async (ctx, args) => {
        const handler = handlers[args.event as LogtoUserEvent];
        if (handler) {
          const payload = args.payload as LogtoWebhookPayload;
          // `ctx` here is typed for the generic data model; the user's handlers
          // are written against their concrete `DataModel`.
          await handler(
            ctx as GenericMutationCtx<DataModel>,
            payload.data,
            payload,
          );
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
};

const SIGNATURE_HEADER = "logto-signature-sha-256";

/**
 * Register the Logto webhook route in one line: verify the signature, then
 * dispatch to the mutation returned by {@link logtoSync}. Responds 401 on a bad
 * signature, 400 on a malformed body, 500 if the signing key is unset, else 200.
 *
 * @example
 * // convex/http.ts
 * import { httpRouter } from "convex/server";
 * import { registerLogtoWebhook } from "convex-logto";
 * import { internal } from "./_generated/api";
 *
 * const http = httpRouter();
 * registerLogtoWebhook(http, internal.logto.sync);
 * export default http;
 */
export function registerLogtoWebhook(
  http: HttpRouter,
  sync: LogtoSyncReference,
  options: RegisterLogtoWebhookOptions = {},
): void {
  http.route({
    path: options.path ?? "/logto/webhook",
    method: "POST",
    handler: httpActionGeneric(async (ctx, request) => {
      const signingKey = options.signingKey ?? process.env.LOGTO_WEBHOOK_SIGNING_KEY;
      if (!signingKey) {
        return new Response(
          "convex-logto: LOGTO_WEBHOOK_SIGNING_KEY is not set",
          { status: 500 },
        );
      }
      const signature = request.headers.get(SIGNATURE_HEADER) ?? "";
      const rawBody = await request.arrayBuffer();
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
        return new Response("Unexpected webhook payload shape", { status: 400 });
      }

      await ctx.runMutation(sync, { event: parsed.event, payload: parsed });
      return new Response(null, { status: 200 });
    }),
  });
}
