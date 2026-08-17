import {
  actionGeneric,
  queryGeneric,
  type Auth,
  type FunctionReference,
  type RegisteredAction,
  type RegisteredQuery,
} from "convex/server";
import { ConvexError, v } from "convex/values";
import {
  DEFAULT_REUSE_WINDOW_MS,
  buildEndSessionUrl,
  sessionReuseDetectedError,
} from "./component/core.js";
import type { LogtoEndpointPolicy } from "./component/endpoint.js";
import { readEndpointAndAppId } from "./config";

// --- component reference typing ---------------------------------------------

/** Public half of the browser's non-extractable ECDSA P-256 binding key. */
export type LogtoSessionDevicePublicKey = {
  kty: "EC";
  crv: "P-256";
  x: string;
  y: string;
};

const devicePublicKeyValidator = v.object({
  kty: v.literal("EC"),
  crv: v.literal("P-256"),
  x: v.string(),
  y: v.string(),
});

/**
 * The shape of `components.logto` in an app that installed the session
 * component (`app.use(logto)` in `convex/convex.config.ts`). Hand-written so
 * the app-side wrappers are typed without dragging the component's generated
 * types into the public surface.
 */
export type LogtoSessionComponent = {
  lib: {
    createSignInUrl: FunctionReference<
      "action",
      "internal",
      {
        endpoint: string;
        appId: string;
        redirectUri: string;
        returnTo?: string;
        scopes?: string[];
        resources?: string[];
      },
      { url: string }
    >;
    exchange: FunctionReference<
      "action",
      "internal",
      {
        endpoint: string;
        appId: string;
        clientSecret: string;
        code: string;
        state: string;
        redirectUri: string;
        devicePublicKey?: LogtoSessionDevicePublicKey;
      },
      {
        idToken: string;
        sessionToken: string;
        sessionId: string;
        returnTo?: string;
      }
    >;
    refresh: FunctionReference<
      "action",
      "internal",
      {
        endpoint: string;
        appId: string;
        clientSecret: string;
        sessionToken: string;
        deviceProof?: string;
        reuseWindowMs?: number;
      },
      { idToken: string; sessionToken: string; sessionId: string }
    >;
    signOut: FunctionReference<
      "action",
      "internal",
      {
        endpoint: string;
        appId: string;
        clientSecret: string;
        sessionToken: string;
        deviceProof?: string;
        postLogoutRedirectUri?: string;
        federated?: boolean;
        reuseWindowMs?: number;
      },
      { endSessionUrl?: string }
    >;
    sessionValid: FunctionReference<
      "query",
      "internal",
      { sessionId: string },
      boolean
    >;
    hasActiveSessionForSubject: FunctionReference<
      "query",
      "internal",
      { subject: string },
      boolean
    >;
    killSubjectSessions: FunctionReference<
      "action",
      "internal",
      { subject: string },
      number
    >;
    killSubjectSessionsByToken: FunctionReference<
      "action",
      "internal",
      {
        sessionToken: string;
        deviceProof?: string;
        now: number;
        reuseWindowMs: number;
      },
      | { outcome: "signed-out"; count: number; subject: string }
      | { outcome: "reuse" }
    >;
    killSessionsBySid: FunctionReference<
      "action",
      "internal",
      { sid: string },
      number
    >;
    recordWebhookDelivery: FunctionReference<
      "mutation",
      "internal",
      { bodyHash: string; now: number },
      boolean
    >;
    forgetWebhookDelivery: FunctionReference<
      "mutation",
      "internal",
      { bodyHash: string },
      null
    >;
  };
};

// --- public function surface -------------------------------------------------

/**
 * The six public functions {@link logtoSessionApi} registers, as the frontend
 * sees them. `ConvexLogtoSessionProvider` takes a reference to the module that
 * re-exports them (e.g. `api.auth`).
 */
export type LogtoSessionApi = {
  signIn: FunctionReference<
    "action",
    "public",
    { redirectUri: string; returnTo?: string },
    { url: string }
  >;
  callback: FunctionReference<
    "action",
    "public",
    {
      code: string;
      state: string;
      redirectUri: string;
      devicePublicKey?: LogtoSessionDevicePublicKey;
    },
    {
      idToken: string;
      sessionToken: string;
      sessionId: string;
      returnTo?: string;
    }
  >;
  refresh: FunctionReference<
    "action",
    "public",
    { sessionToken: string; deviceProof?: string },
    { idToken: string; sessionToken: string; sessionId: string }
  >;
  signOut: FunctionReference<
    "action",
    "public",
    {
      sessionToken: string;
      deviceProof?: string;
      postLogoutRedirectUri?: string;
    },
    { endSessionUrl?: string }
  >;
  /**
   * Optional only for rolling upgrades: providers feature-detect an app module
   * that has not re-exported the new action yet and report the exact fix.
   */
  signOutEverywhere?: FunctionReference<
    "action",
    "public",
    {
      sessionToken: string;
      deviceProof?: string;
      postLogoutRedirectUri?: string;
    },
    { endSessionUrl?: string; count: number }
  >;
  sessionValid: FunctionReference<
    "query",
    "public",
    { sessionId: string },
    boolean
  >;
};

export type LogtoSessionApiOptions = LogtoEndpointPolicy & {
  /**
   * Extra OIDC scopes beyond the built-in `openid offline_access profile email`.
   * Server-configured — the browser can't request scopes on its own.
   */
  scopes?: string[];
  /** API resource indicators to request access for (Logto API resources). */
  resources?: string[];
  /**
   * How long (ms) recently superseded Session-token generations stay accepted,
   * absorbing multi-tab races and network retries. Default 10s.
   */
  reuseWindowMs?: number;
  /** Logto endpoint. Defaults to `LOGTO_ENDPOINT`. */
  endpoint?: string;
  /** Traditional Web app ID. Defaults to `LOGTO_APP_ID`. */
  appId?: string;
  /** Traditional Web app secret. Defaults to `LOGTO_CLIENT_SECRET`. */
  clientSecret?: string;
};

function readSessionConfig(options: LogtoSessionApiOptions): {
  endpoint: string;
  appId: string;
  clientSecret: string;
} {
  const { endpoint, appId } = readEndpointAndAppId(options);
  const clientSecret = (
    options.clientSecret ?? process.env.LOGTO_CLIENT_SECRET
  )?.trim();
  if (!clientSecret) {
    throw new Error(
      `convex-logto: missing LOGTO_CLIENT_SECRET. Session mode needs the ` +
        `Traditional Web app's secret — set it on your Convex deployment ` +
        `(\`npx convex env set LOGTO_CLIENT_SECRET ...\`).`,
    );
  }
  return { endpoint, appId, clientSecret };
}

/**
 * Build the public auth functions for session mode, backed by the Logto session
 * component. Reads `LOGTO_ENDPOINT`, `LOGTO_APP_ID` and `LOGTO_CLIENT_SECRET`
 * from the deployment's env (the secret never leaves the server). Re-export all
 * six — the frontend provider expects these exact names:
 *
 * @example
 * // convex/auth.ts
 * import { components } from "./_generated/api";
 * import { logtoSessionApi } from "convex-logto";
 *
 * export const {
 *   signIn,
 *   callback,
 *   refresh,
 *   signOut,
 *   signOutEverywhere,
 *   sessionValid,
 * } = logtoSessionApi(components.logto);
 */
export function logtoSessionApi(
  component: LogtoSessionComponent,
  options: LogtoSessionApiOptions = {},
): {
  signIn: RegisteredAction<
    "public",
    { redirectUri: string; returnTo?: string },
    Promise<{ url: string }>
  >;
  callback: RegisteredAction<
    "public",
    {
      code: string;
      state: string;
      redirectUri: string;
      devicePublicKey?: LogtoSessionDevicePublicKey;
    },
    Promise<{
      idToken: string;
      sessionToken: string;
      sessionId: string;
      returnTo?: string;
    }>
  >;
  refresh: RegisteredAction<
    "public",
    { sessionToken: string; deviceProof?: string },
    Promise<{ idToken: string; sessionToken: string; sessionId: string }>
  >;
  signOut: RegisteredAction<
    "public",
    {
      sessionToken: string;
      deviceProof?: string;
      postLogoutRedirectUri?: string;
    },
    Promise<{ endSessionUrl?: string }>
  >;
  signOutEverywhere: RegisteredAction<
    "public",
    {
      sessionToken: string;
      deviceProof?: string;
      postLogoutRedirectUri?: string;
    },
    Promise<{ endSessionUrl?: string; count: number }>
  >;
  sessionValid: RegisteredQuery<
    "public",
    { sessionId: string },
    Promise<boolean>
  >;
} {
  return {
    signIn: actionGeneric({
      args: { redirectUri: v.string(), returnTo: v.optional(v.string()) },
      returns: v.object({ url: v.string() }),
      handler: async (ctx, args) => {
        const { endpoint, appId } = readSessionConfig(options);
        return await ctx.runAction(component.lib.createSignInUrl, {
          endpoint,
          appId,
          redirectUri: args.redirectUri,
          returnTo: args.returnTo,
          scopes: options.scopes,
          resources: options.resources,
        });
      },
    }),
    callback: actionGeneric({
      args: {
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
        return await ctx.runAction(component.lib.exchange, {
          ...readSessionConfig(options),
          code: args.code,
          state: args.state,
          redirectUri: args.redirectUri,
          devicePublicKey: args.devicePublicKey,
        });
      },
    }),
    refresh: actionGeneric({
      args: {
        sessionToken: v.string(),
        deviceProof: v.optional(v.string()),
      },
      returns: v.object({
        idToken: v.string(),
        sessionToken: v.string(),
        sessionId: v.string(),
      }),
      handler: async (ctx, args) => {
        return await ctx.runAction(component.lib.refresh, {
          ...readSessionConfig(options),
          sessionToken: args.sessionToken,
          deviceProof: args.deviceProof,
          reuseWindowMs: options.reuseWindowMs,
        });
      },
    }),
    signOut: actionGeneric({
      args: {
        sessionToken: v.string(),
        deviceProof: v.optional(v.string()),
        postLogoutRedirectUri: v.optional(v.string()),
      },
      returns: v.object({ endSessionUrl: v.optional(v.string()) }),
      handler: async (ctx, args) => {
        return await ctx.runAction(component.lib.signOut, {
          ...readSessionConfig(options),
          sessionToken: args.sessionToken,
          deviceProof: args.deviceProof,
          postLogoutRedirectUri: args.postLogoutRedirectUri,
          reuseWindowMs: options.reuseWindowMs,
        });
      },
    }),
    signOutEverywhere: actionGeneric({
      args: {
        sessionToken: v.string(),
        deviceProof: v.optional(v.string()),
        postLogoutRedirectUri: v.optional(v.string()),
      },
      returns: v.object({
        endSessionUrl: v.optional(v.string()),
        count: v.number(),
      }),
      handler: async (ctx, args) => {
        const { endpoint, appId } = readSessionConfig(options);
        const result = await ctx.runAction(
          component.lib.killSubjectSessionsByToken,
          {
            sessionToken: args.sessionToken,
            deviceProof: args.deviceProof,
            now: Date.now(),
            reuseWindowMs: options.reuseWindowMs ?? DEFAULT_REUSE_WINDOW_MS,
          },
        );
        if (result.outcome === "reuse") throw sessionReuseDetectedError();
        return {
          count: result.count,
          endSessionUrl: buildEndSessionUrl({
            endpoint,
            appId,
            postLogoutRedirectUri: args.postLogoutRedirectUri,
          }),
        };
      },
    }),
    sessionValid: queryGeneric({
      args: { sessionId: v.string() },
      returns: v.boolean(),
      handler: async (ctx, args) => {
        return await ctx.runQuery(component.lib.sessionValid, {
          sessionId: args.sessionId,
        });
      },
    }),
  };
}

// --- server-side session assertion -------------------------------------------

type SessionCheckCtx = {
  auth: Auth;
  runQuery: (
    reference: LogtoSessionComponent["lib"]["hasActiveSessionForSubject"],
    args: { subject: string },
  ) => Promise<boolean>;
};

/**
 * Subject-level revocation enforcement: throw unless the authenticated
 * identity's subject has at least one active session in the component.
 *
 * This deliberately does not claim that the current ID token came from that
 * session, nor can it bind a bearer to one particular browser session. Use it
 * when subject-wide revocation is the policy boundary. If more than eight
 * candidate Sessions remain while bounded revocation cleanup is still
 * progressing, this throws the transient
 * `session_liveness_scan_incomplete` error instead of guessing.
 *
 * @example
 * export const sensitive = mutation({
 *   handler: async (ctx) => {
 *     await assertSubjectHasActiveSession(ctx, components.logto);
 *     // ...
 *   },
 * });
 */
export async function assertSubjectHasActiveSession(
  ctx: SessionCheckCtx,
  component: LogtoSessionComponent,
): Promise<void> {
  const identity = await ctx.auth.getUserIdentity();
  if (!identity) {
    throw new ConvexError({
      kind: "terminal" as const,
      code: "unauthenticated",
      message: "Not signed in.",
    });
  }
  const active = await ctx.runQuery(component.lib.hasActiveSessionForSubject, {
    subject: identity.subject,
  });
  if (!active) {
    throw new ConvexError({
      kind: "terminal" as const,
      code: "session_revoked",
      message: "No active session remains for this subject. Sign in again.",
    });
  }
}

/**
 * @deprecated Use {@link assertSubjectHasActiveSession}. The old name implied
 * a per-bearer guarantee that an ID token cannot provide.
 */
export const assertUserHasActiveSession = assertSubjectHasActiveSession;
