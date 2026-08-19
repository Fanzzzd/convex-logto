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

const sessionSummaryValidator = v.object({
  sessionId: v.string(),
  current: v.boolean(),
  createdAt: v.number(),
  lastRefreshedAt: v.number(),
  label: v.optional(v.string()),
  client: v.optional(
    v.object({
      platform: v.optional(v.string()),
      os: v.optional(v.string()),
      browser: v.optional(v.string()),
    }),
  ),
  deviceBound: v.boolean(),
});

// --- component reference typing ---------------------------------------------

/** Public half of the browser's non-extractable ECDSA P-256 binding key. */
export type LogtoSessionDevicePublicKey = {
  kty: "EC";
  crv: "P-256";
  x: string;
  y: string;
};

/**
 * Coarse, self-reported client description. Advisory display data only — it is
 * never authenticated and must never drive a security decision.
 */
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
        label?: string;
        client?: LogtoSessionClientDescriptor;
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
    listSessions: FunctionReference<
      "action",
      "internal",
      {
        sessionToken: string;
        deviceProof?: string;
        now: number;
        reuseWindowMs: number;
      },
      { sessions: LogtoSessionSummary[]; truncated: boolean }
    >;
    renameSession: FunctionReference<
      "action",
      "internal",
      {
        sessionToken: string;
        deviceProof?: string;
        targetSessionId: string;
        label?: string;
        now: number;
        reuseWindowMs: number;
      },
      boolean
    >;
    revokeSession: FunctionReference<
      "action",
      "internal",
      {
        sessionToken: string;
        deviceProof?: string;
        targetSessionId: string;
        now: number;
        reuseWindowMs: number;
      },
      boolean
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
/** Coarse, self-reported description of a signing-in client. */
export type LogtoSessionClientDescriptor = {
  platform?: string;
  os?: string;
  browser?: string;
};

/** One of the caller's sessions, as returned by `listSessions`. */
export type LogtoSessionSummary = {
  sessionId: string;
  /** True for the session whose token authenticated the call. */
  current: boolean;
  createdAt: number;
  lastRefreshedAt: number;
  label?: string;
  client?: LogtoSessionClientDescriptor;
  /** Whether this session requires a device proof to refresh or sign out. */
  deviceBound: boolean;
};

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
      client?: LogtoSessionClientDescriptor;
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
  /**
   * Optional for the same rolling-upgrade reason as `signOutEverywhere`: a
   * provider on a newer library must keep working against an app module that
   * has not re-exported these yet.
   */
  listSessions?: FunctionReference<
    "action",
    "public",
    { sessionToken: string; deviceProof?: string },
    { sessions: LogtoSessionSummary[]; truncated: boolean }
  >;
  renameSession?: FunctionReference<
    "action",
    "public",
    {
      sessionToken: string;
      deviceProof?: string;
      targetSessionId: string;
      label?: string;
    },
    boolean
  >;
  revokeSession?: FunctionReference<
    "action",
    "public",
    { sessionToken: string; deviceProof?: string; targetSessionId: string },
    boolean
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
 * nine — the frontend provider looks them up by these exact names, and a
 * missing one disables that feature rather than failing the build:
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
 *   listSessions,
 *   renameSession,
 *   revokeSession,
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
      client?: LogtoSessionClientDescriptor;
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
  listSessions: RegisteredAction<
    "public",
    { sessionToken: string; deviceProof?: string },
    Promise<{ sessions: LogtoSessionSummary[]; truncated: boolean }>
  >;
  renameSession: RegisteredAction<
    "public",
    {
      sessionToken: string;
      deviceProof?: string;
      targetSessionId: string;
      label?: string;
    },
    Promise<boolean>
  >;
  revokeSession: RegisteredAction<
    "public",
    { sessionToken: string; deviceProof?: string; targetSessionId: string },
    Promise<boolean>
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
        client: v.optional(clientDescriptorValidator),
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
          client: args.client,
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
    listSessions: actionGeneric({
      args: {
        sessionToken: v.string(),
        deviceProof: v.optional(v.string()),
      },
      returns: v.object({
        sessions: v.array(sessionSummaryValidator),
        truncated: v.boolean(),
      }),
      handler: async (ctx, args) => {
        return await ctx.runAction(component.lib.listSessions, {
          sessionToken: args.sessionToken,
          deviceProof: args.deviceProof,
          now: Date.now(),
          reuseWindowMs: options.reuseWindowMs ?? DEFAULT_REUSE_WINDOW_MS,
        });
      },
    }),
    renameSession: actionGeneric({
      args: {
        sessionToken: v.string(),
        deviceProof: v.optional(v.string()),
        targetSessionId: v.string(),
        label: v.optional(v.string()),
      },
      returns: v.boolean(),
      handler: async (ctx, args) => {
        return await ctx.runAction(component.lib.renameSession, {
          sessionToken: args.sessionToken,
          deviceProof: args.deviceProof,
          targetSessionId: args.targetSessionId,
          label: args.label,
          now: Date.now(),
          reuseWindowMs: options.reuseWindowMs ?? DEFAULT_REUSE_WINDOW_MS,
        });
      },
    }),
    revokeSession: actionGeneric({
      args: {
        sessionToken: v.string(),
        deviceProof: v.optional(v.string()),
        targetSessionId: v.string(),
      },
      returns: v.boolean(),
      handler: async (ctx, args) => {
        return await ctx.runAction(component.lib.revokeSession, {
          sessionToken: args.sessionToken,
          deviceProof: args.deviceProof,
          targetSessionId: args.targetSessionId,
          now: Date.now(),
          reuseWindowMs: options.reuseWindowMs ?? DEFAULT_REUSE_WINDOW_MS,
        });
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
