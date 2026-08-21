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
import { ORGANIZATIONS_SCOPE } from "./claims";
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
    exchangeToken: FunctionReference<
      "action",
      "internal",
      {
        endpoint: string;
        appId: string;
        clientSecret: string;
        sessionToken: string;
        deviceProof?: string;
        organizationId?: string;
        resource?: string;
        scopes?: string[];
        includeToken?: boolean;
        forceRefresh?: boolean;
        reuseWindowMs?: number;
      },
      {
        claims: LogtoResourceTokenClaims;
        accessToken?: string;
        minted: boolean;
      }
    >;
    fetchUserInfo: FunctionReference<
      "action",
      "internal",
      {
        endpoint: string;
        appId: string;
        clientSecret: string;
        sessionToken: string;
        deviceProof?: string;
        forceRefresh?: boolean;
        reuseWindowMs?: number;
      },
      unknown
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
      { claimed: boolean; completed: boolean }
    >;
    completeWebhookDelivery: FunctionReference<
      "mutation",
      "internal",
      { bodyHash: string; now: number },
      null
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

/** Coarse, self-reported description of a signing-in client. */
export type LogtoSessionClientDescriptor = {
  platform?: string;
  os?: string;
  browser?: string;
};

/**
 * What an Organization or Resource token authorizes, without the token itself.
 *
 * The default custody in session mode: an app checks `scopes` server-side and
 * the credential never enters `window`. `docs/adr/0002-token-custody.md`.
 */
export type LogtoResourceTokenClaims = {
  /** `organization:<id>`, `resource:<indicator>`, or `default`. */
  audience: string;
  /** What Logto granted — which may be narrower than what was asked for. */
  scopes: string[];
  /** Absolute expiry in ms. */
  expiresAt: number;
  organizationId?: string;
  resource?: string;
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

/**
 * The nine public functions {@link logtoSessionApi} registers, as the frontend
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
  /**
   * Optional for the same rolling-upgrade reason as `listSessions`. Absent
   * means the app has not re-exported it; the client surfaces that as a clear
   * error rather than a mystery.
   */
  exchangeToken?: FunctionReference<
    "action",
    "public",
    {
      sessionToken: string;
      deviceProof?: string;
      organizationId?: string;
      resource?: string;
      scopes?: string[];
      includeToken?: boolean;
      forceRefresh?: boolean;
    },
    {
      claims: LogtoResourceTokenClaims;
      accessToken?: string;
      minted: boolean;
    }
  >;
  fetchUserInfo?: FunctionReference<
    "action",
    "public",
    { sessionToken: string; deviceProof?: string; forceRefresh?: boolean },
    unknown
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
  /**
   * API resource indicators appended to the authorize request.
   *
   * Required for `getAccessTokenClaims`: Logto will not issue a Resource token
   * from a grant that never named the resource — it answers `invalid_target` —
   * so the set has to be fixed before the user signs in and cannot be widened
   * in place. Every indicator must be registered in Logto; one that is not
   * breaks sign-in outright.
   *
   * Organization tokens need nothing here.
   */
  resources?: string[];
  /**
   * Let `getOrganizationToken` / `getAccessToken` return the token *string*,
   * not just its claims.
   *
   * Off by default, which is the whole point of session mode: the component
   * mints the token and hands back what it authorizes, so nothing long-lived
   * enters `window`. Turn this on only for a caller that must reach a
   * non-Convex API from the browser, accepting that the token becomes one more
   * thing XSS can steal. `docs/adr/0002-token-custody.md`.
   */
  exposeAccessTokens?: boolean;
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
 * eleven — the frontend provider looks them up by these exact names, and a
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
 *   exchangeToken,
 *   fetchUserInfo,
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
  exchangeToken: RegisteredAction<
    "public",
    {
      sessionToken: string;
      deviceProof?: string;
      organizationId?: string;
      resource?: string;
      scopes?: string[];
      includeToken?: boolean;
    },
    Promise<{
      claims: LogtoResourceTokenClaims;
      accessToken?: string;
      minted: boolean;
    }>
  >;
  fetchUserInfo: RegisteredAction<
    "public",
    { sessionToken: string; deviceProof?: string },
    Promise<unknown>
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
    exchangeToken: actionGeneric({
      args: {
        sessionToken: v.string(),
        deviceProof: v.optional(v.string()),
        organizationId: v.optional(v.string()),
        resource: v.optional(v.string()),
        scopes: v.optional(v.array(v.string())),
        includeToken: v.optional(v.boolean()),
        forceRefresh: v.optional(v.boolean()),
      },
      returns: v.object({
        claims: v.object({
          audience: v.string(),
          scopes: v.array(v.string()),
          expiresAt: v.number(),
          organizationId: v.optional(v.string()),
          resource: v.optional(v.string()),
        }),
        accessToken: v.optional(v.string()),
        minted: v.boolean(),
      }),
      handler: async (ctx, args) => {
        if (args.organizationId === undefined && args.resource === undefined) {
          // The component refuses this too. Refusing here as well keeps the
          // deployment-facing error close to the call and stops a target-free
          // request ever becoming a component round trip.
          throw new ConvexError({
            kind: "terminal" as const,
            code: "missing_token_target",
            message:
              "convex-logto: pass an organizationId or a resource to exchangeToken.",
          });
        }
        if (
          args.organizationId !== undefined &&
          !(options.scopes ?? []).includes(ORGANIZATIONS_SCOPE)
        ) {
          // Logto answers `403 insufficient_scope` for this, and scopes are
          // fixed at authorization time — so no retry, no `forceRefresh` and no
          // amount of waiting can make it succeed for a session that already
          // exists. Refusing here costs the caller nothing; letting it through
          // spends a refresh claim on a request that cannot work.
          throw new ConvexError({
            kind: "terminal" as const,
            code: "organizations_scope_missing",
            message:
              "convex-logto: an organization token needs the " +
              `${ORGANIZATIONS_SCOPE} scope in the grant. Add it to ` +
              "`logtoSessionApi({ scopes })` and sign in again — a grant " +
              "cannot be widened in place. Membership and roles need no token " +
              "at all; they are already in the ID token.",
          });
        }
        if (args.includeToken && !options.exposeAccessTokens) {
          // Refuse rather than silently downgrade to claims. A caller that
          // asked for the token string is about to call an API with it, and
          // `undefined` would surface as an authorization failure somewhere
          // else entirely.
          throw new ConvexError({
            kind: "terminal" as const,
            code: "access_tokens_not_exposed",
            message:
              "convex-logto: this deployment does not expose access tokens. " +
              "Pass `exposeAccessTokens: true` to logtoSessionApi() to allow " +
              "the token string to reach the browser, or use the claims instead.",
          });
        }
        return await ctx.runAction(component.lib.exchangeToken, {
          ...readSessionConfig(options),
          sessionToken: args.sessionToken,
          deviceProof: args.deviceProof,
          organizationId: args.organizationId,
          resource: args.resource,
          scopes: args.scopes,
          includeToken: args.includeToken,
          forceRefresh: args.forceRefresh,
          reuseWindowMs: options.reuseWindowMs,
        });
      },
    }),
    fetchUserInfo: actionGeneric({
      args: {
        sessionToken: v.string(),
        deviceProof: v.optional(v.string()),
        forceRefresh: v.optional(v.boolean()),
      },
      returns: v.any(),
      handler: async (ctx, args) => {
        return await ctx.runAction(component.lib.fetchUserInfo, {
          ...readSessionConfig(options),
          sessionToken: args.sessionToken,
          deviceProof: args.deviceProof,
          forceRefresh: args.forceRefresh,
          reuseWindowMs: options.reuseWindowMs,
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
