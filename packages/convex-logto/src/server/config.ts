import { type FunctionReference, queryGeneric } from "convex/server";
import { v } from "convex/values";
import {
  logtoIssuer,
  normalizeLogtoEndpoint,
  type LogtoEndpointPolicy,
  type LogtoPublicEndpointConfig,
} from "../shared/endpoint";
import {
  STATIC_JWKS_ALGORITHM,
  readStaticJwks,
  serializeJwks,
} from "../shared/jwks";

/** Where the Logto tenant is and which app's ID tokens to accept. */
export type LogtoConnectionOptions = LogtoEndpointPolicy & {
  /** Logto endpoint, e.g. `https://auth.example.com`. Defaults to `LOGTO_ENDPOINT`. */
  endpoint?: string;
  /** Logto application App ID (the ID token's `aud`). Defaults to `LOGTO_APP_ID`. */
  appId?: string;
};

export type LogtoAuthConfigOptions = LogtoConnectionOptions & {
  /**
   * Logto's signing keys as JWKS JSON, usually `process.env.LOGTO_JWKS` as
   * written by `npx convex-logto sync-jwks`. With it, Convex verifies ID tokens
   * against this copy instead of fetching Logto's discovery document and JWKS
   * on every authenticating WebSocket. After rotating keys in Logto, sync every
   * deployment again, or every new sign-in is rejected.
   *
   * Never read by default: Convex refuses to push an `auth.config.ts` that
   * reads an unset variable, so the opt-in is writing this line.
   */
  jwks?: string;
};

/** Discovery mode: Convex fetches Logto's discovery document and JWKS itself. */
export type LogtoOidcProvider = {
  domain: string;
  applicationID: string;
};

/** Static-JWKS mode: the keys travel inside the provider as a data URI. */
export type LogtoStaticJwksProvider = {
  type: "customJwt";
  issuer: string;
  applicationID: string;
  algorithm: typeof STATIC_JWKS_ALGORITHM;
  jwks: string;
};

export type LogtoAuthProvider = LogtoOidcProvider | LogtoStaticJwksProvider;

/** @internal Shared with session.ts and backchannel-logout.ts. Not part of the public API. */
export function readEndpointAndAppId(options: LogtoConnectionOptions = {}): {
  endpoint: string;
  appId: string;
} {
  const rawEndpoint = (options.endpoint ?? process.env.LOGTO_ENDPOINT)?.trim();
  const appId = (options.appId ?? process.env.LOGTO_APP_ID)?.trim();
  if (!rawEndpoint || !appId) {
    const missing = [!rawEndpoint && "LOGTO_ENDPOINT", !appId && "LOGTO_APP_ID"]
      .filter(Boolean)
      .join(" and ");
    throw new Error(
      `convex-logto: missing ${missing}. Set it on your Convex deployment ` +
        `(\`npx convex env set LOGTO_ENDPOINT https://auth.example.com\`) ` +
        `or pass it to this function.`,
    );
  }
  const endpoint = normalizeLogtoEndpoint(rawEndpoint, options);
  return { endpoint, appId };
}

function base64Utf8(text: string): string {
  let binary = "";
  for (const byte of new TextEncoder().encode(text)) {
    binary += String.fromCharCode(byte);
  }
  return btoa(binary);
}

/**
 * Build the Convex auth provider entry for a Logto app. Reads `LOGTO_ENDPOINT`
 * and `LOGTO_APP_ID` unless you pass them. See the README for why this
 * validates the ID token.
 *
 * Without `jwks` it returns an OIDC provider for `${endpoint}/oidc`, and
 * Convex discovers the JWKS and signing algorithm itself. With `jwks` it
 * returns a `customJwt` provider carrying those keys, with the same issuer, so
 * `tokenIdentifier` does not change between the two.
 *
 * @example
 * // convex/auth.config.ts
 * import { logtoAuthConfig } from "convex-logto";
 * export default {
 *   providers: [logtoAuthConfig({ jwks: process.env.LOGTO_JWKS })],
 * };
 */
export function logtoAuthConfig(
  options: LogtoAuthConfigOptions & { jwks: string },
): LogtoStaticJwksProvider;
export function logtoAuthConfig(
  options?: LogtoAuthConfigOptions & { jwks?: undefined },
): LogtoOidcProvider;
export function logtoAuthConfig(
  options?: LogtoAuthConfigOptions,
): LogtoAuthProvider;
export function logtoAuthConfig(
  options: LogtoAuthConfigOptions = {},
): LogtoAuthProvider {
  const { endpoint, appId } = readEndpointAndAppId(options);
  const issuer = logtoIssuer(endpoint);
  if (options.jwks === undefined) {
    return { domain: issuer, applicationID: appId };
  }
  const keys = readStaticJwks(options.jwks);
  return {
    type: "customJwt",
    issuer,
    applicationID: appId,
    algorithm: STATIC_JWKS_ALGORITHM,
    jwks: `data:text/plain;charset=utf-8;base64,${base64Utf8(serializeJwks(keys))}`,
  };
}

/**
 * Public, non-secret Logto config the frontend needs to start sign-in.
 * `allowInsecureHttp` is only for an explicitly accepted, non-loopback
 * self-hosted HTTP deployment; loopback HTTP needs no opt-in.
 */
export type LogtoPublicConfig = LogtoPublicEndpointConfig;

/** Reference to the query produced by {@link logtoConfigQuery}. */
export type LogtoConfigQueryRef = FunctionReference<
  "query",
  "public",
  Record<string, never>,
  LogtoPublicConfig
>;

/**
 * A public Convex query that serves `{ endpoint, appId, allowInsecureHttp? }`
 * from this deployment's env/options, so the frontend can fetch its Logto
 * config instead of carrying its own copy. Configure Logto in one place per
 * environment, the Convex deployment.
 *
 * @example
 * // convex/logto.ts
 * import { logtoConfigQuery } from "convex-logto";
 * export const config = logtoConfigQuery();
 */
export function logtoConfigQuery(options: LogtoConnectionOptions = {}) {
  return queryGeneric({
    args: {},
    returns: v.object({
      endpoint: v.string(),
      appId: v.string(),
      allowInsecureHttp: v.optional(v.boolean()),
    }),
    handler: (): LogtoPublicConfig => ({
      ...readEndpointAndAppId(options),
      ...(options.allowInsecureHttp === true
        ? { allowInsecureHttp: true }
        : {}),
    }),
  });
}
