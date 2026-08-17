import { type FunctionReference, queryGeneric } from "convex/server";
import { v } from "convex/values";
import {
  buildLogtoEndpointUrl,
  normalizeLogtoEndpoint,
  type LogtoEndpointPolicy,
  type LogtoPublicEndpointConfig,
} from "./component/endpoint";

export type LogtoAuthConfigOptions = LogtoEndpointPolicy & {
  /** Logto endpoint, e.g. `https://auth.example.com`. Defaults to `LOGTO_ENDPOINT`. */
  endpoint?: string;
  /** Logto SPA application App ID (the ID token's `aud`). Defaults to `LOGTO_APP_ID`. */
  appId?: string;
};

export type LogtoOidcProvider = {
  domain: string;
  applicationID: string;
};

/** @internal Shared with session.ts — not part of the public API. */
export function readEndpointAndAppId(options: LogtoAuthConfigOptions = {}): {
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

/**
 * Build the Convex auth provider entry for a Logto app. Reads `LOGTO_ENDPOINT`
 * and `LOGTO_APP_ID` unless you pass them. The OIDC `domain` is `${endpoint}/oidc`;
 * Convex discovers the JWKS and signing algorithm from there, so there is no
 * algorithm or JWKS URL to configure. See the README for why the ID token is used.
 *
 * @example
 * // convex/auth.config.ts
 * import { logtoAuthConfig } from "convex-logto";
 * export default { providers: [logtoAuthConfig()] };
 */
export function logtoAuthConfig(
  options: LogtoAuthConfigOptions = {},
): LogtoOidcProvider {
  const { endpoint, appId } = readEndpointAndAppId(options);
  // `endpoint` is already trimmed and trailing-slash-stripped by readEndpointAndAppId.
  return {
    domain: buildLogtoEndpointUrl(endpoint, ""),
    applicationID: appId,
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
 * environment — the Convex deployment.
 *
 * @example
 * // convex/logto.ts
 * import { logtoConfigQuery } from "convex-logto";
 * export const config = logtoConfigQuery();
 */
export function logtoConfigQuery(options: LogtoAuthConfigOptions = {}) {
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
