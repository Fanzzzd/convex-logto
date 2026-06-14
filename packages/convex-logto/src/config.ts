import { type FunctionReference, queryGeneric } from "convex/server";
import { v } from "convex/values";

export type LogtoAuthConfigOptions = {
  /** Logto endpoint, e.g. `https://auth.example.com`. Defaults to `LOGTO_ENDPOINT`. */
  endpoint?: string;
  /** Logto SPA application App ID (the ID token's `aud`). Defaults to `LOGTO_APP_ID`. */
  appId?: string;
};

export type LogtoOidcProvider = {
  domain: string;
  applicationID: string;
};

function readEndpointAndAppId(options: LogtoAuthConfigOptions = {}): {
  endpoint: string;
  appId: string;
} {
  // Trim stray whitespace and drop trailing slashes so the endpoint normalizes
  // to a single canonical form (e.g. `https://auth.example.com`), regardless of
  // how the env var was pasted.
  const endpoint = (options.endpoint ?? process.env.LOGTO_ENDPOINT)
    ?.trim()
    .replace(/\/+$/, "");
  const appId = (options.appId ?? process.env.LOGTO_APP_ID)?.trim();
  if (!endpoint || !appId) {
    const missing = [!endpoint && "LOGTO_ENDPOINT", !appId && "LOGTO_APP_ID"]
      .filter(Boolean)
      .join(" and ");
    throw new Error(
      `convex-logto: missing ${missing}. Set it on your Convex deployment ` +
        `(\`npx convex env set LOGTO_ENDPOINT https://auth.example.com\`) ` +
        `or pass it to this function.`,
    );
  }
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
    domain: `${endpoint}/oidc`,
    applicationID: appId,
  };
}

/** Public, non-secret Logto config the frontend needs to start sign-in. */
export type LogtoPublicConfig = {
  endpoint: string;
  appId: string;
};

/** Reference to the query produced by {@link logtoConfigQuery}. */
export type LogtoConfigQueryRef = FunctionReference<
  "query",
  "public",
  Record<string, never>,
  LogtoPublicConfig
>;

/**
 * A public Convex query that serves `{ endpoint, appId }` from this deployment's
 * env, so the frontend can fetch its Logto config instead of carrying its own
 * copy. Configure Logto in one place per environment — the Convex deployment.
 *
 * @example
 * // convex/logto.ts
 * import { logtoConfigQuery } from "convex-logto";
 * export const config = logtoConfigQuery();
 */
export function logtoConfigQuery() {
  return queryGeneric({
    args: {},
    returns: v.object({ endpoint: v.string(), appId: v.string() }),
    handler: (): LogtoPublicConfig => readEndpointAndAppId(),
  });
}
