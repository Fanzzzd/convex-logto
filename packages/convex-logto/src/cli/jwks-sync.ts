// What `sync-jwks` and `check-jwks` do, behind two injected dependencies: the
// deployment's environment variables and `fetch`. The bin wires in the Convex
// CLI; the tests wire in a map.

import {
  buildLogtoEndpointUrl,
  normalizeLogtoEndpoint,
} from "../shared/endpoint";
import {
  LogtoJwksError,
  STATIC_JWKS_ALGORITHM,
  fetchLogtoJwks,
  readStaticJwks,
  serializeJwks,
  verificationKeys,
  type LogtoJwk,
} from "../shared/jwks";

/** A Convex deployment's environment variables. */
export type DeploymentEnv = {
  /** The value, or `undefined` when the variable is not set. */
  get(name: string): Promise<string | undefined>;
  set(name: string, value: string): Promise<void>;
};

export type JwksSyncOptions = {
  env: DeploymentEnv;
  fetch?: typeof globalThis.fetch;
  /** Accept a non-loopback `http:` LOGTO_ENDPOINT. */
  allowInsecureHttp?: boolean;
};

export type SyncJwksResult = {
  jwksUrl: string;
  keys: LogtoJwk[];
  /** False when LOGTO_JWKS already held exactly these keys. */
  changed: boolean;
};

export type CheckJwksResult = {
  jwksUrl: string;
  /** Keys Logto may sign with that LOGTO_JWKS lacks. Non-empty means sign-ins fail. */
  missing: string[];
  /** Keys LOGTO_JWKS holds that Logto no longer serves. Harmless; a sync drops them. */
  stale: string[];
};

/** A failure the CLI reports as one line and exit code 1. */
export class JwksSyncError extends Error {}

/** Convex refuses a single environment variable value above 8 KiB. */
const MAX_ENV_VALUE_BYTES = 8 * 1024;

function keyId(key: LogtoJwk): string {
  return key.kid ?? `n=${key.n.slice(0, 16)}…`;
}

async function liveKeys(
  options: JwksSyncOptions,
): Promise<{ jwksUrl: string; keys: LogtoJwk[] }> {
  const rawEndpoint = (await options.env.get("LOGTO_ENDPOINT"))?.trim();
  if (!rawEndpoint) {
    throw new JwksSyncError(
      "LOGTO_ENDPOINT is not set on this deployment. Set it first: npx convex env set LOGTO_ENDPOINT https://auth.example.com",
    );
  }
  // The keys come from the deployment's own LOGTO_ENDPOINT, so a deployment
  // can never be handed another tenant's keys.
  let jwksUrl: string;
  try {
    jwksUrl = buildLogtoEndpointUrl(
      normalizeLogtoEndpoint(rawEndpoint, options),
      "jwks",
    );
  } catch (error) {
    throw new JwksSyncError(
      `LOGTO_ENDPOINT on this deployment is unusable: ${String(error instanceof Error ? error.message : error)}`,
    );
  }
  let keys: LogtoJwk[];
  try {
    keys = await fetchLogtoJwks(jwksUrl, options.fetch);
  } catch (error) {
    if (!(error instanceof LogtoJwksError)) throw error;
    throw new JwksSyncError(`${error.message} (${jwksUrl})`);
  }
  const usable = verificationKeys(keys, STATIC_JWKS_ALGORITHM);
  if (usable.length === 0) {
    throw new JwksSyncError(
      `Logto serves no RSA key that can verify RS256 (${jwksUrl}). Convex accepts only RS256 for a static JWKS, and Logto signs with an EC key by default. Rotate the OIDC signing key to RSA in the Logto Console, then run this again.`,
    );
  }
  return { jwksUrl, keys: usable };
}

/** Copy Logto's current RS256 keys into the deployment's LOGTO_JWKS. */
export async function syncJwks(
  options: JwksSyncOptions,
): Promise<SyncJwksResult> {
  const { jwksUrl, keys } = await liveKeys(options);
  const value = serializeJwks(keys);
  if (new TextEncoder().encode(value).length > MAX_ENV_VALUE_BYTES) {
    throw new JwksSyncError(
      `Logto's ${keys.length} RS256 keys do not fit in one Convex environment variable (8 KiB). Delete retired keys in the Logto Console, then run this again.`,
    );
  }
  if ((await options.env.get("LOGTO_JWKS")) === value) {
    return { jwksUrl, keys, changed: false };
  }
  await options.env.set("LOGTO_JWKS", value);
  return { jwksUrl, keys, changed: true };
}

/**
 * Compare LOGTO_JWKS with the keys Logto serves now. Every key Logto serves
 * counts, including a staged `next` key that has not signed anything yet,
 * because syncing before it is promoted is what keeps sign-in unbroken.
 */
export async function checkJwks(
  options: JwksSyncOptions,
): Promise<CheckJwksResult> {
  const { jwksUrl, keys } = await liveKeys(options);
  const stored = await options.env.get("LOGTO_JWKS");
  if (stored === undefined) {
    throw new JwksSyncError(
      "LOGTO_JWKS is not set on this deployment. Run: npx convex-logto sync-jwks",
    );
  }
  let storedKeys: LogtoJwk[];
  try {
    storedKeys = readStaticJwks(stored);
  } catch (error) {
    if (!(error instanceof Error)) throw error;
    throw new JwksSyncError(error.message.replace(/^convex-logto: /, ""));
  }
  const live = new Map(keys.map((key) => [key.n, keyId(key)]));
  const kept = new Map(storedKeys.map((key) => [key.n, keyId(key)]));
  return {
    jwksUrl,
    missing: [...live].filter(([n]) => !kept.has(n)).map(([, id]) => id),
    stale: [...kept].filter(([n]) => !live.has(n)).map(([, id]) => id),
  };
}
