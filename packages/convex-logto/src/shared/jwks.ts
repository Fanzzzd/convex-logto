// Logto's signing keys: reading a JWKS document, choosing the keys that can
// verify a token, and fetching `${issuer}/jwks` within fixed bounds. One rule
// for back-channel logout, the static-JWKS auth provider, and the sync CLI, so
// the copy a deployment stores is filtered exactly the way a verifier reads it.

import { isRecord } from "./decode";
import { readBoundedBody } from "./http-body";

/** An RSA public signing key as Logto publishes it. */
export type LogtoJwk = {
  kty: "RSA";
  n: string;
  e: string;
  kid?: string;
  alg?: string;
  use?: string;
  key_ops?: string[];
};

/** The RSA signature algorithms this package verifies. */
export type LogtoRsaAlgorithm = "RS256" | "PS256";

/** Logto keeps at most three keys (next, current, previous); this is headroom. */
export const MAX_JWKS_KEYS = 32;
const MAX_JWKS_BODY_BYTES = 256 * 1024;
const JWKS_FETCH_TIMEOUT_MS = 10 * 1000;
const decoder = /* @__PURE__ */ new TextDecoder("utf-8", { fatal: true });

/** A JWKS that cannot be fetched or read. The message is safe to surface. */
export class LogtoJwksError extends Error {}

function readLogtoJwk(value: unknown): LogtoJwk | undefined {
  if (!isRecord(value)) return undefined;
  const { kty, n, e, kid, alg, use, key_ops: keyOps } = value;
  if (
    kty !== "RSA" ||
    typeof n !== "string" ||
    typeof e !== "string" ||
    (kid !== undefined && typeof kid !== "string") ||
    (alg !== undefined && typeof alg !== "string") ||
    (use !== undefined && typeof use !== "string") ||
    (keyOps !== undefined &&
      (!Array.isArray(keyOps) ||
        !keyOps.every((operation) => typeof operation === "string")))
  ) {
    return undefined;
  }
  return {
    kty,
    n,
    e,
    ...(kid === undefined ? {} : { kid }),
    ...(alg === undefined ? {} : { alg }),
    ...(use === undefined ? {} : { use }),
    ...(keyOps === undefined ? {} : { key_ops: keyOps }),
  };
}

/**
 * The RSA keys of a parsed JWKS document. Other key types and malformed
 * entries are skipped rather than rejected: Logto keeps the EC key it rotated
 * away from as the previous key, and one bad entry must not hide a good one.
 * Throws {@link LogtoJwksError} when the value is not a JWKS at all.
 */
export function parseLogtoJwks(value: unknown): LogtoJwk[] {
  if (!isRecord(value) || !Array.isArray(value.keys)) {
    throw new LogtoJwksError("Logto returned a malformed JWKS.");
  }
  if (value.keys.length > MAX_JWKS_KEYS) {
    throw new LogtoJwksError("Logto returned too many JWKS keys.");
  }
  const keys: LogtoJwk[] = [];
  for (const candidate of value.keys) {
    const key = readLogtoJwk(candidate);
    if (key !== undefined) keys.push(key);
  }
  return keys;
}

/**
 * The keys that may verify a signature made with `algorithm`. With a `kid`,
 * only the key it names; without one, every key that permits the algorithm.
 */
export function verificationKeys(
  keys: readonly LogtoJwk[],
  algorithm: LogtoRsaAlgorithm,
  kid?: string,
): LogtoJwk[] {
  return keys.filter(
    (key) =>
      (kid === undefined || key.kid === kid) &&
      (key.alg === undefined || key.alg === algorithm) &&
      (key.use === undefined || key.use === "sig") &&
      (key.key_ops === undefined || key.key_ops.includes("verify")),
  );
}

/**
 * Fetch a Logto JWKS document as parsed JSON, unvalidated. The response is
 * bounded in time and size, so a slow or hostile endpoint cannot hold a Convex
 * action open or exhaust its memory.
 */
export async function fetchJwksDocument(
  url: string,
  fetcher: typeof globalThis.fetch = globalThis.fetch,
): Promise<unknown> {
  const controller = new AbortController();
  const timeout = setTimeout(() => {
    controller.abort();
  }, JWKS_FETCH_TIMEOUT_MS);
  try {
    const response = await fetcher(url, {
      headers: { Accept: "application/json" },
      signal: controller.signal,
    });
    if (!response.ok) {
      throw new LogtoJwksError("Could not fetch the Logto JWKS.");
    }
    const body = await readBoundedBody(response, MAX_JWKS_BODY_BYTES);
    if (!body.ok) throw new LogtoJwksError("Could not read the Logto JWKS.");
    try {
      return JSON.parse(decoder.decode(body.bytes)) as unknown;
    } catch {
      throw new LogtoJwksError("Logto returned a malformed JWKS.");
    }
  } catch (error) {
    if (error instanceof LogtoJwksError) throw error;
    throw new LogtoJwksError("Could not fetch the Logto JWKS.");
  } finally {
    clearTimeout(timeout);
  }
}

/** Fetch a Logto JWKS and return its RSA keys. */
export async function fetchLogtoJwks(
  url: string,
  fetcher?: typeof globalThis.fetch,
): Promise<LogtoJwk[]> {
  return parseLogtoJwks(await fetchJwksDocument(url, fetcher));
}

/** Convex validates a `customJwt` provider's tokens with one fixed algorithm. */
export const STATIC_JWKS_ALGORITHM = "RS256" satisfies LogtoRsaAlgorithm;

/**
 * Read a JWKS stored as JSON text (the `LOGTO_JWKS` deployment variable) and
 * return the keys that can verify Logto's RS256 ID tokens. Throws naming
 * `LOGTO_JWKS` when there is nothing to verify with, because a deployment
 * that pushes with such a copy rejects every sign-in.
 */
export function readStaticJwks(json: string): LogtoJwk[] {
  const fix =
    "Run `npx convex-logto sync-jwks` to copy Logto's current keys into it.";
  if (json.trim() === "") {
    throw new Error(`convex-logto: LOGTO_JWKS is empty. ${fix}`);
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(json) as unknown;
  } catch {
    throw new Error(`convex-logto: LOGTO_JWKS is not valid JSON. ${fix}`);
  }
  let keys: LogtoJwk[];
  try {
    keys = parseLogtoJwks(parsed);
  } catch {
    throw new Error(
      `convex-logto: LOGTO_JWKS is not a JWKS (expected {"keys": [...]}). ${fix}`,
    );
  }
  const usable = verificationKeys(keys, STATIC_JWKS_ALGORITHM);
  if (usable.length === 0) {
    throw new Error(
      "convex-logto: LOGTO_JWKS holds no RSA key that can verify RS256, the only " +
        "algorithm Convex accepts here. Logto signs with an EC key by default: " +
        "rotate its OIDC signing key to RSA in the Logto Console, then run " +
        "`npx convex-logto sync-jwks`.",
    );
  }
  return usable;
}

/** The JWKS document for a set of keys, as the text a deployment stores. */
export function serializeJwks(keys: readonly LogtoJwk[]): string {
  return JSON.stringify({ keys });
}
