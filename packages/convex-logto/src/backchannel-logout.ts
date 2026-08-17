import {
  type HttpRouter,
  type PublicHttpAction,
  httpActionGeneric,
} from "convex/server";
import { readBoundedBody } from "./component/http_body.js";
import { readEndpointAndAppId, type LogtoAuthConfigOptions } from "./config";
import { buildLogtoEndpointUrl } from "./component/endpoint";
import type { LogtoSessionComponent } from "./session";

const encoder = /* @__PURE__ */ new TextEncoder();
const decoder = /* @__PURE__ */ new TextDecoder("utf-8", { fatal: true });

const BACKCHANNEL_LOGOUT_EVENT =
  "http://schemas.openid.net/event/backchannel-logout";
const MAX_BODY_BYTES = 1024 * 1024;
const MAX_TOKEN_AGE_MS = 5 * 60 * 1000;
const MAX_FUTURE_SKEW_MS = 60 * 1000;
const JWKS_CACHE_MS = 5 * 60 * 1000;
const JWKS_MISS_REFRESH_INTERVAL_MS = 60 * 1000;
const JWKS_FETCH_TIMEOUT_MS = 10 * 1000;
const MAX_JWKS_BODY_BYTES = 256 * 1024;
const MAX_JWKS_KEYS = 32;

type SupportedAlgorithm = "RS256" | "PS256";
type LogtoJwk = {
  kty: "RSA";
  n: string;
  e: string;
  kid?: string;
  alg?: string;
  use?: string;
  key_ops?: string[];
};

export type LogtoLogoutTokenClaims = {
  issuer: string;
  subject?: string;
  sid?: string;
  jti: string;
};

export type VerifyLogtoLogoutTokenOptions = LogtoAuthConfigOptions;

export type LogtoBackchannelLogoutHandlerOptions = LogtoAuthConfigOptions & {
  /** The installed session component (`components.logto`). */
  sessions: LogtoSessionComponent;
};

export type RegisterLogtoBackchannelLogoutOptions =
  LogtoBackchannelLogoutHandlerOptions & {
    /** HTTP route path. Default `/logto/backchannel-logout`. */
    path?: string;
  };

class LogoutTokenValidationError extends Error {}

type JwksCacheEntry = {
  expiresAt: number;
  fetchedAt: number;
  promise: Promise<LogtoJwk[]>;
};

type LoadedJwks = {
  keys: LogtoJwk[];
  fromCache: boolean;
  entry: JwksCacheEntry;
};

const jwksCache = new Map<string, JwksCacheEntry>();

function invalid(message: string): never {
  throw new LogoutTokenValidationError(message);
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function decodeBase64Url(value: string): Uint8Array<ArrayBuffer> {
  if (!value || !/^[A-Za-z0-9_-]+$/.test(value) || value.length % 4 === 1) {
    return invalid("Malformed JWT encoding.");
  }
  try {
    const base64 = value.replace(/-/g, "+").replace(/_/g, "/");
    const binary = atob(base64.padEnd(Math.ceil(base64.length / 4) * 4, "="));
    const bytes = new Uint8Array(binary.length);
    for (let index = 0; index < binary.length; index++) {
      bytes[index] = binary.charCodeAt(index);
    }
    return bytes;
  } catch {
    return invalid("Malformed JWT encoding.");
  }
}

function decodeJsonSegment(value: string): Record<string, unknown> {
  try {
    const parsed = JSON.parse(
      decoder.decode(decodeBase64Url(value)),
    ) as unknown;
    if (!isRecord(parsed)) return invalid("Malformed JWT JSON.");
    return parsed;
  } catch (error) {
    if (error instanceof LogoutTokenValidationError) throw error;
    return invalid("Malformed JWT JSON.");
  }
}

function supportedAlgorithm(value: unknown): SupportedAlgorithm {
  if (value !== "RS256" && value !== "PS256") {
    return invalid("Unsupported logout token signing algorithm.");
  }
  return value;
}

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

async function fetchJwks(url: string): Promise<LogtoJwk[]> {
  const controller = new AbortController();
  const timeout = setTimeout(() => {
    controller.abort();
  }, JWKS_FETCH_TIMEOUT_MS);
  try {
    const response = await fetch(url, {
      headers: { Accept: "application/json" },
      signal: controller.signal,
    });
    if (!response.ok) return invalid("Could not fetch the Logto JWKS.");
    const bodyResult = await readBoundedBody(response, MAX_JWKS_BODY_BYTES);
    if (!bodyResult.ok) return invalid("Could not read the Logto JWKS.");
    let body: unknown;
    try {
      body = JSON.parse(decoder.decode(bodyResult.bytes));
    } catch {
      return invalid("Logto returned a malformed JWKS.");
    }
    if (!isRecord(body) || !Array.isArray(body.keys)) {
      return invalid("Logto returned a malformed JWKS.");
    }
    if (body.keys.length > MAX_JWKS_KEYS) {
      return invalid("Logto returned too many JWKS keys.");
    }
    const keys: LogtoJwk[] = [];
    for (const candidate of body.keys) {
      const key = readLogtoJwk(candidate);
      if (key !== undefined) keys.push(key);
    }
    return keys;
  } catch (error) {
    if (error instanceof LogoutTokenValidationError) throw error;
    return invalid("Could not fetch the Logto JWKS.");
  } finally {
    clearTimeout(timeout);
  }
}

async function loadJwks(
  url: string,
  now: number,
  refreshAfter?: JwksCacheEntry,
): Promise<LoadedJwks> {
  const cached = jwksCache.get(url);
  if (
    cached !== undefined &&
    (refreshAfter === undefined
      ? cached.expiresAt > now
      : cached !== refreshAfter)
  ) {
    return {
      keys: await cached.promise,
      fromCache: true,
      entry: cached,
    };
  }
  const promise = fetchJwks(url);
  const entry = {
    expiresAt: now + JWKS_CACHE_MS,
    fetchedAt: now,
    promise,
  };
  jwksCache.set(url, entry);
  try {
    return { keys: await promise, fromCache: false, entry };
  } catch (error) {
    if (jwksCache.get(url) === entry) jwksCache.delete(url);
    throw error;
  }
}

function matchingKeys(
  keys: LogtoJwk[],
  algorithm: SupportedAlgorithm,
  kid: string | undefined,
): LogtoJwk[] {
  return keys.filter(
    (key) =>
      (kid === undefined || key.kid === kid) &&
      (key.alg === undefined || key.alg === algorithm) &&
      (key.use === undefined || key.use === "sig") &&
      (key.key_ops === undefined || key.key_ops.includes("verify")),
  );
}

async function verifySignature(options: {
  compactHeader: string;
  compactPayload: string;
  signature: Uint8Array<ArrayBuffer>;
  algorithm: SupportedAlgorithm;
  kid?: string;
  jwksUrl: string;
  now: number;
}): Promise<boolean> {
  let loaded = await loadJwks(options.jwksUrl, options.now);
  let candidates = matchingKeys(loaded.keys, options.algorithm, options.kid);
  // A new `kid` is the safe key-rotation signal. Bound forced refreshes so an
  // attacker cannot turn arbitrary kid values into an unbounded JWKS fetcher.
  if (
    candidates.length === 0 &&
    loaded.fromCache &&
    options.now - loaded.entry.fetchedAt >= JWKS_MISS_REFRESH_INTERVAL_MS
  ) {
    loaded = await loadJwks(options.jwksUrl, options.now, loaded.entry);
    candidates = matchingKeys(loaded.keys, options.algorithm, options.kid);
  }
  const signed = encoder.encode(
    `${options.compactHeader}.${options.compactPayload}`,
  );
  for (const jwk of candidates) {
    try {
      const webCryptoAlgorithm =
        options.algorithm === "RS256"
          ? { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" }
          : { name: "RSA-PSS", hash: "SHA-256" };
      const key = await crypto.subtle.importKey(
        "jwk",
        jwk,
        webCryptoAlgorithm,
        false,
        ["verify"],
      );
      const verified = await crypto.subtle.verify(
        options.algorithm === "RS256"
          ? { name: "RSASSA-PKCS1-v1_5" }
          : { name: "RSA-PSS", saltLength: 32 },
        key,
        options.signature,
        signed,
      );
      if (verified) return true;
    } catch {
      // A malformed/incompatible JWK is not a reason to skip the other keys.
    }
  }
  return false;
}

function audienceMatches(value: unknown, appId: string): boolean {
  return (
    value === appId ||
    (Array.isArray(value) &&
      value.length > 0 &&
      value.every((audience) => typeof audience === "string") &&
      value.includes(appId))
  );
}

/**
 * Verify a compact, signed OIDC Logout Token against Logto's RSA JWKS and the
 * Back-Channel Logout validation rules. Encrypted logout tokens are not
 * supported; compact JWE input is rejected as malformed.
 */
export async function verifyLogtoLogoutToken(
  logoutToken: string,
  options: VerifyLogtoLogoutTokenOptions = {},
): Promise<LogtoLogoutTokenClaims> {
  const { endpoint, appId } = readEndpointAndAppId(options);
  const parts = logoutToken.split(".");
  if (parts.length !== 3) return invalid("Malformed logout token.");
  const compactHeader = parts[0];
  const compactPayload = parts[1];
  const compactSignature = parts[2];
  if (
    compactHeader === undefined ||
    compactPayload === undefined ||
    compactSignature === undefined
  ) {
    return invalid("Malformed logout token.");
  }
  const header = decodeJsonSegment(compactHeader);
  const payload = decodeJsonSegment(compactPayload);
  const algorithm = supportedAlgorithm(header.alg);
  const kid = header.kid;
  if (kid !== undefined && (typeof kid !== "string" || kid.length === 0)) {
    return invalid("Invalid logout token kid.");
  }
  const signature = decodeBase64Url(compactSignature);
  if (
    !(await verifySignature({
      compactHeader,
      compactPayload,
      signature,
      algorithm,
      ...(typeof kid === "string" ? { kid } : {}),
      jwksUrl: buildLogtoEndpointUrl(endpoint, "jwks"),
      now: Date.now(),
    }))
  ) {
    return invalid("Invalid logout token signature.");
  }

  const issuer = buildLogtoEndpointUrl(endpoint, "");
  if (payload.iss !== issuer || !audienceMatches(payload.aud, appId)) {
    return invalid("Logout token issuer or audience mismatch.");
  }
  const now = Date.now();
  const iat = payload.iat;
  const exp = payload.exp;
  if (
    typeof iat !== "number" ||
    !Number.isFinite(iat) ||
    typeof exp !== "number" ||
    !Number.isFinite(exp)
  ) {
    return invalid("Logout token is missing iat or exp.");
  }
  const issuedAt = iat * 1000;
  const expiresAt = exp * 1000;
  if (
    now - issuedAt > MAX_TOKEN_AGE_MS ||
    issuedAt - now > MAX_FUTURE_SKEW_MS ||
    expiresAt < now - MAX_FUTURE_SKEW_MS ||
    expiresAt < issuedAt
  ) {
    return invalid("Logout token is stale or expired.");
  }
  const events = payload.events;
  const event = isRecord(events) ? events[BACKCHANNEL_LOGOUT_EVENT] : undefined;
  if (!isRecord(event)) return invalid("Logout token event is missing.");
  if (Object.prototype.hasOwnProperty.call(payload, "nonce")) {
    return invalid("Logout tokens must not contain nonce.");
  }
  const subject = payload.sub;
  const sid = payload.sid;
  if (
    (subject !== undefined &&
      (typeof subject !== "string" || subject.length === 0)) ||
    (sid !== undefined && (typeof sid !== "string" || sid.length === 0)) ||
    (subject === undefined && sid === undefined)
  ) {
    return invalid("Logout token must identify a subject or session.");
  }
  const jti = payload.jti;
  if (typeof jti !== "string" || jti.length === 0) {
    return invalid("Logout token is missing jti.");
  }
  return {
    issuer,
    ...(typeof subject === "string" ? { subject } : {}),
    ...(typeof sid === "string" ? { sid } : {}),
    jti,
  };
}

const noStoreHeaders = {
  "Cache-Control": "no-store",
  "Content-Type": "application/json",
} as const;

function successResponse(): Response {
  return new Response(null, {
    status: 200,
    headers: { "Cache-Control": "no-store" },
  });
}

function errorResponse(description: string, status = 400): Response {
  return new Response(
    JSON.stringify({
      error: "invalid_request",
      error_description: description,
    }),
    { status, headers: noStoreHeaders },
  );
}

async function deliveryKey(claims: LogtoLogoutTokenClaims): Promise<string> {
  const digest = await crypto.subtle.digest(
    "SHA-256",
    encoder.encode(`backchannel-logout\0${claims.issuer}\0${claims.jti}`),
  );
  let hex = "";
  for (const byte of new Uint8Array(digest)) {
    hex += byte.toString(16).padStart(2, "0");
  }
  return hex;
}

/** Build the Convex HTTP action for a Logto OIDC back-channel logout URI. */
export function createLogtoBackchannelLogoutHandler(
  options: LogtoBackchannelLogoutHandlerOptions,
): PublicHttpAction {
  return httpActionGeneric(async (ctx, request) => {
    if (request.method !== "POST") {
      return errorResponse("Back-channel logout requires POST.");
    }
    const contentType = request.headers
      .get("Content-Type")
      ?.split(";", 1)[0]
      ?.trim()
      .toLowerCase();
    if (contentType !== "application/x-www-form-urlencoded") {
      return errorResponse(
        "Expected an application/x-www-form-urlencoded logout request.",
      );
    }
    const bodyResult = await readBoundedBody(request, MAX_BODY_BYTES);
    if (!bodyResult.ok && bodyResult.reason === "too_large") {
      return errorResponse("Payload too large.", 413);
    }
    if (!bodyResult.ok) {
      return errorResponse("Could not read the logout request.");
    }
    const rawBody = bodyResult.bytes;
    let form: URLSearchParams;
    try {
      form = new URLSearchParams(decoder.decode(rawBody));
    } catch {
      return errorResponse("Malformed form body.");
    }
    const logoutTokens = form.getAll("logout_token");
    if (logoutTokens.length !== 1 || !logoutTokens[0]) {
      return errorResponse("Exactly one logout_token is required.");
    }

    let claims: LogtoLogoutTokenClaims;
    try {
      claims = await verifyLogtoLogoutToken(logoutTokens[0], options);
    } catch {
      return errorResponse("The logout_token is invalid.");
    }

    const bodyHash = await deliveryKey(claims);
    let claimed = false;
    try {
      claimed = await ctx.runMutation(
        options.sessions.lib.recordWebhookDelivery,
        { bodyHash, now: Date.now() },
      );
      // A valid replay is already fully handled. Always return the same 200 as
      // a first delivery so neither jti nor session existence leaks.
      if (!claimed) return successResponse();
      if (claims.sid !== undefined) {
        await ctx.runAction(options.sessions.lib.killSessionsBySid, {
          sid: claims.sid,
        });
      } else if (claims.subject !== undefined) {
        await ctx.runAction(options.sessions.lib.killSubjectSessions, {
          subject: claims.subject,
        });
      } else {
        throw new Error("Verified logout token has no subject or sid.");
      }
      return successResponse();
    } catch {
      if (claimed) {
        await ctx
          .runMutation(options.sessions.lib.forgetWebhookDelivery, { bodyHash })
          .catch(() => {});
      }
      return errorResponse("The logout request could not be completed.");
    }
  });
}

/**
 * Register `POST /logto/backchannel-logout` (or `options.path`) on a Convex
 * HTTP router. Configure the resulting `.convex.site` URL as the Logto app's
 * back-channel logout URI.
 */
export function registerLogtoBackchannelLogout(
  http: HttpRouter,
  options: RegisterLogtoBackchannelLogoutOptions,
): void {
  const { path = "/logto/backchannel-logout", ...handlerOptions } = options;
  http.route({
    path,
    method: "POST",
    handler: createLogtoBackchannelLogoutHandler(handlerOptions),
  });
}
