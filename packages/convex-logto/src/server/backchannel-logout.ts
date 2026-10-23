import {
  type HttpRouter,
  type PublicHttpAction,
  httpActionGeneric,
} from "convex/server";
import { audienceMatches } from "../shared/claims";
import { decodeBase64Url, isRecord, toHex } from "../shared/decode";
import { buildLogtoEndpointUrl, logtoIssuer } from "../shared/endpoint";
import { readBoundedBody } from "../shared/http-body";
import {
  LogtoJwksError,
  fetchLogtoJwks,
  verificationKeys,
  type LogtoJwk,
  type LogtoRsaAlgorithm,
} from "../shared/jwks";
import { readEndpointAndAppId, type LogtoConnectionOptions } from "./config";
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

export type LogtoLogoutTokenClaims = {
  issuer: string;
  subject?: string;
  sid?: string;
  jti: string;
};

export type VerifyLogtoLogoutTokenOptions = LogtoConnectionOptions;

export type LogtoBackchannelLogoutHandlerOptions = LogtoConnectionOptions & {
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

function decodeSegment(value: string): Uint8Array<ArrayBuffer> {
  return decodeBase64Url(value) ?? invalid("Malformed JWT encoding.");
}

function decodeJsonSegment(value: string): Record<string, unknown> {
  try {
    const parsed = JSON.parse(decoder.decode(decodeSegment(value))) as unknown;
    if (!isRecord(parsed)) return invalid("Malformed JWT JSON.");
    return parsed;
  } catch (error) {
    if (error instanceof LogoutTokenValidationError) throw error;
    return invalid("Malformed JWT JSON.");
  }
}

function supportedAlgorithm(value: unknown): LogtoRsaAlgorithm {
  if (value !== "RS256" && value !== "PS256") {
    return invalid("Unsupported logout token signing algorithm.");
  }
  return value;
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
  const promise = fetchLogtoJwks(url).catch((error: unknown) => {
    if (error instanceof LogtoJwksError) invalid(error.message);
    throw error;
  });
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

async function verifySignature(options: {
  compactHeader: string;
  compactPayload: string;
  signature: Uint8Array<ArrayBuffer>;
  algorithm: LogtoRsaAlgorithm;
  kid?: string;
  jwksUrl: string;
  now: number;
}): Promise<boolean> {
  let loaded = await loadJwks(options.jwksUrl, options.now);
  let candidates = verificationKeys(
    loaded.keys,
    options.algorithm,
    options.kid,
  );
  // A new `kid` is the safe key-rotation signal. Bound forced refreshes so an
  // attacker cannot turn arbitrary kid values into an unbounded JWKS fetcher.
  if (
    candidates.length === 0 &&
    loaded.fromCache &&
    options.now - loaded.entry.fetchedAt >= JWKS_MISS_REFRESH_INTERVAL_MS
  ) {
    loaded = await loadJwks(options.jwksUrl, options.now, loaded.entry);
    candidates = verificationKeys(loaded.keys, options.algorithm, options.kid);
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

/**
 * Verify a compact, signed OIDC Logout Token against Logto's RSA JWKS and the
 * Back-Channel Logout validation rules. Encrypted logout tokens are not
 * supported; this rejects compact JWE input as malformed.
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
  const signature = decodeSegment(compactSignature);
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

  const issuer = logtoIssuer(endpoint);
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
  return toHex(digest);
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
    let revoked = false;
    try {
      const delivery = await ctx.runMutation(
        options.sessions.lib.recordWebhookDelivery,
        { bodyHash, now: Date.now() },
      );
      claimed = delivery.claimed;
      // A *completed* replay is already fully handled. Always return the same
      // 200 as a first delivery so neither jti nor session existence leaks.
      //
      // A claim that has not completed is not the same thing. The revocation
      // may never have committed, and a release that itself failed keeps the
      // claim for the whole dedupe window. Redo the work instead. Revocation
      // is idempotent (the marker takes the max of what it already holds, and
      // the drain deletes rows that are already dead), so the worst case for
      // two deliveries racing inside that window is doing it twice.
      if (!claimed && delivery.completed) return successResponse();
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
      revoked = true;
      // Only now is a later replay safe to answer without working. Suppressing
      // replays still matters. A `sub`-only logout token revokes everything the
      // subject has *at the time it runs*, so a replay after the user signs in
      // again would sign them out a second time.
      await ctx.runMutation(options.sessions.lib.completeWebhookDelivery, {
        bodyHash,
        now: Date.now(),
      });
      return successResponse();
    } catch {
      // The revocation committed and only recording it failed. The logout
      // happened, so say so, and keep the claim: an unfinished claim is
      // already redone on replay, and forgetting it would re-arm a replay of
      // a `sub`-only token against sessions created after this one.
      if (revoked) return successResponse();
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
