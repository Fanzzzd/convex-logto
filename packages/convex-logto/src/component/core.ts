// Pure logic for the session component — no ctx, no fetch, unit-testable.
// Everything here runs in Convex's V8 runtime: Web APIs only.

import { ConvexError } from "convex/values";
import { buildLogtoEndpointUrl } from "./endpoint.js";

/** Default lifetime of a sign-in transaction (state + PKCE verifier). */
export const TRANSACTION_TTL_MS = 10 * 60 * 1000;

/**
 * Default reuse window for a recently superseded session-token generation.
 * Presentations inside the window absorb multi-tab races and network retries
 * the client-side Web Lock cannot cover.
 */
export const DEFAULT_REUSE_WINDOW_MS = 10 * 1000;
/** Maximum out-of-order successful session-token responses retained per session. */
export const SESSION_TOKEN_GENERATION_LIMIT = 8;

/** Longest accepted user-chosen session label, in code points. */
export const SESSION_LABEL_MAX_LENGTH = 64;

/**
 * Longest accepted sign-in redirect URI / `returnTo`, in code points.
 *
 * `signIn` is necessarily unauthenticated, and both strings are stored verbatim
 * in a `transactions` row for the transaction TTL. Unbounded, anyone who knows
 * the deployment URL can park documents near Convex's 1 MiB limit in a loop, and
 * GC only drains four transaction documents per mutation. Every other
 * caller-supplied string in this component is bounded; these are generous by
 * comparison — a redirect URI that does not fit in 2048 code points is not a
 * redirect URI anyone registered with Logto.
 */
export const SIGN_IN_URL_MAX_LENGTH = 2048;
/** Longest accepted value for each self-reported client descriptor field. */
export const CLIENT_DESCRIPTOR_MAX_LENGTH = 32;
/**
 * Sessions returned by one `listSessions` call. Bounded because the query reads
 * whole session documents; the result reports whether it was truncated rather
 * than silently showing a partial list of a user's devices.
 */
export const SESSION_LIST_LIMIT = 16;

/**
 * How many rows one `listSessions` call may read while filling that page.
 * Sessions killed by a `sid` watermark are filtered after the read, so the scan
 * must be allowed to walk past them — but only this far, to keep the query's
 * work bounded no matter how much revoked state is awaiting cleanup.
 */
export const SESSION_LIST_SCAN_LIMIT = 128;

/**
 * The other half of that bound. A session document may approach Convex's 1 MiB
 * limit (a fat ID token with many claims), so a row count alone does not bound
 * the read: the scan also stops once it has read this many bytes. A quarter of
 * the 16 MiB transaction budget leaves room for the one document already in
 * hand when the check fires, and for the watermark lookups alongside it.
 */
export const SESSION_LIST_SCAN_BYTES = 4 * 1024 * 1024;

/** The large, variable fields of a session row, plus slack for the rest. */
export function sessionReadCost(session: {
  logtoRefreshToken: string;
  lastIdToken: string;
  label?: string;
}): number {
  return (
    session.logtoRefreshToken.length +
    session.lastIdToken.length +
    (session.label?.length ?? 0) +
    512
  );
}

/** Self-reported, unauthenticated description of a signing-in client. */
export type SessionClientDescriptor = {
  platform?: string;
  os?: string;
  browser?: string;
};

/**
 * Every invisible character class, not a hand-picked list of bidi overrides:
 * `Cc` controls, `Cf` format characters (the bidi embeddings and isolates, but
 * also RLM/LRM/ALM and the zero-width joiners `\s` never matches), and the line
 * and paragraph separators. A label is rendered next to other sessions, and any
 * of these can make one entry impersonate another.
 */
const INVISIBLE_DISPLAY_CHARACTERS = /[\p{Cc}\p{Cf}\p{Zl}\p{Zp}]/u;

/** Emoji sequences join with ZWJ; dropping it would split families apart. */
const ZERO_WIDTH_JOINER = "\u200d";

/**
 * Collapse whitespace and drop invisible characters, so a label cannot smuggle
 * newlines or direction changes into a UI that lists it beside other sessions.
 */
function normalizeDisplayText(raw: string): string {
  // Code points, not graphemes: the limit these feed is a storage bound, and
  // per-code-point filtering is what strips the invisible characters.
  return Array.from(raw)
    .filter(
      (character) =>
        character === ZERO_WIDTH_JOINER ||
        !INVISIBLE_DISPLAY_CHARACTERS.test(character),
    )
    .join("")
    .replace(/\s+/g, " ")
    .trim();
}

/**
 * Would this label be rejected for its length? Exported so the browser half can
 * pre-empt the round-trip against *exactly* the rule the component applies:
 * normalization first, then a code-point count. Measuring the raw string
 * instead would reject a label the component would have accepted, because
 * normalization collapses whitespace and drops invisible characters.
 */
export function sessionLabelTooLong(raw: string): boolean {
  return (
    Array.from(normalizeDisplayText(raw)).length > SESSION_LABEL_MAX_LENGTH
  );
}

/**
 * Normalize a user-chosen session label. Rejects rather than truncates: a
 * silently shortened label is worse than a clear error, because the user is
 * naming a device they need to recognise later.
 */
export function normalizeSessionLabel(
  raw: string | undefined,
): string | undefined {
  if (raw === undefined) return undefined;
  const label = normalizeDisplayText(raw);
  if (label === "") return undefined;
  if (sessionLabelTooLong(label)) {
    throw terminal(
      "session_label_too_long",
      `A session label may be at most ${SESSION_LABEL_MAX_LENGTH} characters.`,
    );
  }
  return label;
}

/**
 * Normalize the app-supplied client descriptor. Values are advisory, so an
 * over-long field is trimmed to the limit instead of failing a sign-in that is
 * otherwise fine.
 */
export function normalizeClientDescriptor(
  raw: SessionClientDescriptor | undefined,
): SessionClientDescriptor | undefined {
  if (raw === undefined) return undefined;
  const descriptor: SessionClientDescriptor = {};
  for (const field of ["platform", "os", "browser"] as const) {
    const value = raw[field];
    if (value === undefined) continue;
    const normalized = Array.from(normalizeDisplayText(value))
      .slice(0, CLIENT_DESCRIPTOR_MAX_LENGTH)
      .join("");
    if (normalized !== "") descriptor[field] = normalized;
  }
  return Object.keys(descriptor).length === 0 ? undefined : descriptor;
}

/**
 * GC horizon for dead sessions: Logto's grant chain has a hard 180-day cap, so
 * a session not refreshed for longer than this can never refresh again.
 */
export const SESSION_GC_AFTER_MS = 190 * 24 * 60 * 60 * 1000;

/**
 * GC horizon for a revocation watermark, measured from the moment it was
 * written. A watermark is what makes a session created at or before it dead, so
 * collecting one is only safe once nothing can still be governed by it: no
 * session row it covers remains (the collector checks that directly), and no
 * session can still *acquire* the marked `sid`, which a refresh can do long
 * after sign-in. Past this horizon every session that could do either is itself
 * unconditionally GC-dead, so the two conditions together leave no window.
 */
export const REVOCATION_MARKER_GC_AFTER_MS = SESSION_GC_AFTER_MS;

/**
 * GC horizon for webhook-delivery dedupe hashes. Logto's delivery retries land
 * within seconds and the webhook route rejects deliveries older than minutes,
 * so a day of memory is far more than dedupe ever needs.
 */
export const WEBHOOK_DELIVERY_GC_AFTER_MS = 24 * 60 * 60 * 1000;

const encoder = new TextEncoder();

export function toBase64Url(bytes: Uint8Array): string {
  let binary = "";
  for (const b of bytes) binary += String.fromCharCode(b);
  return btoa(binary)
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

function toHex(buffer: ArrayBuffer): string {
  let hex = "";
  for (const b of new Uint8Array(buffer))
    hex += b.toString(16).padStart(2, "0");
  return hex;
}

/** 256-bit random opaque token, base64url — the browser-held session credential. */
export function generateToken(): string {
  const bytes = new Uint8Array(32);
  crypto.getRandomValues(bytes);
  return toBase64Url(bytes);
}

/** SHA-256 hex of a session token — the only form stored at rest. */
export async function hashToken(token: string): Promise<string> {
  return toHex(await crypto.subtle.digest("SHA-256", encoder.encode(token)));
}

export type DevicePublicKey = {
  kty: "EC";
  crv: "P-256";
  x: string;
  y: string;
};

/**
 * A JWT segment is base64url over **UTF-8 bytes**. `atob` alone yields one
 * latin-1 character per byte, which silently mojibakes every multi-byte claim —
 * a `name` of `王小明` decodes as `ç\u008e\u008bå°\u008fæ\u0098\u008e` — so the bytes
 * have to go through a UTF-8 decode. Returns `undefined` rather than a partial
 * result: nothing downstream can act on half-decoded claims.
 */
export function decodeJwtSegment(segment: string): unknown {
  const bytes = fromBase64Url(segment);
  if (bytes === null) return undefined;
  try {
    return JSON.parse(jwtSegmentDecoder.decode(bytes));
  } catch {
    return undefined;
  }
}

const jwtSegmentDecoder = /* @__PURE__ */ new TextDecoder("utf-8", {
  fatal: true,
});

function fromBase64Url(value: string): Uint8Array<ArrayBuffer> | null {
  if (!/^[A-Za-z0-9_-]+$/.test(value)) return null;
  const base64 = value.replace(/-/g, "+").replace(/_/g, "/");
  try {
    const binary = atob(base64.padEnd(Math.ceil(base64.length / 4) * 4, "="));
    const bytes = new Uint8Array(binary.length);
    for (let index = 0; index < binary.length; index++) {
      bytes[index] = binary.charCodeAt(index);
    }
    return bytes;
  } catch {
    return null;
  }
}

/** Verify an ECDSA P-256 proof over the presented rotating session token. */
export async function verifyDeviceProof(options: {
  publicKey: DevicePublicKey;
  sessionToken: string;
  proof: string;
}): Promise<boolean> {
  const signature = fromBase64Url(options.proof);
  // WebCrypto ECDSA signatures use fixed-width IEEE P1363 r || s encoding.
  if (signature?.byteLength !== 64) return false;
  try {
    const key = await crypto.subtle.importKey(
      "jwk",
      {
        ...options.publicKey,
        ext: true,
        key_ops: ["verify"],
      },
      { name: "ECDSA", namedCurve: "P-256" },
      false,
      ["verify"],
    );
    return await crypto.subtle.verify(
      { name: "ECDSA", hash: "SHA-256" },
      key,
      signature,
      encoder.encode(options.sessionToken),
    );
  } catch {
    return false;
  }
}

/**
 * Enforce PoP only for sessions that opted in at exchange time. The signature
 * covers the presented session-token generation, so it cannot be carried forward to
 * the next rotation; token reuse retains only the existing bounded grace rule.
 */
export async function assertDeviceProof(options: {
  publicKey?: DevicePublicKey;
  sessionToken: string;
  proof?: string;
}): Promise<void> {
  const publicKey = options.publicKey;
  if (publicKey === undefined) return;
  if (options.proof === undefined) {
    throw terminal(
      "device_proof_required",
      "This session is device-bound, but its proof of possession is missing. Sign in again.",
    );
  }
  if (
    !(await verifyDeviceProof({
      publicKey,
      sessionToken: options.sessionToken,
      proof: options.proof,
    }))
  ) {
    throw terminal(
      "device_proof_invalid",
      "This session's device proof is invalid. The bound key may have been evicted; sign in again.",
    );
  }
}

/** PKCE S256: verifier (random) + challenge (SHA-256, base64url). */
export async function generatePkce(): Promise<{
  verifier: string;
  challenge: string;
}> {
  const bytes = new Uint8Array(32);
  crypto.getRandomValues(bytes);
  const verifier = toBase64Url(bytes);
  const digest = await crypto.subtle.digest(
    "SHA-256",
    encoder.encode(verifier),
  );
  return { verifier, challenge: toBase64Url(new Uint8Array(digest)) };
}

/** The scopes always requested; extras append. `offline_access` gets the refresh token. */
const BASE_SCOPES = ["openid", "offline_access", "profile", "email"];

export function buildAuthorizeUrl(options: {
  endpoint: string;
  appId: string;
  redirectUri: string;
  state: string;
  challenge: string;
  scopes?: string[];
  resources?: string[];
}): string {
  const params = new URLSearchParams({
    client_id: options.appId,
    redirect_uri: options.redirectUri,
    response_type: "code",
    scope: [...BASE_SCOPES, ...(options.scopes ?? [])].join(" "),
    state: options.state,
    code_challenge: options.challenge,
    code_challenge_method: "S256",
    // Required for offline_access to actually issue a refresh token.
    prompt: "consent",
  });
  for (const resource of options.resources ?? []) {
    params.append("resource", resource);
  }
  return buildLogtoEndpointUrl(options.endpoint, "auth", params);
}

export function buildEndSessionUrl(options: {
  endpoint: string;
  appId: string;
  postLogoutRedirectUri?: string;
}): string {
  const params = new URLSearchParams({ client_id: options.appId });
  if (options.postLogoutRedirectUri) {
    params.set("post_logout_redirect_uri", options.postLogoutRedirectUri);
  }
  return buildLogtoEndpointUrl(options.endpoint, "session/end", params);
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/**
 * Decode a JWT payload without verifying the signature. Verification is not
 * this component's job: the token arrives directly from Logto over TLS, and
 * Convex verifies the signature against Logto's JWKS when the browser presents
 * it. We only need claims for bookkeeping — with a sanity check that the token
 * is for this app and issuer, so a misconfiguration fails loudly here instead
 * of as a silent Convex rejection later.
 */
export function decodeIdToken(
  idToken: string,
  expected: { endpoint: string; appId: string },
): { subject: string; sid?: string; expiresAtMs: number } {
  const parts = idToken.split(".");
  if (parts.length !== 3) {
    throw terminal("invalid_id_token", "Logto returned a malformed ID token.");
  }
  const payloadSegment = parts[1];
  if (payloadSegment === undefined) {
    throw terminal("invalid_id_token", "Logto returned a malformed ID token.");
  }
  const payload = decodeJwtSegment(payloadSegment);
  if (!isRecord(payload)) {
    throw terminal("invalid_id_token", "Logto returned a malformed ID token.");
  }
  const { iss, aud, sub, sid, exp } = payload;
  if (
    iss !== buildLogtoEndpointUrl(expected.endpoint, "") ||
    !audienceMatches(aud, expected.appId)
  ) {
    throw terminal(
      "id_token_mismatch",
      `ID token iss/aud (${String(iss)} / ${String(aud)}) don't match the configured ` +
        `LOGTO_ENDPOINT / LOGTO_APP_ID — check the Traditional Web app's configuration.`,
    );
  }
  if (typeof sub !== "string" || typeof exp !== "number") {
    throw terminal("invalid_id_token", "ID token is missing sub/exp claims.");
  }
  return {
    subject: sub,
    ...(typeof sid === "string" && sid.length > 0 ? { sid } : {}),
    expiresAtMs: exp * 1000,
  };
}

/**
 * The rotation decision — the heart of reuse handling, pure so it's testable.
 * `presentedHash` was found either as the current or a recently superseded
 * Session-token generation; decide what the refresh should do.
 */
export function decideRefresh(options: {
  presentedHash: string;
  session: {
    tokenHash: string;
    prevTokenHash?: string;
    rotatedAt?: number;
    refreshingSince?: number;
    lastIdTokenExp: number;
  };
  now: number;
  reuseWindowMs: number;
  /** Exact expiry for a match from the indexed token-generation history. */
  presentedTokenExpiresAt?: number;
  /** Don't serve a cached ID token with less than this much life left. */
  idTokenSkewMs?: number;
  /** How long a refresh claim blocks competitors before it's considered stale. */
  claimTimeoutMs?: number;
}):
  | { outcome: "refresh" } // presented the current token: rotate + hit Logto
  | { outcome: "cached" } // superseded generation inside the window, cached ID token fresh: rotate locally
  | { outcome: "refresh-superseded" } // superseded generation inside the window, cache stale: rotate + hit Logto
  | { outcome: "in-flight" } // a concurrent refresh holds the claim: transient, retry
  | { outcome: "claim-expired" } // remote outcome unknown: kill locally, require reauthentication
  | {
      outcome: "reuse";
    } /* superseded generation OUTSIDE the window: kill the Session */ {
  const {
    presentedHash,
    session,
    now,
    reuseWindowMs,
    presentedTokenExpiresAt,
    idTokenSkewMs = 60 * 1000,
    claimTimeoutMs = 15 * 1000,
  } = options;

  const claimAge =
    session.refreshingSince === undefined
      ? undefined
      : now - session.refreshingSince;
  const claimed = claimAge !== undefined && claimAge < claimTimeoutMs;

  // Once a claim times out, the action may still have reached Logto and
  // rotated the refresh token. Reusing the stored token would risk a second
  // spend and Logto grant revocation, so the only safe recovery is to abandon
  // this local session and require a new authorization flow.
  if (claimAge !== undefined && claimAge >= claimTimeoutMs) {
    return { outcome: "claim-expired" };
  }

  if (presentedHash === session.tokenHash) {
    // Current token. If another refresh is mid-flight (same token double-fired
    // past the client's Web Lock), don't double-hit Logto's token endpoint —
    // at the ≥70%-TTL rotation boundary a concurrent replay of the same
    // refresh token would trip Logto's reuse detection and destroy the grant.
    if (claimed) return { outcome: "in-flight" };
    return { outcome: "refresh" };
  }

  // Not current — resolution matched a retained superseded generation (or the
  // legacy prevTokenHash adapter).
  const inWindow =
    presentedTokenExpiresAt === undefined
      ? isPreviousTokenWithinReuseWindow({
          rotatedAt: session.rotatedAt,
          now,
          reuseWindowMs,
        })
      : now < presentedTokenExpiresAt;
  if (!inWindow) return { outcome: "reuse" };
  if (claimed) return { outcome: "in-flight" };
  if (session.lastIdTokenExp - idTokenSkewMs > now)
    return { outcome: "cached" };
  return { outcome: "refresh-superseded" };
}

/** Apply the exclusive grace window for a legacy previous-generation field. */
export function isPreviousTokenWithinReuseWindow(options: {
  rotatedAt?: number;
  now: number;
  reuseWindowMs: number;
}): boolean {
  return (
    options.rotatedAt !== undefined &&
    options.now - options.rotatedAt < options.reuseWindowMs
  );
}

/** Rotate while keeping the superseded current generation as the grace token. */
export function rotateTokenHashes(
  currentTokenHash: string,
  candidateHash: string,
): { tokenHash: string; prevTokenHash: string } {
  return {
    tokenHash: candidateHash,
    prevTokenHash: currentTokenHash,
  };
}

/**
 * Bound and sanity-check the two caller-supplied strings a sign-in stores.
 *
 * `redirectUri` only has to be a parseable absolute URI with no embedded
 * credentials: native flows legitimately use a custom scheme
 * (`io.logto://callback`), and Logto itself rejects any URI the app has not
 * registered, so anything stricter here would break platforms rather than
 * protect them.
 */
export function normalizeSignInTargets(targets: {
  redirectUri: string;
  returnTo?: string;
}): { redirectUri: string; returnTo?: string } {
  if (Array.from(targets.redirectUri).length > SIGN_IN_URL_MAX_LENGTH) {
    throw terminal(
      "redirect_uri_too_long",
      `The sign-in redirect URI exceeds ${SIGN_IN_URL_MAX_LENGTH} characters.`,
    );
  }
  let parsed: URL;
  try {
    parsed = new URL(targets.redirectUri);
  } catch {
    throw terminal(
      "redirect_uri_invalid",
      "The sign-in redirect URI is not an absolute URI.",
    );
  }
  if (parsed.username !== "" || parsed.password !== "") {
    throw terminal(
      "redirect_uri_invalid",
      "The sign-in redirect URI must not embed credentials.",
    );
  }
  if (
    targets.returnTo !== undefined &&
    Array.from(targets.returnTo).length > SIGN_IN_URL_MAX_LENGTH
  ) {
    throw terminal(
      "return_to_too_long",
      `\`returnTo\` exceeds ${SIGN_IN_URL_MAX_LENGTH} characters.`,
    );
  }
  return {
    redirectUri: targets.redirectUri,
    ...(targets.returnTo === undefined ? {} : { returnTo: targets.returnTo }),
  };
}

/**
 * OIDC Core §2 allows `aud` to be an array, Convex's own ID-token validation
 * accepts one, and this library's back-channel-logout verifier always has — so
 * rejecting it here would fail a token every other party considers valid, and
 * on the refresh path that costs the session.
 */
export function audienceMatches(value: unknown, appId: string): boolean {
  return (
    value === appId ||
    (Array.isArray(value) &&
      value.length > 0 &&
      value.every((audience) => typeof audience === "string") &&
      value.includes(appId))
  );
}

// --- error taxonomy ---------------------------------------------------------
//
// Terminal: the session/transaction is gone for good — the client clears its
// state and transitions to unauthenticated. Transient: network/5xx/contention —
// the client retries with backoff and NEVER treats it as a sign-out.
//
// One class of terminal error is about the *input*, not the session: a rejected
// session label means "do not retry this value", and nothing about the session
// died. The client validates label length before the round-trip so an app never
// has to tell the two apart, and this guard stays as defence in depth for a
// caller reaching the component directly.

export type SessionErrorData = {
  kind: "terminal" | "transient";
  code: string;
  message: string;
};

export function terminal(
  code: string,
  message: string,
): ConvexError<SessionErrorData> {
  return new ConvexError({ kind: "terminal" as const, code, message });
}

export function transient(
  code: string,
  message: string,
): ConvexError<SessionErrorData> {
  return new ConvexError({ kind: "transient" as const, code, message });
}

/**
 * Re-classify a failure that happened *after* Logto answered with a well-formed
 * token response.
 *
 * The response was unusable to us — an `iss`/`aud` drift after an endpoint
 * change, a missing `openid` scope — but Logto processed the grant and told us
 * what it did with the refresh token, so the session is not dead. Terminal here
 * would delete the row, which is how one wrong environment variable takes out
 * every session in a deployment, one refresh at a time.
 *
 * The caller persists any rotation and releases the claim before raising this:
 * the rotation state is known, so the stored token is the one Logto expects
 * next. A response we could not parse is a different case — the outcome is
 * unknown and `outcomeUnknown` handles it.
 */
/**
 * Re-classify a token-endpoint failure that happened on the *sign-in* path.
 *
 * {@link classifyTokenEndpointFailure} answers for `refresh`, where transient is
 * the safe default because terminal deletes the session row. Sign-in has no
 * session to lose, and by the time Logto is contacted the transaction row is
 * already consumed and the authorization code spent — so a retry can only find
 * nothing and report `transaction_not_found`, burying the diagnosis Logto just
 * gave us. Keep the code and the message; only the verdict changes.
 */
export function asSpentAuthorizationCode(
  error: unknown,
): ConvexError<SessionErrorData> {
  const suffix =
    " Start sign-in again: the authorization code is spent, so this attempt " +
    "cannot be retried.";
  if (error instanceof ConvexError && isSessionErrorData(error.data)) {
    return terminal(error.data.code, `${error.data.message}${suffix}`);
  }
  return terminal(
    "sign_in_failed",
    `Could not exchange the authorization code with Logto.${suffix}`,
  );
}

export function asDeploymentFault(
  error: unknown,
): ConvexError<SessionErrorData> {
  if (error instanceof ConvexError && isSessionErrorData(error.data)) {
    return transient(
      error.data.code,
      `${error.data.message} The session was kept: this looks like a deployment ` +
        `fault rather than a dead session.`,
    );
  }
  return transient(
    "logto_response_unusable",
    "Logto's token response could not be used, but the session was kept.",
  );
}

function isSessionErrorData(data: unknown): data is SessionErrorData {
  return (
    isRecord(data) &&
    typeof data.code === "string" &&
    typeof data.message === "string"
  );
}

/** Terminal signal for a superseded generation presented after its Reuse window. */
export function sessionReuseDetectedError(): ConvexError<SessionErrorData> {
  return terminal(
    "session_reuse_detected",
    "This session token was already rotated away — the session has been revoked. Sign in again.",
  );
}

/** Classify a Logto token-endpoint failure: 4xx auth failures are terminal, the rest transient. */
/**
 * OAuth 2.0 error codes (RFC 6749 §5.2) that describe a broken *deployment*,
 * not a dead user grant. `invalid_client` in particular is answered with 401
 * and means this app's own credentials are wrong — treating it as terminal
 * would delete every session in the deployment the moment a client secret is
 * rotated without updating `LOGTO_CLIENT_SECRET`.
 */
const CONFIGURATION_FAULT_ERRORS = new Set([
  "invalid_client",
  "invalid_request",
  "unauthorized_client",
  "unsupported_grant_type",
  "invalid_scope",
]);

/**
 * `outcome_unknown` marks a refresh whose request reached Logto but whose
 * result never came back. The stored refresh token may already have been
 * rotated, so it must never be presented a second time — Logto's reuse
 * detection destroys the whole grant, including sibling Sessions.
 */
export const TOKEN_OUTCOME_UNKNOWN = "logto_outcome_unknown";

export function outcomeUnknown(message: string): ConvexError<SessionErrorData> {
  return transient(TOKEN_OUTCOME_UNKNOWN, message);
}

export function isOutcomeUnknownError(error: unknown): boolean {
  return (
    error instanceof ConvexError &&
    typeof error.data === "object" &&
    error.data !== null &&
    "code" in error.data &&
    error.data.code === TOKEN_OUTCOME_UNKNOWN
  );
}

export function classifyTokenEndpointFailure(
  status: number,
  body: { error?: string },
): ConvexError<SessionErrorData> {
  if (status === 400 || status === 401) {
    // Logto answered with a decision, so it did not rotate anything.
    if (
      body.error !== undefined &&
      CONFIGURATION_FAULT_ERRORS.has(body.error)
    ) {
      return transient(
        body.error,
        `Logto rejected this deployment's own request (${body.error}) — check ` +
          `LOGTO_APP_ID / LOGTO_CLIENT_SECRET / LOGTO_ENDPOINT. Sessions are kept.`,
      );
    }
    if (body.error === undefined) {
      // No machine-readable reason. Destroying sessions on an answer we cannot
      // attribute is the irreversible choice, so fail transiently instead.
      return transient(
        "logto_rejected",
        `Logto token endpoint responded ${status} without an error code — retry later.`,
      );
    }
    return terminal(
      body.error,
      `Logto rejected the grant (${body.error}) — the session can't continue.`,
    );
  }
  if (status === 429) {
    // Rate limiting happens before the grant is processed.
    return transient(
      "logto_rate_limited",
      "Logto rate-limited the token endpoint — retry later.",
    );
  }
  return outcomeUnknown(
    `Logto token endpoint responded ${status} — the refresh outcome is unknown.`,
  );
}
