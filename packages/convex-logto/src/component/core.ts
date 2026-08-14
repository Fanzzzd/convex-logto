// Pure logic for the session component — no ctx, no fetch, unit-testable.
// Everything here runs in Convex's V8 runtime: Web APIs only.

import { ConvexError } from "convex/values";

/** Default lifetime of a sign-in transaction (state + PKCE verifier). */
export const TRANSACTION_TTL_MS = 10 * 60 * 1000;

/**
 * Default reuse window: re-presenting the immediately-previous session token
 * inside this window rotates again instead of killing the session — tolerating
 * multi-tab races and network retries the client-side Web Lock can't cover.
 * Matches @convex-dev/auth's concurrency window. Logto itself has NO grace
 * window (reuse destroys the whole grant), so this layer is the only tolerance.
 */
export const DEFAULT_REUSE_WINDOW_MS = 10 * 1000;

/**
 * GC horizon for dead sessions: Logto's grant chain has a hard 180-day cap, so
 * a session not refreshed for longer than this can never refresh again.
 */
export const SESSION_GC_AFTER_MS = 190 * 24 * 60 * 60 * 1000;

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
 * covers the one-time session token itself, so it cannot be carried forward to
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
  return `${options.endpoint}/oidc/auth?${params}`;
}

export function buildEndSessionUrl(options: {
  endpoint: string;
  appId: string;
  postLogoutRedirectUri?: string;
  idTokenHint?: string;
}): string {
  const params = new URLSearchParams({ client_id: options.appId });
  if (options.postLogoutRedirectUri) {
    params.set("post_logout_redirect_uri", options.postLogoutRedirectUri);
  }
  if (options.idTokenHint) {
    params.set("id_token_hint", options.idTokenHint);
  }
  return `${options.endpoint}/oidc/session/end?${params}`;
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
  let payload: Record<string, unknown>;
  try {
    const base64 = parts[1]!.replace(/-/g, "+").replace(/_/g, "/");
    payload = JSON.parse(atob(base64)) as Record<string, unknown>;
  } catch {
    throw terminal("invalid_id_token", "Logto returned a malformed ID token.");
  }
  const { iss, aud, sub, sid, exp } = payload;
  if (iss !== `${expected.endpoint}/oidc` || aud !== expected.appId) {
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
 * `presentedHash` was found on `session` either as the current or the previous
 * token hash; decide what the refresh should do.
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
  /** Don't serve a cached ID token with less than this much life left. */
  idTokenSkewMs?: number;
  /** How long a refresh claim blocks competitors before it's considered stale. */
  claimTimeoutMs?: number;
}):
  | { outcome: "refresh" } // presented the current token: rotate + hit Logto
  | { outcome: "cached" } // previous token inside the window, cached ID token fresh: rotate locally
  | { outcome: "refresh-previous" } // previous token inside the window, cache stale: rotate + hit Logto
  | { outcome: "in-flight" } // a concurrent refresh holds the claim: transient, retry
  | {
      outcome: "reuse";
    } /* previous token OUTSIDE the window: kill the session */ {
  const {
    presentedHash,
    session,
    now,
    reuseWindowMs,
    idTokenSkewMs = 60 * 1000,
    claimTimeoutMs = 15 * 1000,
  } = options;

  const claimed =
    session.refreshingSince !== undefined &&
    now - session.refreshingSince < claimTimeoutMs;

  if (presentedHash === session.tokenHash) {
    // Current token. If another refresh is mid-flight (same token double-fired
    // past the client's Web Lock), don't double-hit Logto's token endpoint —
    // at the ≥70%-TTL rotation boundary a concurrent replay of the same
    // refresh token would trip Logto's reuse detection and destroy the grant.
    if (claimed) return { outcome: "in-flight" };
    return { outcome: "refresh" };
  }

  // Not current — the caller matched it via prevTokenHash.
  const inWindow =
    session.rotatedAt !== undefined && now - session.rotatedAt < reuseWindowMs;
  if (!inWindow) return { outcome: "reuse" };
  if (claimed) return { outcome: "in-flight" };
  if (session.lastIdTokenExp - idTokenSkewMs > now)
    return { outcome: "cached" };
  return { outcome: "refresh-previous" };
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

// --- error taxonomy ---------------------------------------------------------
//
// Terminal: the session/transaction is gone for good — the client clears its
// state and transitions to unauthenticated. Transient: network/5xx/contention —
// the client retries with backoff and NEVER treats it as a sign-out.

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

/** Classify a Logto token-endpoint failure: 4xx auth failures are terminal, the rest transient. */
export function classifyTokenEndpointFailure(
  status: number,
  body: { error?: string },
): ConvexError<SessionErrorData> {
  if (status === 400 || status === 401) {
    return terminal(
      body.error ?? "invalid_grant",
      `Logto rejected the grant (${body.error ?? status}) — the session can't continue.`,
    );
  }
  return transient(
    "logto_unreachable",
    `Logto token endpoint responded ${status} — retry later.`,
  );
}
