// Decoding primitives for untrusted input, shared by the component, the
// server entry, and the browser/native clients. Keep this module V8-safe,
// because the component imports it.

const utf8Decoder = /* @__PURE__ */ new TextDecoder("utf-8", { fatal: true });

/** A plain JSON object. Arrays and `null` are not records. */
export function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/** Strict base64url (no padding, no other alphabet), or `null`. */
export function decodeBase64Url(value: string): Uint8Array<ArrayBuffer> | null {
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

/**
 * A JWT segment is base64url over **UTF-8 bytes**. `atob` alone yields one
 * latin-1 character per byte, which mojibakes every multi-byte claim. A `name`
 * of `王小明` decodes as `ç\u008e\u008bå°\u008fæ\u0098\u008e`. So the bytes have
 * to go through a UTF-8 decode. Returns `undefined` rather than a partial
 * result, because nothing downstream can act on half-decoded claims.
 */
export function decodeJwtSegment(segment: string): unknown {
  const bytes = decodeBase64Url(segment);
  if (bytes === null) return undefined;
  try {
    return JSON.parse(utf8Decoder.decode(bytes)) as unknown;
  } catch {
    return undefined;
  }
}

/**
 * The claims of a compact JWT, unverified, or `null` when it is not a
 * three-segment token with a JSON-object payload. Only for reading claims the
 * caller already trusts (or is about to verify); never an authorization check.
 */
export function decodeJwtPayload(
  token: string,
): Record<string, unknown> | null {
  const parts = token.split(".");
  if (parts.length !== 3) return null;
  const decoded = decodeJwtSegment(parts[1] ?? "");
  return isRecord(decoded) ? decoded : null;
}
