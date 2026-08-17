/**
 * A successful bounded body read or the controlled reason it stopped.
 *
 * The buffer is pinned to `ArrayBuffer` rather than the default
 * `ArrayBufferLike`: every caller hands these bytes to `crypto.subtle`, whose
 * `BufferSource` parameter excludes `SharedArrayBuffer`. TypeScript 7's lib
 * definitions enforce that; 5.x accepted the wider type.
 */
export type BoundedBodyResult =
  | { ok: true; bytes: Uint8Array<ArrayBuffer> }
  | { ok: false; reason: "too_large" | "read_error" };

type BodySource = Pick<Request, "body" | "headers">;

function declaredLengthExceedsLimit(
  value: string | null,
  maxBytes: number,
): boolean {
  if (value === null) return false;
  const trimmed = value.trim();
  if (!/^\d+$/.test(trimmed)) return false;
  return Number(trimmed) > maxBytes;
}

async function cancelStream(
  stream: ReadableStream<Uint8Array> | null,
): Promise<void> {
  if (stream === null) return;
  try {
    await stream.cancel("Request body exceeds the configured limit.");
  } catch {
    // A locked or already-failed stream cannot always be cancelled. The caller
    // still gets a controlled rejection, and no more chunks are consumed here.
  }
}

/**
 * Read an HTTP body without ever retaining more than `maxBytes` of chunks.
 *
 * `Content-Length` is only an early-rejection hint: a missing or dishonest
 * header never bypasses the byte count performed while the stream is read.
 */
export async function readBoundedBody(
  source: BodySource,
  maxBytes: number,
  signal?: AbortSignal,
): Promise<BoundedBodyResult> {
  if (!Number.isSafeInteger(maxBytes) || maxBytes < 0) {
    throw new RangeError("maxBytes must be a non-negative safe integer");
  }

  if (
    declaredLengthExceedsLimit(source.headers.get("Content-Length"), maxBytes)
  ) {
    await cancelStream(source.body);
    return { ok: false, reason: "too_large" };
  }

  if (signal?.aborted === true) {
    await cancelStream(source.body);
    return { ok: false, reason: "read_error" };
  }

  if (source.body === null) return { ok: true, bytes: new Uint8Array() };

  let reader: ReadableStreamDefaultReader<Uint8Array>;
  try {
    reader = source.body.getReader();
  } catch {
    return { ok: false, reason: "read_error" };
  }

  const chunks: Uint8Array[] = [];
  let byteLength = 0;
  let aborted = false;
  const abort = () => {
    aborted = true;
    void reader.cancel(signal?.reason).catch(() => {});
  };
  signal?.addEventListener("abort", abort, { once: true });
  try {
    while (true) {
      const chunk = await reader.read();
      if (aborted) return { ok: false, reason: "read_error" };
      if (chunk.done) break;
      byteLength += chunk.value.byteLength;
      if (byteLength > maxBytes) {
        try {
          await reader.cancel("Request body exceeds the configured limit.");
        } catch {
          // Cancellation is best-effort for streams that fail concurrently.
        }
        return { ok: false, reason: "too_large" };
      }
      chunks.push(chunk.value);
    }
  } catch {
    try {
      await reader.cancel("Could not read the request body.");
    } catch {
      // Preserve the controlled read error if cancellation also fails.
    }
    return { ok: false, reason: "read_error" };
  } finally {
    signal?.removeEventListener("abort", abort);
    reader.releaseLock();
  }

  if (aborted) return { ok: false, reason: "read_error" };

  const bytes = new Uint8Array(byteLength);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return { ok: true, bytes };
}
