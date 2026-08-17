import { describe, expect, it, vi } from "vitest";
import { readBoundedBody } from "./http_body";

const encoder = new TextEncoder();

function streamedRequest(
  chunks: readonly Uint8Array[],
  options?: {
    contentLength?: string;
    failAfterChunks?: number;
    cancel?: (reason: unknown) => void;
  },
): Request {
  let index = 0;
  const stream = new ReadableStream<Uint8Array>({
    pull(controller) {
      if (options?.failAfterChunks === index) {
        controller.error(new Error("stream failed"));
        return;
      }
      const chunk = chunks[index];
      if (chunk === undefined) {
        controller.close();
        return;
      }
      index += 1;
      controller.enqueue(chunk);
    },
    cancel(reason) {
      options?.cancel?.(reason);
    },
  });
  const headers = new Headers();
  if (options?.contentLength !== undefined) {
    headers.set("Content-Length", options.contentLength);
  }
  return new Request("https://convex.example/body", {
    method: "POST",
    headers,
    body: stream,
    // Node's fetch implementation requires this for a streaming request body;
    // browsers and Convex ignore the extra standard-fetch implementation hint.
    duplex: "half",
  } as RequestInit);
}

describe("readBoundedBody", () => {
  it("accepts an exact-cap body without a Content-Length header", async () => {
    const request = streamedRequest([
      encoder.encode("123"),
      encoder.encode("45678"),
    ]);

    const result = await readBoundedBody(request, 8);

    expect(result.ok).toBe(true);
    if (result.ok)
      expect(new TextDecoder().decode(result.bytes)).toBe("12345678");
  });

  it("counts actual chunks when Content-Length is falsely small", async () => {
    const cancel = vi.fn();
    const request = streamedRequest(
      [encoder.encode("1234"), encoder.encode("5")],
      {
        contentLength: "1",
        cancel,
      },
    );

    await expect(readBoundedBody(request, 4)).resolves.toEqual({
      ok: false,
      reason: "too_large",
    });
    expect(cancel).toHaveBeenCalledTimes(1);
  });

  it("rejects on the first byte over the cap and cancels before later chunks", async () => {
    const cancel = vi.fn();
    const request = streamedRequest(
      [encoder.encode("1234"), encoder.encode("5"), encoder.encode("unread")],
      { cancel },
    );

    await expect(readBoundedBody(request, 4)).resolves.toEqual({
      ok: false,
      reason: "too_large",
    });
    expect(cancel).toHaveBeenCalledTimes(1);
  });

  it("uses a truthful oversized Content-Length only as a fast rejection", async () => {
    const cancel = vi.fn();
    const request = streamedRequest([encoder.encode("not read")], {
      contentLength: "999",
      cancel,
    });

    await expect(readBoundedBody(request, 8)).resolves.toEqual({
      ok: false,
      reason: "too_large",
    });
    expect(cancel).toHaveBeenCalledTimes(1);
  });

  it("turns a stream failure into a controlled read error", async () => {
    const cancel = vi.fn();
    const request = streamedRequest([encoder.encode("1234")], {
      failAfterChunks: 1,
      cancel,
    });

    await expect(readBoundedBody(request, 8)).resolves.toEqual({
      ok: false,
      reason: "read_error",
    });
  });
});
