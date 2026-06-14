import { createHmac } from "node:crypto";
import { describe, expect, it } from "vitest";
import { verifyLogtoSignature } from "./webhooks";

const signingKey = "whsec_test_signing_key_1234567890";
const body = JSON.stringify({
  hookId: "h1",
  event: "User.Created",
  createdAt: "2026-06-14T00:00:00.000Z",
  data: { id: "user_abc", primaryEmail: "a@b.com", name: "Ada" },
});

const sign = (key: string, payload: Buffer | string) =>
  createHmac("sha256", key).update(payload).digest("hex");

describe("verifyLogtoSignature", () => {
  it("accepts a correct signature", async () => {
    expect(
      await verifyLogtoSignature(signingKey, body, sign(signingKey, body)),
    ).toBe(true);
  });

  it("accepts uppercase hex (Web Crypto emits lowercase)", async () => {
    expect(
      await verifyLogtoSignature(
        signingKey,
        body,
        sign(signingKey, body).toUpperCase(),
      ),
    ).toBe(true);
  });

  it("verifies non-ASCII bodies over the exact bytes", async () => {
    // The webhook route hands raw bytes (request.arrayBuffer()); Logto signs
    // those bytes, so re-encoding a decoded string must not change the result.
    const unicode = JSON.stringify({
      event: "User.Created",
      data: { id: "u1", name: "测试🚀" },
    });
    const bytes = Buffer.from(unicode, "utf8");
    const arrayBuffer = new Uint8Array(bytes).buffer; // exact bytes, as request.arrayBuffer() yields
    expect(
      await verifyLogtoSignature(
        signingKey,
        arrayBuffer,
        sign(signingKey, bytes),
      ),
    ).toBe(true);
  });

  it("rejects a tampered body", async () => {
    expect(
      await verifyLogtoSignature(
        signingKey,
        body + " ",
        sign(signingKey, body),
      ),
    ).toBe(false);
  });

  it("rejects a wrong signing key", async () => {
    expect(
      await verifyLogtoSignature(signingKey, body, sign("other_key", body)),
    ).toBe(false);
  });

  it("rejects an empty signature", async () => {
    expect(await verifyLogtoSignature(signingKey, body, "")).toBe(false);
  });
});
