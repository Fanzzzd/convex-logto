// @vitest-environment happy-dom

import { describe, expect, it } from "vitest";
import { verifyDeviceProof } from "./component/core";
import {
  SessionDeviceBindingError,
  WebCryptoSessionDeviceBinding,
  createSessionDeviceBinding,
  type SessionDeviceKeyRepository,
} from "./session-device";

function memoryRepository(): SessionDeviceKeyRepository & {
  stored: CryptoKeyPair | undefined;
} {
  return {
    stored: undefined,
    async read() {
      return this.stored;
    },
    async add(keyPair) {
      if (this.stored !== undefined) return false;
      this.stored = keyPair;
      return true;
    },
  };
}

describe("WebCryptoSessionDeviceBinding", () => {
  it("persists a non-extractable P-256 key and signs a verifiable token proof", async () => {
    const repository = memoryRepository();
    const binding = new WebCryptoSessionDeviceBinding(repository);
    await binding.prepare();

    expect(repository.stored?.privateKey.extractable).toBe(false);
    expect(repository.stored?.privateKey.algorithm).toMatchObject({
      name: "ECDSA",
      namedCurve: "P-256",
    });

    const publicKey = await binding.getPublicKey();
    const proof = await binding.sign("one-time-session-token");
    await expect(
      verifyDeviceProof({
        publicKey,
        sessionToken: "one-time-session-token",
        proof,
      }),
    ).resolves.toBe(true);

    // A fresh binding instance (another tab/reload) adopts the persisted key.
    const reloaded = new WebCryptoSessionDeviceBinding(repository);
    await expect(reloaded.getPublicKey()).resolves.toEqual(publicKey);
  });

  it("defers an unavailable IndexedDB failure until preparation", async () => {
    expect(window).toBeDefined();
    const binding = createSessionDeviceBinding("deployment", null);

    await expect(binding.prepare()).rejects.toBeInstanceOf(
      SessionDeviceBindingError,
    );
  });
});
