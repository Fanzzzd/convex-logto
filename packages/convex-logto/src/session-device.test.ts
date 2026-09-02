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

/**
 * The narrowest IndexedDB that can model a commit-time abort. A request that
 * succeeds, followed by a transaction that does not.
 */
function fakeIndexedDb(options: {
  abortCommitWith?: string;
  occupied?: boolean;
}): IDBFactory {
  const stored = new Map<string, unknown>();
  if (options.occupied) stored.set("device-key", { winner: true });
  const fire = (handler: unknown, event: unknown) => {
    if (typeof handler === "function") handler(event);
  };
  const database = {
    objectStoreNames: { contains: () => true },
    close: () => undefined,
    transaction: (_store: string, mode: string) => {
      const transaction: Record<string, unknown> = { error: null };
      transaction["objectStore"] = () => ({
        get: (key: string) => {
          const request: Record<string, unknown> = { result: stored.get(key) };
          queueMicrotask(() => fire(request["onsuccess"], { target: request }));
          return request;
        },
        add: (value: unknown, key: string) => {
          const request: Record<string, unknown> = { error: null };
          queueMicrotask(() => {
            if (stored.has(key)) {
              request["error"] = { name: "ConstraintError" };
              fire(request["onerror"], {
                preventDefault: () => undefined,
                stopPropagation: () => undefined,
              });
            } else {
              stored.set(key, value);
              fire(request["onsuccess"], { target: request });
            }
            queueMicrotask(() => {
              if (
                options.abortCommitWith !== undefined &&
                mode === "readwrite"
              ) {
                stored.delete(key);
                transaction["error"] = { name: options.abortCommitWith };
                fire(transaction["onabort"], {});
                return;
              }
              fire(transaction["oncomplete"], {});
            });
          });
          return request;
        },
      });
      return transaction;
    },
  };
  return {
    open: () => {
      const request: Record<string, unknown> = { result: database };
      queueMicrotask(() => fire(request["onsuccess"], { target: request }));
      return request;
    },
  } as unknown as IDBFactory;
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

  it("fails loudly when the key's transaction aborts at commit", async () => {
    // IndexedDB reports a quota failure on the transaction, after the `add`
    // request has already succeeded. Believing the request would leave the key
    // in this tab's memory only. The next reload generates a different one, and
    // the component rejects every device proof and deletes the session.
    const binding = createSessionDeviceBinding(
      "deployment",
      fakeIndexedDb({ abortCommitWith: "QuotaExceededError" }),
    );

    await expect(binding.prepare()).rejects.toBeInstanceOf(
      SessionDeviceBindingError,
    );
  });

  it("adopts another tab's key when the add loses the race", async () => {
    // The repository swallows a ConstraintError so the transaction still
    // commits, and the caller re-reads the winner instead of failing.
    const binding = createSessionDeviceBinding(
      "deployment",
      fakeIndexedDb({ occupied: true }),
    );

    await expect(binding.prepare()).resolves.toBeUndefined();
  });

  it("defers an unavailable IndexedDB failure until preparation", async () => {
    expect(window).toBeDefined();
    const binding = createSessionDeviceBinding("deployment", null);

    await expect(binding.prepare()).rejects.toBeInstanceOf(
      SessionDeviceBindingError,
    );
  });
});
