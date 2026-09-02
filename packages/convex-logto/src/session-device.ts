import type { LogtoSessionDevicePublicKey } from "./session";

const DEVICE_KEY_DATABASE_VERSION = 1;
const DEVICE_KEY_STORE = "keys";
const DEVICE_KEY_ID = "ecdsa-p256";

/** Browser-side capability the framework-free session engine consumes. */
export type SessionDeviceBinding = {
  /** Open persistent storage and create the non-extractable key if needed. */
  prepare(): Promise<void>;
  /** Public half the component captures when it creates the session. */
  getPublicKey(): Promise<LogtoSessionDevicePublicKey>;
  /** Sign the rotating session token without exposing the private key. */
  sign(sessionToken: string): Promise<string>;
};

/**
 * Minimal persistence seam. IndexedDB in production, in-memory in unit tests.
 */
export type SessionDeviceKeyRepository = {
  read(): Promise<unknown>;
  /** Returns false when another tab won the first-write race. */
  add(keyPair: CryptoKeyPair): Promise<boolean>;
};

export class SessionDeviceBindingError extends Error {}

function unavailable(cause?: unknown): SessionDeviceBindingError {
  return new SessionDeviceBindingError(
    "convex-logto: device binding requires working IndexedDB to persist its " +
      "non-extractable key. Disable deviceBinding or make IndexedDB available; " +
      "the library never falls back to an unbound session.",
    cause === undefined ? undefined : { cause },
  );
}

function isCryptoKey(
  value: unknown,
  type: KeyType,
  usage: KeyUsage,
): value is CryptoKey {
  if (typeof value !== "object" || value === null) return false;
  if (!("algorithm" in value)) return false;
  const algorithm = value.algorithm;
  if (typeof algorithm !== "object" || algorithm === null) return false;
  return (
    "type" in value &&
    value.type === type &&
    "name" in algorithm &&
    algorithm.name === "ECDSA" &&
    "namedCurve" in algorithm &&
    algorithm.namedCurve === "P-256" &&
    "usages" in value &&
    Array.isArray(value.usages) &&
    value.usages.includes(usage)
  );
}

function isDeviceKeyPair(value: unknown): value is CryptoKeyPair {
  if (typeof value !== "object" || value === null) return false;
  if (!("privateKey" in value) || !("publicKey" in value)) return false;
  return (
    isCryptoKey(value.privateKey, "private", "sign") &&
    !value.privateKey.extractable &&
    isCryptoKey(value.publicKey, "public", "verify")
  );
}

function toBase64Url(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary)
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

async function generateDeviceKeyPair(): Promise<CryptoKeyPair> {
  const pair = await crypto.subtle.generateKey(
    { name: "ECDSA", namedCurve: "P-256" },
    false,
    ["sign", "verify"],
  );
  if (!isDeviceKeyPair(pair)) throw unavailable();
  return pair;
}

/**
 * ECDSA P-256 binding backed by a pluggable repository. The generated private
 * key is non-extractable; IndexedDB persists the CryptoKey through structured
 * cloning, never as exported key bytes.
 */
export class WebCryptoSessionDeviceBinding implements SessionDeviceBinding {
  private keyPair: Promise<CryptoKeyPair> | null = null;

  constructor(private repository: SessionDeviceKeyRepository) {}

  prepare(): Promise<void> {
    return this.loadKeyPair().then(() => undefined);
  }

  async getPublicKey(): Promise<LogtoSessionDevicePublicKey> {
    const { publicKey } = await this.loadKeyPair();
    const jwk = await crypto.subtle.exportKey("jwk", publicKey);
    if (
      jwk.kty !== "EC" ||
      jwk.crv !== "P-256" ||
      typeof jwk.x !== "string" ||
      typeof jwk.y !== "string"
    ) {
      throw unavailable();
    }
    return { kty: "EC", crv: "P-256", x: jwk.x, y: jwk.y };
  }

  async sign(sessionToken: string): Promise<string> {
    const { privateKey } = await this.loadKeyPair();
    const signature = await crypto.subtle.sign(
      { name: "ECDSA", hash: "SHA-256" },
      privateKey,
      new TextEncoder().encode(sessionToken),
    );
    return toBase64Url(new Uint8Array(signature));
  }

  private loadKeyPair(): Promise<CryptoKeyPair> {
    this.keyPair ??= this.loadKeyPairInner().catch((error: unknown) => {
      this.keyPair = null;
      throw error instanceof SessionDeviceBindingError
        ? error
        : unavailable(error);
    });
    return this.keyPair;
  }

  private async loadKeyPairInner(): Promise<CryptoKeyPair> {
    const existing = await this.repository.read();
    if (existing !== undefined) {
      if (!isDeviceKeyPair(existing)) throw unavailable();
      return existing;
    }

    const candidate = await generateDeviceKeyPair();
    if (await this.repository.add(candidate)) return candidate;

    // Another tab populated the key after our initial read. Adopt its winner
    // so every tab signs with the same device identity.
    const winner = await this.repository.read();
    if (!isDeviceKeyPair(winner)) throw unavailable();
    return winner;
  }
}

class IndexedDbDeviceKeyRepository implements SessionDeviceKeyRepository {
  constructor(
    private factory: IDBFactory | null,
    private databaseName: string,
  ) {}

  async read(): Promise<unknown> {
    const database = await this.open();
    try {
      return await new Promise((resolve, reject) => {
        const request = database
          .transaction(DEVICE_KEY_STORE, "readonly")
          .objectStore(DEVICE_KEY_STORE)
          .get(DEVICE_KEY_ID);
        request.onsuccess = () => {
          const result: unknown = request.result;
          resolve(result);
        };
        request.onerror = () => reject(request.error ?? unavailable());
      });
    } finally {
      database.close();
    }
  }

  async add(keyPair: CryptoKeyPair): Promise<boolean> {
    const database = await this.open();
    try {
      return await new Promise((resolve, reject) => {
        const transaction = database.transaction(DEVICE_KEY_STORE, "readwrite");
        const request = transaction
          .objectStore(DEVICE_KEY_STORE)
          .add(keyPair, DEVICE_KEY_ID);
        let alreadyStored = false;
        request.onerror = (event) => {
          // A key is already stored, so another tab won the race. Swallow the
          // error so the transaction still commits, and report the loss;
          // anything else must abort and reach the caller.
          if (request.error?.name !== "ConstraintError") return;
          event.preventDefault();
          event.stopPropagation();
          alreadyStored = true;
        };
        // Settle on the *transaction*, not the request. A commit-time abort
        // (`QuotaExceededError`) still undoes a successful `add`, and IndexedDB
        // reports it here and not on the request. Reporting the key as
        // persisted when it is not degrades the binding to this tab's memory.
        // The next reload generates a different key, the component rejects
        // every proof, and it deletes the session on sight. Failing instead
        // reaches the module's stated contract: no silent fallback.
        transaction.oncomplete = () => resolve(!alreadyStored);
        transaction.onabort = () => reject(transaction.error ?? unavailable());
        transaction.onerror = () => reject(transaction.error ?? unavailable());
      });
    } finally {
      database.close();
    }
  }

  private open(): Promise<IDBDatabase> {
    const factory = this.factory;
    if (factory === null) return Promise.reject(unavailable());
    return new Promise((resolve, reject) => {
      const request = factory.open(
        this.databaseName,
        DEVICE_KEY_DATABASE_VERSION,
      );
      request.onupgradeneeded = () => {
        if (!request.result.objectStoreNames.contains(DEVICE_KEY_STORE)) {
          request.result.createObjectStore(DEVICE_KEY_STORE);
        }
      };
      request.onsuccess = () => resolve(request.result);
      request.onerror = () => reject(request.error ?? unavailable());
      request.onblocked = () => reject(unavailable());
    });
  }
}

/** Create the deployment-namespaced IndexedDB-backed binding used by React. */
export function createSessionDeviceBinding(
  namespace: string,
  factory: IDBFactory | null = typeof indexedDB === "undefined"
    ? null
    : indexedDB,
): SessionDeviceBinding {
  return new WebCryptoSessionDeviceBinding(
    new IndexedDbDeviceKeyRepository(
      factory,
      `convex-logto:${namespace}:device-binding`,
    ),
  );
}
