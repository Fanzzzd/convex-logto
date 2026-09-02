import type {
  SessionAuthFlow,
  SessionStorageAdapter,
  StoredSession,
} from "./session-client";

type StoredTransaction = { state: string };
type StoredName = "session" | "idToken" | "txn";

/** Artifacts whose durable removal failure must keep reaching the caller. */
const CREDENTIAL_NAMES = new Set<StoredName>(["session", "idToken"]);

/** Structural subset of expo-secure-store used by native session mode. */
export type NativeSecureStore = {
  isAvailableAsync?(): Promise<boolean>;
  getItemAsync(key: string): Promise<string | null>;
  setItemAsync(key: string, value: string): Promise<void>;
  deleteItemAsync(key: string): Promise<void>;
};

/** Structural subset of expo-web-browser used by native session mode. */
export type NativeWebBrowser = {
  openAuthSessionAsync(
    url: string,
    redirectUrl?: string | null,
  ): Promise<{ type: string; url?: string }>;
};

export class NativeSessionStorageError extends Error {}

function storageError(cause?: unknown): NativeSessionStorageError {
  return new NativeSessionStorageError(
    "convex-logto: native session mode requires working expo-secure-store; " +
      "the library never downgrades session credentials to unencrypted storage.",
    cause === undefined ? undefined : { cause },
  );
}

/**
 * SecureStore keys accept only alphanumerics, `.`, `-`, and `_`. Encoding the
 * deployment namespace as fixed-width UTF-16 hex keeps keys valid and avoids
 * two Convex deployments sharing credentials on the same app install.
 */
function encodeNamespace(namespace: string): string {
  let encoded = "";
  for (let index = 0; index < namespace.length; index++) {
    encoded += namespace.charCodeAt(index).toString(16).padStart(4, "0");
  }
  return encoded || "empty";
}

/**
 * Async SecureStore adapter with a synchronous hydrated cache for the shared
 * SessionAuthEngine. Every engine transition awaits `flush()`, so a rotated
 * token is durable before it can be served or the browser flow can continue.
 */
export class NativeSessionStorageArea implements SessionStorageAdapter {
  private values = new Map<StoredName, string>();
  private preparation: Promise<void> | null = null;
  private pendingWrites: Promise<void> = Promise.resolve();
  private pendingWriteError: unknown;
  /**
   * Credential deletes SecureStore refused, kept until one lands.
   *
   * The flush that reports a write fault consumes it; the engine reacts once
   * and moves on. A *removal* fault is a different thing. The credential is
   * still on the device, so sign-out has not happened, and forgetting it after
   * one report would let every later flush claim success.
   */
  private pendingRemovals = new Map<StoredName, unknown>();
  private prefix: string;

  constructor(
    namespace: string,
    private secureStore: NativeSecureStore,
  ) {
    this.prefix = `convex-logto.native.${encodeNamespace(namespace)}`;
  }

  get sessionEventKey(): string {
    return this.key("session");
  }

  prepare(): Promise<void> {
    this.preparation ??= this.load().catch((error: unknown) => {
      this.preparation = null;
      throw error instanceof NativeSessionStorageError
        ? error
        : storageError(error);
    });
    return this.preparation;
  }

  async flush(): Promise<void> {
    await this.pendingWrites;
    if (this.pendingRemovals.size > 0) {
      // Fold any write fault into the same report and consume it. Reporting the
      // removals first is right, because a credential still on the device is
      // the worse failure, but leaving the write error queued behind them would
      // report it much later, long after the flush it belonged to.
      const causes: unknown[] = [...this.pendingRemovals.values()];
      if (this.pendingWriteError !== undefined) {
        causes.push(this.pendingWriteError);
        this.pendingWriteError = undefined;
      }
      throw storageError(causes);
    }
    if (this.pendingWriteError !== undefined) {
      const cause = this.pendingWriteError;
      this.pendingWriteError = undefined;
      throw storageError(cause);
    }
  }

  readSession(): StoredSession | null {
    const value = this.read("session");
    return value !== null &&
      typeof value === "object" &&
      "token" in value &&
      typeof value.token === "string" &&
      "sessionId" in value &&
      typeof value.sessionId === "string"
      ? { token: value.token, sessionId: value.sessionId }
      : null;
  }

  writeSession(session: StoredSession): void {
    this.write("session", session);
  }

  readIdToken(): string | null {
    const value = this.read("idToken");
    return typeof value === "string" ? value : null;
  }

  writeIdToken(idToken: string): void {
    this.write("idToken", idToken);
  }

  stashTransaction(transaction: StoredTransaction): void {
    this.write("txn", transaction);
  }

  takeTransaction(): StoredTransaction | null {
    const value = this.read("txn");
    this.remove("txn");
    return value !== null &&
      typeof value === "object" &&
      "state" in value &&
      typeof value.state === "string"
      ? { state: value.state }
      : null;
  }

  clearAll(): void {
    this.remove("session");
    this.remove("idToken");
    this.remove("txn");
  }

  clearIdToken(): void {
    this.remove("idToken");
  }

  private key(name: StoredName): string {
    return `${this.prefix}.${name}`;
  }

  private async load(): Promise<void> {
    if (
      this.secureStore.isAvailableAsync !== undefined &&
      !(await this.secureStore.isAvailableAsync())
    ) {
      throw storageError();
    }
    const names = ["session", "idToken", "txn"] as const;
    const stored = await Promise.all(
      names.map(async (name) => {
        try {
          return await this.secureStore.getItemAsync(this.key(name));
        } catch {
          // One unreadable key is not a broken store. A locked device, or an
          // entry written under a stricter keychain accessibility class, fails
          // only its own read. Treat it as absent for now and leave it in
          // place. Failing the whole load, or deleting the key, would cost the
          // user a session over a condition that clears by itself on the next
          // unlock.
          return null;
        }
      }),
    );
    for (let index = 0; index < names.length; index++) {
      const name = names[index];
      const raw = stored[index];
      if (name !== undefined && raw !== null && raw !== undefined) {
        this.values.set(name, raw);
      }
    }
  }

  private read(name: StoredName): unknown {
    const raw = this.values.get(name);
    if (raw === undefined) return null;
    try {
      const value: unknown = JSON.parse(raw);
      return value;
    } catch {
      return null;
    }
  }

  private write(name: StoredName, value: unknown): void {
    const raw = JSON.stringify(value);
    // Keep the synchronous cache ahead on purpose if the durable write later
    // fails. Rolling it back would make this live process reuse the superseded
    // rotating token (and trigger reuse-kill after the grace window); only a
    // cold start sees the older durable value, and it re-authenticates from
    // that.
    this.values.set(name, raw);
    this.enqueue(() => this.secureStore.setItemAsync(this.key(name), raw));
  }

  private remove(name: StoredName): void {
    this.values.delete(name);
    this.enqueue(async () => {
      try {
        await this.secureStore.deleteItemAsync(this.key(name));
        this.pendingRemovals.delete(name);
      } catch (error) {
        // A spent `txn` stash holds the OIDC `state` string, not a bearer, so
        // it stays on the ordinary write-fault path. A credential that survived
        // its delete is the case the flush has to keep reporting.
        if (!CREDENTIAL_NAMES.has(name)) throw error;
        this.pendingRemovals.set(name, error);
      }
    });
  }

  private enqueue(operation: () => Promise<void>): void {
    this.pendingWrites = this.pendingWrites
      .then(operation)
      .catch((error: unknown) => {
        this.pendingWriteError ??= error;
      });
  }
}

/** Adapt Expo's system-browser result into the shared engine's auth-flow seam. */
export function createNativeSessionAuthFlow(
  redirectUri: string,
  webBrowser: NativeWebBrowser,
): SessionAuthFlow {
  if (!redirectUri.trim()) {
    throw new Error(
      "convex-logto: native session mode requires a non-empty redirectUri.",
    );
  }
  return {
    redirectUri,
    async openAuthorization(url) {
      const result = await webBrowser.openAuthSessionAsync(url, redirectUri);
      if (result.type !== "success") return null;
      if (typeof result.url !== "string") {
        throw new Error(
          "convex-logto: expo-web-browser returned success without a redirect URL.",
        );
      }
      return result.url;
    },
    async openEndSession(url, returnUrl) {
      await webBrowser.openAuthSessionAsync(url, returnUrl);
    },
  };
}
