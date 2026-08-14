import type {
  SessionAuthFlow,
  SessionStorageAdapter,
  StoredSession,
} from "./session-client";

type StoredTransaction = { state: string };
type StoredName = "session" | "idToken" | "txn";

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
      "session credentials are never downgraded to unencrypted storage.",
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
    if (this.pendingWriteError !== undefined) {
      const cause = this.pendingWriteError;
      this.pendingWriteError = undefined;
      throw storageError(cause);
    }
  }

  readSession(): StoredSession | null {
    const value = this.read<StoredSession>("session");
    return value &&
      typeof value.token === "string" &&
      typeof value.sessionId === "string"
      ? value
      : null;
  }

  writeSession(session: StoredSession): void {
    this.write("session", session);
  }

  readIdToken(): string | null {
    const value = this.read<unknown>("idToken");
    return typeof value === "string" ? value : null;
  }

  writeIdToken(idToken: string): void {
    this.write("idToken", idToken);
  }

  stashTransaction(transaction: StoredTransaction): void {
    this.write("txn", transaction);
  }

  takeTransaction(): StoredTransaction | null {
    const value = this.read<StoredTransaction>("txn");
    this.remove("txn");
    return value && typeof value.state === "string" ? value : null;
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
      names.map((name) => this.secureStore.getItemAsync(this.key(name))),
    );
    for (let index = 0; index < names.length; index++) {
      const raw = stored[index];
      if (raw !== null && raw !== undefined) {
        this.values.set(names[index]!, raw);
      }
    }
  }

  private read<T>(name: StoredName): T | null {
    const raw = this.values.get(name);
    if (raw === undefined) return null;
    try {
      return JSON.parse(raw) as T;
    } catch {
      return null;
    }
  }

  private write(name: StoredName, value: unknown): void {
    const raw = JSON.stringify(value);
    this.values.set(name, raw);
    this.enqueue(() => this.secureStore.setItemAsync(this.key(name), raw));
  }

  private remove(name: StoredName): void {
    this.values.delete(name);
    this.enqueue(() => this.secureStore.deleteItemAsync(this.key(name)));
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
