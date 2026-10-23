import { describe, expect, it, vi } from "vitest";
import {
  JwksSyncError,
  checkJwks,
  syncJwks,
  type DeploymentEnv,
} from "./jwks-sync";

function rsa(kid: string, extra: Record<string, unknown> = {}) {
  return { kty: "RSA", n: `modulus-${kid}`, e: "AQAB", kid, ...extra };
}
const ec = { kty: "EC", crv: "P-384", x: "x", y: "y", kid: "ec-old" };

function memoryEnv(initial: Record<string, string> = {}) {
  const vars = new Map(Object.entries(initial));
  const set = vi.fn(async (name: string, value: string) => {
    vars.set(name, value);
  });
  const env: DeploymentEnv = {
    get: async (name) => vars.get(name),
    set,
  };
  return { env, vars, set };
}

function serving(keys: unknown[], status = 200) {
  return vi.fn(
    async (_url: string | URL | Request) =>
      new Response(JSON.stringify({ keys }), { status }),
  ) as unknown as typeof globalThis.fetch & ReturnType<typeof vi.fn>;
}

const ENDPOINT = { LOGTO_ENDPOINT: "https://auth.example.com" };

describe("syncJwks", () => {
  it("stores the RS256 keys of the deployment's own Logto", async () => {
    const { env, vars } = memoryEnv(ENDPOINT);
    const fetch = serving([rsa("new"), ec, rsa("ps", { alg: "PS256" })]);

    const result = await syncJwks({ env, fetch });

    expect(fetch).toHaveBeenCalledWith(
      "https://auth.example.com/oidc/jwks",
      expect.anything(),
    );
    expect(result).toMatchObject({
      jwksUrl: "https://auth.example.com/oidc/jwks",
      changed: true,
    });
    expect(JSON.parse(vars.get("LOGTO_JWKS")!)).toEqual({
      keys: [rsa("new")],
    });
  });

  it("leaves LOGTO_JWKS alone when it already matches", async () => {
    const { env, set } = memoryEnv(ENDPOINT);
    const fetch = serving([rsa("a")]);
    await syncJwks({ env, fetch });
    set.mockClear();

    const result = await syncJwks({ env, fetch });

    expect(result.changed).toBe(false);
    expect(set).not.toHaveBeenCalled();
  });

  it("keeps a reverse-proxy path prefix", async () => {
    const { env } = memoryEnv({
      LOGTO_ENDPOINT: "https://example.com/logto/",
    });
    const fetch = serving([rsa("a")]);
    await syncJwks({ env, fetch });
    expect(fetch).toHaveBeenCalledWith(
      "https://example.com/logto/oidc/jwks",
      expect.anything(),
    );
  });

  it("refuses non-loopback http unless allowed", async () => {
    const { env } = memoryEnv({ LOGTO_ENDPOINT: "http://logto.internal" });
    const fetch = serving([rsa("a")]);
    await expect(syncJwks({ env, fetch })).rejects.toThrow(/allowInsecureHttp/);
    await expect(
      syncJwks({ env, fetch, allowInsecureHttp: true }),
    ).resolves.toMatchObject({ changed: true });
  });

  it.each([
    [
      "LOGTO_ENDPOINT is unset",
      {},
      serving([rsa("a")]),
      /LOGTO_ENDPOINT is not set/,
    ],
    [
      "Logto serves only EC keys",
      ENDPOINT,
      serving([ec]),
      /no RSA key.*Rotate/,
    ],
    [
      "the JWKS request fails",
      ENDPOINT,
      serving([], 503),
      /Could not fetch the Logto JWKS/,
    ],
  ])("fails when %s, writing nothing", async (_, vars, fetch, message) => {
    const { env, set } = memoryEnv(vars);
    await expect(syncJwks({ env, fetch })).rejects.toThrow(message);
    await expect(syncJwks({ env, fetch })).rejects.toBeInstanceOf(
      JwksSyncError,
    );
    expect(set).not.toHaveBeenCalled();
  });

  it("refuses a key set larger than one Convex variable", async () => {
    const { env, set } = memoryEnv(ENDPOINT);
    const big = Array.from({ length: 24 }, (_, index) =>
      rsa(`k${index}`, { n: "x".repeat(400) + index }),
    );
    await expect(syncJwks({ env, fetch: serving(big) })).rejects.toThrow(
      /8 KiB/,
    );
    expect(set).not.toHaveBeenCalled();
  });
});

describe("checkJwks", () => {
  it("reports nothing missing right after a sync", async () => {
    const { env } = memoryEnv(ENDPOINT);
    const fetch = serving([rsa("a")]);
    await syncJwks({ env, fetch });
    await expect(checkJwks({ env, fetch })).resolves.toEqual({
      jwksUrl: "https://auth.example.com/oidc/jwks",
      missing: [],
      stale: [],
    });
  });

  it("names a rotated-in key as missing and a retired one as stale", async () => {
    const { env } = memoryEnv(ENDPOINT);
    await syncJwks({ env, fetch: serving([rsa("old")]) });

    const result = await checkJwks({
      env,
      fetch: serving([rsa("next"), rsa("current")]),
    });

    expect(result.missing).toEqual(["next", "current"]);
    expect(result.stale).toEqual(["old"]);
  });

  it("matches keys by modulus, not by kid", async () => {
    const { env } = memoryEnv({
      ...ENDPOINT,
      LOGTO_JWKS: JSON.stringify({ keys: [rsa("a", { kid: "renamed" })] }),
    });
    const result = await checkJwks({ env, fetch: serving([rsa("a")]) });
    expect(result).toMatchObject({ missing: [], stale: [] });
  });

  it("fails when LOGTO_JWKS is unset or unreadable", async () => {
    const fetch = serving([rsa("a")]);
    await expect(
      checkJwks({ env: memoryEnv(ENDPOINT).env, fetch }),
    ).rejects.toThrow(/LOGTO_JWKS is not set/);
    await expect(
      checkJwks({
        env: memoryEnv({ ...ENDPOINT, LOGTO_JWKS: "{" }).env,
        fetch,
      }),
    ).rejects.toThrow(/^LOGTO_JWKS is not valid JSON/);
  });
});
