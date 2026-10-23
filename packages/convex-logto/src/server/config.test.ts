import { afterEach, beforeAll, beforeEach, describe, expect, it } from "vitest";
import { logtoAuthConfig, logtoConfigQuery } from "./config";

function restoreEnv(key: string, value: string | undefined) {
  if (value === undefined) delete process.env[key];
  else process.env[key] = value;
}

describe("logtoAuthConfig", () => {
  const saved = {
    endpoint: process.env.LOGTO_ENDPOINT,
    appId: process.env.LOGTO_APP_ID,
  };
  beforeEach(() => {
    delete process.env.LOGTO_ENDPOINT;
    delete process.env.LOGTO_APP_ID;
  });
  afterEach(() => {
    restoreEnv("LOGTO_ENDPOINT", saved.endpoint);
    restoreEnv("LOGTO_APP_ID", saved.appId);
  });

  it("builds { domain: `${endpoint}/oidc`, applicationID } from explicit options", () => {
    expect(
      logtoAuthConfig({
        endpoint: "https://auth.example.com",
        appId: "app123",
      }),
    ).toEqual({
      domain: "https://auth.example.com/oidc",
      applicationID: "app123",
    });
  });

  it("reads LOGTO_ENDPOINT / LOGTO_APP_ID from the environment", () => {
    process.env.LOGTO_ENDPOINT = "https://env.example.com";
    process.env.LOGTO_APP_ID = "env-app";
    expect(logtoAuthConfig()).toEqual({
      domain: "https://env.example.com/oidc",
      applicationID: "env-app",
    });
  });

  it("lets explicit options override the environment", () => {
    process.env.LOGTO_ENDPOINT = "https://env.example.com";
    process.env.LOGTO_APP_ID = "env-app";
    expect(
      logtoAuthConfig({
        endpoint: "https://opt.example.com",
        appId: "opt-app",
      }),
    ).toEqual({
      domain: "https://opt.example.com/oidc",
      applicationID: "opt-app",
    });
  });

  it("strips one or more trailing slashes from the endpoint", () => {
    expect(
      logtoAuthConfig({ endpoint: "https://x.com/", appId: "a" }).domain,
    ).toBe("https://x.com/oidc");
    expect(
      logtoAuthConfig({ endpoint: "https://x.com///", appId: "a" }).domain,
    ).toBe("https://x.com/oidc");
  });

  it("trims surrounding whitespace from endpoint and appId", () => {
    expect(
      logtoAuthConfig({ endpoint: "  https://x.com  ", appId: "  a  " }),
    ).toEqual({ domain: "https://x.com/oidc", applicationID: "a" });
  });

  it("throws naming LOGTO_ENDPOINT when the endpoint is missing", () => {
    expect(() => logtoAuthConfig({ appId: "a" })).toThrow(/LOGTO_ENDPOINT/);
  });

  it("throws naming LOGTO_APP_ID when the appId is missing", () => {
    expect(() => logtoAuthConfig({ endpoint: "https://x.com" })).toThrow(
      /LOGTO_APP_ID/,
    );
  });

  it("names both when endpoint and appId are missing", () => {
    expect(() => logtoAuthConfig()).toThrow(/LOGTO_ENDPOINT and LOGTO_APP_ID/);
  });

  it("treats a whitespace-only endpoint as missing", () => {
    expect(() => logtoAuthConfig({ endpoint: "   ", appId: "a" })).toThrow(
      /LOGTO_ENDPOINT/,
    );
  });

  it("rejects an endpoint that already ends in /oidc (common paste error)", () => {
    expect(() =>
      logtoAuthConfig({ endpoint: "https://x.com/oidc", appId: "a" }),
    ).toThrow(/\/oidc/);
  });

  it("rejects /oidc even with a trailing slash (slash is stripped first)", () => {
    expect(() =>
      logtoAuthConfig({ endpoint: "https://x.com/oidc/", appId: "a" }),
    ).toThrow(/\/oidc/);
  });

  it("rejects a percent-encoded trailing /oidc path segment", () => {
    expect(() =>
      logtoAuthConfig({
        endpoint: "https://x.com/reverse-proxy%2Foidc",
        appId: "a",
      }),
    ).toThrow(/\/oidc/);
  });

  it("preserves a normalized reverse-proxy path prefix", () => {
    expect(
      logtoAuthConfig({
        endpoint: "https://auth.example.com/logto/../tenant-a///",
        appId: "a",
      }).domain,
    ).toBe("https://auth.example.com/tenant-a/oidc");
  });

  it.each(["javascript:alert(1)", "data:text/plain,hello", "ftp://x.com"])(
    "rejects a non-HTTP endpoint: %s",
    (endpoint) => {
      expect(() => logtoAuthConfig({ endpoint, appId: "a" })).toThrow(
        /https?:/i,
      );
    },
  );

  it.each([
    "https://alice@auth.example.com",
    "https://alice:secret@auth.example.com",
  ])("rejects endpoint credentials: %s", (endpoint) => {
    expect(() => logtoAuthConfig({ endpoint, appId: "a" })).toThrow(
      /credentials/i,
    );
  });

  it.each([
    "https://auth.example.com?tenant=a",
    "https://auth.example.com#tenant-a",
    "https://auth.example.com?",
    "https://auth.example.com#",
  ])("rejects endpoint query strings and fragments: %s", (endpoint) => {
    expect(() => logtoAuthConfig({ endpoint, appId: "a" })).toThrow(
      /query|fragment/i,
    );
  });

  it.each([
    "http://localhost:3001",
    "http://localhost.:3001",
    "http://tenant.localhost:3001/logto",
    "http://127.0.0.42:3001",
    "http://[::1]:3001",
  ])("allows HTTP only for loopback by default: %s", (endpoint) => {
    expect(logtoAuthConfig({ endpoint, appId: "a" }).domain).toMatch(
      /^http:\/\//,
    );
  });

  it("requires an explicit opt-in for non-loopback HTTP", () => {
    expect(() =>
      logtoAuthConfig({ endpoint: "http://logto.internal", appId: "a" }),
    ).toThrow(/allowInsecureHttp/);
    expect(
      logtoAuthConfig({
        endpoint: "http://logto.internal/logto",
        appId: "a",
        allowInsecureHttp: true,
      }).domain,
    ).toBe("http://logto.internal/logto/oidc");
  });

  it("does not mistake a DNS name starting with 127 for an IPv4 loopback", () => {
    expect(() =>
      logtoAuthConfig({ endpoint: "http://127.example.com", appId: "a" }),
    ).toThrow(/allowInsecureHttp/);
  });
});

describe("logtoAuthConfig with a static JWKS", () => {
  const connection = { endpoint: "https://auth.example.com", appId: "app123" };
  let rsaKey: JsonWebKey & { kid: string };
  let ecKey: JsonWebKey & { kid: string };

  beforeAll(async () => {
    const rsa = await crypto.subtle.generateKey(
      {
        name: "RSASSA-PKCS1-v1_5",
        modulusLength: 2048,
        publicExponent: new Uint8Array([1, 0, 1]),
        hash: "SHA-256",
      },
      true,
      ["sign", "verify"],
    );
    const ec = await crypto.subtle.generateKey(
      { name: "ECDSA", namedCurve: "P-384" },
      true,
      ["sign", "verify"],
    );
    const { kty, n, e } = await crypto.subtle.exportKey("jwk", rsa.publicKey);
    rsaKey = { kty, n, e, kid: "rsa-1", alg: "RS256", use: "sig" };
    const { crv, x, y } = await crypto.subtle.exportKey("jwk", ec.publicKey);
    ecKey = { kty: "EC", crv, x, y, kid: "ec-1", alg: "ES384", use: "sig" };
  });

  function decodeDataUri(uri: string): unknown {
    const prefix = "data:text/plain;charset=utf-8;base64,";
    expect(uri.startsWith(prefix)).toBe(true);
    return JSON.parse(
      Buffer.from(uri.slice(prefix.length), "base64").toString(),
    );
  }

  it("returns a customJwt provider with the discovery mode's issuer", () => {
    const provider = logtoAuthConfig({
      ...connection,
      jwks: JSON.stringify({ keys: [rsaKey] }),
    });
    expect(provider).toMatchObject({
      type: "customJwt",
      issuer: logtoAuthConfig(connection).domain,
      applicationID: "app123",
      algorithm: "RS256",
    });
    expect(decodeDataUri(provider.jwks)).toEqual({ keys: [rsaKey] });
  });

  it("inlines only the keys that can verify RS256", () => {
    const provider = logtoAuthConfig({
      ...connection,
      jwks: JSON.stringify({
        keys: [
          ecKey,
          rsaKey,
          { ...rsaKey, kid: "ps", alg: "PS256" },
          { ...rsaKey, kid: "enc", use: "enc" },
        ],
      }),
    });
    expect(decodeDataUri(provider.jwks)).toEqual({ keys: [rsaKey] });
  });

  it("falls back to discovery when jwks is undefined", () => {
    expect(logtoAuthConfig({ ...connection, jwks: undefined })).toEqual({
      domain: "https://auth.example.com/oidc",
      applicationID: "app123",
    });
  });

  it("still requires LOGTO_ENDPOINT and LOGTO_APP_ID", () => {
    expect(() =>
      logtoAuthConfig({ jwks: JSON.stringify({ keys: [rsaKey] }) }),
    ).toThrow(/LOGTO_ENDPOINT and LOGTO_APP_ID/);
  });

  it.each([
    ["an empty string", "  ", /LOGTO_JWKS is empty/],
    ["text that is not JSON", "not json", /LOGTO_JWKS is not valid JSON/],
    ["JSON that is not a JWKS", "[]", /LOGTO_JWKS is not a JWKS/],
  ])("throws naming LOGTO_JWKS for %s", (_, jwks, message) => {
    expect(() => logtoAuthConfig({ ...connection, jwks })).toThrow(message);
  });

  it("throws naming LOGTO_JWKS when no key can verify RS256", () => {
    expect(() =>
      logtoAuthConfig({
        ...connection,
        jwks: JSON.stringify({ keys: [ecKey] }),
      }),
    ).toThrow(
      /LOGTO_JWKS holds no RSA key.*rotate its OIDC signing key to RSA/s,
    );
  });
});

describe("logtoConfigQuery", () => {
  it("constructs without reading the environment (lazy until the handler runs)", () => {
    const saved = process.env.LOGTO_ENDPOINT;
    delete process.env.LOGTO_ENDPOINT;
    // Defining the query must not throw even with the env unset.
    expect(() => logtoConfigQuery()).not.toThrow();
    expect(logtoConfigQuery()).toBeDefined();
    restoreEnv("LOGTO_ENDPOINT", saved);
  });

  it("propagates an explicit insecure-HTTP policy to runtime-loaded config", () => {
    const query = logtoConfigQuery({
      endpoint: "http://logto.internal/prefix/",
      appId: "app-1",
      allowInsecureHttp: true,
    });
    const handler = (
      query as unknown as Record<
        string,
        () => {
          endpoint: string;
          appId: string;
          allowInsecureHttp?: boolean;
        }
      >
    )["_handler"]!;

    expect(handler()).toEqual({
      endpoint: "http://logto.internal/prefix",
      appId: "app-1",
      allowInsecureHttp: true,
    });
  });
});
