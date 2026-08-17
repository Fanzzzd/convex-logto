import { afterEach, beforeEach, describe, expect, it } from "vitest";
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
