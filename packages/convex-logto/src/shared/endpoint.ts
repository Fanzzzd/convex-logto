// Shared URL policy for the public config helpers, browser/native adapters, and
// the session component. Keep this module V8-safe, because the component
// imports it.

export type LogtoEndpointPolicy = {
  /**
   * Permit plain HTTP for a non-loopback Logto endpoint. This weakens OIDC
   * transport security and exists only for explicitly accepted self-hosted
   * compatibility constraints. Loopback HTTP works without this option.
   */
  allowInsecureHttp?: boolean;
};

export type LogtoPublicEndpointConfig = LogtoEndpointPolicy & {
  endpoint: string;
  appId: string;
};

function endpointError(message: string): Error {
  return new Error(`convex-logto: invalid Logto endpoint. ${message}`);
}

function isLoopbackHostname(hostname: string): boolean {
  // Accept the fully-qualified `localhost.` spelling too.
  const normalized = hostname.toLowerCase().replace(/\.$/, "");
  return (
    normalized === "localhost" ||
    normalized.endsWith(".localhost") ||
    /^127(?:\.\d{1,3}){3}$/.test(normalized) ||
    normalized === "[::1]"
  );
}

/**
 * Canonicalize a Logto base endpoint and enforce the package-wide trust policy.
 * The result has no trailing slash, query, fragment, or embedded credentials.
 */
export function normalizeLogtoEndpoint(
  endpoint: string,
  policy: LogtoEndpointPolicy = {},
): string {
  const input = endpoint.trim();
  let url: URL;
  try {
    url = new URL(input);
  } catch {
    throw endpointError(
      `Expected an absolute https: URL (or loopback http: URL).`,
    );
  }

  if (url.protocol !== "https:" && url.protocol !== "http:") {
    throw endpointError(
      `Expected an https: URL (or loopback http: URL), not ${url.protocol || "that scheme"}.`,
    );
  }
  if (url.username !== "" || url.password !== "") {
    throw endpointError(
      "Embedded username/password credentials are forbidden.",
    );
  }
  // URL.search/hash do not preserve an empty `?`/`#`, so inspect the original
  // input too. Literal delimiters in a URL path must be percent-encoded.
  if (
    url.search !== "" ||
    url.hash !== "" ||
    input.includes("?") ||
    input.includes("#")
  ) {
    throw endpointError("Query strings and fragments are forbidden.");
  }
  if (
    url.protocol === "http:" &&
    !isLoopbackHostname(url.hostname) &&
    policy.allowInsecureHttp !== true
  ) {
    throw endpointError(
      "Non-loopback HTTP is insecure; use HTTPS or set allowInsecureHttp: true.",
    );
  }

  const pathname = url.pathname.replace(/\/+$/, "");
  let decodedPathname = pathname;
  try {
    decodedPathname = decodeURIComponent(pathname);
  } catch {
    // Preserve URL's encoded pathname. Downstream servers reject malformed
    // percent escapes; this code does not try to read them as `/oidc`.
  }
  const decodedSegments = decodedPathname.replace(/\\/g, "/").split("/");
  const decodedLastSegment = decodedSegments[decodedSegments.length - 1] ?? "";
  if (decodedLastSegment.toLowerCase() === "oidc") {
    throw endpointError(
      'Use the Logto base URL, not the issuer URL ending in "/oidc".',
    );
  }

  url.pathname = pathname || "/";
  const canonical = url.toString();
  return pathname === "" ? canonical.slice(0, -1) : canonical;
}

/** Validate config crossing directly into a browser/native provider. */
export function normalizeLogtoPublicConfig(
  config: LogtoPublicEndpointConfig,
): LogtoPublicEndpointConfig {
  const appId = config.appId.trim();
  if (appId === "") {
    throw new Error("convex-logto: Logto appId must not be empty.");
  }
  return {
    endpoint: normalizeLogtoEndpoint(config.endpoint, config),
    appId,
    ...(config.allowInsecureHttp === true ? { allowInsecureHttp: true } : {}),
  };
}

/** Build a URL below the endpoint while preserving a reverse-proxy path prefix. */
export function buildLogtoEndpointUrl(
  endpoint: string,
  oidcPath: string,
  searchParams?: URLSearchParams,
): string {
  // The public config seam makes the compatibility decision. Revalidate
  // all structural safety properties here without losing an accepted HTTP
  // self-hosted endpoint as it crosses into the component.
  const normalized = normalizeLogtoEndpoint(endpoint, {
    allowInsecureHttp: true,
  });
  const url = new URL(normalized);
  const prefix = url.pathname.replace(/\/+$/, "");
  const suffix = oidcPath.replace(/^\/+|\/+$/g, "");
  url.pathname = `${prefix}/oidc${suffix === "" ? "" : `/${suffix}`}`;
  url.search = searchParams?.toString() ?? "";
  return url.toString();
}

/**
 * Validate an absolute URL on its own, right before browser/native navigation.
 * Authorization and end-session URLs carry queries by design.
 */
export function normalizeHttpNavigationUrl(
  value: string,
  description: string,
): string {
  let url: URL;
  try {
    url = new URL(value);
  } catch (error) {
    throw new Error(`convex-logto: refused an invalid ${description} URL.`, {
      cause: error,
    });
  }
  if (url.protocol !== "https:" && url.protocol !== "http:") {
    throw new Error(
      `convex-logto: refused a ${description} URL using the unsafe ${url.protocol || "unknown"} scheme.`,
    );
  }
  if (url.username !== "" || url.password !== "") {
    throw new Error(
      `convex-logto: refused a ${description} URL containing username/password credentials.`,
    );
  }
  return url.toString();
}
