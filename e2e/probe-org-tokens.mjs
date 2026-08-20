// Answer, against a real Logto, the questions the organization-token design
// cannot be settled without (issue #206):
//
//   1. Do organization membership and organization *roles* really arrive in the
//      ID token, or does reading a role require an organization token?
//   2. Does the organization-token grant return an `id_token` alongside the
//      organization access token?
//   3. Does it rotate the refresh token?
//   4. Does a resource token have to be asked for at *authorization* time, or
//      can it be requested later from a grant that never mentioned it?
//
// (3) is the one that decides the shape of the feature. Session mode's central
// invariant is that a Logto refresh token is never presented twice, enforced by
// a single claimed `refresh` grant. If the organization grant rotates, it is a
// second consumer of that token and must go through the same claim; if it does
// not, it can run beside the claim and never touch it.
//
// Documentation cannot answer these — only the deployment can. So this asks it.
//
//   node probe-org-tokens.mjs
//
// Needs the provisioned environment (`set -a; . ./.env.e2e; set +a`) plus the
// Management API credentials from provision.mjs:
//
//   LOGTO_M2M_APP_ID, LOGTO_M2M_APP_SECRET, optionally LOGTO_ADMIN_ENDPOINT.
//
// Prints findings, never tokens: every token here is a live credential, and a
// terminal is a scrollback buffer. The full decoded claims go to
// `.probe-org-tokens.json` (mode 0600, gitignored) for reading afterwards.

import { writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { createHash, randomBytes } from "node:crypto";
import { chromium } from "playwright-core";

const endpoint = trimSlash(need("LOGTO_ENDPOINT"));
const adminEndpoint = trimSlash(process.env.LOGTO_ADMIN_ENDPOINT ?? endpoint);
const appId = need("LOGTO_SESSION_APP_ID");
const appSecret = need("LOGTO_APP_SECRET");
const m2mId = need("LOGTO_M2M_APP_ID");
const m2mSecret = need("LOGTO_M2M_APP_SECRET");
const email = need("E2E_USER_EMAIL");
const password = need("E2E_USER_PASSWORD");
const webOrigin = trimSlash(process.env.E2E_WEB_ORIGIN ?? "http://localhost:5174");
const redirectUri = `${webOrigin}/callback`;
const headless = process.env.E2E_HEADED !== "1";
const reportPath = fileURLToPath(new URL("./.probe-org-tokens.json", import.meta.url));

const ORG_NAME = "convex-logto-e2e-org";
const ORG_ROLE = "convex-logto-e2e-admin";
const ORG_SCOPE = "e2e:manage";
const RESOURCE_NAME = "convex-logto-e2e-resource";
const RESOURCE_INDICATOR = "https://e2e.convex-logto.test/api";
const RESOURCE_SCOPE = "e2e:read";
const USER_ROLE = "convex-logto-e2e-user";

function trimSlash(value) {
  return value.replace(/\/+$/, "");
}

function need(name) {
  const value = process.env[name];
  if (!value) {
    console.error(
      `probe-org-tokens: ${name} is required.\n` +
        "Run provision.mjs, then `set -a; . ./.env.e2e; set +a`, and export the\n" +
        "Management API credentials you gave provision.mjs.",
    );
    process.exit(1);
  }
  return value;
}

function decodeJwt(token) {
  const [header, payload] = token.split(".");
  const json = (part) =>
    JSON.parse(Buffer.from(part.replace(/-/g, "+").replace(/_/g, "/"), "base64").toString());
  return { header: json(header), payload: json(payload) };
}

/** A stable, non-reversible handle, so "did it change?" is answerable in a log. */
function fingerprint(token) {
  return createHash("sha256").update(token).digest("hex").slice(0, 12);
}

// ---------------------------------------------------------------- Management API

async function managementToken() {
  const res = await fetch(`${adminEndpoint}/oidc/token`, {
    method: "POST",
    headers: {
      Authorization: `Basic ${btoa(`${m2mId}:${m2mSecret}`)}`,
      "Content-Type": "application/x-www-form-urlencoded",
    },
    body: new URLSearchParams({
      grant_type: "client_credentials",
      resource: "https://default.logto.app/api",
      scope: "all",
    }),
  });
  if (!res.ok) {
    throw new Error(`management token (${res.status}): ${await res.text()}`);
  }
  return (await res.json()).access_token;
}

function api(token) {
  return async (path, init = {}) => {
    const res = await fetch(`${endpoint}/api${path}`, {
      ...init,
      headers: {
        Authorization: `Bearer ${token}`,
        "Content-Type": "application/json",
        ...(init.headers ?? {}),
      },
    });
    if (!res.ok) {
      throw new Error(`${init.method ?? "GET"} ${path} → ${res.status}: ${await res.text()}`);
    }
    return res.status === 204 ? null : await res.json();
  };
}

async function findPaged(call, path, match, { pageSize = 100, maxPages = 50 } = {}) {
  const separator = path.includes("?") ? "&" : "?";
  for (let page = 1; page <= maxPages; page += 1) {
    const items = await call(`${path}${separator}page=${page}&page_size=${pageSize}`);
    const hit = items.find(match);
    if (hit) return hit;
    if (items.length < pageSize) return undefined;
  }
  throw new Error(`${path}: scanned ${maxPages} pages without an answer.`);
}

/**
 * Everything below is find-or-create for the same reason provision.mjs is: this
 * gets rerun while the questions are being refined, and a probe that only works
 * on a clean tenant is a probe that works once.
 */
async function ensureOrganization(call, userId) {
  const org =
    (await findPaged(call, "/organizations", (o) => o.name === ORG_NAME)) ??
    (await call("/organizations", {
      method: "POST",
      body: JSON.stringify({
        name: ORG_NAME,
        description: "convex-logto live probe. Safe to delete.",
      }),
    }));

  const scope =
    (await findPaged(call, "/organization-scopes", (s) => s.name === ORG_SCOPE)) ??
    (await call("/organization-scopes", {
      method: "POST",
      body: JSON.stringify({ name: ORG_SCOPE, description: "Safe to delete." }),
    }));

  const role =
    (await findPaged(call, "/organization-roles", (r) => r.name === ORG_ROLE)) ??
    (await call("/organization-roles", {
      method: "POST",
      body: JSON.stringify({
        name: ORG_ROLE,
        description: "Safe to delete.",
        organizationScopeIds: [scope.id],
      }),
    }));

  // Idempotent by construction on Logto's side, but it answers 422 when the
  // membership already exists, so ask first.
  const members = await call(`/organizations/${org.id}/users?page=1&page_size=100`);
  if (!members.some((m) => m.id === userId)) {
    await call(`/organizations/${org.id}/users`, {
      method: "POST",
      body: JSON.stringify({ userIds: [userId] }),
    });
  }
  await call(`/organizations/${org.id}/users/${userId}/roles`, {
    method: "PUT",
    body: JSON.stringify({ organizationRoleIds: [role.id] }),
  });

  return { org, role, scope };
}

async function ensureResource(call, userId) {
  const resource =
    (await findPaged(call, "/resources", (r) => r.indicator === RESOURCE_INDICATOR)) ??
    (await call("/resources", {
      method: "POST",
      body: JSON.stringify({
        name: RESOURCE_NAME,
        indicator: RESOURCE_INDICATOR,
        accessTokenTtl: 3600,
      }),
    }));

  // A resource the user has no scope on may be indistinguishable from a
  // resource that does not exist, so grant one before concluding anything from
  // an `invalid_target`.
  const scope =
    (await findPaged(
      call,
      `/resources/${resource.id}/scopes`,
      (s) => s.name === RESOURCE_SCOPE,
    )) ??
    (await call(`/resources/${resource.id}/scopes`, {
      method: "POST",
      body: JSON.stringify({ name: RESOURCE_SCOPE, description: "Safe to delete." }),
    }));

  const role =
    (await findPaged(call, "/roles", (r) => r.name === USER_ROLE)) ??
    (await call("/roles", {
      method: "POST",
      body: JSON.stringify({
        name: USER_ROLE,
        description: "Safe to delete.",
        type: "User",
        scopeIds: [scope.id],
      }),
    }));
  await call(`/roles/${role.id}/scopes`, {
    method: "POST",
    body: JSON.stringify({ scopeIds: [scope.id] }),
  }).catch(() => {}); // already assigned answers 422; the desired state is the same

  await call(`/users/${userId}/roles`, {
    method: "PUT",
    body: JSON.stringify({ roleIds: [role.id] }),
  });

  return { resource, scope };
}

/**
 * Turn refresh-token rotation *on* before probing.
 *
 * Logto leaves it off for an app created through the API, and "does the
 * organization grant rotate?" answered against a deployment that never rotates
 * anything is not an answer. The interesting configuration is the one where
 * rotation is possible.
 */
async function enableRotation(call) {
  const app = await call(`/applications/${appId}`);
  const before = app.customClientMetadata?.rotateRefreshToken;
  if (before !== true) {
    await call(`/applications/${appId}`, {
      method: "PATCH",
      body: JSON.stringify({
        customClientMetadata: { ...(app.customClientMetadata ?? {}), rotateRefreshToken: true },
      }),
    });
  }
  return { was: before, now: true };
}

// ---------------------------------------------------------------- OIDC

async function tokenRequest(params) {
  const res = await fetch(`${endpoint}/oidc/token`, {
    method: "POST",
    headers: {
      Authorization: `Basic ${btoa(`${appId}:${appSecret}`)}`,
      "Content-Type": "application/x-www-form-urlencoded",
    },
    body: new URLSearchParams(params),
  });
  const text = await res.text();
  let body;
  try {
    body = JSON.parse(text);
  } catch {
    body = { raw: text };
  }
  return { ok: res.ok, status: res.status, body };
}

/**
 * Drive a real sign-in to get an authorization code.
 *
 * The redirect target is fulfilled with a stub rather than a running app: the
 * only thing wanted from `${redirectUri}` is the query string, and requiring an
 * app to be up would couple this probe to the example's build.
 */
async function authorizationCode({ resource, scopes = [] } = {}) {
  const verifier = randomBytes(32).toString("base64url");
  const challenge = createHash("sha256").update(verifier).digest("base64url");
  const authUrl = new URL(`${endpoint}/oidc/auth`);
  const params = new URLSearchParams({
    client_id: appId,
    redirect_uri: redirectUri,
    response_type: "code",
    prompt: "consent",
    code_challenge: challenge,
    code_challenge_method: "S256",
    scope: [
      "openid",
      "offline_access",
      "profile",
      "email",
      "urn:logto:scope:organizations",
      "urn:logto:scope:organization_roles",
      ...scopes,
    ].join(" "),
  });
  if (resource) params.set("resource", resource);
  authUrl.search = params.toString();

  const browser = await chromium.launch({ headless, channel: "chrome" });
  const context = await browser.newContext();
  await context.route(`${redirectUri}*`, (route) =>
    route.fulfill({ status: 200, contentType: "text/html", body: "<p>captured</p>" }),
  );
  const page = await context.newPage();
  try {
    await page.goto(authUrl.toString());
    await page.waitForSelector("input[name=identifier]", { timeout: 30_000 });
    await page.fill("input[name=identifier]", email);
    await page.keyboard.press("Enter");
    await page.waitForSelector("input[type=password]", { timeout: 30_000 });
    await page.fill("input[type=password]", password);
    await page.keyboard.press("Enter");
    await page.waitForURL((url) => url.href.startsWith(redirectUri), { timeout: 60_000 });
    const url = new URL(page.url());
    const code = url.searchParams.get("code");
    if (!code) {
      throw new Error(`no code on the redirect: ${url.search || "(empty)"}`);
    }
    return { code, verifier };
  } finally {
    await browser.close();
  }
}

// ---------------------------------------------------------------- run

const findings = [];
function finding(question, answer, detail) {
  findings.push({ question, answer, detail });
  console.error(`\n  ${question}\n  → ${answer}${detail ? `\n    ${detail}` : ""}`);
}

const report = { grants: {} };
const call = api(await managementToken());
const user = await findPaged(
  call,
  `/users?search=${encodeURIComponent(email)}`,
  (u) => u.primaryEmail === email,
);
if (!user) throw new Error(`no user ${email}. Run provision.mjs first.`);

const { org } = await ensureOrganization(call, user.id);
const { resource, scope } = await ensureResource(call, user.id);
const rotation = await enableRotation(call);
report.setup = {
  organizationId: org.id,
  resourceIndicator: resource.indicator,
  resourceScope: scope.name,
  rotateRefreshToken: rotation,
};
console.error(
  `probing with organization ${org.id}, resource ${resource.indicator}, ` +
    `rotateRefreshToken ${rotation.was === true ? "already on" : "turned on"} …`,
);

/**
 * Each grant consumes the refresh token it was given, so these run in sequence
 * and each one feeds the next. Presenting a spent one is exactly the mistake
 * this probe exists to keep out of the library.
 */
let refreshToken = null;
async function grant(label, extra) {
  const before = fingerprint(refreshToken);
  const result = await tokenRequest({
    grant_type: "refresh_token",
    refresh_token: refreshToken,
    ...extra,
  });
  if (!result.ok) {
    report.grants[label] = { error: result.body, status: result.status };
    finding(
      `Grant: ${label}`,
      `failed (${result.status})`,
      `${result.body.error ?? "?"}: ${result.body.error_description ?? ""}`,
    );
    return null;
  }
  const rotated =
    Boolean(result.body.refresh_token) && result.body.refresh_token !== refreshToken;
  if (result.body.refresh_token) refreshToken = result.body.refresh_token;
  const access = result.body.access_token?.includes(".")
    ? decodeJwt(result.body.access_token)
    : null;
  report.grants[label] = {
    returnedIdToken: Boolean(result.body.id_token),
    returnedRefreshToken: Boolean(result.body.refresh_token),
    rotated,
    refreshBefore: before,
    refreshAfter: fingerprint(refreshToken),
    scope: result.body.scope,
    expiresIn: result.body.expires_in,
    accessTokenClaims: access?.payload,
    accessTokenHeader: access?.header,
    idTokenClaims: result.body.id_token ? decodeJwt(result.body.id_token).payload : undefined,
  };
  finding(
    `Grant: ${label}`,
    [
      `id_token: ${result.body.id_token ? "yes" : "NO"}`,
      `refresh_token: ${
        result.body.refresh_token ? (rotated ? "ROTATED" : "same value") : "absent"
      }`,
    ].join(", "),
    [
      `aud: ${JSON.stringify(access?.payload.aud ?? "(opaque)")}`,
      `scope: ${result.body.scope || "(none)"}`,
      `expires_in: ${result.body.expires_in}s`,
    ].join("  "),
  );
  return result.body;
}

async function signInAndExchange(label, options) {
  const { code, verifier } = await authorizationCode(options);
  const exchanged = await tokenRequest({
    grant_type: "authorization_code",
    code,
    redirect_uri: redirectUri,
    code_verifier: verifier,
  });
  if (!exchanged.ok) {
    throw new Error(`${label} code exchange (${exchanged.status}): ${JSON.stringify(exchanged.body)}`);
  }
  if (!exchanged.body.refresh_token) {
    throw new Error(`${label}: no refresh_token — is offline_access granted to this app?`);
  }
  refreshToken = exchanged.body.refresh_token;
  return exchanged.body;
}

// -- Phase 1: a grant that never mentioned a resource ------------------------

const plainGrant = await signInAndExchange("phase 1", {});
const idToken = decodeJwt(plainGrant.id_token);
report.idToken = { header: idToken.header, payload: idToken.payload };

finding(
  "Q1. Do organization membership and roles ride in the ID token?",
  [
    `organizations: ${Array.isArray(idToken.payload.organizations) ? "YES" : "no"}`,
    `organization_roles: ${
      Array.isArray(idToken.payload.organization_roles) ? "YES" : "no"
    }`,
  ].join(", "),
  `claims: ${Object.keys(idToken.payload).sort().join(", ")}\n    ` +
    `organizations=${JSON.stringify(idToken.payload.organizations)} ` +
    `organization_roles=${JSON.stringify(idToken.payload.organization_roles)}`,
);
finding(
  "    ID token signing algorithm and lifetime",
  `${idToken.header.alg}, ${idToken.payload.exp - idToken.payload.iat}s`,
  `access token expires_in ${plainGrant.expires_in}s`,
);

await grant("plain refresh", {});
await grant("organization token", { organization_id: org.id });
await grant("resource token, not asked for at sign-in", { resource: resource.indicator });
await grant("plain refresh, after the others", {});

// -- Phase 2: the same resource, declared at authorization time --------------

const resourceGrant = await signInAndExchange("phase 2", {
  resource: resource.indicator,
  scopes: [scope.name],
});
report.grants["authorization_code with resource"] = {
  returnedIdToken: Boolean(resourceGrant.id_token),
  scope: resourceGrant.scope,
  accessTokenClaims: resourceGrant.access_token?.includes(".")
    ? decodeJwt(resourceGrant.access_token).payload
    : undefined,
};
await grant("resource token, asked for at sign-in", { resource: resource.indicator });
await grant("organization token, from a resource-scoped grant", { organization_id: org.id });

report.findings = findings;
writeFileSync(reportPath, `${JSON.stringify(report, null, 2)}\n`, { mode: 0o600 });

console.error(`\n\nFull decoded claims → ${reportPath} (mode 0600, gitignored).`);
console.error(
  "Read them before designing anything: the answers above are the summary, the\n" +
    "file is the evidence.",
);
