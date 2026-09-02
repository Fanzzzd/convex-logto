// Answer, against a real Logto, the questions the organization-token design
// depends on (issue #206):
//
//   1. Do organization membership and organization *roles* arrive in the ID
//      token, or does reading a role require an organization token?
//   2. Does the organization-token grant return an `id_token` alongside the
//      organization access token?
//   3. Does it rotate the refresh token? If it does, is a *failed* grant (a
//      resource Logto will not issue for) still a spend?
//   4. Must a resource be named at authorization time, and is it the `resource`
//      parameter that matters or the resource's scope?
//
// (3) is the one that decides the shape of the feature. Session mode's central
// invariant is that nothing presents a Logto refresh token twice; a single
// claimed `refresh` grant enforces it. If the organization grant rotates, it is
// a second consumer of that token and must go through the same claim.
//
// Rotation is normally invisible. Logto only rotates a *confidential* client's
// refresh token once it is past 70% of its lifetime, which no fresh token is.
// So the rotation phases run against the **public** SPA client instead, where
// the same rule rotates on every grant. That is the one configuration in which
// the question is observable rather than inferred.
//
//   node probe-org-tokens.mjs
//
// Needs the provisioned environment (`set -a; . ./.env.e2e; set +a`) plus the
// Management API credentials from provision.mjs:
//
//   LOGTO_M2M_APP_ID, LOGTO_M2M_APP_SECRET, optionally LOGTO_ADMIN_ENDPOINT.
//
// Prints findings to **stderr**, never tokens. Every token here is a live
// credential, and a terminal is a scrollback buffer. The decoded claims go to
// `.probe-org-tokens.json` (mode 0600, gitignored). The script rewrites that
// file after every finding, so a phase that fails late does not discard what
// the earlier phases cost.

import { chmodSync, writeFileSync } from "node:fs";
import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { createHash, randomBytes } from "node:crypto";
import { chromium } from "playwright-core";

const endpoint = trimSlash(need("LOGTO_ENDPOINT"));
const adminEndpoint = trimSlash(process.env.LOGTO_ADMIN_ENDPOINT ?? endpoint);
const confidentialAppId = need("LOGTO_SESSION_APP_ID");
const confidentialSecret = need("LOGTO_APP_SECRET");
const publicAppId = need("LOGTO_APP_ID");
const m2mId = need("LOGTO_M2M_APP_ID");
const m2mSecret = need("LOGTO_M2M_APP_SECRET");
const email = need("E2E_USER_EMAIL");
const password = need("E2E_USER_PASSWORD");
const webOrigin = trimSlash(process.env.E2E_WEB_ORIGIN ?? "http://localhost:5174");
const spaOrigin = trimSlash(process.env.E2E_SPA_ORIGIN ?? "http://localhost:5173");
const headless = process.env.E2E_HEADED !== "1";
const reportPath = fileURLToPath(new URL("./.probe-org-tokens.json", import.meta.url));

const ORG_NAME = "convex-logto-e2e-org";
const ORG_ROLE = "convex-logto-e2e-admin";
const ORG_SCOPE = "e2e:manage";
const RESOURCE_NAME = "convex-logto-e2e-resource";
const RESOURCE_INDICATOR = "https://e2e.convex-logto.test/api";
const RESOURCE_SCOPE = "e2e:read";
const USER_ROLE = "convex-logto-e2e-user";

/** The two clients, which differ in exactly the property the rotation rule reads. */
const CONFIDENTIAL = {
  label: "confidential",
  appId: confidentialAppId,
  secret: confidentialSecret,
  redirectUri: `${webOrigin}/callback`,
};
const PUBLIC = {
  label: "public",
  appId: publicAppId,
  secret: undefined,
  redirectUri: `${spaOrigin}/callback`,
};

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
    JSON.parse(
      Buffer.from(part.replace(/-/g, "+").replace(/_/g, "/"), "base64").toString(),
    );
  return { header: json(header), payload: json(payload) };
}

/** A stable, non-reversible handle, so "did it change?" is answerable in a log. */
function fingerprint(token) {
  return token === null || token === undefined
    ? "(none)"
    : createHash("sha256").update(token).digest("hex").slice(0, 12);
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
    const body = await res.text();
    throw new Error(
      `management token (${res.status}) at ${adminEndpoint}/oidc/token: ${body}` +
        (body.includes("invalid_client") && adminEndpoint === endpoint
          ? "\nA self-hosted Logto issues Management API tokens from the admin " +
            "console's OIDC endpoint. Set LOGTO_ADMIN_ENDPOINT to it."
          : ""),
    );
  }
  return (await res.json()).access_token;
}

class ManagementApiError extends Error {
  constructor(status, path, body) {
    super(`${path} → ${status}: ${body}`);
    this.status = status;
  }
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
      throw new ManagementApiError(res.status, path, await res.text());
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
 * Everything below is find-or-create for the same reason provision.mjs is.
 * People rerun this while the questions are still changing, and a probe that
 * only works on a clean tenant is a probe that works once.
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
  try {
    await call(`/roles/${role.id}/scopes`, {
      method: "POST",
      body: JSON.stringify({ scopeIds: [scope.id] }),
    });
  } catch (error) {
    // 422 is "already assigned", which is the desired state. Anything else,
    // such as an expired management token or a role deleted between the find
    // and the write, would leave the user without the scope, and finding (4)
    // below reads an `invalid_target` as evidence about the *resource
    // parameter*. Swallowing that would turn a broken setup into a confident
    // wrong answer.
    if (!(error instanceof ManagementApiError) || error.status !== 422) throw error;
  }

  await call(`/users/${userId}/roles`, {
    method: "PUT",
    body: JSON.stringify({ roleIds: [role.id] }),
  });

  return { resource, scope };
}

/**
 * Read (and report) the per-application rotation toggle.
 *
 * Logto wraps oidc-provider's rule with its own gate:
 *
 *   rotateRefreshToken: (ctx) => {
 *     const { Client: client } = ctx.oidc.entities;
 *     if (!(client?.metadata().rotateRefreshToken
 *           ?? customClientMetadataDefault.rotateRefreshToken)) return false;
 *     return defaults.rotateRefreshToken(ctx);
 *   }
 *
 * so an unset value means *the default*, not "off". This reads it rather than
 * assuming, and reads it back after any write rather than reporting a PATCH it
 * never confirmed.
 */
async function rotationSetting(call, appId) {
  const before = (await call(`/applications/${appId}`)).customClientMetadata
    ?.rotateRefreshToken;
  if (before === true) return { was: before, effective: true, changed: false };
  await call(`/applications/${appId}`, {
    method: "PATCH",
    body: JSON.stringify({ customClientMetadata: { rotateRefreshToken: true } }),
  });
  const after = (await call(`/applications/${appId}`)).customClientMetadata
    ?.rotateRefreshToken;
  if (after !== true) {
    throw new Error(
      `could not enable rotateRefreshToken on ${appId}. It reads back as ${JSON.stringify(after)}`,
    );
  }
  return { was: before, effective: true, changed: true };
}

// ---------------------------------------------------------------- OIDC

async function tokenRequest(client, params) {
  const headers = { "Content-Type": "application/x-www-form-urlencoded" };
  const body = new URLSearchParams(params);
  if (client.secret === undefined) {
    // A public client authenticates by identity alone. That is also the
    // property that makes oidc-provider rotate on every grant.
    body.set("client_id", client.appId);
  } else {
    headers.Authorization = `Basic ${btoa(`${client.appId}:${client.secret}`)}`;
  }
  const res = await fetch(`${endpoint}/oidc/token`, { method: "POST", headers, body });
  const text = await res.text();
  let parsed;
  try {
    parsed = JSON.parse(text);
  } catch {
    parsed = { raw: text };
  }
  return { ok: res.ok, status: res.status, body: parsed };
}

/**
 * Drive a real sign-in to get an authorization code.
 *
 * A stub fulfils the redirect target instead of a running app. The only thing
 * this needs from it is the query string, and requiring an app to be up would
 * couple this probe to the example's build.
 */
async function authorizationCode(client, { resource, scopes = [] } = {}) {
  const verifier = randomBytes(32).toString("base64url");
  const challenge = createHash("sha256").update(verifier).digest("base64url");
  const params = new URLSearchParams({
    client_id: client.appId,
    redirect_uri: client.redirectUri,
    response_type: "code",
    prompt: "consent",
    code_challenge: challenge,
    code_challenge_method: "S256",
    scope: ["openid", "offline_access", "profile", "email", ...scopes].join(" "),
  });
  if (resource) params.set("resource", resource);
  const authUrl = new URL(`${endpoint}/oidc/auth`);
  authUrl.search = params.toString();

  const browser = await chromium.launch({ headless, channel: "chrome" });
  let signInFormSeen = false;
  let context;
  let page;
  try {
    context = await browser.newContext();
    page = await context.newPage();
    // Wait on the *request* to the redirect URI, not on the navigation
    // completing. Nothing is listening on that port, so whether the redirect
    // "loads" depends on a stub route that has proven unreliable across
    // Logto's interstitials. The query string, which is the only thing needed
    // here, is already on the request either way.
    const redirected = page.waitForRequest(
      (request) => request.url().startsWith(client.redirectUri),
      { timeout: 90_000 },
    );
    // Closing the browser rejects a still-pending wait. Without this, that
    // rejection races the *real* error out of the process and reports
    // "target closed" instead of whatever went wrong.
    redirected.catch(() => {});
    // Keep the stub anyway. A fulfilled 200 avoids a browser error page, which
    // makes `E2E_HEADED=1` watchable.
    await context.route(`${client.redirectUri}*`, (route) =>
      route.fulfill({ status: 200, contentType: "text/html", body: "<p>captured</p>" }),
    );
    // One retry, because this probe spends an authorization grant per phase,
    // and losing the whole run to one slow TLS handshake wastes evidence
    // without reporting anything.
    try {
      await page.goto(authUrl.toString(), { timeout: 60_000 });
    } catch {
      await page.goto(authUrl.toString(), { timeout: 60_000 });
    }
    // A returning user has an SSO cookie and never sees these, so this races
    // the sign-in form against the redirect rather than waiting for it.
    await Promise.race([
      redirected,
      (async () => {
        await page.waitForSelector("input[name=identifier]", { timeout: 60_000 });
        signInFormSeen = true;
        await page.fill("input[name=identifier]", email);
        await page.keyboard.press("Enter");
        await page.waitForSelector("input[type=password]", { timeout: 30_000 });
        await page.fill("input[type=password]", password);
        await page.keyboard.press("Enter");
      })(),
    ]);
    const url = new URL((await redirected).url());
    const code = url.searchParams.get("code");
    if (!code) throw new Error(`no code on the redirect: ${url.search || "(empty)"}`);
    return { code, verifier };
  } catch (error) {
    // Say where it stopped. "Timeout" alone cannot distinguish an unreachable
    // Logto from a consent screen nobody clicked.
    let landed = "(unknown)";
    try {
      landed = page?.url() ?? "(no page)";
    } catch {
      landed = "(page gone)";
    }
    throw new Error(
      `${client.label} sign-in failed after ${
        signInFormSeen ? "submitting credentials" : "loading the authorize URL"
      }; the page was at ${landed}`,
      { cause: error },
    );
  } finally {
    await browser.close();
  }
}

// ---------------------------------------------------------------- run

const report = { grants: {}, phases: {} };
const findings = [];
assertReportIsIgnored();

/**
 * Refuse to write a report git would track.
 *
 * The ignore rule for this file lives in the repository's `.gitignore`, and a
 * `.gitignore` is per-branch. Check out a branch that predates the rule, run
 * `git add -A`, and a dump of decoded ID token claims lands in a commit. That
 * is not hypothetical. It happened once. Checking costs one subprocess at
 * startup and turns a silent commit into a refusal that says why.
 */
function assertReportIsIgnored() {
  try {
    execFileSync("git", ["check-ignore", "-q", reportPath], {
      stdio: "ignore",
      cwd: fileURLToPath(new URL(".", import.meta.url)),
    });
  } catch (error) {
    // Exit code 1 means "not ignored". Anything else, such as git missing or
    // not a repository at all, is not this check's business, and refusing then
    // would make the probe unrunnable outside a checkout.
    if (error?.status !== 1) return;
    console.error(
      `probe-org-tokens: ${reportPath} is not gitignored, and it holds decoded\n` +
        "ID token claims. Add `e2e/.probe-*.json` to .gitignore (or check out a\n" +
        "branch that has it) before running this.",
    );
    process.exit(1);
  }
}

function persist() {
  report.findings = findings;
  writeFileSync(reportPath, `${JSON.stringify(report, null, 2)}\n`, { mode: 0o600 });
  // `mode` only applies when Node *creates* the file. A report left behind by
  // an earlier run, or by a `--out` path someone made themselves, keeps
  // whatever permissions it already had, and this file holds decoded ID token
  // claims, including the user's email.
  chmodSync(reportPath, 0o600);
}

function finding(question, answer, detail) {
  findings.push({ question, answer, detail });
  console.error(`\n  ${question}\n  → ${answer}${detail ? `\n    ${detail}` : ""}`);
  // Persisted as soon as it is learned. A later phase drives a browser and can
  // time out, and the evidence above it cost real authorization grants to
  // collect.
  persist();
}

/**
 * One refresh-token grant, in a chain.
 *
 * Each grant may consume the token it was given, so a *failed* grant leaves the
 * chain in an unknown state. On the failure path this drops the token rather
 * than letting the next call present something Logto may already have spent,
 * which would trip reuse detection and answer a different question than the one
 * being asked. Chains that mean to test that do it explicitly.
 */
function chain(client, initialRefreshToken, phase) {
  let refreshToken = initialRefreshToken;
  return {
    token: () => refreshToken,
    async grant(label, extra = {}) {
      if (refreshToken === null) {
        throw new Error(
          `${label}: the chain has no usable refresh token because a previous grant failed.`,
        );
      }
      const before = fingerprint(refreshToken);
      const presented = refreshToken;
      const result = await tokenRequest(client, {
        grant_type: "refresh_token",
        refresh_token: presented,
        ...extra,
      });
      if (!result.ok) {
        // Unknown whether Logto consumed it. Refuse to present it again.
        refreshToken = null;
        report.grants[label] = {
          phase,
          client: client.label,
          status: result.status,
          error: result.body,
          refreshPresented: before,
        };
        finding(
          `Grant: ${label}`,
          `failed (${result.status})`,
          `${result.body.error ?? "?"}: ${result.body.error_description ?? ""}`,
        );
        return null;
      }
      const rotated =
        Boolean(result.body.refresh_token) && result.body.refresh_token !== presented;
      if (result.body.refresh_token) refreshToken = result.body.refresh_token;
      const access = result.body.access_token?.includes(".")
        ? decodeJwt(result.body.access_token)
        : null;
      report.grants[label] = {
        phase,
        client: client.label,
        returnedIdToken: Boolean(result.body.id_token),
        returnedRefreshToken: Boolean(result.body.refresh_token),
        rotated,
        refreshBefore: before,
        refreshAfter: fingerprint(refreshToken),
        scope: result.body.scope,
        expiresIn: result.body.expires_in,
        accessTokenClaims: access?.payload,
        accessTokenHeader: access?.header,
        idTokenClaims: result.body.id_token
          ? decodeJwt(result.body.id_token).payload
          : undefined,
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
    },
  };
}

async function signIn(client, label, options) {
  const { code, verifier } = await authorizationCode(client, options);
  const exchanged = await tokenRequest(client, {
    grant_type: "authorization_code",
    code,
    redirect_uri: client.redirectUri,
    code_verifier: verifier,
  });
  if (!exchanged.ok) {
    throw new Error(
      `${label} code exchange (${exchanged.status}): ${JSON.stringify(exchanged.body)}`,
    );
  }
  if (!exchanged.body.refresh_token) {
    throw new Error(
      `${label}: no refresh_token. Is offline_access granted to the ${client.label} app?`,
    );
  }
  report.phases[label] = {
    client: client.label,
    requested: options ?? {},
    scope: exchanged.body.scope,
  };
  persist();
  return { tokens: exchanged.body, chain: chain(client, exchanged.body.refresh_token, label) };
}

const ORG_SCOPES = [
  "urn:logto:scope:organizations",
  "urn:logto:scope:organization_roles",
];

try {
  const call = api(await managementToken());
  const user = await findPaged(
    call,
    `/users?search=${encodeURIComponent(email)}`,
    (u) => u.primaryEmail === email,
  );
  if (!user) throw new Error(`no user ${email}. Run provision.mjs first.`);

  const { org } = await ensureOrganization(call, user.id);
  const { resource, scope } = await ensureResource(call, user.id);
  const confidentialRotation = await rotationSetting(call, CONFIDENTIAL.appId);
  const publicRotation = await rotationSetting(call, PUBLIC.appId);
  report.setup = {
    organizationId: org.id,
    resourceIndicator: resource.indicator,
    resourceScope: scope.name,
    rotateRefreshToken: {
      confidential: confidentialRotation,
      public: publicRotation,
    },
  };
  persist();
  console.error(
    `probing organization ${org.id} and resource ${resource.indicator}\n` +
      `  confidential app ${CONFIDENTIAL.appId}, rotateRefreshToken ` +
      `${confidentialRotation.changed ? "set to true" : "already true"}\n` +
      `  public app       ${PUBLIC.appId}, rotateRefreshToken ` +
      `${publicRotation.changed ? "set to true" : "already true"}`,
  );

  // -- Phase 1: confidential client, no resource named at sign-in ------------

  const phase1 = await signIn(CONFIDENTIAL, "phase1", { scopes: ORG_SCOPES });
  const idToken = decodeJwt(phase1.tokens.id_token);
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
    `access token expires_in ${phase1.tokens.expires_in}s`,
  );

  await phase1.chain.grant("confidential: plain refresh");
  await phase1.chain.grant("confidential: organization token", {
    organization_id: org.id,
  });
  await phase1.chain.grant("confidential: plain refresh, after the organization one");
  // Last in this phase on purpose. Logto should reject it, and a failed grant
  // ends the chain rather than handing a possibly-spent token to a successor.
  await phase1.chain.grant("confidential: resource never named at sign-in", {
    resource: resource.indicator,
  });

  // -- Phase 2: the resource parameter alone, without its scope --------------

  const phase2 = await signIn(CONFIDENTIAL, "phase2", {
    scopes: ORG_SCOPES,
    resource: resource.indicator,
  });
  const withResourceParamOnly = await phase2.chain.grant(
    "confidential: resource named at sign-in, scope not requested",
    { resource: resource.indicator },
  );

  // -- Phase 3: the resource's scope alone, without the resource parameter ---

  const phase3 = await signIn(CONFIDENTIAL, "phase3", {
    scopes: [...ORG_SCOPES, scope.name],
  });
  const withScopeOnly = await phase3.chain.grant(
    "confidential: resource scope requested, resource parameter omitted at sign-in",
    { resource: resource.indicator },
  );

  finding(
    "Q4. What makes a resource askable, the `resource` parameter or its scope?",
    [
      `resource parameter alone: ${withResourceParamOnly ? "WORKS" : "rejected"}`,
      `scope alone: ${withScopeOnly ? "WORKS" : "rejected"}`,
    ].join(", "),
    "Logto also rejected both in phase 1, when neither was requested, so " +
      "whichever of these two works is the one to configure before sign-in.",
  );

  // -- Phase 4: the public client, where rotation is observable --------------
  //
  // oidc-provider rotates on every grant for a client whose token-endpoint
  // auth method is `none`. Everything above runs in the regime where rotation
  // is real but rare; this is the regime where it is visible on every grant.

  const phase4 = await signIn(PUBLIC, "phase4", {
    scopes: [...ORG_SCOPES, scope.name],
    resource: resource.indicator,
  });
  await phase4.chain.grant("public: plain refresh");
  await phase4.chain.grant("public: organization token", { organization_id: org.id });
  await phase4.chain.grant("public: resource token", { resource: resource.indicator });
  await phase4.chain.grant("public: plain refresh, after both");

  const rotationByGrant = Object.entries(report.grants)
    .filter(([label]) => label.startsWith("public: "))
    .map(([label, entry]) => `${label.replace("public: ", "")}=${entry.rotated ? "ROTATED" : entry.error ? "failed" : "same"}`);
  finding(
    "Q3a. Does the organization grant rotate the refresh token?",
    rotationByGrant.join(", "),
    "Measured on the public client, where oidc-provider's rule rotates on every " +
      "grant. A confidential client runs the same rule, gated on 70% of the " +
      "refresh token's lifetime. Same handler, same blindness to grant type.",
  );

  // -- Phase 5: is a *failed* grant still a spend? ---------------------------
  //
  // This is the dangerous chain on purpose, isolated in its own sign-in so a
  // grant it destroys cannot affect any answer above.

  const phase5 = await signIn(PUBLIC, "phase5", { scopes: ORG_SCOPES });
  const spentProbe = phase5.chain.token();
  const rejected = await tokenRequest(PUBLIC, {
    grant_type: "refresh_token",
    refresh_token: spentProbe,
    resource: resource.indicator,
  });
  if (rejected.ok) {
    // The premise did not hold. Logto was meant to refuse this grant. Replaying
    // the token now would fail because Logto rotated it *legitimately*, and
    // reporting that as "a rejected grant spends the token" would be a
    // confident inversion of the answer.
    report.grants["public: intended-failure grant unexpectedly succeeded"] = {
      phase: "phase5",
      client: PUBLIC.label,
      rotated: Boolean(rejected.body.refresh_token),
    };
    finding(
      "Q3b. Does a grant that Logto rejects still spend the refresh token?",
      "UNANSWERED. The grant Logto was meant to reject succeeded",
      "The sign-in did not name the resource, so Logto should have answered " +
        "`invalid_target`. It issued a token instead, which means this " +
        "deployment reaches resources differently and the experiment needs a " +
        "target it refuses.",
    );
  } else {
    const after = await tokenRequest(PUBLIC, {
      grant_type: "refresh_token",
      refresh_token: spentProbe,
    });
    report.grants["public: rejected grant, then the same token again"] = {
      phase: "phase5",
      client: PUBLIC.label,
      rejectedStatus: rejected.status,
      rejectedError: rejected.body.error,
      replayOk: after.ok,
      replayStatus: after.status,
      replayError: after.body.error,
    };
    finding(
      "Q3b. Does a grant that Logto rejects still spend the refresh token?",
      after.ok
        ? "NO. The same token still works afterwards"
        : `YES. Replaying it answers ${after.status} ${after.body.error ?? ""}`,
      `The rejected grant was ${rejected.status} ${rejected.body.error ?? ""}. ` +
        "This decides whether a failed exchange may release the claim or must " +
        "leave it to age.",
    );
  }
} finally {
  persist();
  console.error(`\n\nFull decoded claims → ${reportPath} (mode 0600, gitignored).`);
  console.error(
    "Read them before designing anything. The findings above are the summary,\n" +
      "the file is the evidence. Everything is on stderr. Redirect with 2>.",
  );
}
