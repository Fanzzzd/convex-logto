// Answer, against a real Logto, the questions the organization-token design
// cannot be settled without (issue #206):
//
//   1. Do organization membership and organization *roles* really arrive in the
//      ID token, or does reading a role require an organization token?
//   2. Does the organization-token grant return an `id_token` alongside the
//      organization access token?
//   3. Does it rotate the refresh token — and if it does, is a *failed* grant
//      (a resource Logto will not issue for) still a spend?
//   4. Must a resource be named at authorization time, and is it the `resource`
//      parameter that matters or the resource's scope?
//
// (3) is the one that decides the shape of the feature. Session mode's central
// invariant is that a Logto refresh token is never presented twice, enforced by
// a single claimed `refresh` grant. If the organization grant rotates, it is a
// second consumer of that token and must go through the same claim.
//
// Rotation is normally invisible: Logto only rotates a *confidential* client's
// refresh token once it is past 70% of its lifetime, which no fresh token is.
// So the rotation phases run against the **public** SPA client instead, where
// the same rule rotates on every grant — the one configuration in which the
// question is directly observable rather than inferred.
//
//   node probe-org-tokens.mjs
//
// Needs the provisioned environment (`set -a; . ./.env.e2e; set +a`) plus the
// Management API credentials from provision.mjs:
//
//   LOGTO_M2M_APP_ID, LOGTO_M2M_APP_SECRET, optionally LOGTO_ADMIN_ENDPOINT.
//
// Prints findings to **stderr**, never tokens: every token here is a live
// credential, and a terminal is a scrollback buffer. The decoded claims go to
// `.probe-org-tokens.json` (mode 0600, gitignored), written after every finding
// so a phase that fails late does not discard what the earlier phases cost.

import { writeFileSync } from "node:fs";
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
    // 422 is "already assigned", which is the desired state. Anything else —
    // an expired management token, a role deleted between the find and the
    // write — would leave the user without the scope, and finding (4) below
    // reads an `invalid_target` as evidence about the *resource parameter*.
    // Swallowing that would turn a broken setup into a confident wrong answer.
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
      `could not enable rotateRefreshToken on ${appId}: it reads back as ${JSON.stringify(after)}`,
    );
  }
  return { was: before, effective: true, changed: true };
}

// ---------------------------------------------------------------- OIDC

async function tokenRequest(client, params) {
  const headers = { "Content-Type": "application/x-www-form-urlencoded" };
  const body = new URLSearchParams(params);
  if (client.secret === undefined) {
    // A public client authenticates by identity alone — which is also the
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
 * The redirect target is fulfilled with a stub rather than a running app: the
 * only thing wanted from it is the query string, and requiring an app to be up
 * would couple this probe to the example's build.
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
    // Logto's interstitials — but the query string, which is the only thing
    // wanted here, is already on the request either way.
    const redirected = page.waitForRequest(
      (request) => request.url().startsWith(client.redirectUri),
      { timeout: 90_000 },
    );
    // Closing the browser rejects a still-pending wait. Without this, that
    // rejection races the *real* error out of the process and reports
    // "target closed" instead of whatever actually went wrong.
    redirected.catch(() => {});
    // Keep the stub anyway: a fulfilled 200 avoids a browser error page, which
    // makes `E2E_HEADED=1` watchable.
    await context.route(`${client.redirectUri}*`, (route) =>
      route.fulfill({ status: 200, contentType: "text/html", body: "<p>captured</p>" }),
    );
    // Retried once: this probe spends an authorization grant per phase, and
    // losing the whole run to one slow TLS handshake wastes evidence rather
    // than reporting anything.
    try {
      await page.goto(authUrl.toString(), { timeout: 60_000 });
    } catch {
      await page.goto(authUrl.toString(), { timeout: 60_000 });
    }
    // A returning user has an SSO cookie and never sees these, so the sign-in
    // form is raced against the redirect rather than waited for.
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

function persist() {
  report.findings = findings;
  writeFileSync(reportPath, `${JSON.stringify(report, null, 2)}\n`, { mode: 0o600 });
}

function finding(question, answer, detail) {
  findings.push({ question, answer, detail });
  console.error(`\n  ${question}\n  → ${answer}${detail ? `\n    ${detail}` : ""}`);
  // Written as it is learned: a later phase drives a browser and can time out,
  // and the evidence above it cost real authorization grants to collect.
  persist();
}

/**
 * One refresh-token grant, in a chain.
 *
 * Each grant may consume the token it was given, so a *failed* grant leaves the
 * chain in an unknown state: on the failure path this drops the token rather
 * than letting the next call present something Logto may already have spent —
 * which would trip reuse detection and answer a different question than the one
 * being asked. Chains that mean to test that deliberately do it explicitly.
 */
function chain(client, initialRefreshToken, phase) {
  let refreshToken = initialRefreshToken;
  return {
    token: () => refreshToken,
    async grant(label, extra = {}) {
      if (refreshToken === null) {
        throw new Error(
          `${label}: the chain has no usable refresh token — a previous grant failed.`,
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
      `${label}: no refresh_token — is offline_access granted to the ${client.label} app?`,
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
      `  confidential app ${CONFIDENTIAL.appId} — rotateRefreshToken ` +
      `${confidentialRotation.changed ? "set to true" : "already true"}\n` +
      `  public app       ${PUBLIC.appId} — rotateRefreshToken ` +
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
  // Last in this phase on purpose: it is expected to fail, and a failed grant
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
    "Q4. What makes a resource askable — the `resource` parameter or its scope?",
    [
      `resource parameter alone: ${withResourceParamOnly ? "WORKS" : "rejected"}`,
      `scope alone: ${withScopeOnly ? "WORKS" : "rejected"}`,
    ].join(", "),
    "Both were also rejected when neither was requested (phase 1), so whichever " +
      "of these two works is the one that has to be configured before sign-in.",
  );

  // -- Phase 4: the public client, where rotation is observable --------------
  //
  // oidc-provider rotates unconditionally for a client whose token-endpoint
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
      "refresh token's lifetime — same handler, same blindness to grant type.",
  );

  // -- Phase 5: is a *failed* grant still a spend? ---------------------------
  //
  // Deliberately the dangerous chain, isolated in its own sign-in so a grant
  // this destroys cannot affect any answer above.

  const phase5 = await signIn(PUBLIC, "phase5", { scopes: ORG_SCOPES });
  const spentProbe = phase5.chain.token();
  const failed = await tokenRequest(PUBLIC, {
    grant_type: "refresh_token",
    refresh_token: spentProbe,
    resource: resource.indicator,
  });
  const after = await tokenRequest(PUBLIC, {
    grant_type: "refresh_token",
    refresh_token: spentProbe,
  });
  report.grants["public: failed grant, then the same token again"] = {
    phase: "phase5",
    client: PUBLIC.label,
    failedStatus: failed.status,
    failedError: failed.body.error,
    replayOk: after.ok,
    replayStatus: after.status,
    replayError: after.body.error,
  };
  finding(
    "Q3b. Does a grant that Logto rejects still spend the refresh token?",
    after.ok
      ? "NO — the same token still works afterwards"
      : `YES — replaying it answers ${after.status} ${after.body.error ?? ""}`,
    `The rejected grant was ${failed.status} ${failed.body.error ?? ""}. ` +
      "This decides whether a failed exchange may release the claim or must " +
      "leave it to age.",
  );
} finally {
  persist();
  console.error(`\n\nFull decoded claims → ${reportPath} (mode 0600, gitignored).`);
  console.error(
    "Read them before designing anything: the findings above are the summary,\n" +
      "the file is the evidence. Everything is on stderr — redirect with 2>.",
  );
}
