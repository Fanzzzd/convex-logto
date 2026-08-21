// Provision (idempotently) the Logto objects the live tests need, and print the
// environment they run with.
//
// This exists because the objects keep evaporating. The 0.4 session-mode spike
// created a Traditional Web app, a test user and a set of redirect URIs by hand,
// deleted them after the release, and the next person to want a live test had to
// reconstruct all of it from a chat log. Everything here is find-or-create, so
// running it twice is safe and running it after a cleanup is one command.
//
// Zero dependencies: `node e2e/provision.mjs`.
//
//   LOGTO_ENDPOINT         https://auth.example.com — also serves /api
//   LOGTO_M2M_APP_ID       a Machine-to-Machine app with the Management API role
//   LOGTO_M2M_APP_SECRET
//
// Optional: LOGTO_ADMIN_ENDPOINT. A self-hosted Logto with the admin console
// enabled runs *two* OIDC issuers: the tenant one at LOGTO_ENDPOINT, and the
// admin console's own. The built-in `m-default` Management API client exists
// only in the admin tenant, so its token has to be requested from the admin
// issuer even though the Management API itself is served from LOGTO_ENDPOINT.
// Asking the wrong issuer answers `invalid_client`, which reads like a wrong
// secret and is not. Defaults to LOGTO_ENDPOINT, which is right for Logto Cloud
// and for an M2M app you created yourself in the tenant.
//
// Optional: E2E_SPA_ORIGIN (default http://localhost:5173),
//           E2E_WEB_ORIGIN (default http://localhost:5174).

import { writeFileSync } from "node:fs";

const endpoint = required("LOGTO_ENDPOINT").replace(/\/+$/, "");
const adminEndpoint = (process.env.LOGTO_ADMIN_ENDPOINT ?? endpoint).replace(
  /\/+$/,
  "",
);
const m2mId = required("LOGTO_M2M_APP_ID");
const m2mSecret = required("LOGTO_M2M_APP_SECRET");

const spaOrigin = process.env.E2E_SPA_ORIGIN ?? "http://localhost:5173";
const webOrigin = process.env.E2E_WEB_ORIGIN ?? "http://localhost:5174";

const SPA_NAME = "convex-logto-e2e-spa";
const WEB_NAME = "convex-logto-e2e-web";
const ORG_NAME = "convex-logto-e2e-org";
// The name `examples/vite-react-session/convex/organizations.ts` requires. The
// reference app names the role; this provisions the role the reference app
// names, not the other way round.
const ORG_ROLE = "admin";
const USER_EMAIL = "convex-logto-e2e@example.com";
const USER_PASSWORD = required(
  "E2E_USER_PASSWORD",
  "Choose a password for the throwaway test user. This script never invents one:\n" +
    "a secret it generated would have to be printed to be useful, and a secret on\n" +
    "a terminal is a secret in a scrollback buffer and a CI log.",
);
const outPath = argValue("--out") ?? new URL("./.env.e2e", import.meta.url).pathname;

function required(name, hint) {
  const value = process.env[name];
  if (!value) {
    console.error(
      `provision: ${name} is required.\n` +
        (hint ??
          "Create a Machine-to-Machine app in Logto, give it the Logto Management " +
            "API role, and export its id and secret."),
    );
    process.exit(1);
  }
  return value;
}

function argValue(flag) {
  const index = process.argv.indexOf(flag);
  return index >= 0 ? process.argv[index + 1] : undefined;
}

/** Management API access token, via client credentials. */
async function accessToken() {
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
      `Management API token request failed (${res.status}) at ` +
        `${adminEndpoint}/oidc/token: ${body}` +
        (body.includes("invalid_client") && adminEndpoint === endpoint
          ? "\nA self-hosted Logto issues Management API tokens from the admin " +
            "console's OIDC endpoint, not the tenant one. If the secret is right, " +
            "set LOGTO_ADMIN_ENDPOINT to the admin console origin and retry."
          : ""),
    );
  }
  const body = await res.json();
  return body.access_token;
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

/**
 * Walk a paginated Management API collection until `match` hits.
 *
 * Logto rejects `page_size` above 100 with `guard.invalid_pagination`, so a
 * single oversized page is not an option — and a single page of 100 would
 * silently miss an app in a tenant that has more, reporting "not found" and
 * then failing to create it because the name is taken. Paging until a short
 * page is the only answer that is right at both ends.
 */
async function findPaged(call, path, match, { pageSize = 100, maxPages = 50 } = {}) {
  const separator = path.includes("?") ? "&" : "?";
  for (let page = 1; page <= maxPages; page += 1) {
    const items = await call(`${path}${separator}page=${page}&page_size=${pageSize}`);
    const hit = items.find(match);
    if (hit) return hit;
    if (items.length < pageSize) return undefined;
  }
  throw new Error(
    `${path}: scanned ${maxPages} pages of ${pageSize} without finding a match ` +
      "or reaching the end. Narrow the search rather than raising the bound.",
  );
}

/**
 * Find-or-create, and *repair*: an app that exists but has lost a redirect URI
 * is the failure mode that actually happens (a port changes, someone edits the
 * console), and it presents as an opaque HTTP 400 from `/oidc/auth`.
 */
async function ensureApplication(call, { name, type, origin }) {
  const redirectUris = [`${origin}/callback`];
  const postLogoutRedirectUris = [origin];
  const existing = await findPaged(call, "/applications", (app) => app.name === name);
  if (existing) {
    const metadata = existing.oidcClientMetadata ?? {};
    const missing =
      !redirectUris.every((uri) => (metadata.redirectUris ?? []).includes(uri)) ||
      !postLogoutRedirectUris.every((uri) =>
        (metadata.postLogoutRedirectUris ?? []).includes(uri),
      );
    if (missing) {
      await call(`/applications/${existing.id}`, {
        method: "PATCH",
        body: JSON.stringify({
          oidcClientMetadata: {
            ...metadata,
            redirectUris: [
              ...new Set([...(metadata.redirectUris ?? []), ...redirectUris]),
            ],
            postLogoutRedirectUris: [
              ...new Set([
                ...(metadata.postLogoutRedirectUris ?? []),
                ...postLogoutRedirectUris,
              ]),
            ],
          },
        }),
      });
      console.error(`  repaired redirect URIs on ${name}`);
    }
    return existing;
  }
  return await call("/applications", {
    method: "POST",
    body: JSON.stringify({
      name,
      type,
      description: "convex-logto live end-to-end tests. Safe to delete.",
      oidcClientMetadata: { redirectUris, postLogoutRedirectUris },
    }),
  });
}

async function ensureUser(call) {
  const existing = await findPaged(
    call,
    `/users?search=${encodeURIComponent(USER_EMAIL)}`,
    (user) => user.primaryEmail === USER_EMAIL,
  );
  if (existing) {
    // Always reset: the password is the one thing a live run cannot discover,
    // and a user whose password drifted is indistinguishable from a broken sign-in.
    await call(`/users/${existing.id}/password`, {
      method: "PATCH",
      body: JSON.stringify({ password: USER_PASSWORD }),
    });
    return existing;
  }
  return await call("/users", {
    method: "POST",
    body: JSON.stringify({
      primaryEmail: USER_EMAIL,
      password: USER_PASSWORD,
      name: "convex-logto e2e",
    }),
  });
}

/**
 * An organization the test user belongs to, holding {@link ORG_ROLE}.
 *
 * Find-or-create *and* repair, for the same reason `ensureApplication` is: the
 * failure that actually happens is an object that exists but has drifted — the
 * user dropped from the organization, or holding no role in it — and every one
 * of those presents as an authorization denial with nothing to point at.
 *
 * The role assignment is a PUT: it *is* the desired state, so re-running it is
 * both the repair and the no-op.
 */
async function ensureOrganization(call, userId) {
  const org =
    (await findPaged(call, "/organizations", (o) => o.name === ORG_NAME)) ??
    (await call("/organizations", {
      method: "POST",
      body: JSON.stringify({
        name: ORG_NAME,
        description: "convex-logto live end-to-end tests. Safe to delete.",
      }),
    }));

  const role =
    (await findPaged(call, "/organization-roles", (r) => r.name === ORG_ROLE)) ??
    (await call("/organization-roles", {
      method: "POST",
      body: JSON.stringify({
        name: ORG_ROLE,
        description: "convex-logto live end-to-end tests. Safe to delete.",
      }),
    }));

  const members = await call(
    `/organizations/${org.id}/users?page=1&page_size=100`,
  );
  if (!members.some((member) => member.id === userId)) {
    await call(`/organizations/${org.id}/users`, {
      method: "POST",
      body: JSON.stringify({ userIds: [userId] }),
    });
    console.error(`  added the test user to ${ORG_NAME}`);
  }
  await call(`/organizations/${org.id}/users/${userId}/roles`, {
    method: "PUT",
    body: JSON.stringify({ organizationRoleIds: [role.id] }),
  });

  return { org, role };
}

/**
 * The client secret lives only on the application detail response.
 *
 * Fails rather than returning null: session mode's code exchange cannot run
 * without it, so a "successful" run that emitted a placeholder would hand back
 * an environment file that fails much later, at the point where the cause is
 * least visible.
 */
async function clientSecret(call, applicationId, name) {
  // An override first, so the remediation the error below suggests actually
  // works on a rerun. Some Logto versions do not return the secret on the
  // application detail response at all.
  // Validated on the trimmed value, returned untrimmed: a whitespace-only
  // secret is not a secret, and would otherwise both bypass the API fallback and
  // land in the environment file as something unusable.
  const override = process.env.LOGTO_APP_SECRET;
  if (typeof override === "string" && override.trim() !== "") return override;
  const app = await call(`/applications/${applicationId}`);
  const secret = app.secret ?? app.customClientMetadata?.secret ?? null;
  if (typeof secret !== "string" || secret.trim() === "") {
    throw new Error(
      `Could not read the client secret for ${name} (${applicationId}). ` +
        "Session mode's authorization-code exchange needs it. Copy it from the " +
        "Logto console (Applications → " +
        `${name} → App secret), export it as LOGTO_APP_SECRET, and rerun — ` +
        "this script prefers that value when it is set.",
    );
  }
  return secret;
}

const call = api(await accessToken());
console.error(
  `provisioning against ${endpoint}` +
    (adminEndpoint === endpoint ? "" : ` (tokens from ${adminEndpoint})`) +
    " …",
);

const spa = await ensureApplication(call, {
  name: SPA_NAME,
  type: "SPA",
  origin: spaOrigin,
});
const web = await ensureApplication(call, {
  name: WEB_NAME,
  type: "Traditional",
  origin: webOrigin,
});
const user = await ensureUser(call);
const { org, role } = await ensureOrganization(call, user.id);
const secret = await clientSecret(call, web.id, WEB_NAME);

// Secrets go to a 0600 file, never to stdout: a terminal is a scrollback buffer,
// and in CI it is a log. Only the values that are safe to read aloud are printed.
const env = `# Generated by e2e/provision.mjs. Contains secrets — do not commit.
# Bridge mode — examples/tanstack-router-spa, examples/vite-react
LOGTO_ENDPOINT=${endpoint}
# Not a secret, and probe-org-tokens.mjs needs it too: without it a self-hosted
# deployment answers the same \`invalid_client\` this script exists to explain.
LOGTO_ADMIN_ENDPOINT=${adminEndpoint}
LOGTO_APP_ID=${spa.id}

# Session mode — examples/vite-react-session
LOGTO_SESSION_APP_ID=${web.id}
LOGTO_APP_SECRET=${secret}

# Browser flow
E2E_USER_EMAIL=${USER_EMAIL}
E2E_USER_PASSWORD=${USER_PASSWORD}
E2E_SPA_ORIGIN=${spaOrigin}
E2E_WEB_ORIGIN=${webOrigin}

# Organization authorization and the organization token exchange. Not secrets.
E2E_ORG_ID=${org.id}
E2E_ORG_ROLE=${role.name}

# Management API client, written back so this file alone can rerun this script.
# Dropping them is how the setup evaporates: the next run reads the file, finds
# no credentials, and the only copy was in someone's shell history.
LOGTO_M2M_APP_ID=${m2mId}
LOGTO_M2M_APP_SECRET=${m2mSecret}
`;
writeFileSync(outPath, env, { mode: 0o600 });

console.error(`done.

  endpoint         ${endpoint}
  SPA app          ${spa.id}
  web app          ${web.id}
  test user        ${USER_EMAIL}
  organization     ${org.id} (${ORG_NAME}), test user holds "${role.name}"
  client secret    written to the file below

  ${outPath}   (mode 0600, gitignored)

Load it with:  set -a; . ${outPath}; set +a`);
