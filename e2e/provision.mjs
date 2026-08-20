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
//   LOGTO_ENDPOINT         https://auth.example.com
//   LOGTO_M2M_APP_ID       a Machine-to-Machine app with the Management API role
//   LOGTO_M2M_APP_SECRET
//
// Optional: E2E_SPA_ORIGIN (default http://localhost:5173),
//           E2E_WEB_ORIGIN (default http://localhost:5174).

import { writeFileSync } from "node:fs";

const endpoint = required("LOGTO_ENDPOINT").replace(/\/+$/, "");
const m2mId = required("LOGTO_M2M_APP_ID");
const m2mSecret = required("LOGTO_M2M_APP_SECRET");

const spaOrigin = process.env.E2E_SPA_ORIGIN ?? "http://localhost:5173";
const webOrigin = process.env.E2E_WEB_ORIGIN ?? "http://localhost:5174";

const SPA_NAME = "convex-logto-e2e-spa";
const WEB_NAME = "convex-logto-e2e-web";
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
  const res = await fetch(`${endpoint}/oidc/token`, {
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
    throw new Error(
      `Management API token request failed (${res.status}): ${await res.text()}`,
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
 * Find-or-create, and *repair*: an app that exists but has lost a redirect URI
 * is the failure mode that actually happens (a port changes, someone edits the
 * console), and it presents as an opaque HTTP 400 from `/oidc/auth`.
 */
async function ensureApplication(call, { name, type, origin }) {
  const redirectUris = [`${origin}/callback`];
  const postLogoutRedirectUris = [origin];
  const existing = (await call("/applications?page=1&page_size=200")).find(
    (app) => app.name === name,
  );
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
  const found = await call(
    `/users?search=${encodeURIComponent(USER_EMAIL)}&page=1&page_size=20`,
  );
  const existing = found.find((user) => user.primaryEmail === USER_EMAIL);
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
  const override = process.env.LOGTO_APP_SECRET;
  if (typeof override === "string" && override !== "") return override;
  const app = await call(`/applications/${applicationId}`);
  const secret = app.secret ?? app.customClientMetadata?.secret ?? null;
  if (typeof secret !== "string" || secret === "") {
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
console.error(`provisioning against ${endpoint} …`);

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
await ensureUser(call);
const secret = await clientSecret(call, web.id, WEB_NAME);

// Secrets go to a 0600 file, never to stdout: a terminal is a scrollback buffer,
// and in CI it is a log. Only the values that are safe to read aloud are printed.
const env = `# Generated by e2e/provision.mjs. Contains secrets — do not commit.
# Bridge mode — examples/tanstack-router-spa, examples/vite-react
LOGTO_ENDPOINT=${endpoint}
LOGTO_APP_ID=${spa.id}

# Session mode — examples/vite-react-session
LOGTO_SESSION_APP_ID=${web.id}
LOGTO_APP_SECRET=${secret}

# Browser flow
E2E_USER_EMAIL=${USER_EMAIL}
E2E_USER_PASSWORD=${USER_PASSWORD}
E2E_SPA_ORIGIN=${spaOrigin}
E2E_WEB_ORIGIN=${webOrigin}
`;
writeFileSync(outPath, env, { mode: 0o600 });

console.error(`done.

  endpoint         ${endpoint}
  SPA app          ${spa.id}
  web app          ${web.id}
  test user        ${USER_EMAIL}
  client secret    written to the file below

  ${outPath}   (mode 0600, gitignored)

Load it with:  set -a; . ${outPath}; set +a`);
