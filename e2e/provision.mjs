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

const endpoint = required("LOGTO_ENDPOINT").replace(/\/+$/, "");
const m2mId = required("LOGTO_M2M_APP_ID");
const m2mSecret = required("LOGTO_M2M_APP_SECRET");

const spaOrigin = process.env.E2E_SPA_ORIGIN ?? "http://localhost:5173";
const webOrigin = process.env.E2E_WEB_ORIGIN ?? "http://localhost:5174";

const SPA_NAME = "convex-logto-e2e-spa";
const WEB_NAME = "convex-logto-e2e-web";
const USER_EMAIL = "convex-logto-e2e@example.com";
const USER_PASSWORD = process.env.E2E_USER_PASSWORD ?? "Convex-Logto-E2E-1";

function required(name) {
  const value = process.env[name];
  if (!value) {
    console.error(
      `provision: ${name} is required.\n` +
        "Create a Machine-to-Machine app in Logto, give it the Logto Management " +
        "API role, and export its id and secret.",
    );
    process.exit(1);
  }
  return value;
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

/** The client secret lives only on the application detail response. */
async function clientSecret(call, applicationId) {
  const app = await call(`/applications/${applicationId}`);
  return app.secret ?? app.customClientMetadata?.secret ?? null;
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
const secret = await clientSecret(call, web.id);

console.error("done.\n");
console.log(`# Bridge mode — examples/tanstack-router-spa, examples/vite-react
LOGTO_ENDPOINT=${endpoint}
LOGTO_APP_ID=${spa.id}

# Session mode — examples/vite-react-session
LOGTO_ENDPOINT=${endpoint}
LOGTO_APP_ID=${web.id}
LOGTO_APP_SECRET=${secret ?? "<read it from the Logto console>"}

# Shared by the browser flow
E2E_USER_EMAIL=${USER_EMAIL}
E2E_USER_PASSWORD=${USER_PASSWORD}
E2E_SPA_ORIGIN=${spaOrigin}
E2E_WEB_ORIGIN=${webOrigin}`);
