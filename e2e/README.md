# Live end-to-end checks

Everything here runs against a **real Logto** and a **real Convex deployment**.
It is deliberately outside the pnpm workspace and outside CI: it needs
credentials, a browser, and a running app, none of which belong in `verify`.

It exists because the setup keeps evaporating. The 0.4 session-mode spike created
a Logto app, a test user and a set of redirect URIs by hand, deleted them after
the release, and the next person had to reconstruct all of it from a chat log.
`provision.mjs` is that reconstruction, written down and made idempotent.

## What it covers that unit tests cannot

Logto's real token lifetimes; whether a grant actually rotates its refresh token;
what the SSO cookie does on a second sign-in; and how the component behaves when
the wall clock — not a fake timer — advances. Every session-mode defect that took
longest to find was in that gap.

## 1. Provision

Create a **Machine-to-Machine** app in Logto and give it the *Logto Management
API* role. Then:

```bash
export LOGTO_ENDPOINT=https://auth.example.com
export LOGTO_M2M_APP_ID=...
export LOGTO_M2M_APP_SECRET=...

node provision.mjs
```

Find-or-create, and it *repairs* — an app that exists but has lost a redirect URI
is the failure that actually happens (a port changes, someone edits the console),
and it presents as an opaque HTTP 400 from `/oidc/auth`. Running it twice is safe.

It prints the environment for both modes. Nothing is written to disk; pipe it
where you want it:

```bash
node provision.mjs > .env.e2e
```

## 2. Point an example at it

Set the printed `LOGTO_*` values on the example's Convex deployment
(`npx convex env set ...`), start the backend and the app, and note the URL.

Session mode wants `examples/vite-react-session` on `:5174`; bridge mode wants
`examples/tanstack-router-spa` on `:5173`. Those ports are what `provision.mjs`
registers as redirect URIs — Logto rejects any other origin with a bare 400.

> Port conflicts to expect on a dev machine: `:5173` is a common Vite default and
> `:3212` is used by another local Convex backend. If you move a port, re-run
> `provision.mjs` with `E2E_SPA_ORIGIN` / `E2E_WEB_ORIGIN` set so Logto learns
> about it.

## 3. Run the flow

```bash
npm install                       # playwright-core only; no browser download
export E2E_APP_URL=http://localhost:5174
export E2E_USER_EMAIL=... E2E_USER_PASSWORD=...   # printed by provision.mjs
node session-flow.mjs
```

Drives the real browser through cold sign-in → zero-RTT restore → forced refresh
→ re-sign-in over a live session → sign-out. `E2E_HEADED=1` to watch it. A
failure writes `e2e/failure.png`.

Chrome must be installed: `playwright-core` drives the system browser rather than
downloading its own, which keeps this directory small enough to stay out of the
way.

## Cleanup

Everything is named `convex-logto-e2e-*` and described "safe to delete". Deleting
the apps and the user in the Logto console costs nothing — re-run `provision.mjs`
to get them back.
