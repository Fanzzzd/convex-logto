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
export E2E_USER_PASSWORD=...      # you choose it; the script never invents one

node provision.mjs
```

If that fails with `invalid_client`, the secret is probably fine and the *issuer*
is wrong. A self-hosted Logto with the admin console enabled runs two OIDC
issuers, and the built-in `m-default` client exists only in the admin one — while
the Management API it grants access to is served from `LOGTO_ENDPOINT`. Point the
token request at the admin console and keep the API where it is:

```bash
export LOGTO_ADMIN_ENDPOINT=https://admin.example.com
```

Find-or-create, and it *repairs* — an app that exists but has lost a redirect URI
is the failure that actually happens (a port changes, someone edits the console),
and it presents as an opaque HTTP 400 from `/oidc/auth`. Running it twice is safe.

Secrets are written to **`e2e/.env.e2e`** with mode `0600` (gitignored), never to
stdout — a terminal is a scrollback buffer, and in CI it is a log. Only the
non-secret values are printed. `--out <path>` moves the file.

```bash
set -a; . ./.env.e2e; set +a
```

The script never invents the test user's password: a secret it generated would
have to be printed to be useful.

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

All commands in this file run **from `e2e/`**.

```bash
npm install                       # playwright-core only; no browser download
set -a; . ./.env.e2e; set +a
export E2E_APP_URL=http://localhost:5174
export E2E_CONVEX_URL=http://127.0.0.1:3214     # the deployment the app talks to
node session-flow.mjs
```

Drives the real browser through cold sign-in → zero-RTT restore → two rounds of
rotation → sign-out → re-sign-in. `E2E_HEADED=1` to watch it. A failure writes
`failure.png` next to the script and exits non-zero.

Every step is a required assertion, and each one asserts the thing rather than a
proxy for it:

- **zero-RTT** watches for a POST at the deployment and fails if one happens —
  elapsed time proves nothing, because a fast round trip looks identical;
- **rotation runs twice**, because a rotated token that was never persisted
  passes the first refresh and fails the second;
- **sign-out is re-checked after a reload**, because cleared UI with live
  credentials still in storage is exactly the bug;
- **re-sign-in** must mint a *different* session token, not resurrect the old one.

It reads the library's own storage keys, so it tests the library rather than the
example's UI.

Chrome must be installed: `playwright-core` drives the system browser rather than
downloading its own, which keeps this directory small enough to stay out of the
way.

## Probes

`session-flow.mjs` is a regression: it asserts known-good behaviour. A **probe**
is the opposite — it asks the deployment a question whose answer is not known
yet, and its output is a finding, not a pass or a fail.

```bash
set -a; . ./.env.e2e; set +a
export LOGTO_M2M_APP_ID=... LOGTO_M2M_APP_SECRET=...   # same as provisioning
node probe-org-tokens.mjs
```

`probe-org-tokens.mjs` settled [ADR
0003](../docs/adr/0003-organization-token-exchange.md): whether organization
roles reach the ID token, whether an organization-token grant returns an
`id_token`, whether it rotates the refresh token, whether a *rejected* grant
still spends it, and what makes a resource askable. It creates its own
organization, role, API resource and scope — all find-or-create, all named
`convex-logto-e2e-*`.

Findings go to **stderr** (redirect with `2>`), like everything else here. The
decoded claims are credentials and go to `.probe-org-tokens.json` (mode `0600`,
gitignored), rewritten after every finding so a late failure does not discard
evidence that cost real authorization grants.

> **Design the experiment so the answer is visible.** Rotation is invisible on
> any *confidential* client's fresh refresh token — Logto only rotates one past
> 70% of its lifetime — so asking that client answers "no rotation" no matter
> what the rule is. The probe asks the **public** SPA client instead, where the
> same rule rotates on every grant. Reaching for a second configuration beats
> inferring from a null result.

## Cleanup

Everything is named `convex-logto-e2e-*` and described "safe to delete". Deleting
the apps and the user in the Logto console costs nothing — re-run `provision.mjs`
to get them back.
