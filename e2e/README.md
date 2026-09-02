# Live end-to-end checks

Everything here runs against a real Logto and a real Convex deployment. It is
outside the pnpm workspace and outside CI on purpose. It needs credentials, a
browser, and a running app, none of which belong in `verify`.

It exists because the setup keeps evaporating. The 0.4 session-mode spike created
a Logto app, a test user and a set of redirect URIs by hand, deleted them after
the release, and the next person had to reconstruct all of it from a chat log.
`provision.mjs` is that reconstruction, written down and made idempotent.

## What it covers that unit tests cannot

Logto's real token lifetimes; whether a grant rotates its refresh token; what
the SSO cookie does on a second sign-in; and how the component behaves when the
wall clock, not a fake timer, advances. Every session-mode defect that took
longest to find was in that gap.

## 1. Provision

Create a Machine-to-Machine app in Logto and give it the Logto Management API
role. Then:

```bash
export LOGTO_ENDPOINT=https://auth.example.com
export LOGTO_M2M_APP_ID=...
export LOGTO_M2M_APP_SECRET=...
export E2E_USER_PASSWORD=...      # you choose it; the script never invents one

node provision.mjs
```

If that fails with `invalid_client`, the secret is probably fine and the *issuer*
is wrong. A self-hosted Logto with the admin console enabled runs two OIDC
issuers, and the built-in `m-default` client exists only in the admin one, while
`LOGTO_ENDPOINT` serves the Management API it grants access to. Point the token
request at the admin console and keep the API where it is:

```bash
export LOGTO_ADMIN_ENDPOINT=https://admin.example.com
```

Find-or-create, and it *repairs*. An app that exists but has lost a redirect URI
is the failure that happens in practice (a port changes, someone edits the
console), and it presents as an opaque HTTP 400 from `/oidc/auth`. Running it
twice is safe.

It also creates the organization the authorization steps need
(`convex-logto-e2e-org`), an organization role named `admin`, the name
`examples/vite-react-session/convex/organizations.ts` requires, and puts the
test user in the first holding the second. Every run repairs membership and the
role assignment, because a user quietly dropped from an organization presents as
an authorization denial with nothing to point at.

The script writes the Management API credentials back into the file, so
`.env.e2e` alone is enough to rerun the script. Dropping them is how the setup
evaporates. The next run reads the file, finds none, and the only other copy was
in someone's shell history.

Secrets go to `e2e/.env.e2e` with mode `0600` (gitignored), never to stdout. A
terminal is a scrollback buffer, and in CI it is a log. The script prints only
the non-secret values. `--out <path>` moves the file.

```bash
set -a; . ./.env.e2e; set +a
```

The script never invents the test user's password, because a generated secret
would have to be printed to be useful.

## 2. Point an example at it

Session mode wants `examples/vite-react-session` on `:5174`; bridge mode wants
`examples/tanstack-router-spa` on `:5173`. Those ports are what `provision.mjs`
registers as redirect URIs; Logto rejects any other origin with a bare 400.

Set the values on that example's Convex deployment. The names differ on purpose.
The file names the *app* whose secret it is, the deployment names the *client*
the library authenticates as, and session mode's `LOGTO_APP_ID` is the
Traditional Web app, not the SPA one.

```bash
set -a; . e2e/.env.e2e; set +a          # from the repo root, for this block only
cd examples/vite-react-session
npx convex env set LOGTO_ENDPOINT "$LOGTO_ENDPOINT"
npx convex env set LOGTO_APP_ID "$LOGTO_SESSION_APP_ID"
npx convex env set LOGTO_CLIENT_SECRET "$LOGTO_APP_SECRET"
npx convex dev &                        # note the http://127.0.0.1:PORT it prints
npx vite                                # :5174, per vite.config.ts
```

> Port conflicts to expect on a dev machine: `:5173` is a common Vite default and
> another local Convex backend uses `:3212`. If you move a port, re-run
> `provision.mjs` with `E2E_SPA_ORIGIN` / `E2E_WEB_ORIGIN` set so Logto learns
> about it.

## 3. Run the flow

Back in `e2e/`, where every other command in this file runs.

```bash
npm install                       # playwright-core only; no browser download
set -a; . ./.env.e2e; set +a
export E2E_APP_URL=http://localhost:5174
export E2E_CONVEX_URL=http://127.0.0.1:3216     # the port `convex dev` printed
node session-flow.mjs
```

Drives the real browser through cold sign-in → zero-RTT restore → two rounds of
rotation → organization authorization → the organization token exchange and its
cache → userinfo → sign-out → re-sign-in → revoking a second device → sign-out
everywhere. `E2E_HEADED=1` to watch it. A failure writes `failure.png` next to
the script and exits non-zero.

Progress and failures go to stderr, like everything else here; the exit code is
the machine-readable result, so stdout stays free for a caller to redirect
without swallowing the log. Keep a run with `2>`:

```bash
node session-flow.mjs 2> .probe-session-flow.log   # gitignored
```

The last two steps open separate browser contexts, which is what makes them
worth running. A second context is a second cookie jar and a second storage
origin, so it is a second *device* to both Logto and the component, and
"another device lost its session, live, without asking" is not a claim one
browser can check.

Every step is a required assertion, and each one asserts the thing rather than a
proxy for it:

- **zero-RTT** fails if the restore *mints a token*, named by function rather
  than counted by URL. Elapsed time proves nothing (a fast round trip looks
  identical), and a POST count would also catch the calls the example's own UI
  makes, so the library's test would break whenever the example changed;
- **rotation runs twice**, because a rotated token the browser never persisted
  passes the first refresh and fails the second;
- **a reload re-checks sign-out**, because cleared UI with live credentials
  still in storage is exactly the bug;
- **re-sign-in must be prompted.** Sign-out is federated by default, so Logto
  has to ask for credentials again; that prompt is the only evidence the
  RP-initiated logout reached Logto, since clearing local storage looks
  identical from the app either way;
- **revocation reaches the other device without a reload**, because a revocation
  that only lands on the next page load is a cache expiry, not a revocation,
  and the device that *did* the revoking has to stay signed in;
- the **sign-out everywhere** check runs on the device that never saw the click;
- **organization authorization** is asserted both ways: the test user's real
  role in their real organization grants, and the *same role name* in an
  organization they do not belong to is denied. Whether Logto puts
  `organizations` and `organization_roles` in the ID token for the configured
  scopes is a property of the deployment, and every one of the
  `assertOrganization*` helpers depends on it being true;
- **the organization token is minted, then cached, then forced past the cache.**
  `minted` is the only externally visible difference between "asked Logto" and
  "served from the component", every mint spends a refresh grant, and there is no
  way to prove `forceRefresh` bypasses a cache without first proving the cache
  exists. The exchange also has to return no token string, because the app
  never set `exposeAccessTokens`;
- **`fetchUserInfo` answers for the same subject** the ID token names; a
  userinfo response for a different subject would mean the component
  authenticated the wrong session, and both are just JSON to an offline test.

Each run names the session it is about to revoke (`e2e-target-<runid>`). The
test account accumulates sessions because every run leaves some behind, so "the
other device" is not something the list can be asked for, and aiming a revoke at
it would eventually aim at whatever an earlier run abandoned.

### The flake, and what it turned out to be

The re-sign-in step can report that the click reached *neither* Logto's prompt
nor a signed-in app. The first time, all it left was a blank screenshot. Two
things were wrong, and only the diagnostic separated them.

**The harness's own race.** `signInOutcome` used to race two `waitFor*` calls and
map each rejection to `"neither"`, so *any* early rejection decided the whole
question. A sign-in click navigates, navigation destroys the execution context a
`waitForFunction` poll is running in, and that rejects immediately. It won the
race and reported "neither" while the credential prompt was still on its way.
The failures looked like Logto's sign-in page failing to render. It was
rendering fine; a probe found `input[name=identifier]` present and no console
errors. It now polls both conditions in one `evaluate`, treats a failed read as
"ask again", and lets only the deadline answer `"neither"`.

**The IdP itself was slow.** Underneath that, this self-hosted Logto sometimes
stalls a request for tens of seconds. Straight from the shell, three requests to
the same URL:

```text
sign-in page: 000 in 30.005678s   ← timed out (30 seconds)
sign-in page: 302 in 0.304516s
sign-in page: 302 in 0.300324s
```

Nothing in `convex-logto` is on that path; the app has already redirected and is
waiting on the IdP. It shows up now as a Playwright *navigation* timeout naming
the `/oidc/auth` URL, which is a much better failure than "neither". Re-run.

**Reading a failure here.** The assertion prints a redacted URL: origin and
path in full, query and fragment reduced to parameter *names*, and only names it
recognises, since `?SECRET` is a parameter whose name *is* the secret. This runs
right after a sign-in click, so the raw URL can be a callback carrying
`code`/`state`, and failures go to stderr, which this file tells you to redirect
into a log:

```text
at https://auth.example.com/sign-in?[app_id] showing "(unreadable)"
at http://localhost:5174/callback?[code,state] showing "Loading…"
```

Enough to tell a callback from an authorize request without writing either one's
values down. A startup self-check proves the redactor before anything can need
it, because it only ever runs on a failure, which is the one place there is no
second chance. A `"neither"` naming an app origin is the one worth bisecting. It
means the click never got the browser off the app at all.

## Probes

`session-flow.mjs` is a regression test. It asserts known-good behaviour. A
probe is the opposite. It asks the deployment a question whose answer is not
known yet, and its output is a finding, not a pass or a fail.

```bash
set -a; . ./.env.e2e; set +a      # the M2M credentials it needs are in there
node probe-org-tokens.mjs
```

`probe-org-tokens.mjs` settled [ADR
0003](../docs/adr/0003-organization-token-exchange.md): whether organization
roles reach the ID token, whether an organization-token grant returns an
`id_token`, whether it rotates the refresh token, whether a *rejected* grant
still spends it, and what makes a resource askable. It creates its own
organization, role, API resource and scope, all find-or-create, all named
`convex-logto-e2e-*`.

Findings go to stderr (redirect with `2>`), like everything else here. The
decoded claims are credentials and go to `.probe-org-tokens.json` (mode `0600`,
gitignored), rewritten after every finding so a late failure does not discard
evidence that cost real authorization grants.

`probe-exchange.mjs` asks the same kind of question one layer up, through the
*component*, not raw OIDC. It needs an app already running (see step 2), and
`E2E_ORG_ID` from `.env.e2e`:

```bash
node probe-exchange.mjs                       # findings on stderr, like the rest
node probe-exchange.mjs 2> .probe-exchange.log # …redirect to keep them
```

It found two defects the first time it ran: Logto answers `403` for an
organization token asked for on a grant without
`urn:logto:scope:organizations`, and the component read that as *"the refresh
outcome is unknown"*, keeping the claim, so every later refresh answered
`refresh_in_flight` and the component deleted the session when the claim aged
out. One missing scope in a deployment's config signed every user out. It also
showed that an Organization token's `scopes` is always empty, which the docs had
been telling readers to authorize on.

> **Design the experiment so the answer is visible.** Rotation is invisible on
> any *confidential* client's fresh refresh token, because Logto only rotates one
> past 70% of its lifetime, so asking that client answers "no rotation" no matter
> what the rule is. The probe asks the public SPA client instead, where the
> same rule rotates on every grant. Reaching for a second configuration beats
> inferring from a null result.

## Cleanup

Everything is named `convex-logto-e2e-*` and described "safe to delete". Deleting
the apps and the user in the Logto console costs nothing; re-run `provision.mjs`
to get them back.
