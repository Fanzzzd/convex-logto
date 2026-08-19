# AGENTS.md

Guidance for AI agents and human contributors working in this repository.

## What this is

`convex-logto` is an npm package that lets a [Convex](https://convex.dev) React app use a self-hosted (or cloud) [Logto](https://logto.io) instance as its auth provider. It bridges Logto's OIDC **ID token** into Convex auth, and adds a signed webhook to sync Logto users into a Convex table. Published to npm as **`convex-logto`**.

## Repo layout (pnpm + Turborepo monorepo)

- `packages/convex-logto/` — the published library (the **only** published package).
  - `src/config.ts` — `logtoAuthConfig()` (for `auth.config.ts`), `logtoConfigQuery(opts?)` (serves `{ endpoint, appId, allowInsecureHttp? }` to the frontend).
  - `src/react.tsx` — `ConvexLogtoProvider`, `useLogtoAuth()`. This is the `convex-logto/react` entry and is **ESM-only**.
  - `src/webhooks.ts` — `logtoSync()`, `registerLogtoWebhook()`, `verifyLogtoSignature()`.
  - `src/backchannel-logout.ts` — the OIDC back-channel logout endpoint (JWKS verification, bounded and deduplicated).
  - `src/index.ts` — the server entry, `convex-logto`.
  - `src/session.ts` — session mode's app-side surface: `logtoSessionApi()`, `assertSubjectHasActiveSession()` (`assertUserHasActiveSession` is a deprecated alias — it never proved the *bearer* held the session, only that the subject had one).
  - `src/component/` — the **session component** (`convex-logto/convex.config`): schema, `lib.ts` (functions), `core.ts` (pure logic), `crons.ts` (GC). Built by `tsc -p tsconfig.component.json` into `dist/component/` (structure preserved 1:1 — the Convex CLI bundles that directory); everything else is built by tsup. After changing its schema or function signatures, regenerate `src/component/_generated/` with `npx convex codegen --component-dir ../../packages/convex-logto/src/component --typecheck disable`, run from an example dir that has a Convex deployment (e.g. `examples/vite-react-session`).

    If that fails with `A different local backend <name> is running on selected port <n>`, another
    local backend owns the port this deployment was provisioned on. `convex codegen` starts the
    deployment's own backend and takes its ports from the saved deployment config, and the CLI
    exposes no port override. Either stop the other backend, or point this one somewhere free by
    editing `ports` in `examples/vite-react-session/.convex/local/default/config.json` (anonymous
    deployments live under `~/.convex/anonymous-convex-backend-state/<name>/config.json`) and
    changing it back afterwards.
  - `src/component/endpoint.ts` + `src/component/http_body.ts` — shared boundary helpers used by both halves: the single place a configured endpoint becomes a Logto URL (scheme/credential/query validation), and the streamed request/response byte ceiling for every public HTTP handler.
  - `src/session-client.ts` + `src/react-session.tsx` — session mode's browser half: the framework-free auth engine, and the `convex-logto/react-session` entry (`ConvexLogtoSessionProvider`, `useLogtoAuth()`; ESM-only, no Logto SDK dependency).
  - `src/session-cookie.ts` — the opt-in same-site cookie transport: the session token lives in an HttpOnly cookie and a same-origin route proxies to the component.
  - `src/session-device.ts` — opt-in device binding (non-extractable ECDSA P-256 in IndexedDB); bound sessions must present a proof to refresh or sign out.
  - `src/native.tsx` + `src/native-session.tsx` + `src/native-session-client.ts` — the React Native / Expo entries for bridge and session mode.
- `docs/` — the documentation site (Fumadocs on TanStack Start; deployed to Vercel).
- `examples/` — one app per integration. Their `convex/_generated` stubs and framework-generated files (`next-env.d.ts`, `routeTree.gen.ts`) are **committed**: CI has no Convex deployment, so a clean checkout must typecheck and build without running `convex dev`.
- `scripts/audit-dependencies.mjs` — the fail-closed dependency gate. Advisories are allowed only by exact version *and* dependency path, recorded in `SECURITY.md` with a review date. Never silence one with a `pnpm.overrides` entry.
- `.changeset/` — Changesets config + pending release notes (workspace-level).

## Commands (run from the repo root)

CI (the required `verify` check) runs these over the **whole workspace**, in this
order. Run them the same way — `pnpm --filter convex-logto …` only checks the
library and will miss a broken example or docs build.

| Task | Command |
|---|---|
| Install | `pnpm install --frozen-lockfile` |
| Audit dependencies | `pnpm audit:dependencies` |
| Lint | `pnpm lint` (oxlint, type-aware, `--deny-warnings`) |
| Format check | `pnpm format:check` (oxfmt, scoped to `src/`) |
| Typecheck | `pnpm check-types` |
| Test | `pnpm test` (vitest) |
| Build | `NEXT_PUBLIC_CONVEX_URL=… pnpm build` |
| Validate package | `pnpm lint:package` (publint + are-the-types-wrong) |

Not part of that sequence — `format` rewrites files and `dev` never exits:

| Task | Command |
|---|---|
| Format | `pnpm --filter convex-logto format` (run before committing) |
| Docs site | `pnpm --filter docs dev` |

Turbo caches `check-types` and `test`. If a local run passes but CI fails,
suspect a generated file that exists locally and is gitignored: verify against a
clean clone (`git clone --no-hardlinks . /tmp/x && cd /tmp/x && pnpm install
--frozen-lockfile && …`) rather than trusting the cached local result.

## Conventions

- **Lint/format:** OXC — `oxlint` + `oxfmt`. Run `format` before committing; CI enforces `lint` + `format:check`. oxfmt is scoped to `src/` (never reformats `package.json` / `CHANGELOG.md` / lockfiles).
- **Runtime:** the library must run in Convex's **V8 runtime** — use Web APIs (e.g. `crypto.subtle`), not Node-only APIs.
- **TypeScript:** strict, `verbatimModuleSyntax`.
- **`convex-logto/react` is ESM-only** because it depends on `@logto/react@4` (ESM-only). The root `convex-logto` entry is dual ESM+CJS.
- **Auth model:** validate Logto's **ID token** over OIDC (Convex rejects `at+jwt` access tokens). No manual JWT config — the signing algorithm and JWKS are auto-discovered.
- **Component schema evolution:** new fields on existing component tables must be `v.optional(...)`. There is no migration mechanism — the schema ships inside the npm package and is validated against existing rows on the app's next push. A brand-new table may have required fields.
- **Session-mode invariants** (each is load-bearing; read the surrounding comment before changing one):
  - Never present a Logto refresh token twice. Logto's reuse detection destroys the whole grant, and a grant can be shared by sibling Sessions of the same OP session — which is also why abandoning one local Session must not call RFC 7009 revoke.
  - When a refresh outcome is unknown, keep the claim and let it age into `claim-expired` — a path that *deletes the session*, so "unknown" has to mean genuinely unknown. Release the claim once the outcome is known: either the failure proves Logto never processed the request, or Logto answered with a well-formed token response and any rotation it reported has already been persisted.
  - Terminal means "this session is gone for good" and deletes rows. A deployment misconfiguration (`invalid_client`, a wrong `LOGTO_APP_ID`) must be transient — otherwise one wrong env var deletes every session.
  - Revocation commits a logical marker first, then drains rows in bounded batches. A row that is logically revoked but not yet deleted must not retain authority.
  - Every path that installs credentials in the browser re-checks `authGeneration` after each await, so a response issued before a sign-out cannot resurrect it.
  - Anything that reads or mutates a session takes its subject from the caller's presented token, never from an argument — and a row killed by a watermark is invisible to reads too, or a "where am I signed in" list would show sessions that are already dead.
  - A page filtered after the read must be filled by scanning, not by slicing: dead rows must never consume a slot and hide the live device behind them. Bound the scan instead, and report truncation when it stops early.
  - A delivery record separates *claimed* from *completed*. Releasing a claim after the work succeeded re-arms the replay it was there to stop, so only an unfinished claim may be forgotten.
  - Watermark GC runs in its own transaction and collects a marker only once it governs nothing. Its batches are per-table: a sweep that filled the batch in *either* table must reschedule, or a backlog on one side stalls the other.
  - Validate a webhook payload only as far as the fields the library consumes — the event, `createdAt`, and the user id. Rejecting a signature-verified delivery turns Logto schema drift into silent, unretried event loss (Logto retries a 5xx, not a 4xx), and the same handler revokes sessions for deleted and suspended users. A field that drifts out of its declared type is dropped from the entity handed to sync handlers, never rejected.

## Releasing

Changesets + npm **OIDC trusted publishing** (provenance, no tokens):

1. `pnpm changeset` — describe the change (patch/minor/major); commit the generated `.changeset/*.md`.
2. Merge to `main` → a **"Version Packages" PR** opens automatically (bumps version + updates `CHANGELOG.md`).
3. Merge that PR → CI publishes to npm with provenance.

Never version or publish locally — no `changeset version`, `pnpm version-packages`, or `npm publish`, and never hand-edit the version or `CHANGELOG.md`. The Release workflow owns both; your only local step is `pnpm changeset` + committing the `.changeset/*.md`.

## Don't

- Don't add Node-only APIs to the library (it runs in Convex's V8 runtime).
- Don't reformat `package.json`, `CHANGELOG.md`, or lockfiles.
- Don't version or publish locally (`changeset version` / `pnpm version-packages` / `npm publish`) or hand-edit versions / `CHANGELOG.md`.
- Don't silence a dependency advisory with `pnpm.overrides`; add a reviewed exception to `scripts/audit-dependencies.mjs` and `SECURITY.md`, or upgrade.
- Don't gitignore a generated file an example or the docs site needs to typecheck — CI builds from a clean checkout.
