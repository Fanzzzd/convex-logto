# AGENTS.md

Guidance for AI agents and human contributors working in this repository.

## What this is

`convex-logto` is an npm package that lets a [Convex](https://convex.dev) React app use a self-hosted (or cloud) [Logto](https://logto.io) instance as its auth provider. It bridges Logto's OIDC **ID token** into Convex auth, and adds a signed webhook to sync Logto users into a Convex table. Published to npm as **`convex-logto`**.

## Repo layout (pnpm + Turborepo monorepo)

- `packages/convex-logto/`: the published library (the **only** published package). `src/` is laid out by **where the code runs**, and each directory's runtime is a rule, not a convention: the tsconfigs and tsup entries are drawn along the same lines.
  - `src/shared/`: V8-safe modules with no Convex functions, imported by every other directory. `endpoint.ts` is the single place a configured endpoint becomes a Logto URL and the issuer (`logtoIssuer`); `http-body.ts` is the streamed byte ceiling for every public HTTP handler; `decode.ts` is the one `isRecord` / base64url / JWT-segment decoder; `jwks.ts` reads, filters and fetches Logto's JWKS for back-channel logout, the static-JWKS provider and the CLI alike; `session-cookie-protocol.ts` is the wire contract between the cookie handler and the cookie transport. Shared code goes here, never copied into a second directory.
  - `src/component/`: the **session component** (`convex-logto/convex.config`) and nothing else, because every file in it becomes a component module. Schema, `lib.ts` (functions), `core.ts` (pure logic), `crons.ts` (GC). `tsc -p tsconfig.component.json` builds it into `dist/component/` (structure preserved 1:1; the Convex CLI bundles that directory) and emits the `src/shared/` modules it imports into `dist/shared/`; tsup builds everything else. After changing its schema or function signatures, regenerate `src/component/_generated/` with `npx convex codegen --component-dir ../../packages/convex-logto/src/component --typecheck disable`, run from an example dir that has a Convex deployment (e.g. `examples/vite-react-session`; `CONVEX_AGENT_MODE=anonymous npx convex dev --once` provisions a local one without a login).

    If that fails with `A different local backend <name> is running on selected port <n>`, another
    local backend owns the port this deployment was provisioned on. `convex codegen` starts the
    deployment's own backend and takes its ports from the saved deployment config, and the CLI
    exposes no port override. Either stop the other backend, or point this one somewhere free by
    editing `ports` in `examples/vite-react-session/.convex/local/default/config.json` (anonymous
    deployments live under `~/.convex/anonymous-convex-backend-state/<name>/config.json`) and
    changing it back afterwards.
  - `src/server/`: the `convex-logto` entry (`index.ts`), run in Convex's V8 runtime. `config.ts` (`logtoAuthConfig()`, discovery or static-JWKS, and `logtoConfigQuery()`), `session.ts` (session mode's app-side API: `logtoSessionApi()`, `assertSubjectHasActiveSession()`; `assertUserHasActiveSession` is a deprecated alias, since it never proved the *bearer* held the session, only that the subject had one), `webhooks.ts`, `backchannel-logout.ts`, `organizations.ts`, and `session-cookie-handler.ts` (the same-site route that proxies the HttpOnly session cookie to the component).
  - `src/client/`: session mode's framework-free browser half. `session-client.ts` (the auth engine), `session-cookie-transport.ts`, `session-device.ts` (opt-in device binding: non-extractable ECDSA P-256 in IndexedDB; bound sessions must present a proof to refresh or sign out), `session-transport.ts`.
  - `src/react/`: `bridge.tsx` is the `convex-logto/react` entry (bridge mode, on `@logto/react`), `session.tsx` the `convex-logto/react-session` entry (no Logto SDK). Both **ESM-only**.
  - `src/native/`: the React Native / Expo entries, `bridge.tsx` (`convex-logto/native`) and `session.tsx` + `session-client.ts` (`convex-logto/native-session`).
  - `src/cli/`: the `convex-logto` bin (`sync-jwks`, `check-jwks`), the only Node code that ships. `jwks-sync.ts` takes the deployment's env and `fetch` as arguments; `convex-env.ts` is the real env, the project's own Convex CLI run with the caller's deployment flags.
- `docs/`: the documentation site (Fumadocs on TanStack Start; deployed to Vercel).
- `examples/`: one app per integration. Their `convex/_generated` stubs and framework-generated files (`next-env.d.ts`, `routeTree.gen.ts`) are **committed**. CI has no Convex deployment, so a clean checkout must typecheck and build without running `convex dev`. Each example's `check-types` runs `tsc --noEmit` **twice**, once for the app, once for `convex/`, because that second project is the only place that checks the component's public type boundary (`logtoSessionApi(components.logto)`, the shape in `_generated/component.d.ts`) against a consumer.
- `e2e/`: live checks against a **real** Logto and Convex deployment. Outside the pnpm workspace and outside CI on purpose (needs credentials, a browser, a running app). `provision.mjs` is idempotent find-or-create-and-repair for the Logto objects; `session-flow.mjs` drives Chrome through the whole session lifecycle; `probe-org-tokens.mjs` is a *probe* rather than a regression; it asks the deployment a question whose answer is not known yet and prints findings. Reach for this directory when a question is empirical, because unit tests answer none of those: real token lifetimes, whether a grant rotates its refresh token, what the SSO cookie does on a second sign-in. A probe answers it for *today's* deployment. When the answer decides something hard to reverse, confirm it against Logto's source as well ([ADR 0003](docs/adr/0003-organization-token-exchange.md) is the worked example; rotation is invisible on any fresh refresh token).
- `scripts/audit-dependencies.mjs`: the fail-closed dependency gate. It allows an advisory only by exact version *and* dependency path, recorded in `SECURITY.md` with a review date. Never silence one with a `pnpm.overrides` entry.
- `.changeset/`: Changesets config + pending release notes (workspace-level).

## Commands (run from the repo root)

CI (the required `verify` check) runs these over the **whole workspace**, in this
order. Run them the same way; `pnpm --filter convex-logto …` only checks the
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
| Check documented imports | `pnpm check:docs` (every `import … from "convex-logto…"` in `docs/` names a real export; reads `dist/`, so it runs after the build) |

Not part of that sequence, because `format` rewrites files and `dev` never exits:

| Task | Command |
|---|---|
| Format | `pnpm --filter convex-logto format` (run before committing) |
| Docs site | `pnpm --filter docs dev` |

Turbo caches `check-types` and `test`. If a local run passes but CI fails,
suspect a generated file that exists locally and is gitignored. Verify against a
clean clone (`git clone --no-hardlinks . /tmp/x && cd /tmp/x && pnpm install
--frozen-lockfile && …`) rather than trusting the cached local result.

## Conventions

- **Lint/format:** OXC, `oxlint` + `oxfmt`. Run `format` before committing; CI enforces `lint` + `format:check`. oxfmt is scoped to `src/` (never reformats `package.json` / `CHANGELOG.md` / lockfiles).
- **Runtime:** the library must run in Convex's **V8 runtime**; use Web APIs (e.g. `crypto.subtle`), not Node-only APIs. `src/cli/` is the one exception: it is the bin, runs on Node 18+, and nothing in the library imports it.
- **TypeScript:** strict, `verbatimModuleSyntax`. `check-types` runs **two** projects: `tsconfig.json` (the library, `types: []`; no ambient Node globals, because it runs in Convex's V8 runtime and in browsers) and `tsconfig.node.json` (the same options plus `@types/node` and ES2023, over the Node-side code the base config excludes: every test file and `src/cli/`). A new test or CLI file needs no config change; anything that needs a Node API belongs in that second project only.
- **Build verification:** `packages/convex-logto/scripts/verify-build-artifacts.mjs` runs at the end of every build. It asserts every path in `package.json#exports` and `#bin` exists (and the bin starts with a node shebang), that every relative specifier reachable from `dist/component/` resolves, `dist/shared/` included, and `dist/component/convex.config.js` imports (nothing else ever loads them), and that the two session entries still export the small set of names they share. Without it a broken component emit shows up on a *user's* next `convex dev` push, and an export lost from one entry shows up as a failure handleable in one mode and not the other.
- **Docs verification:** `scripts/check-docs-imports.mjs` (`pnpm check:docs`, after the build) checks every `import { … } from "convex-logto…"` in `docs/content/docs/` against the **emitted** declaration files. Nothing compiles an `.mdx` code fence, so a renamed export otherwise reaches readers as a build error in *their* project. Import lines only, on purpose. Making every snippet typecheck would mean giving each one a preamble it does not need to be read.
- **`convex-logto/react` is ESM-only** because it depends on `@logto/react@4` (ESM-only). The root `convex-logto` entry is dual ESM+CJS.
- **Auth model:** validate Logto's **ID token** over OIDC (Convex rejects `at+jwt` access tokens). No manual JWT config; Convex discovers the signing algorithm and JWKS itself.
- **Component schema evolution:** new fields on existing component tables must be `v.optional(...)`. There is no migration mechanism; the schema ships inside the npm package and Convex validates it against existing rows on the app's next push. A brand-new table may have required fields.
- **Session-mode invariants** (each is load-bearing; read the surrounding comment before changing one):
  - Never present a Logto refresh token twice. Logto's reuse detection destroys the whole grant, and a grant can be shared by sibling Sessions of the same OP session, which is also why abandoning one local Session must not call RFC 7009 revoke.
  - When a refresh outcome is unknown, keep the claim and let it age into `claim-expired`, a path that *deletes the session*, so "unknown" has to mean exactly that. Release the claim once the outcome is known, which means either the failure proves Logto never processed the request, or Logto answered with a well-formed token response and the component has already persisted any rotation it reported.
  - Terminal means "this session is gone for good" and deletes rows. A deployment misconfiguration (`invalid_client`, a wrong `LOGTO_APP_ID`) must be transient; otherwise one wrong env var deletes every session.
  - Revocation commits a logical marker first, then drains rows in bounded batches. A row that is logically revoked but not yet deleted must not retain authority.
  - Every path that installs credentials in the browser re-checks `authGeneration` after each await, so a response issued before a sign-out cannot resurrect it.
  - Anything that reads or mutates a session takes its subject from the caller's presented token, never from an argument, and a row killed by a watermark is invisible to reads too, or a "where am I signed in" list would show sessions that are already dead.
  - Fill a page filtered after the read by scanning, not by slicing. Dead rows must never consume a slot and hide the live device behind them. Bound the scan instead, and report truncation when it stops early.
  - A delivery record separates *claimed* from *completed*. Releasing a claim after the work succeeded re-arms the replay it was there to stop, so only an unfinished claim may be forgotten.
  - Watermark GC runs in its own transaction and collects a marker only once it governs nothing. Its batches are per-table. A sweep that filled the batch in *either* table must reschedule, or a backlog on one side stalls the other.
  - Validate a webhook payload only as far as the fields the library consumes: the event, `createdAt`, and the user id. Rejecting a signature-verified delivery turns Logto schema drift into silent, unretried event loss (Logto retries a 5xx, not a 4xx), and the same handler revokes sessions for deleted and suspended users. Drop a field that drifts out of its declared type from the entity handed to sync handlers; never reject it.

## Releasing

Changesets + npm **OIDC trusted publishing** (provenance, no tokens). The
Release workflow is split in two jobs on purpose: `verify` runs the whole
workspace's install scripts, tests and builds with `contents: read` only, and
`release`, the single job granted `id-token: write`, does nothing but check
out, install, and hand off to `changesets/action`. Never move `id-token: write`
back to the workflow level; it would put an npm publish credential within reach
of every dependency's build script.


1. `pnpm changeset`: describe the change (patch/minor/major); commit the generated `.changeset/*.md`.
2. Merge to `main`, and a **"Version Packages" PR** opens on its own (bumps version + updates `CHANGELOG.md`).
3. Merge that PR, and CI publishes to npm with provenance.

Never version or publish locally: no `changeset version`, `pnpm version-packages`, or `npm publish`, and never hand-edit the version or `CHANGELOG.md`. The Release workflow owns both; your only local step is `pnpm changeset` + committing the `.changeset/*.md`.

## Don't

- Don't add Node-only APIs to the library (it runs in Convex's V8 runtime).
- Don't reformat `package.json`, `CHANGELOG.md`, or lockfiles.
- Don't version or publish locally (`changeset version` / `pnpm version-packages` / `npm publish`) or hand-edit versions / `CHANGELOG.md`.
- Don't silence a dependency advisory with `pnpm.overrides`; add a reviewed exception to `scripts/audit-dependencies.mjs` and `SECURITY.md`, or upgrade.
- Don't gitignore a generated file an example or the docs site needs to typecheck; CI builds from a clean checkout.
