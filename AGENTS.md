# AGENTS.md

Guidance for AI agents and human contributors working in this repository.

## What this is

`convex-logto` is an npm package that lets a [Convex](https://convex.dev) React app use a self-hosted (or cloud) [Logto](https://logto.io) instance as its auth provider. It bridges Logto's OIDC **ID token** into Convex auth, and adds a signed webhook to sync Logto users into a Convex table. Published to npm as **`convex-logto`**.

## Repo layout (pnpm + Turborepo monorepo)

- `packages/convex-logto/` — the published library (the **only** published package).
  - `src/config.ts` — `logtoAuthConfig()` (for `auth.config.ts`), `logtoConfigQuery()` (serves `{ endpoint, appId }` to the frontend).
  - `src/react.tsx` — `ConvexLogtoProvider`, `useLogtoAuth()`. This is the `convex-logto/react` entry and is **ESM-only**.
  - `src/webhooks.ts` — `logtoSync()`, `registerLogtoWebhook()`, `verifyLogtoSignature()`.
  - `src/index.ts` — the server entry, `convex-logto`.
- `docs/` — the documentation site (Fumadocs on TanStack Start; deployed to Vercel).
- `.changeset/` — Changesets config + pending release notes (workspace-level).

## Commands (run from the repo root)

| Task | Command |
|---|---|
| Install | `pnpm install` |
| Build library | `pnpm --filter convex-logto build` (tsup; dual ESM/CJS, `/react` ESM-only) |
| Test | `pnpm --filter convex-logto test` (vitest) |
| Typecheck | `pnpm --filter convex-logto check-types` (tsc) |
| Lint | `pnpm --filter convex-logto lint` (oxlint) |
| Format | `pnpm --filter convex-logto format` (oxfmt, scoped to `src/`) |
| Validate package | `pnpm --filter convex-logto lint:package` (publint + are-the-types-wrong) |
| Docs site | `pnpm --filter docs dev` / `pnpm --filter docs build` |

## Conventions

- **Lint/format:** OXC — `oxlint` + `oxfmt`. Run `format` before committing; CI enforces `lint` + `format:check`. oxfmt is scoped to `src/` (never reformats `package.json` / `CHANGELOG.md` / lockfiles).
- **Runtime:** the library must run in Convex's **V8 runtime** — use Web APIs (e.g. `crypto.subtle`), not Node-only APIs.
- **TypeScript:** strict, `verbatimModuleSyntax`.
- **`convex-logto/react` is ESM-only** because it depends on `@logto/react@4` (ESM-only). The root `convex-logto` entry is dual ESM+CJS.
- **Auth model:** validate Logto's **ID token** over OIDC (Convex rejects `at+jwt` access tokens). No manual JWT config — the signing algorithm and JWKS are auto-discovered.

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
