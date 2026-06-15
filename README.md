# convex-logto

[![npm](https://img.shields.io/npm/v/convex-logto.svg)](https://www.npmjs.com/package/convex-logto)
[![CI](https://github.com/Fanzzzd/convex-logto/actions/workflows/ci.yml/badge.svg)](https://github.com/Fanzzzd/convex-logto/actions/workflows/ci.yml)
[![license](https://img.shields.io/npm/l/convex-logto.svg)](./LICENSE)

Use [Logto](https://logto.io) (self-hosted or cloud) as the auth provider for [Convex](https://convex.dev) React apps — an ID-token OIDC bridge plus a signed webhook user-sync, with the least setup possible.

## Install

```bash
npm i convex-logto @logto/react
```

`convex` and `react` are peers you already have.

## Repository

This is a pnpm + Turborepo monorepo.

- **[`packages/convex-logto`](packages/convex-logto)** — the published library. See its [README](packages/convex-logto/README.md) for full docs and quick start.
- **[`examples/`](examples)** — runnable examples across Vite, TanStack Router/Start, and Next.js (one with role-based access).
- **[`docs/`](docs)** — the documentation site source (Fumadocs).

## Links

- npm: <https://www.npmjs.com/package/convex-logto>
- GitHub: <https://github.com/Fanzzzd/convex-logto>

## License

[MIT](./LICENSE)
