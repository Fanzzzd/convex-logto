# convex-logto + Expo (React Native)

The smallest correct way to use `convex-logto` in an Expo app. The frontend carries
**no Logto config** — it pulls `{ endpoint, appId }` from the Convex backend via
`api.logto.config`, exactly like the web examples. Auth uses the **`convex-logto/native`**
entry on top of [`@logto/rn`](https://github.com/logto-io/react-native).

## Run

1. Install from the repo root: `pnpm install`
2. In this directory, start Convex (creates a deployment, writes `EXPO_PUBLIC_CONVEX_URL` to `.env.local`):
   ```bash
   npx convex dev
   ```
3. In Logto, create a **Single page app** (a native app shares the same SPA app type) and register the **native** redirect URIs — these use your `app.json` `scheme` (`io.logto`):
   - **Redirect URI** → `io.logto://callback`
   - **Post sign-out redirect URI** → `io.logto://callback`

   Also rotate the tenant's OIDC signing key to **RSA** (Tenant settings → OIDC configs → **Rotate private keys** → choose RSA). Convex rejects Logto's default ES384, so this is required; otherwise `getUserIdentity()` returns `null`. Note its **endpoint** and **App ID** for the next step.
4. Point that deployment at your Logto app:
   ```bash
   npx convex env set LOGTO_ENDPOINT https://auth.example.com
   npx convex env set LOGTO_APP_ID   your-app-id
   ```
5. Build and run on a device/simulator (see the dev-build note below):
   ```bash
   npx expo run:ios      # or: npx expo run:android
   ```

> In this monorepo the dependency is `convex-logto: workspace:*`. Standalone, run
> `npm i convex-logto @logto/rn` and `npx expo install expo-crypto expo-secure-store expo-web-browser @react-native-async-storage/async-storage`.

## React Native specifics this example gets right

- **One provider, no callback route.** `<ConvexLogtoProvider>` wraps the app in
  `App.tsx`. Unlike the web, `signIn` opens the system browser and resolves when the
  `io.logto://callback` deep link returns — there is no callback screen to add.
- **`redirectUri` on the provider.** `signIn()` defaults to the provider's
  `redirectUri` (`io.logto://callback`), which must match the Logto redirect URI and
  the `scheme` in `app.json`.
- **`fallback` covers the one-time config fetch.** Native has no SSR "inert client"
  trick, so children mount once `{ endpoint, appId }` arrives; Convex's `<AuthLoading>`
  then covers the token handshake.
- **`EXPO_PUBLIC_CONVEX_URL`** — Expo only exposes `EXPO_PUBLIC_*` env vars to the bundle.

## Requires a development build

`@logto/rn` uses native modules (`expo-secure-store`, `expo-crypto`, `expo-web-browser`),
so it is **not** compatible with **Expo Go on Android** — use a development build
(`npx expo run:android` / `run:ios`, or an EAS dev build). iOS Simulator via
`expo run:ios` works.

## A note on Expo SDK / `@logto/rn` versions

This example pins **Expo SDK 56** (latest) to match Logto's own sample app. The
**published** `@logto/rn@1.1.0` still declares peer ranges for the older,
independently-versioned Expo modules (`expo-* >=14 <16`), so `pnpm install` prints
peer-dependency **warnings** for `expo-crypto` / `expo-secure-store` / `expo-web-browser`
on SDK 54+. They are warnings, not errors — the SDK runs fine on SDK 56 (Logto's master
sample proves it) — and will clear once Logto publishes a release with updated peer ranges.
To avoid the warnings entirely, pin Expo SDK 53 (RN 0.79), which is within the published
peer ranges.

> **Want webhook user-sync?** It's framework-agnostic — the `convex/` backend code is
> identical across examples. See the [`tanstack-router-spa`](../tanstack-router-spa) example.
