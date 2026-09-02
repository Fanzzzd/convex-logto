# convex-logto native session mode + Expo (React Native)

In session mode on React Native, your Convex deployment is the OAuth client (a
Logto Traditional Web app), so the Logto refresh token never reaches the device.
A Convex component holds it, rotates a session token with the app, and pushes
revocation reactively. The app bundle carries **no Logto config at all**, not
even the endpoint, and **no Logto SDK**: no `@logto/rn`, no
`@react-native-async-storage/async-storage`. Auth uses the
`convex-logto/native-session` entry on top of `expo-secure-store` and
`expo-web-browser`.

Contrast with [`examples/expo`](../expo), which is *bridge* mode. That one embeds
`@logto/rn`, pulls `{ endpoint, appId }` from the backend, and lets the device
hold the Logto refresh token itself. Both validate the same OIDC ID token, so
`convex/auth.config.ts` is identical; everything else differs.

| | `examples/expo` (bridge) | this example (session) |
| --- | --- | --- |
| Logto app type | Single page app | Traditional web (has a secret) |
| Refresh token | on the device, via `@logto/rn` | server-held, inside the component |
| Device credentials | Logto's SDK storage | short-lived ID token + rotating session token, both SecureStore |
| Client dependencies | `@logto/rn`, async-storage, expo-crypto | `expo-secure-store`, `expo-web-browser` |
| Revocation | ID token expiry | reactive `sessionValid` + `assertSubjectHasActiveSession` |
| Sign out everywhere | none | `signOutEverywhere()` |
| Where am I signed in | none | `listSessions()` / `renameSession()` / `revokeSession()` |

## Run

1. Install from the repo root: `pnpm install`
2. In this directory, start Convex (installs the component, creates a deployment,
   writes `EXPO_PUBLIC_CONVEX_URL` to `.env.local`):
   ```bash
   npx convex dev
   ```
3. In Logto, create a **Traditional web** application and register the **native**
   redirect URIs; these use the `scheme` in `app.json` (`io.logto.session`):
   - **Redirect URI** → `io.logto.session://callback`
   - **Post sign-out redirect URI** → `io.logto.session://callback`

   Also rotate the tenant's OIDC signing key to **RSA** (Tenant settings → OIDC
   configs → **Rotate private keys** → choose RSA). Convex rejects Logto's default
   ES384, so this is required; otherwise `getUserIdentity()` returns `null`. Note
   the app's **endpoint**, **App ID**, and **App Secret**.
4. Point the deployment at that app; all config lives server-side:
   ```bash
   npx convex env set LOGTO_ENDPOINT      https://your-logto.example.com
   npx convex env set LOGTO_APP_ID        your-traditional-web-app-id
   npx convex env set LOGTO_CLIENT_SECRET your-traditional-web-app-secret
   ```
5. Build and run on a device or simulator (see the dev-build note below):
   ```bash
   npx expo run:ios      # or: npx expo run:android
   ```

> In this monorepo the dependency is `convex-logto: workspace:*`. Standalone, run
> `npm i convex-logto` and `npx expo install expo-secure-store expo-web-browser`.
> Session mode needs no other auth dependency.

## Requires a development build

Sign-in returns through the custom `io.logto.session://` scheme, which **Expo Go
on Android can't register**; use a development build there (`npx expo
run:android`, or an EAS dev build). A dev build is the reliable path on both
platforms.

For a bare-workflow or EAS build, `expo prebuild` writes the scheme into the
native projects from `app.json`; the pieces it generates are the iOS
`CFBundleURLTypes` entry and the Android `<intent-filter>` for
`io.logto.session`. If you change the scheme, change it in `app.json`, re-run
`expo prebuild --clean`, and update both Logto URIs to match.

## What to look at

- `convex/convex.config.ts`: installs the session component (`app.use(logto)`).
- `convex/auth.ts`: the entire server side, one `logtoSessionApi(...)` call,
  byte-identical to the web session example's. One server, both platforms.
- `App.tsx`: `ConvexLogtoSessionProvider` with `redirectUri` and the advisory
  `clientDescriptor`, plus the `Sessions` panel (`listSessions()` /
  `renameSession()` / `revokeSession()`) and `signOutEverywhere()`.
- `convex/me.ts`: `assertSubjectHasActiveSession` for subject-level revocation
  enforcement on sensitive functions.

## Native specifics this example gets right

- **No callback route.** `signIn()` opens the system browser and resolves when the
  deep link returns; the exchange happens in place, so there is no screen to add.
- **SecureStore only, never a downgrade.** SecureStore encrypts the rotating
  session token, the OAuth state, and the short-lived ID token, namespaced per
  Convex deployment. If SecureStore is unavailable the provider fails loudly
  rather than falling back to unencrypted storage.
- **Cold start with no round-trip.** A still-valid ID token in SecureStore
  authenticates immediately on launch while its paired session marker remains;
  the provider clears an orphaned bearer. `<AuthLoading>` covers the refresh when
  it expired.
- **Reactive revocation.** The provider subscribes to `sessionValid`, so signing
  out on another device (or a Logto `User.Deleted` webhook) drops this app's auth
  live, not at the next token expiry.
- **No device binding.** Native credential persistence is already bound to the OS
  keystore, so the `deviceBinding` option that exists on web is intentionally
  absent here.
- **`EXPO_PUBLIC_CONVEX_URL`.** Expo only exposes `EXPO_PUBLIC_*` to the bundle,
  and it is the single value this app needs.

> **Want webhook-driven revocation?** `registerLogtoWebhook(http, ..., { sessions: components.logto })`
> wires Logto account events (User.Deleted, suspension) into session revocation, and
> is framework-agnostic; the `convex/` code is identical everywhere. See
> [`vite-react-session`](../vite-react-session/convex/http.ts).

## Expo SDK versions

This example pins **Expo SDK 56** and depends only on `expo-secure-store` and
`expo-web-browser`, both of which version in lockstep with the SDK. Unlike the
bridge-mode example there is no `@logto/rn` peer range to satisfy, so there are no
peer-dependency warnings on any current SDK.
