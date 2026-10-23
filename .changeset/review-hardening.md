---
"convex-logto": minor
---

Fixes from a full review, each with a regression test:

- Session mode: a tab that adopts the session another tab signed in over it no longer keeps serving the revoked session's ID token to Convex (it could keep acting as the previous user until that token expired).
- Session mode: `getOrganizationTokenClaims`, `getAccessTokenClaims` and `fetchUserInfo` read the session token inside the Web Lock. Queued behind a refresh, they could present a rotated-away token past the reuse window, which deletes the session.
- Session mode: a forced token fetch no longer merges into a refresh started before a sign-out, which could sign the new session out.
- Expo: a sign-out whose keychain delete failed no longer blocks the next sign-in until the app restarts.
- The component deletes a session on refresh only for `invalid_grant`. Any other 4xx error code (`invalid_target`, a DPoP error, codes Logto adds later) keeps every session and reports a transient error.
- Webhooks: the route records a delivery as completed. A retry of a delivery that never completed redoes the revocation and answers 503, so a deleted or suspended user can no longer stay signed in for the 24-hour dedupe window after a failed attempt.
- Back-channel logout answers 200 instead of 400 when the revocation committed and only recording it failed.
- The cookie handler's unsafe-`returnTo` rejection uses the same structured error as every other 400.
- `exchangeToken` / `fetchUserInfo` registered types include `forceRefresh`.

CLI: `--defaults <dev|preview|prod>` reads and writes the project's default variables, which is how preview deployments get `LOGTO_JWKS`; `--endpoint <url>` for apps that pass `endpoint` to `logtoAuthConfig`. `check-jwks` warns only about an unusable staged next key, prints multi-line errors as one GitHub annotation, and exits 2 on a bad option.
