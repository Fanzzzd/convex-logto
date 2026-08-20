# convex-logto

## 0.5.0

### Minor Changes

- [#109](https://github.com/Fanzzzd/convex-logto/pull/109) [`f97a023`](https://github.com/Fanzzzd/convex-logto/commit/f97a0230a2aa01723dee44cf75a682ddc5ee72eb) Thanks [@Fanzzzd](https://github.com/Fanzzzd)! - Add opt-in auth phase timings. Every provider now takes an `onAuthEvent` handler
  that receives `{ phase, elapsedMs, source?, errorKind? }` for the auth bootstrap:
  `bootstrap_start`, `config_loaded` (bridge mode's config fetch),
  `session_restored` / `unauthenticated`, `convex_authenticated` — the point where
  the first authenticated query can run — plus `refresh_started` /
  `refresh_succeeded` / `refresh_failed`, `revoked` and `signed_out`.
  
  Bridge mode emits `bootstrap_start`, `convex_authenticated`, and — in
  `configQuery` mode, the only mode with a fetch to time — `config_loaded`. The
  Logto SDK owns the credential lifecycle there, so the rest are session mode's.
  
  `elapsedMs` counts from `bootstrap_start` on a monotonic clock. `source` tells a
  zero-round-trip cache restore apart from an SSR hand-off, a refresh, or a
  callback exchange; `errorKind` tells a dead session apart from an outage. Events
  carry no token, no user identity and no URL, so they can be forwarded to an
  analytics backend as-is.
  
  Without a handler nothing is measured and no clock is read. A handler that throws
  is caught and logged — telemetry can never fail an authentication. Only the first
  settle reports `session_restored` / `unauthenticated`, so a long-lived tab does
  not look like it keeps re-mounting.

- [#48](https://github.com/Fanzzzd/convex-logto/pull/48) [`ae9a28f`](https://github.com/Fanzzzd/convex-logto/commit/ae9a28f2aeb96c06eb19407204b006d94f0356fe) Thanks [@Fanzzzd](https://github.com/Fanzzzd)! - Add verified OIDC back-channel logout for session mode.

- [#85](https://github.com/Fanzzzd/convex-logto/pull/85) [`9a6056d`](https://github.com/Fanzzzd/convex-logto/commit/9a6056d30ee8ef92712b85adf8d357c0514db1fe) Thanks [@Fanzzzd](https://github.com/Fanzzzd)! - Make cookie-transport sign-out honest. The session credential in cookie mode is
  an HttpOnly cookie that only the server can expire, so a failed revoke is a
  failed sign-out: `signOut()` now rejects instead of resolving while the user
  stays signed in, and a revoke failure always reaches `onAuthError` even in
  localStorage mode, where sign-out remains locally complete. Every sign-out
  response from the cookie route now carries the clear-cookie header, including
  the request-validation and malformed-body paths, and validation errors are
  returned in the structured `{ kind, code, message }` shape so the client can
  classify them — an `everywhere: true` call against a handler without
  `signOutEverywhere` gets the 409 upgrade guidance rather than an opaque 400.
  An empty `postLogoutRedirectUri` is treated as absent instead of being
  forwarded to a validator that rejects it.

- [#45](https://github.com/Fanzzzd/convex-logto/pull/45) [`d1d95f3`](https://github.com/Fanzzzd/convex-logto/commit/d1d95f3ee7b68e163e43a2ec1874d02f6d150162) Thanks [@Fanzzzd](https://github.com/Fanzzzd)! - Add React Native and Expo session mode with SecureStore persistence and system-browser OAuth.

- [#42](https://github.com/Fanzzzd/convex-logto/pull/42) [`c8b9a9c`](https://github.com/Fanzzzd/convex-logto/commit/c8b9a9c676782e57ef3196430fb5911240d58244) Thanks [@Fanzzzd](https://github.com/Fanzzzd)! - Add opt-in device binding for session tokens using non-extractable IndexedDB keys and proof-of-possession refresh signatures.

- [#50](https://github.com/Fanzzzd/convex-logto/pull/50) [`12c89b7`](https://github.com/Fanzzzd/convex-logto/commit/12c89b73a98b63ef6197f980b43544b98d722148) Thanks [@Fanzzzd](https://github.com/Fanzzzd)! - Add subject-scoped sign out everywhere to web and native session mode.

- [#37](https://github.com/Fanzzzd/convex-logto/pull/37) [`13ce03b`](https://github.com/Fanzzzd/convex-logto/commit/13ce03b3016da99c69ff0a81e1e981c1a21e77b7) Thanks [@Fanzzzd](https://github.com/Fanzzzd)! - Add an optional same-site HttpOnly cookie transport for session mode, including SSR seeding and Next.js, TanStack Start, and Convex HTTP action mounts.

- [#162](https://github.com/Fanzzzd/convex-logto/pull/162) [`9231f6c`](https://github.com/Fanzzzd/convex-logto/commit/9231f6ccfc44c1d7ce5aabf55d5addbd0498f5bd) Thanks [@Fanzzzd](https://github.com/Fanzzzd)! - Native session mode: `useLogtoAuth()` gains `completeSignIn(url)`, for a sign-in
  whose deep link arrives outside the system-browser promise. When the OS reclaims
  the app mid-flow that promise dies with the process, and the user used to come
  back signed in at Logto but signed out in the app, with no error. Wire it to
  Expo `Linking` — anything that is not the app's `redirectUri` is ignored.

- [#69](https://github.com/Fanzzzd/convex-logto/pull/69) [`90f6dc2`](https://github.com/Fanzzzd/convex-logto/commit/90f6dc24455fa9566538ab34e207ed938c5a60de) Thanks [@Fanzzzd](https://github.com/Fanzzzd)! - Fence refresh claims and client auth generations so stale refreshes cannot
  overwrite or resurrect a signed-out session. Harden persisted-session recovery,
  durable browser sign-out, runtime response validation, bounded session
  revocation, and recent token generation handling. Recheck logical revocation
  markers before committing refreshed credentials. Require device proof before
  revoking a bound session and
  avoid grant-wide RFC 7009 calls when abandoning one local Session, because
  Logto grants may be shared by sibling Sessions. Validate Logto and navigation
  URLs, stream-limit public request bodies, and bound JWKS fetch time, size, key
  count, concurrent refreshes, token-endpoint responses, and browser
  cookie-transport responses. Add
  `assertSubjectHasActiveSession` as the accurately named subject-level policy
  check; retain
  `assertUserHasActiveSession` as a deprecated compatibility alias.
  
  Also fence the sign-in callback exchange against a sign-out that lands while
  the authorization code is being redeemed (the minted session is revoked instead
  of installed), report a durable browser-storage removal failure only when a
  credential is actually still there, keep the refresh claim whenever Logto's
  answer is unknown so a possibly-rotated refresh token is never spent twice,
  treat `invalid_client` and the other OAuth configuration faults as transient
  instead of deleting every session in the deployment, refuse a logically revoked
  session's token for `signOutEverywhere`, and accept Logto's nullable
  `lastSignInAt` and its `User.Deleted` payload with no `data` key.

- [#100](https://github.com/Fanzzzd/convex-logto/pull/100) [`7198889`](https://github.com/Fanzzzd/convex-logto/commit/71988892981850e237043c066e1787eb58f631c5) Thanks [@Fanzzzd](https://github.com/Fanzzzd)! - Session mode: add a "where am I signed in" surface. `logtoSessionApi(...)` now
  returns `listSessions` / `renameSession` / `revokeSession`, and both session
  providers expose them from `useLogtoAuth()` alongside a new optional
  `clientDescriptor` prop that stamps an advisory, app-supplied device description
  on the session at sign-in (the library never reads a User-Agent or IP).
  
  All three authenticate exactly as `signOutEverywhere` does: the subject comes
  only from the caller's presented live session token, so another subject's
  `sessionId` — or one already killed by a revocation watermark — raises the normal
  terminal `session_not_found`. Labels are normalized (whitespace collapsed,
  control characters and bidi overrides stripped) and rejected past 64 code points
  rather than truncated. The list returns at most 16 sessions, newest first, with
  `truncated` when there are more.
  
  The cookie transport gains a `sessions` route multiplexing the three operations,
  and forwards the client descriptor through `callback`. Re-export the three new
  functions from your `convex/auth.ts`; a deployment that has not yet fails with
  the same explicit upgrade message `signOutEverywhere` uses.

- [#147](https://github.com/Fanzzzd/convex-logto/pull/147) [`a06fe1b`](https://github.com/Fanzzzd/convex-logto/commit/a06fe1b48868f9008a572e47b7a32eb7aa30b73f) Thanks [@Fanzzzd](https://github.com/Fanzzzd)! - Surface sign-out failures instead of swallowing them, on web and native.
  
  A failed sign-out is not cosmetic: `@logto/client` reaches OIDC discovery
  **before** it clears tokens, so an unreachable Logto leaves the user signed in
  with a live ID token while the button looks like it worked.
  
  On the web, `@logto/react` caught that failure into its own state and resolved
  the promise, and the bridge only registered sign-*in* attempts — so nothing
  reported it and `onAuthError` never fired. Sign-out now registers an attempt the
  same way, so the swallowed error is reported once, and a direct rejection is
  reported and rethrown.
  
  The native bridge had no error surface at all: `@logto/rn` rejects rather than
  storing the error, and the documented pattern is `void signIn()` in an
  `onPress`, so a dismissed system browser or an offline sign-out became an
  unhandled rejection and *nothing else*. The native `<ConvexLogtoProvider>` now
  takes `onAuthError`, matching the web provider and native session mode, and both
  `signIn()` and `signOut()` report through it before rejecting. Reporting is not
  handling: a promise that rejects still does, so a fire-and-forget caller wants
  `.catch(() => {})` alongside `onAuthError` — the docs now say so instead of
  calling `void signIn()` safe.

- [#133](https://github.com/Fanzzzd/convex-logto/pull/133) [`7d1e28b`](https://github.com/Fanzzzd/convex-logto/commit/7d1e28b6957238e5b58af4fc4be731288e09dc71) Thanks [@Fanzzzd](https://github.com/Fanzzzd)! - Stop dropping a Logto webhook delivery over a field the library never reads.
  
  `isLogtoWebhookPayload` type-checked roughly fifteen advisory fields — `hookId`,
  `userAgent`, `ip`, `path`, `method`, `status`, `matchedRoute`, and most of the
  User entity — and one mismatch made the route answer 400 *before* it recorded
  the delivery or revoked sessions. Logto retries a 5xx, not a 4xx, so a single
  drifted field meant permanent, first-attempt loss of every `User.*` event for
  that user, taking the deletion and suspension revocation path with it. A
  `userAgent: null`, a missing `hookId`, an `identities: []` or a stringified
  `status` was enough.
  
  The predicate now accepts on exactly what the library consumes: a known `User.*`
  event, a string `createdAt` for the replay window, and a usable user id (with
  the existing rule that a `User.Deleted` carrying both `data.id` and
  `params.userId` must not contradict itself). A field that drifted out of its
  declared type is dropped from the entity handed to sync handlers rather than
  rejected, so a handler still receives the declared `LogtoUserEntity` shape while
  the raw value stays reachable on the payload it also receives. Fields Logto adds
  later pass through untouched, as before.
  
  One rejection is new, not relaxed: a `User.Deleted` whose entity carries an
  `id` that is not a string. That id is one the library *does* consume, and an
  unreadable one could be naming a different user than the route params — a
  destructive event must not run on a guess. A `User.Deleted` whose entity simply
  names no one (`data: {}`) is now accepted, since it carries the same
  information as the documented `data: null` shape.
  
  `LogtoWebhookPayload["hookId"]` is now optional, for the same reason as the
  rest: nothing reads it, so nothing should turn on it.

### Patch Changes

- [#148](https://github.com/Fanzzzd/convex-logto/pull/148) [`0c41db4`](https://github.com/Fanzzzd/convex-logto/commit/0c41db45b6c5b4e6b718733e846c6dd4b65ba873) Thanks [@Fanzzzd](https://github.com/Fanzzzd)! - Stop back-channel logout from answering 200 for a revocation that never
  committed.
  
  The endpoint claimed the logout token's `jti` *before* dispatching the
  revocation, and a claim only proves that a delivery started. If the first
  delivery failed after claiming and its release also failed — the release is
  best-effort, since there is nothing left to do about it — every Logto retry for
  the next 24 hours was answered 200 without revoking anything, and the user
  stayed signed in through a completed OIDC back-channel logout.
  
  Delivery records now carry a completion marker. A replay is answered without
  work only once some delivery got as far as recording completion; an unfinished
  claim is redone, which is safe because revocation is idempotent — the watermark
  takes the max of what it already holds, and the drain deletes rows that are
  already dead. Suppressing *completed* replays still matters and is unchanged: a
  `sub`-only logout token revokes whatever the subject has at the moment it runs,
  so replaying one after the user signs in again would sign them out a second
  time.
  
  Releasing a claim after a failure no longer deletes a *completed* record: a
  retry can take over an abandoned claim and finish while the original owner is
  still failing, and deleting the row then would erase the only proof the work
  happened.
  
  The webhook route keeps answering a claimed delivery without redoing it, since
  an app's sync handlers write to its own tables and are not idempotent.

- [#175](https://github.com/Fanzzzd/convex-logto/pull/175) [`6958170`](https://github.com/Fanzzzd/convex-logto/commit/6958170fdd8a7b95218bea62fb5298eceb20f3cd) Thanks [@Fanzzzd](https://github.com/Fanzzzd)! - Session mode: a device public key is now checked before the authorization code
  is spent, and counted against the session-list scan budget. `x` and `y` were the
  only caller-supplied strings the component stored without a bound of their own —
  and the one field `sessionReadCost` did not count — so a hand-driven `callback`
  could store near-1 MiB session rows that the list scan measured at ~512 bytes.

- [#146](https://github.com/Fanzzzd/convex-logto/pull/146) [`1f1e99f`](https://github.com/Fanzzzd/convex-logto/commit/1f1e99f8c5e9a38d9dedd5b53ba5ac5e40d19e68) Thanks [@Fanzzzd](https://github.com/Fanzzzd)! - Fix three bridge-mode defects that all trace to reading `window.location` during
  render.
  
  **A callback that resolved without authenticating could pin Convex at
  `isLoading` forever.** The loading veto was derived from the URL, which is not a
  reactive source, and it has absolute priority over the settle latch. In the
  layout every SPA example ships — provider mounted above the router — the soft
  navigation out of `/callback` re-renders only the router subtree, so the veto
  stayed frozen at "still on /callback" for the rest of the page session. A spent
  or replayed code, a lost sign-in session, a state mismatch, or the documented
  10-second stale-callback timeout would leave the app showing a loading state
  with no Sign in button, recoverable only by reloading. The callback flow is now
  provider state that ends when the callback resolves, whatever the outcome.
  
  **The sign-in error observer never mounted for a page session that began on the
  callback route.** Same frozen read, so a later sign-in whose failure
  `@logto/react` swallows into its own state — the case `onAuthError` exists for —
  went unreported and the button appeared to do nothing.
  
  **A cancelled sign-in could lose its `returnTo`.** The benign/error branch had no
  idempotence guard, so React's StrictMode double-invoke (every shipped example
  wraps the provider in it) ran it twice: the first pass consumed the destructive
  `returnTo` stash and navigated correctly, the second found it empty and
  redirected to `afterSignIn` instead. A setup error was reported twice for the
  same reason.

- [#195](https://github.com/Fanzzzd/convex-logto/pull/195) [`a2e870a`](https://github.com/Fanzzzd/convex-logto/commit/a2e870ac5e33a80116b43467da8de074fa907ff9) Thanks [@Fanzzzd](https://github.com/Fanzzzd)! - Session mode: a sign-in no longer dies on one bad packet.
  
  The callback exchange is single-use, so it is never blindly retried once the deployment has answered — the component consumes the sign-in transaction before it contacts Logto, and a second attempt could only report `transaction_not_found`, burying the real diagnosis. But a failure that never reached the deployment consumed nothing, and losing a sign-in to a dropped connection or a transport timeout is worse than an attempt that finds nothing. A non-`ConvexError` failure is now retried exactly once; if that retry reports the transaction is gone, the first attempt did land after all and *its* error is the one reported.
  
  Also: the sign-in-path error suffix no longer claims "the authorization code is spent" — a `logto_unreachable` may never have reached Logto. What is always true is that the attempt is unrepeatable. The reactive-revocation failure report is deduped against the underlying query error rather than the wrapper built inside the effect.

- [#120](https://github.com/Fanzzzd/convex-logto/pull/120) [`9e46869`](https://github.com/Fanzzzd/convex-logto/commit/9e4686949c9bd7d61d28ce910b6e3ddd699804ba) Thanks [@Fanzzzd](https://github.com/Fanzzzd)! - Fix three defects an adversarial audit of the client half confirmed.
  
  **Non-ASCII ID token claims were garbled in session mode.** The payload was
  decoded with bare `atob`, which yields one latin-1 character per byte, so a
  `name` of `王小明` arrived as mojibake and `José` as `JosÃ©`. It affected every
  snapshot path — cached restore, refresh, callback exchange, and the cookie
  transport's SSR seed — while bridge mode rendered the same name correctly, so
  migrating from bridge to session mode silently broke non-ASCII names. Both
  halves now share one UTF-8 segment decoder.
  
  **One failed durable credential removal wedged `signIn()` and refresh for the
  life of the page.** A sign-out that cannot delete a credential correctly fails
  loud, but the record of that failure also rejected the storage barrier every
  other transition awaits — including the two ways a user recovers. Signing in
  minted an authorize URL and then never navigated, and a completed refresh was
  reported as `refresh_failed` while the tab held live credentials. The barrier now
  waits for writes only; the surviving-credential assertion belongs to sign-out
  alone.
  
  **A refresh span could stay open.** When a sign-out, a revocation, or another
  tab's sign-out landed mid-refresh, the generation fence discarded the result
  without an end phase, so telemetry pairing `refresh_started` with an end event
  recorded a refresh that never finished. The new `refresh_abandoned` phase closes
  it: exactly one end phase now follows every `refresh_started`.

- [#140](https://github.com/Fanzzzd/convex-logto/pull/140) [`c8cdf9f`](https://github.com/Fanzzzd/convex-logto/commit/c8cdf9fe63a69feb0b59833f068ae93bdb070786) Thanks [@Fanzzzd](https://github.com/Fanzzzd)! - Garbage-collect revocation watermarks.
  
  `subjectRevocations` and `sidRevocations` were never collected: `gc` swept every
  other table and skipped these two, and nothing else deleted from them. With
  back-channel logout enabled that is one permanent row per Logto OP session that
  ever ends — `markSidRevoked` inserts even when the logout matched no sessions,
  which the guide describes as a normal outcome — and the tables are
  component-private, so an app cannot prune them either.
  
  `gc` now collects a watermark, but only when it can no longer kill anything: no
  session it governs survives, and it is older than `SESSION_GC_AFTER_MS`. Both
  conditions are load-bearing. Deleting a marker while a row it killed is still
  waiting for a cleanup batch would hand that row's token its authority back, and
  a refresh can bind a `sid` to a session that did not carry one, so "nothing
  governed today" is not sufficient on its own. Two new `by_revokedAt` indexes let
  the sweep find candidates without scanning; the component takes care of building
  them on the next push, and no migration is required.

- [#188](https://github.com/Fanzzzd/convex-logto/pull/188) [`2b9fadf`](https://github.com/Fanzzzd/convex-logto/commit/2b9fadf92a24ebae9f370b2918e16776fabd1ec8) Thanks [@Fanzzzd](https://github.com/Fanzzzd)! - Native session mode: `completeSignIn(url)` now works on the cold start it was
  added for. It waits for SecureStore to hydrate before touching the OIDC stash —
  the deep link normally arrives before the provider's mount effect, and reading
  the stash too early deleted the transaction it came to spend. A duplicate
  delivery of the same URL now completes once instead of reporting a replayed
  callback, and a link that matches the redirect prefix but carries no OIDC
  response leaves an in-flight sign-in alone.

- [#139](https://github.com/Fanzzzd/convex-logto/pull/139) [`29cdb7d`](https://github.com/Fanzzzd/convex-logto/commit/29cdb7d20e805d6a15755bab4621c30dac7e3d03) Thanks [@Fanzzzd](https://github.com/Fanzzzd)! - Fix three defects an adversarial audit of the cookie transport and device
  binding confirmed.
  
  **A Logto outage turned SSR seeding into a 500 for every signed-in visitor.**
  `getInitialToken` rethrew any error it could not classify, and an unreachable
  Logto is exactly that class — the component rethrows a raw `fetch` failure
  unclassified on purpose, so that an outage does not force a reauthentication.
  With the documented root-loader seeding path, the loader threw and the whole
  document failed. The browser `/token` route had always treated the same failure
  as transient and kept the session; the seed now matches both it and the
  documented contract, "every failed seed returns empty without changing the
  cookie".
  
  **"Sign out everywhere" with no cookie answered a body the client rejects.** The
  route parsed the `everywhere` flag and then returned a bare `{}` when the cookie
  was already gone. The client validates that call on `count`, so it retried twice
  and threw — a hard error for what is a clean no-op. It now answers
  `{ count: 0 }`.
  
  **A device key could be reported as persisted when its transaction aborted.**
  `add()` resolved from the IndexedDB *request*, but a commit-time failure
  (`QuotaExceededError`) arrives on the *transaction*, after that request has
  already succeeded. The binding then lived only in the tab's memory: the next
  reload generated a different key, every device proof was rejected, and the
  component deleted the session — a sign-in loop that survived one page load at a
  time. `add()` now settles on the transaction, so the failure reaches the loud
  path the module promises instead of falling back silently.

- [#190](https://github.com/Fanzzzd/convex-logto/pull/190) [`8582f47`](https://github.com/Fanzzzd/convex-logto/commit/8582f47b56edb5fa30088cf1f57e427bfe803ac4) Thanks [@Fanzzzd](https://github.com/Fanzzzd)! - Session mode: a revoked session no longer signs every other tab out.
  
  The session credential is shared by every tab on an origin, but the session id an engine watches is its own. When another tab signed in it replaced that credential, and a revocation of the *previous* session then cleared storage — deleting the credential the new session was reached by, signing every tab out and orphaning the row that was just created. An engine now checks the stored session id against the one it is holding and adopts a newer credential instead of destroying it.
  
  The revoke of a session that a fresh sign-in replaced is also awaited before the post-callback navigation. With no `navigate` prop that navigation is `location.replace`, which tears down the in-flight request, so the cleanup was unreliable in exactly the default configuration; it is bounded by the transport deadline and still reported rather than thrown.

- [#163](https://github.com/Fanzzzd/convex-logto/pull/163) [`9af15f1`](https://github.com/Fanzzzd/convex-logto/commit/9af15f17681c457773d019d738b99a768e23d1ad) Thanks [@Fanzzzd](https://github.com/Fanzzzd)! - Session mode: re-seeding SSR state or passing an inline `cookieTransport.fetch`
  no longer rebuilds the auth engine. `getInitialToken()` mints a fresh ID token on
  every call, so any `router.invalidate()` handed the provider a new seed and
  restarted the mount state machine — flashing signed-out, orphaning an in-flight
  callback exchange, and leaving the `convex_authenticated` span open forever.

- [#176](https://github.com/Fanzzzd/convex-logto/pull/176) [`560b417`](https://github.com/Fanzzzd/convex-logto/commit/560b417cf8d6766d7f1e00ff9fc47d1ec06958d4) Thanks [@Fanzzzd](https://github.com/Fanzzzd)! - Component: GC drains abandoned sign-ins 128 at a time instead of 4, and sweeps
  revocation watermarks once per run rather than once per chained batch. The old
  batch size was sized against a near-1 MiB `transactions` row that
  `SIGN_IN_URL_MAX_LENGTH` has since made impossible, and every extra sweep
  re-reads session documents.

- [#127](https://github.com/Fanzzzd/convex-logto/pull/127) [`6e4a178`](https://github.com/Fanzzzd/convex-logto/commit/6e4a1782cf06f32757137250cb419bca2089651a) Thanks [@Fanzzzd](https://github.com/Fanzzzd)! - Reject an over-long session label in the browser instead of as a terminal
  session error. The component classifies a label past 64 characters as terminal,
  and terminal is defined as "this session is gone for good" — so an app following
  that taxonomy would sign a user out for typing a long device name.
  `renameSession` now checks the length before the round-trip and fails with a
  plain error; the component keeps its guard for callers reaching it directly.

- [#149](https://github.com/Fanzzzd/convex-logto/pull/149) [`28a86cf`](https://github.com/Fanzzzd/convex-logto/commit/28a86cf192be9cefa0f62d459acfa073b84b9c48) Thanks [@Fanzzzd](https://github.com/Fanzzzd)! - Give the revocation-watermark sweep its own transaction.
  
  Collecting a watermark proves it governs no surviving session, and that proof
  reads a `sessions` document — the largest this component stores. Running a
  hundred of those lookups inside `gc`, which had already spent most of its
  16 MiB read budget on the transaction and dead-session sweeps, could exceed the
  limit and fail the whole garbage collection, not just the watermark part. The
  sweep is now a separate scheduled mutation with a batch bounded the way the
  revocation drain is, and it continues durably only when a full batch was
  actually collected — a batch that skipped everything found nothing collectable,
  and rescheduling on that would spin on the same rows. The two tables it drains
  are counted separately, so a run that fills *both* batches — subject watermarks
  and `sid` watermarks together, which is exactly the backlogged case — keeps
  going instead of reading the combined total as a partial batch and stopping.

- [#196](https://github.com/Fanzzzd/convex-logto/pull/196) [`686f43e`](https://github.com/Fanzzzd/convex-logto/commit/686f43e42b4402bd9e0e085e8f07a5576b3f6995) Thanks [@Fanzzzd](https://github.com/Fanzzzd)! - Native: a failed token refresh no longer wedges the app.
  
  Convex stops asking for a token after one `null`, and re-arms only when the `isAuthenticated` the bridge reports goes false→true. `@logto/rn` latches its own flag true and never moves it, so one failed refresh — an expired refresh token, a tunnel hiccup on resume — disarmed Convex for the life of the process, and tapping Sign in changed nothing the provider was watching. The bridge now folds the token failure into what it reports, and clears it once `signIn()` resolves (after, never before: clearing on the way in would re-arm Convex against tokens that are still broken) or when the SDK genuinely goes unauthenticated and back.
  
  Native session storage got two fixes as well. One unreadable SecureStore key no longer fails the whole store — a locked device, or an entry written under a stricter keychain accessibility class, fails only its own read, so it is treated as absent for now and left in place rather than costing the user their session. And a credential delete SecureStore refused is now reported until a later delete actually lands, instead of being consumed by the first `flush()` that saw it: the credential is still on the device, so sign-out has not happened.

- [#53](https://github.com/Fanzzzd/convex-logto/pull/53) [`acbc660`](https://github.com/Fanzzzd/convex-logto/commit/acbc660b27db50a9a54ba4df4b9ff05d445cd082) Thanks [@Fanzzzd](https://github.com/Fanzzzd)! - Report bridge and session sign-in initiation failures through onAuthError.

- [#131](https://github.com/Fanzzzd/convex-logto/pull/131) [`6cc9244`](https://github.com/Fanzzzd/convex-logto/commit/6cc924480479241bd08e38f5c502404ca80da891) Thanks [@Fanzzzd](https://github.com/Fanzzzd)! - Stop resolving an OAuth error hint off `Object.prototype`.
  
  The sign-in error classifier looked its hint table up as a plain object, keyed
  by the `error` parameter taken straight from the callback URL. `?error=constructor`
  therefore found `Object`, and the message the app displays ended with
  `function Object() { [native code] }`; `?error=__proto__` appended
  `[object Object]`. The table is a `Map` now, so a lookup can only find a key the
  library put there.

- [#126](https://github.com/Fanzzzd/convex-logto/pull/126) [`7b6fb56`](https://github.com/Fanzzzd/convex-logto/commit/7b6fb56c27e0b849c282a9fe1a33508036d7c005) Thanks [@Fanzzzd](https://github.com/Fanzzzd)! - Close an open redirect in the post-sign-in `returnTo` guard.
  
  `isSafeReturnTo` rejected `//host` and `\`, but not a raw ASCII tab, LF or CR.
  The WHATWG URL parser strips those *before* it parses anything, so
  `/<TAB>/evil.example.com` inspected as an ordinary same-origin path and then
  resolved to `https://evil.example.com/`. A crafted sign-in link — or, with the
  cookie transport, a crafted `returnTo` in the SSR seed request — could therefore
  send a user to an attacker's origin immediately after authenticating, which is
  exactly the client-side open redirector RFC 9700 §4.11.1 forbids. The guard now
  also refuses the C0 range and DEL; a legitimate path carries a control character
  percent-encoded, never raw.

- [#159](https://github.com/Fanzzzd/convex-logto/pull/159) [`3df72bc`](https://github.com/Fanzzzd/convex-logto/commit/3df72bc9e030fd5ef6ab3d712e1f1ebc69836cbd) Thanks [@Fanzzzd](https://github.com/Fanzzzd)! - Session mode: a failing `sessionValid` subscription no longer blanks the app.
  The revocation watcher sits above every error boundary an app can install, and
  `useQuery` rethrows a query error during render — so a frontend deployed ahead
  of its Convex functions took the whole page down for signed-in users. The error
  is now handled as a value: reactive revocation turns off and reports through
  `onAuthError`, and sessions still expire on their own schedule.

- [#121](https://github.com/Fanzzzd/convex-logto/pull/121) [`5308a7e`](https://github.com/Fanzzzd/convex-logto/commit/5308a7e0dedfa0c7d455e0b95075d40506403231) Thanks [@Fanzzzd](https://github.com/Fanzzzd)! - Stop a deployment misconfiguration from deleting sessions, and bound the two
  strings an unauthenticated sign-in stores.
  
  **A refresh failure that describes your deployment is no longer terminal.**
  `invalid_client` was already handled, but three faults routed around it and
  deleted the session row: a `LOGTO_ENDPOINT` that no longer matches the `iss`
  Logto issues (after a custom domain or a reverse proxy moved), a spec-legal array
  `aud` the component rejected while Convex and this library's own back-channel
  logout accept it, and a missing `openid` scope. Each would destroy every session
  in the deployment, one refresh at a time. They are transient now: any refresh
  token Logto rotated is persisted first — re-presenting a superseded token would
  trip Logto's reuse detection and destroy the grant sibling sessions share — and
  the refresh claim is released in the same transaction, because a claim left to
  expire deletes the very session this keeps.
  
  A 2xx that is not a token response at all (a proxy or WAF interstitial) now
  classifies as an unknown outcome, like a 2xx that could not be read: nothing is
  deleted immediately, and the claim expires rather than risk spending a rotated
  token twice.
  
  **`signIn` bounds `redirectUri` and `returnTo`.** Sign-in is necessarily
  unauthenticated, and both strings were stored verbatim in a `transactions` row,
  so anyone who knew the deployment URL could park documents near Convex's 1 MiB
  limit in a loop while GC drained four per mutation. Both are now capped at 2048
  characters, and `redirectUri` must be an absolute URI without embedded
  credentials — custom schemes still work, since native sign-in depends on them.

- [#196](https://github.com/Fanzzzd/convex-logto/pull/196) [`686f43e`](https://github.com/Fanzzzd/convex-logto/commit/686f43e42b4402bd9e0e085e8f07a5576b3f6995) Thanks [@Fanzzzd](https://github.com/Fanzzzd)! - Examples: the Expo session example now handles a reclaimed sign-in, and both session examples report auth errors.
  
  `examples/expo-session` wires `expo-linking` into `completeSignIn`, so a sign-in the OS reclaimed while Logto had the browser — routine on a low-memory Android device — finishes from the cold-start deep link instead of leaving the user signed in at Logto and signed out in the app. Both session examples now pass `onAuthError` and swallow the rejection at the call site, matching `examples/expo`.

- [#158](https://github.com/Fanzzzd/convex-logto/pull/158) [`b2f178b`](https://github.com/Fanzzzd/convex-logto/commit/b2f178b6857b9ba1fa097300690aa65c6c0e8036) Thanks [@Fanzzzd](https://github.com/Fanzzzd)! - Session mode: run session actions over HTTP instead of the app's WebSocket
  client. Convex stops that socket before asking for a fresh token, so the
  `refresh` action it triggered parked forever and the socket was never restarted
  — a server-rejected ID token (a suspended tab, a backgrounded native app) wedged
  the whole app until reload.

- [#200](https://github.com/Fanzzzd/convex-logto/pull/200) [`8b3d693`](https://github.com/Fanzzzd/convex-logto/commit/8b3d693e9fa524abefb2768af0a7c78ae4ca862a) Thanks [@Fanzzzd](https://github.com/Fanzzzd)! - Document that `resources` on `logtoSessionApi()` currently buys nothing. Session
  mode keeps the refresh token in the component and hands the browser only the ID
  token, so the resource-scoped access token the option requests is discarded —
  while a resource indicator Logto does not have registered breaks sign-in
  outright. Leave it unset for now. Bridge mode's `resources` is unaffected: there
  the Logto SDK owns the tokens and exposes `getAccessToken()`.

- [#171](https://github.com/Fanzzzd/convex-logto/pull/171) [`5fe745b`](https://github.com/Fanzzzd/convex-logto/commit/5fe745b57745d8d4eb44f14d062055cf8d9cd236) Thanks [@Fanzzzd](https://github.com/Fanzzzd)! - Session mode: a failed sign-in now reports what actually went wrong. The
  component consumes the sign-in transaction before it contacts Logto, so the
  client's retry could only ever come back with `transaction_not_found` — and a
  wrong `LOGTO_CLIENT_SECRET` was reported as a stale or replayed callback. The
  exchange is no longer retried, and a token-endpoint failure on the sign-in path
  keeps Logto's own error code and message.

- [#173](https://github.com/Fanzzzd/convex-logto/pull/173) [`c4f8a4e`](https://github.com/Fanzzzd/convex-logto/commit/c4f8a4e0d7e7b38acfadc922aba3904a84462197) Thanks [@Fanzzzd](https://github.com/Fanzzzd)! - Session mode: two ways a session could be left behind.
  
  Signing in over a live session now revokes the one it replaces. Logto's SSO
  cookie makes that a silent redirect, so it is how a user retries anything that
  looks like a sign-out — and the replaced row kept a live Logto grant no client
  could reach, showing up in the user's own device list until GC took it 190 days
  later. Never in cookie transport mode: the stored value there is a marker rather
  than a credential, and the same-origin sign-out route reads the cookie the
  callback has already replaced, so revoking by marker would end the session that
  was just created.
  
  A rejected `localStorage` write no longer leaves the superseded value readable.
  Another tab would build its own storage area, read a session token this one had
  already rotated away from, and present it — killing the session for every tab
  once the reuse window passed.

- [#172](https://github.com/Fanzzzd/convex-logto/pull/172) [`741be23`](https://github.com/Fanzzzd/convex-logto/commit/741be236c28c4b0e1983d25cb657c68e6f638613) Thanks [@Fanzzzd](https://github.com/Fanzzzd)! - Session mode: a transient refresh failure no longer strands the tab signed-out
  until reload. Keeping the session token only helps if something presents it
  again — and nothing did, because Convex stops asking for a token after one
  failure and only re-arms when `isAuthenticated` flips. The engine now retries on
  its own backoff and flips its snapshot back on success, so a tunnel hiccup or a
  laptop waking before its network recovers on its own.

- [#189](https://github.com/Fanzzzd/convex-logto/pull/189) [`2ed88ee`](https://github.com/Fanzzzd/convex-logto/commit/2ed88ee13eb58a29053707893b2627886acfc398) Thanks [@Fanzzzd](https://github.com/Fanzzzd)! - Session mode: bound every session request, and let a fresh transient failure
  always arm a fresh recovery. A request that never answered parked the in-flight
  refresh forever — every later token fetch merged into it — and a recovery loop
  left over from before a sign-out could swallow the arming of a new one for up to
  thirty seconds.

## 0.4.0

### Minor Changes

- [#27](https://github.com/Fanzzzd/convex-logto/pull/27) [`8b325f8`](https://github.com/Fanzzzd/convex-logto/commit/8b325f8775dd17dad1035e57774d49fb9f3f9181) Thanks [@Fanzzzd](https://github.com/Fanzzzd)! - Bridge hardening: static config by default, exact-callback handling, and safer sign-in redirects.

  - **Static `config` prop (new default).** Pass `config={{ endpoint, appId }}` (both public values) from build-time env instead of `configQuery` — no config round-trip, no loading phase; sign-in is interactive on first paint. `configQuery` remains supported for runtime-resolved config (multi-tenant), now rendering the new `fallback` prop while it loads and mounting children exactly once when ready. The internal inert-client + keyed-remount machinery is gone.
  - **Callback handling is gated to `callbackPath`** (new prop, default `/callback`). A stray `?code=&state=` on any other route no longer triggers a pending auth state (previously a 10s spinner). The [#11](https://github.com/Fanzzzd/convex-logto/issues/11)/[#14](https://github.com/Fanzzzd/convex-logto/issues/14) protections (loading latch through the exchange, stale-callback resolution) are unchanged — only their trigger is now the exact callback route.
  - **`signIn({ returnTo })`.** The post-sign-in destination must be a same-origin path starting with `/`; full URLs and protocol-relative values are rejected (open-redirect guard, RFC 9700 §4.11.1). `signIn(redirectUri: string)` is deprecated but still works; if its path can't match `callbackPath`, a console error explains the fix.
  - **`onAuthError` prop.** Recoverable sign-in failures (stale/replayed callback, setup errors like `invalid_scope`) no longer throw during render — they're reported to `onAuthError` (and the console) and the user is returned to the app logged out.
  - **OIDC discovery/JWKS cache on by default** (`discoveryCache={false}` to opt out), so the sign-in and callback pages don't each pay a discovery round-trip.
  - **Concurrent token fetches merge** into one in-flight request per kind; a forced refresh is never satisfied by a stale in-flight fetch.
  - **Peer dependency: `@logto/react >= 4`** (was `>= 3` — already de-facto required since the `/react` entry went ESM-only).
  - Native (`convex-logto/native`): the same `config` XOR `configQuery` union; behavior otherwise unchanged.

- [#27](https://github.com/Fanzzzd/convex-logto/pull/27) [`8b325f8`](https://github.com/Fanzzzd/convex-logto/commit/8b325f8775dd17dad1035e57774d49fb9f3f9181) Thanks [@Fanzzzd](https://github.com/Fanzzzd)! - New **session mode**: keep the Logto refresh token out of the browser entirely.

  A Convex component (`convex-logto/convex.config`, installed with
  `app.use(logto)`) acts as the OAuth client for a Logto **Traditional Web** app:
  it performs the code exchange server-side (client secret + PKCE), stores the
  refresh token in component-isolated tables, and gives the browser only a
  short-lived ID token plus a one-time session token that rotates on every
  refresh (hash-stored, reuse-detected — presenting a spent token outside a 10s
  multi-tab grace window kills the session and revokes the Logto grant, RFC 7009).

  - `logtoSessionApi(components.logto)` (from `convex-logto`) builds the five
    public auth functions — `signIn` / `callback` / `refresh` / `signOut` /
    `sessionValid` — reading `LOGTO_ENDPOINT` / `LOGTO_APP_ID` /
    `LOGTO_CLIENT_SECRET` from the deployment env. The secret never reaches the
    browser; scopes/resources are server-configured.
  - New entry `convex-logto/react-session`: `ConvexLogtoSessionProvider` +
    `useLogtoAuth()` with the same shape as the bridge hook — and **no
    `@logto/react` dependency**, no Logto config in the bundle. Sign-in state is
    pinned to the initiating tab (login-CSRF refusal), the callback completes
    without a callback component, reloads authenticate with zero round-trips
    while the cached ID token is fresh, and multi-tab refreshes are
    single-flighted (Web Locks + in-flight merge + a server-side claim).
  - **Reactive revocation**: every session's liveness is a Convex subscription —
    sign-out elsewhere, theft detection, or a webhook suspension drops auth live,
    not at token expiry. `assertUserHasActiveSession(ctx, components.logto)`
    enforces the same server-side for sensitive functions.
  - Runnable example: `examples/vite-react-session`; docs at `/docs/session-mode`.

  Bridge mode is unchanged and remains the default.

- [#24](https://github.com/Fanzzzd/convex-logto/pull/24) [`4275c7f`](https://github.com/Fanzzzd/convex-logto/commit/4275c7f2c5f8f3a8a717c4aaee1ea6a69c470147) Thanks [@Fanzzzd](https://github.com/Fanzzzd)! - Webhook hardening + session revocation wiring for `registerLogtoWebhook`:

  - **Freshness window**: authentic deliveries whose `createdAt` is older than 5
    minutes (or more than 1 minute in the future) are rejected with 400 — the
    signature scheme has no timestamp binding, so this is what retires replayed
    captures. Logto's own retries land within seconds.
  - **1 MB body cap** (413) before any crypto or parsing.
  - **New `sessions` option** — pass `components.logto` (session mode) to get:
    exactly-once handling (deliveries deduplicated by raw-body SHA-256, so a
    retry whose 200 got lost doesn't re-run your sync handlers; the claim is
    released if processing fails so retries still work), and **session
    revocation** — `User.Deleted`, and `User.SuspensionStatus.Updated` with
    `isSuspended: true`, kill all of that user's sessions before your sync
    handlers run, dropping reactive clients to signed-out live.
  - Documented that `hookId` identifies the webhook configuration, not the
    delivery — it is not an idempotency key.

## 0.3.6

### Patch Changes

- [#20](https://github.com/Fanzzzd/convex-logto/pull/20) [`8d9506d`](https://github.com/Fanzzzd/convex-logto/commit/8d9506d7c0f4cd857211c96743967c91d975705d) Thanks [@Fanzzzd](https://github.com/Fanzzzd)! - Fix the app hanging on a loading spinner when `signIn()` is called before the backend config has finished loading (the "stuck on the login button" symptom). During config load the provider mounts an inert Logto client; a `signIn()` in that window poisoned `@logto/react`'s `loadingCount` (its `signIn` increments but never resets, and the inert method never navigates away), and that count survived the swap to the real client — pinning `isLoading` true forever. The `LogtoProvider` is now remounted across the loading→ready transition, so any state built against the inert client is discarded.

## 0.3.5

### Patch Changes

- [#18](https://github.com/Fanzzzd/convex-logto/pull/18) [`be970e8`](https://github.com/Fanzzzd/convex-logto/commit/be970e83d21334c10df8b50b794c955e2d1c679c) Thanks [@Fanzzzd](https://github.com/Fanzzzd)! - Don't crash the app on a stale or replayed `/callback` URL whose code exchange fails.

  When a sign-in session was still in storage (an abandoned or earlier sign-in) and the page landed on a stale/replayed `/callback?code=…&state=…` — a bookmark, the Back button, or a link from a previous deploy — `@logto/react` ran the exchange and it failed with a state mismatch. The provider surfaced that by **throwing during render**, which blanked any app whose error boundary sits inside `<ConvexLogtoProvider>` (or that has none).

  Following how `react-oidc-context` and `@auth0/auth0-react` handle the redirect callback, a failed exchange is now treated as recoverable, not fatal: it is logged (`console.error`) and the provider returns to the app — the user lands logged-out and can start sign-in again — instead of throwing. Genuine OIDC setup errors (an `error=` in the callback URL) still surface loudly as before.

## 0.3.4

### Patch Changes

- [#15](https://github.com/Fanzzzd/convex-logto/pull/15) [`edca280`](https://github.com/Fanzzzd/convex-logto/commit/edca2808d907380e6290dc6d1709d4937804106d) Thanks [@Fanzzzd](https://github.com/Fanzzzd)! - Fix the Logto sign-in callback hanging forever on a stale or already-authenticated `/callback` URL.

  `ConvexLogtoProvider` decided "a code exchange is in progress, keep waiting" purely from the URL (`?code=&state=`), but `@logto/react` only runs the exchange when `!isAuthenticated && isSignInRedirected(url)`. Re-opening an already-consumed callback URL — by refresh, Back button, or a bookmark, most often while already signed in — left the page stuck on the loading state with no navigation, because the SDK's exchange callback never fires. The provider now resolves the callback from the SDK's observable auth state (with a timeout safety net for a lost sign-in session) instead of waiting for an exchange that will never happen ([#14](https://github.com/Fanzzzd/convex-logto/issues/14)).

## 0.3.3

### Patch Changes

- [#12](https://github.com/Fanzzzd/convex-logto/pull/12) [`0f2e2d5`](https://github.com/Fanzzzd/convex-logto/commit/0f2e2d55d57778582ef44711a155f3aa2afe2bcc) Thanks [@Fanzzzd](https://github.com/Fanzzzd)! - Fix a transient `{ isLoading: false, isAuthenticated: false }` window right after
  sign-in that made `useLogtoAuth()` look logged-out while Convex was still
  validating the freshly-issued ID token. A TanStack Router `beforeLoad` guard (or
  any auth gate that acts on that tick) would redirect the just-signed-in user away
  — and bounce into an infinite loop if the sign-in route auto-restarts `signIn()`
  (issue [#11](https://github.com/Fanzzzd/convex-logto/issues/11)).

  Both entries are fixed:

  - **Web (`convex-logto/react`):** the bridge keeps reporting `isLoading: true`
    while a sign-in callback is in flight (an unconsumed `code` in the URL and Logto
    not yet authenticated), so guards wait the validation window out instead of
    seeing a state indistinguishable from a clean logout.
  - **Native (`convex-logto/native`):** `@logto/rn` flips `isAuthenticated` true the
    instant `signIn()` resolves, with no loading signal of its own. The bridge now
    emits one loading frame on that transition — reported as not-yet-authenticated —
    so Convex resets cleanly to "validating" instead of surfacing the logged-out
    tick, with no auth churn once the token validates.

  Post-login token refreshes still don't flicker the identity, and a genuine
  logged-out visit still settles to signed-out as before.

## 0.3.2

### Patch Changes

- [#9](https://github.com/Fanzzzd/convex-logto/pull/9) [`5857537`](https://github.com/Fanzzzd/convex-logto/commit/5857537bcb3b881213371d43e5237f1aaa3aec49) Thanks [@Fanzzzd](https://github.com/Fanzzzd)! - Docs: the README install command now covers React Native / Expo. The npm front
  page only showed `pnpm add convex-logto @logto/react`, which installs the wrong
  Logto peer for native apps — they need `@logto/rn`. Added a one-line note pointing
  native users at `@logto/rn` (everything else is identical). No code change.

## 0.3.1

### Patch Changes

- [#7](https://github.com/Fanzzzd/convex-logto/pull/7) [`1daaf39`](https://github.com/Fanzzzd/convex-logto/commit/1daaf3931a55f0f85dd98973d4ef4b80d8de79b0) Thanks [@Fanzzzd](https://github.com/Fanzzzd)! - Clarify the `convex-logto/native` `fallback` JSDoc: it renders during the one-time
  config fetch, before the Convex provider mounts, so Convex's `<AuthLoading>` belongs
  in your app's children — not inside `fallback`.

## 0.3.0

### Minor Changes

- [#5](https://github.com/Fanzzzd/convex-logto/pull/5) [`0296a82`](https://github.com/Fanzzzd/convex-logto/commit/0296a82f00bd269dc205e4d9fb786089e59f429a) Thanks [@Fanzzzd](https://github.com/Fanzzzd)! - Add React Native / Expo support via a new `convex-logto/native` entry.

  `ConvexLogtoProvider` and `useLogtoAuth` now have native counterparts built on
  `@logto/rn` (added as an optional peer dependency). The server APIs
  (`logtoAuthConfig`, `logtoConfigQuery`, the webhook sync) are unchanged and fully
  shared. On native, `signIn` opens the system browser and resolves on the deep-link
  return — there's no callback route to add, and `signIn()` defaults to the
  provider's `redirectUri`. See the new React Native guide and the `examples/expo` app.

## 0.2.0

### Minor Changes

- [#2](https://github.com/Fanzzzd/convex-logto/pull/2) [`8f80719`](https://github.com/Fanzzzd/convex-logto/commit/8f80719269523e812023a6e929159178d5f4db1c) Thanks [@Fanzzzd](https://github.com/Fanzzzd)! - SSR-safe, config-only provider (breaking API slim).

  - **`ConvexLogtoProvider` is now safe to render anywhere, including on the server.** It mounts the Logto + Convex tree from the first render using an inert loading client, so children render immediately (under Convex's `<AuthLoading>`) while config loads, and nothing touches `window` on the server. SSR frameworks (Next.js App Router, TanStack Start) no longer need a hand-written client boundary — a single `<ConvexLogtoProvider>` is enough everywhere.
  - **Breaking — the provider is configured by `configQuery` only.** The literal `endpoint`/`appId` props (and their discriminated union) are removed; `{ endpoint, appId }` is served from the Convex deployment via `logtoConfigQuery()`, so config lives in exactly one place per environment.
  - **Breaking — removed the `callbackPath` prop.** `/callback` is the fixed convention; to use a different path, pass it explicitly: ``signIn(`${origin}/your-path`)``.
  - **Breaking — removed the `fallback` prop.** Children render during config load (gated by `<AuthLoading>`), so a separate fallback is no longer needed.
  - Auth no longer flickers on load or reload: the bridge latches on the first settle and sources `isAuthenticated`/`isLoading` from Convex, verified across repeated authenticated reloads.
  - A failed sign-in code exchange (a stale callback URL or a lost sign-in session) now throws a clear error instead of leaving the callback page stuck on "finishing sign in".

  Note: Convex's OIDC verifier accepts only RS256/EdDSA, but Logto signs with ES384 by default. Rotate your tenant's OIDC signing key to **RSA** (Tenant settings → OIDC configs → rotate private key → RSA), or `getUserIdentity()` returns `null`.

## 0.1.1

### Patch Changes

- [`a5d6c31`](https://github.com/Fanzzzd/convex-logto/commit/a5d6c31da7dc97ffe3808c20c92bcf4d129fdc0d) Thanks [@Fanzzzd](https://github.com/Fanzzzd)! - Robustness and packaging fixes:

  - **`convex-logto/react` is now ESM-only.** It previously advertised a CommonJS build, but `@logto/react@4` is ESM-only, so `require("convex-logto/react")` was a runtime trap for CJS/Node consumers. The root `convex-logto` entry stays dual ESM+CJS.
  - **Sign-in callback now handles all OIDC redirects**, not just `?code=` on the callback path — OAuth `?error=…` responses and `signIn(customRedirectUri)` landings are handled too. The handler keys off Logto's stored sign-in session, so it stays a no-op on ordinary navigation.
  - **Webhook handler is stricter**: malformed (non-hex) signatures and unknown event types are now rejected (401/400) instead of being silently accepted.
  - **Token refresh no longer returns a stale ID token** — if the refresh exchange fails, the bridge returns `null` and Convex drives re-authentication.
  - **`LOGTO_ENDPOINT` is trimmed and trailing-slash-normalized**, so a pasted value like `https://auth.example.com/` works.
  - **Types**: `useLogtoAuth().signIn` / `signOut` are now correctly typed as returning `Promise<void>`.

## 0.1.0

### Minor Changes

- Initial release. Use [Logto](https://logto.io) (self-hosted or cloud) as the auth provider for [Convex](https://convex.dev) React apps.
  - **OIDC ID-token bridge** — `logtoAuthConfig()` for `auth.config.ts` and `ConvexLogtoProvider` / `useLogtoAuth()` for React. Convex validates Logto's ID token over OIDC, so signing algorithm and JWKS are auto-discovered; no manual JWT config.
  - **Backend single-source config** — `logtoConfigQuery()` serves `{ endpoint, appId }` to the frontend, so Logto values live only in each Convex deployment's env. Switching environments is just switching `VITE_CONVEX_URL`; the frontend carries zero Logto config.
  - **Signed webhook user-sync** — `logtoSync()` + `registerLogtoWebhook()` keep your `users` table in sync with Logto, with `verifyLogtoSignature()` doing constant-time HMAC-SHA256 verification over the raw request bytes.
