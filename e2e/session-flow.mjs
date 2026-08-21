// The live session-mode flow, against a real Logto and a real Convex deployment.
//
// Unit tests cannot reach what this covers: Logto's actual token lifetimes,
// whether a grant really rotates its refresh token, what the SSO cookie does on
// a second sign-in, and how the component behaves when the wall clock — not a
// fake timer — advances. Every session-mode defect that took longest to find was
// in that gap.
//
//   node e2e/session-flow.mjs        (or `npm run session-flow` from e2e/)
//
// Requires an app already serving at E2E_APP_URL, wired to the Convex deployment
// at E2E_CONVEX_URL, whose env points at the objects `provision.mjs` created.
// Chrome must be installed; `playwright-core` drives it rather than downloading
// its own.
//
// Every step is a required assertion. Nothing is skipped: a check that quietly
// did not run is worse than one that failed, because it reports as a pass.
import { fileURLToPath } from "node:url";
import { chromium } from "playwright-core";

const appUrl = trimSlash(need("E2E_APP_URL"));
// Compared as an origin, never as a prefix: `https://app.example` is a prefix of
// `https://app.example.invalid`, and a check that accepts the second is the same
// mistake the library refuses to make in its own redirect validation.
const appOrigin = new URL(appUrl).origin;
const convexUrl = trimSlash(need("E2E_CONVEX_URL"));
const email = need("E2E_USER_EMAIL");
const password = need("E2E_USER_PASSWORD");
// The organization `provision.mjs` puts the test user in, and the role it gives
// them there — which is the role `examples/vite-react-session`'s `adminOnly`
// query requires.
const organizationId = need("E2E_ORG_ID");
const organizationRole = need("E2E_ORG_ROLE");
const headless = process.env.E2E_HEADED !== "1";
const screenshotPath = fileURLToPath(new URL("./failure.png", import.meta.url));
// Labels outlive a run: a revoke aimed at "the other device" would eventually
// aim at a session some earlier run abandoned. Every run names its own.
const runId = `${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 8)}`;

function trimSlash(value) {
  return value.replace(/\/+$/, "");
}

function need(name) {
  const value = process.env[name];
  if (!value) {
    console.error(
      `session-flow: ${name} is required.\n` +
        "Run e2e/provision.mjs, then `set -a; . ./.env.e2e; set +a`.",
    );
    process.exit(1);
  }
  return value;
}

let passed = 0;
function step(name, detail = "") {
  passed += 1;
  console.error(`  ✓ ${name}${detail ? ` — ${detail}` : ""}`);
}

function assert(condition, message) {
  if (!condition) throw new Error(message);
}

/** Logto's sign-in is two-step: identifier, then password. */
async function signInAtLogto(page) {
  await page.waitForSelector("input[name=identifier]", { timeout: 30_000 });
  await page.fill("input[name=identifier]", email);
  await page.keyboard.press("Enter");
  await page.waitForSelector("input[type=password]", { timeout: 30_000 });
  await page.fill("input[type=password]", password);
  await page.keyboard.press("Enter");
}

/**
 * Authenticated is defined by the library's own state, not the app's copy: the
 * stored ID token plus a rendered `sub`. Reading the app's text alone would pass
 * on a page that merely kept stale UI.
 */
async function waitForSignedIn(page) {
  await page.waitForFunction(
    () =>
      Object.keys(localStorage).some((key) =>
        key.startsWith("convex-logto:"),
      ) && /sign out/i.test(document.body.innerText),
    undefined,
    { timeout: 45_000 },
  );
}

async function waitForSignedOut(page) {
  await page.waitForFunction(
    () => /sign in/i.test(document.body.innerText),
    undefined,
    { timeout: 30_000 },
  );
}

/**
 * Wait until the browser is back on the app's own origin.
 *
 * `localStorage` is per origin, and a federated sign-out leaves the page on
 * Logto's while it ends the OP session. Reading storage there answers a
 * question about *Logto's* storage — and answers "no session token" no matter
 * what the app kept, which is a passing assertion that checked nothing. Every
 * storage assertion waits for this first.
 */
async function waitForAppOrigin(target) {
  await target.waitForURL((url) => url.origin === appOrigin, {
    timeout: 45_000,
  });
  await target.waitForLoadState("domcontentloaded");
}

/**
 * Sign out, and wait for the logout to actually reach Logto and come back.
 *
 * The app clears its own credentials *before* the network call, and the browser
 * is still on the app's origin while it does — so "signed out, and on the app"
 * is already true a millisecond after the click, before the end-session
 * redirect has even started. Anything that navigates into that window cancels
 * the request to Logto, and the OP session survives a sign-out that every
 * local assertion says succeeded. Waiting for the end-session request itself is
 * the only thing that closes it.
 */
async function signOutAndWaitForLogto(target, buttonName) {
  const reachedLogto = target.waitForRequest(
    (request) => request.url().includes("/oidc/session/end"),
    { timeout: 45_000 },
  );
  await target.getByRole("button", { name: buttonName }).click();
  await reachedLogto;
  await waitForAppOrigin(target);
  await waitForSignedOut(target);
}

/**
 * Load the app again, tolerating a redirect still in flight.
 *
 * A federated sign-out is a chain — app → Logto's end-session → back — and the
 * last hop can still be committing when the signed-out UI is already on screen.
 * A navigation issued into that window aborts. Retrying is not papering over a
 * product bug: the chain really is asynchronous, and the assertion that follows
 * is about storage, not about how many redirects it took to get here.
 */
async function reopenApp(target) {
  for (let attempt = 0; ; attempt += 1) {
    try {
      await target.goto(appUrl, { waitUntil: "domcontentloaded" });
      return;
    } catch (error) {
      if (attempt >= 3) throw error;
      await target.waitForTimeout(500);
    }
  }
}

/** The rotating session token the library persisted, read from its own key. */
function readStoredSessionToken(page) {
  return page.evaluate(() => {
    const key = Object.keys(localStorage).find((candidate) =>
      candidate.endsWith(":session"),
    );
    if (key === undefined) return null;
    try {
      return JSON.parse(localStorage.getItem(key) ?? "null")?.token ?? null;
    } catch {
      return null;
    }
  });
}

/**
 * Sign in from a browser context that has never seen Logto. Its cookie jar is
 * empty, so the credential prompt is guaranteed — this is a second device, not
 * a second tab.
 */
async function signInOnFreshDevice(target) {
  await target.goto(appUrl, { waitUntil: "domcontentloaded" });
  await target.getByRole("button", { name: /sign in/i }).click();
  await signInAtLogto(target);
  await waitForSignedIn(target);
}

/** Rename this device's own session through the app's list UI. */
async function renameCurrentDevice(target, label) {
  const own = target.getByRole("listitem").filter({ hasText: "this device" });
  await own.first().waitFor({ timeout: 30_000 });
  await own.first().getByRole("button", { name: /^rename$/i }).click();
  await own.first().getByRole("textbox").fill(label);
  await own.first().getByRole("button", { name: /^save$/i }).click();
  await target
    .getByRole("listitem")
    .filter({ hasText: label })
    .first()
    .waitFor({ timeout: 30_000 });
}

/**
 * Which outcome a sign-in click produced: Logto's credential prompt, or an app
 * that is already signed in. Watching for both is the point — "silent" and
 * "prompted" are both plausible outcomes of the same click, and waiting for only
 * the one we expect turns a wrong answer into an opaque timeout.
 *
 * Polled rather than raced, and that is not a style choice. Racing two
 * `waitFor*` calls and mapping each rejection to "neither" makes *any* early
 * rejection decide the whole question — and a sign-in click navigates, which
 * destroys the execution context a `waitForFunction` poll is running in. That
 * rejects immediately, wins the race, and reports "neither" while the credential
 * prompt is still on its way. It cost an afternoon: the failures looked like
 * Logto's sign-in page not rendering, and the page was rendering fine.
 *
 * So: read both conditions in one evaluate, treat a failed read as "ask again",
 * and let only the deadline answer "neither".
 */
async function signInOutcome(page) {
  const deadline = Date.now() + 45_000;
  while (Date.now() < deadline) {
    const state = await page
      .evaluate(() => ({
        prompted: document.querySelector("input[name=identifier]") !== null,
        signedIn: /sign out/i.test(document.body.innerText),
      }))
      .catch(() => null);
    if (state?.prompted) return "prompted";
    if (state?.signedIn) return "silent";
    await page.waitForTimeout(250);
  }
  return "neither";
}

/**
 * A URL safe to write down: origin and path in full, query and fragment reduced
 * to their parameter *names*.
 *
 * This runs immediately after a sign-in click, so the browser may be sitting on
 * an authorization request or a callback — `?code=…&state=…`, or a fragment
 * carrying a token. Failures go to stderr and the README tells you to redirect
 * stderr to a file, so a raw URL here is an authorization code written into a
 * log. The names alone still answer the question being asked: seeing `code` and
 * `state` present is what tells you the callback was reached.
 */
/**
 * Parameter names that may be written down.
 *
 * A name is still content the URL supplied, and `?SECRET` is a parameter whose
 * *name* is the secret. So this is an allowlist rather than a denylist, and it
 * is safe to let rot: a name that is not here shows as `?`, which loses a little
 * diagnostic detail and leaks nothing. Everything on it is a fixed OAuth/OIDC
 * parameter name from the flows this harness drives.
 */
const NAMEABLE_PARAMS = new Set([
  "access_token",
  "app_id",
  "client_id",
  "code",
  "code_challenge",
  "code_challenge_method",
  "error",
  "error_description",
  "id_token",
  "id_token_hint",
  "iss",
  "nonce",
  "post_logout_redirect_uri",
  "prompt",
  "redirect_uri",
  "response_type",
  "scope",
  "session_state",
  "state",
  "token_type",
]);

function safeUrl(raw) {
  let url;
  try {
    url = new URL(raw);
  } catch {
    return "(unparseable URL)";
  }
  // `about:blank` — the very page this diagnostic was written for — has origin
  // "null", and joining that to a pathname produces "nullblank".
  const base =
    url.origin === "null"
      ? `${url.protocol}${url.pathname}`
      : `${url.origin}${url.pathname}`;
  const parts = [base.slice(0, 200)];
  const names = (search) =>
    [...new URLSearchParams(search).keys()]
      .map((name) => (NAMEABLE_PARAMS.has(name) ? name : "?"))
      .join(",");
  const query = names(url.search);
  // A fragment is not always `a=b`, so say it is there even when nothing parses.
  const fragment = url.hash === "" ? "" : names(url.hash.slice(1)) || "…";
  if (query) parts.push(`?[${query}]`);
  if (fragment) parts.push(`#[${fragment}]`);
  return parts.join("");
}

/**
 * Where the browser actually ended up, for the third outcome.
 *
 * "Neither" is the one answer that names no cause, and it has happened: a blank
 * document with nothing to read. Whether that is Logto refusing the authorize
 * request, a redirect still in flight, or an app that never navigated is the
 * whole question, and the redacted URL plus whatever text is on screen narrows
 * it. Reported rather than asserted on, because this is a diagnosis, not a rule.
 */
async function describePage(page) {
  const text = await page
    .evaluate(() => document.body.innerText.replace(/\s+/g, " ").trim())
    .catch(() => "(unreadable)");
  return `at ${safeUrl(page.url())} showing ${text ? JSON.stringify(text.slice(0, 160)) : "an empty document"}`;
}

/** The cached ID token, read from the library's own key. */
function readStoredIdToken(page) {
  return page.evaluate(() => {
    for (const store of [sessionStorage, localStorage]) {
      const key = Object.keys(store).find((candidate) =>
        candidate.endsWith(":idToken"),
      );
      if (key === undefined) continue;
      const stored = JSON.parse(store.getItem(key) ?? "null");
      const raw = typeof stored === "string" ? stored : stored?.token;
      if (typeof raw === "string") return raw;
    }
    return null;
  });
}

/**
 * Call a Convex function through the page, so the request carries the app's own
 * origin — the deployment's CORS policy is part of what is under test.
 *
 * Returns Convex's envelope untouched (`{status, value}` or
 * `{status, errorData}`): a helper that threw on `status: "error"` would make
 * the denial assertions below unable to see the denial they are asserting.
 */
async function callConvex(page, kind, path, args, bearer) {
  return await page.evaluate(
    async ([url, route, name, payload, token]) => {
      const response = await fetch(`${url}/api/${route}`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          ...(token ? { Authorization: `Bearer ${token}` } : {}),
        },
        body: JSON.stringify({ path: name, args: payload, format: "json" }),
      });
      return await response.json();
    },
    [convexUrl, kind, path, args, bearer ?? null],
  );
}

/** Drop the cached ID token so the next restore must go to the deployment. */
function clearCachedIdToken(page) {
  return page.evaluate(() => {
    for (const store of [sessionStorage, localStorage]) {
      for (const key of Object.keys(store)) {
        if (key.endsWith(":idToken")) store.removeItem(key);
      }
    }
  });
}

/**
 * Prove the redactor before anything can need it.
 *
 * It only ever runs on a failure, so a bug in it would first show up in the one
 * place there is no second chance: a log that has already been written, with an
 * authorization code in it. Checked here rather than in a test file because
 * `e2e/` is outside the workspace and has no runner — and because a guarantee
 * about what may be written down belongs next to the writing.
 */
for (const [raw, expected] of [
  [
    "http://localhost:5174/callback?code=SECRET&state=SECRET",
    "http://localhost:5174/callback?[code,state]",
  ],
  [
    "https://auth.example.com/oidc/auth?client_id=a&state=SECRET",
    "https://auth.example.com/oidc/auth?[client_id,state]",
  ],
  [
    "http://localhost:5174/#access_token=SECRET&token_type=bearer",
    "http://localhost:5174/#[access_token,token_type]",
  ],
  [
    "http://localhost:5174/callback?SECRET&code=SECRET",
    "http://localhost:5174/callback?[?,code]",
  ],
  ["http://localhost:5174/", "http://localhost:5174/"],
  ["about:blank", "about:blank"],
  ["not a url", "(unparseable URL)"],
]) {
  const got = safeUrl(raw);
  if (got !== expected || got.includes("SECRET")) {
    console.error(
      `session-flow: the URL redactor is broken — ${JSON.stringify(raw)} ` +
        `became ${JSON.stringify(got)}, expected ${JSON.stringify(expected)}.`,
    );
    process.exit(1);
  }
}

const browser = await chromium.launch({ headless, channel: "chrome" });

/**
 * A browser context is a separate cookie jar and a separate storage origin, so
 * a second one is a second *device* as far as Logto and the component are
 * concerned — which is the only way to test revoking one from the other.
 */
async function newDevice() {
  const context = await browser.newContext();
  return { context, page: await context.newPage() };
}

const { page } = await newDevice();

/**
 * Every action the page runs at the deployment, by function name.
 *
 * The name, not the URL: session mode's whole surface is one HTTP endpoint, so
 * a URL count cannot tell the library's own token round-trip apart from a call
 * the *app* made — and the app in front of this one lists its devices on
 * render. Asserting on the count would make the library's test fail whenever
 * the example's UI changed, which is the definition of testing a proxy.
 */
const deploymentCalls = [];
page.on("request", (request) => {
  if (request.method() !== "POST" || !request.url().startsWith(convexUrl)) {
    return;
  }
  let path = "(unparseable)";
  try {
    path = JSON.parse(request.postData() ?? "{}").path ?? "(no path)";
  } catch {
    // Keep the placeholder: an action call whose body we cannot read is still
    // evidence, and it must not be silently dropped from the record.
  }
  deploymentCalls.push(path);
});

/** The calls that mint a token — the ones a warm restore must not need. */
function tokenCalls() {
  return deploymentCalls.filter((path) =>
    /:(refresh|callback)$/.test(path),
  );
}

try {
  console.error(`session-flow against ${appUrl} (deployment ${convexUrl})\n`);

  // 1. Cold sign-in.
  await page.goto(appUrl, { waitUntil: "domcontentloaded" });
  await page.getByRole("button", { name: /sign in/i }).click();
  await signInAtLogto(page);
  await waitForSignedIn(page);
  assert(
    new URL(page.url()).origin === appOrigin,
    `expected to land back on ${appOrigin}, got ${page.url()}`,
  );
  const firstToken = await readStoredSessionToken(page);
  assert(firstToken !== null, "no session token was persisted after sign-in");
  step("cold sign-in", page.url());

  // 2. Zero-RTT restore. Timing proves nothing — a fast round trip looks
  //    identical — so assert the absence of the round trip itself. The library
  //    should serve the cached ID token without asking the deployment for one.
  //
  //    This needs `initialAuthTokenReuse: true` on the ConvexReactClient. Without
  //    it Convex confirms the cached token and then immediately refetches, which
  //    spends a Logto refresh grant on every page load; the app under test sets
  //    it, so a failure here is a real regression and not a missing flag.
  deploymentCalls.length = 0;
  await page.reload({ waitUntil: "domcontentloaded" });
  await waitForSignedIn(page);
  assert(
    tokenCalls().length === 0,
    "restore should not mint a token, but called " +
      `${tokenCalls().join(", ")} (all calls: ${deploymentCalls.join(", ") || "none"})`,
  );
  step("zero-RTT restore", "no token minted before authenticated render");

  // 3. Rotation, twice. Once proves a refresh worked; the failure worth catching
  //    is a rotated token that was never persisted, and that only surfaces on the
  //    *next* refresh — which is why this runs the cycle a second time.
  let previous = firstToken;
  for (const round of [1, 2]) {
    await clearCachedIdToken(page);
    await page.reload({ waitUntil: "domcontentloaded" });
    await waitForSignedIn(page);
    const next = await readStoredSessionToken(page);
    assert(next !== null, `round ${round}: the session token vanished`);
    assert(
      next !== previous,
      `round ${round}: the session token did not rotate — the component either ` +
        "did not rotate it or the browser did not persist the rotation",
    );
    previous = next;
  }
  step("rotation persisted across two refreshes");

  // 4. Organization authorization, straight out of the ID token. Nothing here
  //    is checkable offline: whether Logto actually puts `organizations` and
  //    `organization_roles` in the *ID* token for the configured scopes is a
  //    property of the deployment, and the whole helper family is built on it
  //    being true. The denial half matters as much as the grant: a check that
  //    matched on the role alone would authorize one organization's `admin`
  //    inside another's.
  const idToken = await readStoredIdToken(page);
  assert(idToken !== null, "no ID token was cached after sign-in");
  const granted = await callConvex(
    page,
    "query",
    "organizations:adminOnly",
    { organizationId },
    idToken,
  );
  assert(
    granted.status === "success",
    `adminOnly denied a real ${organizationRole} of ${organizationId}: ` +
      JSON.stringify(granted),
  );
  const foreign = await callConvex(
    page,
    "query",
    "organizations:adminOnly",
    { organizationId: `${organizationId}-not-mine` },
    idToken,
  );
  assert(
    foreign.status === "error" &&
      JSON.stringify(foreign).includes("organization_forbidden"),
    "adminOnly authorized an organization the user does not belong to: " +
      JSON.stringify(foreign),
  );
  step(
    "organization authorization",
    `"${organizationRole}" in ${organizationId}, and nowhere else`,
  );

  // 5. The organization token exchange, and its cache. `minted` is the only
  //    externally visible difference between "asked Logto" and "served from the
  //    component", and it is the thing worth asserting: every mint spends a
  //    refresh grant, so a cache that silently never hits would multiply this
  //    deployment's traffic to Logto by however often the app asks. `forceRefresh`
  //    is the deliberate way past it, and there is no way to prove it bypasses a
  //    cache without first proving the cache exists.
  const sessionToken = await readStoredSessionToken(page);
  assert(sessionToken !== null, "no session token to exchange with");
  const exchange = async (extra) =>
    await callConvex(page, "action", "auth:exchangeToken", {
      sessionToken,
      organizationId,
      ...extra,
    });

  const first = await exchange({});
  assert(
    first.status === "success",
    `the organization token exchange failed: ${JSON.stringify(first)}`,
  );
  assert(
    first.value.minted === true,
    "the first exchange of this run was served from cache, so nothing proves " +
      "a mint still works",
  );
  assert(
    first.value.claims.audience === `organization:${organizationId}`,
    `wrong audience: ${JSON.stringify(first.value.claims)}`,
  );
  assert(
    first.value.claims.expiresAt > Date.now(),
    `the minted token is already expired: ${JSON.stringify(first.value.claims)}`,
  );
  // Never requested, so it must never be returned. `exposeAccessTokens` is off
  // in this app, and a token string leaking without it is the failure that
  // would be silent everywhere else.
  assert(
    first.value.accessToken === undefined,
    "the exchange returned a token string that was never asked for",
  );

  const cached = await exchange({});
  assert(
    cached.status === "success" && cached.value.minted === false,
    "the second exchange minted again — the component's cache did not hit, " +
      `and every call spends a Logto refresh grant: ${JSON.stringify(cached)}`,
  );

  const forced = await exchange({ forceRefresh: true });
  assert(
    forced.status === "success" && forced.value.minted === true,
    `forceRefresh was served from cache: ${JSON.stringify(forced)}`,
  );
  step("organization token", "minted, cached, and forced past the cache");

  // 6. `fetchUserInfo` goes to Logto's `/oidc/me` with an opaque token the
  //    component mints for the purpose. Its subject has to be the same person
  //    the ID token names — a userinfo response for a *different* subject would
  //    mean the component authenticated the wrong session, and no offline test
  //    can see the difference because both are just JSON.
  const userinfo = await callConvex(page, "action", "auth:fetchUserInfo", {
    sessionToken,
  });
  assert(
    userinfo.status === "success",
    `fetchUserInfo failed: ${JSON.stringify(userinfo)}`,
  );
  const subject = JSON.parse(
    atob((idToken.split(".")[1] ?? "").replace(/-/g, "+").replace(/_/g, "/")),
  ).sub;
  assert(
    userinfo.value.sub === subject,
    `userinfo answered for ${userinfo.value.sub}, not ${subject}`,
  );
  step("userinfo", "same subject as the ID token");

  // 7. Sign-out has to survive a reload. A cleared UI with live credentials
  //    still in storage would pass a text-only check and is exactly the bug.
  // Not `/^sign out/`: the app also offers "Sign out everywhere", and matching
  // both makes Playwright refuse rather than pick — which is the right call, and
  // the reason this names the one it means.
  await signOutAndWaitForLogto(page, /^sign out(?! everywhere)/i);
  await reopenApp(page);
  await waitForSignedOut(page);
  const afterSignOut = await readStoredSessionToken(page);
  assert(
    afterSignOut === null,
    "a session token survived sign-out and a reload",
  );
  step("sign-out", "credentials gone, and still gone after a reload");

  // 8. Sign in again. Sign-out is federated by default — it ends Logto's SSO
  //    session as well as the local one — so this must *not* be silent. The
  //    credential prompt is the only evidence that the RP-initiated logout
  //    actually reached Logto: clearing local storage looks identical from the
  //    app either way, and a surviving OP session would sign the next visitor
  //    straight back in.
  await page.getByRole("button", { name: /sign in/i }).click();
  const outcome = await signInOutcome(page);
  assert(
    outcome === "prompted",
    outcome === "silent"
      ? "sign-out did not end Logto's session: the next sign-in completed " +
          "silently over a surviving SSO cookie"
      : "the sign-in click reached neither Logto's prompt nor a signed-in app, " +
          `${await describePage(page)}`,
  );
  await signInAtLogto(page);
  await waitForSignedIn(page);
  const resigned = await readStoredSessionToken(page);
  assert(resigned !== null, "re-sign-in produced no session token");
  assert(
    resigned !== previous,
    "re-sign-in reused the previous session token instead of minting one",
  );
  step("re-sign-in", "prompted — the federated sign-out reached Logto");

  // 9. Revoking another device has to reach it without a reload, and must not
  //    touch this one. This is the reactive `sessionValid` subscription plus
  //    the revocation watermark, and it is the part of the component with the
  //    most moving pieces: a marker commits before the rows are drained, and a
  //    row that is logically revoked has to stop being an authority — and stop
  //    being *visible* — before it is physically gone.
  const second = await newDevice();
  try {
    await signInOnFreshDevice(second.page);
    // Name it, and revoke it *by that name*. The test account accumulates
    // sessions — every earlier run left some behind — so "the other one" is not
    // a thing the list can be asked for. Naming the target also means the
    // revoke below is aimed at a session this run created, never at a stranger.
    const label = `e2e-target-${runId}`;
    await renameCurrentDevice(second.page, label);

    // This device's list was rendered before the other one existed.
    await page.reload({ waitUntil: "domcontentloaded" });
    await waitForSignedIn(page);
    const target = page.getByRole("listitem").filter({ hasText: label });
    await target.first().waitFor({ timeout: 30_000 });
    assert(
      (await target.count()) === 1,
      `expected exactly one session named ${label}, saw ${await target.count()}`,
    );
    assert(
      !(await target.first().innerText()).includes("this device"),
      `${label} is this device — the rename landed on the wrong session`,
    );
    await target.first().getByRole("button", { name: /^revoke$/i }).click();

    // No reload on the revoked device: a revocation that only lands on the next
    // page load is not a revocation, it is a cache expiry.
    await waitForSignedOut(second.page);
    assert(
      (await readStoredSessionToken(second.page)) === null,
      "the revoked device kept its session token",
    );
    // And the device that did the revoking is still signed in — revoking
    // another session must not sign me out of this one.
    await waitForSignedIn(page);
    step("revocation", "reached the other device live, and left this one alone");
  } finally {
    await second.context.close();
  }

  // 10. Sign out everywhere. The one guarantee that cannot be checked from a
  //     single browser: a *different* device, which never sees the click, has
  //     to lose its session too — live, and without asking for it.
  const third = await newDevice();
  try {
    await signInOnFreshDevice(third.page);
    await signOutAndWaitForLogto(page, /^sign out everywhere$/i);
    // Same settling as step 4, for the same reason: the sign-out chain's last
    // hop can still be committing, and a storage read into that window is
    // evaluated in a document that is being replaced.
    await reopenApp(page);
    await waitForSignedOut(page);
    await waitForSignedOut(third.page);
    // Both devices, not just the far one: sign-out-everywhere is a different
    // code path from sign-out, and "cleared UI, live credentials in storage" is
    // as much a bug on the device that clicked as on the one that did not.
    assert(
      (await readStoredSessionToken(page)) === null,
      "the device that signed out everywhere kept its own session token",
    );
    assert(
      (await readStoredSessionToken(third.page)) === null,
      "a device kept its session token through sign-out-everywhere",
    );
    step("sign out everywhere", "the other device lost its session too");
  } finally {
    await third.context.close();
  }

  console.error(`\n${passed} steps passed.`);
} catch (error) {
  console.error(
    `\n  ✗ failed after ${passed} step(s): ${error instanceof Error ? error.message : String(error)}`,
  );
  process.exitCode = 1;
  await page.screenshot({ path: screenshotPath }).catch(() => {});
  console.error(`screenshot: ${screenshotPath}`);
} finally {
  await browser.close();
}
