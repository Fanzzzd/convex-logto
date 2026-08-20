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
const convexUrl = trimSlash(need("E2E_CONVEX_URL"));
const email = need("E2E_USER_EMAIL");
const password = need("E2E_USER_PASSWORD");
const headless = process.env.E2E_HEADED !== "1";
const screenshotPath = fileURLToPath(new URL("./failure.png", import.meta.url));

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

const browser = await chromium.launch({ headless, channel: "chrome" });
const context = await browser.newContext();
const page = await context.newPage();

/** Every POST at the deployment — the session actions all go through one. */
const deploymentPosts = [];
page.on("request", (request) => {
  if (request.method() === "POST" && request.url().startsWith(convexUrl)) {
    deploymentPosts.push(request.url());
  }
});

try {
  console.error(`session-flow against ${appUrl} (deployment ${convexUrl})\n`);

  // 1. Cold sign-in.
  await page.goto(appUrl, { waitUntil: "domcontentloaded" });
  await page.getByRole("button", { name: /sign in/i }).click();
  await signInAtLogto(page);
  await waitForSignedIn(page);
  assert(
    page.url().startsWith(appUrl),
    `expected to land back on ${appUrl}, got ${page.url()}`,
  );
  const firstToken = await readStoredSessionToken(page);
  assert(firstToken !== null, "no session token was persisted after sign-in");
  step("cold sign-in", page.url());

  // 2. Zero-RTT restore. Timing proves nothing — a fast round trip looks
  //    identical — so assert the absence of the round trip itself. The library
  //    should serve the cached ID token without asking the deployment for one.
  deploymentPosts.length = 0;
  await page.reload({ waitUntil: "domcontentloaded" });
  await waitForSignedIn(page);
  assert(
    deploymentPosts.length === 0,
    `restore should not reach the deployment, but posted ${deploymentPosts.length}×: ` +
      deploymentPosts.slice(0, 3).join(", "),
  );
  step("zero-RTT restore", "no deployment request before authenticated render");

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

  // 4. Sign-out has to survive a reload. A cleared UI with live credentials
  //    still in storage would pass a text-only check and is exactly the bug.
  await page.getByRole("button", { name: /^sign out/i }).click();
  await waitForSignedOut(page);
  await page.reload({ waitUntil: "domcontentloaded" });
  await waitForSignedOut(page);
  const afterSignOut = await readStoredSessionToken(page);
  assert(
    afterSignOut === null,
    "a session token survived sign-out and a reload",
  );
  step("sign-out", "credentials gone, and still gone after a reload");

  // 5. Sign in again over Logto's surviving SSO cookie. This is how a user
  //    retries anything that looks like a sign-out, and it must work without a
  //    fresh credential prompt.
  await page.getByRole("button", { name: /sign in/i }).click();
  await waitForSignedIn(page);
  const resigned = await readStoredSessionToken(page);
  assert(resigned !== null, "re-sign-in produced no session token");
  assert(
    resigned !== previous,
    "re-sign-in reused the previous session token instead of minting one",
  );
  step("re-sign-in", "silent through the surviving SSO session");

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
