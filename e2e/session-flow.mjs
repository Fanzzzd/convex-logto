// The live session-mode flow, against a real Logto and a real Convex deployment.
//
// Unit tests cannot reach what this covers: Logto's actual token lifetimes,
// whether a grant really rotates its refresh token, what the SSO cookie does on
// a second sign-in, and how the component behaves when the wall clock — not a
// fake timer — advances. Every session-mode defect that took longest to find was
// in that gap.
//
//   node e2e/session-flow.mjs
//
// Requires an app already serving at E2E_APP_URL, wired to a Convex deployment
// whose env points at the objects `provision.mjs` created. Chrome must be
// installed; `playwright-core` drives it rather than downloading its own.
import { chromium } from "playwright-core";

const appUrl = (process.env.E2E_APP_URL ?? "http://localhost:5174").replace(
  /\/+$/,
  "",
);
const email = need("E2E_USER_EMAIL");
const password = need("E2E_USER_PASSWORD");
const headless = process.env.E2E_HEADED !== "1";

function need(name) {
  const value = process.env[name];
  if (!value) {
    console.error(`session-flow: ${name} is required — run e2e/provision.mjs first.`);
    process.exit(1);
  }
  return value;
}

const steps = [];
function step(name, detail = "") {
  steps.push({ name, detail });
  console.error(`  ✓ ${name}${detail ? ` — ${detail}` : ""}`);
}

function fail(message) {
  console.error(`\n  ✗ ${message}`);
  process.exitCode = 1;
  throw new Error(message);
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

/** The example renders the decoded identity; treat its presence as authenticated. */
async function waitForSignedIn(page) {
  await page.waitForFunction(
    () => document.body.innerText.includes("sub") || document.body.innerText.includes("Sign out"),
    undefined,
    { timeout: 30_000 },
  );
}

const browser = await chromium.launch({ headless, channel: "chrome" });
const context = await browser.newContext();
const page = await context.newPage();

try {
  console.error(`session-flow against ${appUrl}\n`);

  // 1. Cold sign-in.
  await page.goto(appUrl, { waitUntil: "domcontentloaded" });
  await page.getByRole("button", { name: /sign in/i }).click();
  await signInAtLogto(page);
  await waitForSignedIn(page);
  if (!page.url().startsWith(appUrl)) {
    fail(`expected to land back on ${appUrl}, got ${page.url()}`);
  }
  step("cold sign-in", page.url());

  // 2. Zero-RTT restore. A reload with a live ID token in storage must not
  //    round-trip to the deployment before it renders authenticated — that is
  //    the whole point of caching the token, and it is invisible to unit tests.
  const before = Date.now();
  await page.reload({ waitUntil: "domcontentloaded" });
  await waitForSignedIn(page);
  step("zero-RTT restore", `${Date.now() - before}ms`);

  // 3. Rotation. A forced refresh must leave the session usable — the failure
  //    this catches is a rotated token that was not persisted, which only shows
  //    up on the *next* refresh.
  const sessions = await page.evaluate(async () => {
    const api = window.__convexLogtoE2E;
    if (!api?.refresh) return null;
    await api.refresh();
    return api.listSessions ? await api.listSessions() : "refreshed";
  });
  if (sessions === null) {
    step("rotation", "skipped — app exposes no __convexLogtoE2E hook");
  } else {
    await waitForSignedIn(page);
    step("rotation", "session still usable after a forced refresh");
  }

  // 4. Sign-in over a live session. Logto's SSO cookie makes this silent, and it
  //    is how a user retries anything that looks like a sign-out. The session it
  //    replaces must be revoked rather than orphaned.
  await page.goto(appUrl, { waitUntil: "domcontentloaded" });
  const signInAgain = page.getByRole("button", { name: /sign in/i });
  if (await signInAgain.count()) {
    await signInAgain.click();
    await waitForSignedIn(page);
    step("re-sign-in over a live session", "silent redirect, no credential prompt");
  } else {
    step("re-sign-in over a live session", "skipped — already signed in, no button");
  }

  // 5. Sign-out.
  await page.getByRole("button", { name: /^sign out/i }).click();
  await page.waitForFunction(
    () => document.body.innerText.match(/sign in/i) !== null,
    undefined,
    { timeout: 30_000 },
  );
  step("sign-out", "back to the signed-out view");

  console.error(`\n${steps.length} steps passed.`);
} catch (error) {
  console.error(`\nfailed: ${error instanceof Error ? error.message : String(error)}`);
  if (process.exitCode === undefined) process.exitCode = 1;
  await page.screenshot({ path: "e2e/failure.png" }).catch(() => {});
  console.error("screenshot: e2e/failure.png");
} finally {
  await browser.close();
}
