// What does the token exchange actually do, end to end through the component?
//
// A probe, not a regression: it asks the deployment questions whose answers are
// not known yet and prints findings. It found two of them the first time it ran.
//
//   set -a; . ./.env.e2e; set +a
//   export E2E_APP_URL=http://localhost:5174 E2E_CONVEX_URL=http://127.0.0.1:3216
//   export E2E_ORG_ID=<an organization the test user belongs to>
//   node probe-exchange.mjs 2>&1
//
// The app must export `exchangeToken` and `fetchUserInfo` from
// `logtoSessionApi(...)`, and — for the organization half — request
// `ORGANIZATIONS_SCOPE`. Running it *without* that scope is itself informative:
// it is the configuration that used to leave the session unusable.
//
// Nothing here asks for a token string (`includeToken` is never set), so no
// credential is printed. The ID token's claim *names* are, because which claims
// a scope produces is the question.
import { chromium } from "playwright-core";

const appUrl = need("E2E_APP_URL").replace(/\/+$/, "");
const convexUrl = need("E2E_CONVEX_URL").replace(/\/+$/, "");
const organizationId = need("E2E_ORG_ID");
const email = need("E2E_USER_EMAIL");
const password = need("E2E_USER_PASSWORD");

function need(name) {
  const value = process.env[name];
  if (!value) {
    console.error(
      `probe-exchange: ${name} is required. See the header of this file.`,
    );
    process.exit(1);
  }
  return value;
}

const browser = await chromium.launch({ headless: true, channel: "chrome" });
const page = await (await browser.newContext()).newPage();
try {
  await page.goto(appUrl, { waitUntil: "domcontentloaded" });
  await page.getByRole("button", { name: /sign in/i }).click();
  await page.waitForSelector("input[name=identifier]", { timeout: 30_000 });
  await page.fill("input[name=identifier]", email);
  await page.keyboard.press("Enter");
  await page.waitForSelector("input[type=password]", { timeout: 30_000 });
  await page.fill("input[type=password]", password);
  await page.keyboard.press("Enter");
  await page.waitForFunction(
    () =>
      Object.keys(localStorage).some((key) =>
        key.startsWith("convex-logto:"),
      ) && /sign out/i.test(document.body.innerText),
    undefined,
    { timeout: 45_000 },
  );

  // Which claims the configured scopes actually produced. Membership and roles
  // arriving here is the whole reason an organization *token* is rarely needed.
  const idToken = await page.evaluate(() => {
    const key = Object.keys(sessionStorage).find((candidate) =>
      candidate.endsWith(":idToken"),
    );
    if (key === undefined) return null;
    const stored = JSON.parse(sessionStorage.getItem(key) ?? "null");
    const raw = typeof stored === "string" ? stored : stored?.token;
    if (typeof raw !== "string") return null;
    const claims = JSON.parse(
      atob((raw.split(".")[1] ?? "").replace(/-/g, "+").replace(/_/g, "/")),
    );
    return {
      organizations: claims.organizations ?? null,
      organization_roles: claims.organization_roles ?? null,
      claimNames: Object.keys(claims).sort(),
    };
  });
  console.error("ID token claims:", JSON.stringify(idToken, null, 2));

  const sessionToken = await page.evaluate(() => {
    const key = Object.keys(localStorage).find((candidate) =>
      candidate.endsWith(":session"),
    );
    return JSON.parse(localStorage.getItem(key ?? "") ?? "null")?.token ?? null;
  });

  // Run through the page so the request carries the app's own origin.
  async function callAction(path, args) {
    return await page.evaluate(
      async ([url, name, payload]) => {
        const response = await fetch(`${url}/api/action`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ path: name, args: payload, format: "json" }),
        });
        return await response.text();
      },
      [convexUrl, path, args],
    );
  }

  for (const [label, path, args] of [
    [
      "organization token",
      "auth:exchangeToken",
      { sessionToken, organizationId },
    ],
    [
      // Expected to fail: organization permissions are not OIDC scopes, so a
      // refresh grant can never hold one to narrow by. See ADR 0003.
      "organization token, narrowed by a permission",
      "auth:exchangeToken",
      { sessionToken, organizationId, scopes: ["e2e:manage"] },
    ],
    ["userinfo", "auth:fetchUserInfo", { sessionToken }],
  ]) {
    console.error(`\n=== ${label}`);
    console.error((await callAction(path, args)).slice(0, 900));
  }
} finally {
  await browser.close();
}
