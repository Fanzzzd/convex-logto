// Runs the adapter against a stand-in `convex` package, so the spawn, the
// argument order, and the unset-variable convention are exercised for real.
import { mkdirSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { convexEnv } from "./convex-env";

// Mimics `convex env get|set`: get prints the value plus a newline (nothing
// when unset, still exit 0); set takes `-- NAME VALUE`. Every call is logged.
const FAKE_CONVEX = `
const fs = require("node:fs");
const path = require("node:path");
const store = path.join(process.cwd(), "env.json");
const vars = fs.existsSync(store) ? JSON.parse(fs.readFileSync(store, "utf8")) : {};
const args = process.argv.slice(2);
fs.appendFileSync(path.join(process.cwd(), "calls.log"), JSON.stringify(args) + "\\n");
if (args.includes("--fail")) { console.error("deployment not found"); process.exit(1); }
if (args[1] === "get") {
  const name = args[args.length - 1];
  if (name in vars) console.log(vars[name]);
  else console.error('Environment variable "' + name + '" not found');
} else if (args[1] === "set") {
  const [name, value] = args.slice(args.indexOf("--") + 1);
  vars[name] = value;
  fs.writeFileSync(store, JSON.stringify(vars));
}
`;

function project(): string {
  const dir = mkdtempSync(join(tmpdir(), "convex-logto-cli-"));
  writeFileSync(join(dir, "package.json"), "{}");
  const pkg = join(dir, "node_modules", "convex");
  mkdirSync(join(pkg, "bin"), { recursive: true });
  writeFileSync(
    join(pkg, "package.json"),
    JSON.stringify({ name: "convex", bin: { convex: "bin/main.cjs" } }),
  );
  writeFileSync(join(pkg, "bin", "main.cjs"), FAKE_CONVEX);
  return dir;
}

function calls(dir: string): string[][] {
  return readFileSync(join(dir, "calls.log"), "utf8")
    .trim()
    .split("\n")
    .map((line) => JSON.parse(line) as string[]);
}

describe("convexEnv", () => {
  it("round-trips a value and passes deployment flags through", async () => {
    const dir = project();
    const env = convexEnv(["--prod"], dir);
    const jwks = JSON.stringify({ keys: [{ kty: "RSA", n: "-n", e: "AQAB" }] });

    expect(await env.get("LOGTO_JWKS")).toBeUndefined();
    await env.set("LOGTO_JWKS", jwks);
    expect(await env.get("LOGTO_JWKS")).toBe(jwks);
    expect(calls(dir)).toEqual([
      ["env", "get", "--prod", "LOGTO_JWKS"],
      ["env", "set", "--prod", "--", "LOGTO_JWKS", jwks],
      ["env", "get", "--prod", "LOGTO_JWKS"],
    ]);
  });

  it("surfaces the Convex CLI's stderr when it fails", async () => {
    const env = convexEnv(["--fail"], project());
    await expect(env.get("LOGTO_ENDPOINT")).rejects.toThrow(
      /convex env get` failed \(exit 1\)\.\ndeployment not found/,
    );
  });

  it("says where to run it when the project has no convex package", () => {
    const dir = mkdtempSync(join(tmpdir(), "convex-logto-cli-"));
    writeFileSync(join(dir, "package.json"), "{}");
    expect(() => convexEnv([], dir)).toThrow(
      /Could not find the "convex" package/,
    );
  });
});
