// The real DeploymentEnv: the project's own Convex CLI, run as
// `convex env get|set` with the caller's deployment flags passed through, so
// `--prod`, `--deployment`, `--url`/`--admin-key`, `--env-file` and
// CONVEX_DEPLOY_KEY select a deployment exactly as they do for
// `npx convex env`. With a deployment type it runs `convex env default
// get|set --type <type>` instead: the project's defaults, which is how a
// preview deployment has LOGTO_JWKS before it exists.

import { spawn } from "node:child_process";
import { existsSync, readFileSync } from "node:fs";
import { dirname, join, resolve as resolvePath } from "node:path";
import { isRecord } from "../shared/decode";
import { JwksSyncError, type DeploymentEnv } from "./jwks-sync";

/**
 * Locate `convex/bin/main.js` by walking `node_modules` up from `cwd`, the
 * way the project's own `npx convex` finds it. Not `require.resolve`: under
 * `pnpm exec` that also searches NODE_PATH and can land on another project's
 * copy.
 */
function convexCliPath(cwd: string): string {
  for (let dir = resolvePath(cwd); ; dir = dirname(dir)) {
    const manifestPath = join(dir, "node_modules", "convex", "package.json");
    if (existsSync(manifestPath)) {
      let manifest: unknown;
      try {
        manifest = JSON.parse(readFileSync(manifestPath, "utf8"));
      } catch {
        throw new JwksSyncError(`Could not read ${manifestPath}.`);
      }
      const bin =
        isRecord(manifest) && isRecord(manifest.bin)
          ? manifest.bin.convex
          : undefined;
      return join(
        dirname(manifestPath),
        typeof bin === "string" ? bin : "bin/main.js",
      );
    }
    if (dirname(dir) === dir) break;
  }
  throw new JwksSyncError(
    `Could not find the "convex" package from ${cwd}. Run this from your Convex project's directory.`,
  );
}

function run(
  cli: string,
  args: string[],
  cwd: string,
  label: string,
): Promise<string> {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [cli, ...args], {
      cwd,
      env: process.env,
      stdio: ["ignore", "pipe", "pipe"],
    });
    let stdout = "";
    let stderr = "";
    child.stdout.setEncoding("utf8").on("data", (chunk: string) => {
      stdout += chunk;
    });
    child.stderr.setEncoding("utf8").on("data", (chunk: string) => {
      stderr += chunk;
    });
    child.on("error", reject);
    child.on("close", (code) => {
      if (code === 0) resolve(stdout);
      else
        reject(
          new JwksSyncError(
            `\`convex ${label}\` failed (exit ${code}).\n${stderr.trim()}`,
          ),
        );
    });
  });
}

/** Project-level default environment variables, per deployment type. */
export type DefaultsType = "dev" | "preview" | "prod";

export function convexEnv(
  passthrough: readonly string[],
  options: { cwd?: string; defaults?: DefaultsType } = {},
): DeploymentEnv {
  const cwd = options.cwd ?? process.cwd();
  const cli = convexCliPath(cwd);
  const scope = options.defaults === undefined ? ["env"] : ["env", "default"];
  const flags =
    options.defaults === undefined
      ? [...passthrough]
      : [...passthrough, "--type", options.defaults];
  return {
    async get(name) {
      // An unset variable prints nothing to stdout and still exits 0.
      const output = await run(
        cli,
        [...scope, "get", ...flags, name],
        cwd,
        [...scope, "get", name].join(" "),
      );
      const value = output.replace(/\r?\n$/, "");
      return value === "" ? undefined : value;
    },
    async set(name, value) {
      await run(
        cli,
        [...scope, "set", ...flags, "--", name, value],
        cwd,
        [...scope, "set", name].join(" "),
      );
    },
  };
}
