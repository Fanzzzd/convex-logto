// `convex-logto`: the package's Node bin.
//
//   npx convex-logto sync-jwks [--allow-insecure-http] [convex env options]
//   npx convex-logto check-jwks [--allow-insecure-http] [convex env options]

import { convexEnv } from "./convex-env";
import {
  JwksSyncError,
  checkJwks,
  syncJwks,
  type DeploymentEnv,
} from "./jwks-sync";

const USAGE = `Usage: convex-logto <command> [options] [convex env options]

Commands:
  sync-jwks    Copy Logto's RS256 signing keys into this deployment's LOGTO_JWKS
  check-jwks   Exit 1 when Logto serves a signing key LOGTO_JWKS lacks

Options:
  --allow-insecure-http   Accept a non-loopback http:// LOGTO_ENDPOINT
  -h, --help              Show this help

Every other option goes to \`convex env\` unchanged and selects the deployment:
--prod, --deployment-name <name>, --preview-name <name>, --url <url>,
--admin-key <key>, --env-file <path>. CONVEX_DEPLOY_KEY works as it does for
\`npx convex env\`.

Run sync-jwks on every deployment after rotating keys in Logto, or every new
sign-in is rejected.`;

export type CliIo = {
  out(line: string): void;
  err(line: string): void;
  /** Builds the deployment environment from the passthrough arguments. */
  env(passthrough: string[]): DeploymentEnv;
  fetch?: typeof globalThis.fetch;
  /** Format errors as GitHub Actions annotations. */
  github?: boolean;
};

/** Deployment flags to echo back, with the admin key's value hidden. */
function redact(args: readonly string[]): string[] {
  return args.map((arg, index) =>
    args[index - 1] === "--admin-key"
      ? "<admin key>"
      : arg.startsWith("--admin-key=")
        ? "--admin-key=<admin key>"
        : arg,
  );
}

/** Run the CLI and return its exit code. */
export async function main(argv: string[], io: CliIo): Promise<number> {
  const [command, ...rest] = argv;
  if (command === undefined || command === "-h" || command === "--help") {
    io.out(USAGE);
    return command === undefined ? 2 : 0;
  }
  if (rest.includes("-h") || rest.includes("--help")) {
    io.out(USAGE);
    return 0;
  }
  if (command !== "sync-jwks" && command !== "check-jwks") {
    io.err(`Unknown command "${command}".\n\n${USAGE}`);
    return 2;
  }
  const allowInsecureHttp = rest.includes("--allow-insecure-http");
  const passthrough = rest.filter((arg) => arg !== "--allow-insecure-http");
  const fail = (message: string) =>
    io.err(io.github ? `::error::${message}` : `convex-logto: ${message}`);

  try {
    const options = {
      env: io.env(passthrough),
      fetch: io.fetch,
      allowInsecureHttp,
    };
    if (command === "sync-jwks") {
      const result = await syncJwks(options);
      const kids = result.keys.map((key) => key.kid ?? "(no kid)").join(", ");
      io.out(
        result.changed
          ? `LOGTO_JWKS set from ${result.jwksUrl} (${kids}).`
          : `LOGTO_JWKS already matches ${result.jwksUrl} (${kids}).`,
      );
      return 0;
    }
    const result = await checkJwks(options);
    const warn = (message: string) =>
      io.err(`${io.github ? "::warning::" : "convex-logto: "}${message}`);
    if (result.unusable.length > 0) {
      warn(
        `Logto also serves ${result.unusable.join(", ")}, which a static JWKS cannot verify. If that is a staged next key, every sign-in fails once Logto promotes it; stage an RSA key instead.`,
      );
    }
    if (result.stale.length > 0) {
      warn(
        `LOGTO_JWKS still holds keys Logto no longer serves (${result.stale.join(", ")}). Harmless; sync-jwks drops them.`,
      );
    }
    if (result.missing.length > 0) {
      fail(
        `Logto serves ${result.missing.join(", ")}, which LOGTO_JWKS lacks. Convex rejects every sign-in signed with it. Run: npx convex-logto sync-jwks ${redact(passthrough).join(" ")}`.trimEnd(),
      );
      return 1;
    }
    io.out(`LOGTO_JWKS holds every key ${result.jwksUrl} serves.`);
    return 0;
  } catch (error) {
    if (!(error instanceof JwksSyncError)) throw error;
    fail(error.message);
    return 1;
  }
}

/** The bin entry: real Convex CLI, real fetch, real streams. */
export async function run(): Promise<void> {
  process.exitCode = await main(process.argv.slice(2), {
    out: (line) => console.log(line),
    err: (line) => console.error(line),
    env: (passthrough) => convexEnv(passthrough),
    github: process.env.GITHUB_ACTIONS === "true",
  });
}
