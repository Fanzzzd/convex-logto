// `convex-logto`: the package's Node bin.
//
//   npx convex-logto sync-jwks  [own options] [convex env options]
//   npx convex-logto check-jwks [own options] [convex env options]

import { convexEnv, type DefaultsType } from "./convex-env";
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
  --endpoint <url>          Logto endpoint, when the app passes \`endpoint\` to
                            logtoAuthConfig instead of setting LOGTO_ENDPOINT
  --defaults <type>         Read and write the project's default variables for
                            a deployment type (dev, preview, prod) instead of
                            one deployment's. Preview deployments start from
                            these.
  --allow-insecure-http     Accept a non-loopback http:// endpoint
  -h, --help                Show this help

Every other option goes to \`convex env\` unchanged and selects the deployment:
--prod, --deployment <ref>, --url <url>, --admin-key <key>, --env-file <path>.
CONVEX_DEPLOY_KEY works as it does for \`npx convex env\`.

Run sync-jwks on every deployment after rotating keys in Logto, or every new
sign-in is rejected.`;

export type CliIo = {
  out(line: string): void;
  err(line: string): void;
  /** Builds the deployment environment from the passthrough arguments. */
  env(passthrough: string[], defaults?: DefaultsType): DeploymentEnv;
  fetch?: typeof globalThis.fetch;
  /** Format errors as GitHub Actions annotations. */
  github?: boolean;
};

type Parsed = {
  endpoint?: string;
  defaults?: DefaultsType;
  allowInsecureHttp: boolean;
  passthrough: string[];
};

class UsageError extends Error {}

/** Split this CLI's own options from the ones `convex env` receives. */
function parseOptions(args: readonly string[]): Parsed {
  const parsed: Parsed = { allowInsecureHttp: false, passthrough: [] };
  for (let index = 0; index < args.length; index++) {
    const arg = args[index] ?? "";
    const equals = arg.startsWith("--") ? arg.indexOf("=") : -1;
    const flag = equals === -1 ? arg : arg.slice(0, equals);
    const inline = equals === -1 ? undefined : arg.slice(equals + 1);
    if (flag === "--allow-insecure-http" && inline === undefined) {
      parsed.allowInsecureHttp = true;
    } else if (flag === "--endpoint" || flag === "--defaults") {
      const value = inline ?? args[++index];
      if (value === undefined || value === "" || value.startsWith("--")) {
        throw new UsageError(`${flag} needs a value.`);
      }
      if (flag === "--endpoint") {
        parsed.endpoint = value;
      } else if (value === "dev" || value === "preview" || value === "prod") {
        parsed.defaults = value;
      } else {
        throw new UsageError(
          `--defaults takes dev, preview or prod, not "${value}".`,
        );
      }
    } else {
      parsed.passthrough.push(arg);
    }
  }
  return parsed;
}

/** Arguments to echo back, with the admin key's value hidden. */
function redact(args: readonly string[]): string[] {
  return args.map((arg, index) =>
    args[index - 1] === "--admin-key"
      ? "<admin key>"
      : arg.startsWith("--admin-key=")
        ? "--admin-key=<admin key>"
        : arg,
  );
}

/**
 * A GitHub Actions workflow command ends at the first newline, so a
 * multi-line message (Convex's own stderr included) has to be encoded.
 */
function annotation(kind: "error" | "warning", message: string): string {
  const encoded = message
    .replace(/%/g, "%25")
    .replace(/\r/g, "%0D")
    .replace(/\n/g, "%0A");
  return `::${kind}::${encoded}`;
}

/** Run the CLI and return its exit code. */
export async function main(argv: string[], io: CliIo): Promise<number> {
  const [command, ...rest] = argv;
  if (command === "-h" || command === "--help") {
    io.out(USAGE);
    return 0;
  }
  if (command === undefined) {
    io.err(USAGE);
    return 2;
  }
  if (rest.includes("-h") || rest.includes("--help")) {
    io.out(USAGE);
    return 0;
  }
  if (command !== "sync-jwks" && command !== "check-jwks") {
    io.err(`Unknown command "${command}".\n\n${USAGE}`);
    return 2;
  }
  let parsed: Parsed;
  try {
    parsed = parseOptions(rest);
  } catch (error) {
    if (!(error instanceof UsageError)) throw error;
    io.err(`convex-logto: ${error.message}`);
    return 2;
  }
  const report = (kind: "error" | "warning", message: string) =>
    io.err(io.github ? annotation(kind, message) : `convex-logto: ${message}`);

  try {
    const options = {
      env: io.env(parsed.passthrough, parsed.defaults),
      fetch: io.fetch,
      endpoint: parsed.endpoint,
      allowInsecureHttp: parsed.allowInsecureHttp,
    };
    const target =
      parsed.defaults === undefined
        ? "LOGTO_JWKS"
        : `the ${parsed.defaults} default LOGTO_JWKS`;
    if (command === "sync-jwks") {
      const result = await syncJwks(options);
      const kids = result.keys.map((key) => key.kid ?? "(no kid)").join(", ");
      io.out(
        result.changed
          ? `${target} set from ${result.jwksUrl} (${kids}).`
          : `${target} already matches ${result.jwksUrl} (${kids}).`,
      );
      return 0;
    }
    const result = await checkJwks(options);
    if (result.unusableNext !== undefined) {
      report(
        "warning",
        `Logto has staged ${result.unusableNext} as its next signing key, and a static JWKS cannot verify it. Every sign-in fails once Logto promotes it. Stage an RSA key instead.`,
      );
    }
    if (result.unusable.length > 0) {
      io.out(
        `Logto also serves ${result.unusable.join(", ")}, which a static JWKS cannot verify. Normally that is the key Logto kept as the previous one after a rotation to RSA, and nothing signs with it.`,
      );
    }
    if (result.stale.length > 0) {
      report(
        "warning",
        `${target} still holds keys Logto no longer serves (${result.stale.join(", ")}). Harmless; sync-jwks drops them.`,
      );
    }
    if (result.missing.length > 0) {
      const rerun = [
        "npx convex-logto sync-jwks",
        ...redact(rest.filter((arg) => arg !== "-h" && arg !== "--help")),
      ].join(" ");
      report(
        "error",
        `Logto serves ${result.missing.join(", ")}, which ${target} lacks. Convex rejects every sign-in signed with it. Run: ${rerun}`,
      );
      return 1;
    }
    io.out(`${target} holds every key ${result.jwksUrl} serves.`);
    return 0;
  } catch (error) {
    if (!(error instanceof JwksSyncError)) throw error;
    report("error", error.message);
    return 1;
  }
}

/** The bin entry: real Convex CLI, real fetch, real streams. */
export async function run(): Promise<void> {
  process.exitCode = await main(process.argv.slice(2), {
    out: (line) => console.log(line),
    err: (line) => console.error(line),
    env: (passthrough, defaults) => convexEnv(passthrough, { defaults }),
    github: process.env.GITHUB_ACTIONS === "true",
  });
}
