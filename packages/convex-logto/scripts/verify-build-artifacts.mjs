// Every file `package.json#exports` promises must exist after a build.
//
// This exists because the failure it catches is silent by construction: tsup
// reports "Build success" and prints the size of a declaration file that a
// concurrent config's cleaner then deletes (see #101). The build looked fine and
// only a consumer's typecheck noticed — sometimes only in CI. It also catches a
// new export added without a matching tsup entry.
import { readdirSync, readFileSync, statSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const packageDir = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const manifest = JSON.parse(
  readFileSync(resolve(packageDir, "package.json"), "utf8"),
);

/** Every string leaf of the exports map is a path this package promises. */
function collectTargets(node, targets = new Set()) {
  if (typeof node === "string") {
    if (node.startsWith("./")) targets.add(node);
    return targets;
  }
  if (node !== null && typeof node === "object") {
    for (const value of Object.values(node)) collectTargets(value, targets);
  }
  return targets;
}

function isFile(path) {
  try {
    return statSync(path).isFile();
  } catch {
    return false;
  }
}

/**
 * A wildcard subpath ("./component/*") is satisfied only by a real file the
 * pattern matches. Asserting the parent directory instead would pass on a
 * half-populated one, which is exactly the failure this script exists to catch.
 */
function matchesWildcard(target) {
  const [prefix, ...rest] = target.split("*");
  const suffix = rest.join("*");
  const root = resolve(packageDir, dirname(prefix));
  const walk = (directory) => {
    let entries;
    try {
      entries = readdirSync(directory, { withFileTypes: true });
    } catch {
      return false;
    }
    return entries.some((entry) => {
      const path = join(directory, entry.name);
      if (entry.isDirectory()) return walk(path);
      const relative = `./${path.slice(packageDir.length + 1)}`;
      return (
        relative.startsWith(prefix) &&
        relative.endsWith(suffix) &&
        relative.length >= prefix.length + suffix.length &&
        isFile(path)
      );
    });
  };
  return walk(root);
}

const missing = [];
for (const target of collectTargets(manifest.exports ?? {})) {
  const satisfied = target.includes("*")
    ? matchesWildcard(target)
    : isFile(resolve(packageDir, target));
  if (!satisfied) missing.push(target);
}

if (missing.length > 0) {
  console.error(
    `convex-logto: the build did not produce ${missing.length} file(s) the ` +
      `exports map promises:\n  ${missing.join("\n  ")}\n` +
      "If the build reported success, suspect a concurrent cleaner (#101).",
  );
  process.exit(1);
}

/**
 * The component half is not bundled: the Convex CLI walks `dist/component/` and
 * bundles the modules it finds there, so every relative specifier in the emitted
 * tree has to resolve on disk. `publint` and `attw` only look at the exports map,
 * and nothing else ever loads these files — so a missing emit, or a specifier
 * `tsc` rewrote in a way Node cannot resolve, would ship and surface on the
 * *user's* next `convex dev` push instead of here.
 */
const componentDir = resolve(packageDir, "dist/component");

function componentModules(directory, found = []) {
  let entries;
  try {
    entries = readdirSync(directory, { withFileTypes: true });
  } catch {
    return found;
  }
  for (const entry of entries) {
    const path = join(directory, entry.name);
    if (entry.isDirectory()) componentModules(path, found);
    else if (entry.name.endsWith(".js")) found.push(path);
  }
  return found;
}

/** Relative `import`/`export ... from` specifiers, as emitted (quotes included). */
const RELATIVE_SPECIFIER = /\bfrom\s*["'](\.[^"']*)["']/g;

const modules = componentModules(componentDir);
if (modules.length === 0) {
  console.error(
    "convex-logto: the build produced no modules under dist/component/. " +
      "The Convex CLI bundles that directory; an empty one ships a broken component.",
  );
  process.exit(1);
}

const unresolved = [];
for (const modulePath of modules) {
  const source = readFileSync(modulePath, "utf8");
  for (const [, specifier] of source.matchAll(RELATIVE_SPECIFIER)) {
    const target = resolve(dirname(modulePath), specifier);
    // tsc emits extensionless specifiers under `moduleResolution: Bundler`;
    // accept either form, since the CLI's bundler resolves both.
    if (isFile(target) || isFile(`${target}.js`) || isFile(join(target, "index.js"))) {
      continue;
    }
    unresolved.push(
      `${modulePath.slice(packageDir.length + 1)} -> ${specifier}`,
    );
  }
}

if (unresolved.length > 0) {
  console.error(
    `convex-logto: ${unresolved.length} relative specifier(s) in dist/component/ ` +
      `do not resolve to a file:\n  ${unresolved.join("\n  ")}`,
  );
  process.exit(1);
}

/**
 * The two session entries have to agree on the surface they share.
 *
 * They are separate tsup entries with separate export lists, so one can quietly
 * lose a name the other keeps — and nothing else notices, because each entry
 * typechecks and builds on its own. That has already happened once:
 * `SessionSignOutError` shipped from `native-session` and not from
 * `react-session`, leaving a web app matching on `error.name` for a failure a
 * native app could `instanceof`.
 *
 * Deliberately a small explicit list rather than a diff with an exception list:
 * the entries *should* differ (cookies and `TokenStorageKind` are web-only,
 * `completeSignIn` is native-only), so a full diff would need an allowlist,
 * and an allowlist is the thing that rots. These are the names that must be in
 * both because both engines produce them.
 */
const SHARED_SESSION_EXPORTS = [
  "ConvexLogtoSessionProvider",
  "useLogtoAuth",
  "LogtoSessionApi",
  "LogtoSessionAuth",
  "LogtoSessionSummary",
  "LogtoResourceTokenClaims",
  "LogtoTokenExchangeOptions",
  "LogtoAuthEvent",
  "LogtoAuthPhase",
  "SessionSignOutError",
  "SessionSignOutServerStatus",
];

const asymmetric = [];
for (const entry of ["react-session", "native-session"]) {
  const declaration = resolve(packageDir, `dist/${entry}.d.ts`);
  if (!isFile(declaration)) {
    console.error(`convex-logto: dist/${entry}.d.ts is missing.`);
    process.exit(1);
  }
  const source = readFileSync(declaration, "utf8");
  // The emitted export list, not the whole file: a `declare class` that no
  // export names is not part of the public surface, and matching on it would
  // make this check pass on exactly the drift it exists to catch.
  const exported = new Set(
    [...source.matchAll(/^export \{([^}]*)\};?$/gm)]
      .flatMap(([, names]) => names.split(","))
      .map((name) => name.trim().replace(/^type\s+/, "").split(/\s+as\s+/).pop())
      .filter(Boolean),
  );
  for (const name of SHARED_SESSION_EXPORTS) {
    if (!exported.has(name)) asymmetric.push(`${entry} is missing ${name}`);
  }
}

if (asymmetric.length > 0) {
  console.error(
    `convex-logto: the session entries disagree about their own API:\n  ` +
      `${asymmetric.join("\n  ")}\n` +
      "Both engines produce these; exporting one from only one entry makes the " +
      "same failure handleable in one mode and not the other.",
  );
  process.exit(1);
}

// The component's entry point must also actually load.
await import(pathToFileURL(resolve(componentDir, "convex.config.js")).href).catch(
  (error) => {
    console.error(
      "convex-logto: dist/component/convex.config.js could not be imported.",
      error,
    );
    process.exit(1);
  },
);
