// Every file `package.json#exports` promises must exist after a build.
//
// This exists because the failure it catches is silent by construction: tsup
// reports "Build success" and prints the size of a declaration file that a
// concurrent config's cleaner then deletes (see #101). The build looked fine and
// only a consumer's typecheck noticed — sometimes only in CI. It also catches a
// new export added without a matching tsup entry.
import { readdirSync, readFileSync, statSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

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
