// Every file `package.json#exports` promises must exist after a build.
//
// This exists because the failure it catches is silent by construction: tsup
// reports "Build success" and prints the size of a declaration file that a
// concurrent config's cleaner then deletes (see #101). The build looked fine and
// only a consumer's typecheck noticed — sometimes only in CI. It also catches a
// new export added without a matching tsup entry.
import { readFileSync, statSync } from "node:fs";
import { dirname, resolve } from "node:path";
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

const missing = [];
for (const target of collectTargets(manifest.exports ?? {})) {
  // A wildcard subpath ("./component/*") names a directory of emitted files;
  // assert the directory rather than trying to enumerate the pattern.
  const path = target.includes("*")
    ? target.slice(0, target.indexOf("*")).replace(/\/$/, "")
    : target;
  try {
    statSync(resolve(packageDir, path));
  } catch {
    missing.push(target);
  }
}

if (missing.length > 0) {
  console.error(
    `convex-logto: the build did not produce ${missing.length} file(s) the ` +
      `exports map promises:\n  ${missing.join("\n  ")}\n` +
      "If the build reported success, suspect a concurrent cleaner (#101).",
  );
  process.exit(1);
}
