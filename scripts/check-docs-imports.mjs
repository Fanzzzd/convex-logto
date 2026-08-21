// Every name the docs import from `convex-logto` has to exist.
//
// This is the drift that keeps happening, and it is silent in both directions:
// nothing compiles an `.mdx` code fence, and the exports map has no idea the
// docs exist. A renamed export leaves the docs telling readers to import
// something that is gone — which they discover as a build error in *their*
// project, on the version they just installed.
//
// Deliberately only the import lines. Making every fenced snippet typecheck
// would mean giving each one a preamble it does not need to be read, and the
// churn would make the docs worse to serve a gate. An import line is the part a
// reader copies verbatim and the part a rename actually breaks.
import { readFileSync, readdirSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const docsDir = resolve(repoRoot, "docs/content/docs");
const distDir = resolve(repoRoot, "packages/convex-logto/dist");

/** Entry subpath -> the declaration file that states its public surface. */
const ENTRIES = {
  "convex-logto": "index.d.ts",
  "convex-logto/react": "react.d.ts",
  "convex-logto/react-session": "react-session.d.ts",
  "convex-logto/native": "native.d.ts",
  "convex-logto/native-session": "native-session.d.ts",
};

/**
 * The emitted `export { ... }` list, not every declaration in the file.
 *
 * tsup emits a `declare class` for anything an exported type mentions, so
 * scanning declarations would accept names no consumer can import — passing on
 * exactly the drift this exists to catch.
 */
function exportedNames(declarationFile) {
  const source = readFileSync(declarationFile, "utf8");
  const names = new Set();
  for (const [, list] of source.matchAll(/^export \{([^}]*)\};?$/gm)) {
    for (const part of list.split(",")) {
      const name = part.trim().replace(/^type\s+/, "").split(/\s+as\s+/).pop();
      if (name) names.add(name);
    }
  }
  return names;
}

const surface = new Map();
for (const [specifier, file] of Object.entries(ENTRIES)) {
  const path = join(distDir, file);
  let names;
  try {
    names = exportedNames(path);
  } catch {
    console.error(
      `check-docs-imports: ${file} is missing. Build the package first ` +
        "(`pnpm --filter convex-logto build`); this check reads the emitted " +
        "declarations, not the source, so it sees what a consumer would.",
    );
    process.exit(1);
  }
  if (names.size === 0) {
    console.error(`check-docs-imports: ${file} declares no exports.`);
    process.exit(1);
  }
  surface.set(specifier, names);
}

/** `import ... from "convex-logto..."`, named bindings only. */
const IMPORT = /import\s+(type\s+)?\{([^}]*)\}\s*from\s*["'](convex-logto[^"']*)["']/g;

const problems = [];
for (const file of readdirSync(docsDir).filter((n) => n.endsWith(".mdx"))) {
  const text = readFileSync(join(docsDir, file), "utf8");
  for (const [, , bindings, specifier] of text.matchAll(IMPORT)) {
    // Subpaths with no importable surface of their own — `convex.config` is a
    // default export the Convex CLI consumes, never a named import.
    if (!surface.has(specifier)) {
      problems.push(`${file}: imports from unknown entry "${specifier}"`);
      continue;
    }
    const names = surface.get(specifier);
    for (const part of bindings.split(",")) {
      const name = part.trim().replace(/^type\s+/, "").split(/\s+as\s+/)[0];
      if (name && !names.has(name)) {
        problems.push(`${file}: "${specifier}" does not export ${name}`);
      }
    }
  }
}

if (problems.length > 0) {
  console.error(
    `check-docs-imports: ${problems.length} import(s) in the docs name ` +
      `something the package does not export:\n  ${problems.join("\n  ")}`,
  );
  process.exit(1);
}

console.error(
  `check-docs-imports: every documented import resolves (${surface.size} entries).`,
);
