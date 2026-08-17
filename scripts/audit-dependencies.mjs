import { spawnSync } from "node:child_process";

const expectedAdvisories = new Map([
  [
    "GHSA-w5hq-g745-h8pq",
    {
      moduleName: "uuid",
      findings: new Set([
        "7.0.3:examples__expo>expo>@expo/config-plugins>xcode>uuid",
      ]),
    },
  ],
  [
    "GHSA-w3rx-r6r6-pgpr",
    {
      moduleName: "image-size",
      findings: new Set([
        "1.2.1:examples__expo>expo>@expo/metro>metro>image-size",
      ]),
    },
  ],
  [
    "GHSA-5p2g-fcmc-qvqq",
    {
      moduleName: "image-size",
      findings: new Set([
        "1.2.1:examples__expo>expo>@expo/metro>metro>image-size",
      ]),
    },
  ],
]);

const pnpmCli = process.env.npm_execpath;
if (!pnpmCli) {
  throw new Error("npm_execpath is unavailable; run this check through pnpm");
}

const audit = spawnSync(process.execPath, [pnpmCli, "audit", "--json"], {
  encoding: "utf8",
  maxBuffer: 50 * 1024 * 1024,
});

if (audit.error) {
  throw audit.error;
}
if (audit.status !== 0 && audit.status !== 1) {
  process.stderr.write(audit.stderr);
  throw new Error(`pnpm audit exited with unexpected status ${audit.status}`);
}

let report;
try {
  report = JSON.parse(audit.stdout);
} catch {
  process.stderr.write(audit.stderr);
  throw new Error("pnpm audit did not return valid JSON");
}

if (
  typeof report !== "object" ||
  report === null ||
  typeof report.advisories !== "object" ||
  report.advisories === null
) {
  throw new Error("pnpm audit returned an unsupported report shape");
}

const seen = new Set();
const failures = [];

for (const advisory of Object.values(report.advisories)) {
  if (typeof advisory !== "object" || advisory === null) {
    failures.push("pnpm audit returned a malformed advisory");
    continue;
  }

  const id = advisory.github_advisory_id;
  const expected = typeof id === "string" ? expectedAdvisories.get(id) : null;
  if (!expected) {
    failures.push(
      `unexpected advisory ${typeof id === "string" ? id : "<missing GHSA id>"}`,
    );
    continue;
  }

  seen.add(id);
  if (advisory.module_name !== expected.moduleName) {
    failures.push(
      `${id} moved from ${expected.moduleName} to ${String(advisory.module_name)}`,
    );
  }

  const actualFindings = new Set();
  if (!Array.isArray(advisory.findings)) {
    failures.push(`${id} has malformed findings`);
    continue;
  }
  for (const finding of advisory.findings) {
    if (
      typeof finding !== "object" ||
      finding === null ||
      typeof finding.version !== "string" ||
      !Array.isArray(finding.paths)
    ) {
      failures.push(`${id} has a malformed finding`);
      continue;
    }
    for (const path of finding.paths) {
      if (typeof path === "string") {
        actualFindings.add(`${finding.version}:${path}`);
      } else {
        failures.push(`${id} has a non-string dependency path`);
      }
    }
  }

  for (const finding of actualFindings) {
    if (!expected.findings.has(finding)) {
      failures.push(`${id} appeared on an unapproved path/version: ${finding}`);
    }
  }
  for (const finding of expected.findings) {
    if (!actualFindings.has(finding)) {
      failures.push(`${id} no longer matches its reviewed exception: ${finding}`);
    }
  }
}

for (const id of expectedAdvisories.keys()) {
  if (!seen.has(id)) {
    failures.push(`${id} is no longer reported; remove its stale exception`);
  }
}

if (failures.length > 0) {
  for (const failure of failures) {
    console.error(`dependency audit: ${failure}`);
  }
  process.exitCode = 1;
} else {
  console.log(
    "Dependency audit passed with 3 reviewed Expo-only advisory paths.",
  );
}
