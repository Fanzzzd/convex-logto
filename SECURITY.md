# Security policy

## Reporting a vulnerability

Report suspected vulnerabilities through GitHub private vulnerability reporting.
Do not open a public issue until a fix or coordinated disclosure is ready.

## Dependency audit exceptions

CI runs `pnpm audit:dependencies` and fails on every advisory except the three
exact dependency paths and versions below. The gate also fails if an exception
moves to another dependency path or becomes stale. These are build-time-only
dependencies of the Expo examples (`examples/expo` and
`examples/expo-session`, which share the same Expo toolchain), not dependencies
shipped by the `convex-logto` npm package. `pnpm audit` reports one resolved
path per advisory, so the paths below name whichever example it resolves
through; if that ever changes the gate fails closed rather than widening on
its own.

| Advisory | Resolved version and dependency path | Reason for temporary exception |
| --- | --- | --- |
| [GHSA-w5hq-g745-h8pq](https://github.com/advisories/GHSA-w5hq-g745-h8pq) | `uuid@7.0.3` via `examples__expo > expo > @expo/config-plugins > xcode > uuid` | This build path does not use the affected caller-supplied buffer API. Expo's upstream range does not yet accept a patched major. |
| [GHSA-w3rx-r6r6-pgpr](https://github.com/advisories/GHSA-w3rx-r6r6-pgpr) | `image-size@1.2.1` via `examples__expo > expo > @expo/metro > metro > image-size` | No patched release exists. Metro only reads local project assets in this example. |
| [GHSA-5p2g-fcmc-qvqq](https://github.com/advisories/GHSA-5p2g-fcmc-qvqq) | `image-size@1.2.1` via `examples__expo > expo > @expo/metro > metro > image-size` | No patched release exists. Metro only reads local project assets in this example. |

These strings are the exact `version:path` keys the audit script matches on
(`scripts/audit-dependencies.mjs`); the gate fails if a version or path drifts.

Owner: repository maintainer. Review by: **2026-09-16**, and on every Expo
upgrade. Remove an exception as soon as its upstream dependency accepts a safe
version.
