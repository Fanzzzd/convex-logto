# Security policy

## Reporting a vulnerability

Please use GitHub private vulnerability reporting for suspected vulnerabilities.
Do not open a public issue until a fix or coordinated disclosure is ready.

## Dependency audit exceptions

CI runs `pnpm audit:dependencies` and fails on every advisory except the three
exact dependency paths and versions below. The gate also fails if an exception
moves to another dependency path or becomes stale. These are build-time-only
dependencies of the Expo example, not dependencies shipped by the
`convex-logto` npm package.

| Advisory | Dependency path | Reason for temporary exception |
| --- | --- | --- |
| [GHSA-w5hq-g745-h8pq](https://github.com/advisories/GHSA-w5hq-g745-h8pq) | Expo config plugins → `xcode` → `uuid@7` | The affected UUID versions and caller-supplied buffer API are not used by this build path. Expo's upstream range does not yet accept a patched major. |
| [GHSA-w3rx-r6r6-pgpr](https://github.com/advisories/GHSA-w3rx-r6r6-pgpr) | Expo Metro → `image-size` | No patched release exists. Metro only reads local project assets in this example. |
| [GHSA-5p2g-fcmc-qvqq](https://github.com/advisories/GHSA-5p2g-fcmc-qvqq) | Expo Metro → `image-size` | No patched release exists. Metro only reads local project assets in this example. |

Owner: repository maintainer. Review by: **2026-09-16**, and on every Expo
upgrade. Remove an exception as soon as its upstream dependency accepts a safe
version.
