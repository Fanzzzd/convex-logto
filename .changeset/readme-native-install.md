---
"convex-logto": patch
---

Docs: the README install command now covers React Native / Expo. The npm front
page only showed `pnpm add convex-logto @logto/react`, which installs the wrong
Logto peer for native apps — they need `@logto/rn`. Added a one-line note pointing
native users at `@logto/rn` (everything else is identical). No code change.
