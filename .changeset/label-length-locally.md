---
"convex-logto": patch
---

Reject an over-long session label in the browser instead of as a terminal
session error. The component classifies a label past 64 characters as terminal,
and terminal is defined as "this session is gone for good" — so an app following
that taxonomy would sign a user out for typing a long device name.
`renameSession` now checks the length before the round-trip and fails with a
plain error; the component keeps its guard for callers reaching it directly.
