---
"convex-logto": patch
---

Garbage-collect revocation watermarks.

`subjectRevocations` and `sidRevocations` were never collected: `gc` swept every
other table and skipped these two, and nothing else deleted from them. With
back-channel logout enabled that is one permanent row per Logto OP session that
ever ends — `markSidRevoked` inserts even when the logout matched no sessions,
which the guide describes as a normal outcome — and the tables are
component-private, so an app cannot prune them either.

`gc` now collects a watermark, but only when it can no longer kill anything: no
session it governs survives, and it is older than `SESSION_GC_AFTER_MS`. Both
conditions are load-bearing. Deleting a marker while a row it killed is still
waiting for a cleanup batch would hand that row's token its authority back, and
a refresh can bind a `sid` to a session that did not carry one, so "nothing
governed today" is not sufficient on its own. Two new `by_revokedAt` indexes let
the sweep find candidates without scanning; the component takes care of building
them on the next push, and no migration is required.
