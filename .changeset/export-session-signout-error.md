---
"convex-logto": minor
---

Export `SessionSignOutError` from `convex-logto/react-session`.

`signOut()` rejects with it when local credential cleanup fails twice, and
`convex-logto/native-session` has always exported the class — the web entry never
did, so the same failure was `instanceof`-checkable in one mode and reachable
only through `error.name` in the other. `SessionSignOutServerStatus` comes with
it, and the web `signOut`'s type now documents the rejection the way native's
already did.

The build verifier gained a check for exactly this: a short list of names both
session entries must export, asserted against the emitted declaration files.
They are separate tsup entries with separate export lists, so one can lose a name
the other keeps and nothing else notices — each entry still typechecks and builds
on its own.
