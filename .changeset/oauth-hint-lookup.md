---
"convex-logto": patch
---

Stop resolving an OAuth error hint off `Object.prototype`.

The sign-in error classifier looked its hint table up as a plain object, keyed
by the `error` parameter taken straight from the callback URL. `?error=constructor`
therefore found `Object`, and the message the app displays ended with
`function Object() { [native code] }`; `?error=__proto__` appended
`[object Object]`. The table is a `Map` now, so a lookup can only find a key the
library put there.
