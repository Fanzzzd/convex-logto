---
"convex-logto": minor
---

Add React Native / Expo support via a new `convex-logto/native` entry.

`ConvexLogtoProvider` and `useLogtoAuth` now have native counterparts built on
`@logto/rn` (added as an optional peer dependency). The server APIs
(`logtoAuthConfig`, `logtoConfigQuery`, the webhook sync) are unchanged and fully
shared. On native, `signIn` opens the system browser and resolves on the deep-link
return — there's no callback route to add, and `signIn()` defaults to the
provider's `redirectUri`. See the new React Native guide and the `examples/expo` app.
