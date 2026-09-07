---
"convex-logto": patch
---

Prose-only release. Session mode is now the documented default. The npm README
and the docs site walk through a Traditional web app, the session component,
`logtoSessionApi`, and `ConvexLogtoSessionProvider` first, with
`initialAuthTokenReuse: true` and `onAuthError` in the quick-start code rather
than in a footnote; bridge mode moves to its own page. Stale claims are gone:
the integration pages no longer teach `configQuery` as the only bridge-mode
path (static `config` has been the default since 0.4.0), "How it works" no
longer describes the inert Logto client that 0.4.0 removed, the `sessionApi`
name list includes `exchangeToken` and `fetchUserInfo`, and the session
provider's props table lists `clientDescriptor` and `onAuthEvent`. No code
changes.
