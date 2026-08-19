---
"convex-logto": patch
---

Fix a regression in the previous patch: in cookie transport mode, signing in
over an existing session revoked the session it had just created. The stored
value there is a marker rather than a credential, and the same-origin sign-out
route reads the cookie — which the callback had already replaced — so the user
was signed straight back out.
