---
"convex-logto": patch
---

Stop a deployment misconfiguration from deleting sessions, and bound the two
strings an unauthenticated sign-in stores.

**A refresh failure that describes your deployment is no longer terminal.**
`invalid_client` was already handled, but three faults routed around it and
deleted the session row: a `LOGTO_ENDPOINT` that no longer matches the `iss`
Logto issues (after a custom domain or a reverse proxy moved), a spec-legal array
`aud` the component rejected while Convex and this library's own back-channel
logout accept it, and a readable non-JSON 2xx such as a proxy interstitial. Each
would destroy every session in the deployment, one refresh at a time. They are
transient now, and because Logto answered 2xx, any refresh token it rotated is
persisted first — re-presenting a superseded token would trip Logto's reuse
detection and destroy the grant sibling sessions share.

**`signIn` bounds `redirectUri` and `returnTo`.** Sign-in is necessarily
unauthenticated, and both strings were stored verbatim in a `transactions` row,
so anyone who knew the deployment URL could park documents near Convex's 1 MiB
limit in a loop while GC drained four per mutation. Both are now capped at 2048
characters, and `redirectUri` must be an absolute URI without embedded
credentials — custom schemes still work, since native sign-in depends on them.
