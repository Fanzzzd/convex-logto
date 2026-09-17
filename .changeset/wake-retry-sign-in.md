---
"convex-logto": patch
---

Session mode retries the two sign-in requests a waking laptop or a phone
changing networks used to lose. `signIn` asks the deployment for the authorize
URL again on the same short backoff a refresh uses, and the callback exchange
retries a transport failure on that backoff instead of once, immediately. A
`ConvexError` is still never retried, and a retry that finds the transaction
gone still reports the first attempt's error. Before this, `Failed to fetch` on
either request rejected `signIn` after a single attempt, and an app that starts
sign-in from an effect stayed on its loader until a reload.
