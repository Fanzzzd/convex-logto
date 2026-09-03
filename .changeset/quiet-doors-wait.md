---
"convex-logto": patch
---

Session mode: a `signIn()` started while a `signOut()` is in flight now waits for it, and starts nothing once the page is on its way to Logto's end-session endpoint.

Sign-out clears local state, then awaits the server revoke, then navigates to end the SSO session. An app that sends every unauthenticated render to its sign-in route (protected route → `/login` → `signIn()` on mount) called `signIn()` inside that await. Its authorize navigation cancelled the end-session one, Logto's SSO cookie answered it without a prompt, and the user who had just clicked "Sign out" was signed straight back in. Reproduced live against a self-hosted Logto; bridge mode never showed it because `@logto/react` navigates in the same tick it clears state.

A sign-out that stays on the page (`federated: false`, native, or a failed navigation) releases the wait, so the sign-in that follows it is an ordinary one.
