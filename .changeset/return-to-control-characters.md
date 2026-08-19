---
"convex-logto": patch
---

Close an open redirect in the post-sign-in `returnTo` guard.

`isSafeReturnTo` rejected `//host` and `\`, but not a raw ASCII tab, LF or CR.
The WHATWG URL parser strips those *before* it parses anything, so
`/<TAB>/evil.example.com` inspected as an ordinary same-origin path and then
resolved to `https://evil.example.com/`. A crafted sign-in link — or, with the
cookie transport, a crafted `returnTo` in the SSR seed request — could therefore
send a user to an attacker's origin immediately after authenticating, which is
exactly the client-side open redirector RFC 9700 §4.11.1 forbids. The guard now
also refuses the C0 range and DEL; a legitimate path carries a control character
percent-encoded, never raw.
