---
"convex-logto": patch
---

Session mode: run session actions over HTTP instead of the app's WebSocket
client. Convex stops that socket before asking for a fresh token, so the
`refresh` action it triggered parked forever and the socket was never restarted
— a server-rejected ID token (a suspended tab, a backgrounded native app) wedged
the whole app until reload.
