---
"convex-logto": minor
---

Native session mode: `useLogtoAuth()` gains `completeSignIn(url)`, for a sign-in
whose deep link arrives outside the system-browser promise. When the OS reclaims
the app mid-flow that promise dies with the process, and the user used to come
back signed in at Logto but signed out in the app, with no error. Wire it to
Expo `Linking` — anything that is not the app's `redirectUri` is ignored.
