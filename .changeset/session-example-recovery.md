---
"convex-logto": patch
---

Examples: the Expo session example now handles a reclaimed sign-in, and both session examples report auth errors.

`examples/expo-session` wires `expo-linking` into `completeSignIn`, so a sign-in the OS reclaimed while Logto had the browser — routine on a low-memory Android device — finishes from the cold-start deep link instead of leaving the user signed in at Logto and signed out in the app. Both session examples now pass `onAuthError` and swallow the rejection at the call site, matching `examples/expo`.
