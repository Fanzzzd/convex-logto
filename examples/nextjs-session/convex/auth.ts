// The whole server side of session mode is eleven public functions backed by
// the Logto session component. The frontend provider and the cookie handler in
// `server/logto-cookie.ts` look them up by these exact names.
import { logtoSessionApi } from "convex-logto";
import { components } from "./_generated/api";

export const {
  signIn,
  callback,
  refresh,
  signOut,
  signOutEverywhere,
  listSessions,
  renameSession,
  revokeSession,
  exchangeToken,
  fetchUserInfo,
  sessionValid,
} = logtoSessionApi(components.logto);
