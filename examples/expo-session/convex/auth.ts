// The whole server side of session mode: eleven public functions backed by the
// Logto session component. The native provider expects these exact names, and
// they are the same functions the web session example re-exports — one server
// surface for both platforms.
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
