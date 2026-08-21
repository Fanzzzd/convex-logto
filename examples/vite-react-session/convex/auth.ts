// The whole server side of session mode: eleven public functions backed by the
// Logto session component. The frontend provider expects these exact names.
import {
  ORGANIZATIONS_SCOPE,
  ORGANIZATION_ROLES_SCOPE,
  logtoSessionApi,
} from "convex-logto";
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
} = logtoSessionApi(components.logto, {
  // Scopes are server-configured: the browser cannot ask for its own, and they
  // are fixed at authorization time — a grant cannot be widened in place, so
  // adding one here means signing in again. These two put `organizations` and
  // `organization_roles` in the ID token, which is where membership and role
  // checks read them from for free. The organization *token* exchange also
  // requires the first one; without it Logto answers `403 insufficient_scope`.
  scopes: [ORGANIZATIONS_SCOPE, ORGANIZATION_ROLES_SCOPE],
});
