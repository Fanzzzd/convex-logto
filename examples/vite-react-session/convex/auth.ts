// The whole server side of session mode: six public functions backed by the
// Logto session component. The frontend provider expects these exact names.
import { logtoSessionApi } from "convex-logto";
import { components } from "./_generated/api";

export const {
  signIn,
  callback,
  refresh,
  signOut,
  signOutEverywhere,
  sessionValid,
} = logtoSessionApi(components.logto);
