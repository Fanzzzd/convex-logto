// Webhook sync handlers. This example keeps no users table, so no handlers are
// mapped — the webhook still matters: with `sessions` attached in http.ts,
// deleting or suspending a user in Logto kills their sessions within seconds.
import { logtoSync } from "convex-logto";

export const { sync } = logtoSync({});
