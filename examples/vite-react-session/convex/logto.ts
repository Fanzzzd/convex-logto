// Webhook sync handlers. This example keeps no users table, so it maps no
// handlers. The webhook still matters. With `sessions` attached in http.ts,
// deleting or suspending a user in Logto kills their sessions within seconds.
import { logtoSync } from "convex-logto";

export const { sync } = logtoSync({});
