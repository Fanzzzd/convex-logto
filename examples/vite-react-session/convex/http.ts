import { httpRouter } from "convex/server";
import { registerLogtoWebhook } from "convex-logto";
import { components, internal } from "./_generated/api";

const http = httpRouter();
// `sessions` wires Logto account events into session revocation: User.Deleted /
// suspension → all of that user's sessions die, and reactive clients drop live.
// It also deduplicates webhook retries by raw-body hash (exactly-once handling).
registerLogtoWebhook(http, internal.logto.sync, { sessions: components.logto });
export default http;
