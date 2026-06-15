import { httpRouter } from "convex/server";
import { registerLogtoWebhook } from "convex-logto";
import { internal } from "./_generated/api";

const http = httpRouter();

// Verifies the `logto-signature-sha-256` header (needs LOGTO_WEBHOOK_SIGNING_KEY)
// and dispatches to the `sync` mutation in `logto.ts`. Serves POST /logto/webhook.
//
// Locally this won't fire (Logto can't reach your dev backend), so rows are created
// by the onboarding form instead — see the README. In production it's what keeps
// email/name in sync and handles suspension/deletion.
registerLogtoWebhook(http, internal.logto.sync);

export default http;
