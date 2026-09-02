// Native session mode validates the same OIDC ID token as every other mode.
// Logto issues it to the Traditional Web app, not a native/SPA app.
// LOGTO_APP_ID must be that app's id.
import { logtoAuthConfig } from "convex-logto";

export default { providers: [logtoAuthConfig()] };
