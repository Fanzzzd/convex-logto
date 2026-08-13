// Session mode validates the same OIDC ID token as bridge mode — issued to the
// Traditional Web app instead of a SPA app. LOGTO_APP_ID must be that app's id.
import { logtoAuthConfig } from "convex-logto";

export default { providers: [logtoAuthConfig()] };
