// App Router route handlers take and return standard Request/Response, so the
// cookie handler mounts as a catch-all with no adapter.
//
// OPTIONS is exported too. A same-site mount on a different origin (app.example
// .com calling api.example.com) sends a credentialed CORS preflight, and the
// handler answers it from the same `allowedOrigins` list.
import { logtoCookieHandler } from "@/server/logto-cookie";

export const POST = logtoCookieHandler;
export const OPTIONS = logtoCookieHandler;
