// Minimal ambient for reading env vars in Convex backend code, without pulling
// in all of @types/node (which would conflict with the DOM `crypto` global used
// by the Web Crypto signature check). Build-only; not emitted to dist.
declare const process: { env: Record<string, string | undefined> };
