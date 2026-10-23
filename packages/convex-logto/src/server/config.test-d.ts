// Type-level coverage for `logtoAuthConfig`. Named `.test-d.ts` so `tsc
// --noEmit` (the `check-types` script) type-checks it, while `vitest run` and
// the tsup build both ignore it. Every return shape has to satisfy Convex's
// own `AuthConfig`, and the overloads must narrow on whether `jwks` is a
// string, absent, or (as `process.env.LOGTO_JWKS` is) possibly undefined.
import type { AuthConfig } from "convex/server";
import { expectTypeOf } from "vitest";
import {
  logtoAuthConfig,
  type LogtoAuthProvider,
  type LogtoOidcProvider,
  type LogtoStaticJwksProvider,
} from "./config";

declare const fromEnv: string | undefined;

expectTypeOf(logtoAuthConfig()).toEqualTypeOf<LogtoOidcProvider>();
expectTypeOf(
  logtoAuthConfig({ jwks: "{}" }),
).toEqualTypeOf<LogtoStaticJwksProvider>();
expectTypeOf(
  logtoAuthConfig({ jwks: fromEnv }),
).toEqualTypeOf<LogtoAuthProvider>();

export const config = {
  providers: [
    logtoAuthConfig(),
    logtoAuthConfig({ jwks: "{}" }),
    logtoAuthConfig({ jwks: fromEnv }),
  ],
} satisfies AuthConfig;
