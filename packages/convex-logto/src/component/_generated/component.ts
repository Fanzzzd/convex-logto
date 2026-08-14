/* eslint-disable */
/**
 * Generated `ComponentApi` utility.
 *
 * THIS CODE IS AUTOMATICALLY GENERATED.
 *
 * To regenerate, run `npx convex dev`.
 * @module
 */

import type { FunctionReference } from "convex/server";

/**
 * A utility for referencing a Convex component's exposed API.
 *
 * Useful when expecting a parameter like `components.myComponent`.
 * Usage:
 * ```ts
 * async function myFunction(ctx: QueryCtx, component: ComponentApi) {
 *   return ctx.runQuery(component.someFile.someQuery, { ...args });
 * }
 * ```
 */
export type ComponentApi<Name extends string | undefined = string | undefined> =
  {
    lib: {
      createSignInUrl: FunctionReference<
        "action",
        "internal",
        {
          appId: string;
          endpoint: string;
          redirectUri: string;
          resources?: Array<string>;
          returnTo?: string;
          scopes?: Array<string>;
        },
        { url: string },
        Name
      >;
      exchange: FunctionReference<
        "action",
        "internal",
        {
          appId: string;
          clientSecret: string;
          code: string;
          devicePublicKey?: { crv: "P-256"; kty: "EC"; x: string; y: string };
          endpoint: string;
          redirectUri: string;
          state: string;
        },
        {
          idToken: string;
          returnTo?: string;
          sessionId: string;
          sessionToken: string;
        },
        Name
      >;
      forgetWebhookDelivery: FunctionReference<
        "mutation",
        "internal",
        { bodyHash: string },
        null,
        Name
      >;
      hasActiveSessionForSubject: FunctionReference<
        "query",
        "internal",
        { subject: string },
        boolean,
        Name
      >;
      killSessionsBySid: FunctionReference<
        "mutation",
        "internal",
        { sid: string },
        number,
        Name
      >;
      killSubjectSessions: FunctionReference<
        "mutation",
        "internal",
        { subject: string },
        number,
        Name
      >;
      killSubjectSessionsByToken: FunctionReference<
        "mutation",
        "internal",
        { presentedHash: string },
        { count: number; idTokenHint: string; subject: string },
        Name
      >;
      recordWebhookDelivery: FunctionReference<
        "mutation",
        "internal",
        { bodyHash: string; now: number },
        boolean,
        Name
      >;
      refresh: FunctionReference<
        "action",
        "internal",
        {
          appId: string;
          clientSecret: string;
          deviceProof?: string;
          endpoint: string;
          reuseWindowMs?: number;
          sessionToken: string;
        },
        { idToken: string; sessionId: string; sessionToken: string },
        Name
      >;
      sessionValid: FunctionReference<
        "query",
        "internal",
        { sessionId: string },
        boolean,
        Name
      >;
      signOut: FunctionReference<
        "action",
        "internal",
        {
          appId: string;
          clientSecret: string;
          endpoint: string;
          federated?: boolean;
          postLogoutRedirectUri?: string;
          sessionToken: string;
        },
        { endSessionUrl?: string },
        Name
      >;
    };
  };
