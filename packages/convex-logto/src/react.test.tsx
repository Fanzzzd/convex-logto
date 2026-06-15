import { renderToString } from "react-dom/server";
import {
  Authenticated,
  AuthLoading,
  ConvexReactClient,
  Unauthenticated,
} from "convex/react";
import { describe, expect, it } from "vitest";
import { ConvexLogtoProvider } from "./react";
import type { LogtoConfigQueryRef } from "./config";

// The headline 0.2.0 guarantee: the provider is safe to render on the server.
// renderToString runs with no `window` and never runs effects, so config stays
// unresolved — children must mount under <AuthLoading> and nothing may throw.
describe("ConvexLogtoProvider SSR", () => {
  it("renders the loading branch on the server (no window) without throwing", () => {
    expect(typeof window).toBe("undefined");

    const client = new ConvexReactClient("https://example.convex.cloud");
    const configQuery = {} as unknown as LogtoConfigQueryRef;

    const html = renderToString(
      <ConvexLogtoProvider client={client} configQuery={configQuery}>
        <AuthLoading>LOADING_SHELL</AuthLoading>
        <Authenticated>AUTHED</Authenticated>
        <Unauthenticated>ANON</Unauthenticated>
      </ConvexLogtoProvider>,
    );

    expect(html).toContain("LOADING_SHELL");
    expect(html).not.toContain("AUTHED");
    expect(html).not.toContain("ANON");
  });
});
