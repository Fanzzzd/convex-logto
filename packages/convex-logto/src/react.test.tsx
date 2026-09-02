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

// The provider is safe to render on the server. renderToString runs with no
// `window` and never runs effects, and nothing in the render path may touch
// browser APIs. Real @logto/react + convex/react, no mocks, so a regression
// in either dependency's SSR behavior fails here too.
describe("ConvexLogtoProvider SSR", () => {
  it("static config: children render under <AuthLoading> without throwing", () => {
    expect(typeof window).toBe("undefined");

    const client = new ConvexReactClient("https://example.convex.cloud");

    const html = renderToString(
      <ConvexLogtoProvider
        client={client}
        config={{ endpoint: "https://example.logto.app", appId: "app123" }}
      >
        <AuthLoading>LOADING_SHELL</AuthLoading>
        <Authenticated>AUTHED</Authenticated>
        <Unauthenticated>ANON</Unauthenticated>
      </ConvexLogtoProvider>,
    );

    expect(html).toContain("LOADING_SHELL");
    expect(html).not.toContain("AUTHED");
    expect(html).not.toContain("ANON");
  });

  it("configQuery: renders the fallback on the server (config unresolved, no effects)", () => {
    const client = new ConvexReactClient("https://example.convex.cloud");
    const configQuery = {} as unknown as LogtoConfigQueryRef;

    const html = renderToString(
      <ConvexLogtoProvider
        client={client}
        configQuery={configQuery}
        fallback={<span>SPLASH</span>}
      >
        <AuthLoading>LOADING_SHELL</AuthLoading>
        <Authenticated>AUTHED</Authenticated>
        <Unauthenticated>ANON</Unauthenticated>
      </ConvexLogtoProvider>,
    );

    expect(html).toContain("SPLASH");
    expect(html).not.toContain("LOADING_SHELL");
    expect(html).not.toContain("AUTHED");
  });
});
