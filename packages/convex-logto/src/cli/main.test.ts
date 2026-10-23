import { describe, expect, it, vi } from "vitest";
import { main, type CliIo } from "./main";
import { JwksSyncError, type DeploymentEnv } from "./jwks-sync";

const key = (kid: string) => ({ kty: "RSA", n: `n-${kid}`, e: "AQAB", kid });

function harness(options: {
  vars?: Record<string, string>;
  serves?: unknown[];
  github?: boolean;
}) {
  const vars = new Map(
    Object.entries({
      LOGTO_ENDPOINT: "https://auth.example.com",
      ...options.vars,
    }),
  );
  const out: string[] = [];
  const err: string[] = [];
  const env = vi.fn(
    (_passthrough: string[], _defaults?: string): DeploymentEnv => ({
      get: async (name) => vars.get(name),
      set: async (name, value) => {
        vars.set(name, value);
      },
    }),
  );
  const io: CliIo = {
    out: (line) => out.push(line),
    err: (line) => err.push(line),
    env,
    fetch: (async () =>
      new Response(
        JSON.stringify({ keys: options.serves ?? [key("a")] }),
      )) as typeof globalThis.fetch,
    github: options.github,
  };
  return { io, out, err, env, vars };
}

describe("convex-logto CLI", () => {
  it("prints usage and exits 2 without a command, 0 with --help", async () => {
    const bare = harness({});
    expect(await main([], bare.io)).toBe(2);
    expect(bare.err.join("\n")).toMatch(/sync-jwks/);
    expect(await main(["sync-jwks", "--help"], harness({}).io)).toBe(0);
  });

  it("rejects an unknown command with exit 2", async () => {
    const h = harness({});
    expect(await main(["sync"], h.io)).toBe(2);
    expect(h.err.join("\n")).toMatch(/Unknown command "sync"/);
  });

  it("passes every option but its own through to convex env", async () => {
    const h = harness({ vars: { LOGTO_ENDPOINT: "http://logto.internal" } });
    const code = await main(
      ["sync-jwks", "--prod", "--allow-insecure-http", "--env-file", ".env"],
      h.io,
    );
    expect(code).toBe(0);
    expect(h.env).toHaveBeenCalledWith(
      ["--prod", "--env-file", ".env"],
      undefined,
    );
    expect(h.out.join("\n")).toMatch(/LOGTO_JWKS set from .*\(a\)/);
  });

  it("check-jwks exits 1 with a GitHub annotation when a key is missing", async () => {
    const h = harness({
      vars: { LOGTO_JWKS: JSON.stringify({ keys: [key("old")] }) },
      serves: [key("new")],
      github: true,
    });
    expect(await main(["check-jwks", "--prod"], h.io)).toBe(1);
    expect(h.err).toEqual([
      expect.stringMatching(/^::warning::.*old/),
      expect.stringMatching(
        /^::error::Logto serves new, which LOGTO_JWKS lacks.*sync-jwks --prod$/,
      ),
    ]);
  });

  it("never echoes an admin key back", async () => {
    const h = harness({
      vars: { LOGTO_JWKS: JSON.stringify({ keys: [key("old")] }) },
      serves: [key("new")],
    });
    const code = await main(
      [
        "check-jwks",
        "--url",
        "https://x.convex.cloud",
        "--admin-key",
        "secret-1",
        "--admin-key=secret-2",
      ],
      h.io,
    );
    expect(code).toBe(1);
    expect(h.err.join("\n")).not.toMatch(/secret/);
    expect(h.err.join("\n")).toMatch(
      /--admin-key <admin key> --admin-key=<admin key>$/,
    );
  });

  it("takes --endpoint instead of the deployment's LOGTO_ENDPOINT", async () => {
    const h = harness({ vars: {} });
    h.vars.delete("LOGTO_ENDPOINT");
    const seen: string[] = [];
    h.io.fetch = (async (url: string | URL | Request) => {
      seen.push(String(url));
      return new Response(JSON.stringify({ keys: [key("a")] }));
    }) as typeof globalThis.fetch;
    expect(
      await main(["sync-jwks", "--endpoint=https://id.example.com/"], h.io),
    ).toBe(0);
    expect(seen).toEqual(["https://id.example.com/oidc/jwks"]);
    expect(h.env).toHaveBeenCalledWith([], undefined);
  });

  it("passes --defaults to the env and names it in the output", async () => {
    const h = harness({});
    expect(await main(["sync-jwks", "--defaults", "preview"], h.io)).toBe(0);
    expect(h.env).toHaveBeenCalledWith([], "preview");
    expect(h.out.join("\n")).toMatch(/the preview default LOGTO_JWKS set/);
  });

  it.each([
    [["sync-jwks", "--defaults", "staging"], /dev, preview or prod/],
    [["sync-jwks", "--endpoint"], /--endpoint needs a value/],
    [["check-jwks", "--defaults", "--prod"], /--defaults needs a value/],
  ])("exits 2 on a bad option: %j", async (argv, message) => {
    const h = harness({});
    expect(await main(argv, h.io)).toBe(2);
    expect(h.err.join("\n")).toMatch(message);
    expect(h.env).not.toHaveBeenCalled();
  });

  it("warns about an unusable staged next key, and only notes a previous one", async () => {
    const ec = (kid: string) => ({
      kty: "EC",
      crv: "P-384",
      x: "x",
      y: "y",
      kid,
    });
    const stored = { LOGTO_JWKS: JSON.stringify({ keys: [key("a")] }) };
    const staged = harness({
      vars: { LOGTO_JWKS: JSON.stringify({ keys: [key("a"), key("prev")] }) },
      serves: [key("a"), ec("next"), key("prev")],
    });
    expect(await main(["check-jwks"], staged.io)).toBe(0);
    expect(staged.err.join("\n")).toMatch(
      /staged next \(EC\) as its next signing key/,
    );

    const afterRotation = harness({
      vars: stored,
      serves: [key("a"), ec("old")],
    });
    expect(await main(["check-jwks"], afterRotation.io)).toBe(0);
    expect(afterRotation.err).toEqual([]);
    expect(afterRotation.out.join("\n")).toMatch(/also serves old \(EC\)/);
  });

  it("encodes a multi-line error as one GitHub annotation", async () => {
    const h = harness({ github: true });
    h.io.env = () => ({
      get: () => Promise.reject(new JwksSyncError("line one\nline two")),
      set: () => Promise.resolve(),
    });
    expect(await main(["check-jwks"], h.io)).toBe(1);
    expect(h.err).toEqual(["::error::line one%0Aline two"]);
  });

  it("check-jwks exits 0 when LOGTO_JWKS is current", async () => {
    const h = harness({
      vars: { LOGTO_JWKS: JSON.stringify({ keys: [key("a")] }) },
    });
    expect(await main(["check-jwks"], h.io)).toBe(0);
    expect(h.err).toEqual([]);
  });

  it("reports a sync failure as one line and exit 1", async () => {
    const h = harness({ vars: {}, serves: [] });
    h.vars.delete("LOGTO_ENDPOINT");
    expect(await main(["sync-jwks"], h.io)).toBe(1);
    expect(h.err).toEqual([
      expect.stringMatching(/^convex-logto: LOGTO_ENDPOINT is not set/),
    ]);
  });
});
