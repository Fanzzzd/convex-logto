import { describe, expect, it, vi } from "vitest";
import { main, type CliIo } from "./main";
import type { DeploymentEnv } from "./jwks-sync";

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
  const env = vi.fn((_passthrough: string[]): DeploymentEnv => ({
    get: async (name) => vars.get(name),
    set: async (name, value) => {
      vars.set(name, value);
    },
  }));
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
    expect(bare.out.join("\n")).toMatch(/sync-jwks/);
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
    expect(h.env).toHaveBeenCalledWith(["--prod", "--env-file", ".env"]);
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
