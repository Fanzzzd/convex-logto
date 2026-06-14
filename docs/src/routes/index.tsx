import { createFileRoute, Link } from "@tanstack/react-router";
import { HomeLayout } from "fumadocs-ui/layouts/home";
import { ArrowRight, Github, Package } from "lucide-react";
import { baseOptions } from "@/lib/layout.shared";

export const Route = createFileRoute("/")({
  component: Home,
});

const GITHUB_URL = "https://github.com/Fanzzzd/convex-logto";
const NPM_URL = "https://www.npmjs.com/package/convex-logto";

function Home() {
  return (
    <HomeLayout {...baseOptions()}>
      <main className="flex flex-1 flex-col items-center justify-center px-6 py-24 text-center">
        <span className="mb-6 rounded-full border border-fd-border px-4 py-1.5 text-sm text-fd-muted-foreground">
          Logto auth for Convex, the easy way
        </span>

        <h1 className="font-mono text-5xl font-bold tracking-tight sm:text-6xl">
          convex-logto
        </h1>

        <p className="mt-6 max-w-2xl text-lg text-fd-muted-foreground">
          Logto auth for Convex React apps — with the least setup. One provider
          on the frontend, one line on the backend, one source of truth across
          environments.
        </p>

        <div className="mt-10 w-full max-w-md">
          <pre className="overflow-x-auto rounded-xl border border-fd-border bg-fd-secondary/40 px-5 py-4 text-left font-mono text-sm">
            <code>
              <span className="text-fd-muted-foreground select-none">$ </span>
              npm i convex-logto
            </code>
          </pre>
        </div>

        <div className="mt-10 flex flex-wrap items-center justify-center gap-3">
          <Link
            to="/docs/$"
            params={{ _splat: "" }}
            className="inline-flex items-center gap-2 rounded-lg bg-fd-primary px-5 py-2.5 text-sm font-medium text-fd-primary-foreground transition-opacity hover:opacity-90"
          >
            Read the docs
            <ArrowRight className="size-4" />
          </Link>
          <a
            href={GITHUB_URL}
            target="_blank"
            rel="noreferrer"
            className="inline-flex items-center gap-2 rounded-lg border border-fd-border px-5 py-2.5 text-sm font-medium transition-colors hover:bg-fd-accent"
          >
            <Github className="size-4" />
            GitHub
          </a>
          <a
            href={NPM_URL}
            target="_blank"
            rel="noreferrer"
            className="inline-flex items-center gap-2 rounded-lg border border-fd-border px-5 py-2.5 text-sm font-medium transition-colors hover:bg-fd-accent"
          >
            <Package className="size-4" />
            npm
          </a>
        </div>

        <p className="mt-16 max-w-xl text-sm text-fd-muted-foreground">
          Uses Logto&apos;s ID token over OIDC, so Convex auto-discovers the
          signing key and algorithm. There is nothing about JWTs for you to
          configure.
        </p>
      </main>
    </HomeLayout>
  );
}
