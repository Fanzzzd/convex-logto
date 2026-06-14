import type { BaseLayoutProps } from "fumadocs-ui/layouts/shared";

const GITHUB_URL = "https://github.com/Fanzzzd/convex-logto";

export function baseOptions(): BaseLayoutProps {
  return {
    nav: {
      title: (
        <span className="font-mono font-semibold tracking-tight">
          convex-logto
        </span>
      ),
    },
    githubUrl: GITHUB_URL,
    links: [
      {
        text: "Docs",
        url: "/docs",
        active: "nested-url",
      },
      {
        text: "npm",
        url: "https://www.npmjs.com/package/convex-logto",
        external: true,
      },
    ],
  };
}
