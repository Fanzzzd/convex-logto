import type { Metadata } from "next";
import { Providers } from "./providers";

export const metadata: Metadata = {
  title: "convex-logto + Next.js, session mode",
  description: "Server-held Logto refresh token, HttpOnly cookie transport, SSR",
};

// Stays a Server Component; it only renders the client <Providers> boundary.
// `app/page.tsx` reads the identity where it is used, rather than this layout,
// so this layout does not force dynamic rendering on a route that does not need
// it.
export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en">
      <body>
        <Providers>{children}</Providers>
      </body>
    </html>
  );
}
