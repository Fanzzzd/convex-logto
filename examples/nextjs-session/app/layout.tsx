import type { Metadata } from "next";
import { Providers } from "./providers";

export const metadata: Metadata = {
  title: "convex-logto + Next.js, session mode",
  description: "Server-held Logto refresh token, HttpOnly cookie transport, SSR",
};

// Stays a Server Component; it only renders the client <Providers> boundary.
// The identity is read where it is used — in `app/page.tsx` — rather than here,
// so a route that does not need it is not forced dynamic by this layout.
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
