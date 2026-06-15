import type { Metadata } from "next";
import { Providers } from "./providers";

export const metadata: Metadata = {
  title: "convex-logto + Next.js",
  description: "Logto auth for Convex in the Next.js App Router",
};

// Stays a Server Component; it only renders the client <Providers> boundary.
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
