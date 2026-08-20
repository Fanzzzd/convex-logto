import type { Metadata } from "next";
import { cookies } from "next/headers";
import { readLogtoIdTokenCookie } from "convex-logto";
import { Providers } from "./providers";

export const metadata: Metadata = {
  title: "convex-logto + Next.js, session mode",
  description: "Server-held Logto refresh token, HttpOnly cookie transport, SSR",
};

// A Server Component. It reads the companion ID-token cookie — a read, not a
// rotation, which is the only thing a layout is allowed to do with a
// credential — and seeds the client provider so the first client render agrees
// with what the server already rendered.
export default async function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  const initialToken = readLogtoIdTokenCookie(await cookies());
  return (
    <html lang="en">
      <body>
        <Providers initialToken={initialToken ?? undefined}>
          {children}
        </Providers>
      </body>
    </html>
  );
}
