"use client";

// `convex-logto/react`, `@logto/react`, and `ConvexReactClient` are client-only
// (React hooks + `window`), so the provider lives in a "use client" component.
import { ConvexReactClient } from "convex/react";
import { ConvexLogtoProvider } from "convex-logto/react";
import { useRouter } from "next/navigation";
import { api } from "../convex/_generated/api";

// Created once on the client — never recreated across renders.
const convex = new ConvexReactClient(process.env.NEXT_PUBLIC_CONVEX_URL!);

export function Providers({ children }: { children: React.ReactNode }) {
  const router = useRouter();
  return (
    <ConvexLogtoProvider
      client={convex}
      configQuery={api.logto.config}
      // Soft navigation after sign-in instead of a full page reload.
      navigate={(to) => router.push(to)}
    >
      {children}
    </ConvexLogtoProvider>
  );
}
