import { useQuery } from "convex/react";
import { api } from "../convex/_generated/api";

export function Dashboard() {
  const me = useQuery(api.me.me);
  return (
    <section>
      <h1>Dashboard (protected)</h1>
      <p>You only see this because the beforeLoad guard lets you through.</p>
      <pre>{me ? JSON.stringify(me, null, 2) : "loading identity…"}</pre>
    </section>
  );
}
