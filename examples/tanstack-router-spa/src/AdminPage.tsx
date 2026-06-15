import { useQuery } from "convex/react";
import { Link } from "@tanstack/react-router";
import { api } from "../convex/_generated/api";

// Two layers of protection here:
//   - The `_authed` route guard already required a signed-in user (authn).
//   - This component mirrors the server's authz for a friendly screen, AND the
//     server enforces it independently: `adminStats` calls `requireRole`, so a
//     non-admin can't read the data even by calling the query directly.
export function AdminPage() {
  const profile = useQuery(api.users.myProfile);

  if (profile === undefined) return <p>Loading…</p>;
  if (profile === null) return <p>You are signed out.</p>;
  if (!profile.onboarded)
    return (
      <p>
        Finish onboarding on the <Link to="/dashboard">dashboard</Link> first.
      </p>
    );

  // Mirror the server's `requireRole` (active AND admin). Without the status check,
  // a suspended/deleted admin would render <AdminContent />, then `adminStats` would
  // throw "forbidden" under an admin header.
  if (profile.status !== "active")
    return (
      <section>
        <h1>Account {profile.status}</h1>
        <p>
          Your account is <code>{profile.status}</code>, so admin tools are
          unavailable.
        </p>
      </section>
    );

  if (profile.role !== "admin")
    return (
      <section>
        <h1>🚫 403 — Admins only</h1>
        <p>
          Your role is <code>{profile.role}</code>. This page requires{" "}
          <code>admin</code>.
        </p>
        <p>
          Go to the <Link to="/dashboard">dashboard</Link>, switch to{" "}
          <code>admin</code>, and come back.
        </p>
      </section>
    );

  return <AdminContent />;
}

function AdminContent() {
  // Reached only by active admins; the server agrees, so this resolves instead of throwing.
  const stats = useQuery(api.users.adminStats);
  return (
    <section>
      <h1>Admin area ✅</h1>
      <p>You're an active admin, so the server let `adminStats` through.</p>
      <pre>{stats ? JSON.stringify(stats, null, 2) : "loading…"}</pre>
    </section>
  );
}
