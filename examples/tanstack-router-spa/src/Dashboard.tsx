import { useState } from "react";
import { useMutation, useQuery } from "convex/react";
import { Link } from "@tanstack/react-router";
import { api } from "../convex/_generated/api";

type Role = "user" | "admin";

export function Dashboard() {
  const profile = useQuery(api.users.myProfile);
  const completeOnboarding = useMutation(api.users.completeOnboarding);
  const setMyRole = useMutation(api.users.setMyRole);

  if (profile === undefined) return <p>Loading…</p>;
  // We're inside the `_authed` guard, so signed-out is unreachable in practice.
  if (profile === null) return <p>You are signed out.</p>;

  // First login: the row doesn't exist yet. The form creates it with the chosen role.
  if (!profile.onboarded)
    return <Onboarding onSubmit={(role) => completeOnboarding({ role })} />;

  if (profile.status !== "active")
    return <InactiveNotice status={profile.status} />;

  return (
    <section>
      <h1>Dashboard (protected)</h1>
      <p>
        Signed in as{" "}
        <strong>{profile.name ?? profile.email ?? "your account"}</strong> — role{" "}
        <RoleBadge role={profile.role} />, status <code>{profile.status}</code>.
      </p>
      <p>
        <Link to="/admin">Open the Admin area →</Link> (only <code>admin</code> may
        enter)
      </p>
      <RoleSwitcher
        role={profile.role}
        onSwitch={(role) => setMyRole({ role })}
      />
    </section>
  );
}

function Onboarding({
  onSubmit,
}: {
  onSubmit: (role: Role) => Promise<unknown>;
}) {
  const [role, setRole] = useState<Role>("user");
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);

  return (
    <section>
      <h1>Welcome 👋</h1>
      <p>Pick a role to finish setting up your account:</p>
      <form
        onSubmit={async (e) => {
          e.preventDefault();
          setSaving(true);
          setError(null);
          try {
            await onSubmit(role);
            // On success the query swaps this component out — nothing to reset.
          } catch (err) {
            setError(err instanceof Error ? err.message : String(err));
            setSaving(false);
          }
        }}
        style={{ display: "grid", gap: 8, maxWidth: 320 }}
      >
        <label>
          <input
            type="radio"
            name="role"
            checked={role === "user"}
            onChange={() => setRole("user")}
          />{" "}
          User (normal access)
        </label>
        <label>
          <input
            type="radio"
            name="role"
            checked={role === "admin"}
            onChange={() => setRole("admin")}
          />{" "}
          Admin (can open the Admin area)
        </label>
        <button type="submit" disabled={saving} style={{ marginTop: 8 }}>
          {saving ? "Creating…" : "Create my account"}
        </button>
        {error && (
          <p style={{ color: "#b30000" }}>Couldn't create account: {error}</p>
        )}
      </form>
      <p style={{ color: "#888", fontSize: 13, marginTop: 12 }}>
        Demo only — real apps create everyone as <code>user</code> and grant admin
        server-side.
      </p>
    </section>
  );
}

function RoleSwitcher({
  role,
  onSwitch,
}: {
  role: Role;
  onSwitch: (role: Role) => Promise<unknown>;
}) {
  const [error, setError] = useState<string | null>(null);
  const switchTo = async (next: Role) => {
    setError(null);
    try {
      await onSwitch(next);
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    }
  };

  return (
    <fieldset
      style={{ marginTop: 16, border: "1px solid #ddd", borderRadius: 8 }}
    >
      <legend>Switch role (demo)</legend>
      <p style={{ color: "#888", fontSize: 13, margin: "4px 0 12px" }}>
        Flip your role, then revisit the Admin area to watch the gate allow / deny.
      </p>
      <div style={{ display: "flex", gap: 12 }}>
        <button
          type="button"
          disabled={role === "user"}
          onClick={() => void switchTo("user")}
        >
          Become user
        </button>
        <button
          type="button"
          disabled={role === "admin"}
          onClick={() => void switchTo("admin")}
        >
          Become admin
        </button>
      </div>
      {error && <p style={{ color: "#b30000" }}>Couldn't switch role: {error}</p>}
    </fieldset>
  );
}

function InactiveNotice({ status }: { status: "suspended" | "deleted" }) {
  return (
    <section>
      <h1>Account {status}</h1>
      <p>
        Your account is <code>{status}</code>, so the app is unavailable. (Set in
        Logto, synced here by the webhook.)
      </p>
    </section>
  );
}

function RoleBadge({ role }: { role: Role }) {
  return (
    <code style={{ color: role === "admin" ? "#b30000" : "#333" }}>{role}</code>
  );
}
