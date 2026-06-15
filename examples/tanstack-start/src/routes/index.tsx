import { createFileRoute } from "@tanstack/react-router";
import { DeclarativeGate } from "../DeclarativeGate";

export const Route = createFileRoute("/")({
  component: Home,
});

function Home() {
  return (
    <section>
      <h1>convex-logto + TanStack Start</h1>
      <DeclarativeGate />
    </section>
  );
}
