import { cronJobs } from "convex/server";
import { internal } from "./_generated/api.js";

// Daily sweep of expired sign-in transactions and dead sessions (idle past
// Logto's 180-day grant cap). Zero app configuration — the cron ships with the
// component, following the official action-retrier/action-cache precedent.
const crons = cronJobs();
crons.interval(
  "gc expired transactions and dead sessions",
  { hours: 24 },
  internal.lib.gc,
  {},
);
export default crons;
