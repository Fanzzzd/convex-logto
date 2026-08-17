import { defineApp } from "convex/server";
import logto from "convex-logto/convex.config";

const app = defineApp();
app.use(logto);
export default app;
