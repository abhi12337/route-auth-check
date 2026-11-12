import { Hono } from "hono";
import { eq } from "drizzle-orm";
import { db } from "./db";
import { projects } from "./schema";

const app = new Hono();

app.delete("/api/projects/:id", async (c) => {
  const id = c.req.param("id");
  await db.delete(projects).where(eq(projects.id, id));
  return c.json({ ok: true });
});

export default app;
