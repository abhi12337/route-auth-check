import { Hono } from "hono";
import { jwt } from "hono/jwt";
import { and, eq } from "drizzle-orm";
import { db } from "./db";
import { projects } from "./schema";

const app = new Hono();

app.use("/api/*", jwt({ secret: process.env.JWT_SECRET!, alg: "HS256" }));

app.delete("/api/projects/:id", async (c) => {
  const id = c.req.param("id");
  const { sub } = c.get("jwtPayload");
  await db.delete(projects).where(and(eq(projects.id, id), eq(projects.ownerId, sub)));
  return c.json({ ok: true });
});

export default app;
