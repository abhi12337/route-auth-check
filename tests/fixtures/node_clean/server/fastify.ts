import Fastify from "fastify";
import fastifyJwt from "@fastify/jwt";
import { hash } from "bcryptjs";
import { prisma } from "./db";

const fastify = Fastify();
fastify.register(fastifyJwt, { secret: process.env.JWT_SECRET! });

fastify.post("/api/signup", async (request, reply) => {
  const { email, password } = request.body as { email: string; password: string };
  const user = await prisma.user.create({ data: { email, passwordHash: await hash(password, 12), role: "member" } });
  return reply.code(201).send({ id: user.id });
});

fastify.delete("/api/sessions/:id", { onRequest: [fastify.authenticate] }, async (request, reply) => {
  const { id } = request.params as { id: string };
  await prisma.session.deleteMany({ where: { id, userId: request.user.id } });
  return reply.code(204).send();
});

fastify.listen({ port: 3002 });
