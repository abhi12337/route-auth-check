import Fastify from "fastify";
import { hash } from "bcryptjs";
import { prisma } from "./db";

const fastify = Fastify();

fastify.post("/api/signup", async (request, reply) => {
  const { email, password, role } = request.body as { email: string; password: string; role?: string };
  const user = await prisma.user.create({ data: { email, passwordHash: await hash(password, 12), role } });
  return reply.code(201).send({ id: user.id });
});

fastify.listen({ port: 3002 });
