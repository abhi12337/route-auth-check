import { hash } from "bcryptjs";
import { z } from "zod";
import { prisma } from "@/lib/db";

const Signup = z.object({ email: z.string().email(), password: z.string().min(12) });

export async function POST(req: Request) {
  const { email, password } = Signup.parse(await req.json());
  const user = await prisma.user.create({ data: { email, passwordHash: await hash(password, 12), role: "member" } });
  return Response.json({ id: user.id }, { status: 201 });
}
