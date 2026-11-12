import { auth } from "@clerk/nextjs/server";
import { prisma } from "@/lib/db";

export async function GET() {
  const { userId, has } = await auth();
  if (!userId) return new Response("Unauthorized", { status: 401 });
  if (!has({ role: "org:admin" })) return new Response("Forbidden", { status: 403 });
  const users = await prisma.user.findMany();
  return Response.json(users);
}
