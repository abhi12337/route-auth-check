import { auth } from "@/auth";
import { prisma } from "@/lib/db";

export async function PUT(req: Request) {
  const session = await auth();
  if (!session?.user) return new Response("Unauthorized", { status: 401 });
  const { userId, displayName, bio } = await req.json();
  await prisma.profile.update({ where: { userId }, data: { displayName, bio } });
  return Response.json({ ok: true });
}
