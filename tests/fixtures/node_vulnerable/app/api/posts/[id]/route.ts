import { getServerSession } from "next-auth";
import { authOptions } from "@/lib/auth";
import { prisma } from "@/lib/db";

type Ctx = { params: Promise<{ id: string }> };

export async function PATCH(req: Request, { params }: Ctx) {
  const session = await getServerSession(authOptions);
  if (!session) return new Response("Unauthorized", { status: 401 });
  const { id } = await params;
  const { title, content } = await req.json();
  const post = await prisma.post.update({ where: { id }, data: { title, content } });
  return Response.json(post);
}

export async function DELETE(req: Request, { params }: Ctx) {
  const session = await getServerSession(authOptions);
  if (!session) return new Response("Unauthorized", { status: 401 });
  const { id } = await params;
  await prisma.post.delete({ where: { id } });
  return new Response(null, { status: 204 });
}
