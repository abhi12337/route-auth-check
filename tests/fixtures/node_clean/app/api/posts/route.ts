import { z } from "zod";
import { auth } from "@/auth";
import { prisma } from "@/lib/db";

const PostInput = z.object({ title: z.string().max(200), content: z.string() });

export async function GET() {
  const posts = await prisma.post.findMany({ where: { published: true } });
  return Response.json(posts);
}

export async function POST(req: Request) {
  const session = await auth();
  if (!session?.user) return new Response("Unauthorized", { status: 401 });
  const data = PostInput.parse(await req.json());
  const post = await prisma.post.create({ data: { ...data, authorId: session.user.id } });
  return Response.json(post, { status: 201 });
}
