import { prisma } from "@/lib/db";

export async function GET() {
  const posts = await prisma.post.findMany({ where: { published: true } });
  return Response.json(posts);
}

export async function POST(req: Request) {
  const body = await req.json();
  const post = await prisma.post.create({ data: body });
  return Response.json(post, { status: 201 });
}
