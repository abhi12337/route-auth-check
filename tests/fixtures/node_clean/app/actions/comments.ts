"use server";

import { revalidatePath } from "next/cache";
import { auth } from "@/auth";
import { prisma } from "@/lib/db";

export async function createComment(postId: string, text: string) {
  const session = await auth();
  if (!session?.user) throw new Error("Unauthorized");
  await prisma.comment.create({ data: { postId, text, authorId: session.user.id } });
  revalidatePath(`/posts/${postId}`);
}

export async function deleteComment(commentId: string) {
  const session = await auth();
  if (!session?.user) throw new Error("Unauthorized");
  await prisma.comment.delete({ where: { id: commentId, authorId: session.user.id } });
  revalidatePath("/posts");
}

export async function updateSettings(theme: string, emailDigest: boolean) {
  const session = await auth();
  if (!session?.user) throw new Error("Unauthorized");
  await prisma.settings.update({ where: { userId: session.user.id }, data: { theme, emailDigest } });
}
