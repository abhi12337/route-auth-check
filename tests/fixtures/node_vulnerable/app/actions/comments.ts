"use server";

import { revalidatePath } from "next/cache";
import { auth } from "@/auth";
import { prisma } from "@/lib/db";

export async function createComment(postId: string, text: string) {
  await prisma.comment.create({ data: { postId, text } });
  revalidatePath(`/posts/${postId}`);
}

export async function deleteComment(commentId: string) {
  const session = await auth();
  if (!session?.user) throw new Error("Unauthorized");
  await prisma.comment.delete({ where: { id: commentId } });
  revalidatePath("/posts");
}

export async function updateSettings(userId: string, data: { theme: string; emailDigest: boolean }) {
  const session = await auth();
  if (!session?.user) throw new Error("Unauthorized");
  await prisma.settings.update({ where: { userId }, data });
}
