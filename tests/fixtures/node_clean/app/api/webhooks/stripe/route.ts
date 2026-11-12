import Stripe from "stripe";
import { prisma } from "@/lib/db";

const stripe = new Stripe(process.env.STRIPE_SECRET_KEY!);

export async function POST(req: Request) {
  const rawBody = await req.text();
  const sig = req.headers.get("stripe-signature")!;
  const event = await stripe.webhooks.constructEventAsync(rawBody, sig, process.env.STRIPE_WEBHOOK_SECRET!);
  if (event.type === "checkout.session.completed") {
    const s = event.data.object;
    await prisma.subscription.upsert({
      where: { id: s.id },
      create: { id: s.id, userId: s.metadata!.userId, status: "active" },
      update: { status: "active" },
    });
  }
  return new Response("ok");
}
