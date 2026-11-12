// NextAuth v5 middleware: protects pages, but the matcher skips every /api route.
export { auth as middleware } from "@/auth";

export const config = {
  matcher: ["/((?!api|_next/static|_next/image|favicon.ico).*)"],
};
