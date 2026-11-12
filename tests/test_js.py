"""Node / TypeScript: true positives, and correctly protected code that must stay quiet."""

from pathlib import Path

from conftest import route, rules
from route_auth_check.js_scan import _match
from route_auth_check.scanner import scan_path

FIX = Path(__file__).parent / "fixtures"


# ---------------------------------------------------------------- fixtures
def test_vulnerable_fixture_exact_findings():
    res = scan_path(str(FIX / "node_vulnerable"))
    got = sorted((f.rule_id, f.file, f.line, f.severity) for f in res.findings)
    assert got == sorted([
        ("RAC001", "app/api/posts/route.ts", 8, "high"),
        ("RAC008", "app/api/posts/route.ts", 10, "medium"),
        ("RAC002", "app/api/posts/[id]/route.ts", 12, "high"),
        ("RAC002", "app/api/posts/[id]/route.ts", 20, "high"),
        ("RAC005", "app/api/admin/users/route.ts", 4, "high"),
        ("RAC006", "app/api/profile/route.ts", 7, "high"),
        ("RAC003", "app/actions/comments.ts", 7, "high"),
        ("RAC002", "app/actions/comments.ts", 15, "high"),
        ("RAC006", "app/actions/comments.ts", 19, "high"),
        ("RAC008", "app/actions/comments.ts", 22, "medium"),
        ("RAC004", "middleware.ts", 5, "medium"),
        ("RAC007", "server/express.ts", 9, "medium"),
        ("RAC001", "server/express.ts", 18, "high"),
        ("RAC008", "server/express.ts", 19, "medium"),
        ("RAC002", "server/express.ts", 24, "high"),
        ("RAC005", "server/express.ts", 28, "high"),
        ("RAC006", "server/express.ts", 34, "high"),
        ("RAC001", "server/routes/invoices.ts", 7, "high"),
        ("RAC001", "server/hono.ts", 8, "high"),
        ("RAC006", "server/fastify.ts", 8, "high"),
    ])


def test_clean_fixture_no_findings_and_every_route_classified():
    res = scan_path(str(FIX / "node_clean"))
    assert res.findings == []
    status = {r.label: r.status for r in res.routes}
    assert len(res.routes) == 24
    assert "unprotected" not in status.values() and "unknown" not in status.values()
    assert status["POST /api/webhooks/stripe"] == "public"
    assert status["POST /api/auth/login"] == "public"            # mounted at /api/auth from another file
    assert status["DELETE /api/invoices/:id"] == "protected"     # app.use("/api/invoices", requireAuth, router)


def test_frameworks_and_cross_file_paths():
    res = scan_path(str(FIX / "node_vulnerable"))
    fw = {r.label: r.framework for r in res.routes}
    assert fw["POST /api/posts"] == "next-app"
    assert fw["server action createComment()"] == "server-action"
    assert fw["POST /api/orders"] == "express"
    assert fw["DELETE /api/projects/:id"] == "hono"
    assert fw["POST /api/signup"] == "fastify"
    assert "DELETE /api/invoices/:id" in fw                      # router prefix applied across files


# ---------------------------------------------------------------- RAC001
def test_next_route_without_auth(scan):
    res = scan({"app/api/items/route.ts": """
export async function POST(req: Request) {
  const { name } = await req.json();
  await db.item.create({ data: { name } });
  return Response.json({ ok: true });
}
export async function GET() { return Response.json(await db.item.findMany()); }
"""})
    assert rules(res) == ["RAC001"]
    assert route(res, "GET /api/items").status == "public"


def test_auth_variants_are_recognised(scan):
    variants = {
        "nextauth": "const session = await getServerSession(authOptions); if (!session) return new Response(null, { status: 401 });",
        "clerk": "const { userId } = await auth(); if (!userId) return new Response(null, { status: 401 });",
        "supabase": "const { data: { user } } = await supabase.auth.getUser(); if (!user) return new Response(null, { status: 401 });",
        "custom": "const user = await requireUser(req);",
        "header": 'if (req.headers.get("authorization") !== `Bearer ${process.env.CRON_SECRET}`) return new Response(null, { status: 401 });',
    }
    for name, check in variants.items():
        res = scan({f"app/api/{name}/route.ts": f"""
export async function POST(req: Request) {{
  {check}
  await db.item.create({{ data: {{ name: "x" }} }});
  return Response.json({{ ok: true }});
}}
"""})
        assert rules(res) == [], name


def test_benign_wrapper_does_not_hide_missing_auth(scan):
    res = scan({"app/api/items/route.ts": """
export const POST = withErrorHandler(async (req: Request) => {
  await db.item.create({ data: { name: "x" } });
  return Response.json({ ok: true });
});
"""})
    assert rules(res) == ["RAC001"]


def test_auth_wrapper_and_unknown_wrapper(scan):
    res = scan({"app/api/a/route.ts": "export const POST = withAuth(async (req) => { await db.x.create({ data: {} }); });",
                "app/api/b/route.ts": "export const POST = withTenant(async (req) => { await db.x.create({ data: {} }); });"})
    assert rules(res) == []
    assert route(res, "POST /api/b").status == "unknown"


def test_public_by_design_routes_are_skipped(scan):
    files = {f"app/api/{p}/route.ts": "export async function POST(req: Request) { await db.x.create({ data: {} }); }"
             for p in ("auth/[...nextauth]", "webhooks/clerk", "login", "sign-up", "health", "newsletter",
                       "forgot-password", "cron/sync")}
    res = scan(files)
    assert [f.file for f in res.findings] == ["app/api/cron/sync/route.ts"]


def test_express_router_level_and_mount_auth(scan):
    res = scan({
        "server/app.js": """
const express = require("express");
const { protect } = require("./auth");
const posts = require("./routes/posts");
const open = require("./routes/open");
const app = express();
app.use("/api/posts", protect, posts);
app.use("/api/open", open);
""",
        "server/routes/posts.js": """
const router = require("express").Router();
router.post("/", async (req, res) => { await Post.create({ title: req.body.title, user: req.user.id }); });
module.exports = router;
""",
        "server/routes/open.js": """
const router = require("express").Router();
router.post("/", async (req, res) => { await Thing.create({ title: req.body.title }); });
module.exports = router;
""",
    })
    assert [(f.rule_id, f.file) for f in res.findings] == [("RAC001", "server/routes/open.js")]
    assert route(res, "POST /api/posts").status == "protected"


def test_express_order_matters_for_app_use(scan):
    res = scan({"server.js": """
const app = require("express")();
app.post("/api/before", async (req, res) => { await Item.create({ name: "x" }); });
app.use(requireAuth);
app.post("/api/after", async (req, res) => { await Item.create({ name: "x" }); });
"""})
    assert [r.label for r in res.routes if r.status == "unprotected"] == ["POST /api/before"]


def test_validation_middleware_is_not_auth_but_unknown_middleware_is_opaque(scan):
    res = scan({"server.js": """
const app = require("express")();
app.post("/api/a", validate(schema), async (req, res) => { await Item.create({ name: "x" }); });
app.post("/api/b", tenantScope, async (req, res) => { await Item.create({ name: "x" }); });
"""})
    assert [(f.rule_id, f.line) for f in res.findings] == [("RAC001", 3)]
    assert route(res, "POST /api/b").status == "unknown"


def test_hono_scoped_middleware(scan):
    res = scan({"src/index.ts": """
import { Hono } from "hono";
import { jwt } from "hono/jwt";
const app = new Hono();
app.use("/api/*", jwt({ secret: process.env.JWT_SECRET!, alg: "HS256" }));
app.post("/api/todos", async (c) => { await db.insert(todos).values({ title: "x" }); return c.text("ok"); });
app.post("/v2/todos", async (c) => { await db.insert(todos).values({ title: "x" }); return c.text("ok"); });
"""})
    assert [(f.rule_id, f.line) for f in res.findings] == [("RAC001", 7)]


def test_clerk_middleware_alone_does_not_protect_express(scan):
    res = scan({"server.ts": """
import express from "express";
import { clerkMiddleware } from "@clerk/express";
const app = express();
app.use(clerkMiddleware());
app.post("/api/items", async (req, res) => { await Item.create({ name: "x" }); });
"""})
    assert rules(res) == ["RAC001"]


def test_fastify_hooks_and_route_options(scan):
    res = scan({"server.ts": """
import Fastify from "fastify";
const fastify = Fastify();
fastify.post("/a", { preHandler: [fastify.authenticate] }, async (request) => { await db.x.create({ data: {} }); });
fastify.post("/b", async (request) => { await db.x.create({ data: {} }); });
fastify.route({ method: "DELETE", url: "/c", handler: async (request) => { await db.x.delete({ where: { id: 1 } }); } });
"""})
    assert sorted(f.line for f in res.findings) == [5, 6]


def test_custom_auth_fn_flag(scan):
    files = {"app/api/items/route.ts": """
export async function POST(req: Request) {
  const me = await whoAmI();
  await db.item.create({ data: { name: "x", ownerId: me.id } });
}
"""}
    assert rules(scan(files)) == ["RAC001"]
    assert rules(scan(files, auth_fns=["whoAmI"])) == []


# ---------------------------------------------------------------- RAC002
def test_idor_prisma_read_with_auth(scan):
    res = scan({"app/api/invoices/[id]/route.ts": """
export async function GET(req: Request, { params }: { params: { id: string } }) {
  const session = await auth();
  if (!session) return new Response(null, { status: 401 });
  const invoice = await prisma.invoice.findUnique({ where: { id: params.id } });
  return Response.json(invoice);
}
"""})
    assert rules(res) == ["RAC002"]
    f = res.findings[0]
    assert f.line == 5 and "reads invoice" in f.message
    assert "findFirst" in f.fix and "userId: session.user.id" in f.fix


def test_idor_not_reported_when_owner_checked(scan):
    for body in (
        "const inv = await prisma.invoice.findUnique({ where: { id: params.id } });\n"
        "  if (inv?.userId !== session.user.id) return new Response(null, { status: 404 });",
        "const inv = await prisma.invoice.findFirst({ where: { id: params.id, userId: session.user.id } });",
        "const inv = await prisma.invoice.findUnique({ where: { id: params.id } });\n"
        "  if (!canView(session.user, inv)) return new Response(null, { status: 403 });",
    ):
        res = scan({"app/api/invoices/[id]/route.ts": f"""
export async function GET(req: Request, {{ params }}: {{ params: {{ id: string }} }}) {{
  const session = await auth();
  if (!session) return new Response(null, {{ status: 401 }});
  {body}
  return Response.json(inv);
}}
"""})
        assert rules(res) == [], body


def test_idor_drizzle_mongoose_sequelize(scan):
    res = scan({"server.ts": """
import express from "express";
const app = express();
app.delete("/a/:id", requireAuth, async (req, res) => { await db.delete(posts).where(eq(posts.id, req.params.id)); });
app.get("/b/:id", requireAuth, async (req, res) => { res.json(await Post.findById(req.params.id)); });
app.get("/c/:id", requireAuth, async (req, res) => { res.json(await Post.findByPk(req.params.id)); });
app.put("/d/:id", requireAuth, async (req, res) => { await Post.update({ title: "x" }, { where: { id: req.params.id } }); });
app.delete("/e/:id", requireAuth, async (req, res) => {
  await db.delete(posts).where(and(eq(posts.id, req.params.id), eq(posts.userId, req.user.id)));
});
"""})
    assert sorted((f.rule_id, f.line, f.extra["orm"]) for f in res.findings) == [
        ("RAC002", 4, "drizzle"), ("RAC002", 5, "mongoose"), ("RAC002", 6, "sequelize"), ("RAC002", 7, "sequelize")]


def test_supabase_user_client_relies_on_rls_but_admin_client_does_not(scan):
    tmpl = """
export async function DELETE(req: Request, {{ params }}: {{ params: {{ id: string }} }}) {{
  const {{ data: {{ user }} }} = await supabase.auth.getUser();
  if (!user) return new Response(null, {{ status: 401 }});
  const db = {client};
  await db.from("todos").delete().eq("id", params.id);
}}
"""
    assert rules(scan({"app/api/todos/[id]/route.ts": tmpl.format(client="await createClient()")})) == []
    res = scan({"app/api/todos/[id]/route.ts": tmpl.format(client="createAdminClient()")})
    assert rules(res) == ["RAC002"] and res.findings[0].extra["orm"] == "supabase-admin"


# ---------------------------------------------------------------- RAC003
def test_server_actions(scan):
    res = scan({"app/actions.ts": """
"use server";
export async function getPosts() { return prisma.post.findMany(); }
export async function archive(id: string) { await prisma.post.update({ where: { id }, data: { archived: true } }); }
export const remove = async (id: string) => { await prisma.post.delete({ where: { id } }); };
export async function signUp(formData: FormData) { await prisma.user.create({ data: { email: String(formData.get("email")) } }); }
""", "app/page.tsx": """
export default function Page() {
  async function inline(formData: FormData) {
    "use server";
    await prisma.note.create({ data: { text: String(formData.get("text")) } });
  }
  return null;
}
"""})
    assert sorted((f.rule_id, f.file, f.line) for f in res.findings) == [
        ("RAC003", "app/actions.ts", 4), ("RAC003", "app/actions.ts", 5), ("RAC003", "app/page.tsx", 3)]


def test_server_action_with_authenticated_client(scan):
    res = scan({"app/actions.ts": """
"use server";
export const archive = authActionClient.schema(Input).action(async ({ parsedInput: { id }, ctx }) => {
  await prisma.post.update({ where: { id, authorId: ctx.userId }, data: { archived: true } });
});
"""})
    assert rules(res) == []


# ---------------------------------------------------------------- RAC004
def test_matcher_conversion():
    assert not _match("/((?!api|_next/static|_next/image|favicon.ico).*)", "/api/posts")
    assert _match("/((?!api|_next/static|_next/image|favicon.ico).*)", "/dashboard")
    assert _match("/dashboard/:path*", "/dashboard") and _match("/dashboard/:path*", "/dashboard/a/b")
    assert not _match("/dashboard/:path*", "/api/x")
    assert _match("/(api|trpc)(.*)", "/api/posts/1")
    assert _match("/sign-in(.*)", "/sign-in/sso-callback")


def test_middleware_matcher_misses_api(scan):
    res = scan({
        "middleware.ts": 'export { default } from "next-auth/middleware";\nexport const config = { matcher: ["/dashboard/:path*"] };\n',
        "app/api/items/route.ts": "export async function POST() { await db.x.create({ data: {} }); }",
        "app/dashboard/items/route.ts": "export async function POST() { await db.x.create({ data: {} }); }",
    })
    assert sorted((f.rule_id, f.file) for f in res.findings) == [("RAC001", "app/api/items/route.ts"),
                                                                ("RAC004", "middleware.ts")]
    assert "does not cover POST /api/items" in next(f for f in res.findings if f.rule_id == "RAC004").message


def test_clerk_without_protect(scan):
    res = scan({
        "src/middleware.ts": 'import { clerkMiddleware } from "@clerk/nextjs/server";\nexport default clerkMiddleware();\n'
                             'export const config = { matcher: ["/(api|trpc)(.*)"] };\n',
        "src/app/api/items/route.ts": "export async function POST() { await db.x.create({ data: {} }); }",
    })
    assert rules(res) == ["RAC001", "RAC004"]
    rac4 = next(f for f in res.findings if f.rule_id == "RAC004")
    assert rac4.line == 2 and "auth.protect()" in rac4.message


def test_clerk_protect_only_some_routes(scan):
    res = scan({
        "middleware.ts": """
import { clerkMiddleware, createRouteMatcher } from "@clerk/nextjs/server";
const isProtectedRoute = createRouteMatcher(["/dashboard(.*)", "/api/private(.*)"]);
export default clerkMiddleware(async (auth, req) => {
  if (isProtectedRoute(req)) await auth.protect();
});
export const config = { matcher: ["/(api|trpc)(.*)", "/((?!_next).*)"] };
""",
        "app/api/private/x/route.ts": "export async function POST() { await db.x.create({ data: {} }); }",
        "app/api/other/route.ts": "export async function POST() { await db.x.create({ data: {} }); }",
    })
    assert sorted((f.rule_id, f.file) for f in res.findings) == [("RAC001", "app/api/other/route.ts"),
                                                                ("RAC004", "middleware.ts")]


# ---------------------------------------------------------------- RAC005 / RAC006
def test_admin_route_role_checks(scan):
    tmpl = """
export async function GET() {{
  const session = await auth();
  if (!session) return new Response(null, {{ status: 401 }});
  {check}
  return Response.json(await prisma.user.findMany());
}}
"""
    assert rules(scan({"app/api/admin/stats/route.ts": tmpl.format(check="")})) == ["RAC005"]
    for check in ('if (session.user.role !== "admin") return new Response(null, { status: 403 });',
                  "if (!session.user.isAdmin) return new Response(null, { status: 403 });",
                  "await requireAdmin(session);"):
        assert rules(scan({"app/api/admin/stats/route.ts": tmpl.format(check=check)})) == [], check


def test_user_list_outside_admin_path(scan):
    res = scan({"app/api/users/route.ts": """
export async function GET() {
  const session = await auth();
  if (!session) return new Response(null, { status: 401 });
  return Response.json(await prisma.user.findMany());
}
"""})
    assert rules(res) == ["RAC005"] and "lists all users" in res.findings[0].message


def test_role_from_body_and_headers(scan):
    res = scan({"server.ts": """
import express from "express";
const app = express();
app.post("/api/register", async (req, res) => {
  const user = await User.create({ email: req.body.email, role: req.body.role });
  res.json(user);
});
app.post("/api/reports", requireAuth, async (req, res) => {
  if (req.headers["x-role"] === "admin") { await Report.deleteMany({}); }
  res.end();
});
app.post("/api/notes", requireAuth, async (req, res) => {
  const { userId, text } = req.body;
  await Note.create({ text, owner: userId });
  res.end();
});
app.post("/api/notes2", requireAuth, async (req, res) => {
  const { userId, text } = req.body;
  if (userId !== req.user.id) return res.status(403).end();
  await Note.create({ text, owner: userId });
  res.end();
});
"""})
    assert sorted((f.rule_id, f.line, f.extra.get("kind")) for f in res.findings) == [
        ("RAC006", 5, "role"), ("RAC006", 9, "header"), ("RAC006", 13, "user-id")]


def test_header_set_by_covering_middleware_is_trusted(scan):
    res = scan({
        "middleware.ts": """
import { NextResponse } from "next/server";
import { jwtVerify } from "jose";
export async function middleware(req) {
  const { payload } = await jwtVerify(req.cookies.get("token")?.value, secret);
  const headers = new Headers(req.headers);
  headers.set("x-user-id", String(payload.sub));
  return NextResponse.next({ request: { headers } });
}
export const config = { matcher: ["/api/:path*"] };
""",
        "app/api/notes/route.ts": """
export async function POST(req: Request) {
  const userId = req.headers.get("x-user-id");
  await prisma.note.create({ data: { text: "x", userId } });
}
""",
    })
    assert rules(res) == []


# ---------------------------------------------------------------- RAC007 / RAC008
def test_cors(scan):
    res = scan({"a.ts": 'import cors from "cors";\napp.use(cors({ origin: "*", credentials: true }));\n',
                "b.ts": 'import cors from "cors";\napp.use(cors({ origin: (origin, cb) => cb(null, true), credentials: true }));\n',
                "c.ts": 'import cors from "cors";\napp.use(cors({ origin: (o, cb) => cb(null, ALLOWED.includes(o)), credentials: true }));\n',
                "d.ts": 'import cors from "cors";\napp.use(cors({ origin: "*" }));\n',
                "e.ts": 'res.setHeader("Access-Control-Allow-Origin", req.headers.origin);\n'
                        'res.setHeader("Access-Control-Allow-Credentials", "true");\n'})
    assert sorted((f.file, f.extra["how"]) for f in res.findings) == [("a.ts", "star"), ("b.ts", "reflect"),
                                                                       ("e.ts", "reflect")]


def test_mass_assignment_shapes(scan):
    res = scan({"server.ts": """
import express from "express";
const app = express();
app.post("/a", requireAuth, async (req, res) => { await Item.create(req.body); });
app.put("/b/:id", requireAuth, async (req, res) => { await Item.findOneAndUpdate({ _id: req.params.id, owner: req.user.id }, req.body); });
app.post("/c", requireAuth, async (req, res) => { await prisma.item.create({ data: { ...req.body, userId: req.user.id } }); });
app.post("/d", requireAuth, async (req, res) => { const data = Schema.parse(req.body); await prisma.item.create({ data }); });
app.post("/e", requireAuth, async (req, res) => { const { name } = req.body; await prisma.item.create({ data: { name } }); });
"""})
    assert sorted((f.rule_id, f.line) for f in res.findings) == [("RAC008", 4), ("RAC008", 5), ("RAC008", 6)]


def test_http_client_calls_are_not_routes(scan):
    res = scan({"src/api.ts": """
import axios from "axios";
const http = axios.create({ baseURL: "/api" });
export const createUser = (payload) => http.post("/users", payload);
export const removeUser = () => axios.delete("/users/1", { data: {} });
"""})
    assert res.routes == [] and res.findings == []


def test_imported_helper_is_followed_one_level(scan):
    res = scan({
        "lib/ctx.ts": 'import { getServerSession } from "next-auth";\n'
                      "export async function getCtx() { const s = await getServerSession(opts); if (!s) throw new Error(); return s; }\n",
        "app/api/a/route.ts": 'import { getCtx } from "@/lib/ctx";\n'
                              "export async function POST() { const ctx = await getCtx(); await db.x.create({ data: {} }); }\n",
        "app/api/b/route.ts": 'import { slugify } from "../../../lib/text";\n'
                              "export async function POST() { await db.x.create({ data: { s: slugify('a') } }); }\n",
        "lib/text.ts": "export function slugify(s: string) { return s.toLowerCase(); }\n",
    })
    assert [(f.rule_id, f.file) for f in res.findings] == [("RAC001", "app/api/b/route.ts")]


def test_pure_post_and_hmac_update_are_not_reported(scan):
    res = scan({
        "app/api/preview/route.ts": "export async function POST(req: Request) {\n"
                                    "  const { text } = await req.json();\n  return Response.json({ html: render(text) });\n}\n",
        "server.ts": 'import express from "express";\nconst app = express();\n'
                     'app.post("/hooks/github", express.raw({ type: "application/json" }), (req, res) => {\n'
                     '  const d = crypto.createHmac("sha256", process.env.S).update(req.body).digest("hex");\n'
                     "  res.end(d);\n});\n",
    })
    assert res.findings == []
