"""Finding model and the rule catalogue (ids, severities, why it matters, how to fix)."""

from __future__ import annotations

import re
import textwrap
from dataclasses import asdict, dataclass, field

SEVERITIES = ("critical", "high", "medium", "low", "info")
SEVERITY_RANK = {name: i for i, name in enumerate(SEVERITIES)}  # lower = worse


@dataclass(frozen=True)
class Rule:
    id: str
    title: str
    severity: str     # default / range shown by `route-auth-check rules`
    why: str
    fix: str          # generic fix; findings carry a framework-specific one


RULES: dict[str, Rule] = {}


def _rule(id: str, title: str, severity: str, why: str, fix: str) -> None:
    RULES[id] = Rule(id, title, severity, " ".join(why.split()), textwrap.dedent(fix).strip("\n"))


_rule(
    "RAC001",
    "Route changes data without any authentication check",
    "high",
    """
Every route is reachable by anyone who can send an HTTP request: hiding the button in the
UI does not hide the endpoint, and the URL is in your frontend bundle. A POST / PUT /
PATCH / DELETE handler (or an admin-looking route) that never checks who is calling lets
anyone create, change or delete data, or run up your bill on paid APIs, with a single curl.
""",
    """
Check the session at the top of the handler (or in middleware that covers the route) and
return 401 when there is none:

  Next.js App Router:  const session = await auth();            // or getServerSession / Clerk auth() / supabase.auth.getUser()
                       if (!session?.user) return new Response("Unauthorized", { status: 401 });
  Express:             router.post(path, requireAuth, handler)   // or router.use(requireAuth) before the routes
  Hono:                app.use("/api/*", jwt({ secret: process.env.JWT_SECRET!, alg: "HS256" }))
  Fastify:             fastify.post(path, { onRequest: [fastify.authenticate] }, handler)
  FastAPI:             current_user: User = Depends(get_current_user)
  Flask:               @login_required  /  @jwt_required()
  Django / DRF:        @login_required  /  permission_classes = [IsAuthenticated]

Run `route-auth-check scan` to get the exact code for your framework and route.
""",
)
_rule(
    "RAC002",
    "Record looked up by a request id with no ownership check (IDOR)",
    "high (heuristic)",
    """
Checking that the caller is logged in is not enough. If the handler loads, updates or
deletes a record using an id from the URL, query string or body (/api/posts/42) and the
query does not also filter on the logged-in user, any signed-in user can change the id
and read, edit or delete everyone else's records. This is Broken Object Level
Authorization (OWASP API #1), and it is the most common hole in generated CRUD code.
""",
    """
Put the owner into the query itself, so a record that is not yours is simply not found
(then return 404), or load it and compare its owner with the session user (403):

  Prisma:      prisma.post.delete({ where: { id, authorId: session.user.id } })     // Prisma 5+
  Drizzle:     .where(and(eq(posts.id, id), eq(posts.userId, session.user.id)))
  Mongoose:    Post.findOneAndDelete({ _id: id, owner: req.user.id })
  SQLAlchemy:  db.query(Item).filter(Item.id == item_id, Item.owner_id == current_user.id).first()
  Django:      get_object_or_404(Post, pk=pk, owner=request.user)
  DRF:         def get_queryset(self): return Post.objects.filter(owner=self.request.user)
""",
)
_rule(
    "RAC003",
    "Server action has no authentication check",
    "high",
    """
Every exported function in a "use server" file (and every inline "use server" function)
becomes a public POST endpoint. Next.js calls it with an action id that is in the page's
JavaScript, so anyone can invoke it directly with any arguments, whether or not the page
that renders the form is protected. The arguments are client input, not trusted values.
""",
    """
Authenticate (and authorize) inside every action, like an API route:

  "use server";
  import { auth } from "@/auth";              // or Clerk auth() / getServerSession / supabase.auth.getUser()
  export async function deletePost(id: string) {
    const session = await auth();
    if (!session?.user) throw new Error("Unauthorized");
    await prisma.post.delete({ where: { id, authorId: session.user.id } });
  }
""",
)
_rule(
    "RAC004",
    "Next.js middleware does not cover the routes it seems meant to protect",
    "medium (heuristic)",
    """
Auth in middleware.ts only applies to paths its matcher matches. The common Next.js matcher
"/((?!api|_next/static|_next/image|favicon.ico).*)" excludes every /api route, and a
matcher like "/dashboard/:path*" protects pages but not the API routes those pages call.
clerkMiddleware() on its own protects nothing until it calls auth.protect(). The app looks
protected in the browser while the API is open.
""",
    """
Make the matcher include the API routes and protect them, or check the session in every
route handler:

  export const config = {
    matcher: ["/((?!_next/static|_next/image|favicon.ico).*)", "/(api|trpc)(.*)"],
  };

  // Clerk
  const isPublicRoute = createRouteMatcher(["/", "/sign-in(.*)", "/api/webhooks(.*)"]);
  export default clerkMiddleware(async (auth, req) => {
    if (!isPublicRoute(req)) await auth.protect();
  });
""",
)
_rule(
    "RAC005",
    "Admin route checks login but not the caller's role",
    "high (heuristic)",
    """
An admin endpoint (an /admin or /internal path, a handler that lists all users, or one that
changes a user's role) that only checks that someone is logged in is open to every user who
can sign up. One request promotes the attacker to admin or dumps the user table.
""",
    """
Check the role from the server-side session / database, never from the request:

  Next.js / Node:  if (session.user.role !== "admin") return new Response("Forbidden", { status: 403 });
  Clerk:           const { has } = await auth(); if (!has({ role: "org:admin" })) return 403;
  FastAPI:         def require_admin(user = Depends(get_current_user)):
                       if not user.is_admin: raise HTTPException(403)
  Django:          @user_passes_test(lambda u: u.is_staff)   /   DRF permission_classes = [IsAdminUser]
""",
)
_rule(
    "RAC006",
    "User id or role taken from the request instead of the session",
    "high",
    """
The body, query string and headers are written by the caller. A handler that takes the
acting user's id (body.userId, ?user_id=, an X-User-Id header) or their role / isAdmin flag
from the request lets anyone act as any user or as an admin by editing one field. The
user's identity must come from the verified session or token.
""",
    """
Use the id and role from the verified session, and ignore the client's copy:

  Next.js:   const session = await auth(); const userId = session.user.id;
  Express:   const userId = req.user.id;            // set by your auth middleware
  FastAPI:   current_user: User = Depends(get_current_user) -> current_user.id
  Django:    request.user
Only accept a user id from the request on admin routes, after a role check.
""",
)
_rule(
    "RAC007",
    "CORS allows any origin together with credentials",
    "medium",
    """
With credentials (cookies) allowed, the Access-Control-Allow-Origin value decides which
websites can make logged-in requests to your API and read the answers. Reflecting the
caller's Origin (origin: true, a callback that allows everything, Starlette / Flask-CORS /
django-cors-headers "allow all" with credentials) lets any website read your users' data
through their browser. "*" with credentials is rejected by browsers, and the usual "fix"
for the resulting errors is to reflect the origin.
""",
    """
Allow an explicit list of your own origins:

  Express / Fastify:  cors({ origin: ["https://app.example.com"], credentials: true })
  Hono:               cors({ origin: ["https://app.example.com"], credentials: true })
  FastAPI:            CORSMiddleware, allow_origins=["https://app.example.com"], allow_credentials=True
  Flask-CORS:         CORS(app, origins=["https://app.example.com"], supports_credentials=True)
  Django:             CORS_ALLOWED_ORIGINS = ["https://app.example.com"]  (and no CORS_ALLOW_ALL_ORIGINS)
""",
)
_rule(
    "RAC008",
    "Whole request body written to the database (mass assignment)",
    "medium",
    """
Passing the parsed request body straight into create / update writes every field the
caller sends, not just the ones your form shows: role, isAdmin, plan, credits, userId,
ownerId, emailVerified. TypeScript types and form fields do not stop this; the body is
whatever the client sends.
""",
    """
Pick the allowed fields explicitly or validate with a schema that strips unknown keys:

  Zod:       const data = PostInput.pick({ title: true, body: true }).parse(await req.json());
             await prisma.post.update({ where: { id, authorId: session.user.id }, data });
  Pydantic:  class PostUpdate(BaseModel): title: str; body: str     (no owner_id / role fields)
  Django:    form / serializer with an explicit fields list, never fields = "__all__"
""",
)


@dataclass
class Finding:
    rule_id: str
    severity: str
    message: str
    file: str | None = None
    line: int | None = None
    evidence: str | None = None
    heuristic: bool = False
    extra: dict = field(default_factory=dict)

    @property
    def rule(self) -> Rule:
        return RULES[self.rule_id]

    @property
    def location(self) -> str:
        if self.file is None:
            return ""
        return f"{self.file}:{self.line}" if self.line else self.file

    @property
    def fix(self) -> str:
        """The fix written for this finding's framework, route and data layer."""
        from .fixes import build_fix

        return build_fix(self.rule_id, self.extra) or self.rule.fix

    def to_dict(self) -> dict:
        d = asdict(self)
        d["title"] = self.rule.title
        d["why"] = self.rule.why
        d["fix"] = self.fix
        if not d["extra"]:
            d.pop("extra")
        return d


def sort_findings(findings: list[Finding]) -> list[Finding]:
    return sorted(
        findings,
        key=lambda f: (SEVERITY_RANK[f.severity], f.rule_id, f.file or "", f.line or 0),
    )


def mask_secret(value: str) -> str:
    """Show at most the first 4 characters of a secret, never enough to use it."""
    keep = min(4, len(value) // 4)
    return f"{value[:keep]}**** ({len(value)} chars)"


# Token formats that are masked in any line we print, whatever rule reported it.
KNOWN_SECRET_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{10,}"),
    re.compile(r"\bwhsec_[A-Za-z0-9+/=_\-]{8,}"),
    re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{40,})"),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"\bsk-(?:proj-|ant-)?[A-Za-z0-9_\-]{20,}"),
    re.compile(r"\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}"),     # JWTs (Supabase keys)
    re.compile(r"\bxox[abposr]-[A-Za-z0-9\-]{10,}"),
    re.compile(r"-----BEGIN (?:[A-Z]+ )?PRIVATE KEY-----"),
]
# A string literal used as a secret: `secret: "..."`, `JWT_SECRET = "..."`, jwt.verify(token, "...").
SECRET_LITERAL_RE = re.compile(
    r"""((?:\b\w*(?:secret|SECRET|Secret|password|PASSWORD|api_?key|API_?KEY|apiKey|private_?key|PRIVATE_?KEY)\w*['"]?"""
    r"""\s*[:=]\s*|\bjwt\s*\.\s*(?:verify|sign|decode)\s*\([^,()]+,\s*|\bjwt\s*\.\s*(?:encode|decode)\s*\([^,()]+,\s*)"""
    r"""(?:\w+\s*(?:\|\||\?\?|or)\s*)?)(['"])([^'"\s]{6,})\2"""
)


def redact_line(line: str, extra_secrets: list[str] | None = None, limit: int = 160) -> str:
    """Strip a source line for display, masking anything secret-shaped."""
    s = line.strip()
    for secret in sorted(extra_secrets or [], key=len, reverse=True):
        if secret and len(secret) >= 4:
            s = s.replace(secret, mask_secret(secret))
    for pat in KNOWN_SECRET_PATTERNS:
        s = pat.sub(lambda m: mask_secret(m.group(0)), s)
    s = SECRET_LITERAL_RE.sub(
        lambda m: m.group(1) + m.group(2) + (m.group(3) if "****" in m.group(3) else mask_secret(m.group(3))) + m.group(2),
        s)
    if len(s) > limit:
        s = s[: limit - 3] + "..."
    return s
