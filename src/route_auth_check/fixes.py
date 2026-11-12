"""Framework-specific fixes. Each finding's `extra` carries the framework, route, model, ORM and
the names used in the code, so the fix can be pasted with minimal editing."""

from __future__ import annotations

import re
import textwrap


def _d(s: str) -> str:
    return textwrap.dedent(s).strip("\n")


def build_fix(rule: str, x: dict) -> str | None:
    fn = {"RAC001": _rac001, "RAC002": _rac002, "RAC003": _rac003, "RAC004": _rac004, "RAC005": _rac005,
          "RAC006": _rac006, "RAC007": _rac007, "RAC008": _rac008}.get(rule)
    return fn(x) if fn and x else None


def _route_parts(x: dict) -> tuple[str, str]:
    label = x.get("route", "")
    meth, _, path = label.partition(" ")
    return meth.split("/")[0].lower() or "post", path or "/path"


def _rac001(x: dict) -> str | None:
    fw = x.get("framework")
    meth, path = _route_parts(x)
    recv = x.get("recv") or ("app" if fw in ("hono", "fastify") else "router")
    lpath = x.get("local_path") or path
    if fw == "next-app":
        M = meth.upper()
        return _d(f"""
            Check the session at the top of the handler and return 401 without one:

              import {{ auth }} from "@/auth";   // NextAuth v5. Or: getServerSession(authOptions),
                                               // Clerk: const {{ userId }} = await auth(),
                                               // Supabase: const {{ data: {{ user }} }} = await supabase.auth.getUser()
              export async function {M}(req: Request) {{
                const session = await auth();
                if (!session?.user) return new Response("Unauthorized", {{ status: 401 }});
                // use session.user.id from here on, never a user id from the request
              }}

            Protecting /api in middleware.ts as well is fine, but keep this check in the handler.""")
    if fw == "next-pages":
        return _d("""
            Check the session at the top of the handler and return 401 without one:

              import { getServerSession } from "next-auth/next";
              import { authOptions } from "@/pages/api/auth/[...nextauth]";

              export default async function handler(req, res) {
                const session = await getServerSession(req, res, authOptions);
                if (!session) return res.status(401).json({ error: "Unauthorized" });
                // use session.user.id from here on
              }""")
    if fw in ("express", "node", "koa"):
        return _d(f"""
            Add an auth middleware to the route (or router.use(requireAuth) before all routes that need it):

              function requireAuth(req, res, next) {{
                const token = req.headers.authorization?.replace(/^Bearer /, "");
                if (!token) return res.status(401).json({{ error: "Unauthorized" }});
                try {{
                  req.user = jwt.verify(token, process.env.JWT_SECRET);
                  return next();
                }} catch {{
                  return res.status(401).json({{ error: "Unauthorized" }});
                }}
              }}

              {recv}.{meth}("{lpath}", requireAuth, handler);

            With Passport: passport.authenticate("jwt", {{ session: false }}). With Clerk: requireAuth() from
            @clerk/express (clerkMiddleware() alone does not reject anonymous requests).""")
    if fw == "hono":
        prefix = lpath.rsplit("/", 1)[0] or "/"
        return _d(f"""
            Put an auth middleware in front of the route (or of the whole sub-app):

              import {{ jwt }} from "hono/jwt";
              {recv}.use("{prefix.rstrip('/')}/*", jwt({{ secret: process.env.JWT_SECRET!, alg: "HS256" }}));

              {recv}.{meth}("{lpath}", async (c) => {{
                const payload = c.get("jwtPayload");   // verified claims; payload.sub is the user id
              }});

            With Clerk: clerkMiddleware() plus `if (!getAuth(c)?.userId) return c.json({{ error: "Unauthorized" }}, 401)`.""")
    if fw == "fastify":
        return _d(f"""
            Register @fastify/jwt once, then protect the route with an onRequest hook:

              fastify.register(require("@fastify/jwt"), {{ secret: process.env.JWT_SECRET }});
              fastify.decorate("authenticate", async (request, reply) => {{
                try {{ await request.jwtVerify(); }} catch {{ return reply.code(401).send({{ error: "Unauthorized" }}); }}
              }});

              {recv}.{meth}("{lpath}", {{ onRequest: [fastify.authenticate] }}, handler);""")
    if fw == "fastapi":
        name = x.get("name") or "handler"
        return _d(f"""
            Require the current user as a dependency (401 when the token is missing or invalid):

              oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

              async def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)) -> User:
                  payload = decode_and_verify(token)          # e.g. jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
                  user = db.get(User, payload["sub"])
                  if user is None:
                      raise HTTPException(status_code=401, detail="Not authenticated")
                  return user

              @router.{meth}("{path}")
              async def {name}(..., current_user: User = Depends(get_current_user)):

            To protect a whole router: APIRouter(dependencies=[Depends(get_current_user)]).""")
    if fw == "flask":
        name = x.get("name") or "view"
        return _d(f"""
            Require a logged-in user on the view (Flask-Login shown; with Flask-JWT-Extended use @jwt_required()):

              from flask_login import login_required, current_user

              @bp.{meth}("{path}")
              @login_required
              def {name}(...):
                  # use current_user.id from here on

            The route decorator must come first (outermost), @login_required directly under it.""")
    if fw == "django":
        name = x.get("name") or "view"
        if name and name[:1].isupper():
            return _d(f"""
                Add LoginRequiredMixin as the first base class:

                  from django.contrib.auth.mixins import LoginRequiredMixin

                  class {name}(LoginRequiredMixin, ...):
                      ...""")
        return _d(f"""
            Decorate the view (or enable django.contrib.auth.middleware.LoginRequiredMiddleware, Django 5.1+):

              from django.contrib.auth.decorators import login_required

              @login_required
              def {name}(request, ...):
                  ...""")
    if fw == "drf":
        name = x.get("name") or "View"
        if name[:1].isupper():
            return _d(f"""
                Require authentication on the view, or for the whole API in settings.py:

                  from rest_framework.permissions import IsAuthenticated

                  class {name}(...):
                      permission_classes = [IsAuthenticated]

                  REST_FRAMEWORK = {{"DEFAULT_PERMISSION_CLASSES": ["rest_framework.permissions.IsAuthenticated"]}}""")
        return _d(f"""
            Require authentication on the view, or for the whole API in settings.py:

              from rest_framework.decorators import api_view, permission_classes
              from rest_framework.permissions import IsAuthenticated

              @api_view(["POST"])
              @permission_classes([IsAuthenticated])
              def {name}(request, ...):
                  ...

              REST_FRAMEWORK = {{"DEFAULT_PERMISSION_CLASSES": ["rest_framework.permissions.IsAuthenticated"]}}""")
    return None


def _rac002(x: dict) -> str | None:
    orm, model, idx, op = x.get("orm"), x.get("model", "record"), x.get("id", "id"), x.get("op", "read")
    owner, sess, fw = x.get("owner", "userId"), x.get("session", "session.user.id"), x.get("framework")
    if orm == "prisma":
        where = f"{{ id{'' if idx == 'id' else ': ' + idx}, {owner}: {sess} }}"
        if op == "read":
            return _d(f"""
                Filter on the owner in the same query, so another user's record is simply not found
                (findUnique only accepts unique fields, so use findFirst):

                  const {model} = await prisma.{model}.findFirst({{ where: {where} }});
                  if (!{model}) return new Response("Not found", {{ status: 404 }});

                Use your schema's owner column if it is not {owner}.""")
        data = ", data" if op == "update" else ""
        return _d(f"""
            Filter on the owner in the same query, so another user's record is simply not found:

              await prisma.{model}.{op}({{ where: {where}{data} }});
              // Prisma 5+ accepts non-unique fields here and throws P2025 when nothing matches: return 404.
              // Older Prisma: prisma.{model}.{op}Many({{ where: {where}{data} }}) and check result.count.

            Use your schema's owner column if it is not {owner}.""")
    if orm == "mongoose":
        call = {"read": "findOne", "update": "findOneAndUpdate", "delete": "findOneAndDelete"}[op]
        upd = ", update, { new: true }" if op == "update" else ""
        return _d(f"""
            Query by id AND owner, and return 404 when nothing matches:

              const doc = await {model}.{call}({{ _id: {idx}, {owner}: {sess} }}{upd});
              if (!doc) return res.status(404).json({{ error: "Not found" }});""")
    if orm == "sequelize":
        call = {"read": "findOne", "update": "update", "delete": "destroy"}[op]
        if op == "update":
            body = f"const [count] = await {model}.update(values, {{ where: {{ id: {idx}, {owner}: {sess} }} }});\n  if (count === 0) return res.status(404).end();"
        elif op == "delete":
            body = f"const count = await {model}.destroy({{ where: {{ id: {idx}, {owner}: {sess} }} }});\n  if (count === 0) return res.status(404).end();"
        else:
            body = f"const row = await {model}.{call}({{ where: {{ id: {idx}, {owner}: {sess} }} }});\n  if (!row) return res.status(404).end();"
        return "Include the owner in the where clause:\n\n  " + body
    if orm == "drizzle":
        return _d(f"""
            Add the owner to the where clause:

              import {{ and, eq }} from "drizzle-orm";
              .where(and(eq({model}.id, {idx}), eq({model}.{owner}, {sess})))

            and return 404 when no row comes back.""")
    if orm == "supabase-admin":
        return _d(f"""
            This query runs with the service-role key, which bypasses Row Level Security. Either use the
            per-request client (createServerClient with the user's cookies) so RLS applies, or filter on the owner:

              .from("{model}").update(values).eq("id", {idx}).eq("user_id", user.id)

            and keep an RLS policy such as `using (auth.uid() = user_id)` on the table.""")
    if orm == "drf":
        return _d(f"""
            Scope the queryset to the caller, so other users' objects return 404:

              def get_queryset(self):
                  return {model}.objects.filter({owner}=self.request.user)

            or add an object-level permission:

              class IsOwner(BasePermission):
                  def has_object_permission(self, request, view, obj):
                      return obj.{owner} == request.user

              permission_classes = [IsAuthenticated, IsOwner]""")
    if orm == "django":
        tail = ".delete()" if op == "delete" else ""
        return _d(f"""
            Look the object up through the owner as well (use your model's owner field):

              obj = get_object_or_404({model}, pk={idx}, {owner}=request.user){tail}

            (or {model}.objects.filter(pk={idx}, {owner}=request.user)...)""")
    if orm in ("sqlalchemy", "orm"):
        col = owner if owner.endswith("_id") else "owner_id"
        who = "current_user.id"
        if fw == "flask":
            return _d(f"""
                Filter on the owner in the same query; a record that is not the caller's becomes a 404:

                  obj = {model}.query.filter_by(id={idx}, {col}=current_user.id).first_or_404()

                Use your model's owner column if it is not {col}.""")
        err = "abort(404)" if fw == "flask" else 'raise HTTPException(status_code=404, detail="Not found")'
        return _d(f"""
            Filter on the owner in the same query and return 404 when nothing matches:

              obj = db.query({model}).filter({model}.id == {idx}, {model}.{col} == {who}).first()
              # SQLAlchemy 2.0: db.scalars(select({model}).where({model}.id == {idx}, {model}.{col} == {who})).first()
              if obj is None:
                  {err}""")
    return None


def _rac003(x: dict) -> str:
    name = x.get("name") or "action"
    return _d(f"""
        Authenticate inside the action (and check ownership of anything it touches by id):

          "use server";
          import {{ auth }} from "@/auth";   // or Clerk auth(), getServerSession(authOptions), supabase.auth.getUser()

          export async function {name}(...) {{
            const session = await auth();
            if (!session?.user) throw new Error("Unauthorized");
            // take the user id from session.user.id, never from the arguments
          }}

        next-safe-action users: build the action from an authenticated client (actionClient.use(authMiddleware)).""")


def _rac004(x: dict) -> str:
    if x.get("clerk"):
        return _d("""
            Call auth.protect() for everything that is not public:

              import { clerkMiddleware, createRouteMatcher } from "@clerk/nextjs/server";

              const isPublicRoute = createRouteMatcher(["/", "/sign-in(.*)", "/sign-up(.*)", "/api/webhooks(.*)"]);

              export default clerkMiddleware(async (auth, req) => {
                if (!isPublicRoute(req)) await auth.protect();
              });

              export const config = {
                matcher: ["/((?!_next|[^?]*\\\\.(?:html?|css|js(?!on)|jpe?g|webp|png|gif|svg|ttf|woff2?|ico)).*)",
                          "/(api|trpc)(.*)"],
              };

            and still check auth() in route handlers and server actions that change data.""")
    return _d("""
        Include the API in the matcher (and keep public paths public inside the middleware):

          export const config = {
            matcher: ["/((?!_next/static|_next/image|favicon.ico).*)", "/(api|trpc)(.*)"],
          };

        Middleware is a first line only: every route handler and server action that changes data should
        also check the session itself (await auth() / getServerSession), returning 401.""")


def _rac005(x: dict) -> str | None:
    fw = x.get("framework")
    if fw in ("next-app", "next-pages", "server-action"):
        return _d("""
            Check the role from the server-side session (or the database), after the login check:

              if (session.user.role !== "admin") return new Response("Forbidden", { status: 403 });
              // Clerk: const { has } = await auth(); if (!has({ role: "org:admin" })) return 403
              // Supabase: read the role from your profiles table / app_metadata, never from user_metadata

            Put the role on the session in your auth callbacks (session.user.role = token.role), never read it
            from the request.""")
    if fw in ("express", "node", "koa", "fastify", "hono"):
        mw = {"hono": 'async (c, next) => { if (c.get("jwtPayload").role !== "admin") return c.json({ error: "Forbidden" }, 403); await next(); }',
              "fastify": 'async (request, reply) => { if (request.user.role !== "admin") return reply.code(403).send({ error: "Forbidden" }); }'
              }.get(fw, '(req, res, next) => req.user?.role === "admin" ? next() : res.status(403).json({ error: "Forbidden" })')
        return _d(f"""
            Add a role check after authentication, using the role from the verified token / database:

              const requireAdmin = {mw};

            and add it to the route (or to the admin router as a whole).""")
    if fw == "fastapi":
        return _d("""
            Add an admin dependency on top of the user dependency:

              def require_admin(user: User = Depends(get_current_user)) -> User:
                  if not user.is_admin:            # or user.role != "admin"
                      raise HTTPException(status_code=403, detail="Forbidden")
                  return user

              admin_router = APIRouter(prefix="/admin", dependencies=[Depends(require_admin)])""")
    if fw == "flask":
        return _d("""
            Check the role after login, from the database user (current_user), not the request:

              def admin_required(view):
                  @functools.wraps(view)
                  def wrapped(*args, **kwargs):
                      if not current_user.is_authenticated or not current_user.is_admin:
                          abort(403)
                      return view(*args, **kwargs)
                  return wrapped""")
    if fw in ("django", "drf"):
        return _d("""
            Django:  @user_passes_test(lambda u: u.is_staff)   or   @staff_member_required
                     class-based: UserPassesTestMixin with test_func returning self.request.user.is_staff
            DRF:     permission_classes = [IsAdminUser]   (or a custom permission checking the user's role)""")
    return None


def _rac006(x: dict) -> str | None:
    fw, sess, expr = x.get("framework"), x.get("session", "session.user.id"), x.get("expr", "")
    if x.get("kind") == "header":
        line = f"user_id = {sess}" if x.get("lang") == "py" else f"const userId = {sess};"
        return _d(f"""
            Derive the user from the verified session / token, not a header the client can set:

              {line}   (after your auth check)

            If an auth proxy or your middleware sets {x.get('header')}, make sure it always overwrites the incoming
            value and that the app cannot be reached without passing through it.""")
    if x.get("kind") == "role":
        role_expr = re.sub(r"\.(?:id|sub)$", ".role", sess) if sess.endswith((".id", ".sub")) else "the user's role"
        return _d(f"""
            Never take the role from the request. Signup / profile updates must not accept a role field:
            assign the default role on the server, and change roles only in an admin route that checks the
            caller's own role. Read the caller's role from the session / database, e.g.:

              {role_expr}   (instead of {expr})""")
    if x.get("lang") == "py":
        return _d(f"""
            Use the authenticated user instead of {expr}:

              {"current_user.id     # current_user = Depends(get_current_user)" if fw == "fastapi" else
               "current_user.id     # Flask-Login / get_jwt_identity()" if fw == "flask" else "request.user"}

            Remove the user id field from the request schema so it cannot be sent at all.""")
    return _d(f"""
        Use the authenticated user instead of {expr}:

          const userId = {sess};

        and drop userId from the request body / query. If an admin may act for another user, accept the
        id only after a role check.""")


def _rac007(x: dict) -> str | None:
    fw = x.get("framework")
    if fw == "fastapi":
        return _d("""
            Allow only your own origins:

              app.add_middleware(CORSMiddleware, allow_origins=["https://app.example.com"],
                                 allow_credentials=True, allow_methods=["*"], allow_headers=["*"])""")
    if fw == "flask":
        return 'Allow only your own origins:\n\n  CORS(app, origins=["https://app.example.com"], supports_credentials=True)'
    if fw == "django":
        return _d("""
            Remove CORS_ALLOW_ALL_ORIGINS / CORS_ORIGIN_ALLOW_ALL and list your origins:

              CORS_ALLOWED_ORIGINS = ["https://app.example.com"]
              CORS_ALLOW_CREDENTIALS = True""")
    if x.get("where") == "headers":
        return _d("""
            Only echo origins from an allowlist:

              const ALLOWED = new Set(["https://app.example.com"]);
              const origin = req.headers.get("origin");
              if (origin && ALLOWED.has(origin)) {
                headers.set("Access-Control-Allow-Origin", origin);
                headers.set("Access-Control-Allow-Credentials", "true");
                headers.set("Vary", "Origin");
              }""")
    return _d("""
        Allow only your own origins:

          cors({ origin: ["https://app.example.com"], credentials: true })
          // with a callback: origin: (origin, cb) => cb(null, ALLOWED.includes(origin))""")


def _rac008(x: dict) -> str | None:
    if x.get("lang") == "py":
        if x.get("serializer"):
            return _d(f"""
                List the writable fields explicitly and make ownership / privilege fields read-only:

                  class {x['serializer']}(serializers.ModelSerializer):
                      class Meta:
                          model = ...
                          fields = ["id", "title", "body"]
                          read_only_fields = ["id", "owner", "created_at"]""")
        fw = x.get("framework")
        if fw == "fastapi":
            return _d("""
                Accept a Pydantic model that only has the fields the client may set, and set the owner yourself:

                  class NoteIn(BaseModel):          # no owner_id / role / is_admin fields
                      title: str
                      body: str

                  obj = Note(**payload.model_dump(), owner_id=current_user.id)""")
        if fw == "flask":
            return _d(f"""
                Copy only the fields users may change, by name, instead of {x.get('sink', 'Model(**data)')}:

                  data = request.get_json()
                  obj.title = data["title"]
                  obj.body = data["body"]
                  # or validate first with a schema that drops unknown keys (marshmallow, pydantic)""")
        return _d(f"""
            Use a ModelForm / Serializer with an explicit fields list, instead of {x.get('sink', 'Model(**data)')}:

              class ProfileForm(forms.ModelForm):
                  class Meta:
                      model = Profile
                      fields = ["bio", "website"]          # never "__all__"

              form = ProfileForm(data, instance=request.user.profile)
              if form.is_valid():
                  form.save()""")
    return _d(f"""
        Validate and pick the allowed fields before writing (zod shown):

          const Input = z.object({{ title: z.string().max(200), body: z.string() }});   // strips unknown keys
          const input = Input.parse({x.get('expr', 'body')});
          // write `input`, and set the owner from the session: {{ ...input, {x.get('owner', 'userId')}: {x.get('session', 'session.user.id')} }}""")
