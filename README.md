# route-auth-check

A static check for API routes that are **missing authentication or authorization**. AI coding
tools are good at generating CRUD endpoints and bad at remembering who is allowed to call them.
route-auth-check reads your Next.js, Node and Python code and finds the routes that:

- **change data with no auth check at all** (POST / PUT / PATCH / DELETE, admin-looking routes)
- load, update or delete a record **by an id from the request without checking it belongs to the
  caller** (IDOR / Broken Object Level Authorization, OWASP API #1)
- are **Server Actions without an auth check** ("use server" functions are public POST endpoints)
- sit behind a **Next.js middleware matcher that skips them** (the common `(?!api|...)` matcher,
  `clerkMiddleware()` without `auth.protect()`)
- are **admin routes that check login but not the role** (`/admin/*`, listing all users, changing roles)
- **trust a user id or role from the request** (`body.userId`, `?user_id=`, `X-User-Id`, `role` on signup)
- allow **any origin with credentials** in CORS (reflected origin, `origin: true`, "allow all" + credentials)
- write the **whole request body into the database** (mass assignment: `prisma.x.create({ data: body })`,
  `Model(**data)`, `Order.create(req.body)`)

Frameworks: **Next.js** (App Router route handlers, `pages/api`, Server Actions, `middleware.ts` /
`proxy.ts`), **Express**, **Hono**, **Fastify**, Koa-style routers, **FastAPI**, **Flask**,
**Django** and **Django REST Framework**. Data layers understood for the IDOR check: Prisma,
Drizzle, Mongoose, Sequelize, Supabase (service-role client), Django ORM,
SQLAlchemy / Flask-SQLAlchemy / SQLModel, Tortoise.

Every finding has a rule id, a severity, `file:line`, the offending line (anything secret-shaped
masked to at most 4 characters), why it matters, and a fix written for **that framework and that
data layer**, with your route, model and variable names filled in.

Zero dependencies (Python 3.10+ standard library only). **Static only:** it never runs your
code, never imports it and makes no network requests. CI-friendly exit codes.

---

## Quick start

```bash
pipx install git+https://github.com/abhi12337/route-auth-check   # straight from GitHub
pipx install .                              # from a clone of this repo (or: pip install .)

route-auth-check scan                       # current folder
route-auth-check scan path/to/web path/to/api
route-auth-check scan app/api/posts/route.ts   # a single file
route-auth-check scan . --json > report.json   # machine-readable output
route-auth-check scan . --auth-fn requireMember --auth-fn get_viewer   # your own auth helpers
route-auth-check rules                      # every rule, why it matters, how to fix it
```

Try it on the deliberately broken demo project (a Next.js app with route handlers, Server
Actions and middleware, Express / Hono / Fastify servers, and a FastAPI + Flask + Django / DRF
backend, copied from `tests/fixtures`):

```bash
python examples/make_demo.py demo-routes
route-auth-check scan demo-routes
```

Exit codes: `0` = nothing at or above `--fail-on` (default `high`), `1` = findings at or above
it, `2` = usage error. Use `--fail-on critical|high|medium|low|info|never` to tune CI.

## Example output

All output below was produced by running this version of the tool on the demo project and the
test fixtures in this repository (nothing is hand-edited).

`route-auth-check scan demo-routes/web/app/actions/comments.ts demo-routes/web/server/express.ts --brief`
(a Server Actions file and an Express server):

```text
route-auth-check 0.1.1
Scanned demo-routes/web/app/actions/comments.ts, demo-routes/web/server/express.ts
2 source file(s), 7 route(s) (Express 4, Server Actions 3)
auth: 4 protected, 1 public, 2 unprotected, 0 unknown

HIGH     RAC001  Route changes data without any authentication check
      at: demo-routes/web/server/express.ts:18
      POST /api/orders accepts POST requests and never checks who is calling (no session, token or
      auth middleware found). Anyone can call it with curl.
      code: app.post("/api/orders", async (req, res) => {

HIGH     RAC002  Record looked up by a request id with no ownership check (IDOR) [heuristic]
      at: demo-routes/web/app/actions/comments.ts:15
      server action deleteComment() deletes comment by an id from the request (commentId) without
      checking that it belongs to the caller: any signed-in user can delete other users' comment
      records by changing the id.
      code: await prisma.comment.delete({ where: { id: commentId } });

HIGH     RAC002  Record looked up by a request id with no ownership check (IDOR) [heuristic]
      at: demo-routes/web/server/express.ts:24
      GET /api/orders/:id reads Order by an id from the request (req.params.id) without checking
      that it belongs to the caller: any signed-in user can read other users' Order records by
      changing the id.
      code: const order = await Order.findById(req.params.id);

HIGH     RAC003  Server action has no authentication check
      at: demo-routes/web/app/actions/comments.ts:7
      Server action createComment() changes data and never checks the session: it is a public POST
      endpoint that anyone can call directly, with any arguments.
      code: export async function createComment(postId: string, text: string) {

HIGH     RAC005  Admin route checks login but not the caller's role [heuristic]
      at: demo-routes/web/server/express.ts:28
      PUT /api/users/:id/role is an admin endpoint (sets a user's role from the request) and
      checks that the caller is signed in (requireAuth) but not their role: every user who can
      create an account can call it.
      code: app.put("/api/users/:id/role", requireAuth, async (req, res) => {

HIGH     RAC006  User id or role taken from the request instead of the session
      at: demo-routes/web/app/actions/comments.ts:19
      server action updateSettings() takes the acting user's id from the request (userId, an
      action argument) instead of the session: anyone can act as, or write data for, any user by
      changing it.
      code: export async function updateSettings(userId: string, data: { theme: string; emailDigest: boolean }) {

HIGH     RAC006  User id or role taken from the request instead of the session
      at: demo-routes/web/server/express.ts:34
      GET /api/me/orders takes the caller's identity or role from the x-user-id header. Clients
      can send any header, so anyone can claim to be any user (or an admin) unless a proxy you
      control always overwrites it.
      code: const userId = req.headers["x-user-id"];

MEDIUM   RAC007  CORS allows any origin together with credentials
      at: demo-routes/web/server/express.ts:9
      CORS reflects the caller's Origin (any site is allowed) with credentials: any website a
      logged-in user visits can call this API with their cookies and read the responses.
      code: app.use(cors({ origin: true, credentials: true }));

MEDIUM   RAC008  Whole request body written to the database (mass assignment)
      at: demo-routes/web/app/actions/comments.ts:22
      server action updateSettings() passes a whole action argument (data) to
      prisma.settings.update({ data: ... }): the caller can set any column, including role /
      isAdmin / userId / plan, not just the fields your form sends.
      code: await prisma.settings.update({ where: { userId }, data });

MEDIUM   RAC008  Whole request body written to the database (mass assignment)
      at: demo-routes/web/server/express.ts:19
      POST /api/orders passes the whole request body (req.body) to Order.create(): the caller can
      set any column, including role / isAdmin / userId / plan, not just the fields your form
      sends.
      code: const order = await Order.create(req.body);

Summary: 0 critical, 7 high, 3 medium, 0 low, 0 info
Exit code: 1
```

A full finding (without `--brief`): the fix is written for the data layer (Prisma) and the
framework (Next.js App Router), with the route's own variable names:

```text
route-auth-check 0.1.1
Scanned demo-routes/web/app/api/posts/[id]/route.ts
1 source file(s), 2 route(s) (Next.js App Router 2)
auth: 2 protected, 0 public, 0 unprotected, 0 unknown

HIGH     RAC002  Record looked up by a request id with no ownership check (IDOR) [heuristic]
      at: demo-routes/web/app/api/posts/[id]/route.ts:12
      PATCH /api/posts/[id] updates post by an id from the request (id) without checking that it
      belongs to the caller: any signed-in user can update other users' post records by changing
      the id.
      code: const post = await prisma.post.update({ where: { id }, data: { title, content } });
      why: Checking that the caller is logged in is not enough. If the handler loads,
           updates or deletes a record using an id from the URL, query string or body
           (/api/posts/42) and the query does not also filter on the logged-in user, any
           signed-in user can change the id and read, edit or delete everyone else's
           records. This is Broken Object Level Authorization (OWASP API #1), and it is the
           most common hole in generated CRUD code.
      fix:
        Filter on the owner in the same query, so another user's record is simply not found:

          await prisma.post.update({ where: { id, userId: session.user.id }, data });
          // Prisma 5+ accepts non-unique fields here and throws P2025 when nothing matches: return 404.
          // Older Prisma: prisma.post.updateMany({ where: { id, userId: session.user.id }, data }) and check result.count.

        Use your schema's owner column if it is not userId.

HIGH     RAC002  Record looked up by a request id with no ownership check (IDOR) [heuristic]
      at: demo-routes/web/app/api/posts/[id]/route.ts:20
      DELETE /api/posts/[id] deletes post by an id from the request (id) without checking that it
      belongs to the caller: any signed-in user can delete other users' post records by changing
      the id.
      code: await prisma.post.delete({ where: { id } });
      fix:
        Filter on the owner in the same query, so another user's record is simply not found:

          await prisma.post.delete({ where: { id, userId: session.user.id } });
          // Prisma 5+ accepts non-unique fields here and throws P2025 when nothing matches: return 404.
          // Older Prisma: prisma.post.deleteMany({ where: { id, userId: session.user.id } }) and check result.count.

        Use your schema's owner column if it is not userId.

Summary: 0 critical, 2 high, 0 medium, 0 low, 0 info
Exit code: 1
```

<details>
<summary>The whole demo project: <code>route-auth-check scan demo-routes --brief</code></summary>

```text
route-auth-check 0.1.1
Scanned demo-routes
15 source file(s), 27 route(s) (Express 6, Next.js App Router 6, FastAPI 3, Flask 3, Server Actions 3, DRF 2, Django 2, Fastify 1, Hono 1)
auth: 14 protected, 4 public, 9 unprotected, 0 unknown

HIGH     RAC001  Route changes data without any authentication check
      at: api/django_views.py:10
      delete_account() accepts POST requests and never checks who is calling (no session, token or
      auth middleware found). Anyone can call it with curl.
      code: @require_POST

HIGH     RAC001  Route changes data without any authentication check
      at: api/django_views.py:28
      InvoiceViewSet (ModelViewSet) accepts POST/PUT/PATCH/DELETE requests and never checks who is
      calling: DRF's default permission is AllowAny and no permission_classes are set here or in
      REST_FRAMEWORK['DEFAULT_PERMISSION_CLASSES'] in the scanned files. Anyone can call it with
      curl.
      code: class InvoiceViewSet(viewsets.ModelViewSet):

HIGH     RAC001  Route changes data without any authentication check
      at: api/fastapi_app.py:20
      POST /notes accepts POST requests and never checks who is calling (no session, token or auth
      middleware found). Anyone can call it with curl.
      code: @app.post("/notes")

HIGH     RAC001  Route changes data without any authentication check
      at: api/flask_app.py:22
      POST /api/comments accepts POST requests and never checks who is calling (no session, token
      or auth middleware found). Anyone can call it with curl.
      code: @app.route("/api/comments", methods=["POST"])

HIGH     RAC001  Route changes data without any authentication check
      at: web/app/api/posts/route.ts:8
      POST /api/posts accepts POST requests and never checks who is calling (no session, token or
      auth middleware found; web/middleware.ts does not cover this path). Anyone can call it with
      curl.
      code: export async function POST(req: Request) {

HIGH     RAC001  Route changes data without any authentication check
      at: web/server/express.ts:18
      POST /api/orders accepts POST requests and never checks who is calling (no session, token or
      auth middleware found). Anyone can call it with curl.
      code: app.post("/api/orders", async (req, res) => {

HIGH     RAC001  Route changes data without any authentication check
      at: web/server/hono.ts:8
      DELETE /api/projects/:id accepts DELETE requests and never checks who is calling (no
      session, token or auth middleware found). Anyone can call it with curl.
      code: app.delete("/api/projects/:id", async (c) => {

HIGH     RAC001  Route changes data without any authentication check
      at: web/server/routes/invoices.ts:7
      DELETE /api/invoices/:id accepts DELETE requests and never checks who is calling (no
      session, token or auth middleware found). Anyone can call it with curl.
      code: router.delete("/:id", deleteInvoice);

HIGH     RAC002  Record looked up by a request id with no ownership check (IDOR) [heuristic]
      at: api/django_views.py:18
      invoice_detail() reads Invoice by an id from the request (pk) without checking that it
      belongs to the caller: any signed-in user can read other users' Invoice records by changing
      the id.
      code: invoice = Invoice.objects.get(pk=pk)

HIGH     RAC002  Record looked up by a request id with no ownership check (IDOR) [heuristic]
      at: api/django_views.py:34
      PaymentMethodViewSet (ModelViewSet) deletes PaymentMethod by an id from the request (the pk
      in the URL) without checking that it belongs to the caller: any signed-in user can delete
      other users' PaymentMethod records.
      code: queryset = PaymentMethod.objects.all()

HIGH     RAC002  Record looked up by a request id with no ownership check (IDOR) [heuristic]
      at: api/fastapi_app.py:30
      DELETE /notes/{note_id} deletes Note by an id from the request (note_id) without checking
      that it belongs to the caller: any signed-in user can delete other users' Note records by
      changing the id.
      code: note = db.query(Note).filter(Note.id == note_id).first()

HIGH     RAC002  Record looked up by a request id with no ownership check (IDOR) [heuristic]
      at: api/flask_app.py:14
      PUT /api/posts/<int:post_id> updates Post by an id from the request (post_id) without
      checking that it belongs to the caller: any signed-in user can update other users' Post
      records by changing the id.
      code: post = Post.query.get_or_404(post_id)

HIGH     RAC002  Record looked up by a request id with no ownership check (IDOR) [heuristic]
      at: web/app/actions/comments.ts:15
      server action deleteComment() deletes comment by an id from the request (commentId) without
      checking that it belongs to the caller: any signed-in user can delete other users' comment
      records by changing the id.
      code: await prisma.comment.delete({ where: { id: commentId } });

HIGH     RAC002  Record looked up by a request id with no ownership check (IDOR) [heuristic]
      at: web/app/api/posts/[id]/route.ts:12
      PATCH /api/posts/[id] updates post by an id from the request (id) without checking that it
      belongs to the caller: any signed-in user can update other users' post records by changing
      the id.
      code: const post = await prisma.post.update({ where: { id }, data: { title, content } });

HIGH     RAC002  Record looked up by a request id with no ownership check (IDOR) [heuristic]
      at: web/app/api/posts/[id]/route.ts:20
      DELETE /api/posts/[id] deletes post by an id from the request (id) without checking that it
      belongs to the caller: any signed-in user can delete other users' post records by changing
      the id.
      code: await prisma.post.delete({ where: { id } });

HIGH     RAC002  Record looked up by a request id with no ownership check (IDOR) [heuristic]
      at: web/server/express.ts:24
      GET /api/orders/:id reads Order by an id from the request (req.params.id) without checking
      that it belongs to the caller: any signed-in user can read other users' Order records by
      changing the id.
      code: const order = await Order.findById(req.params.id);

HIGH     RAC003  Server action has no authentication check
      at: web/app/actions/comments.ts:7
      Server action createComment() changes data and never checks the session: it is a public POST
      endpoint that anyone can call directly, with any arguments. middleware.ts matches every
      page, which may stop anonymous calls, but Next.js recommends checking auth inside every
      action.
      code: export async function createComment(postId: string, text: string) {

HIGH     RAC005  Admin route checks login but not the caller's role [heuristic]
      at: api/fastapi_app.py:36
      GET /admin/users is an admin endpoint ('admin' in the path) and checks that the caller is
      signed in (Depends(get_current_user)) but not their role: every user who can create an
      account can call it.
      code: @app.get("/admin/users")

HIGH     RAC005  Admin route checks login but not the caller's role [heuristic]
      at: api/flask_app.py:31
      POST /api/admin/promote/<int:user_id> is an admin endpoint ('admin' in the path) and checks
      that the caller is signed in (@login_required) but not their role: every user who can create
      an account can call it.
      code: @app.post("/api/admin/promote/<int:user_id>")

HIGH     RAC005  Admin route checks login but not the caller's role [heuristic]
      at: web/app/api/admin/users/route.ts:4
      GET /api/admin/users is an admin endpoint ('admin' in the path) and checks that the caller
      is signed in (currentUser()) but not their role: every user who can create an account can
      call it.
      code: export async function GET() {

HIGH     RAC005  Admin route checks login but not the caller's role [heuristic]
      at: web/server/express.ts:28
      PUT /api/users/:id/role is an admin endpoint (sets a user's role from the request) and
      checks that the caller is signed in (requireAuth) but not their role: every user who can
      create an account can call it.
      code: app.put("/api/users/:id/role", requireAuth, async (req, res) => {

HIGH     RAC006  User id or role taken from the request instead of the session
      at: api/django_views.py:12
      delete_account() takes the acting user's id from the request (request.POST['user_id'],
      request body) instead of the session: anyone can act as, or write data for, any user by
      changing it.
      code: User.objects.filter(id=request.POST["user_id"]).delete()

HIGH     RAC006  User id or role taken from the request instead of the session
      at: api/fastapi_app.py:22
      POST /notes takes the acting user's id from the request (note.owner_id, request body)
      instead of the session: anyone can act as, or write data for, any user by changing it.
      code: obj = Note(title=note.title, body=note.body, owner_id=note.owner_id)

HIGH     RAC006  User id or role taken from the request instead of the session
      at: api/flask_app.py:34
      POST /api/admin/promote/<int:user_id> takes the caller's identity or role from the x-user-
      role header. Clients can send any header, so anyone can claim to be any user (or an admin)
      unless a proxy you control always overwrites it.
      code: if request.headers.get("X-User-Role") != "admin":

HIGH     RAC006  User id or role taken from the request instead of the session
      at: web/app/actions/comments.ts:19
      server action updateSettings() takes the acting user's id from the request (userId, an
      action argument) instead of the session: anyone can act as, or write data for, any user by
      changing it.
      code: export async function updateSettings(userId: string, data: { theme: string; emailDigest: boolean }) {

HIGH     RAC006  User id or role taken from the request instead of the session
      at: web/app/api/profile/route.ts:7
      PUT /api/profile takes the acting user's id from the request (userId, request body) instead
      of the session: anyone can act as, or write data for, any user by changing it.
      code: const { userId, displayName, bio } = await req.json();

HIGH     RAC006  User id or role taken from the request instead of the session
      at: web/server/express.ts:34
      GET /api/me/orders takes the caller's identity or role from the x-user-id header. Clients
      can send any header, so anyone can claim to be any user (or an admin) unless a proxy you
      control always overwrites it.
      code: const userId = req.headers["x-user-id"];

HIGH     RAC006  User id or role taken from the request instead of the session
      at: web/server/fastify.ts:8
      POST /api/signup takes the role from the request (role) and writes it to the user record:
      anyone can make themselves an admin by sending role=admin.
      code: const { email, password, role } = request.body as { email: string; password: string; role?: string };

MEDIUM   RAC004  Next.js middleware does not cover the routes it seems meant to protect [heuristic]
      at: web/middleware.ts:5
      The middleware matcher excludes /api, so its auth check never runs for API routes; POST
      /api/posts has no check of its own.
      code: matcher: ["/((?!api|_next/static|_next/image|favicon.ico).*)"],

MEDIUM   RAC007  CORS allows any origin together with credentials
      at: api/fastapi_app.py:11
      CORSMiddleware allows every origin with allow_credentials=True: Starlette then answers with
      the caller's own Origin for cookie requests, so any website can make logged-in requests and
      read the responses.
      code: app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=True, allow_methods=["*"])

MEDIUM   RAC007  CORS allows any origin together with credentials
      at: api/flask_app.py:8
      Flask-CORS with supports_credentials=True and the default / '*' origins answers with the
      caller's own Origin, so any website can make logged-in requests and read the responses.
      code: CORS(app, supports_credentials=True)

MEDIUM   RAC007  CORS allows any origin together with credentials
      at: api/settings.py:7
      django-cors-headers allows all origins with CORS_ALLOW_CREDENTIALS = True: it answers with
      the caller's own Origin, so any website can make logged-in requests and read the responses.
      code: CORS_ALLOW_ALL_ORIGINS = True

MEDIUM   RAC007  CORS allows any origin together with credentials
      at: web/server/express.ts:9
      CORS reflects the caller's Origin (any site is allowed) with credentials: any website a
      logged-in user visits can call this API with their cookies and read the responses.
      code: app.use(cors({ origin: true, credentials: true }));

MEDIUM   RAC008  Whole request body written to the database (mass assignment) [heuristic]
      at: api/django_views.py:25
      InvoiceSerializer is a ModelSerializer with fields = "__all__" and no read_only_fields: when
      it is used to create or update, the client can set every model field (owner, role, is_staff,
      ...).
      code: fields = "__all__"

MEDIUM   RAC008  Whole request body written to the database (mass assignment)
      at: api/flask_app.py:16
      PUT /api/posts/<int:post_id> passes the whole request body (data) to setattr() loop: the
      caller can set any column, including role / isAdmin / user_id / plan, not just the fields
      your form sends.
      code: for key, value in data.items():

MEDIUM   RAC008  Whole request body written to the database (mass assignment)
      at: api/flask_app.py:25
      POST /api/comments passes the whole request body (data) to Comment(**data): the caller can
      set any column, including role / isAdmin / user_id / plan, not just the fields your form
      sends.
      code: comment = Comment(**data)

MEDIUM   RAC008  Whole request body written to the database (mass assignment)
      at: web/app/actions/comments.ts:22
      server action updateSettings() passes a whole action argument (data) to
      prisma.settings.update({ data: ... }): the caller can set any column, including role /
      isAdmin / userId / plan, not just the fields your form sends.
      code: await prisma.settings.update({ where: { userId }, data });

MEDIUM   RAC008  Whole request body written to the database (mass assignment)
      at: web/app/api/posts/route.ts:10
      POST /api/posts passes the whole request body (body) to prisma.post.create({ data: ... }):
      the caller can set any column, including role / isAdmin / userId / plan, not just the fields
      your form sends.
      code: const post = await prisma.post.create({ data: body });

MEDIUM   RAC008  Whole request body written to the database (mass assignment)
      at: web/server/express.ts:19
      POST /api/orders passes the whole request body (req.body) to Order.create(): the caller can
      set any column, including role / isAdmin / userId / plan, not just the fields your form
      sends.
      code: const order = await Order.create(req.body);

Summary: 0 critical, 28 high, 11 medium, 0 low, 0 info
Exit code: 1
```

</details>

The same routes written correctly (`tests/fixtures/node_clean`, `tests/fixtures/py_clean`)
produce no findings, and every route is classified:

```text
route-auth-check 0.1.1
Scanned tests/fixtures/node_clean, tests/fixtures/py_clean
20 source file(s), 37 route(s) (Next.js App Router 10, Express 8, FastAPI 5, Flask 4, Server Actions 3, DRF 2, Django 2, Fastify 2, Hono 1)
auth: 28 protected, 9 public, 0 unprotected, 0 unknown

No findings. (This is not a guarantee: see 'What it does not check' in the README.)
Summary: 0 critical, 0 high, 0 medium, 0 low, 0 info
Exit code: 0
```

## What it checks

| Rule | Severity | What it finds |
|---|---|---|
| RAC001 | High | A PUT / PATCH / DELETE route, a POST route that touches data or the outside world (a data-layer or API call, `fetch`, or any `await` other than reading the request), or an admin-looking route of any method, with no recognisable auth check in the handler, its middleware, its router, its mount point, `middleware.ts`, or project settings. Routes that are public by design are skipped (see below). For DRF, a view with no `permission_classes` when `REST_FRAMEWORK["DEFAULT_PERMISSION_CLASSES"]` is not set in the scanned files (DRF's default is `AllowAny`). |
| RAC002 | High (heuristic) | An authenticated route that reads / updates / deletes a record by an id taken from the URL, query, body or Server Action arguments, where the query has no owner filter (`userId`, `ownerId`, `authorId`, `user=`, `owner_id`, `tenantId`, `orgId`, ...) and the handler never compares the record with the session user, returns 403, or calls a permission helper (`can()`, `authorize()`, `isOwner()`, `check_object_permissions`, ...). Also DRF detail views / ViewSets with `queryset = X.objects.all()`, no `get_queryset` scoped to `request.user` and no object-level permission class. Supabase queries are only checked when the service-role client is used (otherwise Row Level Security applies). |
| RAC003 | High | An exported function in a `"use server"` file, or an inline `"use server"` function, that writes data and never checks the session. |
| RAC004 | Medium (heuristic) | A Next.js `middleware.ts` / `proxy.ts` that authenticates, but whose matcher (or Clerk `createRouteMatcher` / missing `auth.protect()`) leaves state-changing API routes uncovered, when those routes have no check of their own. |
| RAC005 | High (heuristic) | An authenticated route that looks like an admin route (`admin`, `internal`, `staff`, `superadmin`, `backoffice` in the path or name), lists all users, or writes a user's role, with no role check (`role === "admin"`, `isAdmin`, `has({ role })`, `requireAdmin()`, `IsAdminUser`, `is_staff`, `@user_passes_test`, an admin dependency / middleware, ...). |
| RAC006 | High | A user id (`userId`, `user_id`, `ownerId`, `authorId`, `createdBy`, ...) taken from the body, query string, form data or Server Action arguments and used without comparing it to the session; a `role` / `isAdmin` taken from the request and written or used in a condition; identity headers (`X-User-Id`, `X-User-Role`, `X-Role`, `X-Admin`, ...) unless a scanned Next.js middleware sets that header itself and covers the route. Path parameters are not reported here (they select a record; that is RAC002). |
| RAC007 | Medium | CORS that allows any origin with credentials: `cors({ origin: "*" | true | (o, cb) => cb(null, true), credentials: true })`, a manually reflected `Access-Control-Allow-Origin` with `Allow-Credentials: true`, FastAPI / Starlette `CORSMiddleware(allow_origins=["*"], allow_credentials=True)`, Flask-CORS with `supports_credentials=True` and default origins, django-cors-headers `CORS_ALLOW_ALL_ORIGINS` + `CORS_ALLOW_CREDENTIALS`. |
| RAC008 | Medium | The parsed request body passed whole into a write: Prisma `data: body` / `data: { ...body }`, `Model.create(req.body)`, `new Model(body)`, `findByIdAndUpdate(id, req.body)`, `Object.assign(doc, body)`, Drizzle `.values(body)` / `.set(body)`, Supabase `.insert(body)`, Python `Model(**data)`, `.update(**data)`, `setattr` loops over the body, and DRF `ModelSerializer` with `fields = "__all__"` and no `read_only_fields` (heuristic). A body that went through a schema (`Schema.parse(...)`, a Pydantic model) is not reported. |

### How auth is recognised

Recognition is deliberately generous: anything that looks like an auth check counts, so a route
is only reported when there is no sign of one at all.

- **Calls in the handler** (and in same-file helpers two levels deep, and in functions imported
  from other scanned files one level deep): `getServerSession`, `auth()`, `currentUser()`,
  `getAuth()`, `getUser()`, `supabase.auth.getUser()` / `getSession()` / `getClaims()`,
  `getKindeServerSession`, `validateRequest` (Lucia), `getIronSession`, `getToken`, `jwt.verify`,
  `jwtVerify` (jose), `verifyIdToken` / `verifySessionCookie` (Firebase), `passport.authenticate`,
  `request.jwtVerify()` (Fastify), `auth.protect()`, `withApiAuthRequired`, plus any name shaped
  like `requireUser`, `getCurrentUser`, `verifyToken`, `ensureAuthenticated`, `getSessionUser`,
  `isLoggedIn`, ... References to `req.user`, `req.auth`, `req.session.user`, `c.get("jwtPayload")`,
  `c.var.user`, an `Authorization` / `X-API-Key` header, a session cookie, or a `CRON_SECRET`-style
  secret also count.
- **Route middleware** (`app.post(path, requireAuth, handler)`, Fastify `onRequest` /
  `preHandler`), **router-level** `router.use(protect)` / Hono `app.use("/api/*", jwt(...))` /
  Fastify `addHook("onRequest", ...)`, and **mount points in other files**
  (`app.use("/api/orders", requireAuth, ordersRouter)`, Hono `app.route(...)`). Express / Hono
  `use()` only protects routes registered after it.
- **Next.js `middleware.ts` / `proxy.ts`**: Clerk `clerkMiddleware` with `auth.protect()` (including
  `createRouteMatcher` public / protected lists), NextAuth (`next-auth/middleware`, `withAuth`,
  `export { auth as middleware }`), Supabase `updateSession`, or any recognised auth call; the
  `config.matcher` patterns are evaluated against each route's path, and simple
  `if (pathname.startsWith("/x")) return NextResponse.next()` skips are honoured.
- **Python**: FastAPI `Depends(...)` / `Security(...)` parameters, `Annotated[..., Depends(...)]`
  aliases such as `CurrentUser`, route and `APIRouter(dependencies=[...])` / `FastAPI(dependencies=[...])`,
  `include_router(..., dependencies=[...])` across files; Flask `@login_required`,
  `@jwt_required()`, `@token_required`-style decorators, `before_request` hooks on the app or
  blueprint, `current_user.is_authenticated`, `session["user_id"]`; Django `@login_required`,
  `@permission_required`, `@user_passes_test`, `LoginRequiredMixin` and other auth mixins,
  `request.user.is_authenticated`, `LoginRequiredMiddleware` (Django 5.1+, honouring
  `@login_not_required`); DRF `permission_classes` and `DEFAULT_PERMISSION_CLASSES`.
- **Your own helpers**: `--auth-fn NAME` (repeatable) adds names that count as an auth check when
  called, used as middleware or decorator, or passed to `Depends()`.

A route whose handler is wrapped by a middleware or wrapper the tool does not recognise (for
example `app.post(path, tenantScope, handler)` or `export const POST = withTenant(...)`), or whose
handler lives in a package it cannot see, is never reported as unauthenticated: it shows as
`unknown` in the route list.

### Routes that are public by design (skipped by RAC001 / RAC003)

A route is treated as public when its path, or its function / action name, contains one of these
words: `login`, `logout`, `signin`, `signout`, `signup`, `register`, `registration`, `auth`, `oauth`,
`callback`, `sso`, `saml`, `nextauth`, `token`, `webhook(s)`, `hook(s)`, `health`, `healthz`,
`healthcheck`, `ping`, `ready`, `readiness`, `liveness`, `livez`, `readyz`, `csrf`, `otp`, `captcha`,
`contact`, `newsletter`, `subscribe`, `unsubscribe`, `waitlist`, `feedback`, `checkout` (guest
checkout), `track`, `analytics`,
`telemetry`, `beacon`, `vitals`, `search`, `public`, `graphql`, `trpc`, `inngest`, `uploadthing`; or
the pairs sign-in, sign-up, log-in, forgot-password, reset-password, password-reset,
verify-email, confirm-email, magic-link, verify-otp, refresh-token, csp-report. GraphQL / tRPC
endpoints are skipped because their auth lives in resolvers / procedures. GET (and HEAD) routes
are only reported when they look like admin routes; reading by id without an owner check is
RAC002, which needs an authenticated route. Public routes are still checked by RAC006 for a
role taken from the request (anyone can sign up as `role: "admin"`) and by RAC007 / RAC008.

`node_modules`, `.git`, virtualenvs, build output (`.next`, `dist`, ...), Django migrations and
test / fixture / mock folders and files are skipped (use `--include-tests` to scan tests,
`--exclude GLOB` to skip more).

## What it does not check

Be clear about the limits before relying on it:

- **It is not a penetration test** and gives **no guarantee**. A clean report means "none of
  these known patterns were found", nothing more. It does not prove that a check is correct:
  `if (session)` with the wrong secret, an expired-token bug or a broken RLS policy all look
  "protected".
- **Auth is recognised by name and shape.** A helper called `getUser(id)` that only loads a
  record counts as an auth check; a real check under an unusual name is missed (use `--auth-fn`).
  Auth done in code the tool cannot see (an npm package, a gateway, a reverse proxy, Vercel / Cloud
  Run IAM, an API Gateway authorizer) is invisible: those routes will be reported, and you should
  suppress them with a comment or `--exclude`.
- **Cross-file analysis is limited**: Express / Hono / Fastify mounts and imported handlers and
  helpers are followed one level through relative or `@/` / `~/` imports; dynamic route loading,
  routes built in loops or from config, decorators-based controllers (NestJS) and re-exports
  through barrels are not. FastAPI routers are matched to `include_router` by module name; Flask
  blueprints protected from another file are not seen.
- **RAC002 (IDOR) is a heuristic.** It needs the id to visibly come from the request in the same
  handler and the query to use a recognised ORM call. Raw SQL, query builders other than those
  listed, repository / service layers more than one call away, and ids passed through several
  variables may be missed. Any comparison involving an owner-like field and the session, any 403,
  or any permission helper silences it for the whole handler. Records that are intentionally
  shared within a team are reported if the query does not mention the team / org.
- **Supabase** routes that use the anon / user client are assumed to be protected by Row Level
  Security; the tool cannot check your RLS policies.
- **RAC004** only knows Next.js middleware and the auth libraries listed above. It does not
  evaluate custom logic in the middleware body beyond `startsWith(...)` skips.
- **RAC005** relies on route names and paths (`/admin`, `internal`), user-listing calls and role
  writes; an admin endpoint with an innocent name is not recognised.
- **RAC008** sees a body as validated as soon as it goes through any function call; a schema that
  allows extra keys (`.passthrough()`, `extra = "allow"`) is not detected.
- **TypeScript / JavaScript is analysed without a full parser** (comments and strings are lexed
  out, then patterns are matched). Unusual code shapes may be missed. Python uses the real `ast`
  module.
- **Not supported yet:** NestJS guards, SvelteKit / Remix / Nuxt / Astro endpoints, tRPC
  procedures, GraphQL resolvers, Go, Ruby, PHP, Java, C#.

## How to fix each finding

`route-auth-check rules` prints all of this. Every finding in a report carries its own fix with
the framework, route, model and variable names filled in.

**RAC001 - no auth.** Check the session first and return 401 without one:

```ts
// Next.js App Router
const session = await auth();          // or getServerSession(authOptions), Clerk auth(), supabase.auth.getUser()
if (!session?.user) return new Response("Unauthorized", { status: 401 });
```
```python
# FastAPI
@router.post("/notes")
def create_note(payload: NoteIn, current_user: User = Depends(get_current_user)): ...
```

Express: `router.post(path, requireAuth, handler)`; Hono: `app.use("/api/*", jwt({ secret, alg: "HS256" }))`;
Fastify: `{ onRequest: [fastify.authenticate] }`; Flask: `@login_required` / `@jwt_required()`;
Django: `@login_required` / `LoginRequiredMixin`; DRF: `permission_classes = [IsAuthenticated]`.

**RAC002 - IDOR.** Put the owner into the query, so another user's record is not found (404):
`prisma.post.delete({ where: { id, authorId: session.user.id } })`,
`.where(and(eq(posts.id, id), eq(posts.userId, userId)))`, `Post.findOneAndDelete({ _id: id, owner: req.user.id })`,
`get_object_or_404(Post, pk=pk, owner=request.user)`, DRF `get_queryset()` filtered by `self.request.user`.

**RAC003 - Server Action.** `const session = await auth(); if (!session?.user) throw new Error("Unauthorized");`
inside every action, and take the user id from the session, never from the arguments.

**RAC004 - middleware.** Include `/(api|trpc)(.*)` in the matcher; with Clerk call
`auth.protect()` for every non-public route; keep the checks in the handlers too.

**RAC005 - admin without role.** Check the role from the session / database:
`if (session.user.role !== "admin") return 403`, Clerk `has({ role: "org:admin" })`, FastAPI
`require_admin` dependency, DRF `IsAdminUser`, Django `@user_passes_test(lambda u: u.is_staff)`.

**RAC006 - identity from the request.** Use `session.user.id` / `req.user.id` / `current_user.id`
/ `request.user`; never accept `role` on signup or profile updates.

**RAC007 - CORS.** An explicit allowlist of your own origins.

**RAC008 - mass assignment.** Validate with a schema that strips unknown keys (zod `object()`,
Pydantic models without owner / role fields, Django forms / serializers with an explicit `fields`
list) and set the owner from the session.

## Suppressing a finding

Add `route-auth-check: ignore` as a comment on the reported line (works in Python and JS/TS):

```ts
app.post("/internal/reindex", reindex); // route-auth-check: ignore  (only reachable inside the VPC)
```

To turn a rule off for a whole run: `--disable RAC008` (repeatable). To hide medium and lower:
`--min-severity high`. To teach it your auth helper: `--auth-fn requireMember`.

## Use in CI

See [`examples/github-actions/route-auth-check.yml`](examples/github-actions/route-auth-check.yml).
It runs on every pull request, fails the build on High findings, and uploads the JSON report as
an artifact.

## JSON output

`--json` prints (two routes and one finding shown, from the demo project):

```json
{
  "tool": "route-auth-check",
  "version": "0.1.1",
  "targets": [
    "/abs/path/demo-routes"
  ],
  "files_scanned": 15,
  "routes": [
    {
      "file": "api/django_views.py",
      "line": 10,
      "route": "delete_account()",
      "framework": "django",
      "kind": "route",
      "methods": [
        "POST"
      ],
      "auth": null,
      "status": "unprotected"
    },
    {
      "file": "api/django_views.py",
      "line": 16,
      "route": "invoice_detail()",
      "framework": "django",
      "kind": "route",
      "methods": [
        "ALL"
      ],
      "auth": "@login_required",
      "status": "protected"
    }
  ],
  "skipped": [],
  "exit_code": 1,
  "summary": {
    "critical": 0,
    "high": 28,
    "medium": 11,
    "low": 0,
    "info": 0
  },
  "findings": [
    {
      "rule_id": "RAC006",
      "severity": "high",
      "message": "delete_account() takes the acting user's id from the request (request.POST['user_id'], request body) instead of the session: anyone can act as, or write data for, any user by changing it.",
      "file": "api/django_views.py",
      "line": 12,
      "evidence": "User.objects.filter(id=request.POST[\"user_id\"]).delete()",
      "heuristic": false,
      "extra": {
        "lang": "py",
        "framework": "django",
        "route": "delete_account()",
        "method": "POST",
        "path": "",
        "name": "delete_account",
        "session": "request.user",
        "owner": "user",
        "recv": "",
        "local_path": "",
        "kind": "user-id",
        "expr": "request.POST['user_id']",
        "key": "user_id",
        "written": true,
        "source": "body"
      },
      "title": "User id or role taken from the request instead of the session",
      "why": "The body, query string and headers are written by the caller. A handler that takes the acting user's id (body.userId, ?user_id=, an X-User-Id header) or their role / isAdmin flag from the request lets anyone act as any user or as an admin by editing one field. The user's identity must come from the verified session or token.",
      "fix": "Use the authenticated user instead of request.POST['user_id']:\n\n  request.user\n\nRemove the user id field from the request schema so it cannot be sent at all."
    }
  ]
}
```

`status` is `protected`, `public` (public by design, or a read-only route), `unprotected`, or
`unknown` (behind middleware or code the tool cannot see into).

`"skipped"` lists Python files that could not be parsed (`{"path": ..., "reason": "syntax error
line 12"}`). Such files are never treated as clean: each is also reported on stderr
(`warning: api/views.py: syntax error line 12; file not scanned`) and counted in the text
header. They do not change the exit code.

## Development

```bash
pip install -e ".[test]"
pytest
```

Test fixtures never contain real or real-looking secrets: fake keys are assembled at runtime in
`tests/conftest.py`. Every rule has tests for code that must be reported and for correctly
protected code that must not be; `tests/fixtures/*_clean` must stay free of findings.

## License

MIT, Copyright (c) 2026 Abheesht Tripathi. See [LICENSE](LICENSE).

---

**More open-source checks from the same author:** [mcp-audit](https://github.com/abhi12337/mcp-audit) · [rules-file-audit](https://github.com/abhi12337/rules-file-audit) · [inject-test](https://github.com/abhi12337/inject-test) · [supa-launch-check](https://github.com/abhi12337/supa-launch-check) · [firebase-launch-check](https://github.com/abhi12337/firebase-launch-check) · [key-leak-check](https://github.com/abhi12337/key-leak-check) · [webhook-check](https://github.com/abhi12337/webhook-check) · [llm-cost-lint](https://github.com/abhi12337/llm-cost-lint) · [pg-launch-check](https://github.com/abhi12337/pg-launch-check). Overview and research: [github.com/abhi12337](https://github.com/abhi12337)

Questions, or want a review of your API's authentication and authorization before you launch? abheeshttripathi890@gmail.com
