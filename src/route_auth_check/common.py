"""Shared vocabulary: what counts as an auth check, a public route, an owner column, a role
check, and the Route / Site model that the language scanners fill in."""

from __future__ import annotations

import re
from dataclasses import dataclass, field

STATE_METHODS = {"POST", "PUT", "PATCH", "DELETE", "ALL"}

# ---------------------------------------------------------------- auth recognition
# Calls that establish who the caller is. Matched as `name(`; recognised conservatively:
# anything that looks like an auth helper counts, so a route is only reported when there
# is no sign of a check at all.
AUTH_CALL_NAMES = {
    "getServerSession", "unstable_getServerSession", "getSession", "getIronSession", "getToken", "getAuth", "auth",
    "currentUser", "getKindeServerSession", "validateRequest", "jwtVerify", "verifyIdToken", "verifySessionCookie",
    "withApiAuthRequired", "withPageAuthRequired", "getAccessToken", "authenticate", "authenticateRequest",
    "ensureAuthenticated", "ensureLoggedIn", "isAuthenticated", "isLoggedIn", "checkAuth", "verifyAuth",
    "verifySession", "getClaims", "requireAuth", "requireUser", "requireSession", "getUserFromRequest",
}
AUTH_NAME_RE = re.compile(
    r"(?:get|require|ensure|check|verify|validate|assert|authenticate|authorize|authorise|protect|with|is|has|current)?_?"
    r"(?:server_?)?(?:current_?|logged_?in_?|signed_?in_?|authenticated_?|valid_?|active_?|session_?|auth_?|request_?)?"
    r"(?:user|session|auth|viewer|token|jwt|claims|principal|identity|login|me|admin|authenticated|authed|"
    r"logged_?in|signed_?in)"
    r"(?:_?(?:or_?throw|or_?401|or_?redirect|or_?fail|from_?\w+|session|id|or_?null|required|guard|middleware|check|"
    r"handler|or_?error))?",
    re.I,
)
# Names that look like auth but are data access or plumbing.
NOT_AUTH_NAMES = re.compile(
    r"^(?:get_?db|get_?session_?local|get_?async_?session|get_?settings|create_?user|update_?user|delete_?user|"
    r"get_?user_?by\w*|get_?users|find_?user\w*|list_?users|getSessionStorage|commitSession|destroySession|"
    r"clerkMiddleware|useSession|useUser|useAuth|signIn|signOut|signUp)$",
    re.I,
)
# Middleware / decorator / dependency names (searched, not full-matched).
MW_AUTH_RE = re.compile(
    r"auth|jwt|token|login|logged|session|protect|guard|secure|signed|passport|clerk|isUser|verifyUser|admin|"
    r"role|permission|perm|acl|rbac|ensure|restrict|current_?user|require_?user|bearer|api_?key|firebase|supabase",
    re.I,
)
ROLE_NAME_RE = re.compile(r"admin|role|permission|perm\b|acl|rbac|staff|superuser|restrictTo|authori[sz]e|owner",
                          re.I)

# ---------------------------------------------------------------- route classification
PUBLIC_WORDS = {
    "login", "logout", "signin", "signout", "signup", "register", "registration", "auth", "oauth", "oauth2",
    "callback", "callbacks", "sso", "saml", "webhook", "webhooks", "hook", "hooks", "health", "healthz",
    "healthcheck", "ping", "ready", "readiness", "liveness", "livez", "readyz", "csrf", "otp", "contact",
    "newsletter", "subscribe", "unsubscribe", "waitlist", "feedback", "captcha", "nextauth", "token",
    "checkout", "track", "analytics", "telemetry", "beacon", "vitals", "search", "public", "graphql", "trpc", "inngest",
    "uploadthing",
}
PUBLIC_PAIRS = {("sign", "in"), ("sign", "out"), ("sign", "up"), ("log", "in"), ("log", "out"),
                ("forgot", "password"), ("reset", "password"), ("password", "reset"), ("verify", "email"),
                ("confirm", "email"), ("magic", "link"), ("refresh", "token"), ("verify", "otp"), ("csp", "report")}
ADMIN_WORDS = {"admin", "admins", "internal", "staff", "superadmin", "superuser", "backoffice", "sudo"}


def words(text: str) -> list[str]:
    """Lower-case words of a path or identifier: '/api/sign-up/[id]' -> ['api','sign','up','id'];
    'handleStripeWebhook' -> ['handle','stripe','webhook']."""
    text = re.sub(r"([a-z0-9])([A-Z])", r"\1 \2", text or "")
    return [w for w in re.split(r"[^A-Za-z0-9]+", text.lower()) if w]


def _hit(ws: list[str], vocab: set[str], pairs: set[tuple[str, str]] = frozenset()) -> str | None:
    for w in ws:
        if w in vocab:
            return w
    for a, b in zip(ws, ws[1:]):
        if (a, b) in pairs:
            return f"{a}-{b}"
    return None


def public_reason(path: str | None, name: str | None) -> str | None:
    """Why a route is public by design (login, webhooks, health, ...), or None."""
    for src in (path, name):
        if src:
            w = _hit(words(src), PUBLIC_WORDS, PUBLIC_PAIRS)
            if w:
                return w
    return None


def admin_reason(path: str | None, name: str | None) -> str | None:
    for src in (path, name):
        if src:
            w = _hit(words(src), ADMIN_WORDS)
            if w:
                return f"'{w}' in the {'path' if src == path else 'name'}"
    return None


# ---------------------------------------------------------------- ownership / identity vocabulary
USER_KEYS = (
    "userId|user_id|ownerId|owner_id|authorId|author_id|createdBy|created_by|createdById|created_by_id|creatorId|"
    "creator_id|tenantId|tenant_id|orgId|org_id|organizationId|organization_id|teamId|team_id|workspaceId|"
    "workspace_id|accountId|account_id|memberId|member_id|profileId|profile_id|customerId|customer_id|clerkId|"
    "clerk_id|clerkUserId|uid|owner|author|user|creator|members|tenant|organization|team|workspace"
)
USER_KEY_RE = re.compile(r"(?<![\w$])(?:" + USER_KEYS + r")(?![\w$])")
TRUST_ID_KEYS = {"userId", "user_id", "uid", "ownerId", "owner_id", "authorId", "author_id", "createdBy",
                 "created_by", "creatorId", "creator_id", "currentUserId", "current_user_id", "clerkId", "clerkUserId",
                 "actorId", "actor_id"}
ROLE_KEYS = {"role", "roles", "isAdmin", "is_admin", "isStaff", "is_staff", "is_superuser", "isSuperuser",
             "isSuperAdmin", "userRole", "user_role", "permissions"}
IDENTITY_HEADERS = {"x-user-id", "x-userid", "x-user", "x-user-email", "x-user-role", "x-role", "x-admin",
                    "x-is-admin", "x-uid", "x-account-id", "x-auth-user", "x-auth-user-id", "x-tenant-id",
                    "x-org-id"}
SESSIONISH_RE = re.compile(
    r"\b(?:session|currentUser|current_user|viewer|claims|decoded|payload|token|auth|me|req\.user|request\.user|"
    r"g\.user|user\.id|user\.sub|user\.uid|userId|user_id|sub|uid)\b"
)


@dataclass
class Site:
    """A location inside a handler that a rule reports (data access, trusted id, ...)."""
    file: str
    line: int
    evidence: str
    detail: dict = field(default_factory=dict)


@dataclass
class Facts:
    """What a handler's code does, computed by the language scanner."""
    auth: str | None = None             # e.g. "getServerSession()"
    role_check: str | None = None
    owner_check: str | None = None      # handler-wide ownership signal (comparison, 403, can())
    writes: bool = False
    touches: bool = True                # calls a data layer / API / awaits something (False: pure endpoint)
    idor: list[Site] = field(default_factory=list)
    trusted: list[Site] = field(default_factory=list)     # detail: kind = user-id | role | header, written
    mass: list[Site] = field(default_factory=list)
    admin_reason: str | None = None


@dataclass
class Route:
    file: str
    line: int
    lang: str                 # js | py
    framework: str            # next-app, next-pages, server-action, express, hono, fastify, fastapi, flask, django, drf
    methods: list[str]
    path: str | None
    label: str
    kind: str = "route"       # route | action
    name: str | None = None   # handler / action / view name
    auth: str | None = None   # what protects it (in-handler, middleware, decorator, router, settings)
    role_check: str | None = None
    opaque: bool = False      # behind middleware / code the tool cannot see: never reported as unauthenticated
    evidence: str = ""
    facts: Facts = field(default_factory=Facts)
    status: str = ""          # filled in by evaluate(): protected / public / unprotected / unknown
    meta: dict = field(default_factory=dict, repr=False)   # scanner-private data (spans, router, ...)

    @property
    def state_changing(self) -> bool:
        if self.kind == "action":
            return True
        ms = {m.upper() for m in self.methods}
        if ms & {"PUT", "PATCH", "DELETE"}:
            return True
        if "POST" in ms:
            return self.facts.touches
        return "ALL" in ms and self.facts.writes

    def to_dict(self) -> dict:
        return {"file": self.file, "line": self.line, "route": self.label, "framework": self.framework,
                "kind": self.kind, "methods": self.methods, "auth": self.auth, "status": self.status}
