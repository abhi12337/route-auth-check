"""Language-independent rules: turn a Route (with its Facts and outside protection) into findings."""

from __future__ import annotations

import re

from .common import Route, admin_reason, public_reason
from .findings import Finding

SESSION_EXPR = {
    "next-app": "session.user.id", "next-pages": "session.user.id", "server-action": "session.user.id",
    "express": "req.user.id", "koa": "ctx.state.user.id", "node": "req.user.id", "hono": 'c.get("jwtPayload").sub',
    "fastify": "request.user.id", "fastapi": "current_user.id", "flask": "current_user.id",
    "django": "request.user", "drf": "request.user",
}
SOURCES = {"body": "request body", "query": "query string", "form": "form data", "arg": "an action argument",
           "header": "a header"}
VERB = {"read": "reads", "update": "updates", "delete": "deletes"}
OWNER_COLS = ["authorId", "ownerId", "userId", "createdById", "author_id", "owner_id", "user_id", "created_by_id"]


def _owner_guess(text: str, lang: str, framework: str) -> str:
    for c in OWNER_COLS:
        if re.search(r"\b" + c + r"\b", text):
            if framework in ("django", "drf") and c.endswith("_id"):
                return c[:-3]
            return c
    return {"django": "owner", "drf": "owner"}.get(framework, "user_id" if lang == "py" else "userId")


def evaluate(route: Route, ctx: dict) -> list[Finding]:
    f = route.facts
    out: list[Finding] = []
    mw_auth = route.meta.get("mw_auth", [])
    ext = route.meta.get("ext_auth", [])
    late = route.meta.get("mw_ext", [])         # Next.js middleware: shown after an in-handler check
    route.auth = (mw_auth[0] if mw_auth else None) or (ext[0] if ext else None) or f.auth or (late[0] if late else None)
    role = (route.meta.get("mw_role") or [None])[0] or f.role_check
    route.role_check = role
    name_for_public = route.name if route.framework not in ("next-app", "next-pages") else None
    public = public_reason(route.path, name_for_public)
    role_written = [s for s in f.trusted if s.detail.get("kind") == "role" and s.detail.get("written")]
    admin = admin_reason(route.path, route.name) or f.admin_reason or \
        ("sets a user's role from the request" if role_written and route.auth else None)
    fw = route.framework
    sess = SESSION_EXPR.get(fw, "the session user's id")
    owner = _owner_guess(ctx.get("file_text", {}).get(route.file, ""), route.lang, fw)
    base = {"lang": route.lang, "framework": fw, "route": route.label, "method": (route.methods or ["POST"])[0],
            "path": route.path or "", "name": route.name or "", "session": sess, "owner": owner,
            "recv": route.meta.get("recv") if route.meta.get("recv") not in (None, "?") else "",
            "local_path": route.meta.get("local_path", route.path or "")}

    def add(rule, sev, msg, file, line, evidence, heuristic=False, **extra):
        out.append(Finding(rule, sev, msg, file, line, evidence, heuristic=heuristic, extra={**base, **extra}))

    if route.auth:
        route.status = "protected"
    elif route.opaque:
        route.status = "unknown"
    elif public or not (route.state_changing or admin):
        route.status = "public"
    else:
        route.status = "unprotected"

    # RAC003 / RAC001: no authentication at all
    if route.kind == "action":
        if not route.auth and not public and (f.writes or f.idor):
            note = (" middleware.ts matches every page, which may stop anonymous calls, but Next.js recommends "
                    "checking auth inside every action.") if ctx.get("mw_all") else ""
            add("RAC003", "high",
                f"Server action {route.name}() changes data and never checks the session: it is a public POST endpoint "
                f"that anyone can call directly, with any arguments.{note}",
                route.file, route.line, route.evidence)
    elif not route.auth and not route.opaque and not public and (route.state_changing or admin):
        mw = route.meta.get("mw_note", "")
        drf = route.meta.get("drf_default")
        if admin and not route.state_changing:
            what = f"looks like an admin endpoint ({admin}) and has no authentication check at all"
        else:
            ms = "/".join(m for m in route.methods if m in ("POST", "PUT", "PATCH", "DELETE", "ALL")) or "POST"
            what = (f"accepts {ms} requests" + (f" (it {admin})" if admin and admin.startswith(("lists", "sets")) else "") +
                    " and never checks who is calling")
        if drf:
            tail = (": DRF's default permission is AllowAny and no permission_classes are set here or in "
                    "REST_FRAMEWORK['DEFAULT_PERMISSION_CLASSES'] in the scanned files")
        else:
            tail = " (no session, token or auth middleware found" + (f"; {mw}" if mw else "") + ")"
        add("RAC001", "high", f"{route.label} {what}{tail}. Anyone can call it with curl.",
            route.file, route.line, route.evidence, drf=bool(drf))

    # RAC005: authenticated admin route without a role check
    if route.auth and admin and not role:
        add("RAC005", "high",
            f"{route.label} is an admin endpoint ({admin}) and checks that the caller is signed in ({route.auth}) but "
            f"not their role: every user who can create an account can call it.",
            route.file, route.line, route.evidence, heuristic=True, admin=admin)

    admin_ok = bool(admin and role)
    # RAC002: IDOR
    if route.auth and not admin and not role and not f.owner_check:
        for s in f.idor:
            d = s.detail
            what = "records" if d.get("drf") else "records by changing the id"
            add("RAC002", "high",
                f"{route.label} {VERB[d['op']]} {d['model']} by an id from the request ({d['id']}) without checking that "
                f"it belongs to the caller: any signed-in user can {d['op']} other users' {d['model']} {what}.",
                s.file, s.line, s.evidence, heuristic=True, **d)

    # RAC006: identity / role from the request
    for s in f.trusted:
        d = s.detail
        k = d.get("kind")
        if admin_ok:
            continue
        if k == "header":
            if d.get("header") in ctx.get("mw_headers", set()) and route.meta.get("mw_covered"):
                continue
            msg = (f"{route.label} takes the caller's identity or role from the {d['header']} header. Clients can send "
                   f"any header, so anyone can claim to be any user (or an admin) unless a proxy you control always "
                   f"overwrites it.")
        elif k == "user-id":
            if public:
                continue
            msg = (f"{route.label} takes the acting user's id from the request ({d['expr']}, {SOURCES.get(d['source'], d['source'])}) instead of "
                   f"the session: anyone can act as, or write data for, any user by changing it.")
        else:
            if d.get("written") and route.auth:
                continue                     # reported as RAC005 (role change without a role check)
            how = "writes it to the user record" if d.get("written") else "uses it to decide what the caller may do"
            msg = (f"{route.label} takes the role from the request ({d['expr']}) and {how}: anyone can make "
                   f"themselves an admin by sending role=admin.")
        add("RAC006", "high", msg, s.file, s.line, s.evidence, **d)

    # RAC008: mass assignment
    for s in f.mass:
        d = s.detail
        add("RAC008", "medium",
            f"{route.label} passes {'a whole action argument' if route.kind == 'action' else 'the whole request body'} "
            f"({d['expr']}) to {d['sink']}: the caller can set any column, "
            f"including role / isAdmin / {owner} / plan, not just the fields your form sends.",
            s.file, s.line, s.evidence, **d)
    return out


def middleware_findings(mw, routes: list[Route]) -> list[Finding]:
    """RAC004: an auth middleware whose matcher leaves state-changing API routes uncovered."""
    out = []
    if mw.auth is None:
        return out
    uncovered = [r for r in routes if r.status == "unprotected" and r.kind == "route" and r.state_changing and
                 r.framework in ("next-app", "next-pages") and r.file.startswith(mw.root)]
    if not uncovered:
        return out
    labels = ", ".join(r.label for r in uncovered[:3]) + (f" and {len(uncovered) - 3} more" if len(uncovered) > 3 else "")
    extra = {"lang": "js", "framework": "next-middleware", "clerk": mw.clerk_protect == "none",
             "excludes_api": bool(mw.matchers and any("?!" in m and "api" in m for m in mw.matchers))}
    if mw.clerk_protect == "none":
        msg = (f"clerkMiddleware() is used without auth.protect(): it makes the session available but protects no "
               f"route, so {labels} {'is' if len(uncovered) == 1 else 'are'} open (no check in the handler either).")
        line = mw.clerk_line or mw.line
    elif extra["excludes_api"]:
        msg = (f"The middleware matcher excludes /api, so its auth check never runs for API routes; {labels} "
               f"{'has' if len(uncovered) == 1 else 'have'} no check of {'its' if len(uncovered) == 1 else 'their'} own.")
        line = mw.line
    else:
        msg = (f"The middleware ({mw.auth}) does not cover {labels}, which change data and have no auth check of "
               f"their own.")
        line = mw.line
    from .findings import redact_line
    text = mw.text.splitlines() if hasattr(mw, "text") else []
    ev = redact_line(text[line - 1]) if 0 < line <= len(text) else ""
    out.append(Finding("RAC004", "medium", msg, mw.file, line, ev, heuristic=True, extra=extra))
    return out
