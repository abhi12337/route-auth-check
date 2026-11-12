"""Node / TypeScript: route discovery and per-handler analysis.

Routes are found as Next.js App Router `export async function POST` (and GET/PUT/PATCH/DELETE)
in app/**/route.ts, Next.js pages/api default exports, Server Actions ("use server" files and
inline "use server" functions), and `app.post("/path", ...)` style registrations (Express,
Hono, Fastify, Koa-style routers), plus `app.use(...)` / `app.route(...)` / `register(...)`
calls so that router-level middleware and mount prefixes can be applied across files.
Everything works on a lexed copy of the source (see jslex): patterns never match inside
comments or strings unless they deliberately read string contents."""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from .common import (AUTH_CALL_NAMES, AUTH_NAME_RE, IDENTITY_HEADERS, MW_AUTH_RE, NOT_AUTH_NAMES, ROLE_KEYS,
                     ROLE_NAME_RE, SESSIONISH_RE, TRUST_ID_KEYS, USER_KEY_RE, USER_KEYS, Facts, Route, Site)
from .findings import Finding, redact_line
from .jsfn import IDENT, KEYWORDS, Fn, _body_after_params, find_functions, stmt_end
from .jslex import lex, match_close, split_args

APP_ROUTE_RE = re.compile(r"(?:^|/)app/(?:(.*)/)?route\.(?:ts|js|mts|mjs|tsx|jsx)$")
PAGES_API_RE = re.compile(r"(?:^|/)pages/api/(.+)\.(?:ts|js|mts|mjs|tsx|jsx)$")
MIDDLEWARE_FILE_RE = re.compile(r"(?:^|/)(?:middleware|proxy)\.(?:ts|js|mts|mjs)$")
HTTP_METHODS = ("GET", "POST", "PUT", "PATCH", "DELETE")
HTTP_CLIENTS = {"axios", "ky", "got", "superagent", "supertest", "request", "agent", "wretch", "$http", "http", "https",
                "fetcher", "apiClient", "httpClient", "params", "searchParams", "headers",
                "cookies", "formData", "map", "cache", "store", "redis", "localStorage", "sessionStorage", "Object",
                "Reflect", "res", "response", "Promise", "url", "URL", "kv", "storage"}
BENIGN_MW_RE = re.compile(
    r"^(?:(?:express|bodyParser|body_parser)\.\w+|json|raw|text|urlencoded|cors|helmet|morgan|compression|compress|"
    r"cookieParser|multer|upload(?:\.\w+)?|asyncHandler|catchAsync|asyncWrapper|wrapAsync|tryCatch|catchErrors|"
    r"asyncMiddleware|withErrorHandler|errorHandler|handleErrors?|rateLimit\w*|\w*[lL]imiter|logger|requestLogger|"
    r"bodyLimit|zValidator|validator|validate\w*|validation\w*|celebrate|check|body|param|query|sanitize\w*|"
    r"handleValidationErrors|cache\w*|timeout|etag|secureHeaders|prettyJSON|poweredBy|logger|tsr|"
    r"clerkMiddleware|withMiddleware|withLogging|withSentry\w*|withErrorHandling)$"
)
ROUTER_CTOR_RE = re.compile(r"(?:express\s*\.\s*Router|Router|new\s+Hono|new\s+Router|new\s+KoaRouter|Hono)\s*(?:<[^>()]*>)?\s*\(")


@dataclass
class Use:
    """`recv.use(...)`, `recv.route(prefix, sub)`, `recv.register(plugin, {prefix})` or `recv.addHook(...)`."""
    off: int
    recv: str
    prefix: str | None
    items: list[tuple[str, str, int, int]]  # (kind, text, a, b): kind = ident | call | fn | array | object
    kind: str = "use"                       # use | route | register | hook
    anywhere: bool = False                  # Fastify hooks apply regardless of order


@dataclass
class MwInfo:
    """A Next.js middleware.ts / proxy.ts."""
    file: str
    root: str                       # project folder the middleware belongs to
    line: int                       # line of the matcher (or of the middleware export)
    matchers: list[str] | None      # None = every path
    auth: str | None                # what it uses to authenticate, or None
    clerk_protect: object = None    # None (not Clerk) | "none" | "all" | ("only", pats) | ("except", pats)
    clerk_line: int = 0
    skips: list[str] = field(default_factory=list)          # pathname.startsWith("/x") -> NextResponse.next()
    sets_headers: set[str] = field(default_factory=set)

    def covers(self, path: str) -> bool:
        if not self.auth:
            return False
        sample = sample_path(path)
        if self.matchers is not None and not any(_match(p, sample) for p in self.matchers):
            return False
        if any(sample == s or sample.startswith(s.rstrip("/") + "/") for s in self.skips):
            return False
        cp = self.clerk_protect
        if cp == "none":
            return False
        if isinstance(cp, tuple):
            hit = any(_match(p, sample) for p in cp[1])
            return hit if cp[0] == "only" else not hit
        return True


def sample_path(path: str) -> str:
    p = re.sub(r"\[\[\.\.\.[^\]]+\]\]", "a/b", path)
    p = re.sub(r"\[\.\.\.[^\]]+\]", "a/b", p)
    p = re.sub(r"\[[^\]]+\]", "1", p)
    p = re.sub(r":\w+[?*+]?", "1", p)
    return p or "/"


def matcher_regex(pat: str) -> str:
    """Next.js / Clerk path-to-regexp style matcher -> Python regex (full match)."""
    out, i, n = "", 0, len(pat)
    while i < n:
        c = pat[i]
        if c == ":":
            m = re.match(r":(\w+)([*+?])?", pat[i:])
            if m:
                slash = out.endswith("/")
                if slash:
                    out = out[:-1]
                seg = "/[^/]+" if slash else "[^/]+"
                mod = m.group(2) or ""
                out += f"(?:{seg})*" if mod == "*" else f"(?:{seg})+" if mod == "+" else f"(?:{seg})?" if mod == "?" else seg
                i += m.end()
                continue
        if c == "(":
            depth, j = 0, i
            while j < n:
                if pat[j] == "\\":
                    j += 2
                    continue
                if pat[j] == "(":
                    depth += 1
                elif pat[j] == ")":
                    depth -= 1
                    if depth == 0:
                        break
                j += 1
            out += pat[i:j + 1]
            i = j + 1
            continue
        if c == "*":
            out += ".*"
        elif c == "\\" and i + 1 < n:
            out += pat[i:i + 2]
            i += 2
            continue
        else:
            out += re.escape(c)
        i += 1
    return out


def _match(pat: str, path: str) -> bool:
    try:
        return re.fullmatch(matcher_regex(pat), path) is not None or \
            re.fullmatch(matcher_regex(pat), path.rstrip("/") or "/") is not None
    except re.error:
        return True          # cannot read it: assume it matches (no false alarm)


# ---------------------------------------------------------------- file model
class JsFile:
    def __init__(self, rel: str, text: str):
        self.rel = rel
        self.text = text
        self.lines = text.splitlines()
        self.clean, self.code = lex(text)
        self.fns = find_functions(self.code)
        self.by_name: dict[str, list[Fn]] = {}
        for f in self.fns:
            if f.name:
                self.by_name.setdefault(f.name, []).append(f)
        self._nl = [i for i, c in enumerate(text) if c == "\n"]
        self.framework = self._framework()
        self.imports = self._imports()
        self.routers = set(re.findall(r"(?:const|let|var)\s+(" + IDENT + r")\s*(?::[^=;]+)?=\s*" + ROUTER_CTOR_RE.pattern,
                                      self.code))
        self.routes: list[Route] = []
        self.uses: list[Use] = []
        self.findings: list[Finding] = []
        self.middleware: MwInfo | None = None

    def _framework(self) -> str:
        if APP_ROUTE_RE.search(self.rel):
            return "next-app"
        if PAGES_API_RE.search(self.rel):
            return "next-pages"
        for fw, rx in (("hono", r"""['"]hono(?:/[\w-]+)?['"]"""), ("fastify", r"""['"]fastify['"]|\bfastify\s*\."""),
                       ("express", r"""['"]express['"]"""), ("koa", r"""['"](?:koa|@koa/router|koa-router)['"]""")):
            if re.search(rx, self.clean):
                return fw
        return "node"

    def _imports(self) -> dict[str, tuple[str, str]]:
        imp: dict[str, tuple[str, str]] = {}
        c = self.clean
        for m in re.finditer(r"import\s+(?:type\s+)?(" + IDENT + r")\s*(?:,\s*\{[^}]*\})?\s+from\s*['\"]([^'\"]+)['\"]", c):
            imp[m.group(1)] = (m.group(2), "default")
        for m in re.finditer(r"import\s+(?:type\s+)?(?:" + IDENT + r"\s*,\s*)?\{([^}]*)\}\s*from\s*['\"]([^'\"]+)['\"]", c):
            for part in m.group(1).split(","):
                bits = part.replace("type ", "").split(" as ")
                if bits[0].strip():
                    imp[bits[-1].strip()] = (m.group(2), bits[0].strip())
        for m in re.finditer(r"import\s+\*\s+as\s+(" + IDENT + r")\s+from\s*['\"]([^'\"]+)['\"]", c):
            imp[m.group(1)] = (m.group(2), "*")
        for m in re.finditer(r"(?:const|let|var)\s+(" + IDENT + r")\s*=\s*require\(\s*['\"]([^'\"]+)['\"]\s*\)", c):
            imp[m.group(1)] = (m.group(2), "*")
        for m in re.finditer(r"(?:const|let|var)\s*\{([^}]*)\}\s*=\s*require\(\s*['\"]([^'\"]+)['\"]\s*\)", c):
            for part in m.group(1).split(","):
                bits = part.split(":")
                if bits[0].strip():
                    imp[bits[-1].strip()] = (m.group(2), bits[0].strip())
        return imp

    def line_of(self, off: int) -> int:
        lo, hi = 0, len(self._nl)
        while lo < hi:
            mid = (lo + hi) // 2
            if self._nl[mid] < off:
                lo = mid + 1
            else:
                hi = mid
        return lo + 1

    def line_text(self, line: int) -> str:
        return self.lines[line - 1] if 0 < line <= len(self.lines) else ""

    def ev(self, off: int) -> str:
        return redact_line(self.line_text(self.line_of(off)))

    def exported_fn(self, name: str) -> Fn | None:
        fs = self.by_name.get(name, [])
        return fs[0] if fs else None


def _string_at(clean: str, i: int) -> str | None:
    while i < len(clean) and clean[i] in " \t\r\n":
        i += 1
    if i < len(clean) and clean[i] in "'\"`":
        q = clean[i]
        j = clean.find(q, i + 1)
        if j > 0:
            val = clean[i + 1:j]
            return None if "${" in val else val
    return None


def _strings(clean: str, a: int, b: int) -> list[str]:
    return [m.group(2).replace("\\\\", "\\") for m in re.finditer(r"(['\"`])((?:\\.|(?!\1).)*)\1", clean[a:b])]


def _is_inline_fn(expr: str) -> bool:
    s = expr.strip()
    return bool(re.match(r"(?:async\b\s*)?(?:function\b|\(|" + IDENT + r"\s*=>)", s)) and \
        ("=>" in s or s.startswith(("function", "async function")))


def _callee(expr: str) -> str | None:
    m = re.match(r"\s*(?:new\s+)?([A-Za-z_$][\w$.]*)\s*(?:<[^>()]*>)?\s*\(", expr)
    return m.group(1) if m else None


def _arg_items(jf: JsFile, args: list[tuple[int, int]]) -> list[tuple[str, str, int, int]]:
    out = []
    for a, b in args:
        s = jf.code[a:b].strip()
        if not s:
            continue
        if s.startswith("["):
            out.append(("array", s, a, b))
        elif s.startswith("{"):
            out.append(("object", s, a, b))
        elif _is_inline_fn(s):
            out.append(("fn", s, a, b))
        elif _callee(s):
            out.append(("call", s, a, b))
        elif re.fullmatch(r"[A-Za-z_$][\w$.]*(?:\s*!)?", s):
            out.append(("ident", s.rstrip("!").strip(), a, b))
        else:
            out.append(("other", s, a, b))
    return out


# ---------------------------------------------------------------- middleware classification
def classify_name(name: str, extra: set[str]) -> str:
    """auth | role | benign | unknown for a middleware / wrapper / dependency name."""
    last = name.split(".")[-1]
    if last in extra or name in extra:
        return "auth"
    if last == "clerkMiddleware":      # attaches auth state, protects nothing by itself (Clerk docs)
        return "benign"
    if ROLE_NAME_RE.search(name):
        return "role"
    if MW_AUTH_RE.search(name) or last in AUTH_CALL_NAMES:
        return "auth"
    if BENIGN_MW_RE.match(name) or BENIGN_MW_RE.match(last):
        return "benign"
    return "unknown"


def classify_items(jf: JsFile, items, extra: set[str]) -> tuple[list[str], list[str], bool, list[tuple[int, int]]]:
    """-> (auth names, role names, opaque, inline middleware spans) for middleware arguments."""
    auths, roles, opaque, spans = [], [], False, []
    for kind, s, a, b in items:
        if kind == "array":
            inner = split_args(jf.code, a + 1, a + len(jf.code[a:b].rstrip()) - 1) if s.endswith("]") else []
            r = classify_items(jf, _arg_items(jf, inner), extra)
            auths += r[0]
            roles += r[1]
            opaque |= r[2]
            spans += r[3]
            continue
        if kind == "fn":
            spans.append((a, b))
            found = find_auth(jf.code[a:b], jf.clean[a:b], extra)
            if found:
                auths.append(found)
            if role_check(jf.code[a:b], jf.clean[a:b], set()):
                roles.append("inline role check")
            continue
        if kind == "object":
            for m in re.finditer(r"(?:preHandler|onRequest|preValidation|preParsing|beforeHandle)\s*:\s*", s):
                k = a + (len(jf.code[a:b]) - len(jf.code[a:b].lstrip())) + m.end()
                end = stmt_end(jf.code, k)
                r = classify_items(jf, _arg_items(jf, [(k, end)]), extra)
                auths += r[0]
                roles += r[1]
                opaque |= r[2]
                spans += r[3]
            continue
        name = _callee(s) if kind == "call" else s if kind == "ident" else None
        if name is None:
            continue
        c = classify_name(name, extra)
        if c == "role":
            roles.append(name)
            auths.append(name)
        elif c == "auth":
            auths.append(name)
        elif c == "unknown":
            # a local middleware function: look inside it
            f = jf.exported_fn(name.split(".")[-1]) if "." not in name else None
            if f is not None:
                found = find_auth(jf.code[f.popen:f.bend], jf.clean[f.popen:f.bend], extra)
                if found:
                    auths.append(f"{name} ({found})")
                    if role_check(jf.code[f.popen:f.bend], jf.clean[f.popen:f.bend], set()):
                        roles.append(name)
                    continue
            if kind == "call" and "=>" not in s:
                opaque = True
            elif kind == "ident":
                opaque = True
    return auths, roles, opaque, spans


# ---------------------------------------------------------------- discovery
def discover(jf: JsFile, extra: set[str]) -> None:
    _find_next_app(jf, extra)
    _find_next_pages(jf, extra)
    _find_actions(jf, extra)
    _find_express_style(jf, extra)
    _find_uses(jf)
    if MIDDLEWARE_FILE_RE.search(jf.rel) and re.search(
            r"next/server|NextResponse|clerkMiddleware|next-auth|matcher|@supabase/ssr", jf.clean):
        jf.middleware = parse_middleware(jf, extra)
    check_cors(jf)


def _mk(jf: JsFile, framework: str, methods: list[str], path: str | None, label: str, off: int, *,
        name: str | None = None, kind: str = "route", **meta) -> Route:
    r = Route(file=jf.rel, line=jf.line_of(off), lang="js", framework=framework, methods=methods, path=path,
              label=label, kind=kind, name=name, evidence=jf.ev(off))
    r.meta.update({"jf": jf, "off": off, "spans": [], "refs": [], "mw_auth": [], "mw_role": [], **meta})
    jf.routes.append(r)
    return r


def _wrapped_export(jf: JsFile, r: Route, start: int, extra: set[str]) -> None:
    """`export const POST = withAuth(async (req) => ...)` or `= handler` or `= async (req) => ...`."""
    end = stmt_end(jf.code, start)
    items = _arg_items(jf, [(start, end)])
    if not items:
        return
    kind, s, a, b = items[0]
    if kind == "fn":
        r.meta["spans"].append((jf, a, b))
    elif kind == "ident":
        _ref(jf, r, s)
    elif kind == "call":
        callee = _callee(s) or ""
        o = a + jf.code[a:b].index("(")
        inner = _arg_items(jf, split_args(jf.code, o + 1, match_close(jf.code, o)))
        fns = [x for x in inner if x[0] in ("fn", "ident", "call")]
        c = classify_name(callee, extra)
        if c in ("auth", "role"):
            r.meta["mw_auth"].append(callee + "()")
            if c == "role":
                r.meta["mw_role"].append(callee + "()")
        elif c == "unknown":
            r.opaque = True
        for k2, s2, a2, b2 in fns:
            if k2 == "fn":
                r.meta["spans"].append((jf, a2, b2))
            elif k2 == "ident":
                _ref(jf, r, s2)
            elif k2 == "call":
                _wrapped_export(jf, r, a2, extra)


def _ref(jf: JsFile, r: Route, ident: str) -> None:
    """Handler given by name: same-file function, or an import resolved later by the scanner."""
    head, _, member = ident.partition(".")
    if not member:
        f = jf.exported_fn(head)
        if f is not None:
            r.meta["spans"].append((jf, f.popen, f.bend))
            return
    if head in jf.imports:
        spec, imported = jf.imports[head]
        r.meta["refs"].append((spec, member or imported))
        return
    r.opaque = True


def _find_next_app(jf: JsFile, extra: set[str]) -> None:
    m = APP_ROUTE_RE.search(jf.rel)
    if not m:
        return
    segs = [s for s in (m.group(1) or "").split("/") if s and not (s.startswith("(") and s.endswith(")"))]
    segs = [s for s in segs if not s.startswith("@")]
    route = "/" + "/".join(segs)
    code = jf.code
    for meth in HTTP_METHODS:
        fm = re.search(r"export\s+(?:async\s+)?function\s+" + meth + r"\s*(?:<[^>()]*>)?\s*\(", code)
        if fm:
            f = next((x for x in jf.fns if x.popen == fm.end() - 1), None)
            if f:
                r = _mk(jf, "next-app", [meth], route, f"{meth} {route}", fm.start(), name=meth)
                r.meta["spans"].append((jf, f.popen, f.bend))
            continue
        cm = re.search(r"export\s+const\s+" + meth + r"\s*(?::[^=]+)?=\s*", code)
        if cm:
            r = _mk(jf, "next-app", [meth], route, f"{meth} {route}", cm.start(), name=meth)
            _wrapped_export(jf, r, cm.end(), extra)
            continue
        em = re.search(r"export\s*\{[^}]*\b(" + IDENT + r")\s+as\s+" + meth + r"\b", code)
        if em:
            r = _mk(jf, "next-app", [meth], route, f"{meth} {route}", em.start(), name=meth)
            _ref(jf, r, em.group(1))
            continue
        dm = re.search(r"export\s+const\s*\{[^}]*\b" + meth + r"\b[^}]*\}\s*=", code)   # export const { GET, POST } = handlers
        if dm:
            r = _mk(jf, "next-app", [meth], route, f"{meth} {route}", dm.start(), name=meth)
            r.opaque = True


def _find_next_pages(jf: JsFile, extra: set[str]) -> None:
    pm = PAGES_API_RE.search(jf.rel)
    if not pm:
        return
    sub = re.sub(r"(?:^|/)index$", "", pm.group(1))
    route = "/api/" + sub if sub else "/api"
    code = jf.code
    dm = re.search(r"export\s+default\s+", code)
    if not dm:
        return
    rest = code[dm.end():]
    r = _mk(jf, "next-pages", ["ALL"], route, f"ALL {route}", dm.start(), name="handler")
    if re.match(r"(?:async\s+)?function\b", rest):
        f = next((x for x in jf.fns if dm.end() <= x.start <= dm.end() + 20), None)
        if f:
            r.meta["spans"].append((jf, f.popen, f.bend))
    else:
        _wrapped_export(jf, r, dm.end(), extra)
    text = "\n".join(jf.clean[a:b] for _, a, b in r.meta["spans"]) or jf.clean
    found = []
    for mm in re.finditer(r"req\s*\.\s*method\s*(===|==|!==|!=)\s*['\"](\w+)['\"]|case\s+['\"](GET|POST|PUT|PATCH|DELETE)['\"]",
                          text):
        meth = (mm.group(2) or mm.group(3)).upper()
        if meth in HTTP_METHODS and meth not in found:
            found.append(meth)
    if found:
        r.methods = found
        r.label = f"{'/'.join(found)} {route}"


def _binding_names(params: str) -> list[str]:
    """Parameter names of a JS parameter list (destructuring followed one level)."""
    out = []
    for part in split_args(params, 0, len(params)):
        s = params[part[0]:part[1]].strip()
        if s.startswith("{"):
            close = match_close(s, 0)
            inner = s[1:close]
            for m in re.finditer(r"(" + IDENT + r")\s*(?::\s*(?:\{([^}]*)\}|(" + IDENT + r")))?\s*(?:=[^,]*)?(?:,|$)", inner):
                if m.group(2):
                    out += re.findall(IDENT, m.group(2))
                else:
                    out.append(m.group(3) or m.group(1))
        else:
            m = re.match(r"(?:\.\.\.)?(" + IDENT + r")", s)
            if m:
                out.append(m.group(1))
    return [n for n in out if n not in KEYWORDS]


USE_SERVER_RE = re.compile(r"""^\s*['"]use server['"]""")


def _find_actions(jf: JsFile, extra: set[str]) -> None:
    file_level = bool(USE_SERVER_RE.match(jf.clean))
    seen: set[int] = set()
    if file_level:
        for m in re.finditer(r"export\s+(?:default\s+)?(?:async\s+)?function\s*\*?\s*(" + IDENT + r")?\s*\(", jf.code):
            f = next((x for x in jf.fns if x.popen == m.end() - 1), None)
            if f:
                seen.add(f.popen)
                _action(jf, f, m.start(), f.name or "default")
        for m in re.finditer(r"export\s+const\s+(" + IDENT + r")\s*(?::[^=]+)?=\s*", jf.code):
            name = m.group(1)
            f = next((x for x in jf.fns if x.name == name and m.start() <= x.start <= m.end() + 5), None)
            if f:
                seen.add(f.popen)
                _action(jf, f, m.start(), name)
                continue
            end = stmt_end(jf.code, m.end())
            expr = jf.code[m.end():end]
            fm = re.search(r"(?:async\s*)?\(", expr)
            if "=>" not in expr or not fm:
                continue
            inner = next((x for x in jf.fns if m.end() <= x.popen < end and x.bend <= end + 1), None)
            if inner is None:
                continue
            seen.add(inner.popen)
            r = _action(jf, inner, m.start(), name)
            prefix = expr[:inner.popen - m.end()]
            for nm in re.findall(r"[A-Za-z_$][\w$]*", prefix):
                c = classify_name(nm, extra)
                if c in ("auth", "role") and nm not in ("action", "schema", "inputSchema"):
                    r.meta["mw_auth"].append(nm)
                    if c == "role":
                        r.meta["mw_role"].append(nm)
                    break
    for f in jf.fns:
        if f.popen in seen:
            continue
        body = jf.clean[f.bopen:f.bend]
        if jf.clean[f.bopen:f.bopen + 1] == "{" and USE_SERVER_RE.match(body[1:]):
            _action(jf, f, f.start, f.name or "inline action")


def _action(jf: JsFile, f: Fn, off: int, name: str) -> Route:
    r = _mk(jf, "server-action", ["POST"], None, f"server action {name}()", off, name=name, kind="action")
    r.meta["spans"].append((jf, f.popen, f.bend))
    pclose = match_close(jf.code, f.popen) if jf.code[f.popen:f.popen + 1] == "(" else f.bopen
    params = jf.code[f.popen + 1:pclose] if jf.code[f.popen:f.popen + 1] == "(" else jf.code[f.popen:f.bopen]
    names = _binding_names(params)
    prim = set(re.findall(r"(" + IDENT + r")\s*\??\s*:\s*(?:string|number|boolean|bigint)\b", params))
    r.meta["arg_names"] = names
    r.meta["arg_whole"] = [n for n in names if n not in prim]
    return r


def _find_express_style(jf: JsFile, extra: set[str]) -> None:
    code, clean = jf.code, jf.clean
    rx = re.compile(r"(?:(?<![\w$.])((?:this\s*\.\s*)?" + IDENT + r")|(\)))\s*\.\s*(get|post|put|patch|delete|all|route)\s*\(")
    chained: set[int] = set()
    clients = set(re.findall(r"(" + IDENT + r")\s*=\s*(?:axios|ky|got|wretch|ofetch|\$fetch)\s*\.\s*(?:create|extend)\s*\(", code))
    for m in rx.finditer(code):
        recv = (m.group(1) or "?").replace(" ", "")
        method = m.group(3)
        if recv in HTTP_CLIENTS or recv.split(".")[-1] in HTTP_CLIENTS or recv in clients:
            continue
        o = m.end() - 1
        if o in chained:
            continue
        c = match_close(code, o)
        args = split_args(code, o + 1, c)
        if not args:
            continue
        fw = jf.framework if jf.framework not in ("node", "next-app", "next-pages") else "express"
        if method == "route":
            first = code[args[0][0]:args[0][1]].strip()
            if first.startswith("{"):                     # fastify.route({ method, url, handler })
                obj = clean[args[0][0]:args[0][1]]
                mm = re.search(r"""method\s*:\s*(\[[^\]]*\]|['"]\w+['"])""", obj)
                if not mm:
                    continue
                meths = [x.upper() for x in re.findall(r"\w+", mm.group(1))]
                um = re.search(r"""(?:url|path)\s*:\s*(['"])(.*?)\1""", obj)
                path = um.group(2) if um else "/"
                r = _mk(jf, "fastify", meths, path, f"{'/'.join(meths)} {path}", m.start(), recv=recv, name=None)
                hm = re.search(r"\bhandler\s*:\s*", code[args[0][0]:args[0][1]])
                opts = _arg_items(jf, [args[0]])
                auths, roles, opaque, spans = classify_items(jf, opts, extra)
                r.meta["mw_auth"] += auths
                r.meta["mw_role"] += roles
                r.opaque |= opaque
                if hm:
                    hs = args[0][0] + hm.end()
                    it = _arg_items(jf, [(hs, stmt_end(code, hs))])
                    if it and it[0][0] == "fn":
                        r.meta["spans"].append((jf, it[0][2], it[0][3]))
                    elif it and it[0][0] == "ident":
                        _ref(jf, r, it[0][1])
                continue
            path = _string_at(clean, args[0][0])
            if path is None:
                continue
            if len(args) >= 2:                            # hono: app.route("/posts", posts) is a mount
                items = _arg_items(jf, args[1:])
                jf.uses.append(Use(m.start(), recv, path, items, kind="route"))
                continue
            k = c + 1
            while True:
                cm = re.compile(r"\s*\.\s*(" + IDENT + r")\s*\(").match(code, k)
                if not cm:
                    break
                co = cm.end() - 1
                cc = match_close(code, co)
                chained.add(co)
                if cm.group(1) in ("get", "post", "put", "patch", "delete", "all"):
                    _route_args(jf, fw, cm.group(1), path, m.start(), recv, split_args(code, co + 1, cc), extra)
                k = cc + 1
            continue
        path = _string_at(clean, args[0][0])
        if path is None or not path.startswith(("/", "*")) or len(args) < 2:
            continue
        _route_args(jf, fw, method, path, m.start(), recv, args[1:], extra)


def _route_args(jf: JsFile, fw: str, method: str, path: str, off: int, recv: str, args, extra: set[str]) -> None:
    meth = method.upper()
    r = _mk(jf, fw, [meth], path, f"{meth} {path}", off, recv=recv)
    items = _arg_items(jf, args)
    if not items:
        return
    *mws, last = items
    auths, roles, opaque, spans = classify_items(jf, mws, extra)
    r.meta["mw_auth"] += auths
    r.meta["mw_role"] += roles
    r.opaque |= opaque
    for sp in spans:
        r.meta["spans"].append((jf, *sp))
    kind, s, a, b = last
    if kind == "fn":
        r.meta["spans"].append((jf, a, b))
    elif kind == "ident":
        _ref(jf, r, s)
    elif kind == "call":
        callee = _callee(s) or ""
        o = a + jf.code[a:b].index("(")
        inner = _arg_items(jf, split_args(jf.code, o + 1, match_close(jf.code, o)))
        c = classify_name(callee, extra)
        if c in ("auth", "role"):
            r.meta["mw_auth"].append(callee + "()")
            if c == "role":
                r.meta["mw_role"].append(callee + "()")
        elif c == "unknown" and not callee.endswith(("Handler", "handler", "Controller", "controller")):
            r.opaque = True
        for k2, s2, a2, b2 in inner:
            if k2 == "fn":
                r.meta["spans"].append((jf, a2, b2))
            elif k2 == "ident" and not re.search(r"schema|Schema", s2):
                _ref(jf, r, s2)
    else:
        r.opaque = True


def _find_uses(jf: JsFile) -> None:
    code, clean = jf.code, jf.clean
    for m in re.finditer(r"(?<![\w$.])(" + IDENT + r")\s*\.\s*(use|register|addHook)\s*\(", code):
        recv, kind = m.group(1), m.group(2)
        if recv in HTTP_CLIENTS:
            continue
        o = m.end() - 1
        args = split_args(code, o + 1, match_close(code, o))
        if not args:
            continue
        prefix = _string_at(clean, args[0][0])
        if kind == "addHook":
            if prefix not in ("onRequest", "preHandler", "preValidation", "preParsing"):
                continue
            jf.uses.append(Use(m.start(), recv, None, _arg_items(jf, args[1:]), kind="hook", anywhere=True))
            continue
        if kind == "register":
            opts = clean[args[1][0]:args[1][1]] if len(args) > 1 else ""
            pm = re.search(r"""prefix\s*:\s*(['"])(.*?)\1""", opts)
            jf.uses.append(Use(m.start(), recv, pm.group(2) if pm else None, _arg_items(jf, args[:1]), kind="register"))
            continue
        if prefix is not None:
            args = args[1:]
        jf.uses.append(Use(m.start(), recv, prefix, _arg_items(jf, args)))


# ---------------------------------------------------------------- Next.js middleware
def parse_middleware(jf: JsFile, extra: set[str]) -> MwInfo:
    root = jf.rel.rsplit("/", 1)[0] if "/" in jf.rel else ""
    if root.endswith("src"):
        root = root[:-3].rstrip("/")
    code, clean = jf.code, jf.clean
    info = MwInfo(file=jf.rel, root=root, line=1, matchers=None, auth=None)
    cm = re.search(r"\bmatcher\s*:\s*", code)
    if cm:
        end = stmt_end(code, cm.end())
        info.matchers = _strings(clean, cm.end(), end)
        info.line = jf.line_of(cm.start())
    else:
        em = re.search(r"export\s+(?:default|const\s+(?:middleware|proxy)|(?:async\s+)?function\s+(?:middleware|proxy))", code)
        info.line = jf.line_of(em.start()) if em else 1
    if re.search(r"\bclerkMiddleware\s*\(", code):
        info.auth = "clerkMiddleware()"
        info.clerk_line = jf.line_of(re.search(r"\bclerkMiddleware\s*\(", code).start())
        matchers = {mm.group(1): _strings(clean, mm.end(), match_close(code, mm.end() - 1))
                    for mm in re.finditer(r"(?:const|let|var)\s+(" + IDENT + r")\s*=\s*createRouteMatcher\s*\(", code)}
        protects = list(re.finditer(r"\bprotect\s*\(", code))
        if not protects:
            info.clerk_protect = "none"
        else:
            cp = "all"
            for p in protects:
                before = code[max(0, p.start() - 300):p.start()]
                conds = list(re.finditer(r"\bif\s*\(", before))
                if not conds:
                    cp = "all"
                    break
                cstart = max(0, p.start() - 300) + conds[-1].end() - 1
                cond = code[cstart:match_close(code, cstart) + 1]
                for name, pats in matchers.items():
                    nm = re.search(r"(!\s*)?" + re.escape(name) + r"\s*\(", cond)
                    if nm:
                        cp = ("except", pats) if nm.group(1) else ("only", pats)
                        break
            info.clerk_protect = cp
    elif re.search(r"""['"]next-auth/middleware['"]|\bwithAuth\s*\(""", clean):
        info.auth = "next-auth middleware"
    elif re.search(r"export\s*\{\s*auth\s+as\s+(?:middleware|default|proxy)\s*\}|export\s+default\s+auth\s*\(|"
                   r"export\s+const\s+(?:middleware|proxy)\s*=\s*auth\b|=\s*NextAuth\s*\(", code):
        info.auth = "NextAuth auth()"
    elif re.search(r"\bupdateSession\s*\(|auth\s*\.\s*getUser\s*\(", code):
        info.auth = "Supabase session check"
    else:
        found = find_auth(code, clean, extra)
        if found:
            info.auth = found
    for mm in re.finditer(r"\bif\s*\(", code):
        o = mm.end() - 1
        cl = match_close(code, o)
        cond = clean[o:cl + 1]
        after = code[cl + 1:cl + 200]
        if "NextResponse.next" in after.split(";")[0] + after[:120] and "redirect" not in after[:120]:
            info.skips += [s.group(1) for s in re.finditer(r"startsWith\(\s*['\"]([^'\"]+)['\"]", cond)]
    info.sets_headers = {h.lower() for h in re.findall(r"""\.set\(\s*['"](x-[\w-]+)['"]""", clean)}
    return info


# ---------------------------------------------------------------- auth / role / owner recognition
_CALL_RE = re.compile(r"(?<![\w$])(\.\s*)?([A-Za-z_$][\w$]*)\s*(?:<[^>()]*>)?\s*\(")
_AUTH_MISC = [
    (re.compile(r"\.\s*auth\s*\.\s*(getUser|getSession|getClaims)\s*\("), "supabase.auth.{0}()"),
    (re.compile(r"\bjwt\s*\.\s*verify\s*\("), "jwt.verify()"),
    (re.compile(r"\bpassport\s*\.\s*authenticate\s*\("), "passport.authenticate()"),
    (re.compile(r"\b(?:request|req)\s*\.\s*jwtVerify\s*\("), "request.jwtVerify()"),
    (re.compile(r"\bauth\s*\.\s*protect\s*\("), "auth.protect()"),
    (re.compile(r"\.\s*(verifyIdToken|verifySessionCookie|authenticateRequest|verifyToken)\s*\("), "{0}()"),
    (re.compile(r"(?<![\w$])(?:req|request|ctx\s*\.\s*state|ctx)\s*\.\s*(user|auth|session\s*\.\s*(?:user|userId|uid))\b"),
     "req.{0}"),
    (re.compile(r"\bc\s*\.\s*var\s*\.\s*(user|session|jwtPayload|auth)\b"), "c.var.{0}"),
]
_AUTH_MISC_CLEAN = [
    (re.compile(r"\bc\s*\.\s*get\s*\(\s*['\"](user|jwtPayload|session|auth|userId|clerkAuth|currentUser)['\"]"),
     'c.get("{0}")'),
    (re.compile(r"(?i)headers?\s*(?:\(\s*\))?\s*(?:\.\s*get\s*\(\s*|\[\s*|\.\s*)['\"]?(authorization|x-api-key|api-key)\b"),
     "{0} header check"),
    (re.compile(r"(?i)\.\s*(?:get|header)\s*\(\s*['\"](authorization|x-api-key|api-key)['\"]"), "{0} header check"),
    (re.compile(r"cookies\s*(?:\(\s*\))?\s*\.\s*get\s*\(\s*['\"](\w*(?:token|session|auth|jwt|sid)\w*)['\"]", re.I),
     "{0} cookie check"),
    (re.compile(r"(?<![\w$])(?:req|request)\s*\.\s*cookies\s*(?:\.\s*|\[\s*['\"])(\w*(?:token|session|auth|jwt|sid)\w*)",
                re.I), "{0} cookie check"),
    (re.compile(r"process\.env\.(\w*(?:CRON_SECRET|API_KEY|API_SECRET|ADMIN_SECRET|ADMIN_KEY|INTERNAL_SECRET|AUTH_TOKEN))"),
     "{0} secret check"),
]


def find_auth(code: str, clean: str, extra: set[str]) -> str | None:
    for m in _CALL_RE.finditer(code):
        name = m.group(2)
        if name in KEYWORDS or NOT_AUTH_NAMES.match(name):
            continue
        if name in extra:
            return f"{name}()"
        if m.group(1):
            continue
        if name in AUTH_CALL_NAMES or AUTH_NAME_RE.fullmatch(name):
            return f"{name}()"
    for rx, fmt in _AUTH_MISC:
        m = rx.search(code)
        if m:
            return fmt.format(*(re.sub(r"\s+", "", g) for g in m.groups()))
    for rx, fmt in _AUTH_MISC_CLEAN:
        m = rx.search(clean)
        if m:
            return fmt.format(*m.groups())
    return None


ROLE_CHECK_RES = [
    re.compile(r"\b(?:role|roles|userRole|orgRole|org_role|publicMetadata\s*\??\.\s*role)\b[^;\n]{0,60}?"
               r"(?:===|!==|==|!=|\.includes\s*\(|\.some\s*\()"),
    re.compile(r"(?:===|!==|==|!=)\s*[\w$.?]*\b(?:role|roles|Role)\b"),
    re.compile(r"(?:\bif\s*\(|&&|\|\||!|\?)\s*\(?\s*[\w$.?!]*\b(?:isAdmin|is_admin|isSuperAdmin|isSuperuser|isStaff|is_staff)\b"),
    re.compile(r"\bhas\s*\(\s*\{\s*(?:role|permission)"),
    re.compile(r"(?<![\w$])(?:require|ensure|check|assert|verify|is|has|with|only)_?(?:Admin|Role|Roles|Permission|"
               r"Permissions|SuperAdmin|Staff)\w*\s*\("),
    re.compile(r"(?<![\w$])(?:hasRole|checkRole|authorize|authorise|ability|restrictTo|requirePermission|can)\s*\("),
    re.compile(r"\bprotect\s*\(\s*(?:\{\s*(?:role|permission)|\(?\s*has)"),
]


def role_check(code: str, clean: str, tainted: set[str]) -> str | None:
    for ln_code in code.split("\n"):
        if tainted and any(re.search(r"(?<![\w$])" + re.escape(t) + r"(?![\w$])", ln_code) for t in tainted):
            continue
        for rx in ROLE_CHECK_RES:
            m = rx.search(ln_code)
            if m:
                return re.sub(r"\s+", " ", m.group(0)).strip()[:60]
    return None


OWNER_HELPERS = re.compile(
    r"(?<![\w$])(?:can|cannot|authorize|authorise|ability|checkPermission|hasPermission|assertCan|isOwner|checkOwner\w*|"
    r"assertOwner\w*|ensureOwner\w*|requireOwner\w*|verifyOwner\w*|canAccess|canEdit|canDelete|canView|canUpdate|"
    r"canManage|enforce|checkAccess|hasAccess|assertAccess|requireMembership|assertMember\w*|isMember)\s*\(")
_CMP = re.compile(r"===|!==|==|!=")


def owner_check(code: str, clean: str) -> str | None:
    for ln in code.split("\n"):
        if _CMP.search(ln) and USER_KEY_RE.search(ln):
            rest = USER_KEY_RE.sub(" ", ln, count=1)
            if SESSIONISH_RE.search(rest) or USER_KEY_RE.search(rest):
                return re.sub(r"\s+", " ", ln.strip())[:70]
    m = re.search(r"\beq\s*\(\s*[\w$.]+\.\s*(?:" + USER_KEYS + r")\s*,", code)
    if m:
        return m.group(0)
    m = OWNER_HELPERS.search(code)
    if m:
        return m.group(0)
    if re.search(r"\b403\b", code) or re.search(r"\bForbidden|\bforbidden\s*\(", clean):
        return "403 response"
    return None


WRITE_RE = re.compile(
    r"\.\s*(?:create|createMany|update|updateMany|upsert|delete|deleteMany|save|insert|insertOne|insertMany|updateOne|"
    r"replaceOne|deleteOne|destroy|remove|findByIdAndUpdate|findByIdAndDelete|findByIdAndRemove|findOneAndUpdate|"
    r"findOneAndDelete|findOneAndReplace|bulkWrite|bulkCreate|increment|decrement|sendMail|hset|lpush|rpush|"
    r"publish|enqueue|trigger|values)\s*\(|"
    r"\b(?:sendEmail|sendMail|writeFile|appendFile|unlink|revalidatePath|revalidateTag)\s*\(|"
    r"\.\s*(?:completions|messages|responses|images|embeddings)\s*\.\s*(?:create|generate)\s*\(|"
    r"\b(?:db|tx)\s*\.\s*(?:insert|update|delete)\s*\("
)
HASH_CHAIN_RE = re.compile(r"createHmac|createHash|createCipher\w*|createSign|createVerify|\bhash\w*\s*\(|\bhmac\b|"
                           r"\bsha\d*\b|\bmd5\b|\bdigest\b|URLSearchParams|\bheaders\b|new\s+Map|new\s+Set", re.I)
TOUCH_RE = re.compile(
    r"\b(?:db|prisma|supabase|knex|sql|pool|client|redis|kv|stripe|openai|anthropic|resend|s3|storage|ctx\s*\.\s*db|"
    r"repo\w*|\w+Service|\w+Repository)\s*\.\s*[\w$]+|\b[A-Z][\w$]*\s*\.\s*(?:create|update|delete|find\w*|insert\w*|save|"
    r"destroy|remove|upsert)\s*\(|\bfetch\s*\(|"
    r"\bawait\s+(?!(?:req|request|c\s*\.\s*req|ctx\s*\.\s*request|event|params|context|props|headers|cookies)\b)"
    r"[\w$.]+\s*\(")
WRITE_SQL_RE = re.compile(r"(?i)\b(?:insert\s+into|update\s+[\w\"`.]+\s+set|delete\s+from)\b")
LIST_USERS_RE = re.compile(
    r"\b(?:prisma|db|tx|ctx\s*\.\s*(?:db|prisma))\s*\.\s*(?:user|users|profile|profiles|account|accounts)\s*\.\s*findMany\s*\(\s*(\)|\{)|"
    r"(?<![\w$.])(?:User|Users|Profile|Account)\s*\.\s*(?:find|findAll)\s*\(\s*(?:\{\s*\})?\s*\)|"
    r"\bauth\s*\.\s*admin\s*\.\s*listUsers\s*\(|\busers\s*\.\s*getUserList\s*\(|\blistUsers\s*\("
)
ADMIN_CLIENT_RE = re.compile(r"SERVICE_ROLE|service_role|serviceRole|supabaseAdmin|createAdminClient|adminClient|"
                             r"createServiceClient|createServiceRoleClient")


# ---------------------------------------------------------------- request taint
_REQ_OBJ = (r"(?:(?:req|request|ctx\s*\.\s*request|ctx)\s*\.\s*(?:params|query|body)|context\s*\.\s*params|"
            r"props\s*\.\s*params|ctx\s*\.\s*params|params|searchParams|(?:req|request)\s*\.\s*nextUrl\s*\.\s*searchParams|"
            r"new\s+URL\s*\([^)]*\)\s*\.\s*searchParams)")
_REQ_OBJ_RE = re.compile(r"^(?:await\s+)?\(?\s*(?:await\s+)?" + _REQ_OBJ + r"\s*\)?$")
_WHOLE_RE = re.compile(
    r"^(?:await\s+)?\(?\s*(?:await\s+)?(?:(?:req|request|ctx\s*\.\s*request|c\s*\.\s*req|event)\s*\.\s*"
    r"(?:json|formData|parseBody)\s*\(\s*\)|(?:req|request|ctx\s*\.\s*request)\s*\.\s*body|"
    r"Object\s*\.\s*fromEntries\s*\(\s*(?:await\s+)?[\w$.]+(?:\s*\.\s*formData\s*\(\s*\))?\s*\))\s*\)?"
    r"(?:\s+as\s+[\w$<>\[\]{}|,. ]+)?$")
_WRAP_RE = re.compile(r"^(?:Number|parseInt|parseFloat|String|BigInt|Boolean|new\s+(?:[\w$.]+\.)?ObjectId|"
                      r"[\w$.]*ObjectId|decodeURIComponent)\s*\(\s*(.*?)\s*(?:,\s*\d+\s*)?\)$")


def _source(obj_expr: str) -> str:
    s = obj_expr
    if re.search(r"\.\s*params\b|^params$|^\(?\s*await\s+params", s) or "param(" in s:
        return "path"
    if "query" in s or "searchParams" in s:
        return "query"
    if re.search(r"header", s, re.I):
        return "header"
    if "formData" in s or "fromEntries" in s:
        return "form"
    return "body"


def _strip_as(s: str) -> str:
    """Drop a trailing TypeScript `as Type` / `satisfies Type`."""
    return re.sub(r"\s+(?:as|satisfies)\s+(?:const|[A-Za-z_$({\[]).*$", "", s, flags=re.S).strip()


class Taint:
    """Names in a handler that hold request input. obj: name -> source (whole objects / bags);
    scalar: name -> (source, key)."""

    def __init__(self, code: str, clean: str, arg_names: list[str] | None = None, arg_whole: list[str] | None = None,
                 next_params: bool = False):
        self.code, self.clean = code, clean
        self.obj: dict[str, str] = {}
        self.whole: set[str] = set()
        self.scalar: dict[str, tuple[str, str]] = {}
        if next_params:
            self.obj["params"] = "path"
        for n in arg_names or []:
            self.scalar[n] = ("arg", n)
        for n in arg_whole or []:
            self.obj[n] = "arg"
            self.whole.add(n)
        assigns = []
        for m in re.finditer(r"(?<![\w$.])(?:const|let|var)\s+(" + IDENT + r"|\{)", code):
            dest_start = m.start(1)
            if code[dest_start] == "{":
                dclose = match_close(code, dest_start)
                dest = code[dest_start:dclose + 1]
                k = dclose + 1
            else:
                dest = m.group(1)
                k = m.end(1)
            tm = re.compile(r"\s*(?::\s*[^=;]+?)?\s*=\s*(?!=)").match(code, k)
            if not tm:
                continue
            rs = tm.end()
            re_ = stmt_end(code, rs)
            assigns.append((dest, code[rs:re_].strip(), clean[rs:re_].strip(), rs))
        for _ in range(3):
            for dest, rhs, rhs_clean, _off in assigns:
                self._assign(dest, rhs, rhs_clean)

    def _assign(self, dest: str, rhs: str, rhs_clean: str) -> None:
        rhs = _strip_as(rhs)
        rhs = re.sub(r"\s*(?:\?\?|\|\|)\s*\{\s*\}$", "", rhs)
        if dest.startswith("{"):
            src = None
            m = _REQ_OBJ_RE.match(rhs)
            if m:
                src = _source(rhs)
            else:
                base = re.sub(r"^(?:await\s+)?\(?\s*(?:await\s+)?", "", rhs).rstrip(")").strip()
                if base in self.obj:
                    src = self.obj[base]
                elif _WHOLE_RE.match(rhs):
                    src = _source(rhs)
                elif re.match(r"^(?:await\s+)?c\s*\.\s*req\s*\.\s*(?:param|query)\s*\(\s*\)$", rhs):
                    src = "path" if "param" in rhs else "query"
            if src is None:
                return
            inner = dest[1:-1]
            for mm in re.finditer(r"(?:\.\.\.\s*(" + IDENT + r"))|(" + IDENT + r")\s*(?::\s*(" + IDENT + r"))?\s*(?:=[^,]*)?(?:,|$)",
                                  inner):
                if mm.group(1):
                    self.obj[mm.group(1)] = src
                    self.whole.add(mm.group(1))
                elif mm.group(2):
                    self.scalar[mm.group(3) or mm.group(2)] = (src, mm.group(2))
            return
        if _WHOLE_RE.match(rhs):
            self.obj[dest] = _source(rhs)
            self.whole.add(dest)
            return
        if _REQ_OBJ_RE.match(rhs):
            self.obj[dest] = _source(rhs)
            return
        base = re.sub(r"^await\s+", "", rhs)
        if base in self.whole:
            self.whole.add(dest)
            self.obj[dest] = self.obj.get(base, "body")
            return
        sc = self.scalar_of(rhs, rhs_clean)
        if sc:
            self.scalar[dest] = sc

    def scalar_of(self, expr: str, expr_clean: str = "") -> tuple[str, str] | None:
        """(source, key) when expr is a single request value, else None."""
        s = expr.strip().rstrip("!").strip()
        s = _strip_as(s)
        s = re.sub(r"\s*(?:\?\?|\|\|).*$", "", s).strip()
        s = re.sub(r"^\+\s*", "", s)
        w = _WRAP_RE.match(s)
        if w:
            s = w.group(1).strip()
            if expr_clean:
                w2 = _WRAP_RE.match(expr_clean.strip())
                expr_clean = w2.group(1) if w2 else expr_clean
        if re.fullmatch(IDENT, s):
            return self.scalar.get(s)
        m = re.fullmatch(r"(?:await\s+)?\(?\s*(?:await\s+)?(" + _REQ_OBJ + r"|" + IDENT + r")\s*\)?\s*(?:\?\.|\.)\s*(" + IDENT + r")", s)
        if m:
            base = m.group(1)
            if _REQ_OBJ_RE.match(base):
                return (_source(base), m.group(2))
            if base in self.obj:
                return (self.obj[base], m.group(2))
        m = re.fullmatch(r"(?:await\s+)?(" + _REQ_OBJ + r"|" + IDENT + r")\s*\[\s*(.*)\]", s)
        if m and (_REQ_OBJ_RE.match(m.group(1)) or m.group(1) in self.obj):
            km = re.search(r"['\"]([\w-]+)['\"]", expr_clean)
            return (_source(m.group(1)) if _REQ_OBJ_RE.match(m.group(1)) else self.obj[m.group(1)],
                    km.group(1) if km else "?")
        m = re.fullmatch(r"(?:[\w$.]*searchParams|(?:await\s+)?" + IDENT + r")\s*\.\s*get\s*\(.*\)", s)
        if m:
            base = s.split(".")[0].replace("await", "").strip()
            if "searchParams" in s or base in ("formData", "form", "fd", "data") or self.obj.get(base) in ("form", "arg"):
                km = re.search(r"\.get\s*\(\s*['\"]([\w-]+)['\"]", expr_clean)
                return ("query" if "searchParams" in s else "form", km.group(1) if km else "?")
        m = re.fullmatch(r"(?:await\s+)?c\s*\.\s*req\s*\.\s*(param|query)\s*\(.*\)", s)
        if m:
            km = re.search(r"\(\s*['\"]([\w-]+)['\"]", expr_clean)
            return ("path" if m.group(1) == "param" else "query", km.group(1) if km else "?")
        return None

    def is_whole(self, expr: str) -> str | None:
        s = _strip_as(expr.strip())
        if re.match(r"^\{\s*\.\.\.\s*", s):
            m = re.match(r"^\{\s*\.\.\.\s*((?:req|request|ctx\s*\.\s*request)\s*\.\s*body|" + IDENT + r")(?![\w$.])", s)
            if not m:
                return None
            s = re.sub(r"\s+", "", m.group(1))
        s = s.strip()
        if s in self.whole:
            return s
        if _WHOLE_RE.match(s):
            return re.sub(r"\s+", "", s)
        return None


# ---------------------------------------------------------------- object literal helpers
def obj_entries(code: str, brace: int) -> list[tuple[str | None, int, int, bool]]:
    """Top-level entries of the object literal at code[brace] == '{':
    (key or None for spreads, value_start, value_end, shorthand)."""
    close = match_close(code, brace)
    out = []
    for a, b in split_args(code, brace + 1, close):
        s = code[a:b]
        st = a + len(s) - len(s.lstrip())
        m = re.match(r"\s*\.\.\.\s*", s)
        if m:
            out.append((None, a + m.end(), b, False))
            continue
        m = re.match(r"\s*['\"]?(" + IDENT + r")['\"]?\s*:\s*", s)
        if m:
            out.append((m.group(1), a + m.end(), b, False))
            continue
        m = re.match(r"\s*(" + IDENT + r")\s*$", s)
        if m:
            out.append((m.group(1), st, st + len(m.group(1)), True))
    return out


ID_KEY_RE = re.compile(r"^(?:id|_id|uuid|pk|[a-z][\w$]*Id|[a-z][\w$]*_id)$")
USER_KEY_FULL = re.compile(r"^(?:" + USER_KEYS + r")$")


# ---------------------------------------------------------------- handler analysis
@dataclass
class Part:
    jf: JsFile
    a: int
    b: int


def _helpers(jf: JsFile, a: int, b: int, depth: int = 0, seen: set[int] | None = None) -> list[tuple[int, int]]:
    """Same-file functions called from code[a:b], two levels deep."""
    seen = seen if seen is not None else set()
    out = []
    if depth >= 2:
        return out
    for n in sorted(set(re.findall(r"(?<![\w$.])(" + IDENT + r")\s*\(", jf.code[a:b]))):
        if n in KEYWORDS:
            continue
        for f in jf.by_name.get(n, [])[:1]:
            if f.popen in seen or (f.popen >= a and f.bend <= b):
                continue
            seen.add(f.popen)
            out.append((f.popen, f.bend))
            out += _helpers(jf, f.popen, f.bend, depth + 1, seen)
    return out


def analyze(route: Route, extra: set[str]) -> Facts:
    parts: list[Part] = []
    for jf, a, b in route.meta["spans"]:
        parts.append(Part(jf, a, b))
        for ha, hb in _helpers(jf, a, b, seen={a}):
            parts.append(Part(jf, ha, hb))
    code = "\n".join(p.jf.code[p.a:p.b] for p in parts)
    clean = "\n".join(p.jf.clean[p.a:p.b] for p in parts)
    facts = Facts()
    facts.auth = find_auth(code, clean, extra)
    facts.writes = bool(WRITE_RE.search(code) or WRITE_SQL_RE.search(clean))
    facts.touches = facts.writes or bool(TOUCH_RE.search(code))
    taint = Taint(code, clean, route.meta.get("arg_names"), route.meta.get("arg_whole"),
                  next_params=route.framework in ("next-app",))
    role_names = {n for n, (src, key) in taint.scalar.items() if key in ROLE_KEYS and src != "path"}
    facts.owner_check = owner_check(code, clean)
    admin_client = bool(ADMIN_CLIENT_RE.search(clean) or any(ADMIN_CLIENT_RE.search(p.jf.clean) for p in parts))
    m = LIST_USERS_RE.search(code)
    if m and not (m.group(1) == "{" and re.search(r"\bwhere\s*:", code[m.end():m.end() + 200])):
        facts.admin_reason = "lists all users"
    for p in parts:
        _scan_part(p, taint, facts, route, admin_client)
    tainted_roles = role_names | {f"{o}.role" for o in taint.obj}
    facts.role_check = role_check(code, clean, tainted_roles)
    return facts


def _site(p: Part, off: int, **detail) -> Site:
    jf = p.jf
    return Site(jf.rel, jf.line_of(off), jf.ev(off), detail)


def _scan_part(p: Part, taint: Taint, facts: Facts, route: Route, admin_client: bool) -> None:
    jf, a, b = p.jf, p.a, p.b
    code, clean = jf.code, jf.clean
    seg = code[a:b]

    def is_req(x0: int, x1: int) -> tuple[str, str] | None:
        return taint.scalar_of(code[x0:x1], clean[x0:x1])

    # --- RAC002: record by request id, no owner in the query
    def idor(off: int, op: str, model: str, idexpr: str, orm: str) -> None:
        facts.idor.append(_site(p, off, op=op, model=model, id=idexpr.strip(), orm=orm))

    for m in re.finditer(r"(?<![\w$])((?:[\w$]+\s*\.\s*)*?[\w$]+)\s*\.\s*([\w$]+)\s*\.\s*(findUnique|findUniqueOrThrow|findFirst|"
                         r"findFirstOrThrow|update|delete|upsert)\s*\(\s*\{", seg):
        brace = a + m.end() - 1
        ents = obj_entries(code, brace)
        where = next((e for e in ents if e[0] == "where"), None)
        if where is None or code[where[1]:where[1] + 1] != "{":
            continue
        wents = obj_entries(code, where[1])
        if any(k and USER_KEY_FULL.match(k) for k, *_ in wents) or USER_KEY_RE.search(code[where[1]:where[2]]):
            continue
        for k, va, vb, short in wents:
            if k and ID_KEY_RE.match(k) and is_req(va, vb):
                idor(a + m.start(), _op(m.group(3)), m.group(2), code[va:vb] if not short else k, "prisma")
                break
    for m in re.finditer(r"(?<![\w$.])([A-Z][\w$]*)\s*\.\s*(findById|findByIdAndUpdate|findByIdAndDelete|findByIdAndRemove|"
                         r"findByPk)\s*\(", seg):
        o = a + m.end() - 1
        args = split_args(code, o + 1, match_close(code, o))
        if args and is_req(*args[0]):
            idor(a + m.start(), _op(m.group(2)), m.group(1), code[args[0][0]:args[0][1]],
                 "sequelize" if m.group(2) == "findByPk" else "mongoose")
    for m in re.finditer(r"(?<![\w$.])([A-Z][\w$]*)\s*\.\s*(findOne|findOneAndUpdate|findOneAndDelete|findOneAndRemove|"
                         r"deleteOne|updateOne|destroy|update|findOneBy)\s*\(", seg):
        o = a + m.end() - 1
        args = split_args(code, o + 1, match_close(code, o))
        if not args:
            continue
        cand = args[1] if m.group(2) == "update" and len(args) > 1 else args[0]
        cs = code[cand[0]:cand[1]].strip()
        if not cs.startswith("{"):
            continue
        brace = cand[0] + code[cand[0]:cand[1]].index("{")
        ents = obj_entries(code, brace)
        wh = next((e for e in ents if e[0] == "where" and code[e[1]:e[1] + 1] == "{"), None)
        if wh:
            ents = obj_entries(code, wh[1])
        if any(k and USER_KEY_FULL.match(k) for k, *_ in ents):
            continue
        for k, va, vb, short in ents:
            if k and ID_KEY_RE.match(k) and is_req(va, vb):
                orm = "sequelize" if wh else "mongoose"
                idor(a + m.start(), _op(m.group(2)), m.group(1), code[va:vb] if not short else k, orm)
                break
    for m in re.finditer(r"\.\s*where\s*\(", seg):
        o = a + m.end() - 1
        c = match_close(code, o)
        inner = code[o + 1:c]
        if USER_KEY_RE.search(inner):
            continue
        em = re.search(r"\beq\s*\(\s*([\w$]+)\s*\.\s*(id|[a-z][\w$]*Id)\s*,\s*", inner)
        if not em:
            continue
        va = o + 1 + em.end()
        vb = stmt_end(code, va)
        if not is_req(va, vb):
            continue
        stmt_start = max(code.rfind(";", 0, o), code.rfind("\n\n", 0, o), a)
        before = code[stmt_start:o]
        opm = re.findall(r"\b(?:db|tx)\s*\.\s*(update|delete|select|insert)\b", before)
        op = {"update": "update", "delete": "delete"}.get(opm[-1] if opm else "", "read")
        idor(o, op, em.group(1), code[va:vb], "drizzle")
    if admin_client:
        for m in re.finditer(r"\.\s*from\s*\(\s*(['\"])(\w+)\1\s*\)", clean[a:b]):
            chain_end = stmt_end(code, a + m.end())
            chain = clean[a + m.start():chain_end]
            if re.search(r"\.eq\(\s*['\"](?:" + USER_KEYS + r")['\"]", chain):
                continue
            em = re.search(r"\.eq\(\s*['\"](id|\w+_id)['\"]\s*,\s*", chain)
            if not em:
                continue
            va = a + m.start() + em.end()
            vb = stmt_end(code, va)
            if is_req(va, vb):
                op = "delete" if ".delete(" in chain else "update" if re.search(r"\.(?:update|upsert)\(", chain) else "read"
                idor(a + m.start(), op, m.group(2), code[va:vb], "supabase-admin")

    # --- RAC006: identity / role from the request
    seen_names: set[str] = set()
    for name, (src, key) in taint.scalar.items():
        if src == "path" or name in seen_names:
            continue
        kind = "user-id" if key in TRUST_ID_KEYS else "role" if key in ROLE_KEYS else None
        if kind is None:
            continue
        dm = re.search(r"(?<![\w$.])" + re.escape(name) + r"(?![\w$])", seg)
        if not dm:
            continue
        seen_names.add(name)
        _trusted(p, taint, facts, name, a + dm.start(), kind, src, key)
    bases = [re.escape(o) for o in sorted(taint.obj, key=len, reverse=True)] + [r"(?:req|request)\s*\.\s*(?:body|query)"]
    keys = "|".join(sorted(TRUST_ID_KEYS | ROLE_KEYS))
    for m in re.finditer(r"(?<![\w$.])(" + "|".join(bases) + r")\s*(?:\?\.|\.)\s*(" + keys + r")(?![\w$])", seg):
        base = re.sub(r"\s+", "", m.group(1))
        src = taint.obj.get(base, "query" if "query" in base else "body")
        if src == "path":
            continue
        key = m.group(2)
        _trusted(p, taint, facts, base + "." + key, a + m.start(), "user-id" if key in TRUST_ID_KEYS else "role", src, key)
    for m in re.finditer(r"""(?:\.\s*(?:get|header)\s*\(\s*|headers\s*\[\s*)(['"])(x-[\w-]+)\1""", clean[a:b], re.I):
        h = m.group(2).lower()
        if h in IDENTITY_HEADERS:
            facts.trusted.append(_site(p, a + m.start(), kind="header", header=h, expr=h, written=False, source="header"))

    # --- RAC008: whole body into a write
    def mass(off: int, sink: str, expr: str) -> None:
        facts.mass.append(_site(p, off, sink=sink, expr=expr))

    for m in re.finditer(r"(?<![\w$])((?:[\w$]+\s*\.\s*)*?[\w$]+)\s*\.\s*([\w$]+)\s*\.\s*(create|update|upsert|createMany|updateMany)"
                         r"\s*\(\s*\{", seg):
        brace = a + m.end() - 1
        for k, va, vb, short in obj_entries(code, brace):
            if k in ("data", "create", "update"):
                w = taint.is_whole(k if short else code[va:vb])
                if w:
                    mass(a + m.start(), f"prisma.{m.group(2)}.{m.group(3)}({{ {k}: ... }})", w)
                    break
    sinks = [
        (r"(?<![\w$.])(new\s+[A-Z][\w$]*|[A-Z][\w$]*\s*\.\s*(?:create|insertMany|build|bulkCreate))\s*\(", 0),
        (r"\.\s*(findByIdAndUpdate|findOneAndUpdate|updateOne|updateMany|replaceOne)\s*\(", 1),
        (r"\.\s*(update|insert|upsert|values|set|save)\s*\(", 0),
        (r"\b(Object\s*\.\s*assign)\s*\(", 1),
    ]
    for rx, idx in sinks:
        for m in re.finditer(rx, seg):
            o = a + m.end() - 1
            args = split_args(code, o + 1, match_close(code, o))
            if len(args) <= idx:
                continue
            w = taint.is_whole(code[args[idx][0]:args[idx][1]])
            if w and not HASH_CHAIN_RE.search(code[max(a, a + m.start() - 160):a + m.start()].split(";")[-1]):
                mass(a + m.start(), re.sub(r"\s+", "", m.group(1)) + "()", w)
    for m in re.finditer(r"\$set\s*:\s*", seg):
        va = a + m.end()
        w = taint.is_whole(code[va:stmt_end(code, va)])
        if w:
            mass(a + m.start(), "$set", w)


def _trusted(p: Part, taint: Taint, facts: Facts, name: str, off: int, kind: str, src: str, key: str) -> None:
    jf = p.jf
    code = jf.code[p.a:p.b]
    pat = re.escape(name).replace(r"\.", r"\s*(?:\?\.|\.)\s*")
    # compared with the session user -> it is being checked, not trusted
    for ln in code.split("\n"):
        if re.search(r"(?<![\w$])" + pat + r"(?![\w$])", ln) and _CMP.search(ln):
            rest = re.sub(r"(?<![\w$])" + pat + r"(?![\w$])", " ", ln)
            if SESSIONISH_RE.search(rest):
                return
    written = bool(re.search(r"(?<![\w$])(?:" + "|".join(sorted(ROLE_KEYS | TRUST_ID_KEYS)) + r")\s*:\s*" + pat + r"(?![\w$])", code)
                   or re.search(r"[{,]\s*" + pat + r"\s*[,}]", code))
    in_cond = bool(re.search(pat + r"\s*(?:===|!==|==|!=)|(?:===|!==|==|!=)\s*" + pat, code) or
                   re.search(r"\bif\s*\(\s*!?\s*" + pat + r"\s*\)", code))
    used = len(re.findall(r"(?<![\w$])" + pat + r"(?![\w$])", code)) > 1 or written or "." in name
    if kind == "role" and not (written or in_cond):
        return
    if kind == "user-id" and not used:
        return
    facts.trusted.append(_site(p, off, kind=kind, expr=name, key=key, written=written, source=src))


def _op(method: str) -> str:
    m = method.lower()
    if "delete" in m or "destroy" in m or "remove" in m:
        return "delete"
    if "update" in m or "upsert" in m:
        return "update"
    return "read"


# ---------------------------------------------------------------- RAC007 CORS
def check_cors(jf: JsFile) -> None:
    code, clean = jf.code, jf.clean
    if not re.search(r"cors|Access-Control-Allow", clean, re.I):
        return
    for m in re.finditer(r"\bcredentials\s*:\s*true\b", code):
        # the object literal that contains it
        depth, i = 0, m.start()
        while i > 0:
            i -= 1
            if code[i] == "}":
                depth += 1
            elif code[i] == "{":
                if depth == 0:
                    break
                depth -= 1
        ents = obj_entries(code, i)
        org = next((e for e in ents if e[0] == "origin"), None)
        if org is None:
            continue
        val_code = code[org[1]:org[2]].strip()
        val_clean = clean[org[1]:org[2]].strip()
        how = None
        if val_clean in ("'*'", '"*"', "`*`") or re.fullmatch(r"\[\s*['\"]\*['\"]\s*\]", val_clean):
            how = "star"
        elif val_code == "true":
            how = "reflect"
        elif _is_inline_fn(val_code) and not re.search(r"includes|indexOf|\.has\(|\.test\(|===|==|\.match\(|endsWith|"
                                                       r"startsWith|allow", val_code, re.I):
            if re.search(r"(?:cb|callback|done)\s*\(\s*null\s*,\s*(?:true|origin)\b|=>\s*\(?\s*\w+\s*\)?\s*$|return\s+\w+",
                         val_code):
                how = "reflect"
        if how:
            jf.findings.append(_cors_finding(jf, org[1], how, "cors"))
    # manual headers
    acao = list(re.finditer(r"""['"]Access-Control-Allow-Origin['"]\s*[,:]\s*""", clean, re.I))
    acac = re.search(r"""['"]Access-Control-Allow-Credentials['"]\s*[,:]\s*(?:value\s*:\s*)?['"]?true""", clean, re.I)
    if acao and acac:
        for m in acao:
            line_end = clean.find("\n", m.end())
            val = clean[m.end():line_end if line_end > 0 else len(clean)]
            if re.match(r"""\s*(?:value\s*:\s*)?['"]\*['"]""", val):
                jf.findings.append(_cors_finding(jf, m.start(), "star", "headers"))
            elif re.search(r"origin", val, re.I) and not re.search(
                    r"includes|indexOf|\.has\(|allowed|allowlist|whitelist|===", clean[max(0, m.start() - 600):m.start()], re.I):
                jf.findings.append(_cors_finding(jf, m.start(), "reflect", "headers"))


def _cors_finding(jf: JsFile, off: int, how: str, where: str) -> Finding:
    line = jf.line_of(off)
    fw = jf.framework if jf.framework in ("express", "hono", "fastify") else "node"
    if how == "star":
        msg = ("CORS allows origin '*' together with credentials. Browsers reject this combination, and the usual "
               "fix for the errors is to reflect the caller's origin, which lets any website make logged-in requests.")
    else:
        msg = ("CORS reflects the caller's Origin (any site is allowed) with credentials: any website a logged-in "
               "user visits can call this API with their cookies and read the responses.")
    return Finding("RAC007", "medium", msg, jf.rel, line, redact_line(jf.line_text(line)),
                   extra={"lang": "js", "framework": fw, "how": how, "where": where})
