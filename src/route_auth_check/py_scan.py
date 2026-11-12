"""Python: route discovery and per-handler analysis with the standard `ast` module.

Routes: FastAPI / Starlette (`@app.post`, `@router.delete`, `api_route`), Flask (`@app.route(...,
methods=[...])`, `@bp.post`), Django function views (any module-level `def view(request, ...)` in
a module that imports Django) and class-based views, Django REST Framework APIView / generic
views / ViewSets. Auth is recognised in decorators, FastAPI dependencies (parameters, router and
app level), Flask `before_request` hooks, DRF permission_classes / settings, Django mixins and
LoginRequiredMiddleware, and calls in the handler body."""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass, field

from .common import (AUTH_NAME_RE, IDENTITY_HEADERS, MW_AUTH_RE, ROLE_KEYS, ROLE_NAME_RE, SESSIONISH_RE,
                     TRUST_ID_KEYS, USER_KEY_RE, Facts, Route, Site)
from .findings import Finding, redact_line

PY_NOT_AUTH = re.compile(r"^(?:get_?db|get_?session|get_?async_?session|get_?db_?session|session_?dep|db_?dep|db|"
                         r"get_?settings|get_?redis|get_?client|get_?engine|get_?conn\w*|common_?parameters|pagination\w*|"
                         r"get_?token_?service)$", re.I)
METHOD_DECOS = {"get", "post", "put", "patch", "delete", "api_route", "route", "websocket"}
DRF_WRITE_BASES = {
    "ModelViewSet": ["GET", "POST", "PUT", "PATCH", "DELETE"], "GenericViewSet": ["GET"], "ViewSet": ["GET"],
    "CreateAPIView": ["POST"], "UpdateAPIView": ["PUT", "PATCH"], "DestroyAPIView": ["DELETE"],
    "ListCreateAPIView": ["GET", "POST"], "RetrieveUpdateAPIView": ["GET", "PUT", "PATCH"],
    "RetrieveDestroyAPIView": ["GET", "DELETE"], "RetrieveUpdateDestroyAPIView": ["GET", "PUT", "PATCH", "DELETE"],
    "RetrieveAPIView": ["GET"], "ListAPIView": ["GET"], "ReadOnlyModelViewSet": ["GET"],
}
DRF_DETAIL_BASES = {"ModelViewSet", "UpdateAPIView", "DestroyAPIView", "RetrieveUpdateAPIView", "RetrieveDestroyAPIView",
                    "RetrieveUpdateDestroyAPIView", "RetrieveAPIView", "ReadOnlyModelViewSet"}
DRF_BUILTIN_PERMS = {"IsAuthenticated", "IsAuthenticatedOrReadOnly", "AllowAny", "DjangoModelPermissions",
                     "DjangoModelPermissionsOrAnonReadOnly", "IsAdminUser", "TokenHasReadWriteScope"}
CBV_AUTH_MIXINS = re.compile(r"LoginRequired|PermissionRequired|UserPassesTest|StaffRequired|SuperuserRequired|"
                             r"AccessMixin|Auth\w*Mixin", re.I)
DJANGO_VIEW_BASES = re.compile(r"(?:^|\.)(?:View|TemplateView|FormView|CreateView|UpdateView|DeleteView|DetailView|"
                               r"ListView|RedirectView|APIView|GenericAPIView|\w*ViewSet|\w+APIView)$")


def dotted(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = dotted(node.value)
        return f"{base}.{node.attr}" if base else node.attr
    if isinstance(node, ast.Call):
        return dotted(node.func)
    if isinstance(node, ast.Await):
        return dotted(node.value)
    if isinstance(node, ast.Subscript):
        return dotted(node.value)
    return ""


def _str(node) -> str | None:
    return node.value if isinstance(node, ast.Constant) and isinstance(node.value, str) else None


def _strs(node) -> list[str]:
    if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
        return [s for s in (_str(e) for e in node.elts) if s]
    s = _str(node)
    return [s] if s else []


def _kw(call: ast.Call, name: str):
    return next((k.value for k in call.keywords if k.arg == name), None)


def py_auth_kind(name: str, extra: set[str]) -> str | None:
    """'role' | 'auth' | None for a decorator / dependency / permission name."""
    last = name.split(".")[-1]
    if last in extra or name in extra:
        return "auth"
    if PY_NOT_AUTH.match(last) or re.search(r"not_required|exempt|anonymous|optional", last, re.I) or last in ("AllowAny","api_view", "csrf_exempt", "require_POST",
                                           "require_http_methods", "require_GET", "transaction", "atomic"):
        return None
    if ROLE_NAME_RE.search(last) and not re.search(r"IsAuthenticated", last):
        return "role"
    if MW_AUTH_RE.search(last) or AUTH_NAME_RE.fullmatch(last) or re.search(r"IsAuthenticated|Permission", last):
        return "auth"
    return None


@dataclass
class PyFacts:
    """Project-wide facts gathered from settings / app files."""
    drf_default_auth: str | None = None
    django_login_mw: bool = False
    protected_routers: set[str] = field(default_factory=set)   # module or router names included with auth deps


class PyFile:
    def __init__(self, rel: str, text: str, tree: ast.Module):
        self.rel = rel
        self.text = text
        self.tree = tree
        self.lines = text.splitlines()
        src = text
        self.framework = ("fastapi" if re.search(r"^\s*(?:from|import)\s+(?:fastapi|starlette)\b", src, re.M) else
                          "flask" if re.search(r"^\s*(?:from|import)\s+flask\b", src, re.M) else
                          "drf" if re.search(r"^\s*(?:from|import)\s+rest_framework\b", src, re.M) else
                          "django" if re.search(r"^\s*(?:from|import)\s+django\b", src, re.M) else "python")
        self.routes: list[Route] = []
        self.findings: list[Finding] = []
        self.funcs: dict[str, ast.AST] = {}
        self.classes: dict[str, ast.ClassDef] = {}
        for n in tree.body:
            if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)):
                self.funcs[n.name] = n
            elif isinstance(n, ast.ClassDef):
                self.classes[n.name] = n
        self.models = {name for name, c in self.classes.items()
                       if any(dotted(b).split(".")[-1] in ("BaseModel", "Schema", "SQLModel") for b in c.bases)}

    def line_text(self, line: int) -> str:
        return self.lines[line - 1] if 0 < line <= len(self.lines) else ""

    def ev(self, line: int) -> str:
        return redact_line(self.line_text(line))


# ---------------------------------------------------------------- discovery
def discover(pf: PyFile, extra: set[str], facts: PyFacts) -> None:
    routers = _router_auth(pf, extra)
    hooks = _before_request(pf, extra)
    aliases = _annotated_aliases(pf, extra)
    pf.meta = {"routers": routers, "hooks": hooks, "aliases": aliases}
    _settings(pf, facts)
    _include_router(pf, extra, facts)
    for fn in pf.funcs.values():
        _decorated_route(pf, fn, extra) or _django_function_view(pf, fn, extra)
    for cls in pf.classes.values():
        _class_view(pf, cls, extra)
    check_cors(pf)
    check_serializers(pf)


def _router_auth(pf: PyFile, extra: set[str]) -> dict[str, tuple[str | None, str | None, bool]]:
    """router / app name -> (auth, prefix, role) from APIRouter(dependencies=[...]) / FastAPI(dependencies=[...])."""
    out = {}
    for n in pf.tree.body:
        if isinstance(n, ast.Assign) and isinstance(n.value, ast.Call) and \
                dotted(n.value.func).split(".")[-1] in ("APIRouter", "FastAPI", "Blueprint", "Flask"):
            auth, role = None, False
            deps = _kw(n.value, "dependencies")
            for d in getattr(deps, "elts", []) or []:
                if isinstance(d, ast.Call) and d.args:
                    nm = dotted(d.args[0])
                    k = py_auth_kind(nm, extra)
                    if k:
                        auth = f"router dependencies=[Depends({nm})]"
                        role |= k == "role"
            prefix = _str(_kw(n.value, "prefix")) or _str(_kw(n.value, "url_prefix"))
            for t in n.targets:
                if isinstance(t, ast.Name):
                    out[t.id] = (auth, prefix, role)
    return out


def _before_request(pf: PyFile, extra: set[str]) -> dict[str, tuple[str, str | None]]:
    """blueprint / app name -> (label, role check) for before_request hooks that authenticate."""
    out = {}
    for fn in pf.funcs.values():
        for d in fn.decorator_list:
            nm = dotted(d)
            if nm.endswith(".before_request") or nm.endswith(".before_app_request"):
                found = _body_auth(fn, extra)
                if found:
                    role = _role_check_py(ast.unparse(fn), set())
                    out[nm.rsplit(".", 1)[0]] = (f"before_request {fn.name}() ({found})", role)
    return out


def _annotated_aliases(pf: PyFile, extra: set[str]) -> dict[str, str]:
    """CurrentUser = Annotated[User, Depends(get_current_user)] -> {"CurrentUser": "get_current_user"}."""
    out = {}
    for n in pf.tree.body:
        if isinstance(n, ast.Assign) and isinstance(n.value, ast.Subscript) and dotted(n.value.value).endswith("Annotated"):
            for c in ast.walk(n.value):
                if isinstance(c, ast.Call) and dotted(c.func).split(".")[-1] in ("Depends", "Security") and c.args:
                    nm = dotted(c.args[0])
                    if py_auth_kind(nm, extra):
                        for t in n.targets:
                            if isinstance(t, ast.Name):
                                out[t.id] = nm
    return out


def _settings(pf: PyFile, facts: PyFacts) -> None:
    for n in pf.tree.body:
        if not isinstance(n, ast.Assign) or not n.targets or not isinstance(n.targets[0], ast.Name):
            continue
        name = n.targets[0].id
        if name == "REST_FRAMEWORK" and isinstance(n.value, ast.Dict):
            for k, v in zip(n.value.keys, n.value.values):
                if _str(k) == "DEFAULT_PERMISSION_CLASSES":
                    perms = [p.split(".")[-1] for p in _strs(v)]
                    if perms and not all(p == "AllowAny" for p in perms):
                        facts.drf_default_auth = f"DEFAULT_PERMISSION_CLASSES ({', '.join(perms)})"
        if name == "MIDDLEWARE":
            if any(s.endswith("LoginRequiredMiddleware") for s in _strs(n.value)):
                facts.django_login_mw = True


def _include_router(pf: PyFile, extra: set[str], facts: PyFacts) -> None:
    for c in ast.walk(pf.tree):
        if isinstance(c, ast.Call) and dotted(c.func).endswith("include_router") and c.args:
            deps = _kw(c, "dependencies")
            for d in getattr(deps, "elts", []) or []:
                if isinstance(d, ast.Call) and d.args and py_auth_kind(dotted(d.args[0]), extra):
                    target = dotted(c.args[0])
                    facts.protected_routers.add(target.split(".")[0] if "." in target else target)
                    facts.protected_routers.add(target)


def _mk(pf: PyFile, fn, framework: str, methods: list[str], path: str | None, label: str, line: int, **meta) -> Route:
    r = Route(file=pf.rel, line=line, lang="py", framework=framework, methods=methods, path=path, label=label,
              name=getattr(fn, "name", None), evidence=pf.ev(line))
    r.meta.update({"pf": pf, "fn": fn, "mw_auth": [], "mw_role": [], **meta})
    pf.routes.append(r)
    return r


def _decorated_route(pf: PyFile, fn, extra: set[str]) -> bool:
    found = False
    for d in fn.decorator_list:
        if not isinstance(d, ast.Call) or not isinstance(d.func, ast.Attribute):
            continue
        meth = d.func.attr
        if meth not in METHOD_DECOS:
            continue
        recv = dotted(d.func.value)
        path = _str(d.args[0]) if d.args else _str(_kw(d, "path")) or _str(_kw(d, "rule"))
        if path is None:
            continue
        if meth in ("route", "api_route"):
            methods = [m.upper() for m in _strs(_kw(d, "methods"))] or ["GET"]
        elif meth == "websocket":
            continue
        else:
            methods = [meth.upper()]
        fw = "flask" if pf.framework == "flask" else "fastapi" if pf.framework in ("fastapi", "python") else pf.framework
        rinfo = pf.meta["routers"].get(recv, (None, None, False))
        full = (rinfo[1] or "").rstrip("/") + path if rinfo[1] else path
        r = _mk(pf, fn, fw, methods, full, f"{'/'.join(methods)} {full}", d.lineno, recv=recv, deco=d)
        if rinfo[0]:
            r.meta["mw_auth"].append(rinfo[0])
            if rinfo[2]:
                r.meta["mw_role"].append(rinfo[0])
        if recv in pf.meta["hooks"]:
            label, hook_role = pf.meta["hooks"][recv]
            r.meta["mw_auth"].append(label)
            if hook_role:
                r.meta["mw_role"].append(label)
        for dep in getattr(_kw(d, "dependencies"), "elts", []) or []:
            if isinstance(dep, ast.Call) and dep.args:
                nm = dotted(dep.args[0])
                k = py_auth_kind(nm, extra)
                if k:
                    r.meta["mw_auth"].append(f"dependencies=[Depends({nm})]")
                    if k == "role":
                        r.meta["mw_role"].append(nm)
        _decorator_auth(r, fn, extra)
        _param_auth(pf, r, fn, extra)
        found = True
    return found


def _decorator_auth(r: Route, fn, extra: set[str]) -> None:
    for d in fn.decorator_list:
        nm = dotted(d)
        last = nm.split(".")[-1]
        if last in METHOD_DECOS:
            continue
        if last == "permission_classes" and isinstance(d, ast.Call) and d.args:
            perms = [dotted(e).split(".")[-1] for e in getattr(d.args[0], "elts", [])]
            if perms and not all(p == "AllowAny" for p in perms):
                r.meta["mw_auth"].append(f"@permission_classes({', '.join(perms)})")
                if "IsAdminUser" in perms or any(p not in DRF_BUILTIN_PERMS for p in perms):
                    r.meta["mw_role"].append("permission_classes")
            continue
        k = py_auth_kind(nm, extra)
        if k:
            r.meta["mw_auth"].append(f"@{nm}")
            if k == "role" or last in ("permission_required", "user_passes_test", "staff_member_required"):
                r.meta["mw_role"].append(f"@{nm}")


def _param_auth(pf: PyFile, r: Route, fn, extra: set[str]) -> None:
    args = fn.args.args + fn.args.kwonlyargs
    defaults = [None] * (len(fn.args.args) - len(fn.args.defaults)) + list(fn.args.defaults) + list(fn.args.kw_defaults)
    for a, dflt in zip(args, defaults):
        names = []
        if isinstance(dflt, ast.Call) and dotted(dflt.func).split(".")[-1] in ("Depends", "Security") and dflt.args:
            names.append(dotted(dflt.args[0]))
        ann = a.annotation
        if ann is not None:
            for c in ast.walk(ann):
                if isinstance(c, ast.Call) and dotted(c.func).split(".")[-1] in ("Depends", "Security") and c.args:
                    names.append(dotted(c.args[0]))
            an = dotted(ann)
            if an in pf.meta["aliases"]:
                names.append(pf.meta["aliases"][an])
            elif an and re.fullmatch(r"(?:Current|Active|Authenticated|Admin|Superuser)\w*(?:User|Admin|Superuser)\w*", an):
                names.append(an)
        if a.arg in ("current_user", "current_active_user", "auth_user", "authenticated_user", "admin_user") and \
                (dflt is not None or ann is not None):
            names.append(a.arg)
        for nm in names:
            k = py_auth_kind(nm, extra)
            if k:
                r.meta["mw_auth"].append(f"Depends({nm})" if nm != a.arg else a.arg)
                if k == "role":
                    r.meta["mw_role"].append(nm)


def _django_function_view(pf: PyFile, fn, extra: set[str]) -> bool:
    if pf.framework not in ("django", "drf") or fn.name.startswith("_"):
        return False
    args = fn.args.args
    if not args or args[0].arg != "request":
        return False
    methods: list[str] = []
    for d in fn.decorator_list:
        nm = dotted(d).split(".")[-1]
        if nm == "require_POST":
            methods = ["POST"]
        elif nm == "require_safe" or nm == "require_GET":
            methods = ["GET"]
        elif nm in ("require_http_methods", "api_view") and isinstance(d, ast.Call) and d.args:
            methods = [m.upper() for m in _strs(d.args[0])]
    if not methods:
        body = ast.unparse(fn)
        methods = sorted({m for m in re.findall(r"request\.method\s*(?:==|!=|in)\s*[\[(]?\s*['\"](\w+)['\"]", body)
                          if m in ("POST", "PUT", "PATCH", "DELETE", "GET")}) or ["ALL"]
        if any(isinstance(d, ast.Call) and dotted(d).endswith("api_view") and not d.args for d in fn.decorator_list):
            methods = ["GET"]
    fw = "drf" if any(dotted(d).split(".")[-1] == "api_view" for d in fn.decorator_list) else "django"
    line = fn.decorator_list[0].lineno if fn.decorator_list else fn.lineno
    r = _mk(pf, fn, fw, methods, None, f"{fn.name}()", line, path_params=[a.arg for a in args[1:]])
    _decorator_auth(r, fn, extra)
    if fw == "drf" and not any(dotted(d).split(".")[-1] == "permission_classes" for d in fn.decorator_list):
        r.meta["drf_default"] = True
    return True


def _class_view(pf: PyFile, cls: ast.ClassDef, extra: set[str]) -> None:
    bases = [dotted(b) for b in cls.bases]
    if not any(DJANGO_VIEW_BASES.search(b) for b in bases):
        return
    base_last = [b.split(".")[-1] for b in bases]
    drf = any(b in DRF_WRITE_BASES or b.endswith("APIView") or b.endswith("ViewSet") for b in base_last)
    fw = "drf" if drf else "django"
    auth, role = None, None
    for b in base_last:
        if CBV_AUTH_MIXINS.search(b):
            auth = b
            if re.search(r"Permission|UserPassesTest|Staff|Superuser", b):
                role = b
    attrs = {}
    for n in cls.body:
        if isinstance(n, ast.Assign) and n.targets and isinstance(n.targets[0], ast.Name):
            attrs[n.targets[0].id] = n
    pc = attrs.get("permission_classes")
    perms = [dotted(e).split(".")[-1] for e in getattr(pc.value, "elts", [])] if pc else None
    if perms is not None and perms and not all(p == "AllowAny" for p in perms):
        auth = f"permission_classes = [{', '.join(perms)}]"
        if "IsAdminUser" in perms or any(p not in DRF_BUILTIN_PERMS for p in perms):
            role = auth
    methods_defined = {n.name: n for n in cls.body if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))}
    implicit = []
    for b in base_last:
        implicit += DRF_WRITE_BASES.get(b, [])
    handlers = {m.upper(): methods_defined[m] for m in ("get", "post", "put", "patch", "delete") if m in methods_defined}
    for m, n in (("create", "POST"), ("update", "PUT"), ("partial_update", "PATCH"), ("destroy", "DELETE"),
                 ("perform_create", "POST"), ("perform_update", "PUT"), ("perform_destroy", "DELETE")):
        if m in methods_defined and n not in handlers:
            handlers[n] = methods_defined[m]
    meths = sorted(set(handlers) | set(implicit), key=["GET", "POST", "PUT", "PATCH", "DELETE"].index)
    if not meths:
        return
    line = cls.lineno
    label = f"{cls.name} ({', '.join(b for b in base_last if DJANGO_VIEW_BASES.search(b)) or base_last[0]})"
    r = _mk(pf, cls, fw, meths, None, label, line, handlers=handlers, cls=cls, attrs=attrs, base_last=base_last,
            drf_default=drf and perms is None and auth is None)
    r.name = cls.name
    if auth:
        r.meta["mw_auth"].append(auth)
    if role:
        r.meta["mw_role"].append(role)
    for fn in methods_defined.values():
        _decorator_auth(r, fn, extra)
    for d in cls.decorator_list:      # @method_decorator(login_required, name="dispatch")
        for c in ast.walk(d):
            if isinstance(c, (ast.Name, ast.Attribute)):
                k = py_auth_kind(dotted(c), extra)
                if k:
                    r.meta["mw_auth"].append(f"@{dotted(c)}")
                    break


# ---------------------------------------------------------------- body analysis
_BODY_AUTH_RES = [
    re.compile(r"\b(?:request|current_user)\.(?:user\.)?is_authenticated\b"),
    re.compile(r"\b(?:get_jwt_identity|verify_jwt_in_request|get_jwt|jwt\.decode|decode_token|verify_id_token)\s*\("),
    re.compile(r"\bsession(?:\.get\(|\[)\s*['\"](?:user|user_id|uid|logged_in|username|email)['\"]"),
    re.compile(r"['\"](?:user|user_id|uid|logged_in|username)['\"]\s+(?:not\s+)?in\s+session\b"),
    re.compile(r"\brequest\.state\.user\b|\bg\.user\b"),
    re.compile(r"\brequest\.headers(?:\.get\(|\[)\s*['\"]authorization['\"]", re.I),
    re.compile(r"\brequest\.META(?:\.get\(|\[)\s*['\"]HTTP_AUTHORIZATION['\"]"),
    re.compile(r"\b(?:CRON_SECRET|API_KEY|ADMIN_TOKEN|INTERNAL_SECRET)\b"),
]


def _body_auth(fn, extra: set[str]) -> str | None:
    for c in ast.walk(fn):
        if isinstance(c, ast.Call):
            nm = dotted(c.func)
            last = nm.split(".")[-1]
            if not last or PY_NOT_AUTH.match(last):
                continue
            if last in extra or nm in extra:
                return f"{nm}()"
            if AUTH_NAME_RE.fullmatch(last) and not re.match(r"(?:get|create|update|delete)_users?_by", last) and \
                    last not in ("get_user_model", "get_users", "user", "session", "login", "me", "token"):
                return f"{nm}()"
    text = ast.unparse(fn)
    for rx in _BODY_AUTH_RES:
        m = rx.search(text)
        if m:
            return m.group(0).rstrip("(").strip()
    return None


class PyTaint:
    """Request input names inside one handler."""

    def __init__(self, pf: PyFile, route: Route, fn):
        self.whole: set[str] = set()                 # names holding the whole body / form / query dict
        self.obj: dict[str, str] = {}                # name -> source for dict-like request objects
        self.scalar: dict[str, tuple[str, str]] = {}   # name -> (source, key)
        self.models: dict[str, str] = {}             # pydantic body params: name -> source "body"
        path_params = set(re.findall(r"[{<](?:\w+:)?(\w+)[}>]", route.path or "")) | set(route.meta.get("path_params", []))
        if route.meta.get("cls") is not None and isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
            # class-based view methods: post(self, request, pk) -> pk comes from the URL
            path_params |= {a.arg for a in fn.args.args[1:] + fn.args.kwonlyargs if a.arg not in ("request", "self")}
        if isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
            args = fn.args.args + fn.args.kwonlyargs
            defaults = [None] * (len(fn.args.args) - len(fn.args.defaults)) + list(fn.args.defaults) + \
                list(fn.args.kw_defaults)
            for a, d in zip(args, defaults):
                if a.arg in ("self", "request", "req", "db", "session", "cls"):
                    continue
                ann = dotted(a.annotation) if a.annotation is not None else ""
                dcall = dotted(d.func).split(".")[-1] if isinstance(d, ast.Call) else ""
                if dcall in ("Depends", "Security") or a.arg in ("current_user",):
                    continue
                if dcall == "Header":
                    self.scalar[a.arg] = ("header", a.arg.replace("_", "-"))
                elif a.arg in path_params:
                    self.scalar[a.arg] = ("path", a.arg)
                elif dcall == "Body" or ann in pf.models or (ann[:1].isupper() and ann not in (
                        "UUID", "Optional", "Request", "Response", "BackgroundTasks", "Session", "AsyncSession",
                        "HTTPRequest", "HttpRequest", "Annotated", "List", "Dict", "Any") and
                        ann not in pf.meta["aliases"] and not re.search(r"User|Session|Db|DB", ann)):
                    self.models[a.arg] = "body"
                elif route.lang == "py" and route.framework == "fastapi":
                    self.scalar[a.arg] = ("query", a.arg)
        for n in ast.walk(fn):
            if isinstance(n, ast.Assign) and len(n.targets) == 1:
                self._assign(n.targets[0], n.value)
            elif isinstance(n, ast.AnnAssign) and n.value is not None:
                self._assign(n.target, n.value)

    def whole_src(self, node) -> str | None:
        while isinstance(node, ast.Await):
            node = node.value
        t = ast.unparse(node)
        if re.fullmatch(r"request\.(?:get_json\(.*\)|json\(\)|json|form|data|POST|values|args|GET|query_params)"
                        r"(?:\.(?:dict|copy|to_dict)\(\))?|json\.loads\(request\.(?:body|data|get_data\(\))\)|"
                        r"dict\(request\.(?:form|POST|args|GET|data)\)", t):
            return "query" if re.search(r"args|GET|query_params", t) else "body"
        if isinstance(node, ast.Name) and node.id in self.whole:
            return self.obj.get(node.id, "body")
        return None

    def _assign(self, target, value) -> None:
        if isinstance(target, ast.Name):
            src = self.whole_src(value)
            if src:
                self.whole.add(target.id)
                self.obj[target.id] = src
                return
            sc = self.scalar_of(value)
            if sc:
                self.scalar[target.id] = sc

    def scalar_of(self, node) -> tuple[str, str] | None:
        while isinstance(node, (ast.Await,)):
            node = node.value
        if isinstance(node, ast.Call) and dotted(node.func) in ("int", "str", "UUID", "uuid.UUID", "ObjectId") and node.args:
            return self.scalar_of(node.args[0])
        if isinstance(node, ast.Name):
            return self.scalar.get(node.id)
        if isinstance(node, ast.Subscript):
            key = _str(node.slice)
            base = node.value
            if key is not None:
                if isinstance(base, ast.Name) and base.id in self.obj:
                    return (self.obj[base.id], key)
                bs = self.whole_src(base)
                if bs:
                    return (bs, key)
                b = ast.unparse(base)
                if re.fullmatch(r"request\.headers|request\.META", b):
                    return ("header", key.lower().replace("http_", "").replace("_", "-"))
                if re.fullmatch(r"(?:self\.)?kwargs", b):
                    return ("path", key)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "get" and node.args:
            key = _str(node.args[0])
            base = node.func.value
            if key is None:
                return None
            if isinstance(base, ast.Name) and base.id in self.obj:
                return (self.obj[base.id], key)
            bs = self.whole_src(base)
            if bs:
                return (bs, key)
            b = ast.unparse(base)
            if re.fullmatch(r"request\.headers|request\.META", b):
                return ("header", key.lower().replace("http_", "").replace("_", "-"))
            if re.fullmatch(r"(?:self\.)?kwargs", b):
                return ("path", key)
        if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name) and node.value.id in self.models:
            return ("body", node.attr)
        return None


def _handler_nodes(route: Route) -> list:
    fn = route.meta["fn"]
    if isinstance(fn, ast.ClassDef):
        return [n for n in fn.body if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))]
    pf = route.meta["pf"]
    out = [fn]
    seen = {fn.name}
    stack = [fn]
    depth = 0
    while stack and depth < 2:          # same-file helpers, two levels
        nxt = []
        for f in stack:
            for c in ast.walk(f):
                if isinstance(c, ast.Call) and isinstance(c.func, ast.Name) and c.func.id in pf.funcs and c.func.id not in seen:
                    seen.add(c.func.id)
                    out.append(pf.funcs[c.func.id])
                    nxt.append(pf.funcs[c.func.id])
        stack = nxt
        depth += 1
    return out


_CMP_PY = re.compile(r"==|!=|\bis not\b|\bis\b|\bnot in\b|\bin\b")
ROLE_CHECK_PY = [
    re.compile(r"\b(?:is_admin|is_staff|is_superuser|isAdmin|is_superadmin)\b"),
    re.compile(r"\brole\w*\b[^\n]{0,40}?(?:==|!=|\bin\b|\bnot in\b)|(?:==|!=)\s*[\w.]*\brole\b"),
    re.compile(r"\bhas_perms?\s*\(|\bhas_role\s*\(|\brequire_(?:admin|role|permission)\w*\s*\(|\bcheck_(?:admin|role|permission)\w*\s*\("),
    re.compile(r"\bIsAdminUser\b|\bstaff_member_required\b|\bpermission_required\b|\buser_passes_test\b"),
]


def _role_check_py(text: str, tainted: set[str]) -> str | None:
    for ln in text.split("\n"):
        if tainted and any(re.search(r"\b" + re.escape(t) + r"\b", ln) for t in tainted):
            continue
        if re.search(r"^\s*(?:if|elif|assert|return|raise)\b|\b(?:and|or|not)\b|\bif\b", ln) or "has_perm" in ln or \
                "require_" in ln or "check_" in ln:
            for rx in ROLE_CHECK_PY:
                m = rx.search(ln)
                if m:
                    return m.group(0).strip()[:60]
    return None


def _owner_check_py(text: str) -> str | None:
    for ln in text.split("\n"):
        if _CMP_PY.search(ln) and USER_KEY_RE.search(ln):
            rest = USER_KEY_RE.sub(" ", ln, count=1)
            if SESSIONISH_RE.search(rest) or USER_KEY_RE.search(rest):
                return ln.strip()[:70]
    m = re.search(r"\b403\b|HTTP_403_FORBIDDEN|PermissionDenied|HttpResponseForbidden|\bForbidden\b|"
                  r"check_object_permissions|has_object_permission|\bcan_\w+\s*\(|\bis_owner\w*\s*\(|"
                  r"\bensure_owner\w*\s*\(|\bassert_owner\w*\s*\(|\bauthorize\w*\s*\(", text)
    return m.group(0) if m else None


WRITE_PY = re.compile(r"\.(?:save|delete|create|update|bulk_create|bulk_update|add|add_all|commit|insert\w*|"
                      r"update_one|update_many|delete_one|delete_many|insert_one|insert_many|get_or_create|"
                      r"update_or_create|merge|execute)\s*\(|\bsend_mail\s*\(|\bsend_email\s*\(")
LIST_USERS_PY = re.compile(r"\b(?:User|get_user_model\(\))\.objects\.all\(\)|\bquery\(\s*User\s*\)\.all\(\)|"
                           r"\bUser\.query\.all\(\)|\bselect\(\s*User\s*\)\s*\)|\bawait\s+User\.all\(\)|"
                           r"\bauth\.list_users\(|\badmin\.list_users\(")
ID_KW = re.compile(r"^(?:id|pk|uuid|_id|\w+_id|\w+_pk)$")
USER_KW = re.compile(r"^(?:user|owner|author|creator|created_by|account|tenant|organization|org|team|workspace|member|"
                     r"members|profile|customer)(?:_id|__\w+)?$|^(?:user_id|owner_id|author_id|created_by_id|tenant_id|"
                     r"org_id|organization_id|team_id|workspace_id|account_id|customer_id)$")


def analyze(route: Route, extra: set[str]) -> Facts:
    pf: PyFile = route.meta["pf"]
    facts = Facts()
    nodes = _handler_nodes(route)
    for fn in nodes:
        a = _body_auth(fn, extra)
        if a:
            facts.auth = a
            break
    text = "\n".join(ast.unparse(n) for n in nodes)
    facts.writes = bool(WRITE_PY.search(text)) or any(m in ("POST", "PUT", "PATCH", "DELETE") for m in route.methods
                                                         if route.framework == "drf")
    facts.touches = facts.writes or bool(re.search(
        r"\b(?:db|session|objects|query|requests|httpx|client|s3|redis|cursor|conn|engine)\b\s*\.|\bawait\b|"
        r"\bsend_mail\s*\(|\b[A-Z]\w*\s*\(", text))
    facts.owner_check = _owner_check_py(text)
    if LIST_USERS_PY.search(text) or (isinstance(route.meta["fn"], ast.ClassDef) and _drf_user_queryset(route)):
        facts.admin_reason = "lists all users"
    tainted_roles: set[str] = set()
    for fn in nodes:
        taint = PyTaint(pf, route, fn)
        tainted_roles |= {n for n, (s, k) in taint.scalar.items() if k in ROLE_KEYS}
        _scan_fn(pf, route, fn, taint, facts)
    facts.role_check = _role_check_py(text, tainted_roles)
    if isinstance(route.meta["fn"], ast.ClassDef):
        _drf_idor(pf, route, facts)
    return facts


def _drf_user_queryset(route: Route) -> bool:
    qs = route.meta.get("attrs", {}).get("queryset")
    return bool(qs and re.fullmatch(r"(?:User|get_user_model\(\))\.objects\.all\(\)", ast.unparse(qs.value)))


def _drf_idor(pf: PyFile, route: Route, facts: Facts) -> None:
    """ModelViewSet / RetrieveUpdateDestroyAPIView with queryset = X.objects.all(), no get_queryset filtering by
    the user and no object-level permission class: any authenticated user can read / change / delete any X."""
    if not any(b in DRF_DETAIL_BASES for b in route.meta.get("base_last", [])):
        return
    attrs = route.meta.get("attrs", {})
    qs = attrs.get("queryset")
    if qs is None:
        return
    qtext = ast.unparse(qs.value)
    if USER_KEY_RE.search(qtext) or "request.user" in qtext:
        return
    cls = route.meta["cls"]
    gq = next((n for n in cls.body if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and
               n.name in ("get_queryset", "get_object")), None)
    if gq is not None and re.search(r"request\.user|USER|user", ast.unparse(gq)):
        return
    pc = attrs.get("permission_classes")
    perms = [dotted(e).split(".")[-1] for e in getattr(pc.value, "elts", [])] if pc else []
    if any(p not in DRF_BUILTIN_PERMS or p == "IsAdminUser" for p in perms) or \
            any(re.search(r"Owner|Object", p) for p in perms):
        return
    model = re.match(r"(\w+)\.objects", qtext)
    ops = [m for m in route.methods if m != "GET"]
    op = "delete" if "DELETE" in ops else "update" if ops else "read"
    facts.idor.append(Site(pf.rel, qs.lineno, pf.ev(qs.lineno),
                           {"op": op, "model": model.group(1) if model else "object", "id": "the pk in the URL",
                            "orm": "drf", "drf": True}))


def _id_value(call: ast.Call, taint: PyTaint) -> tuple[str, bool] | None:
    """(id expression, owner-filtered) for a lookup call, or None when no request id is used."""
    idv, owned = None, False
    for k in call.keywords:
        if k.arg is None:
            continue
        if USER_KW.match(k.arg):
            owned = True
        elif ID_KW.match(k.arg) and taint.scalar_of(k.value):
            idv = ast.unparse(k.value)
    return (idv, owned) if idv else None


def _scan_fn(pf: PyFile, route: Route, fn, taint: PyTaint, facts: Facts) -> None:
    def site(node, **d) -> Site:
        return Site(pf.rel, node.lineno, pf.ev(node.lineno), d)

    deleted, updated = set(), set()
    for c in ast.walk(fn):
        if isinstance(c, ast.Call):
            nm = dotted(c.func)
            if nm.endswith(".delete") and c.args and isinstance(c.args[0], ast.Name):
                deleted.add(c.args[0].id)
            if isinstance(c.func, ast.Attribute) and c.func.attr in ("delete", "remove") and isinstance(c.func.value, ast.Name):
                deleted.add(c.func.value.id)
            if nm == "setattr" and c.args and isinstance(c.args[0], ast.Name):
                updated.add(c.args[0].id)
        if isinstance(c, (ast.Assign, ast.AugAssign)):
            for t in (c.targets if isinstance(c, ast.Assign) else [c.target]):
                if isinstance(t, ast.Attribute) and isinstance(t.value, ast.Name):
                    updated.add(t.value.id)
    assigned_to: dict[int, str] = {}
    for c in ast.walk(fn):
        if isinstance(c, ast.Assign) and len(c.targets) == 1 and isinstance(c.targets[0], ast.Name):
            for sub in ast.walk(c.value):
                assigned_to[id(sub)] = c.targets[0].id

    def op_for(call, tail: str) -> str:
        if tail in ("delete",):
            return "delete"
        if tail in ("update",):
            return "update"
        var = assigned_to.get(id(call))
        if var in deleted:
            return "delete"
        if var in updated:
            return "update"
        return "read"

    def chain_text(call) -> str:
        return ast.unparse(call)

    reported: set[int] = set()
    parents: dict[int, ast.AST] = {}
    for p in ast.walk(fn):
        for ch in ast.iter_child_nodes(p):
            parents[id(ch)] = p

    def outer_call(call):
        """Walk up a method chain: X.objects.filter(...).delete() -> the outermost call."""
        cur = call
        while True:
            p = parents.get(id(cur))
            if isinstance(p, ast.Attribute):
                gp = parents.get(id(p))
                if isinstance(gp, ast.Call) and gp.func is p:
                    cur = gp
                    continue
            return cur

    for c in ast.walk(fn):
        if not isinstance(c, ast.Call):
            continue
        nm = dotted(c.func)
        last = nm.split(".")[-1]
        hit = None
        # Django ORM / Tortoise: X.objects.get(pk=...), get_object_or_404(X, pk=...), X.get(id=...)
        if last in ("get", "filter", "get_or_none", "first", "get_or_404", "filter_by", "update", "delete") and \
                isinstance(c.func, ast.Attribute):
            recv = ast.unparse(c.func.value)
            if "request.user" in recv or "current_user" in recv or "g.user" in recv:
                continue
            if last in ("get", "filter", "get_or_none", "filter_by") and c.keywords:
                v = _id_value(c, taint)
                if v and not v[1]:
                    full = outer_call(c)
                    if USER_KEY_RE.search(ast.unparse(full).replace(ast.unparse(c), "")):
                        continue
                    model = re.match(r"(?:await\s+)?([A-Z]\w*)", recv)
                    tail = dotted(full.func).split(".")[-1] if isinstance(full, ast.Call) else ""
                    hit = (full, v[0], model.group(1) if model else recv.split(".")[0],
                           "django" if ".objects" in recv else "sqlalchemy" if "query" in recv else "orm", tail)
            elif last in ("get", "get_or_404") and c.args and not c.keywords and \
                    re.search(r"\.query$|^(?:db\.)?session$|^db$|^session$|\bdb\.session$", recv):
                model_node = c.args[0] if len(c.args) == 2 else None
                idnode = c.args[1] if len(c.args) == 2 else c.args[0]
                if taint.scalar_of(idnode):
                    model = dotted(model_node) if model_node is not None else recv.split(".")[0]
                    hit = (c, ast.unparse(idnode), model, "sqlalchemy", "")
            elif last == "filter" and c.args:
                for arg in c.args:
                    if isinstance(arg, ast.Compare) and len(arg.ops) == 1 and isinstance(arg.ops[0], ast.Eq):
                        left = ast.unparse(arg.left)
                        if re.search(r"\.(?:id|\w+_id|pk|uuid)$", left) and taint.scalar_of(arg.comparators[0]):
                            full = outer_call(c)
                            if USER_KEY_RE.search(ast.unparse(full)) or re.search(r"current_user|request\.user|g\.user",
                                                                                   ast.unparse(full)):
                                break
                            tail = dotted(full.func).split(".")[-1] if isinstance(full, ast.Call) else ""
                            model = re.search(r"query\(\s*(\w+)", ast.unparse(full))
                            hit = (full, ast.unparse(arg.comparators[0]), model.group(1) if model else left.split(".")[0],
                                   "sqlalchemy", tail)
                            break
        elif nm in ("get_object_or_404", "get_list_or_404") and c.args:
            v = _id_value(c, taint)
            if v and not v[1] and not USER_KEY_RE.search(ast.unparse(c.args[0])) and "request.user" not in ast.unparse(c.args[0]):
                hit = (c, v[0], dotted(c.args[0]).split(".")[0], "django", "")
        elif last in ("get", "get_or_404") and nm.startswith(("db.", "session.", "db.session.")) and len(c.args) == 2:
            if taint.scalar_of(c.args[1]):
                hit = (c, ast.unparse(c.args[1]), dotted(c.args[0]), "sqlalchemy", "")
        elif isinstance(c.func, ast.Name) and c.func.id == "select" and c.args:
            full = outer_call(c)
            ft = ast.unparse(full)
            m = re.search(r"\.where\(\s*(\w+)\.(?:id|\w+_id)\s*==\s*([\w.\[\]'\"]+)\s*\)", ft)
            if m and not USER_KEY_RE.search(ft.replace(m.group(0), "")) and not re.search(r"current_user|request\.user", ft):
                expr = ast.parse(m.group(2), mode="eval").body if re.fullmatch(r"[\w.]+", m.group(2)) else None
                if expr is not None and taint.scalar_of(expr):
                    hit = (full, m.group(2), m.group(1), "sqlalchemy", "")
        if hit and id(hit[0]) not in reported:
            reported.add(id(hit[0]))
            call, idexpr, model, orm, tail = hit
            facts.idor.append(site(call, op=op_for(call, tail), model=model, id=idexpr, orm=orm))

    # --- RAC006
    seen: set[str] = set()
    text = ast.unparse(fn)
    for name, (src, key) in list(taint.scalar.items()):
        if src == "path" or name in seen:
            continue
        kind = "user-id" if key in TRUST_ID_KEYS else "role" if key in ROLE_KEYS else None
        if kind is None:
            continue
        seen.add(name)
        node = next((n for n in ast.walk(fn) if isinstance(n, ast.Name) and n.id == name), None) or \
            next((a for a in fn.args.args if a.arg == name), None) if hasattr(fn, "args") else None
        if node is None:
            continue
        _trusted_py(pf, facts, text, name, node, kind, src, key)
    for c in ast.walk(fn):
        if isinstance(c, (ast.Subscript, ast.Call, ast.Attribute)) and not isinstance(c, ast.Name):
            sc = None
            if isinstance(c, ast.Attribute) and isinstance(c.value, ast.Name) and c.value.id in taint.models:
                sc = ("body", c.attr)
            elif isinstance(c, (ast.Subscript, ast.Call)):
                sc = taint.scalar_of(c)
            if not sc or sc[0] == "path":
                continue
            src, key = sc
            expr = ast.unparse(c)
            if expr in seen:
                continue
            if sc[0] == "header" and key.lower() in IDENTITY_HEADERS:
                seen.add(expr)
                facts.trusted.append(site(c, kind="header", header=key.lower(), expr=expr, written=False, source="header"))
                continue
            kind = "user-id" if key in TRUST_ID_KEYS else "role" if key in ROLE_KEYS else None
            if kind is None:
                continue
            seen.add(expr)
            _trusted_py(pf, facts, text, expr, c, kind, src, key)

    # --- RAC008 mass assignment
    for c in ast.walk(fn):
        if isinstance(c, ast.Call):
            for k in c.keywords:
                if k.arg is None and taint.whole_src(k.value):
                    nm = dotted(c.func)
                    if nm.split(".")[-1] in ("dict", "Response", "JsonResponse", "jsonify", "render", "redirect",
                                             "HTTPException", "print", "format", "update_wrapper"):
                        continue
                    facts.mass.append(site(c, sink=f"{nm}(**{ast.unparse(k.value)})", expr=ast.unparse(k.value)))
            nm = dotted(c.func)
            if nm.endswith("__dict__.update") and c.args and taint.whole_src(c.args[0]):
                facts.mass.append(site(c, sink="__dict__.update()", expr=ast.unparse(c.args[0])))
        if isinstance(c, ast.For) and isinstance(c.iter, ast.Call) and isinstance(c.iter.func, ast.Attribute) and \
                c.iter.func.attr == "items" and taint.whole_src(c.iter.func.value):
            if any(isinstance(s, ast.Call) and dotted(s.func) == "setattr" for s in ast.walk(c)):
                facts.mass.append(site(c, sink="setattr() loop", expr=ast.unparse(c.iter.func.value)))


def _trusted_py(pf: PyFile, facts: Facts, text: str, expr: str, node, kind: str, src: str, key: str) -> None:
    pat = r"(?<![\w.])" + re.escape(expr) + r"(?![\w])"
    for ln in text.split("\n"):
        if re.search(pat, ln) and _CMP_PY.search(ln):
            rest = re.sub(pat, " ", ln)
            if re.search(r"current_user|request\.user|g\.user|user\.id|session|claims|token|payload", rest):
                return
    written = bool(re.search(r"\b\w+\s*=\s*" + re.escape(expr) + r"\s*[,)]", text) or
                   re.search(r"\.\w+\s*=\s*" + re.escape(expr) + r"\s*$", text, re.M))
    in_cond = bool(re.search(r"\bif\b[^\n]*" + pat, text))
    if kind == "role" and not (written or in_cond):
        return
    if kind == "user-id" and len(re.findall(pat, text)) < 2 and not written and "." not in expr and "[" not in expr \
            and "(" not in expr:
        return
    facts.trusted.append(Site(pf.rel, node.lineno, pf.ev(node.lineno),
                              {"kind": kind, "expr": expr, "key": key, "written": written, "source": src}))


# ---------------------------------------------------------------- RAC007 / RAC008 file-level
def check_cors(pf: PyFile) -> None:
    for c in ast.walk(pf.tree):
        if not isinstance(c, ast.Call):
            continue
        nm = dotted(c.func)
        if nm.endswith("add_middleware") and c.args and dotted(c.args[0]).endswith("CORSMiddleware"):
            cred = _kw(c, "allow_credentials")
            if not (isinstance(cred, ast.Constant) and cred.value is True):
                continue
            origins = _strs(_kw(c, "allow_origins"))
            rx = _str(_kw(c, "allow_origin_regex"))
            if "*" in origins or (rx and rx in (".*", ".+", "https?://.*", "^.*$")):
                pf.findings.append(_cors(pf, c.lineno, "fastapi"))
        elif nm.split(".")[-1] == "CORS" and c.args:
            cred = _kw(c, "supports_credentials")
            if not (isinstance(cred, ast.Constant) and cred.value is True):
                continue
            origins = _kw(c, "origins")
            if origins is None or "*" in _strs(origins):
                res = _kw(c, "resources")
                if res is not None and "origins" in ast.unparse(res) and "'*'" not in ast.unparse(res):
                    continue
                pf.findings.append(_cors(pf, c.lineno, "flask"))
    names = {}
    for n in pf.tree.body:
        if isinstance(n, ast.Assign) and n.targets and isinstance(n.targets[0], ast.Name) and isinstance(n.value, ast.Constant):
            names[n.targets[0].id] = (n.value.value, n.lineno)
    allow_all = names.get("CORS_ALLOW_ALL_ORIGINS") or names.get("CORS_ORIGIN_ALLOW_ALL")
    creds = names.get("CORS_ALLOW_CREDENTIALS")
    if allow_all and allow_all[0] is True and creds and creds[0] is True:
        pf.findings.append(_cors(pf, allow_all[1], "django"))


def _cors(pf: PyFile, line: int, fw: str) -> Finding:
    msg = {"fastapi": "CORSMiddleware allows every origin with allow_credentials=True: Starlette then answers with the "
                      "caller's own Origin for cookie requests, so any website can make logged-in requests and read the "
                      "responses.",
           "flask": "Flask-CORS with supports_credentials=True and the default / '*' origins answers with the caller's own "
                    "Origin, so any website can make logged-in requests and read the responses.",
           "django": "django-cors-headers allows all origins with CORS_ALLOW_CREDENTIALS = True: it answers with the "
                     "caller's own Origin, so any website can make logged-in requests and read the responses."}[fw]
    return Finding("RAC007", "medium", msg, pf.rel, line, pf.ev(line),
                   extra={"lang": "py", "framework": fw, "how": "reflect"})


def check_serializers(pf: PyFile) -> None:
    for cls in pf.classes.values():
        if not any(dotted(b).endswith("ModelSerializer") for b in cls.bases):
            continue
        meta = next((n for n in cls.body if isinstance(n, ast.ClassDef) and n.name == "Meta"), None)
        if meta is None:
            continue
        attrs = {n.targets[0].id: n for n in meta.body if isinstance(n, ast.Assign) and n.targets and
                 isinstance(n.targets[0], ast.Name)}
        f = attrs.get("fields")
        if f is not None and _str(f.value) == "__all__" and "read_only_fields" not in attrs:
            pf.findings.append(Finding(
                "RAC008", "medium",
                f"{cls.name} is a ModelSerializer with fields = \"__all__\" and no read_only_fields: when it is used to "
                f"create or update, the client can set every model field (owner, role, is_staff, ...).",
                pf.rel, f.lineno, pf.ev(f.lineno), heuristic=True,
                extra={"lang": "py", "framework": "drf", "serializer": cls.name}))
