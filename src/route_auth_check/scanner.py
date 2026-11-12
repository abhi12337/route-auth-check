"""Walks a folder (or takes a single file), discovers routes in every file, then resolves what
protects each route across files (router mounts, Next.js middleware, DRF / Django settings,
FastAPI include_router dependencies) and applies the rules.
Reads local files only. Never imports, runs or connects to anything it scans."""

from __future__ import annotations

import ast
import fnmatch
import os
import posixpath
import re
from dataclasses import dataclass, field
from pathlib import Path

from . import js_scan, py_scan
from .common import Route
from .findings import Finding
from .routes import evaluate, middleware_findings

MAX_BYTES_DEFAULT = 2 * 1024 * 1024
IGNORE_MARK = "route-auth-check: ignore"
SKIP_DIRS = {"node_modules", ".git", ".hg", ".svn", "dist", "build", "out", ".next", ".nuxt", ".vercel", ".output",
             ".svelte-kit", ".venv", "venv", "env", "__pycache__", "site-packages", ".tox", ".nox", ".mypy_cache",
             ".pytest_cache", ".ruff_cache", "coverage", ".turbo", ".cache", ".idea", "target", "vendor", ".gradle",
             "migrations"}
TEST_DIRS = {"test", "tests", "__tests__", "spec", "specs", "fixtures", "__fixtures__", "testdata", "e2e",
             "__mocks__", "mocks"}
PY_EXT = {".py"}
JS_EXT = {".ts", ".mts", ".cts", ".js", ".mjs", ".cjs", ".tsx", ".jsx"}
RESOLVE_EXT = ["", ".ts", ".tsx", ".js", ".mjs", ".cjs", ".jsx", "/index.ts", "/index.tsx", "/index.js", "/index.mjs"]


@dataclass
class ScanResult:
    root: str
    findings: list[Finding] = field(default_factory=list)
    routes: list[Route] = field(default_factory=list)
    files_scanned: int = 0


def _is_test_file(name: str) -> bool:
    n = name.lower()
    return n.startswith("test_") or n == "conftest.py" or n.endswith((
        "_test.py", ".test.ts", ".test.js", ".spec.ts", ".spec.js", ".test.mjs", ".spec.mjs", ".test.tsx",
        ".spec.tsx", ".test.jsx", ".spec.jsx", ".stories.tsx", ".stories.ts"))


def _read(p: Path, max_bytes: int) -> str | None:
    try:
        if p.stat().st_size > max_bytes:
            return None
        data = p.read_bytes()
    except OSError:
        return None
    if b"\x00" in data[:4096]:
        return None
    return data.decode("utf-8", errors="replace")


def _collect(target: str, excludes: list[str], include_tests: bool) -> tuple[str, list[tuple[Path, str]]]:
    root = Path(target)
    if root.is_file():
        return str(root.resolve().parent), [(root, target.replace("\\", "/"))]
    out = []
    for dirpath, dirnames, filenames in os.walk(root):
        rel_dir = os.path.relpath(dirpath, root).replace("\\", "/")
        rel_dir = "" if rel_dir == "." else rel_dir + "/"
        keep = []
        for d in sorted(dirnames):
            if d in SKIP_DIRS or (not include_tests and d.lower() in TEST_DIRS):
                continue
            if d.startswith(".") and d not in (".github",):
                continue
            if any(fnmatch.fnmatch(rel_dir + d, pat) or fnmatch.fnmatch(rel_dir + d + "/", pat) for pat in excludes):
                continue
            keep.append(d)
        dirnames[:] = keep
        for fn in sorted(filenames):
            rel = rel_dir + fn
            if any(fnmatch.fnmatch(rel, pat) for pat in excludes):
                continue
            if not include_tests and _is_test_file(fn):
                continue
            out.append((Path(dirpath) / fn, rel))
    return str(root.resolve()), out


def scan_path(target: str, *, excludes: list[str] | None = None, include_tests: bool = False,
              max_bytes: int = MAX_BYTES_DEFAULT, auth_fns: list[str] | None = None) -> ScanResult:
    extra = set(auth_fns or [])
    root, files = _collect(target, excludes or [], include_tests)
    res = ScanResult(root)
    jfiles: dict[str, js_scan.JsFile] = {}
    pfiles: dict[str, py_scan.PyFile] = {}
    pyfacts = py_scan.PyFacts()
    texts: dict[str, str] = {}
    for path, rel in files:
        suffix = path.suffix.lower()
        if suffix not in PY_EXT and (suffix not in JS_EXT or path.name.endswith((".d.ts", ".min.js"))):
            continue
        text = _read(path, max_bytes)
        if text is None:
            continue
        res.files_scanned += 1
        texts[rel] = text
        if suffix in PY_EXT:
            try:
                tree = ast.parse(text)
            except (SyntaxError, ValueError):
                continue
            pf = py_scan.PyFile(rel, text, tree)
            py_scan.discover(pf, extra, pyfacts)
            pfiles[rel] = pf
        else:
            jf = js_scan.JsFile(rel, text)
            js_scan.discover(jf, extra)
            jfiles[rel] = jf
    findings: list[Finding] = []
    routes: list[Route] = []
    ctx_base = {"file_text": texts}
    _resolve_js(jfiles, extra)
    mws = [jf.middleware for jf in jfiles.values() if jf.middleware is not None]
    for mw in mws:
        mw.text = texts.get(mw.file, "")
    for jf in jfiles.values():
        findings += jf.findings
        for r in jf.routes:
            ctx = dict(ctx_base)
            _apply_middleware(r, mws, ctx)
            r.facts = js_scan.analyze(r, extra)
            findings += evaluate(r, ctx)
            routes.append(r)
    for pf in pfiles.values():
        findings += pf.findings
        for r in pf.routes:
            _apply_py_project(r, pf, pyfacts)
            r.facts = py_scan.analyze(r, extra)
            findings += evaluate(r, dict(ctx_base))
            routes.append(r)
    for mw in mws:
        findings += middleware_findings(mw, routes)
    seen = set()
    for f in findings:
        key = (f.rule_id, f.file, f.line)
        if key in seen:
            continue
        seen.add(key)
        lines = texts.get(f.file, "").splitlines()
        raw = lines[f.line - 1] if f.line and 0 < f.line <= len(lines) else ""
        if IGNORE_MARK in raw:
            continue
        res.findings.append(f)
    # suppressing a route's own line also hides it from the route list status
    res.routes = sorted(routes, key=lambda r: (r.file, r.line))
    return res


# ---------------------------------------------------------------- JS cross-file resolution
def _resolve_spec(files: dict, from_rel: str, spec: str) -> str | None:
    base = posixpath.dirname(from_rel)
    cands = []
    if spec.startswith("."):
        cands.append(posixpath.normpath(posixpath.join(base, spec)))
    elif spec.startswith(("@/", "~/")):
        rest = spec[2:]
        parts = from_rel.split("/")
        for i in range(len(parts)):
            prefix = "/".join(parts[:i])
            for mid in ("", "src/"):
                cands.append(posixpath.normpath(posixpath.join(prefix, mid + rest)) if prefix else mid + rest)
    else:
        return None
    for c in cands:
        c = c.lstrip("./") if c.startswith("./") else c
        for ext in RESOLVE_EXT:
            if c + ext in files:
                return c + ext
        stem = re.sub(r"\.(?:js|mjs|cjs|jsx)$", "", c)
        for ext in (".ts", ".tsx", ".mts"):
            if stem + ext in files:
                return stem + ext
    return None


def _find_export(jf: js_scan.JsFile, name: str):
    if name == "default":
        m = re.search(r"export\s+default\s+(?:async\s+)?function\s*\*?\s*(" + js_scan.IDENT + r")?\s*\(", jf.code)
        if m:
            return next((f for f in jf.fns if f.popen == m.end() - 1), None)
        m = re.search(r"(?:export\s+default|module\.exports\s*=)\s*(" + js_scan.IDENT + r")\s*;?\s*(?:\n|$)", jf.code)
        if m:
            return jf.exported_fn(m.group(1))
        return None
    if name == "*":
        return None
    f = jf.exported_fn(name)
    if f is None:
        m = re.search(r"(?:module\.)?exports\s*\.\s*" + re.escape(name) + r"\s*=\s*(" + js_scan.IDENT + r")", jf.code)
        if m:
            f = jf.exported_fn(m.group(1))
    return f


@dataclass
class _Mount:
    parent: js_scan.JsFile
    use: js_scan.Use
    target_file: str | None
    target_recv: str | None
    prefix: str
    items: list


def _prefix_match(prefix: str | None, path: str | None) -> bool:
    if not prefix or prefix in ("*", "/*", "/"):
        return True
    p = (path or "/")
    pre = prefix.rstrip("*").rstrip("/")
    return p == pre or p.startswith(pre + "/") or (prefix.endswith("*") and p.startswith(prefix.rstrip("*")))


def _resolve_js(jfiles: dict[str, js_scan.JsFile], extra: set[str]) -> None:
    route_files = {rel for rel, jf in jfiles.items() if jf.routes or jf.uses}
    mounts: list[_Mount] = []
    for jf in jfiles.values():
        for u in jf.uses:
            if u.kind == "hook":
                continue
            for idx, (kind, s, a, b) in enumerate(u.items):
                if kind != "ident":
                    continue
                head = s.split(".")[0]
                if head in jf.routers:
                    mounts.append(_Mount(jf, u, None, head, u.prefix or "", u.items[:idx]))
                elif head in jf.imports:
                    tgt = _resolve_spec(jfiles, jf.rel, jf.imports[head][0])
                    if tgt and tgt in route_files:
                        mounts.append(_Mount(jf, u, tgt, None, u.prefix or "", u.items[:idx]))
    mount_args = {(id(m.use), a) for m in mounts for (_, _, a, _) in m.use.items if (m.target_file or m.target_recv)}

    def uses_auth(jf, recv, before, path) -> tuple[list[str], list[str]]:
        auths, roles = [], []
        for u in jf.uses:
            if u.kind == "register" or (u.recv != recv and recv != "?"):
                continue
            if not (u.anywhere or u.off < before):
                continue
            if u.kind != "hook" and not _prefix_match(u.prefix, path):
                continue
            items = [it for it in u.items if (id(u), it[2]) not in mount_args]
            routers = [it for it in items if it[0] == "ident" and (it[1] in jf.routers or it[1] in jf.imports and
                       _resolve_spec(jfiles, jf.rel, jf.imports[it[1]][0]) in route_files)]
            items = [it for it in items if it not in routers]
            if routers and u.kind == "route":
                continue
            a, r, _opaque, _spans = js_scan.classify_items(jf, items, extra)
            label = f"{u.recv}.{'addHook' if u.kind == 'hook' else 'use'}({', '.join(a)})"
            if a:
                auths.append(label)
            if r:
                roles.append(label)
        return auths, roles

    def chains(jf, recv, depth=0) -> list[tuple[str, list[str], list[str]]]:
        if depth > 3:
            return [("", [], [])]
        out = []
        for m in mounts:
            if (m.target_file == jf.rel) or (m.target_recv is not None and m.parent is jf and m.target_recv == recv):
                a, r, _o, _s = js_scan.classify_items(m.parent, m.items, extra)
                labels_a = [f"{m.use.recv}.{m.use.kind}({m.prefix!r}, {x}, ...)" for x in a]
                pa, pr = uses_auth(m.parent, m.use.recv, m.use.off, m.prefix)
                for pre, ca, cr in chains(m.parent, m.use.recv, depth + 1):
                    out.append((pre.rstrip("/") + (m.prefix.rstrip("/") if m.prefix not in ("/", "") else ""),
                                ca + pa + labels_a, cr + pr + (labels_a if r else [])))
        return out or [("", [], [])]

    for jf in jfiles.values():
        for r in jf.routes:
            for spec, name in r.meta["refs"]:
                tgt = _resolve_spec(jfiles, jf.rel, spec)
                f = _find_export(jfiles[tgt], name) if tgt else None
                if f is None:
                    r.opaque = True
                else:
                    r.meta["spans"].append((jfiles[tgt], f.popen, f.bend))
            _follow_imports(r, jfiles)
            if r.framework in ("next-app", "next-pages", "server-action"):
                continue
            recv = r.meta.get("recv", "?")
            la, lr = uses_auth(jf, recv, r.meta["off"], r.path)
            cs = chains(jf, recv)
            pre = cs[0][0]
            r.meta["local_path"] = r.path
            if pre:
                r.path = pre + (r.path if r.path != "/" else "")
                meth = r.label.split(" ", 1)[0]
                r.label = f"{meth} {r.path}"
            ext = la + [x for c in cs for x in c[1]]
            roles = lr + [x for c in cs for x in c[2]]
            r.meta.setdefault("ext_auth", []).extend(ext)
            r.meta["mw_role"] += roles


def _follow_imports(r: Route, jfiles: dict) -> None:
    """Add functions the handler calls that are imported from scanned files (one level), so an auth
    check or data access inside a local helper (lib/auth.ts, services/*.ts) is seen."""
    seen = {(jf.rel, a) for jf, a, _ in r.meta["spans"]}
    for jf, a, b in list(r.meta["spans"]):
        for name in sorted(set(re.findall(r"(?<![\w$.])([A-Za-z_$][\w$]*)\s*(?:<[^>()]*>)?\s*\(", jf.code[a:b]))):
            if name not in jf.imports:
                continue
            spec, imported = jf.imports[name]
            tgt = _resolve_spec(jfiles, jf.rel, spec)
            f = _find_export(jfiles[tgt], imported) if tgt else None
            if f is not None and (tgt, f.popen) not in seen:
                seen.add((tgt, f.popen))
                r.meta["spans"].append((jfiles[tgt], f.popen, f.bend))


def _apply_middleware(r: Route, mws: list, ctx: dict) -> None:
    mine = [m for m in mws if not m.root or r.file.startswith(m.root + "/")]
    ctx["mw_all"] = any(m.auth and m.covers("/") and m.covers("/dashboard/settings") for m in mine)
    if r.framework not in ("next-app", "next-pages") or not mine:
        return
    for m in mine:
        if m.covers(r.path or "/"):
            r.meta.setdefault("mw_ext", []).append(f"{m.file} ({m.auth})")
            r.meta["mw_covered"] = True
            ctx["mw_headers"] = m.sets_headers
            return
    if any(m.auth for m in mine):
        r.meta["mw_note"] = f"{mine[0].file} does not cover this path"


def _apply_py_project(r: Route, pf: py_scan.PyFile, facts: py_scan.PyFacts) -> None:
    ext = r.meta.setdefault("ext_auth", [])
    if r.meta.get("drf_default") and facts.drf_default_auth:
        ext.append(f"settings REST_FRAMEWORK {facts.drf_default_auth}")
        r.meta["drf_default"] = False
    if facts.django_login_mw and r.framework in ("django", "drf"):
        fn = r.meta["fn"]
        decos = [py_scan.dotted(d) for d in getattr(fn, "decorator_list", [])]
        if not any(d.endswith("login_not_required") for d in decos):
            ext.append("LoginRequiredMiddleware")
    if facts.protected_routers:
        stem = posixpath.splitext(posixpath.basename(r.file))[0]
        recv = r.meta.get("recv", "")
        if stem in facts.protected_routers or recv in facts.protected_routers or f"{stem}.{recv}" in facts.protected_routers:
            ext.append("include_router(..., dependencies=[Depends(...)])")
