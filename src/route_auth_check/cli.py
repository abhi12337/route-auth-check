"""Command line interface.

  route-auth-check scan [PATH ...]
  route-auth-check rules
"""

from __future__ import annotations

import argparse
import os
import sys
import textwrap
from collections import Counter

from . import __version__
from .findings import RULES, SEVERITIES, SEVERITY_RANK, Finding
from .report import render_json, render_text, use_color
from .scanner import MAX_BYTES_DEFAULT, ScanResult, scan_path

EXIT_OK, EXIT_FINDINGS, EXIT_ERROR = 0, 1, 2
FW_LABELS = {"next-app": "Next.js App Router", "next-pages": "Next.js pages/api", "server-action": "Server Actions",
             "express": "Express", "hono": "Hono", "fastify": "Fastify", "koa": "Koa", "fastapi": "FastAPI",
             "flask": "Flask", "django": "Django", "drf": "DRF"}


def _exit_code(findings: list[Finding], fail_on: str) -> int:
    if fail_on == "never":
        return EXIT_OK
    lim = SEVERITY_RANK[fail_on]
    return EXIT_FINDINGS if any(SEVERITY_RANK[f.severity] <= lim for f in findings) else EXIT_OK


def _filter_min(findings: list[Finding], min_sev: str) -> list[Finding]:
    lim = SEVERITY_RANK[min_sev]
    return [f for f in findings if SEVERITY_RANK[f.severity] <= lim]


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="route-auth-check",
        description="Static check for API routes that are missing authentication or authorization (IDOR) in "
                    "Next.js, Express, Hono, Fastify, FastAPI, Flask and Django / DRF. Reads files only: never "
                    "runs your code or sends a request.",
        epilog="A clean report is not a guarantee. See 'What it does not check' in the README.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    s = sub.add_parser("scan", help="scan folders / files")
    s.add_argument("paths", nargs="*", default=None, help="folders or files to scan (default: .)")
    s.add_argument("--auth-fn", action="append", default=[], metavar="NAME",
                   help="treat a call / middleware / decorator / dependency with this name as an auth check "
                        "(repeatable), e.g. --auth-fn getMe --auth-fn require_member")
    s.add_argument("--exclude", action="append", default=[], metavar="GLOB",
                   help="glob of paths to skip (repeatable), e.g. --exclude 'scripts/*'")
    s.add_argument("--include-tests", action="store_true", help="also scan test / fixture / mock files")
    s.add_argument("--disable", action="append", default=[], metavar="RULE",
                   help="ignore a rule id (repeatable), e.g. --disable RAC008")
    s.add_argument("--max-file-mb", type=float, default=MAX_BYTES_DEFAULT / 1024 / 1024,
                   help="skip files larger than this (default: 2)")
    s.add_argument("--json", action="store_true", help="print a JSON report instead of text")
    s.add_argument("--fail-on", choices=[*SEVERITIES, "never"], default="high",
                   help="exit 1 if any finding is at or above this severity (default: high)")
    s.add_argument("--min-severity", choices=SEVERITIES, default="info",
                   help="hide findings below this severity (default: info = show all)")
    s.add_argument("--no-color", action="store_true", help="disable ANSI colours")
    s.add_argument("--brief", action="store_true", help="omit the why/fix text")

    sub.add_parser("rules", help="list every rule with why it matters and how to fix it")
    return parser


def _route_summary(results: list[ScanResult]) -> tuple[str, list[str]]:
    rs = [r for res in results for r in res.routes]
    fws = Counter(FW_LABELS.get(r.framework, r.framework) for r in rs)
    status = Counter(r.status for r in rs)
    line = f"{len(rs)} route(s)"
    if fws:
        line += " (" + ", ".join(f"{k} {v}" for k, v in sorted(fws.items(), key=lambda kv: (-kv[1], kv[0]))) + ")"
    extra = []
    if rs:
        extra.append("auth: " + ", ".join(f"{status.get(k, 0)} {k}" for k in ("protected", "public", "unprotected",
                                                                                 "unknown")))
    else:
        extra.append("No routes found (looked for Next.js route handlers, pages/api, server actions, Express, Hono, "
                     "Fastify, FastAPI, Flask and Django / DRF views).")
    return line, extra


def cmd_scan(args) -> int:
    paths = args.paths or ["."]
    for p in paths:
        if not os.path.exists(p):
            print(f"error: {p} does not exist", file=sys.stderr)
            return EXIT_ERROR
    unknown = [r for r in args.disable if r.upper() not in RULES]
    if unknown:
        print(f"error: unknown rule id(s): {', '.join(unknown)} (see `route-auth-check rules`)", file=sys.stderr)
        return EXIT_ERROR
    max_bytes = int(args.max_file_mb * 1024 * 1024)
    results = [scan_path(p, excludes=args.exclude, include_tests=args.include_tests, max_bytes=max_bytes,
                         auth_fns=args.auth_fn) for p in paths]
    if len(results) > 1:   # make locations unambiguous
        for r, label in zip(results, paths):
            if os.path.isfile(label):
                continue
            for item in [*r.findings, *r.routes]:
                if item.file and label != ".":
                    item.file = f"{label.rstrip('/').rstrip(chr(92))}/{item.file}".replace("\\", "/")
            for x in r.skipped:
                if label != ".":
                    x["path"] = f"{label.rstrip('/').rstrip(chr(92))}/{x['path']}".replace("\\", "/")
    disabled = {r.upper() for r in args.disable}
    findings = [f for r in results for f in r.findings if f.rule_id not in disabled]
    exit_code = _exit_code(findings, args.fail_on)
    skipped = [x for r in results for x in r.skipped]
    for x in skipped:
        print(f"warning: {x['path']}: {x['reason']}; file not scanned", file=sys.stderr)
    shown = _filter_min(findings, args.min_severity)
    files = sum(r.files_scanned for r in results)
    summary, extra = _route_summary(results)
    if args.json:
        sys.stdout.write(render_json(shown, meta={
            "targets": [r.root for r in results], "files_scanned": files,
            "routes": [rt.to_dict() for r in results for rt in r.routes],
            "skipped": skipped,
            "exit_code": exit_code,
        }))
    else:
        header = [f"Scanned {', '.join(paths)}", f"{files} source file(s), {summary}", *extra]
        if skipped:
            header.append(f"{len(skipped)} file(s) could not be parsed and were not scanned (see warnings)")
        sys.stdout.write(render_text(shown, header=header, color=use_color(force=False if args.no_color else None),
                                     verbose_fix=not args.brief, footer=[f"Exit code: {exit_code}"]))
    return exit_code


def cmd_rules(_args) -> int:
    for r in RULES.values():
        print(f"{r.id}  {r.title}  [{r.severity}]")
        print(textwrap.fill(r.why, 92, initial_indent="    ", subsequent_indent="    "))
        print("    Fix:")
        print(textwrap.indent(r.fix, "      "))
        print()
    return EXIT_OK


def main(argv: list[str] | None = None) -> int:
    if hasattr(sys.stdout, "reconfigure"):
        try:
            sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        except (ValueError, OSError):
            pass
    args = build_parser().parse_args(argv)
    return {"scan": cmd_scan, "rules": cmd_rules}[args.command](args)


if __name__ == "__main__":
    sys.exit(main())
