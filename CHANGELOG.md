# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/).

## [0.1.1] - 2026-11-12

### Fixed

- A Python file with a syntax error was skipped silently, so its routes were never checked and
  nothing said so. It is now reported: a `warning: <path>: syntax error line N; file not scanned`
  line on stderr, a count in the text header and a `"skipped": [{"path": ..., "reason": ...}]`
  list in the JSON report. Exit codes are unchanged.

## [0.1.0] - 2026-11-11

First release.

### Added

- `route-auth-check scan [PATH ...]`: static scan of folders or single files. Never runs or
  imports the scanned code; no network access.
- `route-auth-check rules`: every rule with why it matters and how to fix it.
- Route discovery for Next.js (App Router route handlers, `pages/api`, Server Actions in
  `"use server"` files and inline, `middleware.ts` / `proxy.ts` matchers), Express, Hono, Fastify
  and Koa-style routers (lexer-based, following router mounts, imported handlers and helpers
  across files), FastAPI, Flask and Django / DRF (`ast`-based).
- Rules:
  - RAC001 route changes data without any authentication check
  - RAC002 record looked up by a request id with no ownership check (IDOR, heuristic)
  - RAC003 Server Action without an authentication check
  - RAC004 Next.js middleware matcher does not cover the routes it seems meant to protect (heuristic)
  - RAC005 admin route checks login but not the caller's role (heuristic)
  - RAC006 user id or role taken from the request body, query, arguments or headers
  - RAC007 CORS allows any origin together with credentials
  - RAC008 whole request body written to the database (mass assignment)
- Text and JSON reports (JSON lists every route with what protects it), a framework- and
  data-layer-specific fix for every finding, `--auth-fn`, `--fail-on`, `--min-severity`,
  `--disable`, `--exclude`, `--include-tests`, `--brief`, `--no-color`,
  `route-auth-check: ignore` comments, exit codes `0` / `1` / `2`. Secret-shaped strings in
  printed code are masked to at most 4 characters.
- Demo project generator (`examples/make_demo.py`) and a GitHub Actions example.
