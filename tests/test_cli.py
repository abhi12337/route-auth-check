import json
import subprocess
import sys
from pathlib import Path

import pytest

from route_auth_check.cli import main
from route_auth_check.findings import RULES, SEVERITIES, mask_secret, redact_line

FIX = Path(__file__).parent / "fixtures"
ROOT = Path(__file__).parent.parent


def run(capsys, *argv):
    code = main(list(argv))
    out, err = capsys.readouterr()
    return code, out, err


def test_scan_vulnerable_text_report(capsys):
    code, out, _ = run(capsys, "scan", str(FIX / "node_vulnerable"), "--no-color")
    assert code == 1
    assert "HIGH     RAC001" in out and "app/api/posts/route.ts:8" in out
    assert "why:" in out and "fix:" in out and "await auth()" in out
    assert "Exit code: 1" in out


def test_scan_clean_exits_0(capsys):
    code, out, _ = run(capsys, "scan", str(FIX / "py_clean"), str(FIX / "node_clean"), "--no-color")
    assert code == 0
    assert "No findings" in out and "37 route(s)" in out and "0 unprotected" in out


def test_json_report_shape(capsys):
    code, out, _ = run(capsys, "scan", str(FIX / "py_vulnerable"), "--json")
    doc = json.loads(out)
    assert code == 1 and doc["exit_code"] == 1 and doc["tool"] == "route-auth-check"
    assert set(doc["summary"]) == set(SEVERITIES)
    first = doc["findings"][0]
    assert first["severity"] == "high"
    assert {"rule_id", "severity", "message", "file", "line", "evidence", "title", "why", "fix"} <= set(first)
    rt = doc["routes"][0]
    assert {"file", "line", "route", "framework", "kind", "methods", "auth", "status"} <= set(rt)


def test_fail_on_min_severity_and_disable(capsys):
    assert run(capsys, "scan", str(FIX / "py_vulnerable"), "--fail-on", "never")[0] == 0
    code, out, _ = run(capsys, "scan", str(FIX / "py_vulnerable"), "--json", "--min-severity", "high")
    assert {f["severity"] for f in json.loads(out)["findings"]} == {"high"}
    high = ["RAC001", "rac002", "RAC005", "RAC006"]
    args = [x for r in high for x in ("--disable", r)]
    code, out, _ = run(capsys, "scan", str(FIX / "py_vulnerable"), "--json", *args)
    ids = {f["rule_id"] for f in json.loads(out)["findings"]}
    assert ids == {"RAC007", "RAC008"} and code == 0          # medium only: below --fail-on high
    assert run(capsys, "scan", str(FIX / "py_vulnerable"), *args, "--fail-on", "medium")[0] == 1


def test_unknown_rule_and_missing_path(capsys, tmp_path):
    code, _, err = run(capsys, "scan", str(tmp_path / "nope"))
    assert code == 2 and "does not exist" in err
    code, _, err = run(capsys, "scan", str(tmp_path), "--disable", "RAC999")
    assert code == 2 and "unknown rule" in err


def test_bad_option_is_usage_error():
    with pytest.raises(SystemExit) as e:
        main(["scan", "--fail-on", "sometimes"])
    assert e.value.code == 2


def test_scan_single_file(capsys):
    code, out, _ = run(capsys, "scan", str(FIX / "node_vulnerable" / "server" / "hono.ts"), "--json")
    doc = json.loads(out)
    assert code == 1 and [f["rule_id"] for f in doc["findings"]] == ["RAC001"]


def test_auth_fn_flag(capsys, make_repo):
    root = make_repo({"app/api/x/route.ts": "export async function POST() { const me = await loadMe(); "
                                             "await db.x.create({ data: { ownerId: me.id } }); }\n"})
    assert run(capsys, "scan", str(root))[0] == 1
    assert run(capsys, "scan", str(root), "--auth-fn", "loadMe")[0] == 0


def test_ignore_comment_and_brief(capsys, make_repo):
    root = make_repo({"server.js": """
const app = require("express")();
app.post("/api/a", async (req, res) => { await Item.create({ name: "x" }); });   // route-auth-check: ignore
app.post("/api/b", async (req, res) => { await Item.create({ name: "x" }); });
"""})
    code, out, _ = run(capsys, "scan", str(root), "--brief", "--no-color")
    assert code == 1 and "server.js:4" in out and "server.js:3" not in out
    assert "why:" not in out and "fix:" not in out


def test_tests_and_excludes_are_skipped_unless_asked(capsys, make_repo):
    bad = 'const app = require("express")();\napp.post("/x", async (req, res) => { await Item.create({}); });\n'
    root = make_repo({"tests/server.js": bad, "scripts/seed.js": bad, "src/a.test.js": bad})
    assert run(capsys, "scan", str(root), "--exclude", "scripts/*")[0] == 0
    code, out, _ = run(capsys, "scan", str(root), "--include-tests", "--json", "--exclude", "scripts/*")
    assert code == 1 and {f["file"] for f in json.loads(out)["findings"]} == {"tests/server.js", "src/a.test.js"}


def test_output_never_contains_secrets(capsys, make_repo, fake):
    root = make_repo({
        "server.js": f"""
const app = require("express")();
app.post("/api/charge", async (req, res) => {{ const s = new Stripe("{fake['stripe']}"); await s.charges.create({{}}); }});
app.put("/api/x/:id", (req, res) => {{ const u = jwt.verify(req.cookies.t, "{fake['jwt_secret']}"); return Item.findByIdAndUpdate(req.params.id, req.body); }});
""",
    })
    for fmt in ([], ["--json"]):
        code, out, _ = run(capsys, "scan", str(root), "--no-color", *fmt)
        assert code == 1
        assert fake["stripe"] not in out and fake["jwt_secret"] not in out
        assert fake["stripe"][:4] + "****" in out or "sk_l****" in out


def test_mask_and_redact():
    assert mask_secret("abcdefghijklmnop") == "abcd**** (16 chars)"
    assert mask_secret("abc") == "**** (3 chars)"
    s = "s3" + "cretvalue99"
    assert s not in redact_line(f'const JWT_SECRET = "{s}";')
    assert redact_line('const label = "hello world";') == 'const label = "hello world";'


def test_every_rule_has_fix_for_every_framework():
    from route_auth_check.fixes import build_fix
    for fw in ("next-app", "next-pages", "server-action", "express", "hono", "fastify", "fastapi", "flask",
               "django", "drf"):
        lang = "py" if fw in ("fastapi", "flask", "django", "drf") else "js"
        x = {"framework": fw, "lang": lang, "route": "POST /api/items", "name": "create_item", "owner": "userId",
             "session": "session.user.id", "model": "Item", "id": "id", "op": "delete", "kind": "user-id",
             "expr": "body.userId", "sink": "Item.create()", "orm": "prisma" if lang == "js" else "sqlalchemy"}
        for rule in RULES:
            if rule == "RAC004" or (rule == "RAC001" and fw == "server-action"):
                continue
            fix = build_fix(rule, x)
            assert fix and len(fix) > 40, (rule, fw)


def test_rules_command(capsys):
    code, out, _ = run(capsys, "rules")
    assert code == 0
    for rid in RULES:
        assert rid in out


def test_module_entry_point_and_own_source_is_clean():
    r = subprocess.run([sys.executable, "-m", "route_auth_check", "scan", str(ROOT / "src"), "--fail-on", "low",
                        "--no-color"], capture_output=True, text=True, cwd=ROOT,
                       env={**__import__("os").environ, "PYTHONPATH": str(ROOT / "src")})
    assert r.returncode == 0, r.stdout


def test_demo_project(tmp_path):
    demo = tmp_path / "demo"
    subprocess.run([sys.executable, str(ROOT / "examples" / "make_demo.py"), str(demo)], check=True,
                   capture_output=True)
    assert (demo / "web" / "middleware.ts").exists() and (demo / "api" / "fastapi_app.py").exists()
    assert main(["scan", str(demo), "--fail-on", "never"]) == 0


def test_unparseable_python_file_is_warned_not_silently_clean(capsys, tmp_path):
    (tmp_path / "views.py").write_text('@app.post("/admin/delete")\ndef delete():\n    x = = 1\n')
    code, out, err = run(capsys, "scan", str(tmp_path), "--no-color")
    assert code == 0                                  # exit code still depends on findings only
    assert "warning: views.py: syntax error line 3; file not scanned" in err
    assert "1 file(s) could not be parsed" in out
    code, out, _ = run(capsys, "scan", str(tmp_path), "--json")
    assert json.loads(out)["skipped"] == [{"path": "views.py", "reason": "syntax error line 3"}]
