"""Shared helpers. Fake secrets are assembled at runtime so that no secret-shaped string is
ever committed to this repository (keeps secret scanners quiet)."""

from __future__ import annotations

from pathlib import Path

import pytest

from route_auth_check.scanner import scan_path

FIXTURES = Path(__file__).parent / "fixtures"

FAKE = {
    "stripe": "sk_" + "live_" + "FAKEfakeFAKEfake0123456789",
    "jwt_secret": "s3cr3t" + "-jwt-" + "signing-value-42",
}


@pytest.fixture
def fake():
    return FAKE


@pytest.fixture
def make_repo(tmp_path):
    """make_repo({"rel/path": "content", ...}) -> Path"""

    def _make(files: dict) -> Path:
        root = tmp_path / "repo"
        root.mkdir(exist_ok=True)
        for rel, content in files.items():
            p = root / rel
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(content, encoding="utf-8")
        return root

    return _make


@pytest.fixture
def scan(make_repo):
    """scan({"rel": "content"}, auth_fns=[...]) -> ScanResult"""

    def _scan(files: dict, **kw):
        return scan_path(str(make_repo(files)), **kw)

    return _scan


def rules(res) -> list[str]:
    return sorted(f.rule_id for f in res.findings)


def route(res, label: str):
    return next(r for r in res.routes if r.label == label)
