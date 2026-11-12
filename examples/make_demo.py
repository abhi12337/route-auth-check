"""Generate a deliberately insecure demo project to try route-auth-check on.

    python examples/make_demo.py demo-routes
    route-auth-check scan demo-routes

The demo contains a Next.js app with route handlers, server actions and middleware plus
Express, Hono and Fastify servers (web/), and a FastAPI + Flask + Django / DRF backend (api/),
copied from tests/fixtures. Every route has a common authentication or authorization mistake
found in AI-generated code. Nothing in it runs anywhere.
"""

from __future__ import annotations

import shutil
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
FIXTURES = HERE.parent / "tests" / "fixtures"


def main(dest: str) -> None:
    root = Path(dest)
    if root.exists():
        shutil.rmtree(root)
    shutil.copytree(FIXTURES / "node_vulnerable", root / "web")
    shutil.copytree(FIXTURES / "py_vulnerable", root / "api")
    print(f"Demo project written to {root}. Now run:  route-auth-check scan {root}")


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "demo-routes")
