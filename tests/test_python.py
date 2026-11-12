"""Python (FastAPI, Flask, Django / DRF): true positives and protected code that must stay quiet."""

from pathlib import Path

from conftest import route, rules
from route_auth_check.scanner import scan_path

FIX = Path(__file__).parent / "fixtures"


def test_vulnerable_fixture_exact_findings():
    res = scan_path(str(FIX / "py_vulnerable"))
    got = sorted((f.rule_id, f.file, f.line, f.severity) for f in res.findings)
    assert got == sorted([
        ("RAC007", "fastapi_app.py", 11, "medium"),
        ("RAC001", "fastapi_app.py", 20, "high"),
        ("RAC006", "fastapi_app.py", 22, "high"),
        ("RAC002", "fastapi_app.py", 30, "high"),
        ("RAC005", "fastapi_app.py", 36, "high"),
        ("RAC007", "flask_app.py", 8, "medium"),
        ("RAC002", "flask_app.py", 14, "high"),
        ("RAC008", "flask_app.py", 16, "medium"),
        ("RAC001", "flask_app.py", 22, "high"),
        ("RAC008", "flask_app.py", 25, "medium"),
        ("RAC005", "flask_app.py", 31, "high"),
        ("RAC006", "flask_app.py", 34, "high"),
        ("RAC001", "django_views.py", 10, "high"),
        ("RAC006", "django_views.py", 12, "high"),
        ("RAC002", "django_views.py", 18, "high"),
        ("RAC008", "django_views.py", 25, "medium"),
        ("RAC001", "django_views.py", 28, "high"),
        ("RAC002", "django_views.py", 34, "high"),
        ("RAC007", "settings.py", 7, "medium"),
    ])


def test_clean_fixture_no_findings():
    res = scan_path(str(FIX / "py_clean"))
    assert res.findings == []
    status = {r.label: r.status for r in res.routes}
    assert status["GET /admin/users"] == "protected"            # APIRouter(prefix=..., dependencies=[...])
    assert status["POST /auth/login"] == "public" and status["POST /webhooks/github"] == "public"
    assert "unprotected" not in status.values()


# ---------------------------------------------------------------- FastAPI
def test_fastapi_dependency_shapes(scan):
    res = scan({"app.py": """
from typing import Annotated
from fastapi import APIRouter, Depends, FastAPI, Security
from .deps import get_current_user, get_db

CurrentUser = Annotated["User", Depends(get_current_user)]
app = FastAPI()
private = APIRouter(dependencies=[Depends(get_current_user)])

@app.post("/a")
def a(user: CurrentUser): ...

@app.post("/b")
def b(user=Security(get_current_user, scopes=["items"])): ...

@app.post("/c", dependencies=[Depends(get_current_user)])
def c(): ...

@private.post("/d")
def d(): ...

@app.post("/e")
def e(db=Depends(get_db)): ...
"""})
    assert [(f.rule_id, f.line) for f in res.findings] == [("RAC001", 22)]


def test_fastapi_include_router_dependencies_across_files(scan):
    res = scan({
        "app/main.py": """
from fastapi import Depends, FastAPI
from .routers import items, public
from .deps import get_current_user
app = FastAPI()
app.include_router(items.router, dependencies=[Depends(get_current_user)])
app.include_router(public.router)
""",
        "app/routers/items.py": "from fastapi import APIRouter\nrouter = APIRouter()\n@router.post('/items')\n"
                                "def create(db=Depends(get_db)):\n    db.add(Item())\n",
        "app/routers/public.py": "from fastapi import APIRouter\nrouter = APIRouter()\n@router.post('/things')\n"
                                 "def create(db=Depends(get_db)):\n    db.add(Thing())\n",
    })
    assert [(f.rule_id, f.file) for f in res.findings] == [("RAC001", "app/routers/public.py")]


def test_fastapi_idor_variants(scan):
    res = scan({"app.py": """
from fastapi import Depends, FastAPI
app = FastAPI()

@app.get("/a/{item_id}")
def a(item_id: int, db=Depends(get_db), current_user=Depends(get_current_user)):
    return db.get(Item, item_id)

@app.get("/b/{item_id}")
def b(item_id: int, db=Depends(get_db), current_user=Depends(get_current_user)):
    return db.scalars(select(Item).where(Item.id == item_id)).first()

@app.get("/c/{item_id}")
def c(item_id: int, db=Depends(get_db), current_user=Depends(get_current_user)):
    return db.query(Item).filter(Item.id == item_id, Item.owner_id == current_user.id).first()

@app.get("/d/{item_id}")
def d(item_id: int, db=Depends(get_db), current_user=Depends(get_current_user)):
    item = db.get(Item, item_id)
    if item.owner_id != current_user.id:
        raise HTTPException(status_code=404)
    return item

@app.get("/e/{item_id}")
async def e(item_id: int, current_user=Depends(get_current_user)):
    return await Item.get(id=item_id)
"""})
    assert sorted((f.rule_id, f.line) for f in res.findings) == [("RAC002", 7), ("RAC002", 11), ("RAC002", 26)]


def test_fastapi_public_get_and_body_model_without_owner(scan):
    res = scan({"app.py": """
from fastapi import FastAPI
from pydantic import BaseModel
app = FastAPI()

class Q(BaseModel):
    text: str

@app.get("/posts/{slug}")
def read(slug: str):
    return db.query(Post).filter(Post.slug == slug).first()

@app.post("/search")
def search(q: Q):
    return []
"""})
    assert res.findings == []


# ---------------------------------------------------------------- Flask
def test_flask_blueprint_before_request(scan):
    res = scan({"views.py": """
from flask import Blueprint, abort, session
from flask_login import current_user
admin = Blueprint("admin", __name__)
api = Blueprint("api", __name__)

@admin.before_request
def guard():
    if not current_user.is_authenticated or not current_user.is_admin:
        abort(403)

@admin.post("/admin/purge")
def purge():
    db.session.query(Log).delete()

@api.post("/items")
def create_item():
    db.session.add(Item())
"""})
    assert [(f.rule_id, f.line) for f in res.findings] == [("RAC001", 16)]


def test_flask_jwt_and_session_auth(scan):
    res = scan({"app.py": """
from flask import Flask, session
from flask_jwt_extended import jwt_required, get_jwt_identity
app = Flask(__name__)

@app.post("/a")
@jwt_required()
def a():
    return Note.create(user_id=get_jwt_identity())

@app.post("/b")
def b():
    if "user_id" not in session:
        return "", 401
    return "ok"
"""})
    assert res.findings == []


def test_flask_user_id_from_json(scan):
    res = scan({"app.py": """
from flask import Flask, request
from flask_login import login_required
app = Flask(__name__)

@app.post("/notes")
@login_required
def create_note():
    data = request.get_json()
    note = Note(text=data["text"], user_id=data["user_id"])
    return "ok"
"""})
    assert rules(res) == ["RAC006"] and res.findings[0].line == 10


# ---------------------------------------------------------------- Django / DRF
def test_django_views_and_mixins(scan):
    res = scan({"views.py": """
from django.contrib.auth.decorators import login_required
from django.contrib.auth.mixins import LoginRequiredMixin
from django.views import View

def create_post(request):
    if request.method == "POST":
        Post.objects.create(title=request.POST["title"])

class EditView(LoginRequiredMixin, View):
    def post(self, request, pk):
        post = Post.objects.get(pk=pk)
        post.title = request.POST["title"]
        post.save()

class OpenView(View):
    def delete(self, request, pk):
        Post.objects.filter(pk=pk, owner=request.user).delete()

def about(request):
    return render(request, "about.html")
"""})
    assert sorted((f.rule_id, f.line) for f in res.findings) == [("RAC001", 6), ("RAC001", 16), ("RAC002", 12)]
    assert route(res, "about()").status == "public"


def test_django_login_required_middleware(scan):
    res = scan({
        "settings.py": 'MIDDLEWARE = ["django.contrib.auth.middleware.LoginRequiredMiddleware"]\n',
        "views.py": "from django.http import HttpResponse\nfrom django.contrib.auth.decorators import login_not_required\n"
                    "def create(request):\n    if request.method == 'POST':\n        Thing.objects.create()\n\n"
                    "@login_not_required\ndef touch(request):\n    if request.method == 'POST':\n        Thing.objects.create()\n",
    })
    assert [(f.rule_id, f.line) for f in res.findings] == [("RAC001", 7)]


def test_drf_settings_default_permission(scan):
    view = ("from rest_framework import viewsets\nclass ThingViewSet(viewsets.ModelViewSet):\n"
            "    queryset = Thing.objects.all()\n    serializer_class = ThingSerializer\n")
    assert rules(scan({"api/views.py": view})) == ["RAC001"]
    res = scan({"api/views.py": view, "proj/settings.py":
                'REST_FRAMEWORK = {"DEFAULT_PERMISSION_CLASSES": ["rest_framework.permissions.IsAuthenticated"]}\n'})
    assert rules(res) == ["RAC002"]          # authenticated now, but queryset is everyone's objects


def test_drf_function_views(scan):
    res = scan({"views.py": """
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import AllowAny, IsAuthenticated

@api_view(["POST"])
@permission_classes([AllowAny])
def open_write(request):
    Thing.objects.create(name=request.data["name"])

@api_view(["POST"])
@permission_classes([IsAuthenticated])
def closed_write(request):
    Thing.objects.create(name=request.data["name"], owner=request.user)

@api_view(["DELETE"])
@permission_classes([IsAuthenticated])
def remove(request, pk):
    get_object_or_404(Thing, pk=pk).delete()
"""})
    assert sorted((f.rule_id, f.line) for f in res.findings) == [("RAC001", 5), ("RAC002", 18)]


def test_django_mass_assignment(scan):
    res = scan({"views.py": """
import json
from django.contrib.auth.decorators import login_required

@login_required
def update_profile(request):
    data = json.loads(request.body)
    Profile.objects.filter(user=request.user).update(**data)

@login_required
def ok(request):
    data = json.loads(request.body)
    Profile.objects.filter(user=request.user).update(bio=data["bio"])
"""})
    assert [(f.rule_id, f.line) for f in res.findings] == [("RAC008", 8)]


def test_python_cors_safe_configs(scan):
    res = scan({"a.py": "app.add_middleware(CORSMiddleware, allow_origins=['*'])\n",
                "b.py": "app.add_middleware(CORSMiddleware, allow_origins=['https://x.example'], allow_credentials=True)\n",
                "c.py": "CORS(app, origins=['https://x.example'], supports_credentials=True)\n",
                "settings.py": "CORS_ALLOW_ALL_ORIGINS = True\n"})
    assert res.findings == []
