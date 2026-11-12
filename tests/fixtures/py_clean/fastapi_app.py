from typing import Annotated

from fastapi import APIRouter, Depends, FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from sqlalchemy.orm import Session

from .db import get_db
from .deps import get_current_user, require_admin
from .models import Note, User

CurrentUser = Annotated[User, Depends(get_current_user)]

app = FastAPI()
app.add_middleware(CORSMiddleware, allow_origins=["https://app.example.com"], allow_credentials=True)
admin = APIRouter(prefix="/admin", dependencies=[Depends(require_admin)])


class NoteIn(BaseModel):
    title: str
    body: str


@app.post("/notes")
def create_note(note: NoteIn, current_user: CurrentUser, db: Session = Depends(get_db)):
    obj = Note(**note.model_dump(), owner_id=current_user.id)
    db.add(obj)
    db.commit()
    return obj


@app.delete("/notes/{note_id}")
def delete_note(note_id: int, current_user: CurrentUser, db: Session = Depends(get_db)):
    note = db.query(Note).filter(Note.id == note_id, Note.owner_id == current_user.id).first()
    if note is None:
        raise HTTPException(status_code=404, detail="Not found")
    db.delete(note)
    db.commit()
    return {"ok": True}


@admin.get("/users")
def list_users(db: Session = Depends(get_db)):
    return db.query(User).all()


@app.post("/auth/login")
def login(form: NoteIn, db: Session = Depends(get_db)):
    return {"token": "..."}


@app.get("/health")
def health():
    return {"ok": True}
