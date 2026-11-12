from fastapi import Depends, FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from sqlalchemy.orm import Session

from .db import get_db
from .deps import get_current_user
from .models import Note, User

app = FastAPI()
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=True, allow_methods=["*"])


class NoteIn(BaseModel):
    title: str
    body: str
    owner_id: int


@app.post("/notes")
def create_note(note: NoteIn, db: Session = Depends(get_db)):
    obj = Note(title=note.title, body=note.body, owner_id=note.owner_id)
    db.add(obj)
    db.commit()
    return obj


@app.delete("/notes/{note_id}")
def delete_note(note_id: int, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    note = db.query(Note).filter(Note.id == note_id).first()
    db.delete(note)
    db.commit()
    return {"ok": True}


@app.get("/admin/users")
def list_users(db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    return db.query(User).all()
