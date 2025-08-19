# server_app.py
# -*- coding: utf-8 -*-
"""
중앙 사용자/세션/이력/저장멘트 관리 서버 (FastAPI + PostgreSQL)
무료 배포 예: Render(웹서비스) + Neon(Postgres)
환경변수:
  DATABASE_URL = "postgresql+psycopg2://user:pass@host/dbname?sslmode=require"
포트:
  Render 환경에서 uvicorn --port $PORT 로 실행
"""

import os, hashlib, secrets, datetime
from typing import Optional, List

from fastapi import FastAPI, HTTPException, Depends, Header, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from sqlalchemy import (
    create_engine, String, Integer, Boolean, Text, Date, DateTime, ForeignKey, UniqueConstraint
)
from sqlalchemy.orm import sessionmaker, declarative_base, Mapped, mapped_column, Session as SASession
from sqlalchemy.exc import IntegrityError

DATABASE_URL = os.environ.get("DATABASE_URL", "").strip()
if not DATABASE_URL:
    raise RuntimeError("환경변수 DATABASE_URL이 비어있습니다. Neon/Railway 등 Postgres 연결문자열을 설정하세요.")

engine = create_engine(DATABASE_URL, pool_pre_ping=True)
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)
Base = declarative_base()

app = FastAPI(title="EuiSinChung Central API", version="2.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], allow_methods=["*"], allow_headers=["*"], allow_credentials=True
)

# -------------------- 모델 --------------------
class User(Base):
    __tablename__ = "users"
    username: Mapped[str] = mapped_column(String(120), primary_key=True)
    password_hash: Mapped[str] = mapped_column(String(128), nullable=False)
    hospital: Mapped[str] = mapped_column(String(200), default="")
    memo: Mapped[str] = mapped_column(Text, default="")
    is_admin: Mapped[bool] = mapped_column(Boolean, default=False)

class Period(Base):
    __tablename__ = "periods"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    username: Mapped[str] = mapped_column(String(120), ForeignKey("users.username", ondelete="CASCADE"), index=True)
    start_date: Mapped[Optional[datetime.date]] = mapped_column(Date, nullable=True)
    end_date:   Mapped[Optional[datetime.date]] = mapped_column(Date, nullable=True)

class Session(Base):
    __tablename__ = "sessions"
    username: Mapped[str] = mapped_column(String(120), primary_key=True)
    token:    Mapped[str] = mapped_column(String(120), nullable=False, unique=True, index=True)
    started_at: Mapped[datetime.datetime] = mapped_column(DateTime, default=lambda: datetime.datetime.now(datetime.timezone.utc))

class Draft(Base):
    __tablename__ = "drafts"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    username: Mapped[str] = mapped_column(String(120), index=True)
    title: Mapped[str] = mapped_column(String(300), default="")
    content: Mapped[str] = mapped_column(Text, default="")
    created: Mapped[str] = mapped_column(String(32), default=lambda: datetime.datetime.now().strftime("%Y-%m-%d %H:%M"))

# -------------------- 유틸 --------------------
def _hash(pw: str) -> str:
    return hashlib.sha256((pw or "").encode("utf-8")).hexdigest()

def _today() -> datetime.date:
    return datetime.date.today()

def _active_period_allowed(db: SASession, username: str) -> bool:
    if username == "rnj88":  # 관리자는 제한 없음
        return True
    today = _today()
    q = db.query(Period).filter(
        Period.username == username,
        ((Period.start_date == None) | (Period.start_date <= today)),
        ((Period.end_date == None)   | (Period.end_date >= today))
    )
    return db.query(q.exists()).scalar() or False

def _is_admin(db: SASession, username: str) -> bool:
    u = db.get(User, username)
    return bool(u and u.is_admin)

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def _require_token(db: SASession, auth: Optional[str]) -> dict:
    if not auth or not auth.lower().startswith("bearer "):
        raise HTTPException(401, "인증 토큰 필요")
    token = auth.split(" ", 1)[1].strip()
    s = db.query(Session).filter_by(token=token).first()
    if not s:
        raise HTTPException(401, "토큰이 유효하지 않습니다")
    return {"username": s.username, "is_admin": _is_admin(db, s.username), "token": token}

# -------------------- 스키마/초기화 --------------------
def init_db():
    Base.metadata.create_all(bind=engine)
    with SessionLocal() as db:
        if not db.get(User, "rnj88"):
            admin = User(username="rnj88", password_hash=_hash("6548"), hospital="관리자", memo="", is_admin=True)
            db.add(admin)
            db.commit()

init_db()

# -------------------- 요청 모델 --------------------
class LoginBody(BaseModel):
    username: str
    password: str
    force: Optional[bool] = False

class VerifyBody(BaseModel):
    username: str
    password: str

class UserCreate(BaseModel):
    username: str
    password: str
    hospital: Optional[str] = ""

class UserPwd(BaseModel):
    password: str

class TextBody(BaseModel):
    value: str

class DraftCreate(BaseModel):
    username: str
    title: str
    content: str

# -------------------- 엔드포인트 --------------------
@app.get("/status")
def status():
    return {"ok": True, "today": _today().isoformat()}

# Auth
@app.post("/auth/verify")
def auth_verify(body: VerifyBody, db: SASession = Depends(get_db)):
    u = db.get(User, body.username)
    if not u or u.password_hash != _hash(body.password):
        raise HTTPException(401, "아이디/비밀번호 불일치")
    return {"ok": True, "allowed": _active_period_allowed(db, body.username), "is_admin": bool(u.is_admin)}

@app.post("/auth/start_session")
def auth_start_session(body: LoginBody, db: SASession = Depends(get_db)):
    u = db.get(User, body.username)
    if not u or u.password_hash != _hash(body.password):
        raise HTTPException(401, "아이디/비밀번호 불일치")
    if not _active_period_allowed(db, body.username):
        raise HTTPException(403, "사용기간이 아닙니다. 관리자에게 문의하세요.")
    if db.get(Session, body.username):
        if not body.force:
            raise HTTPException(409, "이미 로그인 중입니다. 강제 로그인을 사용하세요.")
        db.delete(db.get(Session, body.username)); db.commit()
    token = secrets.token_hex(24)
    db.merge(Session(username=body.username, token=token))
    db.commit()
    return {"ok": True, "token": token, "is_admin": bool(u.is_admin)}

@app.post("/auth/end_session")
def auth_end_session(auth: Optional[str] = Header(None), username: Optional[str] = None, db: SASession = Depends(get_db)):
    info = _require_token(db, auth)
    target = username or info["username"]
    if info["username"] != target and not info["is_admin"]:
        raise HTTPException(403, "권한이 없습니다")
    s = db.get(Session, target)
    if s:
        db.delete(s); db.commit()
    return {"ok": True}

# Users (admin)
@app.get("/users")
def list_users(auth: Optional[str] = Header(None), db: SASession = Depends(get_db)):
    info = _require_token(db, auth)
    if not info["is_admin"]:
        raise HTTPException(403, "관리자만 가능합니다")
    rows = db.query(User).order_by(User.username.asc()).all()
    return [{"username": r.username, "hospital": r.hospital} for r in rows]

@app.post("/users")
def create_user(user: UserCreate, auth: Optional[str] = Header(None), db: SASession = Depends(get_db)):
    info = _require_token(db, auth)
    if not info["is_admin"]:
        raise HTTPException(403, "관리자만 가능합니다")
    if db.get(User, user.username):
        raise HTTPException(409, "동일한 아이디가 존재합니다")
    db.add(User(username=user.username, password_hash=_hash(user.password), hospital=user.hospital or ""))
    db.add(Period(username=user.username, start_date=_today(), end_date=None))
    db.commit()
    return {"ok": True}

@app.get("/users/{uid}")
def user_detail(uid: str, auth: Optional[str] = Header(None), db: SASession = Depends(get_db)):
    info = _require_token(db, auth)
    if not info["is_admin"]:
        raise HTTPException(403, "관리자만 가능합니다")
    u = db.get(User, uid)
    if not u:
        raise HTTPException(404, "사용자를 찾을 수 없습니다")
    periods = db.query(Period).filter_by(username=uid).order_by(Period.id.asc()).all()
    return {
        "username": u.username,
        "hospital": u.hospital,
        "memo": u.memo or "",
        "periods": [{"id": p.id, "start_date": p.start_date.isoformat() if p.start_date else "", "end_date": p.end_date.isoformat() if p.end_date else ""} for p in periods]
    }

@app.delete("/users/{uid}")
def del_user(uid: str, auth: Optional[str] = Header(None), db: SASession = Depends(get_db)):
    info = _require_token(db, auth)
    if not info["is_admin"]:
        raise HTTPException(403, "관리자만 가능합니다")
    u = db.get(User, uid)
    if u:
        db.delete(u); db.commit()
    return {"ok": True}

@app.put("/users/{uid}/password")
def set_password(uid: str, body: UserPwd, auth: Optional[str] = Header(None), db: SASession = Depends(get_db)):
    info = _require_token(db, auth)
    if not info["is_admin"]:
        raise HTTPException(403, "관리자만 가능합니다")
    u = db.get(User, uid)
    if not u: raise HTTPException(404, "없음")
    u.password_hash = _hash(body.password); db.commit()
    return {"ok": True}

@app.put("/users/{uid}/hospital")
def set_hospital(uid: str, body: TextBody, auth: Optional[str] = Header(None), db: SASession = Depends(get_db)):
    info = _require_token(db, auth)
    if not info["is_admin"]:
        raise HTTPException(403, "관리자만 가능합니다")
    u = db.get(User, uid)
    if not u: raise HTTPException(404, "없음")
    u.hospital = body.value or ""; db.commit()
    return {"ok": True}

@app.put("/users/{uid}/memo")
def set_memo(uid: str, body: TextBody, auth: Optional[str] = Header(None), db: SASession = Depends(get_db)):
    info = _require_token(db, auth)
    if not info["is_admin"]:
        raise HTTPException(403, "관리자만 가능합니다")
    u = db.get(User, uid)
    if not u: raise HTTPException(404, "없음")
    u.memo = body.value or ""; db.commit()
    return {"ok": True}

@app.post("/users/{uid}/end_today")
def end_today(uid: str, auth: Optional[str] = Header(None), db: SASession = Depends(get_db)):
    info = _require_token(db, auth)
    if not info["is_admin"]:
        raise HTTPException(403, "관리자만 가능합니다")
    today = _today()
    rows = db.query(Period).filter(Period.username==uid, (Period.end_date==None)).all()
    for r in rows:
        r.end_date = today
    db.commit()
    return {"ok": True, "date": today.isoformat()}

@app.post("/users/{uid}/reuse_today")
def reuse_today(uid: str, auth: Optional[str] = Header(None), db: SASession = Depends(get_db)):
    info = _require_token(db, auth)
    if not info["is_admin"]:
        raise HTTPException(403, "관리자만 가능합니다")
    today = _today()
    db.add(Period(username=uid, start_date=today, end_date=None))
    db.commit()
    return {"ok": True, "date": today.isoformat()}

# Drafts
@app.get("/drafts")
def list_drafts(username: str = Query(...), auth: Optional[str] = Header(None), db: SASession = Depends(get_db)):
    info = _require_token(db, auth)
    if info["username"] != username and not info["is_admin"]:
        raise HTTPException(403, "권한이 없습니다")
    rows = db.query(Draft).filter_by(username=username).order_by(Draft.id.desc()).all()
    return [{"id": d.id, "title": d.title, "preview": (d.content or "")[:200], "created": d.created} for d in rows]

@app.get("/drafts/{did}")
def get_draft(did: int, auth: Optional[str] = Header(None), db: SASession = Depends(get_db)):
    info = _require_token(db, auth)
    d = db.get(Draft, did)
    if not d:
        raise HTTPException(404, "없음")
    if info["username"] != d.username and not info["is_admin"]:
        raise HTTPException(403, "권한이 없습니다")
    return {"id": d.id, "username": d.username, "title": d.title, "content": d.content, "created": d.created}

@app.post("/drafts")
def save_draft(body: DraftCreate, auth: Optional[str] = Header(None), db: SASession = Depends(get_db)):
    info = _require_token(db, auth)
    if info["username"] != body.username and not info["is_admin"]:
        raise HTTPException(403, "권한이 없습니다")
    d = Draft(username=body.username, title=body.title, content=body.content)
    db.add(d); db.commit()
    return {"ok": True, "id": d.id}

@app.delete("/drafts/{did}")
def delete_draft(did: int, auth: Optional[str] = Header(None), db: SASession = Depends(get_db)):
    info = _require_token(db, auth)
    d = db.get(Draft, did)
    if not d:
        raise HTTPException(404, "없음")
    if info["username"] != d.username and not info["is_admin"]:
        raise HTTPException(403, "권한이 없습니다")
    db.delete(d); db.commit()
    return {"ok": True}
