# server_app.py
import os, secrets, datetime as dt
from typing import Optional, List

from fastapi import FastAPI, HTTPException, Depends, Header, status
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from starlette.responses import RedirectResponse, Response

from sqlalchemy import (
    create_engine, String, Integer, Boolean, DateTime, ForeignKey,
    func, select, UniqueConstraint
)
from sqlalchemy.orm import declarative_base, relationship, sessionmaker, Session, Mapped, mapped_column
from passlib.hash import bcrypt

# ------------------ 환경 ------------------
DATABASE_URL = os.getenv("DATABASE_URL", "").strip() or "sqlite:///./app.db"

def _make_engine(url: str):
    if url.startswith("sqlite"):
        return create_engine(url, future=True, connect_args={"check_same_thread": False})
    return create_engine(
        url, future=True, pool_pre_ping=True, pool_size=5, max_overflow=2,
        pool_recycle=280, pool_timeout=10
    )

engine = _make_engine(DATABASE_URL)
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False, future=True)
Base = declarative_base()

# ------------------ 모델 ------------------
class User(Base):
    __tablename__ = "users"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    username: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    password_hash: Mapped[str] = mapped_column(String(255))
    hospital: Mapped[Optional[str]] = mapped_column(String(128), default=None)
    role: Mapped[str] = mapped_column(String(16), default="user")  # 'admin' | 'user'
    active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    sessions: Mapped[List["SessionToken"]] = relationship("SessionToken", back_populates="user")

class SessionToken(Base):
    __tablename__ = "sessions"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    token: Mapped[str] = mapped_column(String(128), unique=True, index=True)
    user_id: Mapped[int] = mapped_column(Integer, ForeignKey("users.id", ondelete="CASCADE"))
    created_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    revoked: Mapped[bool] = mapped_column(Boolean, default=False)
    user: Mapped[User] = relationship("User", back_populates="sessions")

# ------------------ FastAPI ------------------
app = FastAPI(title="EuiSinChung API", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], allow_methods=["*"], allow_headers=["*"]
)

# ------------------ 유틸/의존성 ------------------
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def ensure_admin_exists(db: Session):
    """부팅 시 관리자 계정 보장(rnj88 / 6548)."""
    admin = db.execute(select(User).where(User.username == "rnj88")).scalar_one_or_none()
    if not admin:
        u = User(
            username="rnj88",
            password_hash=bcrypt.hash("6548"),
            hospital="Admin",
            role="admin",
            active=True,
        )
        db.add(u)
        db.commit()
    else:
        # 혹시 비번 초기화가 필요하면 주석 해제
        # admin.password_hash = bcrypt.hash("6548"); db.commit()
        pass

def bearer_token(auth_header: Optional[str]) -> str:
    if not auth_header or not auth_header.lower().startswith("bearer "):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="missing bearer token")
    return auth_header.split(" ", 1)[1].strip()

def require_user(db: Session, token: str) -> User:
    sess = db.execute(
        select(SessionToken).where(SessionToken.token == token, SessionToken.revoked == False)
    ).scalar_one_or_none()
    if not sess:
        raise HTTPException(status_code=401, detail="invalid token")
    user = db.get(User, sess.user_id)
    if not user or not user.active:
        raise HTTPException(status_code=401, detail="inactive user")
    return user

def require_admin(db: Session, token: str) -> User:
    user = require_user(db, token)
    if user.role != "admin":
        raise HTTPException(status_code=403, detail="admin only")
    return user

# ------------------ 스타트업 ------------------
@app.on_event("startup")
def on_startup():
    Base.metadata.create_all(bind=engine)
    with SessionLocal() as db:
        # DB 연결 확인 + 관리자 보장
        db.execute(select(func.now()))
        ensure_admin_exists(db)

# ------------------ 기본 엔드포인트 ------------------
@app.get("/", include_in_schema=False)
def root():
    return RedirectResponse(url="/docs", status_code=307)

@app.get("/favicon.ico", include_in_schema=False)
def favicon():
    return Response(status_code=204)

@app.get("/status")
def status():
    return {"ok": True, "db": ("sqlite" if DATABASE_URL.startswith("sqlite") else "postgres")}

# ------------------ 인증 ------------------
class LoginIn(BaseModel):
    username: str
    password: str
    force: bool = True

class LoginOut(BaseModel):
    ok: bool
    token: str
    user: dict

@app.post("/auth/start_session", response_model=LoginOut)
def start_session(body: LoginIn, db: Session = Depends(get_db)):
    user = db.execute(select(User).where(User.username == body.username)).scalar_one_or_none()
    # 혹시 관리자 계정이 사라졌다면 즉시 복구
    if not user and body.username == "rnj88":
        ensure_admin_exists(db)
        user = db.execute(select(User).where(User.username == "rnj88")).scalar_one()

    if not user or not bcrypt.verify(body.password, user.password_hash):
        raise HTTPException(status_code=401, detail="invalid credentials")

    # 강제 로그인: 이전 세션 무효화
    if body.force:
        db.execute(
            select(SessionToken).where(SessionToken.user_id == user.id, SessionToken.revoked == False)
        )
        db.query(SessionToken).filter(SessionToken.user_id == user.id, SessionToken.revoked == False).update({"revoked": True})
        db.commit()

    token = secrets.token_urlsafe(32)
    sess = SessionToken(token=token, user_id=user.id, revoked=False)
    db.add(sess); db.commit()

    return {"ok": True, "token": token, "user": {"username": user.username, "hospital": user.hospital, "role": user.role}}

# ------------------ 사용자 관리(관리자용) ------------------
class CreateUserIn(BaseModel):
    username: str
    password: str
    hospital: Optional[str] = None

@app.get("/users")
def list_users(Authorization: Optional[str] = Header(None), db: Session = Depends(get_db)):
    token = bearer_token(Authorization)
    admin = require_admin(db, token)
    rows = db.execute(select(User).order_by(User.id)).scalars().all()
    return {"ok": True, "items": [
        {"id": u.id, "username": u.username, "hospital": u.hospital, "role": u.role, "active": u.active, "created_at": u.created_at}
        for u in rows
    ]}

@app.post("/users", status_code=201)
def create_user(body: CreateUserIn, Authorization: Optional[str] = Header(None), db: Session = Depends(get_db)):
    token = bearer_token(Authorization)
    admin = require_admin(db, token)
    exists = db.execute(select(User).where(User.username == body.username)).scalar_one_or_none()
    if exists:
        raise HTTPException(status_code=409, detail="duplicate username")
    u = User(
        username=body.username,
        password_hash=bcrypt.hash(body.password),
        hospital=(body.hospital or "").strip() or None,
        role="user",
        active=True,
    )
    db.add(u); db.commit()
    return {"ok": True, "id": u.id}






