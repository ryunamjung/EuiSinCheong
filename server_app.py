# server_app.py
import os, secrets, datetime as dt, logging
from typing import Optional, List
from urllib.parse import urlparse, parse_qsl, urlencode, urlunparse

from fastapi import FastAPI, HTTPException, Depends, Header, status
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from starlette.responses import RedirectResponse, Response, JSONResponse, HTMLResponse

from sqlalchemy import (
    create_engine, String, Integer, Boolean, DateTime, ForeignKey,
    func, select
)
from sqlalchemy.orm import declarative_base, relationship, sessionmaker, Session, Mapped, mapped_column
from passlib.hash import bcrypt

log = logging.getLogger("uvicorn.error")

# ------------------ DB URL sanitize ------------------
def _sanitize_db_url(url: str) -> str:
    if not url:
        return url
    try:
        u = urlparse(url)
        qs = dict(parse_qsl(u.query, keep_blank_values=True))
        # 문제 유발: channel_binding=require → 제거
        qs.pop("channel_binding", None)
        # ssl 모드는 기본 require 유지
        qs.setdefault("sslmode", "require")
        return urlunparse(u._replace(query=urlencode(qs)))
    except Exception:
        return url

RAW_DB_URL = os.getenv("DATABASE_URL", "").strip()
DATABASE_URL = _sanitize_db_url(RAW_DB_URL) or "sqlite:///./app.db"

# ------------------ SQLAlchemy engine ------------------
def _make_engine(url: str):
    if url.startswith("sqlite"):
        return create_engine(url, future=True, connect_args={"check_same_thread": False})
    return create_engine(
        url,
        future=True,
        pool_pre_ping=True,
        pool_size=5,
        max_overflow=2,
        pool_recycle=280,
        pool_timeout=10,
    )

engine = _make_engine(DATABASE_URL)
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False, future=True)
Base = declarative_base()
DB_READY = False  # 헬스 상태 보관

# ------------------ Models ------------------
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
app = FastAPI(title="EuiSinChung API", version="1.0.1")  # docs_url="/docs" 기본 유지

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], allow_methods=["*"], allow_headers=["*"],
)

# ------------------ utils/deps ------------------
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def ensure_admin_exists(db: Session):
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

def bearer_token(auth_header: Optional[str]) -> str:
    if not auth_header or not auth_header.lower().startswith("bearer "):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="missing bearer token")
    return auth_header.split(" ", 1)[1].strip()

def require_user(db: Session, token: str) -> User:
    sess = db.execute(select(SessionToken).where(SessionToken.token == token, SessionToken.revoked == False)).scalar_one_or_none()
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

# ------------------ startup ------------------
@app.on_event("startup")
def on_startup():
    global DB_READY
    try:
        Base.metadata.create_all(bind=engine)
        with SessionLocal() as db:
            # DB 핑 + 관리자 보장
            db.execute(select(func.now()))
            ensure_admin_exists(db)
        DB_READY = True
        log.info("DB ready (url sanitized=%s)", DATABASE_URL != RAW_DB_URL)
    except Exception as e:
        # 서버가 죽지 않게 하고, /status에서 원인 노출
        DB_READY = False
        log.exception("DB init failed: %s", e)

# ------------------ entry/health ------------------
APP_ENTRY = "/app"  # Electron이 열 최초 진입 경로

@app.head("/", include_in_schema=False)
def head_root():
    # Render 헬스체크가 HEAD / 를 호출 → 200으로 응답해 405 방지
    return Response(status_code=200)

@app.get("/", include_in_schema=False)
def root():
    # 루트는 항상 앱 진입으로 보냄 (Swagger로 보내지 않음)
    return RedirectResponse(url=APP_ENTRY, status_code=307)

@app.get("/login", include_in_schema=False)
def login_redirect():
    # 옛 경로로 접근해도 앱 진입으로
    return RedirectResponse(url=APP_ENTRY, status_code=307)

@app.get("/healthz", include_in_schema=False)
def healthz():
    return JSONResponse({"ok": True, "db_ready": DB_READY})

# 아주 간단한 임시 UI 셸 (원한다면 정적파일/템플릿/프런트로 교체)
APP_HTML = """<!doctype html><html lang="ko"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>AI이의신청프로그램</title>
<style>
  body{margin:0;background:#0b1220;color:#e5f0ff;font-family:Segoe UI,Arial}
  .wrap{max-width:880px;margin:40px auto;padding:0 16px}
  .card{background:linear-gradient(145deg,#0f172a,#0b1220);border:1px solid #1c2b47;border-radius:14px;padding:18px}
  .btn{display:inline-block;padding:10px 14px;background:#22d3ee;color:#02242a;border-radius:10px;text-decoration:none;font-weight:700}
</style></head><body><div class="wrap">
<div class="card">
  <h2>AI이의신청프로그램</h2>
  <p>서버 연결이 정상입니다. 이 페이지는 임시 진입 셸입니다.</p>
  <p>Electron의 <code>remote.entry</code>는 <strong>/app</strong> 으로 설정하세요.</p>
  <p><a class="btn" href="/docs">API 문서 열기</a></p>
</div></div></body></html>"""

@app.get(APP_ENTRY, response_class=HTMLResponse, include_in_schema=False)
def app_shell():
    return HTMLResponse(APP_HTML)

@app.get("/favicon.ico", include_in_schema=False)
def favicon():
    return Response(status_code=204)

@app.get("/status")
def status():
    return {
        "ok": True,
        "db_ready": DB_READY,
        "db_kind": ("sqlite" if DATABASE_URL.startswith("sqlite") else "postgres"),
        "url_sanitized": (DATABASE_URL != RAW_DB_URL),
    }

# 공통: DB 미준비시 503으로 명시
def _guard_db():
    if not DB_READY:
        return JSONResponse(status_code=503, content={"ok": False, "error": "database not ready"})

# ------------------ auth ------------------
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
    guard = _guard_db()
    if guard:  # DB 안 되면 즉시 503
        return guard

    try:
        user = db.execute(select(User).where(User.username == body.username)).scalar_one_or_none()
        if not user and body.username == "rnj88":
            ensure_admin_exists(db)
            user = db.execute(select(User).where(User.username == "rnj88")).scalar_one()

        if not user or not bcrypt.verify(body.password, user.password_hash):
            raise HTTPException(status_code=401, detail="invalid credentials")

        # force: 이전 세션 revoke
        if body.force:
            db.query(SessionToken).filter(SessionToken.user_id == user.id, SessionToken.revoked == False).update({"revoked": True})
            db.commit()

        token = secrets.token_urlsafe(32)
        db.add(SessionToken(token=token, user_id=user.id, revoked=False))
        db.commit()

        return {"ok": True, "token": token, "user": {"username": user.username, "hospital": user.hospital, "role": user.role}}
    except HTTPException:
        raise
    except Exception as e:
        log.exception("login failed: %s", e)
        raise HTTPException(status_code=500, detail="internal error")

# ------------------ users (admin) ------------------
class CreateUserIn(BaseModel):
    username: str
    password: str
    hospital: Optional[str] = None

@app.get("/users")
def list_users(Authorization: Optional[str] = Header(None), db: Session = Depends(get_db)):
    guard = _guard_db()
    if guard: return guard
    token = bearer_token(Authorization)
    _ = require_admin(db, token)
    rows = db.execute(select(User).order_by(User.id)).scalars().all()
    return {"ok": True, "items": [
        {"id": u.id, "username": u.username, "hospital": u.hospital, "role": u.role, "active": u.active, "created_at": u.created_at}
        for u in rows
    ]}

@app.post("/users", status_code=201)
def create_user(body: CreateUserIn, Authorization: Optional[str] = Header(None), db: Session = Depends(get_db)):
    guard = _guard_db()
    if guard: return guard
    token = bearer_token(Authorization)
    _ = require_admin(db, token)
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










