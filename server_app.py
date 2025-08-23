# server_app.py
# AI Appeal Auth Service - v0.3.5
# - DB URL 자동 해석 (postgres / neon / sqlite fallback)
# - 간이 마이그레이션: users.id -> VARCHAR(64), sessions.user_id 정합
# - JWT 인증 (/auth/login, /auth/me)
# - Admin 전용 /users CRUD (Electron 클라이언트용)
# - CORS 허용

import os
import datetime
from typing import Optional, List, Any, Dict

from fastapi import FastAPI, Depends, HTTPException, Body
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from starlette.responses import JSONResponse

from sqlalchemy import (
    create_engine, text, String, Boolean,
    Date, TIMESTAMP, func, select, update, delete
)
from sqlalchemy.orm import Session, sessionmaker, declarative_base, Mapped, mapped_column

import bcrypt
import jwt  # PyJWT

# ------------------------------------------------------------------------------
# 서비스 메타
# ------------------------------------------------------------------------------
SERVICE_NAME = "ai-appeal-auth"
VERSION = "v0.3.5"
BRAND = os.getenv("BRAND", "ryoryocompany")

# ------------------------------------------------------------------------------
# DB URL 해석
# ------------------------------------------------------------------------------
def resolve_database_url() -> (str, str):
    """환경변수 DATABASE_URL을 읽어 SQLAlchemy가 이해하는 URL로 변환.
    - postgres:// → postgresql+psycopg2://
    - postgresql:// → postgresql+psycopg2:// (드라이버 명시)
    - 비어있거나 파싱 실패 시 sqlite 로 폴백
    """
    raw = os.getenv("DATABASE_URL", "").strip()
    resolved = ""
    backend = "sqlite"

    def _fix_pg(url: str) -> str:
        # 이미 query string이 붙은 경우도 그대로 두고 scheme만 정리
        if url.startswith("postgres://"):
            url = "postgresql://" + url[len("postgres://"):]
        if url.startswith("postgresql://") and "+psycopg2" not in url:
            url = "postgresql+psycopg2://" + url[len("postgresql://"):]
        return url

    try:
        if raw:
            if raw.startswith("postgres://") or raw.startswith("postgresql://"):
                resolved = _fix_pg(raw)
                backend = "postgresql"
            elif raw.startswith("sqlite://"):
                resolved = raw
                backend = "sqlite"
            else:
                # Render에서 가끔 'psql ...' 이상한 형태로 들어가는 경우 방지
                if "postgresql://" in raw or "postgres://" in raw:
                    resolved = _fix_pg(raw[raw.find("postgres"):])
                    backend = "postgresql"
                else:
                    raise ValueError("Unsupported DATABASE_URL format")
        else:
            raise ValueError("No DATABASE_URL")
    except Exception:
        # 폴백: 로컬 파일
        resolved = "sqlite:///./users.db"
        backend = "sqlite"

    return backend, raw or "", resolved

DB_BACKEND, RAW_DATABASE_URL, RESOLVED_DATABASE_URL = resolve_database_url()

# ------------------------------------------------------------------------------
# SQLAlchemy 초기화
# ------------------------------------------------------------------------------
connect_args = {}
if RESOLVED_DATABASE_URL.startswith("sqlite"):
    connect_args = {"check_same_thread": False}

engine = create_engine(RESOLVED_DATABASE_URL, pool_pre_ping=True, connect_args=connect_args)
SessionLocal = sessionmaker(bind=engine, expire_on_commit=False, autoflush=False)
Base = declarative_base()

# ------------------------------------------------------------------------------
# 모델
# 기존 DB 열을 최대한 포괄: id, username, password_hash, org, dept, start_date, end_date, role, active, created_at
# ------------------------------------------------------------------------------
class User(Base):
    __tablename__ = "users"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    username: Mapped[Optional[str]] = mapped_column(String(128), unique=True, nullable=True)
    password_hash: Mapped[str] = mapped_column(String, nullable=False)
    org: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    dept: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    start_date: Mapped[Optional[datetime.date]] = mapped_column(Date, nullable=True)
    end_date: Mapped[Optional[datetime.date]] = mapped_column(Date, nullable=True)
    role: Mapped[Optional[str]] = mapped_column(String(32), nullable=True, default="user")
    active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    created_at: Mapped[datetime.datetime] = mapped_column(
        TIMESTAMP(timezone=True), server_default=func.now(), nullable=False
    )

# 세션 테이블이 있는 환경을 고려(없는 곳도 있으므로 ORM 선언은 생략)
# FK 마이그레이션은 raw SQL로 처리

# ------------------------------------------------------------------------------
# 보안/JWT
# ------------------------------------------------------------------------------
JWT_SECRET = os.getenv("JWT_SECRET", "change-me")  # 반드시 환경변수로 교체 권장
JWT_ALG = "HS256"
TOKEN_TTL_HOURS = int(os.getenv("TOKEN_TTL_HOURS", "12"))

def hpw(plain: str) -> str:
    return bcrypt.hashpw(plain.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")

def vpw(plain: str, hashed: str) -> bool:
    try:
        return bcrypt.checkpw(plain.encode("utf-8"), hashed.encode("utf-8"))
    except Exception:
        return False

def issue_token(user: User) -> str:
    exp = datetime.datetime.utcnow() + datetime.timedelta(hours=TOKEN_TTL_HOURS)
    payload = {"sub": user.id, "role": user.role, "exp": exp}
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALG)

# ------------------------------------------------------------------------------
# Pydantic 스키마
# ------------------------------------------------------------------------------
class LoginIn(BaseModel):
    id: str
    password: str

class LoginOut(BaseModel):
    ok: bool
    id: str
    username: Optional[str] = None
    role: Optional[str] = None
    org: Optional[str] = None
    token: str

class UserCreate(BaseModel):
    id: str
    username: Optional[str] = None
    password: str = Field(min_length=1)
    org: Optional[str] = None
    dept: Optional[str] = None
    start_date: Optional[datetime.date] = None
    end_date: Optional[datetime.date] = None
    role: Optional[str] = "user"
    active: Optional[bool] = True

class UserUpdate(BaseModel):
    username: Optional[str] = None
    password: Optional[str] = None
    org: Optional[str] = None
    dept: Optional[str] = None
    start_date: Optional[datetime.date] = None
    end_date: Optional[datetime.date] = None
    role: Optional[str] = None
    active: Optional[bool] = None

# ------------------------------------------------------------------------------
# FastAPI
# ------------------------------------------------------------------------------
app = FastAPI(title="AI Appeal Auth", version=VERSION)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
    allow_credentials=True,
)

# ------------------------------------------------------------------------------
# 헬퍼
# ------------------------------------------------------------------------------
def get_db() -> Session:
    return SessionLocal()

def get_current_user(db: Session, token: str) -> User:
    if not token:
        raise HTTPException(status_code=401, detail="Missing token")
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALG])
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid token")
    uid = payload.get("sub")
    if not uid:
        raise HTTPException(status_code=401, detail="Invalid token(sub)")
    u = db.get(User, uid)
    if not u:
        raise HTTPException(status_code=401, detail="User not found")
    if not u.active:
        raise HTTPException(status_code=403, detail="User inactive")
    return u

def require_admin(u: User):
    if (u.role or "").lower() != "admin":
        raise HTTPException(status_code=403, detail="Admin only")
    return True

# ------------------------------------------------------------------------------
# 간이 마이그레이션 (가능하면 시도, 실패해도 서버는 계속)
# ------------------------------------------------------------------------------
def try_migrate_id_to_varchar(db: Session):
    if DB_BACKEND != "postgresql":
        return
    # users.id → varchar(64), sessions.user_id → varchar(64), FK 정합
    # 이미 변경된 경우에도 실패 없이 통과하도록 IF EXISTS/TRY 패턴
    stmts = [
        # users.id 타입 변경 (integer → text/varchar)
        "ALTER TABLE users ALTER COLUMN id TYPE VARCHAR(64) USING id::text",
        # sessions.user_id 타입 변경
        "ALTER TABLE sessions ALTER COLUMN user_id TYPE VARCHAR(64) USING user_id::text",
        # 기존 FK 있으면 삭제
        "ALTER TABLE sessions DROP CONSTRAINT IF EXISTS sessions_user_id_fkey",
        # FK 재생성
        "ALTER TABLE sessions ADD CONSTRAINT sessions_user_id_fkey FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE",
    ]
    for s in stmts:
        try:
            db.execute(text(s))
            db.commit()
        except Exception:
            db.rollback()
            # non-fatal: 그냥 넘긴다.

def seed_admin(db: Session):
    """최초 부팅 시 admin 계정 보장 (이미 있으면 스킵)"""
    admin_id = os.getenv("SEED_ADMIN_ID", "rnj88")
    admin_user = db.get(User, admin_id)
    if admin_user:
        return
    # username/active NOT NULL 환경 대비
    username = os.getenv("SEED_ADMIN_USERNAME", admin_id)
    org = os.getenv("SEED_ADMIN_ORG", BRAND)
    role = "admin"
    pw = os.getenv("SEED_ADMIN_PASSWORD", "6548")
    u = User(
        id=admin_id,
        username=username,
        password_hash=hpw(pw),
        org=org,
        dept=None,
        start_date=None,
        end_date=None,
        role=role,
        active=True,
    )
    db.add(u)
    db.commit()

def ensure_schema_and_migrate():
    # 테이블 생성(없으면)
    Base.metadata.create_all(engine)
    with SessionLocal() as db:
        try_migrate_id_to_varchar(db)
        # 시드
        try:
            seed_admin(db)
        except Exception as e:
            # 시드 실패는 서비스 치명적이지 않음 (로그만)
            print(f"[seed] failed: {e}")

# ------------------------------------------------------------------------------
# 라우트
# ------------------------------------------------------------------------------
@app.get("/")
def root():
    return {
        "ok": True,
        "service": SERVICE_NAME,
        "brand": BRAND,
        "version": VERSION,
        "db_backend": DB_BACKEND,
        "raw_database_url": RAW_DATABASE_URL + ("\n" if RAW_DATABASE_URL else ""),
        "resolved_database_url": RESOLVED_DATABASE_URL,
    }

@app.on_event("startup")
def on_startup():
    ensure_schema_and_migrate()

# ------------------- Auth -------------------
@app.post("/auth/login", response_model=LoginOut)
def login(body: LoginIn):
    with SessionLocal() as db:
        u = db.get(User, body.id)
        if not u:
            raise HTTPException(status_code=401, detail="Invalid credentials")
        if not vpw(body.password, u.password_hash):
            raise HTTPException(status_code=401, detail="Invalid credentials")
        if not u.active:
            raise HTTPException(status_code=403, detail="User inactive")
        token = issue_token(u)
        return {
            "ok": True,
            "id": u.id,
            "username": u.username,
            "role": u.role,
            "org": u.org,
            "token": token,
        }

@app.get("/auth/me")
def auth_me(authorization: Optional[str] = None):
    # Authorization: Bearer <token>
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(status_code=401, detail="Missing bearer")
    token = authorization.split(" ", 1)[1].strip()
    with SessionLocal() as db:
        u = get_current_user(db, token)
        return {
            "id": u.id,
            "username": u.username,
            "role": u.role,
            "org": u.org,
            "active": u.active,
            "created_at": u.created_at,
        }

# ------------------- Users (Admin only) -------------------
@app.get("/users")
def list_users(authorization: Optional[str] = None):
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(status_code=401, detail="Missing bearer")
    token = authorization.split(" ", 1)[1].strip()
    with SessionLocal() as db:
        u = get_current_user(db, token)
        require_admin(u)
        rows = db.execute(select(User)).scalars().all()
        return [
            {
                "id": r.id,
                "username": r.username,
                "role": r.role,
                "org": r.org,
                "dept": r.dept,
                "start_date": r.start_date,
                "end_date": r.end_date,
                "active": r.active,
                "created_at": r.created_at,
            }
            for r in rows
        ]

@app.post("/users")
def create_user(payload: UserCreate, authorization: Optional[str] = None):
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(status_code=401, detail="Missing bearer")
    token = authorization.split(" ", 1)[1].strip()
    with SessionLocal() as db:
        cur = get_current_user(db, token)
        require_admin(cur)
        if db.get(User, payload.id):
            raise HTTPException(status_code=409, detail="User id exists")
        if payload.username:
            # username unique 체크
            exists = db.execute(select(User).where(User.username == payload.username)).scalar_one_or_none()
            if exists:
                raise HTTPException(status_code=409, detail="Username exists")
        u = User(
            id=payload.id,
            username=payload.username or payload.id,
            password_hash=hpw(payload.password),
            org=payload.org,
            dept=payload.dept,
            start_date=payload.start_date,
            end_date=payload.end_date,
            role=payload.role or "user",
            active=True if payload.active is None else payload.active,
        )
        db.add(u)
        db.commit()
        return {"ok": True, "id": u.id}

@app.put("/users/{user_id}")
def update_user(user_id: str, payload: UserUpdate, authorization: Optional[str] = None):
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(status_code=401, detail="Missing bearer")
    token = authorization.split(" ", 1)[1].strip()
    with SessionLocal() as db:
        cur = get_current_user(db, token)
        require_admin(cur)
        u = db.get(User, user_id)
        if not u:
            raise HTTPException(status_code=404, detail="User not found")

        if payload.username is not None:
            if payload.username != u.username and payload.username != "":
                exists = db.execute(select(User).where(User.username == payload.username)).scalar_one_or_none()
                if exists:
                    raise HTTPException(status_code=409, detail="Username exists")
                u.username = payload.username

        if payload.password:
            u.password_hash = hpw(payload.password)
        if payload.org is not None:
            u.org = payload.org
        if payload.dept is not None:
            u.dept = payload.dept
        if payload.start_date is not None:
            u.start_date = payload.start_date
        if payload.end_date is not None:
            u.end_date = payload.end_date
        if payload.role is not None:
            u.role = payload.role
        if payload.active is not None:
            u.active = payload.active

        db.commit()
        return {"ok": True}

@app.delete("/users/{user_id}")
def delete_user(user_id: str, authorization: Optional[str] = None):
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(status_code=401, detail="Missing bearer")
    token = authorization.split(" ", 1)[1].strip()
    with SessionLocal() as db:
        cur = get_current_user(db, token)
        require_admin(cur)
        u = db.get(User, user_id)
        if not u:
            raise HTTPException(status_code=404, detail="User not found")
        db.delete(u)
        db.commit()
        return {"ok": True}



















