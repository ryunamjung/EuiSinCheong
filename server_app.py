# server_app.py
import os
import uuid
import bcrypt
import jwt
import datetime as dt
from typing import Optional, List

from fastapi import FastAPI, Depends, HTTPException, Header, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from sqlalchemy import (
    create_engine, text, String, Boolean, Date, DateTime, func,
    ForeignKey, select
)
from sqlalchemy.orm import (
    DeclarativeBase, Mapped, mapped_column, relationship, Session, sessionmaker
)


# -----------------------------------------------------------------------------
# Config / DB URL normalize
# -----------------------------------------------------------------------------
SERVICE_NAME = "ai-appeal-auth"
VERSION = "v0.3.5"

def normalize_db_url(raw: Optional[str]) -> Optional[str]:
    """
    DATABASE_URL을 SQLAlchemy가 이해하는 형태로 정규화.
    - postgresql://...  혹은 postgresql+psycopg2://... 허용
    - sqlite:///...     허용
    """
    if not raw:
        return None
    s = raw.strip()

    # 흔한 실수 방지: 'psql+psycopg2:' 같은 틀린 프리픽스 제거
    if s.startswith("psql+psycopg2:"):
        s = s.replace("psql+psycopg2:", "postgresql+psycopg2:", 1)

    # 채널바인딩 등 쿼리스트링은 그대로 두되, 스킴만 보정
    if s.startswith("postgres://"):
        s = s.replace("postgres://", "postgresql+psycopg2://", 1)
    elif s.startswith("postgresql://"):
        s = s.replace("postgresql://", "postgresql+psycopg2://", 1)

    # sqlite 단축형 보정
    if s.startswith("sqlite:/./"):
        # 'sqlite:/./users.db' 같은 오타 -> 'sqlite:///./users.db'
        s = s.replace("sqlite:/./", "sqlite:///./", 1)

    return s


RAW_DATABASE_URL = os.getenv("DATABASE_URL")
DATABASE_URL = normalize_db_url(RAW_DATABASE_URL)

if not DATABASE_URL:
    # 안전한 기본값 (로컬 개발용)
    DATABASE_URL = "sqlite:///./users.db"
    DB_BACKEND = "sqlite"
else:
    DB_BACKEND = "postgresql"


engine = create_engine(DATABASE_URL, pool_pre_ping=True, future=True)
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False, future=True)


# -----------------------------------------------------------------------------
# ORM
# -----------------------------------------------------------------------------
class Base(DeclarativeBase):
    pass


class User(Base):
    __tablename__ = "users"

    # 문자열 PK (분점/사번 형태 등)
    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    username: Mapped[str] = mapped_column(String(64), unique=True, nullable=False, index=True)
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)

    # 조직 정보
    org: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    dept: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)

    # 근무/계약 기간
    start_date: Mapped[Optional[dt.date]] = mapped_column(Date, nullable=True)
    end_date: Mapped[Optional[dt.date]]   = mapped_column(Date, nullable=True)

    # 권한/활성
    role: Mapped[Optional[str]] = mapped_column(String(32), nullable=True, default="user")
    active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)

    created_at: Mapped[dt.datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now()
    )

    sessions: Mapped[List["SessionModel"]] = relationship(
        back_populates="user", cascade="all, delete-orphan"
    )


class SessionModel(Base):
    __tablename__ = "sessions"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)  # 세션/토큰 식별자
    user_id: Mapped[str] = mapped_column(
        String(64),
        ForeignKey("users.id", ondelete="CASCADE"),
        index=True,
        nullable=False
    )
    created_at: Mapped[dt.datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    expires_at: Mapped[Optional[dt.datetime]] = mapped_column(DateTime(timezone=True), nullable=True)

    user: Mapped[User] = relationship(back_populates="sessions")


# -----------------------------------------------------------------------------
# FastAPI
# -----------------------------------------------------------------------------
app = FastAPI(
    title=SERVICE_NAME,
    version=VERSION
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS", "HEAD"],  # HEAD 포함
    allow_headers=["*"],
)


# -----------------------------------------------------------------------------
# Schemas
# -----------------------------------------------------------------------------
class LoginBody(BaseModel):
    id: str
    password: str


class UserCreateBody(BaseModel):
    id: str
    username: str
    password: str
    org: Optional[str] = None
    dept: Optional[str] = None
    role: Optional[str] = "user"
    active: Optional[bool] = True


class UserUpdateBody(BaseModel):
    username: Optional[str] = None
    password: Optional[str] = None
    org: Optional[str] = None
    dept: Optional[str] = None
    role: Optional[str] = None
    active: Optional[bool] = None


# -----------------------------------------------------------------------------
# Utils: password / jwt
# -----------------------------------------------------------------------------
SECRET_KEY = os.getenv("SECRET_KEY", "change-me-in-prod")
JWT_ALG = "HS256"
JWT_TTL_HOURS = int(os.getenv("JWT_TTL_HOURS", "24"))

def hash_password(plain: str) -> str:
    return bcrypt.hashpw(plain.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")

def verify_password(plain: str, hashed: str) -> bool:
    try:
        return bcrypt.checkpw(plain.encode("utf-8"), hashed.encode("utf-8"))
    except Exception:
        return False

def new_session_id() -> str:
    return uuid.uuid4().hex

def create_jwt(user_id: str, role: str, sid: str) -> str:
    exp = dt.datetime.utcnow() + dt.timedelta(hours=JWT_TTL_HOURS)
    payload = {"sub": user_id, "role": role, "sid": sid, "exp": exp}
    return jwt.encode(payload, SECRET_KEY, algorithm=JWT_ALG)

def decode_jwt(token: str) -> dict:
    try:
        return jwt.decode(token, SECRET_KEY, algorithms=[JWT_ALG])
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")


# -----------------------------------------------------------------------------
# DB / Migrations (best-effort)
# -----------------------------------------------------------------------------
def col_exists(db: Session, table: str, col: str) -> bool:
    if DB_BACKEND == "sqlite":
        q = text(f"PRAGMA table_info({table})")
        rows = db.execute(q).all()
        return any(r[1] == col for r in rows)
    else:
        q = text("""
            SELECT 1
            FROM information_schema.columns
            WHERE table_name = :t AND column_name = :c
        """)
        return db.execute(q, {"t": table, "c": col}).first() is not None


def ensure_schema_and_migrate():
    Base.metadata.create_all(engine)

    with SessionLocal() as db:
        # users.id가 문자열 아닌 경우(이전 integer) → varchar로 시도
        try:
            if DB_BACKEND != "sqlite":
                # 실제 타입 확인
                t = db.execute(text("""
                    SELECT data_type
                    FROM information_schema.columns
                    WHERE table_name='users' AND column_name='id'
                """)).scalar()
                if t and t.lower() not in ("character varying", "text"):
                    # 관계(세션) 등 때문에 실패 가능 → 예외는 무시
                    db.execute(text("ALTER TABLE users ALTER COLUMN id TYPE VARCHAR(64) USING id::text"))
                    db.commit()
        except Exception:
            db.rollback()

        # sessions.user_id를 varchar(64)로
        try:
            if DB_BACKEND != "sqlite":
                t = db.execute(text("""
                    SELECT data_type
                    FROM information_schema.columns
                    WHERE table_name='sessions' AND column_name='user_id'
                """)).scalar()
                if t and t.lower() not in ("character varying", "text"):
                    db.execute(text("ALTER TABLE sessions ALTER COLUMN user_id TYPE VARCHAR(64) USING user_id::text"))
                    db.commit()
        except Exception:
            db.rollback()

        # sessions.expires_at 없으면 추가
        try:
            if not col_exists(db, "sessions", "expires_at"):
                if DB_BACKEND == "sqlite":
                    db.execute(text("ALTER TABLE sessions ADD COLUMN expires_at TIMESTAMP"))
                else:
                    db.execute(text("ALTER TABLE sessions ADD COLUMN expires_at TIMESTAMPTZ"))
                db.commit()
        except Exception:
            db.rollback()


def seed_admin():
    """최초 배포 시 관리자 계정(rnj88/6548) 자동 생성(없을 때만)"""
    admin_id = "rnj88"
    with SessionLocal() as db:
        u = db.get(User, admin_id)
        if u:
            return
        u = User(
            id=admin_id,
            username="rnj88",
            password_hash=hash_password("6548"),
            org="ryoryocompany",
            role="admin",
            active=True,
        )
        db.add(u)
        db.commit()


# -----------------------------------------------------------------------------
# Dependencies
# -----------------------------------------------------------------------------
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def bearer_auth(authorization: Optional[str] = Header(None)) -> str:
    if not authorization:
        raise HTTPException(status_code=401, detail="Missing Authorization")
    parts = authorization.split()
    if len(parts) != 2 or parts[0].lower() != "bearer":
        raise HTTPException(status_code=401, detail="Invalid Authorization header")
    return parts[1]


def get_current_user(token: str = Depends(bearer_auth), db: Session = Depends(get_db)) -> User:
    payload = decode_jwt(token)
    user_id = payload.get("sub")
    sid = payload.get("sid")
    if not user_id or not sid:
        raise HTTPException(status_code=401, detail="Invalid token payload")

    # 세션 유효성 확인(단일 로그인 보장: 해당 sid 가 실제 존재해야 함)
    sess = db.get(SessionModel, sid)
    if not sess or sess.user_id != user_id:
        raise HTTPException(status_code=401, detail="Session not found")

    if sess.expires_at and sess.expires_at < dt.datetime.utcnow().replace(tzinfo=dt.timezone.utc):
        # 만료 세션
        db.delete(sess)
        db.commit()
        raise HTTPException(status_code=401, detail="Session expired")

    u = db.get(User, user_id)
    if not u or not u.active:
        raise HTTPException(status_code=401, detail="Inactive or not found")
    return u


def admin_required(u: User = Depends(get_current_user)) -> User:
    if (u.role or "").lower() != "admin":
        raise HTTPException(status_code=403, detail="Admin only")
    return u


# -----------------------------------------------------------------------------
# Health / Root (Render 헬스체크: HEAD 200 보장)
# -----------------------------------------------------------------------------
@app.get("/", include_in_schema=False)
def root():
    return {
        "ok": True,
        "service": SERVICE_NAME,
        "version": VERSION,
        "db_backend": DB_BACKEND,
        "raw_database_url": RAW_DATABASE_URL or "(unset)",
        "resolved_database_url": DATABASE_URL,
    }

@app.head("/", include_in_schema=False)
def root_head():
    return Response(status_code=200)

@app.get("/healthz", include_in_schema=False)
def healthz():
    return {"ok": True}

@app.head("/healthz", include_in_schema=False)
def healthz_head():
    return Response(status_code=200)


# -----------------------------------------------------------------------------
# Auth
# -----------------------------------------------------------------------------
@app.post("/auth/login")
def login(body: LoginBody, db: Session = Depends(get_db)):
    # id로 우선 검색(없으면 username으로 fallback)
    u = db.get(User, body.id)
    if not u:
        u = db.scalar(select(User).where(User.username == body.id))
    if not u:
        raise HTTPException(status_code=401, detail="Invalid credentials")

    if not u.active or not verify_password(body.password, u.password_hash):
        raise HTTPException(status_code=401, detail="Invalid credentials")

    # 단일 로그인 보장: 기존 세션 모두 제거
    db.execute(text("DELETE FROM sessions WHERE user_id = :uid"), {"uid": u.id})

    sid = new_session_id()
    exp = dt.datetime.utcnow().replace(tzinfo=dt.timezone.utc) + dt.timedelta(hours=JWT_TTL_HOURS)

    s = SessionModel(id=sid, user_id=u.id, expires_at=exp)
    db.add(s)
    db.commit()

    token = create_jwt(u.id, u.role or "user", sid)
    return {
        "ok": True,
        "id": u.id,
        "username": u.username,
        "role": u.role or "user",
        "org": u.org,
        "token": token,
    }


@app.get("/auth/me")
def me(u: User = Depends(get_current_user)):
    return {
        "ok": True,
        "id": u.id,
        "username": u.username,
        "role": u.role or "user",
        "org": u.org,
        "dept": u.dept,
        "active": u.active,
        "created_at": u.created_at,
    }


@app.post("/auth/logout")
def logout(u: User = Depends(get_current_user), token: str = Depends(bearer_auth), db: Session = Depends(get_db)):
    # 현재 토큰의 sid만 제거
    payload = decode_jwt(token)
    sid = payload.get("sid")
    if sid:
        db.execute(text("DELETE FROM sessions WHERE id = :sid"), {"sid": sid})
        db.commit()
    return {"ok": True}


# -----------------------------------------------------------------------------
# Admin: users CRUD
# -----------------------------------------------------------------------------
@app.get("/admin/users")
def list_users(_: User = Depends(admin_required), db: Session = Depends(get_db)):
    rows = db.execute(select(User)).scalars().all()
    return [
        {
            "id": r.id,
            "username": r.username,
            "org": r.org,
            "dept": r.dept,
            "role": r.role,
            "active": r.active,
            "created_at": r.created_at
        }
        for r in rows
    ]


@app.post("/admin/users")
def create_user(body: UserCreateBody, _: User = Depends(admin_required), db: Session = Depends(get_db)):
    if db.get(User, body.id) or db.scalar(select(User).where(User.username == body.username)):
        raise HTTPException(status_code=409, detail="User already exists")

    u = User(
        id=body.id,
        username=body.username,
        password_hash=hash_password(body.password),
        org=body.org,
        dept=body.dept,
        role=body.role or "user",
        active=True if body.active is None else bool(body.active),
    )
    db.add(u)
    db.commit()
    return {"ok": True}


@app.put("/admin/users/{user_id}")
def update_user(user_id: str, body: UserUpdateBody, _: User = Depends(admin_required), db: Session = Depends(get_db)):
    u = db.get(User, user_id)
    if not u:
        raise HTTPException(status_code=404, detail="User not found")

    if body.username is not None:
        # 다른 유저와 중복 방지
        exists = db.scalar(select(User).where(User.username == body.username, User.id != user_id))
        if exists:
            raise HTTPException(status_code=409, detail="Username already taken")
        u.username = body.username

    if body.password:
        u.password_hash = hash_password(body.password)

    if body.org is not None:
        u.org = body.org
    if body.dept is not None:
        u.dept = body.dept
    if body.role is not None:
        u.role = body.role
    if body.active is not None:
        u.active = bool(body.active)

    db.add(u)
    db.commit()
    return {"ok": True}


@app.delete("/admin/users/{user_id}")
def delete_user(user_id: str, _: User = Depends(admin_required), db: Session = Depends(get_db)):
    u = db.get(User, user_id)
    if not u:
        raise HTTPException(status_code=404, detail="User not found")
    db.delete(u)  # sessions는 FK CASCADE
    db.commit()
    return {"ok": True}


# -----------------------------------------------------------------------------
# Startup
# -----------------------------------------------------------------------------
@app.on_event("startup")
def on_startup():
    ensure_schema_and_migrate()
    seed_admin()























