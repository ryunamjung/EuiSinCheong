# server_app.py
# FastAPI + SQLAlchemy + JWT
# - Postgres(Neon) 우선 사용, 없으면 sqlite로 폴백
# - users.id 문자열 PK (VARCHAR(64))
# - /auth/login, /auth/me, /admin/users CRUD
# - 시작 시 자동 스키마 생성 + 필요한 경우(정수 PK → 문자열 PK) 마이그레이션 시도
# - 루트에 GET/HEAD 허용(405 소음 제거)

import os
import time
from datetime import date
from typing import Optional, List

import jwt  # PyJWT
import bcrypt
from fastapi import FastAPI, Depends, HTTPException, Request, Response, status
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from sqlalchemy import (
    create_engine, text, select, Column, String, Integer, Date, DateTime,
    Boolean, ForeignKey, func
)
from sqlalchemy.orm import declarative_base, sessionmaker, Session

APP_VERSION = "v0.3.5"

# -----------------------------
# DB URL Sanitizer
# -----------------------------
def resolve_database_url() -> tuple[str, str]:
    """
    환경변수 DATABASE_URL을 정리해서 SQLAlchemy가 이해하는 URL로 변환.
    - postgres:// → postgresql:// 로 치환
    - 오타: 'psql+psycopg2:' 프리픽스 잘못 붙은 경우 제거
    - 없거나 잘못된 경우 sqlite로 폴백
    """
    raw = os.getenv("DATABASE_URL", "").strip()

    # 치명적인 오타 프리픽스 제거
    if raw.startswith("psql+psycopg2:"):
        raw = raw.replace("psql+psycopg2:", "", 1)

    # postgres → postgresql 정규화
    if raw.startswith("postgres://"):
        raw = "postgresql://" + raw[len("postgres://") :]

    if not raw:
        return ("sqlite:///./users.db", "sqlite")

    try:
        # 간단 검증(스킴만 체크)
        if raw.startswith("postgresql://") or raw.startswith("postgresql+psycopg2://"):
            return (raw, "postgresql")
        if raw.startswith("sqlite://"):
            return (raw, "sqlite")
        # 그 외도 SQLAlchemy가 처리할 수도 있지만, 여기선 명시 스킴만 허용
        raise ValueError("Unsupported DB URL")
    except Exception:
        return ("sqlite:///./users.db", "sqlite")


RESOLVED_DB_URL, DB_BACKEND = resolve_database_url()

# 엔진 생성
engine_kwargs = dict(pool_pre_ping=True, future=True)
if DB_BACKEND == "sqlite":
    engine_kwargs["connect_args"] = {"check_same_thread": False}

engine = create_engine(RESOLVED_DB_URL, **engine_kwargs)
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False, future=True)
Base = declarative_base()


# -----------------------------
# 모델 정의
# -----------------------------
class User(Base):
    __tablename__ = "users"

    # 문자열 PK
    id = Column(String(64), primary_key=True)

    # 운영 편의용 계정명
    username = Column(String(64), nullable=False, unique=True)

    password_hash = Column(String(128), nullable=False)

    org = Column(String(100))
    dept = Column(String(100))
    start_date = Column(Date)
    end_date = Column(Date)

    role = Column(String(20), nullable=False, default="user")  # 'admin' / 'user' 등
    active = Column(Boolean, nullable=False, server_default=text("true"))

    created_at = Column(DateTime(timezone=True), server_default=func.now())


class SessionRec(Base):
    __tablename__ = "sessions"

    id = Column(Integer, primary_key=True, autoincrement=True)
    user_id = Column(String(64), ForeignKey("users.id"))
    created_at = Column(DateTime(timezone=True), server_default=func.now())


# -----------------------------
# 보안/인증 유틸
# -----------------------------
JWT_ALG = "HS256"
JWT_SECRET = os.getenv("JWT_SECRET") or os.getenv("APP_SECRET") or "please-change-me"

def hash_password(plain: str) -> str:
    return bcrypt.hashpw(plain.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")

def verify_password(plain: str, pw_hash: str) -> bool:
    try:
        return bcrypt.checkpw(plain.encode("utf-8"), pw_hash.encode("utf-8"))
    except Exception:
        return False

def make_token(user_id: str, role: str, ttl_sec: int = 60 * 60 * 24 * 7) -> str:
    payload = {"sub": user_id, "role": role, "exp": int(time.time()) + ttl_sec}
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALG)

def decode_token(token: str) -> dict:
    try:
        return jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALG])
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="token expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="invalid token")


# -----------------------------
# DB 세션 의존성
# -----------------------------
def get_db() -> Session:
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


# -----------------------------
# 마이그레이션(자동)
# -----------------------------
def pg_column_exists(conn, table: str, column: str) -> bool:
    q = text("""
        SELECT 1
        FROM information_schema.columns
        WHERE table_name=:t AND column_name=:c
        LIMIT 1
    """)
    return conn.execute(q, {"t": table, "c": column}).first() is not None

def pg_column_type(conn, table: str, column: str) -> Optional[str]:
    q = text("""
        SELECT data_type
        FROM information_schema.columns
        WHERE table_name=:t AND column_name=:c
        LIMIT 1
    """)
    row = conn.execute(q, {"t": table, "c": column}).first()
    return row[0] if row else None

def ensure_schema_and_migrate() -> None:
    """
    - 테이블 미존재 시 생성
    - Postgres에서 users.id가 integer면: FK 드롭 → (sessions.user_id 먼저 변경) → users.id 변경 → FK 재생성
    - users.username / users.active 컬럼 보정
    """
    # 1) 우선 모델 기준으로 테이블 생성(없으면)
    Base.metadata.create_all(engine)

    if DB_BACKEND != "postgresql":
        # sqlite는 여기서 종료 (복잡한 타입 변경은 생략)
        return

    with engine.begin() as conn:
        # 2) users.id 타입 확인
        ctype = pg_column_type(conn, "users", "id")
        if ctype in ("integer", "bigint", "smallint"):
            # 다른 테이블 FK가 걸려있으면 먼저 끊어야 함(대표적으로 sessions.user_id)
            # 안전하게 if exists 로 드롭 시도
            conn.execute(text("ALTER TABLE IF EXISTS sessions DROP CONSTRAINT IF EXISTS sessions_user_id_fkey"))

            # sessions.user_id 자체 타입도 바꿈(있으면)
            if pg_column_exists(conn, "sessions", "user_id"):
                conn.execute(text("ALTER TABLE sessions ALTER COLUMN user_id TYPE VARCHAR(64) USING user_id::text"))

            # users.id 타입 변경
            conn.execute(text("ALTER TABLE users ALTER COLUMN id TYPE VARCHAR(64) USING id::text"))

            # FK 재생성(세션 테이블이 있다면)
            if pg_column_exists(conn, "sessions", "user_id"):
                conn.execute(text("""
                    ALTER TABLE sessions
                    ADD CONSTRAINT sessions_user_id_fkey
                    FOREIGN KEY (user_id) REFERENCES users(id)
                    ON UPDATE CASCADE ON DELETE CASCADE
                """))

        # 3) username 컬럼 없으면 추가
        if not pg_column_exists(conn, "users", "username"):
            conn.execute(text("ALTER TABLE users ADD COLUMN username VARCHAR(64)"))
            # 기본값 채우기: username이 NULL이면 id로 채움
            conn.execute(text("UPDATE users SET username = id WHERE username IS NULL"))
            # 유니크 인덱스
            conn.execute(text("CREATE UNIQUE INDEX IF NOT EXISTS ix_users_username ON users(username)"))
            # NOT NULL 부여
            conn.execute(text("ALTER TABLE users ALTER COLUMN username SET NOT NULL"))

        # 4) active 컬럼 없으면 추가
        if not pg_column_exists(conn, "users", "active"):
            conn.execute(text("ALTER TABLE users ADD COLUMN active BOOLEAN DEFAULT true"))
        # NULL 채우고 NOT NULL 강제
        conn.execute(text("UPDATE users SET active = true WHERE active IS NULL"))
        conn.execute(text("ALTER TABLE users ALTER COLUMN active SET NOT NULL"))

        # 5) created_at에 기본값 보정(없으면)
        # (정보스키마에서는 DEFAULT 검사 번거로워 간단 보정만)
        # 필요 시 스킵 가능


# -----------------------------
# 시드 (선택)
# -----------------------------
def seed_initial_admin():
    """
    환경변수로 ADMIN_ID / ADMIN_PASSWORD / ADMIN_ORG / ADMIN_ROLE('admin')가 있으면
    없을 때만 한 번 넣는다. 이미 존재하면 스킵.
    """
    admin_id = os.getenv("ADMIN_ID")
    admin_pw = os.getenv("ADMIN_PASSWORD")
    admin_org = os.getenv("ADMIN_ORG", "default-org")
    admin_role = os.getenv("ADMIN_ROLE", "admin")

    if not admin_id or not admin_pw:
        return

    with SessionLocal() as db:
        exists = db.get(User, admin_id)
        if exists:
            return
        u = User(
            id=admin_id,
            username=admin_id,
            password_hash=hash_password(admin_pw),
            org=admin_org,
            role=admin_role,
            active=True,
        )
        db.add(u)
        db.commit()


# -----------------------------
# Pydantic 스키마
# -----------------------------
class LoginBody(BaseModel):
    id: str = Field(..., description="User ID (문자열 PK)")
    password: str

class UserCreate(BaseModel):
    id: str
    username: Optional[str] = None
    password: str
    org: Optional[str] = None
    dept: Optional[str] = None
    start_date: Optional[date] = None
    end_date: Optional[date] = None
    role: str = "user"
    active: bool = True

class UserUpdate(BaseModel):
    username: Optional[str] = None
    password: Optional[str] = None
    org: Optional[str] = None
    dept: Optional[str] = None
    start_date: Optional[date] = None
    end_date: Optional[date] = None
    role: Optional[str] = None
    active: Optional[bool] = None


# -----------------------------
# FastAPI 앱
# -----------------------------
app = FastAPI(title="ai-appeal-auth", version=APP_VERSION)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], allow_credentials=True,
    allow_methods=["*"], allow_headers=["*"],
)

# 루트: GET/HEAD 모두 허용
@app.api_route("/", methods=["GET", "HEAD"])
def root():
    return {
        "ok": True,
        "service": "ai-appeal-auth",
        "brand": os.getenv("BRAND", "ryoryocompany"),
        "version": APP_VERSION,
        "db_backend": DB_BACKEND,
        "raw_database_url": os.getenv("DATABASE_URL", ""),
        "resolved_database_url": RESOLVED_DB_URL,
    }


# 현재 사용자 의존성
def get_current_user(request: Request, db: Session = Depends(get_db)) -> User:
    auth = request.headers.get("Authorization") or request.headers.get("authorization") or ""
    scheme, _, token = auth.partition(" ")
    if scheme.lower() != "bearer" or not token:
        # 선택: 쿼리파라미터 허용 (테스트 편의)
        if os.getenv("ALLOW_TOKEN_QUERY") and request.query_params.get("token"):
            token = request.query_params["token"]
        else:
            raise HTTPException(status_code=401, detail="missing bearer token")

    claims = decode_token(token)
    user_id = claims.get("sub")
    if not user_id:
        raise HTTPException(status_code=401, detail="invalid token payload")

    u = db.get(User, user_id)  # 문자열 PK
    if not u or not u.active:
        raise HTTPException(status_code=401, detail="inactive or not found")

    return u

def require_admin(u: User = Depends(get_current_user)) -> User:
    if (u.role or "").lower() != "admin":
        raise HTTPException(status_code=403, detail="admin only")
    return u


# -----------------------------
# 엔드포인트
# -----------------------------
@app.post("/auth/login")
def login(body: LoginBody, db: Session = Depends(get_db)):
    u = db.get(User, body.id)
    if not u or not verify_password(body.password, u.password_hash):
        raise HTTPException(status_code=401, detail="invalid credentials")
    token = make_token(u.id, u.role or "user")
    return {
        "ok": True,
        "id": u.id,
        "username": u.username,
        "role": u.role,
        "org": u.org,
        "token": token,
    }

@app.get("/auth/me")
def auth_me(u: User = Depends(get_current_user)):
    return {
        "ok": True,
        "id": u.id,
        "username": u.username,
        "role": u.role,
        "org": u.org,
    }

# Admin: 사용자 목록
@app.get("/admin/users")
def admin_list_users(_: User = Depends(require_admin), db: Session = Depends(get_db)):
    rows = db.execute(select(User).order_by(User.created_at.desc()).limit(200)).scalars().all()
    return [
        {
            "id": x.id, "username": x.username, "org": x.org, "dept": x.dept,
            "start_date": x.start_date, "end_date": x.end_date,
            "role": x.role, "active": x.active, "created_at": x.created_at,
        }
        for x in rows
    ]

# Admin: 사용자 생성
@app.post("/admin/users")
def admin_create_user(body: UserCreate, _: User = Depends(require_admin), db: Session = Depends(get_db)):
    if db.get(User, body.id):
        raise HTTPException(status_code=400, detail="id already exists")
    username = body.username or body.id
    if db.execute(select(User).where(User.username == username)).first():
        raise HTTPException(status_code=400, detail="username already exists")

    u = User(
        id=body.id,
        username=username,
        password_hash=hash_password(body.password),
        org=body.org, dept=body.dept,
        start_date=body.start_date, end_date=body.end_date,
        role=body.role, active=body.active,
    )
    db.add(u)
    db.commit()
    return {"ok": True}

# Admin: 사용자 수정
@app.patch("/admin/users/{user_id}")
def admin_update_user(user_id: str, body: UserUpdate, _: User = Depends(require_admin), db: Session = Depends(get_db)):
    u = db.get(User, user_id)
    if not u:
        raise HTTPException(status_code=404, detail="not found")

    if body.username is not None:
        if body.username != u.username:
            # 중복 체크
            if db.execute(select(User).where(User.username == body.username)).first():
                raise HTTPException(status_code=400, detail="username already exists")
        u.username = body.username

    if body.password:
        u.password_hash = hash_password(body.password)

    if body.org is not None:
        u.org = body.org
    if body.dept is not None:
        u.dept = body.dept
    if body.start_date is not None:
        u.start_date = body.start_date
    if body.end_date is not None:
        u.end_date = body.end_date
    if body.role is not None:
        u.role = body.role
    if body.active is not None:
        u.active = body.active

    db.commit()
    return {"ok": True}

# Admin: 사용자 삭제
@app.delete("/admin/users/{user_id}")
def admin_delete_user(user_id: str, _: User = Depends(require_admin), db: Session = Depends(get_db)):
    u = db.get(User, user_id)
    if not u:
        raise HTTPException(status_code=404, detail="not found")
    db.delete(u)
    db.commit()
    return {"ok": True}


# -----------------------------
# 수명 이벤트(시작 시 마이그레이션 & 시드)
# -----------------------------
@app.on_event("startup")
def on_startup():
    try:
        ensure_schema_and_migrate()
    except Exception as e:
        # 마이그레이션 실패는 로그만 남기고 계속(서비스는 올라가야 하므로)
        print(f"WARNING: [migrate] attempt failed (non-fatal): {e}")

    try:
        seed_initial_admin()
    except Exception as e:
        print(f"WARNING: [seed] failed (non-fatal): {e}")





















