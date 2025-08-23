# server_app.py
import os
import uuid
import logging
from datetime import datetime, timedelta, timezone
from typing import Optional, Dict, Any

from fastapi import FastAPI, Depends, HTTPException, Header, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker
from passlib.context import CryptContext
import jwt  # PyJWT

# ------------------------------------------------------------
# 환경설정
# ------------------------------------------------------------
SERVICE_NAME = "ai-appeal-auth"
BRAND = os.getenv("BRAND", "ryoryocompany")
VERSION = "v0.3.5"

RAW_DB_URL = os.getenv("DATABASE_URL", "").strip()
SECRET_KEY = os.getenv("SECRET_KEY", "PLEASE_CHANGE_ME_TO_RANDOM_SECRET")
JWT_EXPIRE_HOURS = int(os.getenv("JWT_EXPIRE_HOURS", "12"))
ALGORITHM = "HS256"

def _normalize_db_url(url: str) -> str:
    """
    SQLAlchemy가 파싱 가능한 형태로 DB URL을 정리.
    - 지원: postgresql://..., postgresql+psycopg2://..., sqlite:///...
    """
    if not url:
        return "sqlite:///./users.db"

    lower = url.lower()
    if lower.startswith("postgres://"):
        # 오래된 스킴 → postgresql로 치환
        url = "postgresql://" + url.split("://", 1)[1]

    if lower.startswith("postgresql://"):
        # psycopg2 드라이버 명시 (없어도 되지만 일관성 있게)
        if "+psycopg2://" not in lower:
            url = "postgresql+psycopg2://" + url.split("://", 1)[1]

        # sslmode 누락 시 require 부여(Neon 기본)
        if "sslmode=" not in url:
            sep = "&" if "?" in url else "?"
            url = f"{url}{sep}sslmode=require"

    # 절대 금지: 'psql+psycopg2:postgresql://...' 같은 잘못된 접두어
    if url.lower().startswith("psql+psycopg2:postgresql://"):
        url = url.replace("psql+psycopg2:postgresql://", "postgresql+psycopg2://")

    return url

RESOLVED_DB_URL = _normalize_db_url(RAW_DB_URL)

# DB 연결
engine = create_engine(
    RESOLVED_DB_URL,
    pool_pre_ping=True,
)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# 암호화
pwd_ctx = CryptContext(schemes=["bcrypt"], deprecated="auto")

# FastAPI
app = FastAPI()

# CORS (Electron 포함 모든 출처 허용)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ------------------------------------------------------------
# 유틸
# ------------------------------------------------------------
def db_exec(sql: str, params: Optional[Dict[str, Any]] = None, fetch: bool = False):
    with engine.connect() as conn:
        if fetch:
            return conn.execute(text(sql), params or {}).mappings().all()
        else:
            conn.execute(text(sql), params or {})
            conn.commit()
            return None

def get_user_by_id_or_username(db, uid: str):
    # users 테이블 스키마가 프로젝트마다 조금씩 달라서 최소 필드만 읽음
    # 필요한 컬럼: id, username, password_hash, role, org, active(없으면 True 처리)
    row = db.execute(text("""
        SELECT id, username, password_hash, role, org,
               CASE
                 WHEN EXISTS(
                   SELECT 1
                   FROM information_schema.columns
                   WHERE table_name = 'users' AND column_name = 'active'
                 )
                 THEN active
                 ELSE TRUE
               END as active
        FROM users
        WHERE id = :uid OR username = :uid
        LIMIT 1
    """), {"uid": uid}).mappings().first()
    return row

def verify_password(plain: str, hashed: str) -> bool:
    try:
        return pwd_ctx.verify(plain, hashed)
    except Exception:
        return False

def hash_password(pw: str) -> str:
    return pwd_ctx.hash(pw)


# ------------------------------------------------------------
# 세션(동시로그인 차단) 테이블 보장 & 마이그레이션
# ------------------------------------------------------------
def ensure_schema_and_migrate():
    # users.id 를 varchar(64)로(이미 완료되어 있으면 무시)
    try:
        db_exec("""ALTER TABLE users ALTER COLUMN id DROP DEFAULT;""")
    except Exception:
        pass
    try:
        db_exec("""ALTER TABLE users ALTER COLUMN id TYPE VARCHAR(64) USING id::text;""")
    except Exception as e:
        # 이미 varchar거나 FK 충돌 등은 무시(로그만)
        logging.warning("[migrate] users.id alter attempt: %s", e)

    # sessions 테이블 생성(없으면)
    db_exec("""
    CREATE TABLE IF NOT EXISTS sessions (
        sid UUID PRIMARY KEY,
        user_id VARCHAR(64) NOT NULL,
        created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
        expires_at TIMESTAMPTZ NOT NULL,
        revoked BOOLEAN NOT NULL DEFAULT FALSE
    );
    """)
    # FK 정비(이미 있으면 무시)
    try:
        db_exec("""ALTER TABLE sessions DROP CONSTRAINT IF EXISTS sessions_user_id_fkey;""")
        db_exec("""ALTER TABLE sessions
                  ADD CONSTRAINT sessions_user_id_fkey
                  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE;""")
    except Exception as e:
        logging.warning("[migrate] sessions FK: %s", e)

    # 인덱스
    db_exec("""CREATE INDEX IF NOT EXISTS ix_sessions_user_id ON sessions(user_id);""")
    db_exec("""CREATE INDEX IF NOT EXISTS ix_sessions_active ON sessions(user_id, revoked, expires_at);""")


@app.on_event("startup")
def on_startup():
    ensure_schema_and_migrate()
    logging.info("[startup] %s %s db=%s", SERVICE_NAME, VERSION,
                 "postgresql" if RESOLVED_DB_URL.startswith("postgresql") else "sqlite")


# ------------------------------------------------------------
# 모델 (Pydantic)
# ------------------------------------------------------------
class LoginBody(BaseModel):
    id: str
    password: str


# ------------------------------------------------------------
# 인증 공통
# ------------------------------------------------------------
def create_token(user_id: str, role: str, sid: str) -> str:
    exp = datetime.now(tz=timezone.utc) + timedelta(hours=JWT_EXPIRE_HOURS)
    payload = {"sub": user_id, "role": role, "sid": sid, "exp": exp}
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)

def decode_token(token: str) -> Dict[str, Any]:
    try:
        return jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="token expired")
    except Exception:
        raise HTTPException(status_code=401, detail="invalid token")

def bearer_token(auth_header: Optional[str] = Header(None)) -> str:
    if not auth_header or not auth_header.lower().startswith("bearer "):
        raise HTTPException(status_code=401, detail="missing bearer token")
    return auth_header.split(" ", 1)[1]


def require_user(auth: str = Depends(bearer_token)) -> Dict[str, Any]:
    payload = decode_token(auth)
    sid = payload.get("sid")
    uid = payload.get("sub")
    if not sid or not uid:
        raise HTTPException(status_code=401, detail="invalid token payload")

    # 세션 유효성(동시로그인 차단 핵심)
    row = db_exec("""
        SELECT sid, user_id, revoked, expires_at
        FROM sessions
        WHERE sid = :sid AND user_id = :uid
        LIMIT 1
    """, {"sid": sid, "uid": uid}, fetch=True)
    if not row:
        raise HTTPException(status_code=401, detail="session revoked or not found")
    s = row[0]
    if s["revoked"]:
        raise HTTPException(status_code=401, detail="session revoked")
    if s["expires_at"] <= datetime.now(timezone.utc):
        raise HTTPException(status_code=401, detail="session expired")

    return payload  # {"sub":..., "role":..., "sid":...}


# ------------------------------------------------------------
# 라우트
# ------------------------------------------------------------
@app.get("/")
def root():
    backend = "postgresql" if RESOLVED_DB_URL.startswith("postgresql") else "sqlite"
    return {
        "ok": True,
        "service": SERVICE_NAME,
        "brand": BRAND,
        "version": VERSION,
        "db_backend": backend,
        "raw_database_url": RAW_DB_URL if RAW_DB_URL else "sqlite:///./users.db",
        "resolved_database_url": RESOLVED_DB_URL,
    }


@app.post("/auth/login")
def login(body: LoginBody, request: Request):
    with engine.connect() as conn:
        u = get_user_by_id_or_username(conn, body.id)
        if not u:
            raise HTTPException(status_code=401, detail="invalid credentials")

        if not verify_password(body.password, u["password_hash"]):
            raise HTTPException(status_code=401, detail="invalid credentials")

        if not u["active"]:
            raise HTTPException(status_code=403, detail="inactive user")

        # 기존 세션 전부 revoke(한 아이디 1세션 정책)
        conn.execute(text("""
            UPDATE sessions SET revoked = TRUE
            WHERE user_id = :uid AND revoked = FALSE
        """), {"uid": u["id"]})

        # 새 세션 발급
        sid = str(uuid.uuid4())
        expires_at = datetime.now(timezone.utc) + timedelta(hours=JWT_EXPIRE_HOURS)
        conn.execute(text("""
            INSERT INTO sessions (sid, user_id, expires_at, revoked)
            VALUES (:sid, :uid, :exp, FALSE)
        """), {"sid": sid, "uid": u["id"], "exp": expires_at})
        conn.commit()

        token = create_token(u["id"], u["role"] or "user", sid)

        return {
            "ok": True,
            "id": u["id"],
            "username": u["username"],
            "role": u["role"],
            "org": u["org"],
            "token": token,
        }


@app.get("/auth/me")
def me(user=Depends(require_user)):
    # 토큰 확인 + 세션 유효성은 require_user에서 이미 체크됨
    uid = user["sub"]
    with engine.connect() as conn:
        u = get_user_by_id_or_username(conn, uid)
        if not u:
            raise HTTPException(status_code=404, detail="user not found")
        return {
            "ok": True,
            "id": u["id"],
            "username": u["username"],
            "role": u["role"],
            "org": u["org"],
        }


@app.post("/auth/logout")
def logout(user=Depends(require_user)):
    sid = user["sid"]
    uid = user["sub"]
    db_exec("""
        UPDATE sessions SET revoked = TRUE
        WHERE sid = :sid AND user_id = :uid
    """, {"sid": sid, "uid": uid})
    return {"ok": True}






















