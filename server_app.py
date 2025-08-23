# server_app.py
# AI Appeal Auth (v0.3.5 호환) - ryoryocompany
# - / , /status : GET/HEAD 헬스 체크 (UptimeRobot 무료 플랜 HEAD 지원)
# - /auth/login : 관리자/사용자 로그인
# - DB URL 자동 보정(sqlite:/./ → sqlite:///./), 테이블 자동 생성
# - Postgres에서 users.id 가 integer면 VARCHAR(64)로 1회 자동 마이그레이션
# - ADMIN_ID / ADMIN_PW 로 부팅 시 자동 시드/업데이트

from __future__ import annotations

import os
import sys
import logging
from datetime import datetime
from typing import Optional

from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, Response

from pydantic import BaseModel

from sqlalchemy import (
    create_engine, text, String, Date, func
)
from sqlalchemy.orm import sessionmaker, DeclarativeBase, Mapped, mapped_column
from sqlalchemy.exc import SQLAlchemyError

from passlib.context import CryptContext

# ------------------------------------------------------------------------------
# 기본 설정
# ------------------------------------------------------------------------------
SERVICE_NAME = "ai-appeal-auth"
BRAND = "ryoryocompany"
VERSION = "v0.3.5"

logger = logging.getLogger("uvicorn.error")

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# ------------------------------------------------------------------------------
# DB URL 정리 (sqlite 오타 자동 보정)
# ------------------------------------------------------------------------------
def normalize_db_url(raw: Optional[str]) -> str:
    if not raw or not raw.strip():
        # 기본값: 로컬 sqlite
        return "sqlite:///./users.db"
    url = raw.strip()

    # 흔한 오타: sqlite:/./users.db  →  sqlite:///./users.db
    if url.startswith("sqlite:/./"):
        url = url.replace("sqlite:/./", "sqlite:///./", 1)

    # psycopg2 드라이버 명시는 없어도 되지만, 표시용으로 남김
    return url

RAW_DATABASE_URL = os.getenv("DATABASE_URL", "")
DATABASE_URL = normalize_db_url(RAW_DATABASE_URL)

# 엔진 생성
engine = create_engine(
    DATABASE_URL,
    pool_pre_ping=True,
    future=True,
)

SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False, future=True)


# ------------------------------------------------------------------------------
# SQLAlchemy 모델
# ------------------------------------------------------------------------------
class Base(DeclarativeBase):
    pass

class User(Base):
    __tablename__ = "users"

    # 문자열 PK를 표준으로 사용
    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    password_hash: Mapped[str] = mapped_column(String(255))
    org: Mapped[Optional[str]] = mapped_column(String(100), default=None)
    dept: Mapped[Optional[str]] = mapped_column(String(100), default=None)
    start_date: Mapped[Optional[datetime]] = mapped_column(Date, default=None)
    end_date: Mapped[Optional[datetime]] = mapped_column(Date, default=None)
    role: Mapped[Optional[str]] = mapped_column(String(50), default="admin")
    created_at: Mapped[Optional[datetime]] = mapped_column(default=func.now())


# ------------------------------------------------------------------------------
# 테이블 생성 + 호환 마이그레이션
# ------------------------------------------------------------------------------
def ensure_schema_and_migrate():
    # 테이블이 없다면 생성
    Base.metadata.create_all(engine)

    # Postgres에서 users.id 가 integer로 만들어진 과거 DB라면 문자형으로 변환
    try:
        with engine.begin() as conn:
            # DB 종류 판별(표시용)
            backend = engine.url.get_backend_name()

            # 정보 스키마에서 타입 조회 (Postgres/SQLite 모두 대응)
            q = text("""
                SELECT data_type
                FROM information_schema.columns
                WHERE table_name = 'users' AND column_name = 'id'
                LIMIT 1
            """)
            res = conn.execute(q).scalar_one_or_none()
            if res is None:
                return  # users 테이블이 없거나 정보 조회 불가 → create_all 로 충분

            # Postgres에서는 'integer', SQLite에서는 'INTEGER' 등으로 나올 수 있음
            dtype = str(res).lower()

            if "int" in dtype:
                # 기본값(시퀀스) 제거 후 타입 변경 (Postgres)
                try:
                    conn.execute(text("ALTER TABLE users ALTER COLUMN id DROP DEFAULT"))
                except Exception:
                    # 기본값이 없으면 여기서 에러가 나도 무시해도 됨
                    pass
                try:
                    # Postgres 문법
                    conn.execute(text("ALTER TABLE users ALTER COLUMN id TYPE VARCHAR(64) USING id::text"))
                except Exception as e:
                    # SQLite 등에서는 위 문법이 다를 수 있으므로, SQLite는 사실상 문자열로 수용됨
                    logger.warning(f"[migrate] attempt failed (non-fatal): {e}")

    except Exception as e:
        logger.error(f"[migrate] failed: {e}")


# ------------------------------------------------------------------------------
# 관리자 시드
# ------------------------------------------------------------------------------
def seed_admin():
    admin_id = os.getenv("ADMIN_ID", "admin").strip()
    admin_pw = os.getenv("ADMIN_PW", "admin").strip()
    if not admin_id or not admin_pw:
        logger.warning("[seed] ADMIN_ID/ADMIN_PW not set; skip seeding")
        return

    try:
        with SessionLocal() as db:
            u = db.get(User, admin_id)
            password_hash = pwd_context.hash(admin_pw)
            if u is None:
                u = User(id=admin_id, password_hash=password_hash, role="admin", org=BRAND)
                db.add(u)
                db.commit()
                logger.info("[seed] admin created")
            else:
                # 비번 갱신만
                u.password_hash = password_hash
                if not u.role:
                    u.role = "admin"
                db.commit()
                logger.info("[seed] admin updated")
    except Exception as e:
        logger.error(f"[seed] failed: {e}")


# ------------------------------------------------------------------------------
# FastAPI 앱
# ------------------------------------------------------------------------------
app = FastAPI(title="AI Appeal Auth", version=VERSION)

# CORS: 클라이언트 앱에서 호출 용이하게 전체 허용 (필요 시 도메인 제한)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# 헬스 체크 (GET)
@app.get("/", include_in_schema=False)
def root():
    backend = engine.url.get_backend_name()
    return {
        "ok": True,
        "service": SERVICE_NAME,
        "brand": BRAND,
        "version": VERSION,
        "db_backend": backend,
        # 운영 노출 최소화 위해 raw url 마스킹/생략 가능
        # "raw_database_url": RAW_DATABASE_URL,
        # "resolved_database_url": str(engine.url)
    }

# 헬스 체크 (HEAD) — UptimeRobot 무료 플랜 대응
@app.head("/", include_in_schema=False)
def root_head():
    return Response(status_code=200)

# 선택: /status 도 동일 제공
@app.get("/status", include_in_schema=False)
def status():
    return JSONResponse({"ok": True, "service": SERVICE_NAME, "version": VERSION})

@app.head("/status", include_in_schema=False)
def status_head():
    return Response(status_code=200)


# ------------------------------------------------------------------------------
# 로그인 API
# ------------------------------------------------------------------------------
class LoginBody(BaseModel):
    id: str
    password: str

@app.post("/auth/login")
def login(body: LoginBody, request: Request):
    try:
        with SessionLocal() as db:
            u = db.get(User, body.id)
            if not u:
                raise HTTPException(status_code=401, detail="invalid credentials")

            if not pwd_context.verify(body.password, u.password_hash):
                raise HTTPException(status_code=401, detail="invalid credentials")

            # 최소 응답 (프론트 호환을 위해 ok + id/role 정도만)
            return {
                "ok": True,
                "id": u.id,
                "role": u.role or "user",
            }
    except HTTPException:
        raise
    except SQLAlchemyError as e:
        logger.error(f"[login] db error: {e}")
        raise HTTPException(status_code=500, detail="server error")


# ------------------------------------------------------------------------------
# 앱 기동 훅: 스키마 보장 → 호환 마이그레이션 → 관리자 시드
# ------------------------------------------------------------------------------
@app.on_event("startup")
def on_startup():
    # 스키마 생성 및 호환 마이그레이션
    ensure_schema_and_migrate()
    # 관리자 계정 시드/업데이트
    seed_admin()


# 로컬 실행용 (Render에선 uvicorn server_app:app 으로 실행)
if __name__ == "__main__":
    import uvicorn
    uvicorn.run("server_app:app", host="0.0.0.0", port=int(os.getenv("PORT", "8000")), reload=True)

















