# server_app.py
import os
import logging
import datetime as dt
from typing import Generator, Optional
from urllib.parse import urlparse, parse_qsl, urlencode, urlunparse

from fastapi import FastAPI, Depends
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from sqlalchemy import create_engine, text, select
from sqlalchemy.orm import declarative_base, sessionmaker, Session
from sqlalchemy.exc import SQLAlchemyError

log = logging.getLogger("uvicorn.error")

# ------------------ DB URL sanitize ------------------
def _sanitize_db_url(url: Optional[str]) -> tuple[str, bool]:
    """
    Render의 PostgreSQL URL에 종종 붙는 channel_binding=require 등의
    연결 옵션이 드물게 문제를 유발할 수 있어 제거합니다.
    반환: (정리된 URL, 정리여부)
    """
    if not url:
        return "sqlite:///./app.db", False

    try:
        u = urlparse(url)
        qs = dict(parse_qsl(u.query, keep_blank_values=True))
        # 문제 유발 소지 옵션 제거
        removed = False
        for k in ["channel_binding"]:
            if k in qs:
                qs.pop(k, None)
                removed = True
        # 재조합
        new_q = urlencode(qs, doseq=True)
        sanitized = urlunparse((u.scheme, u.netloc, u.path, u.params, new_q, u.fragment))
        return sanitized, removed
    except Exception as e:
        log.warning(f"DB URL sanitize skipped: {e}")
        return url, False


# ------------------ DB / SQLAlchemy ------------------
RAW_DB_URL = os.getenv("DATABASE_URL") or os.getenv("DB_URL")
DB_URL, SANITIZED = _sanitize_db_url(RAW_DB_URL)

# SQLite일 때만 check_same_thread 옵션
connect_args = {}
if DB_URL.startswith("sqlite"):
    connect_args = {"check_same_thread": False}

engine = create_engine(DB_URL, pool_pre_ping=True, connect_args=connect_args)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


def get_db() -> Generator[Session, None, None]:
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


# ------------------ FastAPI App ------------------
app = FastAPI(title="EuiSinChung API", version="1.0.0")

# CORS (필요 시 도메인 제한)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # 배포 후 필요한 도메인만 남기세요.
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ------------------ Schemas (예시) ------------------
class HealthOut(BaseModel):
    status: str
    db_ok: bool
    time: str


# ------------------ Startup / Shutdown ------------------
@app.on_event("startup")
def on_startup():
    # 테이블 자동 생성이 필요한 경우 아래 줄 유지.
    # Base.metadata.create_all(bind=engine)

    # DB 연결 확인 (헬스체크 전에 준비 여부 로그)
    try:
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
        log.info(f"DB ready (url sanitized={SANITIZED})")
    except SQLAlchemyError as e:
        log.error(f"DB connection failed: {e}")
        # Render 배포 자체는 올라가되, 헬스체크는 /healthz에서 db_ok=False로 드러나게 함.


# ------------------ Health / Meta ------------------
@app.get("/", tags=["meta"])
def root():
    """
    Render 기본 헬스체크가 루트를 칠 때 200을 돌려주도록 간단 응답.
    """
    return {"ok": True, "time": dt.datetime.utcnow().isoformat() + "Z"}

@app.get("/healthz", response_model=HealthOut, include_in_schema=False)
def healthz(db: Session = Depends(get_db)):
    """
    Render에서 healthCheckPath를 /healthz로 잡아도 통과.
    DB가 죽었어도 200은 주되 db_ok=False로 표기(플랫폼의 재시도/재시작 유도 목적).
    """
    ok = True
    try:
        db.execute(select(text("1")))
        db_ok = True
    except Exception as e:
        log.warning(f"/healthz db check failed: {e}")
        db_ok = False
    return HealthOut(status="ok", db_ok=db_ok, time=dt.datetime.utcnow().isoformat() + "Z")


# ------------------ 예시 API (필요 시 확장) ------------------
@app.get("/api/ping", tags=["meta"])
def ping():
    return {"pong": True}


# ------------------ Local Run (optional) ------------------
if __name__ == "__main__":
    import uvicorn

    port = int(os.getenv("PORT", "8000"))
    uvicorn.run(
        "server_app:app",
        host="0.0.0.0",
        port=port,
        log_level="info",
        reload=bool(os.getenv("DEV_RELOAD", "")),
    )












