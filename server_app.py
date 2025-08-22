# server_app.py
import os
import logging
import datetime as dt
from typing import Generator, Optional
from urllib.parse import urlparse, parse_qsl, urlencode, urlunparse

from fastapi import FastAPI, Depends
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from sqlalchemy import create_engine, text
from sqlalchemy.orm import declarative_base, sessionmaker, Session

# ------------------ Logging (강화) ------------------
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO").upper()
logging.basicConfig(
    level=LOG_LEVEL,
    format="%(asctime)s %(levelname)s [%(name)s] %(message)s",
)
log = logging.getLogger("server")

# ------------------ DB URL sanitize ------------------
def _sanitize_db_url(url: Optional[str]) -> tuple[str, bool]:
    """
    Render의 PostgreSQL URL에 붙는 일부 쿼리옵션이 드물게 드라이버와 충돌할 수 있어 제거.
    실패해도 원본을 그대로 사용.
    """
    if not url:
        return "sqlite:///./app.db", False

    try:
        u = urlparse(url)
        qs = dict(parse_qsl(u.query, keep_blank_values=True))
        removed = False
        for k in ("channel_binding",):
            if k in qs:
                qs.pop(k, None)
                removed = True
        new_q = urlencode(qs, doseq=True)
        sanitized = urlunparse((u.scheme, u.netloc, u.path, u.params, new_q, u.fragment))
        return sanitized, removed
    except Exception as e:
        log.exception("DB URL sanitize skipped")
        return url, False


# ------------------ SQLAlchemy 기본 셋업 ------------------
RAW_DB_URL = os.getenv("DATABASE_URL") or os.getenv("DB_URL")
DB_URL, SANITIZED = _sanitize_db_url(RAW_DB_URL)

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

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # 필요 시 허용 도메인만 남기세요
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ------------------ Schemas ------------------
class HealthOut(BaseModel):
    status: str
    db_ok: bool
    time: str

# ------------------ Startup (예외 삼키기) ------------------
@app.on_event("startup")
def on_startup():
    try:
        log.info("Booting... (sanitized_db_url=%s)", SANITIZED)
        # 필요 시 테이블 자동 생성
        # Base.metadata.create_all(bind=engine)

        # DB 연결 간단 확인 (드라이버/네트워크 문제 시 여기서 터짐)
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
        log.info("DB ready")
    except Exception:
        # 어떤 예외든 로그에 '스택트레이스' 남기고 서비스는 기동 유지
        log.exception("Startup DB check failed (service will still start)")

# ------------------ Health / Meta ------------------
@app.get("/", tags=["meta"])
def root():
    return {"ok": True, "time": dt.datetime.utcnow().isoformat() + "Z"}

@app.get("/healthz", response_model=HealthOut, include_in_schema=False)
def healthz(db: Session = Depends(get_db)):
    db_ok = True
    try:
        db.execute(text("SELECT 1"))
    except Exception:
        db_ok = False
        log.exception("/healthz DB check failed")
    return HealthOut(status="ok", db_ok=db_ok, time=dt.datetime.utcnow().isoformat() + "Z")

@app.get("/api/ping", tags=["meta"])
def ping():
    return {"pong": True}

# ------------------ Local run (옵션) ------------------
if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", "8000"))
    uvicorn.run(
        "server_app:app",
        host="0.0.0.0",
        port=port,
        log_level=LOG_LEVEL.lower(),
    )














