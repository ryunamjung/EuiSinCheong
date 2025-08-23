import os, secrets, datetime as dt, logging
from typing import Optional, List, Set
from urllib.parse import urlparse, parse_qsl, urlencode, urlunparse

from fastapi import FastAPI, HTTPException, Depends, Header
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from sqlalchemy import create_engine, String, Date, DateTime, text, inspect
from sqlalchemy.orm import declarative_base, sessionmaker, mapped_column, Mapped
from passlib.hash import bcrypt

log = logging.getLogger("uvicorn.error")
DEFAULT_SQLITE = "sqlite:///./users.db"

def _sanitize_db_url(url: str) -> str:
    if not url:
        return DEFAULT_SQLITE
    url = url.strip().strip('"').strip("'")
    try:
        if url.startswith("postgres://"):
            url = "postgresql+psycopg2://" + url[len("postgres://"):]
        elif url.startswith("postgresql://") and "+psycopg2" not in url:
            url = "postgresql+psycopg2://" + url[len("postgresql://"):]
        if url.startswith("sqlite:/") and not url.startswith("sqlite:///"):
            url = "sqlite:///" + url[len("sqlite:/"):]
        if url.startswith("sqlite:") and ":///" not in url:
            path = url.split("sqlite:",1)[1].lstrip("/")
            url = "sqlite:///" + path
        u = urlparse(url)
        qs = dict(parse_qsl(u.query, keep_blank_values=True))
        qs.pop("channel_binding", None)
        url = urlunparse((u.scheme, u.netloc, u.path, u.params, urlencode(qs), u.fragment))
        return url
    except Exception as e:
        log.error(f"[sanitize] failed ({e}); fallback to default sqlite")
        return DEFAULT_SQLITE

RAW_DATABASE_URL = os.getenv("DATABASE_URL", DEFAULT_SQLITE)
DATABASE_URL = _sanitize_db_url(RAW_DATABASE_URL)

def _safe_engine(url: str):
    from sqlalchemy import text
    try:
        eng = create_engine(url, connect_args={"check_same_thread": False} if url.startswith("sqlite") else {}, pool_pre_ping=True)
        with eng.connect() as conn:
            conn.execute(text("SELECT 1"))
        return eng
    except Exception as e:
        log.error(f"[engine] invalid DATABASE_URL='{url}' ({e}); fallback to default sqlite")
        return create_engine(DEFAULT_SQLITE, connect_args={"check_same_thread": False}, pool_pre_ping=True)

engine = _safe_engine(DATABASE_URL)
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)
Base = declarative_base()

class User(Base):
    __tablename__ = "users"
    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    password_hash: Mapped[str] = mapped_column(String(256))
    org: Mapped[Optional[str]] = mapped_column(String(128), default=None)
    dept: Mapped[Optional[str]] = mapped_column(String(128), default=None)
    start_date: Mapped[Optional[dt.date]] = mapped_column(Date, default=None)
    end_date: Mapped[Optional[dt.date]] = mapped_column(Date, default=None)
    role: Mapped[str] = mapped_column(String(16), default="user")
    created_at: Mapped[dt.datetime] = mapped_column(DateTime, default=lambda: dt.datetime.utcnow())

class LoginIn(BaseModel):
    id: str
    password: str

class UserIn(BaseModel):
    id: str
    password: Optional[str] = None
    org: Optional[str] = None
    dept: Optional[str] = None
    start_date: Optional[dt.date] = None
    end_date: Optional[dt.date] = None
    role: Optional[str] = "user"

app = FastAPI(title="AI 이의신청프로그램 Auth API (ryoryocompany v0.3.5)")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

def ensure_schema():
    insp = inspect(engine)
    backend = engine.url.get_backend_name()
    tbls = insp.get_table_names()
    if "users" not in tbls:
        Base.metadata.create_all(engine)
        return
    existing: Set[str] = {c["name"] for c in insp.get_columns("users")}
    needed = {"org":("VARCHAR(128)",None), "dept":("VARCHAR(128)",None), "start_date":("DATE",None), "end_date":("DATE",None), "role":("VARCHAR(16)","'user'"), "created_at":("TIMESTAMP",None)}
    with engine.begin() as conn:
        for col, (ctype, _) in needed.items():
            if col not in existing:
                if backend == "sqlite":
                    sql = f'ALTER TABLE users ADD COLUMN {col} {ctype}'
                    if col == "role":
                        sql += " DEFAULT 'user'"
                    conn.execute(text(sql))
                else:
                    sql = f'ALTER TABLE users ADD COLUMN "{col}" {ctype}'
                    if col == "role":
                        sql += " DEFAULT 'user'"
                    conn.execute(text(sql))
        if backend.startswith("postgresql"):
            conn.execute(text("ALTER TABLE users ALTER COLUMN created_at SET DEFAULT NOW()"))

ensure_schema()
with SessionLocal() as db:
    try:
        from sqlalchemy.orm import Session
        u = db.get(User, os.getenv("ADMIN_ID", "rnj88"))
        if not u:
            db.add(User(id=os.getenv("ADMIN_ID", "rnj88"), password_hash=bcrypt.hash(os.getenv("ADMIN_PW", "6548")), role="admin"))
        else:
            u.password_hash = bcrypt.hash(os.getenv("ADMIN_PW", "6548"))
            u.role = "admin"
        db.commit()
    except Exception as e:
        log.error(f"[seed] failed: {e}")

TOKENS = {}
def make_token(uid: str) -> str:
    token = secrets.token_hex(16)
    TOKENS[token] = {"id": uid, "ts": dt.datetime.utcnow()}
    return token

def validate_token(x_auth: str = Header(..., alias="X-Auth")):
    info = TOKENS.get(x_auth)
    if not info:
        raise HTTPException(status_code=401, detail="no token")
    with SessionLocal() as db:
        u = db.get(User, info["id"])
        if not u:
            raise HTTPException(status_code=401, detail="invalid token")
        return u

@app.get("/")
def health():
    backend = engine.url.get_backend_name()
    return {"ok": True, "service": "ai-appeal-auth", "brand": "ryoryocompany", "version": "v0.3.5",
            "db_backend": backend, "raw_database_url": os.getenv("DATABASE_URL", ""), "resolved_database_url": str(engine.url)}

@app.post("/auth/login")
def login(body: LoginIn):
    with SessionLocal() as db:
        u = db.get(User, body.id)
        if not u:
            raise HTTPException(status_code=401, detail="invalid credentials: user not found")
        if not bcrypt.verify(body.password, u.password_hash):
            raise HTTPException(status_code=401, detail="invalid credentials: wrong password")
        return {"token": make_token(u.id), "role": u.role, "displayName": u.id}
















