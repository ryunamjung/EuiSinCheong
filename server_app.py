import os, secrets, datetime as dt
from typing import Optional, List
from urllib.parse import urlparse, parse_qsl, urlencode, urlunparse

from fastapi import FastAPI, HTTPException, Depends, Header, status
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from sqlalchemy import create_engine, String, Date, DateTime
from sqlalchemy.orm import declarative_base, sessionmaker, mapped_column, Mapped, Session
from passlib.hash import bcrypt

# ------------------ DB URL sanitize ------------------
def _sanitize_db_url(url: str) -> str:
    if not url:
        return url
    try:
        u = urlparse(url)
        scheme = u.scheme
        # Render/Heroku often provide postgres:// — normalize to postgresql+psycopg2://
        if scheme == "postgres":
            scheme = "postgresql+psycopg2"
        elif scheme == "postgresql":
            # add driver explicitly for clarity
            scheme = "postgresql+psycopg2"
        # strip troublesome query parameters (e.g., channel_binding=require)
        qs = dict(parse_qsl(u.query, keep_blank_values=True))
        qs.pop("channel_binding", None)
        new_url = urlunparse((
            scheme,
            u.netloc,
            u.path,
            u.params,
            urlencode(qs),
            u.fragment
        ))
        return new_url
    except Exception:
        return url

# --- Config ---
DATABASE_URL = _sanitize_db_url(os.getenv("DATABASE_URL", "sqlite:///./users.db"))
ADMIN_ID = os.getenv("ADMIN_ID", "rnj88")
ADMIN_PW = os.getenv("ADMIN_PW", "6548")

# --- DB setup ---
engine = create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {}
)
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)
Base = declarative_base()

class User(Base):
    __tablename__ = "users"
    id: Mapped[str] = mapped_column(String(64), primary_key=True)  # 로그인 아이디
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

class UserOut(BaseModel):
    id: str
    org: Optional[str] = None
    dept: Optional[str] = None
    start_date: Optional[dt.date] = None
    end_date: Optional[dt.date] = None
    role: str

app = FastAPI(title="AI 이의신청프로그램 Auth API (ryoryocompany v0.3.1)")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# create tables
Base.metadata.create_all(engine)

# seed or UPDATE admin (upsert behavior)
with SessionLocal() as db:
    u = db.get(User, ADMIN_ID)
    if not u:
        db.add(User(id=ADMIN_ID, password_hash=bcrypt.hash(ADMIN_PW), role="admin"))
    else:
        # always sync password with env for recovery
        u.password_hash = bcrypt.hash(ADMIN_PW)
    db.commit()

# --- Token store (demo) ---
TOKENS = {}

def make_token(uid: str) -> str:
    token = secrets.token_hex(16)
    TOKENS[token] = {"id": uid, "ts": dt.datetime.utcnow()}
    return token

def validate_token(x_auth: str = Header(..., alias="X-Auth"), db: Session = Depends(get_db)) -> User:
    info = TOKENS.get(x_auth)
    if not info:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="no token")
    u = db.get(User, info["id"])
    if not u:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="invalid token")
    return u

@app.get("/")
def health():
    return {"ok": True, "service": "ai-appeal-auth", "brand": "ryoryocompany", "version": "v0.3.1"}

@app.post("/auth/login")
def login(body: LoginIn, db: Session = Depends(get_db)):
    u = db.get(User, body.id)
    if not u:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="invalid credentials: user not found")
    if not bcrypt.verify(body.password, u.password_hash):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="invalid credentials: wrong password")
    return {"token": make_token(u.id), "role": u.role, "displayName": u.id}

@app.get("/users")
def list_users(current: User = Depends(validate_token), db: Session = Depends(get_db)) -> List[UserOut]:
    if current.role != "admin":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="forbidden")
    rows = db.query(User).all()
    return [UserOut(id=u.id, org=u.org, dept=u.dept, start_date=u.start_date, end_date=u.end_date, role=u.role) for u in rows]

@app.post("/users")
def create_user(body: UserIn, current: User = Depends(validate_token), db: Session = Depends(get_db)):
    if current.role != "admin":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="forbidden")
    if db.get(User, body.id):
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="exists")
    db.add(User(
        id=body.id,
        password_hash=bcrypt.hash(body.password or "1111"),
        org=body.org, dept=body.dept,
        start_date=body.start_date, end_date=body.end_date,
        role=body.role or "user"
    ))
    db.commit()
    return {"ok": True}

@app.put("/users/{uid}")
def update_user(uid: str, body: UserIn, current: User = Depends(validate_token), db: Session = Depends(get_db)):
    if current.role != "admin":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="forbidden")
    u = db.get(User, uid)
    if not u:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="not found")
    if body.password:
        u.password_hash = bcrypt.hash(body.password)
    for f in ["org", "dept", "start_date", "end_date", "role"]:
        v = getattr(body, f)
        if v is not None:
            setattr(u, f, v)
    db.commit()
    return {"ok": True}

@app.delete("/users/{uid}")
def delete_user(uid: str, current: User = Depends(validate_token), db: Session = Depends(get_db)):
    if current.role != "admin":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="forbidden")
    u = db.get(User, uid)
    if not u:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="not found")
    db.delete(u)
    db.commit()
    return {"ok": True}















