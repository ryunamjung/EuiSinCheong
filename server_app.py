# server_app.py
import os
import secrets
from datetime import datetime, timedelta, timezone
from typing import Optional, List

from fastapi import FastAPI, HTTPException, Depends, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from sqlalchemy import (
    create_engine, Column, String, Boolean, DateTime, Text, ForeignKey, func, text, select
)
from sqlalchemy.orm import declarative_base, sessionmaker, Session as OrmSession, relationship
from passlib.context import CryptContext
import jwt  # PyJWT

# ------------------------------------------------------------------------------
# 환경
# ------------------------------------------------------------------------------
DATABASE_URL        = os.getenv("DATABASE_URL", "postgresql+psycopg2://user:pass@localhost:5432/db")
RULES_DATABASE_URL  = os.getenv("RULES_DATABASE_URL", "postgresql://ai_appeal_db_user:tQNCd98GrICo1F3Y4S7Stgqo8rKakzsx@dpg-d2tousvfte5s73af5g4g-a/ai_appeal_db")  # 규정 DB(실제 사용은 rules_api.py에서 함)
JWT_SECRET          = os.getenv("JWT_SECRET", "change-me")
JWT_ALG             = os.getenv("JWT_ALG", "HS256")
SESSION_TTL_HOURS   = int(os.getenv("SESSION_TTL_HOURS", "12"))
ADMIN_BOOTSTRAP_ID  = os.getenv("ADMIN_BOOTSTRAP_ID", "")
ADMIN_BOOTSTRAP_PASSWORD = os.getenv("ADMIN_BOOTSTRAP_PASSWORD", "")

engine = create_engine(DATABASE_URL, pool_pre_ping=True, future=True)
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False, future=True)
Base = declarative_base()
pwd_ctx = CryptContext(schemes=["bcrypt"], deprecated="auto")

# ------------------------------------------------------------------------------
# 모델
# ------------------------------------------------------------------------------
class User(Base):
    __tablename__ = "users"
    id            = Column(String(64), primary_key=True)           # ex) rnj88
    username      = Column(String(64), unique=True, index=True, nullable=False)
    password_hash = Column(String(255), nullable=False)
    org           = Column(String(128), nullable=True)             # 회사/기관
    dept          = Column(String(128), nullable=True)             # 부서
    role          = Column(String(32),  nullable=False, default="user")
    active        = Column(Boolean,     nullable=False, server_default=text("true"))
    start_date    = Column(DateTime(timezone=True), nullable=True)
    end_date      = Column(DateTime(timezone=True), nullable=True)
    created_at    = Column(DateTime(timezone=True), server_default=func.now())

    sessions      = relationship("Session", back_populates="user", cascade="all,delete")


class Session(Base):
    __tablename__ = "sessions"
    # 문자열 PK
    id         = Column(String(64), primary_key=True)                         # secrets.token_hex(16)
    token      = Column(Text, nullable=False, unique=True, index=True)        # 발급한 JWT 저장
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    revoked    = Column(Boolean, nullable=False, server_default=text("false"))
    expires_at = Column(DateTime(timezone=True), nullable=False,
                        server_default=text("(now() + '12:00:00'::interval)"))
    user_id    = Column(String(64), ForeignKey("users.id", ondelete="CASCADE"), index=True, nullable=False)

    user       = relationship("User", back_populates="sessions")

# ------------------------------------------------------------------------------
# 스키마
# ------------------------------------------------------------------------------
class LoginIn(BaseModel):
    id: str
    password: str

class LoginOut(BaseModel):
    ok: bool
    id: str
    username: Optional[str] = None
    role: str
    org: Optional[str] = None
    token: str

class MeOut(BaseModel):
    ok: bool
    id: str
    username: Optional[str]
    role: str
    org: Optional[str]

class UserIn(BaseModel):
    id: str
    username: str
    password: Optional[str] = None
    org: Optional[str] = None
    dept: Optional[str] = None
    role: str = "user"
    active: bool = True
    start_date: Optional[datetime] = None
    end_date: Optional[datetime] = None

class UserOut(BaseModel):
    id: str
    username: str
    org: Optional[str]
    dept: Optional[str]
    role: str
    active: bool
    created_at: Optional[datetime]

# ------------------------------------------------------------------------------
# FastAPI
# ------------------------------------------------------------------------------
app = FastAPI(title="AI Appeal Auth API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], allow_credentials=True,
    allow_methods=["*"], allow_headers=["*"]
)

# 규정 API(별도 DB): rules_api.py 를 같은 폴더에 두고 사용
from rules_api import router as rules_router, init_rules_db  # 파일명이 다르면 여기만 맞추세요.
init_rules_db()
app.include_router(rules_router)

def db_dep():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# ------------------------------------------------------------------------------
# 유틸
# ------------------------------------------------------------------------------
def make_token(uid: str, role: str, sid: str, exp: datetime) -> str:
    payload = {"sub": uid, "role": role, "sid": sid, "exp": exp}
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALG)

def parse_auth(request: Request) -> str:
    h = request.headers.get("authorization") or request.headers.get("Authorization") or ""
    if not h.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="missing bearer")
    return h.split()[1]

def verify_token_and_session(db: OrmSession, token: str):
    try:
        data = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALG])
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="token expired")
    except Exception:
        raise HTTPException(status_code=401, detail="invalid token")

    uid = data.get("sub")
    sid = data.get("sid")
    if not uid or not sid:
        raise HTTPException(status_code=401, detail="invalid token payload")

    sess = db.query(Session).filter(
        Session.id == sid,
        Session.user_id == uid,
        Session.revoked == False
    ).first()
    if not sess:
        raise HTTPException(status_code=401, detail="revoked or not found")

    if sess.expires_at <= datetime.now(timezone.utc):
        raise HTTPException(status_code=401, detail="session expired")

    user = db.get(User, uid)
    if not user or not user.active:
        raise HTTPException(status_code=401, detail="user disabled")

    return user, data, sess

# ------------------------------------------------------------------------------
# 라우트
# ------------------------------------------------------------------------------
@app.get("/")
def ping():
    return {
        "ok": True,
        "service": "auth+rules",
        "rules_db": bool(RULES_DATABASE_URL)
    }

@app.post("/auth/login", response_model=LoginOut)
def login(body: LoginIn, db: OrmSession = Depends(db_dep)):
    uid = (body.id or "").strip()
    pw  = body.password or ""

    user = db.query(User).filter(User.id == uid).first()
    if not user or not user.active or not pwd_ctx.verify(pw, user.password_hash):
        raise HTTPException(status_code=401, detail="invalid id or password")

    # 동시 로그인 1개: 기존 세션 revoke
    db.query(Session).filter(Session.user_id == uid, Session.revoked == False)\
        .update({"revoked": True})

    sid = secrets.token_hex(16)  # 문자열
    exp = datetime.now(timezone.utc) + timedelta(hours=SESSION_TTL_HOURS)
    token = make_token(user.id, user.role, sid, exp)

    db.add(Session(
        id=sid,
        user_id=user.id,
        token=token,           # NOT NULL, DB 저장
        expires_at=exp,
        revoked=False
    ))
    db.commit()

    return LoginOut(ok=True, id=user.id, username=user.username, role=user.role, org=user.org, token=token)

@app.get("/auth/me", response_model=MeOut)
def me(request: Request, db: OrmSession = Depends(db_dep)):
    token = parse_auth(request)
    user, _, _ = verify_token_and_session(db, token)
    return MeOut(ok=True, id=user.id, username=user.username, role=user.role, org=user.org)

@app.post("/auth/logout")
def logout(request: Request, db: OrmSession = Depends(db_dep)):
    token = parse_auth(request)
    _, _, sess = verify_token_and_session(db, token)
    sess.revoked = True
    db.commit()
    return {"ok": True}

# -------------------------- Admin -------------------------------
def ensure_admin(user: User):
    if (user.role or "").lower() != "admin":
        raise HTTPException(status_code=403, detail="admin only")

@app.get("/admin/users", response_model=List[UserOut])
def admin_list_users(request: Request, db: OrmSession = Depends(db_dep)):
    token = parse_auth(request)
    user, _, _ = verify_token_and_session(db, token)
    ensure_admin(user)
    rows = db.query(User).order_by(User.created_at.desc()).all()
    return [UserOut(
        id=r.id, username=r.username, org=r.org, dept=r.dept,
        role=r.role, active=bool(r.active), created_at=r.created_at
    ) for r in rows]

@app.post("/admin/users", response_model=UserOut)
def admin_create_user(body: UserIn, request: Request, db: OrmSession = Depends(db_dep)):
    token = parse_auth(request)
    user, _, _ = verify_token_and_session(db, token)
    ensure_admin(user)

    if db.get(User, body.id):
        raise HTTPException(409, detail="id exists")

    pw_hash = pwd_ctx.hash(body.password or "6548")
    row = User(
        id=body.id, username=body.username, password_hash=pw_hash,
        org=body.org, dept=body.dept, role=body.role, active=body.active,
        start_date=body.start_date, end_date=body.end_date
    )
    db.add(row); db.commit()
    return UserOut(
        id=row.id, username=row.username, org=row.org, dept=row.dept,
        role=row.role, active=row.active, created_at=row.created_at
    )

@app.put("/admin/users/{uid}", response_model=UserOut)
def admin_update_user(uid: str, body: UserIn, request: Request, db: OrmSession = Depends(db_dep)):
    token = parse_auth(request)
    user, _, _ = verify_token_and_session(db, token)
    ensure_admin(user)

    row = db.get(User, uid)
    if not row:
        raise HTTPException(404, detail="not found")

    row.username = body.username or row.username
    row.org = body.org
    row.dept = body.dept
    row.role = body.role or row.role
    row.active = body.active
    row.start_date = body.start_date
    row.end_date = body.end_date
    if body.password:
        row.password_hash = pwd_ctx.hash(body.password)
    db.commit()
    return UserOut(
        id=row.id, username=row.username, org=row.org, dept=row.dept,
        role=row.role, active=row.active, created_at=row.created_at
    )

@app.delete("/admin/users/{uid}")
def admin_delete_user(uid: str, request: Request, db: OrmSession = Depends(db_dep)):
    token = parse_auth(request)
    user, _, _ = verify_token_and_session(db, token)
    ensure_admin(user)

    row = db.get(User, uid)
    if not row:
        raise HTTPException(404, detail="not found")
    db.delete(row); db.commit()
    return {"ok": True}

# ------------------------------------------------------------------------------
# 시작 시 테이블 생성 + 최초 관리자 부트스트랩(옵션)
# ------------------------------------------------------------------------------
@app.on_event("startup")
def on_startup():
    # 기본 테이블 생성
    Base.metadata.create_all(bind=engine)

    # --- 최초 관리자 1회 생성(환경변수로 제어) ---
    if ADMIN_BOOTSTRAP_ID and ADMIN_BOOTSTRAP_PASSWORD:
        with SessionLocal() as db:
            exists = db.execute(select(User).where(User.id == ADMIN_BOOTSTRAP_ID)).scalar_one_or_none()
            if not exists:
                row = User(
                    id=ADMIN_BOOTSTRAP_ID,
                    username=ADMIN_BOOTSTRAP_ID,
                    password_hash=pwd_ctx.hash(ADMIN_BOOTSTRAP_PASSWORD),
                    org="",
                    dept="",
                    role="admin",
                    active=True,
                )
                db.add(row)
                db.commit()




























