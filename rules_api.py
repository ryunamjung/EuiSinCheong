# rules_api.py (final) — Rules DB (separate) + snapshot + admin CRUD
import os
import datetime as dt
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, Header, status
from pydantic import BaseModel
from sqlalchemy import create_engine, String, Integer, Boolean, DateTime, Text, Table, Column, select, desc
from sqlalchemy.orm import registry, sessionmaker, Session
import jwt  # PyJWT

# ------------------------- DB -------------------------
RULES_DATABASE_URL = os.getenv("RULES_DATABASE_URL") or os.getenv("DATABASE_URL")
if not RULES_DATABASE_URL:
    raise RuntimeError("RULES_DATABASE_URL or DATABASE_URL must be set")

_engine = create_engine(RULES_DATABASE_URL, pool_pre_ping=True, future=True)
RulesSessionLocal = sessionmaker(bind=_engine, autoflush=False, autocommit=False, future=True)

mapper_registry = registry()
metadata = mapper_registry.metadata

rules_table = Table(
    "rules",
    metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("title", String(200), nullable=False),
    Column("body", Text, nullable=False),
    Column("tags", String(400), default=""),
    Column("enabled", Boolean, default=True, nullable=False),
    Column("version", Integer, default=1, nullable=False),
    Column("updated_at", DateTime, default=dt.datetime.utcnow, onupdate=dt.datetime.utcnow, nullable=False),
)

def init_rules_db():
    metadata.create_all(_engine)

# ------------------------- Auth -------------------------
JWT_SECRET = os.getenv("JWT_SECRET", "change-me")
JWT_ALG = os.getenv("JWT_ALG", "HS256")

def _decode_token(authorization: Optional[str] = Header(None)) -> dict:
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Missing Bearer token")
    token = authorization.split(" ", 1)[1].strip()
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALG])
        return payload
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=f"Invalid token: {e}")

def get_db():
    db = RulesSessionLocal()
    try:
        yield db
    finally:
        db.close()

def _require_admin(payload: dict):
    if (payload.get("role", "") or "").lower() != "admin":
        raise HTTPException(status_code=403, detail="admin only")

# ------------------------- Schemas -------------------------
class RuleBase(BaseModel):
    title: str
    body: str
    tags: str = ""
    enabled: bool = True
    version: int = 1

class RuleIn(RuleBase):
    pass

class RulePatch(BaseModel):
    title: Optional[str] = None
    body: Optional[str] = None
    tags: Optional[str] = None
    enabled: Optional[bool] = None
    version: Optional[int] = None

class RuleOut(RuleBase):
    id: int
    updated_at: dt.datetime

class Snapshot(BaseModel):
    ok: bool = True
    version: int
    updated_at: dt.datetime
    items: List[RuleOut]

# ------------------------- Router -------------------------
router = APIRouter(prefix="/rules", tags=["rules"])

@router.get("/snapshot", response_model=Snapshot)
def rules_snapshot(_user=Depends(_decode_token), db: Session = Depends(get_db)):
    rows = db.execute(
        select(rules_table).where(rules_table.c.enabled == True).order_by(desc(rules_table.c.updated_at))
    ).fetchall()
    items = [RuleOut(**dict(r._mapping)) for r in rows]
    if items:
        latest = items[0]
        version = latest.version or 1
        updated_at = latest.updated_at
    else:
        version = 1
        updated_at = dt.datetime(1970,1,1)
    return Snapshot(ok=True, version=version, updated_at=updated_at, items=items)

# -------- Admin CRUD (requires role=admin) --------
@router.get("", response_model=List[RuleOut])
def list_rules(_user=Depends(_decode_token), db: Session = Depends(get_db)):
    _require_admin(_user)
    rows = db.execute(select(rules_table).order_by(desc(rules_table.c.updated_at))).fetchall()
    return [RuleOut(**dict(r._mapping)) for r in rows]

@router.post("", response_model=RuleOut, status_code=201)
def create_rule(rule: RuleIn, _user=Depends(_decode_token), db: Session = Depends(get_db)):
    _require_admin(_user)
    values = {
        "title": rule.title,
        "body": rule.body,
        "tags": rule.tags,
        "enabled": rule.enabled,
        "version": rule.version,
        "updated_at": dt.datetime.utcnow(),
    }
    row = db.execute(rules_table.insert().values(**values).returning(rules_table)).fetchone()
    db.commit()
    return RuleOut(**dict(row._mapping))

@router.patch("/{rid}", response_model=RuleOut)
def update_rule(rid: int, patch: RulePatch, _user=Depends(_decode_token), db: Session = Depends(get_db)):
    _require_admin(_user)
    current = db.execute(select(rules_table).where(rules_table.c.id == rid)).first()
    if not current:
        raise HTTPException(404, "not found")
    values = {}
    for k in ["title","body","tags","enabled","version"]:
        v = getattr(patch, k, None)
        if v is not None:
            values[k] = v
    values["updated_at"] = dt.datetime.utcnow()
    row = db.execute(rules_table.update().where(rules_table.c.id==rid).values(**values).returning(rules_table)).fetchone()
    db.commit()
    return RuleOut(**dict(row._mapping))

@router.delete("/{rid}")
def delete_rule(rid: int, _user=Depends(_decode_token), db: Session = Depends(get_db)):
    _require_admin(_user)
    res = db.execute(rules_table.delete().where(rules_table.c.id == rid))
    if res.rowcount == 0:
        raise HTTPException(404, "not found")
    db.commit()
    return {"ok": True}
