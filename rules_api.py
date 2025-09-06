# rules_api.py — FastAPI router for Rules management (separate RULES DB)
import os
import datetime as dt
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, Header, status
from pydantic import BaseModel
from sqlalchemy import create_engine, String, Integer, Boolean, DateTime, Text, Table, Column
from sqlalchemy.orm import registry, sessionmaker, Session
import jwt

# --- DB (separate engine) ---
RULES_DATABASE_URL = os.getenv("RULES_DATABASE_URL") or os.getenv("DATABASE_URL")
if not RULES_DATABASE_URL:
    raise RuntimeError("RULES_DATABASE_URL or DATABASE_URL must be set")

_rules_engine = create_engine(RULES_DATABASE_URL, pool_pre_ping=True)
RulesSessionLocal = sessionmaker(bind=_rules_engine, autoflush=False, autocommit=False)

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
    metadata.create_all(_rules_engine)

# --- JWT auth (minimal, align with your existing secret) ---
JWT_SECRET = os.getenv("JWT_SECRET", "change-me")
JWT_ALG = os.getenv("JWT_ALG", "HS256")

def _decode_token(authz: Optional[str] = Header(None)) -> dict:
    if not authz or not authz.lower().startswith("bearer "):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Missing Bearer token")
    token = authz.split(" ", 1)[1].strip()
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

# --- Schemas ---
class RuleOut(BaseModel):
    id: int
    title: str
    body: str
    tags: str = ""
    enabled: bool = True
    version: int = 1
    updated_at: dt.datetime

class Snapshot(BaseModel):
    ok: bool = True
    version: int
    updated_at: dt.datetime
    items: List[RuleOut]

# --- Router ---
router = APIRouter(prefix="/rules", tags=["rules"])

@router.get("/snapshot", response_model=Snapshot)
def rules_snapshot(_user=Depends(_decode_token), db: Session = Depends(get_db)):
    q = db.execute(rules_table.select().where(rules_table.c.enabled == True).order_by(rules_table.c.updated_at.desc()))
    rows = q.fetchall()
    items = [RuleOut(**dict(row._mapping)) for row in rows]
    last = rows[0]._mapping if rows else {"updated_at": dt.datetime(1970,1,1), "version": 1}
    version = int(last.get("version", 1))
    updated_at = last.get("updated_at") or dt.datetime(1970,1,1)
    return Snapshot(ok=True, version=version, updated_at=updated_at, items=items)

# Optional: simple admin endpoint to upsert a rule (protect with your own admin check)
class RuleIn(BaseModel):
    title: str
    body: str
    tags: str = ""
    enabled: bool = True
    version: int = 1

@router.post("", response_model=RuleOut, status_code=201)
def create_rule(rule: RuleIn, _user=Depends(_decode_token), db: Session = Depends(get_db)):
    # Here you can add your own admin/role check based on _user
    values = {
        "title": rule.title,
        "body": rule.body,
        "tags": rule.tags,
        "enabled": rule.enabled,
        "version": rule.version,
        "updated_at": dt.datetime.utcnow(),
    }
    res = db.execute(rules_table.insert().values(**values).returning(rules_table))
    db.commit()
    row = res.fetchone()._mapping
    return RuleOut(**dict(row))
