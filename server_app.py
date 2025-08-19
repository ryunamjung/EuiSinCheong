# server_app.py
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

app = FastAPI(title="EuiSinChung API")

# CORS (필요 시 도메인 허용)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/status")
def status():
    return {"ok": True}

# ---- 데모 로그인 엔드포인트 (관리자 고정) ----
class LoginIn(BaseModel):
    username: str
    password: str
    force: bool = True

@app.post("/auth/start_session")
def start_session(body: LoginIn):
    if body.username == "rnj88" and body.password == "6548":
        # 실제 구현에선 JWT 발급/DB 조회
        return {"token": "demo-token-123", "ok": True}
    raise HTTPException(status_code=401, detail="invalid credentials")


