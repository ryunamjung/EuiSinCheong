# server_app.py
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from starlette.responses import RedirectResponse, Response

app = FastAPI(title="EuiSinChung API")

# CORS (필요 시 도메인 제한)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# 1) 루트: /docs로 리다이렉트 (404 방지)
@app.get("/", include_in_schema=False)
def root():
    return RedirectResponse(url="/docs", status_code=307)

# 2) 파비콘: 빈 응답(204)로 404 방지
@app.get("/favicon.ico", include_in_schema=False)
def favicon():
    return Response(status_code=204)

# 3) 헬스체크
@app.get("/status")
def status():
    return {"ok": True}

# 4) 데모 로그인(관리자 고정) — 실제 구현으로 교체 가능
class LoginIn(BaseModel):
    username: str
    password: str
    force: bool = True

@app.post("/auth/start_session")
def start_session(body: LoginIn):
    if body.username == "rnj88" and body.password == "6548":
        return {"token": "demo-token-123", "ok": True}
    raise HTTPException(status_code=401, detail="invalid credentials")




