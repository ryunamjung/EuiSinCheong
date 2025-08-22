
# entry_fix.py — drop-in patch for FastAPI running on Render
# 사용법:
#   from entry_fix import attach_entry_routes
#   attach_entry_routes(app, target="/app")   # "/"와 "/login"을 "/app"으로 고정
#
# 결과:
#   - HEAD /           -> 200 OK (Render 헬스체크 405 방지)
#   - GET  /           -> 307 -> /app  (또는 target으로 변경)
#   - GET  /login      -> 307 -> /app  (또는 target으로 변경)
#   - GET  /healthz    -> {"ok":true}
#   - GET  /app        -> HTML 셸(임시): 나중에 당신의 실제 UI로 교체 가능

from fastapi import FastAPI
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse, Response

HTML_SHELL = """<!doctype html><html lang="ko"><head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>AI이의신청프로그램</title>
<style>body{margin:0;background:#0b1220;color:#e5f0ff;font-family:Segoe UI,Arial}
.wrap{max-width:880px;margin:40px auto;padding:0 16px}
.card{background:linear-gradient(145deg,#0f172a,#0b1220);border:1px solid #1c2b47;border-radius:14px;padding:18px}
a.btn{display:inline-block;padding:10px 14px;background:#22d3ee;color:#02242a;border-radius:10px;text-decoration:none;font-weight:700}
</style></head><body><div class="wrap">
<div class="card"><h2>AI이의신청프로그램</h2>
<p>서버가 정상 동작 중입니다. 이 페이지는 임시 셸입니다.</p>
<p>/app 경로에 실제 UI를 배치하거나, 리버스 프록시/템플릿으로 교체하세요.</p>
<p><a class="btn" href="/docs">Swagger 열기</a></p>
</div></div></body></html>"""

def attach_entry_routes(app: FastAPI, target: str = "/app") -> None:
    @app.head("/")
    async def _head_root():
        return Response(status_code=200)

    @app.get("/")
    async def _root():
        return RedirectResponse(url=target, status_code=307)

    @app.get("/login")
    async def _login_redirect():
        return RedirectResponse(url=target, status_code=307)

    @app.get("/healthz")
    async def _healthz():
        return JSONResponse({"ok": True})

    # 최소 HTML 셸 (원하면 제거하고 StaticFiles/Template로 교체)
    @app.get(target, response_class=HTMLResponse)
    async def _app_shell():
        return HTMLResponse(HTML_SHELL)


