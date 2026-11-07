from __future__ import annotations

import io
import json
import logging
import time
from contextlib import asynccontextmanager

import qrcode
import qrcode.image.svg
from fastapi import FastAPI, Request, Response
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse

from app.checker import Checker
from app.config import Settings, get_settings
from app.render import (
    node_display_name,
    render_base64,
    subscription_headers,
    subscription_info,
)
from app.scheduler import Aggregator
from app.security import RateLimiter, token_matches
from app.singbox import build_subscription_config
from app.store import Store
from app.xray import build_xray_config

log = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    settings = get_settings()
    logging.basicConfig(
        level=getattr(logging, settings.log_level.upper(), logging.INFO),
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("httpcore").setLevel(logging.WARNING)
    for secret_name in settings.placeholder_secrets:
        log.warning("%s still has a placeholder value", secret_name)

    store = Store(settings.data_dir)
    checker = Checker(settings)
    aggregator = Aggregator(settings, store, checker)

    app.state.settings = settings
    app.state.store = store
    app.state.checker = checker
    app.state.aggregator = aggregator
    app.state.limiter = RateLimiter(settings.rate_limit_per_min)

    await aggregator.start()
    log.info("Service started: %d cached live nodes", len(store.live))
    try:
        yield
    finally:
        await aggregator.stop()


app = FastAPI(
    title="my-vpn aggregator",
    docs_url=None,
    redoc_url=None,
    openapi_url=None,
    lifespan=lifespan,
)


# --------------------------------------------------------------------------- helpers


def _settings(request: Request) -> Settings:
    return request.app.state.settings


def _client_ip(request: Request) -> str:
    if _settings(request).trust_forwarded_for:
        forwarded = request.headers.get("x-forwarded-for", "")
        if forwarded:
            # Caddy appends the real peer address last; use it to avoid spoofing.
            return forwarded.split(",")[-1].strip()
    return request.client.host if request.client else "unknown"


def _validate_sub_token(request: Request, token: str) -> bool:
    return token_matches(_settings(request).sub_token, token)


def _validate_admin(request: Request) -> bool:
    header = request.headers.get("authorization", "")
    if not header.lower().startswith("bearer "):
        return False
    return token_matches(_settings(request).admin_token, header[7:].strip())


def _no_nodes_response() -> JSONResponse:
    return JSONResponse(
        {"detail": "No live nodes yet, retry later"},
        status_code=503,
        headers={"Retry-After": "60"},
    )


def _base_url(request: Request) -> str:
    return str(request.base_url).rstrip("/")


# --------------------------------------------------------------------------- middleware


@app.middleware("http")
async def rate_limit(request: Request, call_next):
    path = request.url.path
    if path.startswith(("/sub/", "/p/", "/qr/")):
        limiter: RateLimiter | None = getattr(request.app.state, "limiter", None)
        if limiter is not None and not limiter.allow(_client_ip(request)):
            return JSONResponse({"detail": "Too many requests"}, status_code=429)
    return await call_next(request)


# --------------------------------------------------------------------------- basic


@app.get("/healthz")
async def healthz() -> dict:
    return {"status": "ok", "ts": int(time.time())}


@app.get("/readyz")
async def readyz(request: Request):
    store: Store = request.app.state.store
    settings: Settings = _settings(request)
    if len(store.live) >= settings.min_live_for_ready:
        return {"status": "ready", "live": len(store.live)}
    return JSONResponse(
        {"status": "not-ready", "live": len(store.live)},
        status_code=503,
    )


@app.get("/robots.txt", response_class=PlainTextResponse)
async def robots() -> str:
    return "User-agent: *\nDisallow: /\n"


@app.get("/", response_class=HTMLResponse)
async def index(request: Request) -> str:
    store: Store = request.app.state.store
    settings = _settings(request)
    return f"""<!doctype html>
<html lang="ru"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{settings.profile_title}</title>
<style>body{{font-family:system-ui,sans-serif;max-width:640px;margin:40px auto;padding:0 16px;line-height:1.5}}
code{{background:#f2f2f2;padding:2px 6px;border-radius:4px}}</style></head>
<body>
<h1>{settings.profile_title}</h1>
<p>Сервис работает. Живых нод в кэше: <b>{len(store.live)}</b>.</p>
<p>Ссылка подписки содержит секретный токен и не отображается на этой странице.</p>
<p>Откройте <code>/p/&lt;SUB_TOKEN&gt;</code>, чтобы увидеть ссылку и QR-код.</p>
</body></html>"""


# --------------------------------------------------------------------------- subscriptions


@app.get("/sub/{token}")
async def subscription_base64(request: Request, token: str) -> Response:
    if not _validate_sub_token(request, token):
        return JSONResponse({"detail": "Forbidden"}, status_code=403)
    store: Store = request.app.state.store
    settings = _settings(request)
    live = store.top(settings.nodes_in_sub, settings.max_nodes_per_subnet)
    if not live:
        return _no_nodes_response()

    body = render_base64(live)
    headers = subscription_headers(settings, "text/plain; charset=utf-8")
    return Response(content=body, headers=headers, media_type=None)


@app.get("/sub/{token}/singbox")
async def subscription_singbox(request: Request, token: str) -> Response:
    if not _validate_sub_token(request, token):
        return JSONResponse({"detail": "Forbidden"}, status_code=403)
    store: Store = request.app.state.store
    settings = _settings(request)
    live = store.top(settings.nodes_in_sub, settings.max_nodes_per_subnet)
    if not live:
        return _no_nodes_response()

    config = build_subscription_config([item.node for item in live])
    if config is None:
        return _no_nodes_response()
    headers = subscription_headers(settings, "application/json; charset=utf-8")
    headers["Content-Disposition"] = 'attachment; filename="singbox.json"'
    return Response(content=json.dumps(config, ensure_ascii=False, indent=2), headers=headers, media_type=None)


@app.get("/sub/{token}/xray")
async def subscription_xray(request: Request, token: str) -> Response:
    if not _validate_sub_token(request, token):
        return JSONResponse({"detail": "Forbidden"}, status_code=403)
    store: Store = request.app.state.store
    settings = _settings(request)
    live = store.top(settings.nodes_in_sub, settings.max_nodes_per_subnet)
    if not live:
        return _no_nodes_response()

    config = build_xray_config([item.node for item in live])
    if config is None:
        return _no_nodes_response()
    headers = subscription_headers(settings, "application/json; charset=utf-8")
    headers["Content-Disposition"] = 'attachment; filename="xray.json"'
    return Response(content=json.dumps(config, ensure_ascii=False, indent=2), headers=headers, media_type=None)


@app.get("/sub/{token}/info")
async def subscription_meta(request: Request, token: str) -> JSONResponse:
    if not _validate_sub_token(request, token):
        return JSONResponse({"detail": "Forbidden"}, status_code=403)
    store: Store = request.app.state.store
    settings = _settings(request)
    live = store.top(settings.nodes_in_sub, settings.max_nodes_per_subnet)
    base = _base_url(request)
    data = subscription_info(live, settings)
    data["endpoints"] = {
        "base64": f"{base}/sub/{token}",
        "singbox": f"{base}/sub/{token}/singbox",
        "xray": f"{base}/sub/{token}/xray",
    }
    return JSONResponse(data)


# --------------------------------------------------------------------------- personal page / qr


@app.get("/p/{token}", response_class=HTMLResponse)
async def personal_page(request: Request, token: str) -> Response:
    if not _validate_sub_token(request, token):
        return HTMLResponse("<h1>403</h1>", status_code=403)
    store: Store = request.app.state.store
    settings = _settings(request)
    live = store.top(settings.nodes_in_sub, settings.max_nodes_per_subnet)
    base = _base_url(request)
    sub_url = f"{base}/sub/{token}"

    rows = "".join(
        f"<tr><td>{node_display_name(index, item)}</td><td>{item.latency_ms} ms</td>"
        f"<td>{item.node.protocol}</td></tr>"
        for index, item in enumerate(live, start=1)
    )
    updated = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(store.updated_at)) if store.updated_at else "—"
    return HTMLResponse(
        f"""<!doctype html>
<html lang="ru"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{settings.profile_title}</title>
<style>
body{{font-family:system-ui,sans-serif;max-width:760px;margin:32px auto;padding:0 16px;line-height:1.5}}
code{{background:#f2f2f2;padding:2px 6px;border-radius:4px;word-break:break-all}}
table{{border-collapse:collapse;width:100%;margin-top:12px}}
td,th{{border-bottom:1px solid #eee;padding:6px 8px;text-align:left;font-size:14px}}
.muted{{color:#666}}
</style></head>
<body>
<h1>{settings.profile_title}</h1>
<p>Живых нод: <b>{len(live)}</b>. Обновлено: {updated}</p>
<p>Ссылка подписки:<br><code>{sub_url}</code></p>
<p><img src="{base}/qr/{token}.svg" alt="QR" width="220" height="220"></p>
<ul>
<li><b>Hiddify / sing-box</b> (автопереключение): <code>{sub_url}/singbox</code></li>
<li>v2rayNG / Streisand (список): <code>{sub_url}</code></li>
<li>Xray JSON: <code>{sub_url}/xray</code></li>
</ul>
<table><thead><tr><th>Нода</th><th>Пинг</th><th>Протокол</th></tr></thead>
<tbody>{rows or '<tr><td colspan="3">Пока нет проверенных нод</td></tr>'}</tbody></table>
<p class="muted">Публичные ноды небезопасны для банкинга и приватных ключей. Для чувствительных задач используйте свою ноду.</p>
</body></html>"""
    )


@app.get("/qr/{token}.svg")
async def qr(request: Request, token: str) -> Response:
    if not _validate_sub_token(request, token):
        return JSONResponse({"detail": "Forbidden"}, status_code=403)
    url = f"{_base_url(request)}/sub/{token}"
    image = qrcode.make(url, image_factory=qrcode.image.svg.SvgPathImage)
    buffer = io.BytesIO()
    image.save(buffer)
    return Response(content=buffer.getvalue(), media_type="image/svg+xml")


# --------------------------------------------------------------------------- admin


@app.get("/admin/status")
async def admin_status(request: Request) -> JSONResponse:
    if not _validate_admin(request):
        return JSONResponse({"detail": "Unauthorized"}, status_code=401)
    store: Store = request.app.state.store
    aggregator: Aggregator = request.app.state.aggregator
    live = [
        {
            "name": node_display_name(index, item),
            "protocol": item.node.protocol,
            "host": item.node.host,
            "port": item.node.port,
            "latency_ms": item.latency_ms,
            "score": item.score,
        }
        for index, item in enumerate(store.live[:20], start=1)
    ]
    return JSONResponse(
        {
            "stats": aggregator.stats,
            "live_count": len(store.live),
            "updated_at": store.updated_at,
            "top": live,
        }
    )


@app.post("/admin/refresh")
async def admin_refresh(request: Request) -> JSONResponse:
    if not _validate_admin(request):
        return JSONResponse({"detail": "Unauthorized"}, status_code=401)
    aggregator: Aggregator = request.app.state.aggregator
    aggregator.request_refresh()
    return JSONResponse({"status": "scheduled"})
