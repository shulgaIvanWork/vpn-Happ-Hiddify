from __future__ import annotations

import base64
import json
from typing import Any

from app.config import Settings
from app.models import LiveNode, Node
from app.parsers.common import decode_b64


def node_display_name(index: int, live: LiveNode) -> str:
    latency = int(live.latency_ms)
    return f"{index:02d} · ⚡{latency}ms · {live.node.protocol}"


def display_uri(node: Node, name: str) -> str:
    """Attach a fresh remark to a stored URI (rebuilds vmess JSON safely)."""
    if node.protocol == "vmess":
        payload = node.uri[len("vmess://") :]
        text = decode_b64(payload)
        try:
            data = json.loads(text)
        except (json.JSONDecodeError, TypeError):
            return node.uri
        if isinstance(data, dict):
            data["ps"] = name
            encoded = base64.b64encode(
                json.dumps(data, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
            ).decode("ascii")
            return f"vmess://{encoded}"
        return node.uri

    base = node.uri.split("#", 1)[0]
    from urllib.parse import quote

    return f"{base}#{quote(name, safe='')}"


def render_base64(live_nodes: list[LiveNode]) -> str:
    lines: list[str] = []
    for index, live in enumerate(live_nodes, start=1):
        name = node_display_name(index, live)
        lines.append(display_uri(live.node, name))
    body = "\n".join(lines)
    return base64.b64encode(body.encode("utf-8")).decode("ascii")


def subscription_headers(settings: Settings, content_type: str) -> dict[str, str]:
    title = base64.b64encode(settings.profile_title.encode("utf-8")).decode("ascii")
    headers = {
        "Profile-Title": f"base64:{title}",
        "Profile-Update-Interval": "1",
        "Subscription-Userinfo": (
            f"upload=0; download=0; total={settings.total_bytes}; expire={settings.expire_unix}"
        ),
        "Support-Url": settings.support_url,
        "Content-Type": content_type,
        "Cache-Control": "no-store",
        "Content-Disposition": 'attachment; filename="subscription.txt"',
    }
    if settings.web_page_url:
        headers["Profile-Web-Page-Url"] = settings.web_page_url
    return headers


def subscription_info(live_nodes: list[LiveNode], settings: Settings) -> dict[str, Any]:
    return {
        "title": settings.profile_title,
        "nodes": len(live_nodes),
        "updated_at": max((live.checked_at for live in live_nodes), default=0),
        "top": [
            {
                "name": node_display_name(index, live),
                "protocol": live.node.protocol,
                "host": live.node.host,
                "latency_ms": live.latency_ms,
                "score": round(live.score, 1),
            }
            for index, live in enumerate(live_nodes[:10], start=1)
        ],
    }
