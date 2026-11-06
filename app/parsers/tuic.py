from __future__ import annotations

import uuid as uuid_module
from urllib.parse import unquote

from app.models import Node

from .common import alpn_list, as_bool, query_dict, safe_urlparse, split_uri


def parse(uri: str) -> Node | None:
    base, remark = split_uri(uri)
    parsed = safe_urlparse(base)
    if parsed is None or parsed.scheme.lower() != "tuic":
        return None
    if not parsed.hostname:
        return None
    try:
        port = parsed.port or 443
    except ValueError:
        return None
    if not (0 < port < 65536):
        return None

    uuid = unquote(parsed.username or "")
    password = unquote(parsed.password or "")
    if not uuid or not password:
        return None
    try:
        uuid_module.UUID(uuid)
    except ValueError:
        return None

    q = query_dict(parsed.query)
    congestion = (q.get("congestion_control") or "bbr").lower()
    if congestion not in ("bbr", "cubic", "new_reno"):
        congestion = "bbr"
    relay_mode = (q.get("udp_relay_mode") or "native").lower()
    if relay_mode not in ("native", "quic"):
        relay_mode = "native"

    params: dict[str, object] = {
        "security": "tls",
        "sni": q.get("sni") or parsed.hostname,
        "insecure": as_bool(q.get("allow_insecure") or q.get("insecure")),
        "alpn": alpn_list(q.get("alpn")) or ["h3"],
        "congestion_control": congestion,
        "udp_relay_mode": relay_mode,
        "disable_sni": as_bool(q.get("disable_sni")),
    }
    return Node(
        protocol="tuic",
        host=parsed.hostname,
        port=port,
        credential=f"{uuid}:{password}",
        params=params,
        uri=base,
        remark=remark,
    )
