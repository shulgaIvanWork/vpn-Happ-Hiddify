from __future__ import annotations

from urllib.parse import unquote

from app.models import Node

from .common import alpn_list, as_bool, query_dict, safe_urlparse, split_uri


def parse(uri: str) -> Node | None:
    base, remark = split_uri(uri)
    parsed = safe_urlparse(base)
    if parsed is None or parsed.scheme.lower() not in ("hysteria2", "hy2"):
        return None
    if not parsed.hostname:
        return None
    try:
        port = parsed.port or 443
    except ValueError:
        return None
    if not (0 < port < 65536):
        return None

    password = unquote(parsed.username or "")
    if parsed.password:
        password = f"{password}:{unquote(parsed.password)}"
    if not password:
        return None

    q = query_dict(parsed.query)
    obfs_type = (q.get("obfs") or "").lower()
    if obfs_type and obfs_type != "salamander":
        return None
    obfs_password = q.get("obfs-password") or q.get("obfs_password") or ""
    if obfs_type and not obfs_password:
        return None

    params: dict[str, object] = {
        "security": "tls",
        "sni": q.get("sni") or parsed.hostname,
        "insecure": as_bool(q.get("insecure") or q.get("allowInsecure")),
        "alpn": alpn_list(q.get("alpn")) or ["h3"],
        "obfs": obfs_type,
        "obfs_password": obfs_password,
        "pin_sha256": q.get("pinSHA256") or "",
    }

    return Node(
        protocol="hysteria2",
        host=parsed.hostname,
        port=port,
        credential=password,
        params=params,
        uri=base,
        remark=remark,
    )
