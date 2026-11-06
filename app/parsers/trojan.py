from __future__ import annotations

from urllib.parse import unquote

from app.models import Node

from .common import alpn_list, as_bool, normalize_fingerprint, query_dict, safe_urlparse, split_uri


def parse(uri: str) -> Node | None:
    base, remark = split_uri(uri)
    parsed = safe_urlparse(base)
    if parsed is None or parsed.scheme.lower() != "trojan":
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
    network = (q.get("type") or "tcp").lower()
    if network == "h2":
        network = "http"
    if network not in ("tcp", "ws", "grpc", "http", "httpupgrade"):
        return None
    security = (q.get("security") or "tls").lower()
    if security == "xtls":
        security = "tls"

    host_header = q.get("host") or ""
    sni = q.get("sni") or host_header or parsed.hostname
    path = q.get("path") or "/"
    service_name = q.get("serviceName") or q.get("service_name") or ""
    if network == "grpc" and not service_name:
        service_name = path.strip("/") or ""

    params: dict[str, object] = {
        "network": network,
        "security": security,
        "sni": sni,
        "host": host_header,
        "path": path,
        "service_name": service_name,
        "fp": normalize_fingerprint(q.get("fp")),
        "alpn": alpn_list(q.get("alpn")),
        "insecure": as_bool(q.get("allowInsecure") or q.get("insecure")),
    }

    return Node(
        protocol="trojan",
        host=parsed.hostname,
        port=port,
        credential=password,
        params=params,
        uri=base,
        remark=remark,
    )
