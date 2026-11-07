from __future__ import annotations

import json

from app.models import Node

from .common import alpn_list, as_int, decode_b64, is_valid_path, normalize_fingerprint, split_uri

SECURITY_VALUES = {"auto", "aes-128-gcm", "chacha20-poly1305", "none", "zero"}


def parse(uri: str) -> Node | None:
    base, remark = split_uri(uri)
    payload = base[len("vmess://") :]
    text = decode_b64(payload)
    if not text:
        return None
    try:
        data = json.loads(text)
    except (json.JSONDecodeError, TypeError):
        return None
    if not isinstance(data, dict):
        return None

    host = str(data.get("add") or "").strip()
    if not host:
        return None
    port = as_int(data.get("port"), 0)
    if not (0 < port < 65536):
        return None
    uuid = str(data.get("id") or "").strip()
    if not uuid:
        return None

    network = str(data.get("net") or "tcp").lower()
    header_type = str(data.get("type") or "none").lower()
    if network == "h2":
        network = "http"
    if network not in ("tcp", "ws", "grpc", "http"):
        return None
    if network == "tcp" and header_type in ("http", "srtp", "wechat-video"):
        return None

    tls_mode = str(data.get("tls") or "").lower()
    security = "tls" if tls_mode in ("tls", "reality", "xtls") else "none"
    host_header = str(data.get("host") or "")
    sni = str(data.get("sni") or "") or host_header or host
    path = str(data.get("path") or "/")
    if not is_valid_path(path):
        return None
    service_name = path.strip("/") if network == "grpc" else ""

    cipher = str(data.get("scy") or "auto").lower()
    if cipher not in SECURITY_VALUES:
        cipher = "auto"

    params: dict[str, object] = {
        "network": network,
        "security": security,
        "sni": sni,
        "host": host_header,
        "path": path,
        "service_name": service_name,
        "fp": normalize_fingerprint(str(data.get("fp") or "")),
        "alpn": alpn_list(str(data.get("alpn") or "")),
        "insecure": bool(data.get("allowInsecure") or data.get("verify_cert") is False),
        "cipher": cipher,
        "alter_id": as_int(data.get("aid"), 0),
    }

    return Node(
        protocol="vmess",
        host=host,
        port=port,
        credential=uuid,
        params=params,
        uri=base,
        remark=remark or str(data.get("ps") or ""),
    )
