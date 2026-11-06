from __future__ import annotations

from urllib.parse import unquote

from app.models import Node

from .common import (
    alpn_list,
    as_bool,
    as_int,
    b64_decoded_len,
    clean_remark,
    is_hex,
    normalize_fingerprint,
    query_dict,
    safe_urlparse,
    split_uri,
)

SUPPORTED_NETWORKS = {"tcp", "ws", "grpc", "http", "httpupgrade"}
SUPPORTED_SECURITY = {"none", "tls", "reality"}


def parse(uri: str) -> Node | None:
    base, remark = split_uri(uri)
    parsed = safe_urlparse(base)
    if parsed is None or parsed.scheme.lower() != "vless":
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
    if not uuid:
        return None

    q = query_dict(parsed.query)
    network = (q.get("type") or "tcp").lower()
    security = (q.get("security") or "none").lower()
    header_type = (q.get("headerType") or "none").lower()

    if security == "xtls":
        security = "tls"
    if network == "h2":
        network = "http"
    if network in ("xhttp", "splithttp", "kcp", "mkcp", "quic"):
        return None
    if network not in SUPPORTED_NETWORKS:
        return None
    if network == "tcp" and header_type == "http":
        # Xray TCP obfuscation is not supported by sing-box.
        return None
    if security not in SUPPORTED_SECURITY:
        return None
    if security == "reality":
        public_key = q.get("pbk") or ""
        if b64_decoded_len(public_key) != 32:
            return None
    flow = q.get("flow") or ""
    if flow and (flow != "xtls-rprx-vision" or security == "none" or network != "tcp"):
        flow = ""

    host_header = q.get("host") or ""
    sni = q.get("sni") or host_header or parsed.hostname
    path = q.get("path") or "/"
    service_name = q.get("serviceName") or q.get("service_name") or ""
    if network == "grpc" and not service_name:
        service_name = path.strip("/") or ""

    short_id = q.get("sid") or ""
    if short_id and (len(short_id) > 16 or len(short_id) % 2 or not is_hex(short_id)):
        short_id = ""

    packet_encoding = q.get("packetEncoding") or q.get("packet_encoding") or ""
    if packet_encoding not in ("packetaddr", "xudp"):
        packet_encoding = ""

    params: dict[str, object] = {
        "network": network,
        "security": security,
        "sni": sni,
        "host": host_header,
        "path": path,
        "service_name": service_name,
        "fp": normalize_fingerprint(q.get("fp"))
        or ("chrome" if security == "reality" else ""),
        "pbk": q.get("pbk") or "",
        "sid": short_id,
        "alpn": alpn_list(q.get("alpn")),
        "flow": flow,
        "packet_encoding": packet_encoding,
        "insecure": as_bool(q.get("allowInsecure") or q.get("insecure")),
        "encryption": q.get("encryption") or "none",
    }
    early_data = as_int(q.get("ed"), 0)
    if early_data > 0:
        params["early_data"] = early_data
        params["early_data_header"] = q.get("eh") or "Sec-WebSocket-Protocol"

    return Node(
        protocol="vless",
        host=parsed.hostname,
        port=port,
        credential=uuid,
        params=params,
        uri=base,
        remark=remark or clean_remark(q.get("remarks", "")),
    )
