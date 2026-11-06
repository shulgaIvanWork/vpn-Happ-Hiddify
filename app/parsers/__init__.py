from __future__ import annotations

from app.models import Node

from . import hysteria2, shadowsocks, trojan, tuic, vless, vmess

PARSERS = {
    "vless": vless.parse,
    "vmess": vmess.parse,
    "trojan": trojan.parse,
    "ss": shadowsocks.parse,
    "hysteria2": hysteria2.parse,
    "hy2": hysteria2.parse,
    "tuic": tuic.parse,
}

SUPPORTED_SCHEMES = tuple(PARSERS)


def parse_uri(uri: str, source: str = "") -> Node | None:
    """Parse a proxy URI; returns None for unsupported/malformed input."""
    value = (uri or "").strip().strip("'\"").rstrip(",;")
    if not value or value.startswith("#"):
        return None

    if "://" not in value:
        # Some aggregators publish VLESS URIs without the scheme.
        if "@" in value and "?" in value:
            value = "vless://" + value
        else:
            return None

    scheme = value.split("://", 1)[0].lower()
    parser = PARSERS.get(scheme)
    if parser is None:
        return None

    try:
        node = parser(value)
    except Exception:
        return None
    if node is not None and source:
        node.source = source
    return node


def dedup_key(node: Node) -> str:
    return node.identity()
