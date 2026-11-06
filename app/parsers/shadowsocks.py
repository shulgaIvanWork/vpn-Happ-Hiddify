from __future__ import annotations

from urllib.parse import unquote, urlparse

from app.models import Node

from .common import (
    b64_decoded_len,
    decode_b64,
    parse_host_port,
    query_dict,
    split_uri,
)

AEAD_METHODS = {
    "aes-128-gcm",
    "aes-192-gcm",
    "aes-256-gcm",
    "chacha20-ietf-poly1305",
    "xchacha20-ietf-poly1305",
    "none",
}
METHOD_2022 = {
    "2022-blake3-aes-128-gcm": 16,
    "2022-blake3-aes-256-gcm": 32,
    "2022-blake3-chacha20-poly1305": 32,
}
METHOD_ALIASES = {
    "chacha20-poly1305": "chacha20-ietf-poly1305",
    "xchacha20-poly1305": "xchacha20-ietf-poly1305",
}
SUPPORTED_PLUGINS = {"obfs-local", "simple-obfs", "v2ray-plugin", "shadow-tls", "restls", "kcptun"}


def parse(uri: str) -> Node | None:
    base, remark = split_uri(uri)
    if not base.lower().startswith("ss://"):
        return None
    rest = base[5:]

    query: dict[str, str] = {}
    if "?" in rest:
        rest, _, query_string = rest.partition("?")
        query = query_dict(query_string)

    method = password = ""
    host = ""
    port = 0

    if "@" in rest:
        userinfo, _, hostport = rest.rpartition("@")
        hostport = hostport.rstrip("/")
        if ":" in userinfo:
            method, _, password = userinfo.partition(":")
            method, password = unquote(method), unquote(password)
        else:
            decoded = decode_b64(userinfo)
            if ":" not in decoded:
                return None
            method, _, password = decoded.partition(":")
        parsed_host = parse_host_port(hostport)
        if not parsed_host:
            return None
        host, port = parsed_host
    else:
        decoded = decode_b64(rest)
        if "@" not in decoded:
            return None
        userinfo, _, hostport = decoded.rpartition("@")
        method, _, password = userinfo.partition(":")
        parsed_host = parse_host_port(hostport)
        if not parsed_host:
            return None
        host, port = parsed_host

    method, password = method.strip().lower(), password.strip()
    if not method or not password or not host:
        return None

    method = METHOD_ALIASES.get(method, method)
    if method not in AEAD_METHODS and method not in METHOD_2022:
        return None

    if method in METHOD_2022:
        key_length = METHOD_2022[method]
        parts = password.split(":")
        if not parts or any(b64_decoded_len(part) != key_length for part in parts):
            return None

    plugin = query.get("plugin") or ""
    plugin_name, plugin_opts = "", ""
    if plugin:
        plugin_name, _, plugin_opts = plugin.partition(";")
        plugin_name = plugin_name.strip().lower()
        if plugin_name not in SUPPORTED_PLUGINS:
            return None
        if plugin_name == "simple-obfs":
            plugin_name = "obfs-local"

    params: dict[str, object] = {
        "method": method,
        "plugin": plugin_name,
        "plugin_opts": unquote(plugin_opts),
    }

    return Node(
        protocol="ss",
        host=host,
        port=port,
        credential=password,
        params=params,
        uri=base,
        remark=remark,
    )


def parse_legacy_hostport(value: str) -> tuple[str, int, str, str] | None:
    """Helper for tests: decode 'method:password@host:port'."""
    parsed = urlparse("//" + value)
    if not parsed.hostname or not parsed.port:
        return None
    return parsed.hostname, parsed.port, "", ""
