from __future__ import annotations

from typing import Any

from app.models import Node

PROBE_URL = "https://cp.cloudflare.com/generate_204"


def _tls(node: Node) -> dict[str, Any] | None:
    p = node.params
    security = str(p.get("security") or "none").lower()
    if security not in ("tls", "reality"):
        return None

    sni = str(p.get("sni") or p.get("host") or node.host)
    tls: dict[str, Any] = {"enabled": True, "server_name": sni}
    if p.get("insecure"):
        tls["insecure"] = True
    if p.get("alpn"):
        tls["alpn"] = list(p["alpn"])
    fingerprint = str(p.get("fp") or "")
    if fingerprint or security == "reality":
        tls["utls"] = {"enabled": True, "fingerprint": fingerprint or "chrome"}
    if security == "reality":
        tls["reality"] = {
            "enabled": True,
            "public_key": str(p.get("pbk") or ""),
            "short_id": str(p.get("sid") or ""),
        }
    return tls


def _transport(node: Node) -> dict[str, Any] | None:
    p = node.params
    network = str(p.get("network") or "tcp").lower()
    if network == "tcp":
        return None

    host = str(p.get("host") or "")
    path = str(p.get("path") or "/")
    sni = str(p.get("sni") or "")

    if network == "ws":
        transport: dict[str, Any] = {"type": "ws", "path": path}
        headers: dict[str, str] = {}
        if host:
            headers["Host"] = host
        elif sni and sni != node.host:
            headers["Host"] = sni
        if headers:
            transport["headers"] = headers
        early_data = int(p.get("early_data") or 0)
        if early_data > 0:
            transport["max_early_data"] = early_data
            transport["early_data_header_name"] = str(p.get("early_data_header") or "Sec-WebSocket-Protocol")
        return transport

    if network == "grpc":
        return {
            "type": "grpc",
            "service_name": str(p.get("service_name") or path.strip("/") or ""),
        }

    if network == "http":
        transport = {"type": "http", "path": path}
        if host:
            transport["host"] = [host]
        return transport

    if network == "httpupgrade":
        transport = {"type": "httpupgrade", "path": path}
        if host:
            transport["host"] = host
        return transport

    return None


def build_outbound(node: Node, tag: str | None = None) -> dict[str, Any] | None:
    p = node.params
    outbound_tag = tag or node.tag
    protocol = node.protocol

    if protocol == "vless":
        outbound: dict[str, Any] = {
            "type": "vless",
            "tag": outbound_tag,
            "server": node.host,
            "server_port": node.port,
            "uuid": node.credential,
        }
        if p.get("flow") and str(p.get("network") or "tcp") == "tcp":
            outbound["flow"] = str(p["flow"])
        packet_encoding = str(p.get("packet_encoding") or "")
        if packet_encoding in ("packetaddr", "xudp"):
            outbound["packet_encoding"] = packet_encoding

    elif protocol == "vmess":
        outbound = {
            "type": "vmess",
            "tag": outbound_tag,
            "server": node.host,
            "server_port": node.port,
            "uuid": node.credential,
            "security": str(p.get("cipher") or "auto"),
            "alter_id": int(p.get("alter_id") or 0),
        }

    elif protocol == "trojan":
        outbound = {
            "type": "trojan",
            "tag": outbound_tag,
            "server": node.host,
            "server_port": node.port,
            "password": node.credential,
        }

    elif protocol == "ss":
        outbound = {
            "type": "shadowsocks",
            "tag": outbound_tag,
            "server": node.host,
            "server_port": node.port,
            "method": str(p.get("method") or ""),
            "password": node.credential,
        }
        if p.get("plugin"):
            outbound["plugin"] = str(p["plugin"])
            if p.get("plugin_opts"):
                outbound["plugin_opts"] = str(p["plugin_opts"])

    elif protocol == "hysteria2":
        outbound = {
            "type": "hysteria2",
            "tag": outbound_tag,
            "server": node.host,
            "server_port": node.port,
            "password": node.credential,
        }
        if p.get("obfs"):
            outbound["obfs"] = {
                "type": str(p["obfs"]),
                "password": str(p.get("obfs_password") or ""),
            }

    elif protocol == "tuic":
        uuid, _, password = node.credential.partition(":")
        outbound = {
            "type": "tuic",
            "tag": outbound_tag,
            "server": node.host,
            "server_port": node.port,
            "uuid": uuid,
            "password": password,
            "congestion_control": str(p.get("congestion_control") or "bbr"),
            "udp_relay_mode": str(p.get("udp_relay_mode") or "native"),
        }

    else:
        return None

    tls = _tls(node)
    if tls:
        outbound["tls"] = tls
    transport = _transport(node)
    if transport:
        outbound["transport"] = transport

    return outbound


def build_check_config(
    nodes: list[Node], ports: int | list[int]
) -> tuple[dict[str, Any], list[tuple[int, Node]]] | None:
    """Build a temp sing-box config with one mixed inbound per node."""

    if isinstance(ports, int):
        ports = [ports + index for index in range(len(nodes))]

    inbounds: list[dict[str, Any]] = []
    outbounds: list[dict[str, Any]] = [{"type": "direct", "tag": "direct"}]
    rules: list[dict[str, Any]] = []
    port_map: list[tuple[int, Node]] = []

    for index, node in enumerate(nodes):
        if index >= len(ports):
            break
        port = ports[index]
        if not (0 < port < 65536):
            continue
        outbound = build_outbound(node, tag=f"n{index}")
        if outbound is None:
            continue
        inbounds.append(
            {
                "type": "mixed",
                "tag": f"in{index}",
                "listen": "127.0.0.1",
                "listen_port": port,
            }
        )
        outbounds.append(outbound)
        rules.append({"inbound": [f"in{index}"], "outbound": f"n{index}"})
        port_map.append((port, node))

    if not port_map:
        return None

    config = {
        "log": {"level": "error", "timestamp": True},
        "inbounds": inbounds,
        "outbounds": outbounds,
        "route": {"rules": rules, "final": "direct"},
    }
    return config, port_map


def build_subscription_config(nodes: list[Node]) -> dict[str, Any] | None:
    outbounds: list[dict[str, Any]] = []
    tags: list[str] = []

    for node in nodes:
        outbound = build_outbound(node)
        if outbound is None:
            continue
        outbounds.append(outbound)
        tags.append(str(outbound["tag"]))

    if not tags:
        return None

    auto = {
        "type": "urltest",
        "tag": "auto",
        "outbounds": tags,
        "url": PROBE_URL,
        "interval": "1m",
        "tolerance": 50,
        "idle_timeout": "30m",
    }
    selector = {
        "type": "selector",
        "tag": "proxy",
        "outbounds": ["auto", *tags],
        "default": "auto",
    }
    return {
        "log": {"level": "warn"},
        "inbounds": [
            {
                "type": "mixed",
                "tag": "mixed-in",
                "listen": "127.0.0.1",
                "listen_port": 2080,
            }
        ],
        "outbounds": [*outbounds, auto, selector, {"type": "direct", "tag": "direct"}],
        "route": {"final": "proxy"},
    }
