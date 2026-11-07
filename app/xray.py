from __future__ import annotations

import ipaddress
from typing import Any

from app.models import Node
from app.singbox import PROBE_URL


def _is_public_ip(host: str) -> bool:
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        return False
    return not (
        address.is_private
        or address.is_loopback
        or address.is_link_local
        or address.is_multicast
        or address.is_reserved
    )


def _stream_settings(node: Node) -> dict[str, Any] | None:
    p = node.params
    security = str(p.get("security") or "none").lower()
    network = str(p.get("network") or "tcp").lower()
    xray_network = {"http": "h2"}.get(network, network)

    stream: dict[str, Any] = {"network": xray_network}
    sni = str(p.get("sni") or p.get("host") or node.host)
    fingerprint = str(p.get("fp") or "chrome")

    if security == "reality":
        stream["security"] = "reality"
        stream["realitySettings"] = {
            "serverName": sni,
            "fingerprint": fingerprint,
            "publicKey": str(p.get("pbk") or ""),
            "shortId": str(p.get("sid") or ""),
            "spiderX": "/",
        }
    elif security == "tls":
        stream["security"] = "tls"
        tls_settings: dict[str, Any] = {
            "serverName": sni,
            "fingerprint": fingerprint,
        }
        if p.get("alpn"):
            tls_settings["alpn"] = list(p["alpn"])
        stream["tlsSettings"] = tls_settings
    else:
        stream["security"] = "none"

    host = str(p.get("host") or "")
    path = str(p.get("path") or "/")

    if xray_network == "ws":
        ws: dict[str, Any] = {"path": path}
        if host:
            ws["headers"] = {"Host": host}
        stream["wsSettings"] = ws
    elif xray_network == "grpc":
        stream["grpcSettings"] = {"serviceName": str(p.get("service_name") or path.strip("/") or "")}
    elif xray_network == "h2":
        h2: dict[str, Any] = {"path": path}
        if host:
            h2["host"] = [host]
        stream["httpSettings"] = h2
    elif xray_network == "httpupgrade":
        upgrade: dict[str, Any] = {"path": path}
        if host:
            upgrade["host"] = host
        stream["httpupgradeSettings"] = upgrade
    elif xray_network == "tcp":
        stream["tcpSettings"] = {"header": {"type": "none"}}

    return stream


def build_xray_outbound(node: Node) -> dict[str, Any] | None:
    p = node.params
    tag = node.tag
    protocol = node.protocol

    security = str(p.get("security") or "none").lower()
    if security == "tls" and p.get("insecure"):
        # Xray 26 removed allowInsecure; self-signed nodes cannot work there.
        return None

    if protocol == "vless":
        security = str(p.get("security") or "none").lower()
        if security == "none" and _is_public_ip(node.host):
            # Xray 26 rejects plaintext VLESS to public IPs.
            return None
        user: dict[str, Any] = {"id": node.credential, "encryption": "none"}
        if p.get("flow") and str(p.get("network") or "tcp") == "tcp":
            user["flow"] = str(p["flow"])
        outbound: dict[str, Any] = {
            "tag": tag,
            "protocol": "vless",
            "settings": {
                "vnext": [
                    {
                        "address": node.host,
                        "port": node.port,
                        "users": [user],
                    }
                ]
            },
        }

    elif protocol == "vmess":
        outbound = {
            "tag": tag,
            "protocol": "vmess",
            "settings": {
                "vnext": [
                    {
                        "address": node.host,
                        "port": node.port,
                        "users": [
                            {
                                "id": node.credential,
                                "alterId": int(p.get("alter_id") or 0),
                                "security": str(p.get("cipher") or "auto"),
                            }
                        ],
                    }
                ]
            },
        }

    elif protocol == "trojan":
        outbound = {
            "tag": tag,
            "protocol": "trojan",
            "settings": {
                "servers": [
                    {
                        "address": node.host,
                        "port": node.port,
                        "password": node.credential,
                    }
                ]
            },
        }

    elif protocol == "ss":
        server: dict[str, Any] = {
            "address": node.host,
            "port": node.port,
            "method": str(p.get("method") or ""),
            "password": node.credential,
        }
        if p.get("plugin"):
            server["plugin"] = str(p["plugin"])
            server["pluginOpts"] = str(p.get("plugin_opts") or "")
        outbound = {"tag": tag, "protocol": "shadowsocks", "settings": {"servers": [server]}}

    else:
        return None

    stream = _stream_settings(node)
    if stream is None:
        return None
    outbound["streamSettings"] = stream
    return outbound


def build_xray_config(nodes: list[Node]) -> dict[str, Any] | None:
    outbounds: list[dict[str, Any]] = []
    tags: list[str] = []

    for node in nodes:
        outbound = build_xray_outbound(node)
        if outbound is None:
            continue
        outbounds.append(outbound)
        tags.append(str(outbound["tag"]))

    if not tags:
        return None

    balancer = {
        "tag": "auto",
        "selector": tags,
        "strategy": {"type": "leastPing"},
    }
    return {
        "log": {"loglevel": "warning"},
        "inbounds": [
            {
                "tag": "socks-in",
                "listen": "127.0.0.1",
                "port": 10808,
                "protocol": "socks",
                "settings": {"udp": True},
            },
            {
                "tag": "http-in",
                "listen": "127.0.0.1",
                "port": 10809,
                "protocol": "http",
            },
        ],
        "outbounds": [
            *outbounds,
            {
                "tag": "direct",
                "protocol": "freedom",
                "settings": {"domainStrategy": "UseIP"},
                "streamSettings": {"sockopt": {"domainStrategy": "UseIP"}},
            },
            {"tag": "block", "protocol": "blackhole"},
        ],
        "observatory": {
            "subjectSelector": tags,
            "probeUrl": PROBE_URL,
            "probeInterval": "60s",
            "enableConcurrency": True,
        },
        "routing": {
            "domainStrategy": "AsIs",
            "balancers": [balancer],
            "rules": [
                {
                    # No inboundTag: matches whatever inbound the client injects.
                    "type": "field",
                    "network": "tcp,udp",
                    "balancerTag": "auto",
                }
            ],
        },
    }
