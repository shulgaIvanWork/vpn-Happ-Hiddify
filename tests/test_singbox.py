from __future__ import annotations

import base64
import json

from app.models import LiveNode
from app.parsers import parse_uri
from app.render import display_uri, node_display_name, render_base64, subscription_headers
from app.singbox import build_check_config, build_subscription_config
from app.xray import build_xray_config

UUID = "bcf31ced-07e7-4bd3-ae6d-9280d9a47834"
VLESS = (
    f"vless://{UUID}@217.16.27.216:4249"
    "?security=reality&sni=sun6-22.userapi.com&fp=chrome"
    "&pbk=2z8C1eWOMSZEYNoERS8E6f8jiWvY38Z4iebbYh8mtXc"
    "&sid=a20d3ed244c76426&type=tcp&flow=xtls-rprx-vision#A"
)


def _node(**kwargs):
    node = parse_uri(kwargs.get("uri", VLESS))
    assert node is not None
    return node


def test_check_config_ports_and_rules():
    nodes = [_node(), _node(uri=VLESS.replace("217.16.27.216:4249", "1.1.1.1:443"))]
    built = build_check_config(nodes, 20000)
    assert built is not None
    config, port_map = built
    assert [port for port, _ in port_map] == [20000, 20001]
    assert len(config["inbounds"]) == 2
    assert config["route"]["rules"][0]["inbound"] == ["in0"]
    outbound = config["outbounds"][1]
    assert outbound["type"] == "vless"
    assert outbound["flow"] == "xtls-rprx-vision"
    assert outbound["tls"]["reality"]["public_key"].startswith("2z8C")


def test_subscription_config_urltest():
    nodes = [_node()]
    config = build_subscription_config(nodes)
    assert config is not None
    tags = [outbound["tag"] for outbound in config["outbounds"]]
    assert nodes[0].tag in tags
    urltest = next(outbound for outbound in config["outbounds"] if outbound["type"] == "urltest")
    assert urltest["outbounds"] == [nodes[0].tag]
    assert config["route"]["final"] == "proxy"
    selector = next(outbound for outbound in config["outbounds"] if outbound["type"] == "selector")
    assert selector["default"] == "auto"


def test_xray_config_balancer():
    config = build_xray_config([_node()])
    assert config is not None
    balancer = config["routing"]["balancers"][0]
    assert balancer["strategy"]["type"] == "leastPing"
    assert config["observatory"]["probeUrl"].endswith("generate_204")


def test_base64_subscription_roundtrip():
    node = _node()
    live = [LiveNode(node=node, latency_ms=87, score=87.0, checked_at=1)]
    body = render_base64(live)
    decoded = base64.b64decode(body).decode("utf-8")
    assert decoded.startswith("vless://")
    assert "#" in decoded
    assert "87ms" in decoded


def test_vmess_name_is_rebuilt():
    payload = {
        "v": "2",
        "ps": "old",
        "add": "example.com",
        "port": "443",
        "id": UUID,
        "net": "tcp",
    }
    encoded = base64.b64encode(json.dumps(payload).encode()).decode()
    node = parse_uri(f"vmess://{encoded}")
    assert node is not None
    renamed = display_uri(node, "new name")
    decoded = base64.b64decode(renamed[len("vmess://") :]).decode()
    assert json.loads(decoded)["ps"] == "new name"


def test_headers():
    from app.config import Settings

    settings = Settings(sub_token="x", admin_token="y", profile_title="Test VPN")
    headers = subscription_headers(settings, "text/plain")
    assert headers["Profile-Title"].startswith("base64:")
    assert headers["Subscription-Userinfo"].startswith("upload=0")
    assert headers["Profile-Update-Interval"] == "1"


def test_display_name():
    live = LiveNode(node=_node(), latency_ms=40, score=40.0, checked_at=1)
    assert node_display_name(1, live) == "01 · ⚡40ms · vless"
