from __future__ import annotations

import base64
import json

import pytest

from app.parsers import parse_uri

UUID = "bcf31ced-07e7-4bd3-ae6d-9280d9a47834"


def test_vless_reality():
    uri = (
        f"vless://{UUID}@217.16.27.216:4249"
        "?security=reality&sni=sun6-22.userapi.com&fp=chrome"
        "&pbk=2z8C1eWOMSZEYNoERS8E6f8jiWvY38Z4iebbYh8mtXc"
        "&sid=a20d3ed244c76426&type=tcp&flow=xtls-rprx-vision&encryption=none#Armenia"
    )
    node = parse_uri(uri, "test")
    assert node is not None
    assert node.protocol == "vless"
    assert node.host == "217.16.27.216"
    assert node.port == 4249
    assert node.params["security"] == "reality"
    assert node.params["pbk"].startswith("2z8C")
    assert node.params["network"] == "tcp"
    assert node.remark == "Armenia"
    assert node.source == "test"


def test_vless_ws():
    uri = (
        f"vless://{UUID}@example.com:443?type=ws&security=tls&sni=example.com"
        "&host=cdn.example.com&path=%2Fws&fp=chrome#WS"
    )
    node = parse_uri(uri)
    assert node is not None
    assert node.params["network"] == "ws"
    assert node.params["host"] == "cdn.example.com"
    assert node.params["path"] == "/ws"


def test_vless_reality_without_pbk_rejected():
    uri = f"vless://{UUID}@example.com:443?security=reality&type=tcp#bad"
    assert parse_uri(uri) is None


def test_vless_reality_with_bad_pbk_rejected():
    uri = (
        f"vless://{UUID}@example.com:443?security=reality&type=tcp"
        "&pbk=not-a-32-byte-key&sid=01#bad"
    )
    assert parse_uri(uri) is None


def test_vless_invalid_packet_encoding_is_dropped():
    uri = (
        f"vless://{UUID}@example.com:443?security=tls&type=tcp"
        "&packetEncoding=none#p"
    )
    node = parse_uri(uri)
    assert node is not None
    assert node.params["packet_encoding"] == ""


def test_vless_tcp_http_obfs_rejected():
    uri = f"vless://{UUID}@example.com:443?security=none&type=tcp&headerType=http#bad"
    assert parse_uri(uri) is None


def test_vmess():
    payload = {
        "v": "2",
        "ps": "vmess node",
        "add": "example.com",
        "port": "443",
        "id": UUID,
        "aid": "0",
        "scy": "auto",
        "net": "ws",
        "type": "none",
        "host": "cdn.example.com",
        "path": "/ws",
        "tls": "tls",
        "sni": "example.com",
    }
    encoded = base64.b64encode(json.dumps(payload).encode()).decode()
    node = parse_uri(f"vmess://{encoded}")
    assert node is not None
    assert node.protocol == "vmess"
    assert node.host == "example.com"
    assert node.params["network"] == "ws"
    assert node.params["security"] == "tls"
    assert node.remark == "vmess node"


def test_trojan():
    node = parse_uri("trojan://secret@example.com:443?sni=example.com&type=grpc&serviceName=svc#T")
    assert node is not None
    assert node.protocol == "trojan"
    assert node.credential == "secret"
    assert node.params["service_name"] == "svc"


def test_trojan_reality():
    node = parse_uri(
        "trojan://secret@example.com:443?security=reality&sni=example.com"
        "&pbk=AgE09mNrPAe9eidpIgw9gVKLC71TgG4L4ctuB3wttiw&sid=aabbccdd&type=tcp#R"
    )
    assert node is not None
    assert node.params["security"] == "reality"
    assert node.params["pbk"].startswith("AgE0")
    assert node.params["sid"] == "aabbccdd"


def test_trojan_reality_bad_pbk_rejected():
    assert (
        parse_uri("trojan://secret@example.com:443?security=reality&pbk=short&type=tcp#bad")
        is None
    )


def test_invalid_ws_path_rejected():
    assert (
        parse_uri(f"vless://{UUID}@example.com:443?type=ws&security=tls&path=/%3...&sni=x#bad")
        is None
    )


def test_shadowsocks_sip002():
    userinfo = base64.b64encode(b"aes-256-gcm:secret").decode().rstrip("=")
    node = parse_uri(f"ss://{userinfo}@1.2.3.4:8388#SS")
    assert node is not None
    assert node.protocol == "ss"
    assert node.params["method"] == "aes-256-gcm"
    assert node.credential == "secret"
    assert node.host == "1.2.3.4"


def test_shadowsocks_legacy():
    encoded = base64.b64encode(b"chacha20-ietf-poly1305:pass@1.2.3.4:8388").decode()
    node = parse_uri(f"ss://{encoded}#Legacy")
    assert node is not None
    assert node.params["method"] == "chacha20-ietf-poly1305"
    assert node.port == 8388


def test_shadowsocks_plugin():
    userinfo = base64.b64encode(b"aes-256-gcm:secret").decode().rstrip("=")
    node = parse_uri(
        f"ss://{userinfo}@example.com:443?plugin=v2ray-plugin%3Bmode%3Dwebsocket%3Bhost%3Dexample.com#P"
    )
    assert node is not None
    assert node.params["plugin"] == "v2ray-plugin"
    assert "mode=websocket" in node.params["plugin_opts"]


def test_shadowsocks_unsupported_method_rejected():
    userinfo = base64.b64encode(b"rc4-md5:secret").decode().rstrip("=")
    assert parse_uri(f"ss://{userinfo}@example.com:443#bad") is None


def test_shadowsocks_method_alias():
    userinfo = base64.b64encode(b"chacha20-poly1305:secret").decode().rstrip("=")
    node = parse_uri(f"ss://{userinfo}@example.com:443#alias")
    assert node is not None
    assert node.params["method"] == "chacha20-ietf-poly1305"


def test_shadowsocks_2022_bad_key_rejected():
    userinfo = base64.b64encode(b"2022-blake3-aes-256-gcm:short").decode().rstrip("=")
    assert parse_uri(f"ss://{userinfo}@example.com:443#bad") is None


def test_shadowsocks_unknown_plugin_rejected():
    userinfo = base64.b64encode(b"aes-256-gcm:secret").decode().rstrip("=")
    assert (
        parse_uri(f"ss://{userinfo}@example.com:443?plugin=unknown-plugin%3Bx%3D1#bad")
        is None
    )


def test_hysteria2():
    node = parse_uri(
        "hysteria2://pass@example.com:443?sni=example.com&insecure=1"
        "&obfs=salamander&obfs-password=xyz#H"
    )
    assert node is not None
    assert node.protocol == "hysteria2"
    assert node.params["insecure"] is True
    assert node.params["obfs"] == "salamander"


def test_hysteria2_obfs_without_password_rejected():
    assert parse_uri("hysteria2://pass@example.com:443?obfs=salamander#bad") is None


def test_tuic():
    node = parse_uri(
        f"tuic://{UUID}:pass@example.com:443?congestion_control=bbr&udp_relay_mode=native&alpn=h3#T"
    )
    assert node is not None
    assert node.protocol == "tuic"
    assert node.credential == f"{UUID}:pass"


def test_tuic_invalid_uuid_rejected():
    assert parse_uri("tuic://not-a-uuid:pass@example.com:443#bad") is None


@pytest.mark.parametrize(
    "uri",
    [
        "",
        "https://example.com",
        "vless://broken",
        "ss://not-base64@",
        "vmess://not-base64",
    ],
)
def test_invalid(uri):
    assert parse_uri(uri) is None


def test_dedup_identity_ignores_remark():
    a = parse_uri(f"vless://{UUID}@example.com:443?security=tls&sni=example.com&type=tcp#one")
    b = parse_uri(f"vless://{UUID}@example.com:443?security=tls&sni=example.com&type=tcp#two")
    assert a is not None and b is not None
    assert a.identity() == b.identity()
    assert a.tag == b.tag


def test_identity_differs_by_transport():
    a = parse_uri(f"vless://{UUID}@example.com:443?security=tls&type=tcp#a")
    b = parse_uri(f"vless://{UUID}@example.com:443?security=tls&type=ws#b")
    assert a.identity() != b.identity()
