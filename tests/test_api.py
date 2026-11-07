from __future__ import annotations

import base64

import pytest
from fastapi.testclient import TestClient

from app.config import get_settings
from app.models import LiveNode
from app.parsers import parse_uri

UUID = "bcf31ced-07e7-4bd3-ae6d-9280d9a47834"
VLESS = (
    f"vless://{UUID}@example.com:443?security=tls&sni=example.com&type=tcp#A"
)


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("SCHEDULER_ENABLED", "false")
    monkeypatch.setenv("DATA_DIR", str(tmp_path))
    monkeypatch.setenv("SUB_TOKEN", "test-sub")
    monkeypatch.setenv("ADMIN_TOKEN", "test-admin")
    monkeypatch.setenv("PROFILE_TITLE", "Test VPN")
    monkeypatch.setenv("MIN_LIVE_FOR_READY", "1")
    get_settings.cache_clear()

    from app.main import app

    with TestClient(app) as test_client:
        yield test_client
    get_settings.cache_clear()


def _seed(client: TestClient) -> None:
    node = parse_uri(VLESS)
    assert node is not None
    client.app.state.store.save_live(
        [LiveNode(node=node, latency_ms=42, score=42.0, checked_at=1)]
    )


def test_health(client):
    response = client.get("/healthz")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"


def test_ready_requires_nodes(client):
    assert client.get("/readyz").status_code == 503
    _seed(client)
    response = client.get("/readyz")
    assert response.status_code == 200
    assert response.json()["live"] == 1


def test_subscription_headers_and_body(client):
    _seed(client)
    response = client.get("/sub/test-sub")
    assert response.status_code == 200
    assert response.headers["Profile-Update-Interval"] == "1"
    assert response.headers["Profile-Title"].startswith("base64:")
    decoded = base64.b64decode(response.text).decode()
    assert decoded.startswith("vless://")


def test_subscription_forbidden(client):
    _seed(client)
    assert client.get("/sub/wrong").status_code == 403


def test_subscription_503_when_empty(client):
    assert client.get("/sub/test-sub").status_code == 503


def test_singbox_subscription(client):
    _seed(client)
    response = client.get("/sub/test-sub/singbox")
    assert response.status_code == 200
    config = response.json()
    types = {outbound["type"] for outbound in config["outbounds"]}
    assert {"vless", "urltest", "selector", "direct"} <= types


def test_xray_subscription(client):
    _seed(client)
    response = client.get("/sub/test-sub/xray")
    assert response.status_code == 200
    config = response.json()
    assert config["routing"]["balancers"][0]["strategy"]["type"] == "leastPing"


def test_happ_subscription_is_json_array_with_failover(client):
    _seed(client)
    response = client.get("/sub/test-sub/happ")
    assert response.status_code == 200
    configs = response.json()
    assert isinstance(configs, list) and len(configs) == 1
    config = configs[0]
    assert config["remarks"]
    assert "inbounds" not in config
    assert config["routing"]["balancers"][0]["strategy"]["type"] == "leastPing"
    assert config["observatory"]["probeUrl"]
    rule = config["routing"]["rules"][0]
    assert rule["balancerTag"] == "auto"
    assert "inboundTag" not in rule


def test_info_and_page_and_qr(client):
    _seed(client)
    info = client.get("/sub/test-sub/info")
    assert info.status_code == 200
    assert info.json()["nodes"] == 1

    page = client.get("/p/test-sub")
    assert page.status_code == 200
    assert "Test VPN" in page.text

    qr = client.get("/qr/test-sub.svg")
    assert qr.status_code == 200
    assert "svg" in qr.text.lower()


def test_admin_auth(client):
    _seed(client)
    assert client.get("/admin/status").status_code == 401
    ok = client.get("/admin/status", headers={"Authorization": "Bearer test-admin"})
    assert ok.status_code == 200
    assert ok.json()["live_count"] == 1
    refresh = client.post("/admin/refresh", headers={"Authorization": "Bearer test-admin"})
    assert refresh.status_code == 200
