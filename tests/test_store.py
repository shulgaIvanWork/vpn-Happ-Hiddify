from __future__ import annotations

from app.models import CheckResult, LiveNode
from app.parsers import parse_uri
from app.scoring import score_node, to_live, update_history
from app.store import Store

UUID = "bcf31ced-07e7-4bd3-ae6d-9280d9a47834"
VLESS = f"vless://{UUID}@example.com:443?security=tls&type=tcp#A"


def _node():
    node = parse_uri(VLESS)
    assert node is not None
    return node


def test_store_roundtrip(tmp_path):
    store = Store(tmp_path)
    node = _node()
    store.save_live([LiveNode(node=node, latency_ms=50, score=50.0, checked_at=123)])
    store.save_history()
    store.history[node.identity()] = {
        "attempts": 1,
        "successes": 1,
        "fail_streak": 0,
        "ema_ms": 50.0,
        "last_ok": 123,
        "last_check": 123,
    }
    store.save_history()

    reloaded = Store(tmp_path)
    assert len(reloaded.live) == 1
    assert reloaded.live[0].node.identity() == node.identity()
    assert reloaded.live[0].latency_ms == 50
    assert reloaded.history[node.identity()]["attempts"] == 1


def test_history_and_scoring():
    history: dict[str, dict] = {}
    node = _node()
    update_history(history, [CheckResult(node=node, ok=True, latency_ms=100)])
    entry = history[node.identity()]
    assert entry["attempts"] == 1
    assert entry["successes"] == 1
    assert entry["ema_ms"] == 100.0

    update_history(history, [CheckResult(node=node, ok=False, error="timeout")])
    assert history[node.identity()]["fail_streak"] == 1
    penalized = score_node(history, node.identity(), 100)
    assert penalized > 100

    live = to_live([CheckResult(node=node, ok=True, latency_ms=90)], history)
    assert len(live) == 1
    assert live[0].node.identity() == node.identity()


def test_to_live_skips_failures():
    node = _node()
    assert to_live([CheckResult(node=node, ok=False, error="x")], {}) == []


def test_top_diversifies_subnets(tmp_path):
    store = Store(tmp_path)
    live = []
    for index in range(10):
        node = parse_uri(
            f"vless://00000000-0000-0000-0000-{index:012d}@82.38.31.{index + 1}:443"
            "?security=tls&type=tcp#a"
        )
        assert node is not None
        live.append(LiveNode(node=node, latency_ms=index + 1, score=float(index + 1), checked_at=1))
    for index in range(10):
        node = parse_uri(
            f"vless://00000000-0000-0000-0000-{index + 100:012d}@45.1.2.{index + 1}:443"
            "?security=tls&type=tcp#b"
        )
        assert node is not None
        live.append(LiveNode(node=node, latency_ms=index + 1, score=float(index + 1), checked_at=1))
    store.save_live(live)

    top = store.top(8, max_per_subnet=3)
    assert len(top) == 8
    first = sum(1 for item in top if item.node.host.startswith("82.38.31."))
    second = sum(1 for item in top if item.node.host.startswith("45.1.2."))
    assert first >= 3 and second >= 3
