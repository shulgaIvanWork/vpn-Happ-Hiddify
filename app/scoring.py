from __future__ import annotations

import time

from app.models import CheckResult, LiveNode


def _new_entry() -> dict:
    return {
        "attempts": 0,
        "successes": 0,
        "fail_streak": 0,
        "ema_ms": None,
        "last_ok": 0,
        "last_check": 0,
    }


def update_history(history: dict[str, dict], results: list[CheckResult]) -> None:
    now = int(time.time())
    for result in results:
        key = result.node.identity()
        entry = history.get(key) or _new_entry()
        entry["attempts"] = int(entry.get("attempts") or 0) + 1
        entry["last_check"] = now
        if result.ok and result.latency_ms is not None:
            entry["successes"] = int(entry.get("successes") or 0) + 1
            entry["fail_streak"] = 0
            entry["last_ok"] = now
            previous = entry.get("ema_ms")
            latency = float(result.latency_ms)
            entry["ema_ms"] = latency if previous is None else round(0.7 * float(previous) + 0.3 * latency, 1)
        else:
            entry["fail_streak"] = int(entry.get("fail_streak") or 0) + 1
        history[key] = entry


def score_node(history: dict[str, dict], key: str, latency_ms: int) -> float:
    entry = history.get(key)
    if not entry:
        return float(latency_ms)
    ema = entry.get("ema_ms")
    ema_value = float(ema) if ema is not None else float(latency_ms)
    attempts = max(1, int(entry.get("attempts") or 0))
    successes = int(entry.get("successes") or 0)
    fail_rate = max(0.0, 1.0 - successes / attempts)
    fail_streak = min(int(entry.get("fail_streak") or 0), 5)
    return round(ema_value + fail_rate * 1500 + fail_streak * 600, 1)


def to_live(
    results: list[CheckResult], history: dict[str, dict], max_latency_ms: int | None = None
) -> list[LiveNode]:
    live: list[LiveNode] = []
    for result in results:
        if not result.ok or result.latency_ms is None:
            continue
        if max_latency_ms is not None and result.latency_ms > max_latency_ms:
            continue
        key = result.node.identity()
        live.append(
            LiveNode(
                node=result.node,
                latency_ms=int(result.latency_ms),
                score=score_node(history, key, int(result.latency_ms)),
                checked_at=result.checked_at,
            )
        )
    live.sort(key=lambda item: (item.score, item.latency_ms))
    return live
