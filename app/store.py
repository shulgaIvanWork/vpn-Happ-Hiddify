from __future__ import annotations

import ipaddress
import json
import logging
import os
import time
from collections import defaultdict
from pathlib import Path

from app.models import LiveNode

log = logging.getLogger(__name__)


def _subnet_key(host: str) -> str:
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        parts = host.lower().split(".")
        return ".".join(parts[-2:]) if len(parts) >= 2 else host.lower()
    if address.version == 4:
        return ".".join(str(address).split(".")[:3])
    return ":".join(address.exploded.split(":")[:3])


class Store:
    """Small atomic JSON store for the last good node set and history."""

    def __init__(self, data_dir: Path) -> None:
        self.data_dir = Path(data_dir)
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.live_path = self.data_dir / "live.json"
        self.history_path = self.data_dir / "history.json"
        self.live: list[LiveNode] = []
        self.history: dict[str, dict] = {}
        self.updated_at: int = 0
        self._load()

    def _load(self) -> None:
        live_data = self._read_json(self.live_path)
        if isinstance(live_data, dict):
            self.updated_at = int(live_data.get("updated_at") or 0)
            for item in live_data.get("nodes") or []:
                try:
                    self.live.append(LiveNode.from_dict(item))
                except Exception:
                    continue
        history_data = self._read_json(self.history_path)
        if isinstance(history_data, dict):
            nodes = history_data.get("nodes")
            if isinstance(nodes, dict):
                self.history = {str(key): value for key, value in nodes.items() if isinstance(value, dict)}
        log.info("Store loaded: %d live nodes, %d history entries", len(self.live), len(self.history))

    @staticmethod
    def _read_json(path: Path):
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except FileNotFoundError:
            return None
        except Exception as exc:
            log.warning("Cannot read %s: %s", path, exc)
            return None

    @staticmethod
    def _atomic_write(path: Path, payload: object) -> None:
        tmp = path.with_name(path.name + ".tmp")
        tmp.write_text(json.dumps(payload, ensure_ascii=False, separators=(",", ":")), encoding="utf-8")
        os.replace(tmp, path)

    def save_live(self, live: list[LiveNode]) -> None:
        self.live = live
        self.updated_at = int(time.time())
        self._atomic_write(
            self.live_path,
            {"updated_at": self.updated_at, "nodes": [item.to_dict() for item in live]},
        )

    def save_history(self, max_entries: int = 8000) -> None:
        if len(self.history) > max_entries:
            ordered = sorted(
                self.history.items(),
                key=lambda kv: int(kv[1].get("last_check") or 0),
                reverse=True,
            )[:max_entries]
            self.history = dict(ordered)
        self._atomic_write(self.history_path, {"nodes": self.history})

    def top(self, limit: int, max_per_subnet: int = 0) -> list[LiveNode]:
        if max_per_subnet <= 0:
            return self.live[:limit]

        selected: list[LiveNode] = []
        counts: dict[str, int] = defaultdict(int)
        for item in self.live:
            key = _subnet_key(item.node.host)
            if counts[key] >= max_per_subnet:
                continue
            selected.append(item)
            counts[key] += 1
            if len(selected) >= limit:
                return selected

        # If diversity limits left us short, fill the rest with the best remaining.
        chosen = {item.node.identity() for item in selected}
        for item in self.live:
            if item.node.identity() in chosen:
                continue
            selected.append(item)
            if len(selected) >= limit:
                break
        return selected
