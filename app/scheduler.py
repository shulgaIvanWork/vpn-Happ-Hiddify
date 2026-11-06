from __future__ import annotations

import asyncio
import logging
import random
import time
from collections import Counter
from typing import Any

from app.checker import Checker
from app.config import Settings
from app.models import CheckResult, Node
from app.parsers import parse_uri
from app.scoring import to_live, update_history
from app.sources import fetch_all
from app.store import Store

log = logging.getLogger(__name__)

PREMIUM_SOURCES = {"rjsxrd-bypass-all", "rjsxrd-servers"}


class Aggregator:
    def __init__(self, settings: Settings, store: Store, checker: Checker) -> None:
        self.settings = settings
        self.store = store
        self.checker = checker
        self.stats: dict[str, Any] = {
            "last_full_scan": 0,
            "last_quick_recheck": 0,
            "last_full_duration_sec": 0,
            "last_error": "",
            "parsed": 0,
            "unique": 0,
            "candidates": 0,
            "checked": 0,
            "alive": 0,
            "by_protocol": {},
            "sources": [],
        }
        self._task: asyncio.Task | None = None
        self._stop = asyncio.Event()
        self._wake = asyncio.Event()
        self._lock = asyncio.Lock()
        self._force_full = False
        self._last_full_monotonic = 0.0
        self._last_quick_monotonic = 0.0
        self._last_tier2_wall = 0.0

    # ------------------------------------------------------------------ lifecycle

    async def start(self) -> None:
        if not self.settings.scheduler_enabled:
            log.info("Scheduler disabled")
            return
        self._task = asyncio.create_task(self._run_loop(), name="aggregator-loop")

    async def stop(self) -> None:
        self._stop.set()
        self._wake.set()
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except (asyncio.CancelledError, Exception):
                pass

    def request_refresh(self) -> None:
        self._force_full = True
        self._wake.set()

    # ------------------------------------------------------------------ scans

    async def full_scan(self, include_tier2: bool | None = None) -> None:
        async with self._lock:
            started = time.monotonic()
            if include_tier2 is None:
                include_tier2 = time.time() - self._last_tier2_wall >= 86_400
            tiers = {1, 2} if include_tier2 else {1}
            log.info("Full scan started, tiers=%s", sorted(tiers))

            try:
                lines, source_stats = await fetch_all(self.settings, tiers=tiers)
                nodes = self._dedup(lines)
                candidates = self._prioritize(nodes)
                results = await self.checker.check_many(candidates)

                update_history(self.store.history, results)
                live = to_live(results, self.store.history, self.settings.max_latency_ms)[
                    : self.settings.max_live_store
                ]
                if not live:
                    # Never end up empty because every node is slow.
                    live = to_live(results, self.store.history)[: self.settings.max_live_store]

                if len(live) < self.settings.min_live_for_ready and self.store.live:
                    log.warning(
                        "Scan produced only %d live nodes, keeping previous %d",
                        len(live),
                        len(self.store.live),
                    )
                    error = f"low-live:{len(live)}"
                else:
                    self.store.save_live(live)
                    error = ""

                self.store.save_history()
                if include_tier2:
                    self._last_tier2_wall = time.time()

                self._last_full_monotonic = time.monotonic()
                self._last_quick_monotonic = self._last_full_monotonic
                duration = round(time.monotonic() - started, 1)
                self.stats.update(
                    {
                        "last_full_scan": int(time.time()),
                        "last_full_duration_sec": duration,
                        "last_error": error,
                        "parsed": len(lines),
                        "unique": len(nodes),
                        "candidates": len(candidates),
                        "checked": len(results),
                        "alive": sum(1 for result in results if result.ok),
                        "by_protocol": dict(Counter(node.protocol for node in nodes)),
                        "sources": source_stats,
                    }
                )
                log.info(
                    "Full scan finished in %.1fs: %d parsed, %d unique, %d checked, %d alive, %d stored",
                    duration,
                    len(lines),
                    len(nodes),
                    len(results),
                    sum(1 for result in results if result.ok),
                    len(self.store.live),
                )
            except Exception as exc:
                self.stats["last_error"] = f"{type(exc).__name__}: {exc}"
                log.exception("Full scan failed")

    async def quick_recheck(self) -> None:
        async with self._lock:
            if not self.store.live:
                self._force_full = True
                return
            started = time.monotonic()
            nodes = [item.node for item in self.store.live]
            log.info("Quick recheck of %d live nodes", len(nodes))
            try:
                results = await self.checker.check_many(nodes)
                update_history(self.store.history, results)
                live = to_live(results, self.store.history, self.settings.max_latency_ms)[
                    : self.settings.max_live_store
                ]
                if not live:
                    # Never end up empty because every node is slow.
                    live = to_live(results, self.store.history)[: self.settings.max_live_store]
                if len(live) < self.settings.min_live_for_ready:
                    log.warning("Quick recheck left %d nodes, scheduling full scan", len(live))
                    self._force_full = True
                else:
                    self.store.save_live(live)
                self.store.save_history()
                self._last_quick_monotonic = time.monotonic()
                self.stats["last_quick_recheck"] = int(time.time())
                self.stats["last_error"] = "" if len(live) >= self.settings.min_live_for_ready else "quick-low"
                log.info(
                    "Quick recheck finished in %.1fs: %d/%d alive",
                    time.monotonic() - started,
                    sum(1 for result in results if result.ok),
                    len(results),
                )
            except Exception as exc:
                self.stats["last_error"] = f"{type(exc).__name__}: {exc}"
                log.exception("Quick recheck failed")

    # ------------------------------------------------------------------ helpers

    @staticmethod
    def _dedup(lines) -> list[Node]:
        unique: dict[str, Node] = {}
        for line in lines:
            node = parse_uri(line.uri, line.source)
            if node is None:
                continue
            unique.setdefault(node.identity(), node)
        return list(unique.values())

    def _prioritize(self, nodes: list[Node]) -> list[Node]:
        previous = {item.node.identity() for item in self.store.live}
        head = [node for node in nodes if node.identity() in previous]
        rest = [node for node in nodes if node.identity() not in previous]

        premium = [node for node in rest if node.source in PREMIUM_SOURCES]
        tail = [node for node in rest if node.source not in PREMIUM_SOURCES]
        random.Random(int(time.time() // 3600)).shuffle(tail)
        ordered = head + premium + tail
        return ordered[: self.settings.max_nodes_per_scan]

    # ------------------------------------------------------------------ loop

    async def _run_loop(self) -> None:
        try:
            await self.full_scan()
        except asyncio.CancelledError:
            return
        except Exception:
            log.exception("Initial scan failed")

        while not self._stop.is_set():
            now = time.monotonic()
            try:
                if self._force_full or now - self._last_full_monotonic >= self.settings.full_scan_interval:
                    self._force_full = False
                    await self.full_scan()
                elif now - self._last_quick_monotonic >= self.settings.live_recheck_interval:
                    await self.quick_recheck()
            except asyncio.CancelledError:
                return
            except Exception:
                log.exception("Scheduled scan failed")

            try:
                await asyncio.wait_for(self._wake.wait(), timeout=30.0)
                self._wake.clear()
            except TimeoutError:
                pass
            except asyncio.CancelledError:
                return

    def top_results(self, limit: int = 20) -> list[CheckResult]:
        return [
            CheckResult(node=item.node, ok=True, latency_ms=item.latency_ms)
            for item in self.store.live[:limit]
        ]
