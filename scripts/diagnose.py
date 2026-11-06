from __future__ import annotations

import asyncio
import json
import subprocess
import sys
import tempfile
import time
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import httpx

from app import singbox
from app.models import Node
from app.parsers import parse_uri
from app.sources import extract_uris

if sys.stdout.encoding and sys.stdout.encoding.lower() != "utf-8":
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")


def validate(nodes: list[Node]) -> None:
    print(f"validating {len(nodes)} single-node configs...")
    failures: list[tuple[Node, str]] = []
    for index, node in enumerate(nodes):
        built = singbox.build_check_config([node], 22000)
        if built is None:
            failures.append((node, "build returned None"))
            continue
        config, _ = built
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False, encoding="utf-8") as file:
            json.dump(config, file, ensure_ascii=False)
            path = file.name
        try:
            result = subprocess.run(
                ["bin/sing-box.exe", "check", "-c", path], capture_output=True, timeout=10
            )
            if result.returncode != 0:
                message = result.stderr.decode("utf-8", "replace").strip().splitlines()
                failures.append((node, message[-1] if message else result.stdout.decode("utf-8", "replace")))
        finally:
            Path(path).unlink(missing_ok=True)
        if (index + 1) % 50 == 0:
            print(f"  {index + 1}/{len(nodes)}, failures={len(failures)}")

    print(f"failures: {len(failures)}/{len(nodes)}")
    for node, error in failures[:30]:
        print(f"  {node.protocol:9} {node.host}:{node.port} -> {error[:160]}")
    print("error kinds:", Counter(error[:60] for _, error in failures).most_common(10))


async def timing(nodes: list[Node]) -> None:
    import os

    from app.checker import Checker
    from app.config import get_settings

    settings = get_settings()
    settings.singbox_path = "bin/sing-box.exe"
    settings.probe_concurrency = int(os.getenv("PROBE_CONCURRENCY", "40"))
    settings.check_timeout = float(os.getenv("CHECK_TIMEOUT", "2.5"))
    print(f"concurrency={settings.probe_concurrency} timeout={settings.check_timeout}")
    started = time.monotonic()
    results = await Checker(settings).check_many(nodes)
    alive = [result for result in results if result.ok]
    print(f"checked {len(results)} in {time.monotonic() - started:.1f}s, alive={len(alive)}")
    for result in results[:15]:
        print(
            f"  {'OK ' if result.ok else 'ERR'} {result.node.protocol:9} {result.node.host}:{result.node.port}"
            f" latency={result.latency_ms} error={result.error}"
        )
    for result in sorted(alive, key=lambda item: item.latency_ms or 10**9)[:20]:
        print(f"  {result.latency_ms:5}ms {result.node.protocol:9} {result.node.host}:{result.node.port}")
    print("errors:", Counter(result.error for result in results if not result.ok).most_common(10))


async def main(path: str, limit: int) -> None:
    uris = extract_uris(Path(path).read_text(encoding="utf-8", errors="ignore"))
    nodes = []
    for uri in uris:
        node = parse_uri(uri, "debug")
        if node is not None:
            nodes.append(node)
        if len(nodes) >= limit:
            break
    if len(sys.argv) <= 4 or sys.argv[4] != "skip":
        validate(nodes)
    print()
    count = int(sys.argv[3]) if len(sys.argv) > 3 else 70
    await timing(nodes[:count])


if __name__ == "__main__":
    asyncio.run(main(sys.argv[1], int(sys.argv[2]) if len(sys.argv) > 2 else 200))
