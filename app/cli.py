from __future__ import annotations

import argparse
import asyncio
import json
import logging
import sys
from pathlib import Path

from app.checker import Checker
from app.config import get_settings
from app.parsers import parse_uri
from app.scheduler import Aggregator
from app.sources import extract_uris, fetch_all
from app.store import Store


def _read_text(path: str) -> str:
    return Path(path).read_text(encoding="utf-8", errors="ignore")


def cmd_parse(args: argparse.Namespace) -> int:
    uris = extract_uris(_read_text(args.file))
    nodes = []
    skipped = 0
    for uri in uris:
        node = parse_uri(uri, "cli")
        if node is None:
            skipped += 1
        else:
            nodes.append(node)

    counts: dict[str, int] = {}
    for node in nodes:
        counts[node.protocol] = counts.get(node.protocol, 0) + 1

    print(json.dumps({"uris": len(uris), "parsed": len(nodes), "skipped": skipped, "by_protocol": counts}))
    for node in nodes[: args.show]:
        print(f"{node.protocol:9} {node.host}:{node.port}  {node.remark[:40]}")
    return 0


async def _cmd_check(args: argparse.Namespace) -> int:
    settings = get_settings()
    if args.singbox:
        settings.singbox_path = args.singbox
    uris = extract_uris(_read_text(args.file))
    nodes = [node for uri in uris if (node := parse_uri(uri, "cli")) is not None]
    nodes = nodes[: args.limit]
    print(f"Checking {len(nodes)} nodes with {settings.singbox_path} ...", file=sys.stderr)
    results = await Checker(settings).check_many(nodes)
    alive = sorted(
        (result for result in results if result.ok),
        key=lambda result: result.latency_ms or 10**9,
    )
    print(json.dumps({"checked": len(results), "alive": len(alive)}))
    for result in alive:
        print(f"{result.latency_ms:5} ms  {result.node.protocol:9} {result.node.host}:{result.node.port}")
    return 0


def cmd_check(args: argparse.Namespace) -> int:
    return asyncio.run(_cmd_check(args))


async def _cmd_fetch(args: argparse.Namespace) -> int:
    settings = get_settings()
    tiers = {int(tier) for tier in args.tiers.split(",") if tier.strip()}
    lines, stats = await fetch_all(settings, tiers=tiers)
    print(json.dumps({"uris": len(lines), "sources": stats}, ensure_ascii=False, indent=2))
    return 0


def cmd_fetch(args: argparse.Namespace) -> int:
    return asyncio.run(_cmd_fetch(args))


async def _cmd_scan(args: argparse.Namespace) -> int:
    settings = get_settings()
    if args.limit:
        settings.max_nodes_per_scan = args.limit
    if args.singbox:
        settings.singbox_path = args.singbox
    store = Store(settings.data_dir)
    aggregator = Aggregator(settings, store, Checker(settings))
    await aggregator.full_scan(include_tier2=args.tier2)
    print(json.dumps(aggregator.stats, ensure_ascii=False, indent=2))
    print(f"stored live nodes: {len(store.live)}")
    return 0


def cmd_scan(args: argparse.Namespace) -> int:
    return asyncio.run(_cmd_scan(args))


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="python -m app.cli")
    sub = parser.add_subparsers(dest="command", required=True)

    parse = sub.add_parser("parse", help="parse a local file with URIs")
    parse.add_argument("file")
    parse.add_argument("--show", type=int, default=10)
    parse.set_defaults(func=cmd_parse)

    check = sub.add_parser("check", help="run a real sing-box health check on a local file")
    check.add_argument("file")
    check.add_argument("--limit", type=int, default=30)
    check.add_argument("--singbox", default="")
    check.set_defaults(func=cmd_check)

    fetch = sub.add_parser("fetch", help="fetch configured sources and print stats")
    fetch.add_argument("--tiers", default="1,2")
    fetch.set_defaults(func=cmd_fetch)

    scan = sub.add_parser("scan", help="run a full scan and save live nodes to DATA_DIR")
    scan.add_argument("--limit", type=int, default=0)
    scan.add_argument("--tier2", action="store_true")
    scan.add_argument("--singbox", default="")
    scan.set_defaults(func=cmd_scan)
    return parser


def main() -> int:
    if sys.stdout.encoding and sys.stdout.encoding.lower() != "utf-8":
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    settings = get_settings()
    logging.basicConfig(
        level=getattr(logging, settings.log_level.upper(), logging.INFO),
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("httpcore").setLevel(logging.WARNING)
    args = build_parser().parse_args()
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
