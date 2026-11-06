from __future__ import annotations

import asyncio
import logging
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import httpx
import yaml

from app.config import Settings
from app.parsers.common import decode_b64, is_probably_base64

log = logging.getLogger(__name__)

URI_RE = re.compile(r"(?:vless|vmess|trojan|ss|hysteria2|hy2|tuic)://[^\s\"'<>]+", re.IGNORECASE)
MAX_URIS_PER_SOURCE = 20_000
FETCH_CONCURRENCY = 8
USER_AGENT = "my-vpn-aggregator/0.1 (+https://github.com/)"


@dataclass(slots=True)
class Source:
    name: str
    url: str
    tier: int
    enabled: bool = True


@dataclass(slots=True)
class FetchedLine:
    uri: str
    source: str
    tier: int


@dataclass(slots=True)
class SourceConfig:
    sources: list[Source]
    mirrors: list[str]
    max_bytes: int


DEFAULT_SOURCES = [
    Source(
        name="rjsxrd-bypass-all",
        url="https://raw.githubusercontent.com/whoahaow/rjsxrd/main/githubmirror/bypass/bypass-all.txt",
        tier=1,
    ),
    Source(
        name="rjsxrd-servers",
        url="https://raw.githubusercontent.com/whoahaow/rjsxrd/main/source/config/servers.txt",
        tier=1,
    ),
]


def load_source_config(path: Path) -> SourceConfig:
    try:
        raw = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
    except FileNotFoundError:
        log.warning("sources file %s not found, using defaults", path)
        return SourceConfig(DEFAULT_SOURCES, [], 8_388_608)
    except Exception as exc:
        log.error("Cannot parse %s: %s", path, exc)
        return SourceConfig(DEFAULT_SOURCES, [], 8_388_608)

    sources: list[Source] = []
    for item in raw.get("sources") or []:
        if not isinstance(item, dict) or not item.get("url"):
            continue
        sources.append(
            Source(
                name=str(item.get("name") or item["url"])[:80],
                url=str(item["url"]),
                tier=int(item.get("tier") or 1),
                enabled=bool(item.get("enabled", True)),
            )
        )
    mirrors = [str(prefix) for prefix in (raw.get("mirrors") or []) if prefix]
    max_bytes = int(raw.get("max_bytes") or 8_388_608)
    return SourceConfig(sources or DEFAULT_SOURCES, mirrors, max_bytes)


def _decode_content(raw: bytes) -> str:
    for encoding in ("utf-8-sig", "utf-8"):
        try:
            return raw.decode(encoding)
        except UnicodeDecodeError:
            continue
    return raw.decode("utf-8", errors="ignore")


def extract_uris(text: str) -> list[str]:
    text = text.lstrip("\ufeff").strip()
    if not text:
        return []

    if "://" not in text:
        decoded = decode_b64(text)
        if "://" in decoded:
            text = decoded

    found: list[str] = []
    for raw_line in text.splitlines():
        line = raw_line.strip().strip("'\"")
        if not line or line.startswith("#") or line.startswith("//"):
            continue
        matches = URI_RE.findall(line)
        if matches:
            found.extend(matches)
            continue
        if "@" in line and "?" in line:
            found.append("vless://" + line)
            continue
        if is_probably_base64(line):
            decoded = decode_b64(line)
            if "://" in decoded:
                found.extend(URI_RE.findall(decoded))
        if len(found) >= MAX_URIS_PER_SOURCE:
            break
    return found[:MAX_URIS_PER_SOURCE]


async def _fetch_one(
    client: httpx.AsyncClient,
    source: Source,
    config: SourceConfig,
    semaphore: asyncio.Semaphore,
) -> tuple[list[str], dict[str, Any]]:
    urls = [source.url]
    for mirror in config.mirrors:
        urls.append(mirror.rstrip("/") + "/" + source.url)

    stats: dict[str, Any] = {
        "name": source.name,
        "url": source.url,
        "tier": source.tier,
        "status": "error",
        "bytes": 0,
        "uris": 0,
        "error": "",
    }

    async with semaphore:
        for url in urls:
            try:
                async with client.stream("GET", url, timeout=httpx.Timeout(20.0, connect=10.0)) as response:
                    if response.status_code != 200:
                        stats["error"] = f"HTTP {response.status_code}"
                        continue
                    buffer = bytearray()
                    async for chunk in response.aiter_bytes():
                        buffer.extend(chunk)
                        if len(buffer) >= config.max_bytes:
                            break
                    text = _decode_content(bytes(buffer))
                    uris = extract_uris(text)
                    stats.update(status="ok", bytes=len(buffer), uris=len(uris), error="")
                    return uris, stats
            except Exception as exc:
                stats["error"] = type(exc).__name__
                continue

    log.warning("Source %s failed: %s", source.name, stats["error"])
    return [], stats


async def fetch_all(
    settings: Settings, tiers: set[int] | None = None
) -> tuple[list[FetchedLine], list[dict[str, Any]]]:
    config = load_source_config(settings.sources_file)
    selected = [
        source
        for source in config.sources
        if source.enabled and (tiers is None or source.tier in tiers)
    ]
    if not selected:
        return [], []

    semaphore = asyncio.Semaphore(FETCH_CONCURRENCY)
    headers = {"User-Agent": USER_AGENT, "Accept": "*/*"}
    async with httpx.AsyncClient(headers=headers, follow_redirects=True, trust_env=False) as client:
        results = await asyncio.gather(
            *(_fetch_one(client, source, config, semaphore) for source in selected)
        )

    lines: list[FetchedLine] = []
    stats: list[dict[str, Any]] = []
    for source, (uris, stat) in zip(selected, results, strict=False):
        stats.append(stat)
        for uri in uris:
            lines.append(FetchedLine(uri=uri, source=source.name, tier=source.tier))

    log.info(
        "Fetched %d URIs from %d sources (%d ok)",
        len(lines),
        len(stats),
        sum(1 for item in stats if item["status"] == "ok"),
    )
    return lines, stats
