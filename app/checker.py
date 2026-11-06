from __future__ import annotations

import asyncio
import json
import logging
import os
import socket
import ssl
import tempfile
import time
from pathlib import Path

from app import singbox
from app.config import Settings
from app.models import CheckResult, Node

log = logging.getLogger(__name__)

PROBE_HOST = "cp.cloudflare.com"
PROBE_PATH = "/generate_204"
USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"


class ProxyConnectError(RuntimeError):
    def __init__(self, status: int) -> None:
        super().__init__(f"proxy CONNECT returned {status}")
        self.status = status


class ProbeHttpError(RuntimeError):
    def __init__(self, status: int) -> None:
        super().__init__(f"probe returned {status}")
        self.status = status


def _allocate_ports(count: int) -> list[int]:
    """Ask the OS for free loopback ports (avoids clashes with stale processes)."""
    sockets: list[socket.socket] = []
    ports: list[int] = []
    try:
        for _ in range(count):
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind(("127.0.0.1", 0))
            ports.append(int(sock.getsockname()[1]))
            sockets.append(sock)
    finally:
        for sock in sockets:
            sock.close()
    return ports


def _classify_error(exc: BaseException) -> str:
    if isinstance(exc, (TimeoutError, asyncio.TimeoutError)):
        return "timeout"
    if isinstance(exc, ProxyConnectError):
        return f"proxy-{exc.status}"
    if isinstance(exc, ProbeHttpError):
        return f"http-{exc.status}"
    if isinstance(exc, ssl.SSLError):
        return "tls"
    if isinstance(exc, ConnectionRefusedError):
        return "refused"
    if isinstance(exc, OSError):
        return "network"
    return type(exc).__name__.lower()


def _status_code(head: bytes) -> int:
    first_line = head.split(b"\r\n", 1)[0].decode("latin-1", "ignore")
    parts = first_line.split()
    if len(parts) < 2:
        return 0
    try:
        return int(parts[1])
    except ValueError:
        return 0


async def _read_head(reader: asyncio.StreamReader, limit: int = 65536) -> bytes:
    data = bytearray()
    while b"\r\n\r\n" not in data:
        chunk = await reader.read(4096)
        if not chunk:
            break
        data.extend(chunk)
        if len(data) >= limit:
            break
    return bytes(data)


class Checker:
    """Batch health checker: one sing-box process per batch, raw-socket probes."""

    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self.singbox_path = settings.singbox_path

    async def check_many(self, nodes: list[Node]) -> list[CheckResult]:
        results: list[CheckResult] = []
        batch_size = self.settings.batch_size
        for batch_index, start in enumerate(range(0, len(nodes), batch_size)):
            batch = nodes[start : start + batch_size]
            if not batch:
                continue
            started = time.monotonic()
            batch_results = await self._check_batch_with_fallback(batch)
            alive = sum(1 for result in batch_results if result.ok)
            log.info(
                "Batch %d: %d/%d alive in %.1fs",
                batch_index,
                alive,
                len(batch_results),
                time.monotonic() - started,
            )
            results.extend(batch_results)
        return results

    async def _check_batch_with_fallback(self, nodes: list[Node]) -> list[CheckResult]:
        if not nodes:
            return []
        result = await self._run_batch(nodes)
        if result is not None:
            return result
        log.warning("sing-box rejected config for %d nodes, splitting", len(nodes))
        if len(nodes) == 1:
            return [CheckResult(node=nodes[0], ok=False, error="invalid-config")]
        middle = len(nodes) // 2
        left = await self._check_batch_with_fallback(nodes[:middle])
        right = await self._check_batch_with_fallback(nodes[middle:])
        return left + right

    async def _run_batch(self, nodes: list[Node]) -> list[CheckResult] | None:
        for attempt in range(2):
            ports = _allocate_ports(len(nodes))
            built = singbox.build_check_config(nodes, ports)
            if built is None:
                return None
            config, port_map = built

            handle, config_path = tempfile.mkstemp(prefix="sb-check-", suffix=".json")
            process: asyncio.subprocess.Process | None = None
            try:
                with os.fdopen(handle, "w", encoding="utf-8") as file:
                    json.dump(config, file, ensure_ascii=False)
                process = await asyncio.create_subprocess_exec(
                    self.singbox_path,
                    "run",
                    "-c",
                    config_path,
                    stdout=asyncio.subprocess.DEVNULL,
                    stderr=asyncio.subprocess.DEVNULL,
                )
                ready = await self._wait_ready(process, [port for port, _ in port_map])
                if not ready:
                    if attempt == 0:
                        log.warning("Batch of %d did not start, retrying on new ports", len(nodes))
                        continue
                    return None

                semaphore = asyncio.Semaphore(self.settings.probe_concurrency)

                async def probe(
                    port: int, node: Node, semaphore: asyncio.Semaphore = semaphore
                ) -> CheckResult:
                    async with semaphore:
                        return await self._probe(port, node)

                tasks = [probe(port, node) for port, node in port_map]
                try:
                    return await asyncio.wait_for(
                        asyncio.gather(*tasks),
                        timeout=self.settings.check_timeout + 15.0,
                    )
                except TimeoutError:
                    return [
                        CheckResult(node=node, ok=False, error="batch-timeout")
                        for _, node in port_map
                    ]
            finally:
                if process is not None:
                    await self._stop(process)
                try:
                    Path(config_path).unlink(missing_ok=True)
                except OSError:
                    pass
        return None

    async def _wait_ready(
        self, process: asyncio.subprocess.Process, ports: list[int]
    ) -> bool:
        remaining = set(ports)
        deadline = time.monotonic() + 3.0
        while remaining and time.monotonic() < deadline:
            if process.returncode is not None:
                return False
            for port in list(remaining):
                try:
                    reader, writer = await asyncio.open_connection("127.0.0.1", port)
                    writer.close()
                    del reader
                    remaining.discard(port)
                except OSError:
                    continue
            if remaining:
                await asyncio.sleep(0.05)
        return not remaining

    async def _probe(self, port: int, node: Node) -> CheckResult:
        started = time.monotonic()
        try:
            async with asyncio.timeout(self.settings.check_timeout):
                await self._http_204(port)
            latency = int((time.monotonic() - started) * 1000)
            return CheckResult(node=node, ok=True, latency_ms=latency)
        except Exception as exc:
            return CheckResult(node=node, ok=False, error=_classify_error(exc))

    async def _http_204(self, port: int) -> None:
        writer: asyncio.StreamWriter | None = None
        try:
            reader, writer = await asyncio.open_connection("127.0.0.1", port)
            connect_request = (
                f"CONNECT {PROBE_HOST}:443 HTTP/1.1\r\n"
                f"Host: {PROBE_HOST}:443\r\n"
                "Proxy-Connection: keep-alive\r\n\r\n"
            )
            writer.write(connect_request.encode("ascii"))
            await writer.drain()

            head = await _read_head(reader)
            status = _status_code(head)
            if status != 200:
                raise ProxyConnectError(status)

            context = ssl.create_default_context()
            await writer.start_tls(context, server_hostname=PROBE_HOST)

            request = (
                f"GET {PROBE_PATH} HTTP/1.1\r\n"
                f"Host: {PROBE_HOST}\r\n"
                f"User-Agent: {USER_AGENT}\r\n"
                "Accept: */*\r\n"
                "Connection: close\r\n\r\n"
            )
            writer.write(request.encode("ascii"))
            await writer.drain()

            head = await _read_head(reader)
            status = _status_code(head)
            if status not in (200, 204):
                raise ProbeHttpError(status)
        finally:
            if writer is not None:
                writer.close()
                abort = getattr(writer.transport, "abort", None)
                if abort is not None:
                    abort()

    async def _stop(self, process: asyncio.subprocess.Process) -> None:
        if process.returncode is not None:
            return
        try:
            process.terminate()
            await asyncio.wait_for(process.wait(), timeout=3.0)
        except (TimeoutError, ProcessLookupError):
            try:
                process.kill()
                await asyncio.wait_for(process.wait(), timeout=2.0)
            except (TimeoutError, ProcessLookupError):
                pass
