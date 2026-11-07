from __future__ import annotations

import asyncio
import json
import logging
import os
import re
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


def _pick_ports(count: int, base: int) -> list[int]:
    """Pick free loopback ports from a dedicated (non-ephemeral) range."""
    ports: list[int] = []
    port = base
    while len(ports) < count and port < 49000:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            sock.bind(("127.0.0.1", port))
        except OSError:
            port += 1
            continue
        finally:
            sock.close()
        ports.append(port)
        port += 1
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


_OUTBOUND_ERROR_RE = re.compile(r"outbound\[(\d+)\]")


def _outbound_error_index(stderr: str) -> int | None:
    match = _OUTBOUND_ERROR_RE.search(stderr)
    return int(match.group(1)) if match else None


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
        self._scan_slot = 0

    def _next_port_base(self) -> int:
        span = max(1, (49_000 - self.settings.port_base) // self.settings.port_band)
        base = self.settings.port_base + (self._scan_slot % span) * self.settings.port_band
        self._scan_slot += 1
        return base

    async def check_many(self, nodes: list[Node]) -> list[CheckResult]:
        results: list[CheckResult] = []
        batch_size = self.settings.batch_size
        port_base = self._next_port_base()
        for batch_index, start in enumerate(range(0, len(nodes), batch_size)):
            batch = nodes[start : start + batch_size]
            if not batch:
                continue
            started = time.monotonic()
            batch_results = await self._check_batch_with_fallback(batch, port_base + start)
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

    async def _check_batch_with_fallback(
        self, nodes: list[Node], base: int
    ) -> list[CheckResult]:
        if not nodes:
            return []
        result = await self._run_batch(nodes, base)
        if result is not None:
            return result
        log.warning("sing-box rejected config for %d nodes, splitting", len(nodes))
        if len(nodes) == 1:
            return [CheckResult(node=nodes[0], ok=False, error="invalid-config")]
        middle = len(nodes) // 2
        left = await self._check_batch_with_fallback(nodes[:middle], base)
        right = await self._check_batch_with_fallback(nodes[middle:], base)
        return left + right

    async def _run_batch(self, nodes: list[Node], base: int) -> list[CheckResult] | None:
        remaining = list(nodes)
        for attempt in range(2):
            while remaining:
                ports = _pick_ports(len(remaining), base + attempt * self.settings.port_band)
                if len(ports) < len(remaining):
                    log.warning("Not enough free ports for %d nodes", len(remaining))
                    return None
                built = singbox.build_check_config(remaining, ports)
                if built is None:
                    return None
                config, port_map = built

                handle, config_path = tempfile.mkstemp(prefix="sb-check-", suffix=".json")
                process: asyncio.subprocess.Process | None = None
                try:
                    with os.fdopen(handle, "w", encoding="utf-8") as file:
                        json.dump(config, file, ensure_ascii=False)

                    valid, error = await self._check_config(config_path)
                    if not valid:
                        index = _outbound_error_index(error)
                        if index is None or not (1 <= index <= len(port_map)):
                            log.warning("Config check failed: %s", error.strip()[-300:])
                            return None
                        bad_node = port_map[index - 1][1]
                        log.warning(
                            "Excluding invalid %s node %s:%s",
                            bad_node.protocol,
                            bad_node.host,
                            bad_node.port,
                        )
                        remaining = [node for node in remaining if node is not bad_node]
                        continue

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
                        log.warning(
                            "Batch of %d did not start, retrying on new ports", len(remaining)
                        )
                        break

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

    async def _check_config(self, config_path: str) -> tuple[bool, str]:
        try:
            process = await asyncio.create_subprocess_exec(
                self.singbox_path,
                "check",
                "-c",
                config_path,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
        except OSError as exc:
            return False, str(exc)
        try:
            _, stderr = await asyncio.wait_for(process.communicate(), timeout=15.0)
        except TimeoutError:
            process.kill()
            await process.wait()
            return False, "config check timeout"
        return process.returncode == 0, stderr.decode("utf-8", "replace")

    async def _wait_ready(
        self, process: asyncio.subprocess.Process, ports: list[int]
    ) -> bool:
        if not ports:
            return False
        # sing-box binds inbounds in order, so the last port is the last to appear.
        # A short per-attempt timeout prevents hangs on half-open loopback sockets.
        deadline = time.monotonic() + 3.0
        await asyncio.sleep(0.2)
        while time.monotonic() < deadline:
            if process.returncode is not None:
                return False
            writer = None
            try:
                async with asyncio.timeout(0.5):
                    reader, writer = await asyncio.open_connection("127.0.0.1", ports[-1])
                writer.close()
                del reader
                return True
            except (OSError, TimeoutError):
                if writer is not None:
                    writer.close()
                if process.returncode is not None:
                    return False
                await asyncio.sleep(0.1)
        return False

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
