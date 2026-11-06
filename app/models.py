from __future__ import annotations

import hashlib
import time
from dataclasses import dataclass, field
from typing import Any


@dataclass(slots=True)
class Node:
    """Parsed proxy node in a protocol-agnostic form."""

    protocol: str
    host: str
    port: int
    credential: str
    params: dict[str, Any] = field(default_factory=dict)
    uri: str = ""
    remark: str = ""
    source: str = ""

    def identity(self) -> str:
        p = self.params
        parts = [self.protocol, self.host.lower(), str(self.port), self.credential]
        if self.protocol in ("vless", "vmess", "trojan"):
            parts += [
                str(p.get("network", "tcp")),
                str(p.get("security", "none")),
                str(p.get("sni", "")),
                str(p.get("path", "")),
                str(p.get("service_name", "")),
                str(p.get("host", "")),
            ]
        elif self.protocol == "ss":
            parts += [str(p.get("method", "")), str(p.get("plugin", ""))]
        elif self.protocol == "hysteria2":
            parts += [str(p.get("sni", "")), str(p.get("obfs", ""))]
        return "|".join(parts)

    @property
    def tag(self) -> str:
        digest = hashlib.sha1(self.identity().encode("utf-8")).hexdigest()[:10]
        return f"{self.protocol}-{digest}"

    def to_dict(self) -> dict[str, Any]:
        return {
            "protocol": self.protocol,
            "host": self.host,
            "port": self.port,
            "credential": self.credential,
            "params": self.params,
            "uri": self.uri,
            "remark": self.remark,
            "source": self.source,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Node:
        return cls(
            protocol=data["protocol"],
            host=data["host"],
            port=int(data["port"]),
            credential=data["credential"],
            params=data.get("params") or {},
            uri=data.get("uri", ""),
            remark=data.get("remark", ""),
            source=data.get("source", ""),
        )


@dataclass(slots=True)
class CheckResult:
    node: Node
    ok: bool
    latency_ms: int | None = None
    error: str | None = None
    checked_at: int = field(default_factory=lambda: int(time.time()))


@dataclass(slots=True)
class LiveNode:
    node: Node
    latency_ms: int
    score: float
    checked_at: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "node": self.node.to_dict(),
            "latency_ms": self.latency_ms,
            "score": self.score,
            "checked_at": self.checked_at,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> LiveNode:
        return cls(
            node=Node.from_dict(data["node"]),
            latency_ms=int(data.get("latency_ms", 0)),
            score=float(data.get("score", 0)),
            checked_at=int(data.get("checked_at", 0)),
        )
