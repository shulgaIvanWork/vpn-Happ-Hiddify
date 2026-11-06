from __future__ import annotations

import base64
import binascii
import re
from urllib.parse import unquote, urlparse

_CONTROL = re.compile(r"[\x00-\x1f\x7f]")

UTLS_FINGERPRINTS = {
    "chrome",
    "firefox",
    "edge",
    "safari",
    "360",
    "qq",
    "ios",
    "android",
    "random",
    "randomized",
}


def b64_decoded_len(text: str) -> int | None:
    """Length of decoded base64 (standard or url-safe), or None if invalid."""
    raw = (text or "").strip()
    if not raw:
        return None
    raw = raw.replace("-", "+").replace("_", "/")
    raw += "=" * (-len(raw) % 4)
    try:
        return len(base64.b64decode(raw, validate=True))
    except (binascii.Error, ValueError):
        return None


def normalize_fingerprint(value: str | None) -> str:
    fingerprint = (value or "").strip().lower()
    return fingerprint if fingerprint in UTLS_FINGERPRINTS else ""


def is_hex(value: str) -> bool:
    return bool(re.fullmatch(r"[0-9a-fA-F]*", value or ""))


def decode_b64(text: str) -> str:
    """Decode standard or url-safe base64 with missing padding."""
    raw = (text or "").strip()
    raw = raw.replace("-", "+").replace("_", "/")
    raw += "=" * (-len(raw) % 4)
    try:
        return base64.b64decode(raw, validate=False).decode("utf-8", errors="ignore")
    except (binascii.Error, ValueError):
        return ""


def is_probably_base64(text: str) -> bool:
    text = text.strip()
    if len(text) < 8 or len(text) % 4 not in (0, 2, 3):
        return False
    return bool(re.fullmatch(r"[A-Za-z0-9+/=_\-]+", text))


def split_uri(uri: str) -> tuple[str, str]:
    """Split URI into the part before '#' and the decoded remark."""
    base, _, fragment = uri.partition("#")
    return base.strip(), clean_remark(unquote(fragment))


def clean_remark(text: str) -> str:
    text = unquote(text or "")
    text = _CONTROL.sub("", text)
    return text.strip()[:80]


def query_dict(query: str) -> dict[str, str]:
    from urllib.parse import parse_qs

    if not query:
        return {}
    parsed = parse_qs(query, keep_blank_values=True)
    return {key: values[-1] for key, values in parsed.items()}


def as_bool(value: object) -> bool:
    if isinstance(value, bool):
        return value
    if value is None:
        return False
    return str(value).strip().lower() in ("1", "true", "yes", "on")


def as_int(value: object, default: int = 0) -> int:
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return default


def alpn_list(value: str | None) -> list[str]:
    if not value:
        return []
    return [item.strip() for item in value.split(",") if item.strip()]


def parse_host_port(value: str) -> tuple[str, int] | None:
    """Parse 'host:port' including bracketed IPv6."""
    value = value.strip()
    if value.startswith("["):
        end = value.find("]")
        if end < 0:
            return None
        host = value[1:end]
        rest = value[end + 1 :]
        if not rest.startswith(":"):
            return None
        port = as_int(rest[1:], 0)
    else:
        if ":" not in value:
            return None
        host, _, port_str = value.rpartition(":")
        port = as_int(port_str, 0)
    if not host or not (0 < port < 65536):
        return None
    return host, port


def safe_urlparse(uri: str):
    try:
        return urlparse(uri)
    except ValueError:
        return None
