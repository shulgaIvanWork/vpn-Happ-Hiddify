from __future__ import annotations

import base64

from app.sources import extract_uris

VLESS = "vless://bcf31ced-07e7-4bd3-ae6d-9280d9a47834@example.com:443?security=tls&type=tcp#A"
TROJAN = "trojan://pass@example.com:443?sni=example.com#T"
SS = "ss://YWVzLTI1Ni1nY206c2VjcmV0@1.2.3.4:8388#S"


def test_plain_lines_and_comments():
    text = f"#profile-title: test\n{VLESS}\n\n{TROJAN}\n// comment\n{SS}\n"
    uris = extract_uris(text)
    assert uris == [VLESS, TROJAN, SS]


def test_whole_file_base64():
    payload = "\n".join([VLESS, TROJAN]).encode()
    encoded = base64.b64encode(payload).decode()
    assert extract_uris(encoded) == [VLESS, TROJAN]


def test_line_by_line_base64():
    encoded = base64.b64encode(VLESS.encode()).decode()
    assert extract_uris(f"# header\n{encoded}\n") == [VLESS]


def test_schemeless_vless_is_repaired():
    line = (
        "bcf31ced-07e7-4bd3-ae6d-9280d9a47834@example.com:443"
        "?security=reality&type=tcp&pbk=abc&sni=example.com&sid=01&fp=chrome"
    )
    uris = extract_uris(line)
    assert uris == ["vless://" + line]


def test_garbage_is_ignored():
    assert extract_uris("hello world\nnot a config\n") == []
