from __future__ import annotations

import os
import sys

import paramiko


def main() -> int:
    host = os.environ.get("VPNSERVER_HOST", "185.17.0.143")
    user = os.environ.get("VPNSERVER_USER", "root")
    password = os.environ.get("VPNSERVER_PASSWORD")
    if not password:
        print("VPNSERVER_PASSWORD is not set", file=sys.stderr)
        return 2

    command = sys.stdin.read()
    if not command.strip():
        print("Pass a shell command via stdin", file=sys.stderr)
        return 2

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(
        host,
        username=user,
        password=password,
        timeout=20,
        banner_timeout=20,
        auth_timeout=20,
        allow_agent=False,
        look_for_keys=False,
    )
    try:
        _, stdout, stderr = client.exec_command(
            command, timeout=int(os.environ.get("REMOTE_TIMEOUT", "1800"))
        )
        sys.stdout.write(stdout.read().decode("utf-8", "replace"))
        error = stderr.read().decode("utf-8", "replace")
        if error:
            sys.stderr.write("STDERR:\n" + error)
        code = stdout.channel.recv_exit_status()
        print(f"\nEXIT: {code}")
        return code
    finally:
        client.close()


if __name__ == "__main__":
    raise SystemExit(main())
