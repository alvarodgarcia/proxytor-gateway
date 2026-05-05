#!/usr/bin/env python3
import argparse
import ipaddress
import json
import os
import signal
import socket
import subprocess
import sys
from pathlib import Path


SAFE_ENV = {
    "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
    "LANG": "C.UTF-8",
    "LC_ALL": "C.UTF-8",
}

ACTION_SERVICES = {
    "tor": "tor@default",
    "privoxy": "privoxy",
}

LOG_SERVICES = {
    "tor": "tor@default",
    "privoxy": "privoxy",
    "api": "proxytor-api",
    "telegram": "proxytor-telegram-bot",
    "token-rotate": "proxytor-token-rotate",
}

ALLOWED_ACTIONS = {"restart", "reload"}
DEFAULT_SOCKET = Path("/run/proxytor-root-helper.sock")


def ensure_root():
    if os.geteuid() != 0:
        raise PermissionError("This helper must run as root.")


def validate_ip(value: str) -> str:
    ipaddress.ip_address(value)
    return value


def run(cmd: list[str], timeout: int = 15) -> dict:
    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        env=SAFE_ENV,
        timeout=timeout,
    )
    return {
        "returncode": int(result.returncode),
        "stdout": result.stdout.strip(),
        "stderr": result.stderr.strip(),
    }


def ensure_ban_chain() -> dict:
    run(["iptables", "-N", "PROXYTOR_BAN"])
    check = subprocess.run(
        [
            "iptables",
            "-C",
            "INPUT",
            "-p",
            "tcp",
            "-m",
            "multiport",
            "--dports",
            "9050,8118",
            "-j",
            "PROXYTOR_BAN",
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        env=SAFE_ENV,
        timeout=10,
        text=True,
    )
    if check.returncode != 0:
        return run(
            [
                "iptables",
                "-I",
                "INPUT",
                "1",
                "-p",
                "tcp",
                "-m",
                "multiport",
                "--dports",
                "9050,8118",
                "-j",
                "PROXYTOR_BAN",
            ]
        )
    return {"returncode": 0, "stdout": "", "stderr": ""}


def handle_request(payload: dict) -> dict:
    command = payload.get("command", "")

    if command == "service-action":
        service = str(payload.get("service", ""))
        action = str(payload.get("action", ""))
        if service not in ACTION_SERVICES or action not in ALLOWED_ACTIONS:
            return {"returncode": 2, "stdout": "", "stderr": "Service or action not allowed."}
        return run(["systemctl", action, ACTION_SERVICES[service]], timeout=30)

    if command == "logs":
        service = str(payload.get("service", ""))
        lines = max(1, min(int(payload.get("lines", 120)), 500))
        if service not in LOG_SERVICES:
            return {"returncode": 2, "stdout": "", "stderr": "Service not allowed."}
        return run(
            ["journalctl", "-u", LOG_SERVICES[service], "-n", str(lines), "--no-pager"],
            timeout=20,
        )

    if command == "iptables-ensure-chain":
        return ensure_ban_chain()

    if command == "iptables-ban-ip":
        ip = validate_ip(str(payload.get("ip", "")))
        ensured = ensure_ban_chain()
        if ensured["returncode"] != 0:
            return ensured
        check = subprocess.run(
            ["iptables", "-C", "PROXYTOR_BAN", "-s", ip, "-j", "DROP"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            env=SAFE_ENV,
            timeout=10,
            text=True,
        )
        if check.returncode == 0:
            return {"returncode": 0, "stdout": "", "stderr": ""}
        return run(["iptables", "-A", "PROXYTOR_BAN", "-s", ip, "-j", "DROP"])

    if command == "iptables-unban-ip":
        ip = validate_ip(str(payload.get("ip", "")))
        while True:
            result = subprocess.run(
                ["iptables", "-D", "PROXYTOR_BAN", "-s", ip, "-j", "DROP"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                env=SAFE_ENV,
                timeout=10,
                text=True,
            )
            if result.returncode != 0:
                break
        return {"returncode": 0, "stdout": "", "stderr": ""}

    return {"returncode": 2, "stdout": "", "stderr": f"Unknown command: {command}"}


def run_server(socket_path: Path, group_name: str) -> int:
    ensure_root()
    socket_path.parent.mkdir(parents=True, exist_ok=True)
    if socket_path.exists():
        socket_path.unlink()

    group_info = None
    if group_name:
        import grp
        group_info = grp.getgrnam(group_name)

    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    server.bind(str(socket_path))
    os.chmod(socket_path, 0o660)
    if group_info:
        os.chown(socket_path, 0, group_info.gr_gid)
    server.listen(16)

    stop = {"value": False}

    def _stop(_signum, _frame):
        stop["value"] = True
        try:
            server.close()
        except Exception:
            pass

    signal.signal(signal.SIGTERM, _stop)
    signal.signal(signal.SIGINT, _stop)

    while not stop["value"]:
        try:
            conn, _ = server.accept()
        except OSError:
            break
        with conn:
            try:
                raw = b""
                while True:
                    chunk = conn.recv(65536)
                    if not chunk:
                        break
                    raw += chunk

                payload = json.loads(raw.decode("utf-8") or "{}")
                response = handle_request(payload)
            except Exception as exc:
                response = {"returncode": 1, "stdout": "", "stderr": str(exc)}

            conn.sendall(json.dumps(response).encode("utf-8"))

    try:
        socket_path.unlink()
    except FileNotFoundError:
        pass
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="ProxyTor privileged helper")
    subparsers = parser.add_subparsers(dest="command", required=True)

    server = subparsers.add_parser("server")
    server.add_argument("--socket", default=str(DEFAULT_SOCKET))
    server.add_argument("--group", default="proxytor-api")

    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    if args.command == "server":
        return run_server(Path(args.socket), args.group)

    return 2


if __name__ == "__main__":
    raise SystemExit(main())
