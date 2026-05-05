import os
import json
import html
import time
import csv
import io
from datetime import datetime, timedelta
import socket
import sqlite3
import secrets
import ipaddress
import subprocess
import threading
from pathlib import Path
from typing import Optional
from collections import defaultdict, deque

import psutil
import requests
from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.responses import HTMLResponse, Response
from stem import Signal
from stem.control import Controller


BASE_DIR = Path("/etc/proxytor-api")
DATA_DIR = Path("/var/lib/proxytor-api")
ROOT_HELPER_SOCKET = Path("/run/proxytor-root-helper.sock")

TOKEN_FILE = BASE_DIR / "token"
VIEWER_TOKEN_FILE = BASE_DIR / "token.viewer"
TOKEN_PREVIOUS_FILE = BASE_DIR / "token.previous"
CONFIG_FILE = BASE_DIR / "config.json"
DB_FILE = DATA_DIR / "proxytor.db"
PREVIOUS_TOKEN_GRACE_SECONDS = 600
AUTH_FAILURE_LIMIT = 10
AUTH_FAILURE_WINDOW_SECONDS = 300
ADMIN_ACTION_LIMIT = 20
ADMIN_ACTION_WINDOW_SECONDS = 60
GEOLOOKUP_URL = "https://ipwho.is/{ip}"
GEOIP_CACHE_TTL_SECONDS = 3600
HTTP_USER_AGENT = "ProxyTor-Gateway/3.0"
SAFE_SUBPROCESS_ENV = {
    "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
    "LANG": "C.UTF-8",
    "LC_ALL": "C.UTF-8",
}

TELEGRAM_CONFIG = Path("/etc/default/proxytor-telegram")

TOR_CONTROL_HOST = "127.0.0.1"
TOR_CONTROL_PORT = 9051
TOR_SOCKS = "socks5h://127.0.0.1:9050"
PRIVOXY_HTTP = "http://127.0.0.1:8118"

EXIT_CACHE = {
    "tor": {"ts": 0, "data": {}},
    "privoxy": {"ts": 0, "data": {}},
}

LAST_TRAFFIC_SAMPLE = None
LAST_ALERTS = {}
OUI_CACHE = None
GEOIP_CACHE = {}
RATE_LIMIT_STATE = defaultdict(deque)
RATE_LIMIT_LOCK = threading.Lock()

LOG_SERVICES = {
    "tor": "tor@default",
    "privoxy": "privoxy",
    "api": "proxytor-api",
    "telegram": "proxytor-telegram-bot",
    "token-rotate": "proxytor-token-rotate",
}

ACTION_SERVICES = {
    "tor": "tor@default",
    "privoxy": "privoxy",
}

ALLOWED_ACTIONS = {"restart", "reload"}

DEFAULT_CONFIG = {
    "npmplus_ips": ["NPMPLUS_IP_1", "NPMPLUS_IP_2", "NPMPLUS_VIP"],
    "recent_minutes": 10,
    "alert_service_down": True,
    "alert_exit_ip_change": False,
    "alert_new_client": False,
    "alert_connection_threshold": 30,
    "telegram_alerts": True,
    "events_view_limit": 50,
    "events_max_view_limit": 500,
    "events_max_rows": 5000,
    "events_export_enabled": True,
    "device_aliases": {},
    "external_geoip_enabled": True,
    "geoip_cache_minutes": 60,
}

app = FastAPI(
    title="ProxyTor API",
    version="3.0.0",
    description="Dashboard para Tor + Privoxy con SQLite, clientes recientes y alertas",
)

SECURITY_HEADERS = {
    "Content-Security-Policy": "; ".join(
        [
            "default-src 'self'",
            "base-uri 'self'",
            "object-src 'none'",
            "frame-ancestors 'none'",
            "img-src 'self' data:",
            "style-src 'self' 'unsafe-inline'",
            "script-src 'self' 'unsafe-inline'",
            "connect-src 'self'",
            "frame-src 'self' https://www.openstreetmap.org",
            "font-src 'self' data:",
            "form-action 'self'",
        ]
    ),
    "Referrer-Policy": "no-referrer",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Permissions-Policy": (
        "accelerometer=(), autoplay=(), camera=(), display-capture=(), "
        "fullscreen=(), geolocation=(), gyroscope=(), magnetometer=(), "
        "microphone=(), midi=(), payment=(), usb=()"
    ),
    "Cross-Origin-Resource-Policy": "same-origin",
}


@app.middleware("http")
async def apply_security_headers(request: Request, call_next):
    response = await call_next(request)

    for header, value in SECURITY_HEADERS.items():
        response.headers.setdefault(header, value)

    if request.url.scheme == "https":
        response.headers.setdefault(
            "Strict-Transport-Security",
            "max-age=31536000; includeSubDomains",
        )

    if request.url.path == "/" or request.url.path.startswith("/api/"):
        response.headers.setdefault("Cache-Control", "no-store")
        response.headers.setdefault("Pragma", "no-cache")

    return response


def now_ts() -> int:
    return int(time.time())


def fmt_ts(ts: int) -> str:
    try:
        return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(int(ts)))
    except Exception:
        return ""


def ensure_files():
    BASE_DIR.mkdir(parents=True, exist_ok=True)
    DATA_DIR.mkdir(parents=True, exist_ok=True)

    if not TOKEN_FILE.exists():
        TOKEN_FILE.write_text(secrets.token_hex(32) + "\n")
        os.chmod(TOKEN_FILE, 0o600)

    if not VIEWER_TOKEN_FILE.exists():
        VIEWER_TOKEN_FILE.write_text(secrets.token_hex(32) + "\n")
        os.chmod(VIEWER_TOKEN_FILE, 0o600)

    if not CONFIG_FILE.exists():
        CONFIG_FILE.write_text(json.dumps(DEFAULT_CONFIG, indent=2) + "\n")
        os.chmod(CONFIG_FILE, 0o600)


def read_text_file(path: Path) -> str:
    try:
        return path.read_text().strip()
    except Exception:
        return ""


def read_current_token() -> str:
    return read_text_file(TOKEN_FILE)


def read_viewer_token() -> str:
    return read_text_file(VIEWER_TOKEN_FILE)


def read_previous_admin_token() -> str:
    try:
        if not TOKEN_PREVIOUS_FILE.exists():
            return ""

        age = now_ts() - int(TOKEN_PREVIOUS_FILE.stat().st_mtime)
        if age > PREVIOUS_TOKEN_GRACE_SECONDS:
            return ""

        return TOKEN_PREVIOUS_FILE.read_text().strip()
    except Exception:
        return ""


def get_request_ip(request: Request) -> str:
    try:
        if request.client and request.client.host:
            return request.client.host
    except Exception:
        pass

    return "unknown"


def run_root_helper(args: list[str], timeout: int = 20) -> dict:
    if not ROOT_HELPER_SOCKET.exists():
        return {
            "cmd": "root-helper-socket " + " ".join(args),
            "returncode": 127,
            "stdout": "",
            "stderr": f"Root helper socket not found: {ROOT_HELPER_SOCKET}",
        }
    command = args[0] if args else ""
    payload: dict[str, object] = {"command": command}
    index = 1
    while index < len(args):
        key = args[index]
        if key.startswith("--"):
            field = key[2:].replace("-", "_")
            value = args[index + 1] if index + 1 < len(args) else ""
            payload[field] = value
            index += 2
            continue
        if "service" not in payload:
            payload["service"] = key
        elif "action" not in payload:
            payload["action"] = key
        elif "ip" not in payload:
            payload["ip"] = key
        else:
            payload.setdefault("args", []).append(key)
        index += 1

    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
            client.settimeout(timeout)
            client.connect(str(ROOT_HELPER_SOCKET))
            client.sendall((json.dumps(payload) + "\n").encode("utf-8"))
            client.shutdown(socket.SHUT_WR)

            chunks: list[bytes] = []
            while True:
                chunk = client.recv(65536)
                if not chunk:
                    break
                chunks.append(chunk)

        response = json.loads(b"".join(chunks).decode("utf-8") or "{}")
        return {
            "cmd": "root-helper-socket " + " ".join(args),
            "returncode": int(response.get("returncode", 1)),
            "stdout": str(response.get("stdout", "")).strip(),
            "stderr": str(response.get("stderr", "")).strip(),
        }
    except Exception as exc:
        return {
            "cmd": "root-helper-socket " + " ".join(args),
            "returncode": 1,
            "stdout": "",
            "stderr": str(exc),
        }


def _rate_limit_retry_after(
    bucket: str,
    key: str,
    limit: int,
    window_seconds: int,
    *,
    consume: bool,
) -> int:
    now = time.monotonic()
    state_key = (bucket, key)

    with RATE_LIMIT_LOCK:
        events = RATE_LIMIT_STATE[state_key]
        cutoff = now - window_seconds

        while events and events[0] <= cutoff:
            events.popleft()

        if len(events) >= limit:
            return max(1, int(window_seconds - (now - events[0])))

        if consume:
            events.append(now)

        if not events:
            RATE_LIMIT_STATE.pop(state_key, None)

    return 0


def enforce_auth_failure_limit(request: Request):
    retry_after = _rate_limit_retry_after(
        "auth-failure",
        get_request_ip(request),
        AUTH_FAILURE_LIMIT,
        AUTH_FAILURE_WINDOW_SECONDS,
        consume=False,
    )

    if retry_after:
        log_event(
            "warning",
            "auth_rate_limited",
            "Rate limit de autenticacion activado",
            {"retry_after": retry_after},
            source_ip=get_request_ip(request),
        )
        raise HTTPException(
            status_code=429,
            detail="Demasiados intentos de autenticacion fallidos. Intenta mas tarde.",
            headers={"Retry-After": str(retry_after)},
        )


def register_auth_failure(request: Request):
    _rate_limit_retry_after(
        "auth-failure",
        get_request_ip(request),
        AUTH_FAILURE_LIMIT,
        AUTH_FAILURE_WINDOW_SECONDS,
        consume=True,
    )


def enforce_admin_action_limit(request: Request):
    retry_after = _rate_limit_retry_after(
        "admin-action",
        get_request_ip(request),
        ADMIN_ACTION_LIMIT,
        ADMIN_ACTION_WINDOW_SECONDS,
        consume=True,
    )

    if retry_after:
        log_event(
            "warning",
            "admin_action_rate_limited",
            "Rate limit de acciones administrativas activado",
            {"retry_after": retry_after},
            source_ip=get_request_ip(request),
        )
        raise HTTPException(
            status_code=429,
            detail="Demasiadas acciones administrativas en poco tiempo. Intenta mas tarde.",
            headers={"Retry-After": str(retry_after)},
        )


def _validate_bool(config: dict, key: str, default: bool) -> bool:
    value = config.get(key, default)
    if not isinstance(value, bool):
        raise HTTPException(status_code=400, detail=f"{key} must be a boolean")
    return value


def _validate_int(
    config: dict,
    key: str,
    default: int,
    *,
    min_value: int,
    max_value: int,
) -> int:
    value = config.get(key, default)
    if isinstance(value, bool) or not isinstance(value, int):
        raise HTTPException(status_code=400, detail=f"{key} must be an integer")
    if value < min_value or value > max_value:
        raise HTTPException(
            status_code=400,
            detail=f"{key} must be between {min_value} and {max_value}",
        )
    return value


def _validate_ip_list(config: dict, key: str) -> list[str]:
    value = config.get(key, DEFAULT_CONFIG.get(key, []))
    if not isinstance(value, list):
        raise HTTPException(status_code=400, detail=f"{key} must be a list")

    normalized: list[str] = []
    for item in value:
        if not isinstance(item, str):
            raise HTTPException(
                status_code=400, detail=f"{key} entries must be strings"
            )

        candidate = item.strip()
        if not candidate:
            continue

        try:
            ipaddress.ip_address(candidate)
        except ValueError:
            if candidate.startswith("NPMPLUS_") or candidate.endswith("_IP"):
                normalized.append(candidate)
                continue
            raise HTTPException(
                status_code=400,
                detail=f"{key} contains an invalid IP value: {candidate}",
            )

        normalized.append(candidate)

    return normalized


def _validate_port_list(config: dict, key: str) -> list[int]:
    value = config.get(key, ABUSE_DEFAULTS.get(key, []))
    if not isinstance(value, list):
        raise HTTPException(status_code=400, detail=f"{key} must be a list")

    ports: list[int] = []
    for item in value:
        if isinstance(item, bool) or not isinstance(item, int):
            raise HTTPException(
                status_code=400, detail=f"{key} entries must be integers"
            )
        if item < 1 or item > 65535:
            raise HTTPException(
                status_code=400,
                detail=f"{key} contains an out-of-range port: {item}",
            )
        ports.append(item)

    return ports


def validate_config_payload(config: dict) -> dict:
    if not isinstance(config, dict):
        raise HTTPException(status_code=400, detail="Config payload must be an object")

    validated = DEFAULT_CONFIG.copy()
    validated.update(ABUSE_DEFAULTS)

    validated["npmplus_ips"] = _validate_ip_list(config, "npmplus_ips")
    validated["protected_ips"] = _validate_ip_list(config, "protected_ips")

    validated["recent_minutes"] = _validate_int(
        config, "recent_minutes", DEFAULT_CONFIG["recent_minutes"], min_value=1, max_value=1440
    )
    validated["alert_connection_threshold"] = _validate_int(
        config,
        "alert_connection_threshold",
        DEFAULT_CONFIG["alert_connection_threshold"],
        min_value=1,
        max_value=100000,
    )
    validated["events_view_limit"] = _validate_int(
        config,
        "events_view_limit",
        DEFAULT_CONFIG["events_view_limit"],
        min_value=1,
        max_value=500,
    )
    validated["events_max_view_limit"] = _validate_int(
        config,
        "events_max_view_limit",
        DEFAULT_CONFIG["events_max_view_limit"],
        min_value=1,
        max_value=5000,
    )
    validated["events_max_rows"] = _validate_int(
        config,
        "events_max_rows",
        DEFAULT_CONFIG["events_max_rows"],
        min_value=100,
        max_value=100000,
    )
    validated["geoip_cache_minutes"] = _validate_int(
        config,
        "geoip_cache_minutes",
        DEFAULT_CONFIG["geoip_cache_minutes"],
        min_value=1,
        max_value=1440,
    )
    validated["abuse_connections_per_client"] = _validate_int(
        config,
        "abuse_connections_per_client",
        ABUSE_DEFAULTS["abuse_connections_per_client"],
        min_value=1,
        max_value=100000,
    )
    validated["abuse_alert_interval_seconds"] = _validate_int(
        config,
        "abuse_alert_interval_seconds",
        ABUSE_DEFAULTS["abuse_alert_interval_seconds"],
        min_value=60,
        max_value=86400,
    )
    validated["ban_ports"] = _validate_port_list(config, "ban_ports")

    for key, default in {
        "alert_service_down": DEFAULT_CONFIG["alert_service_down"],
        "alert_exit_ip_change": DEFAULT_CONFIG["alert_exit_ip_change"],
        "alert_new_client": DEFAULT_CONFIG["alert_new_client"],
        "telegram_alerts": DEFAULT_CONFIG["telegram_alerts"],
        "events_export_enabled": DEFAULT_CONFIG["events_export_enabled"],
        "external_geoip_enabled": DEFAULT_CONFIG["external_geoip_enabled"],
        "abuse_detection_enabled": ABUSE_DEFAULTS["abuse_detection_enabled"],
    }.items():
        validated[key] = _validate_bool(config, key, default)

    return validated


def read_config() -> dict:
    config = DEFAULT_CONFIG.copy()
    config.update(ABUSE_DEFAULTS)

    try:
        user_config = json.loads(CONFIG_FILE.read_text())
        if isinstance(user_config, dict):
            config = validate_config_payload(user_config)
    except Exception:
        pass

    return config


def write_config(config: dict):
    merged = validate_config_payload(config)
    CONFIG_FILE.write_text(json.dumps(merged, indent=2) + "\n")
    os.chmod(CONFIG_FILE, 0o600)


def write_new_token(path: Path, previous_path: Optional[Path] = None) -> str:
    new_token = secrets.token_hex(32)

    current = read_text_file(path)
    if current and previous_path:
        previous_path.write_text(current + "\n")
        os.chmod(previous_path, 0o600)

    tmp_file = path.with_suffix(".tmp")
    tmp_file.write_text(new_token + "\n")
    os.chmod(tmp_file, 0o600)
    os.replace(tmp_file, path)
    os.chmod(path, 0o600)

    return new_token


def auth_role_optional(authorization: Optional[str]) -> str:
    admin_token = read_current_token()
    viewer_token = read_viewer_token()
    previous_admin_token = read_previous_admin_token()

    if not authorization or not authorization.startswith("Bearer "):
        return ""

    supplied = authorization.replace("Bearer ", "", 1).strip()

    if admin_token and secrets.compare_digest(supplied, admin_token):
        return "admin"

    if previous_admin_token and secrets.compare_digest(supplied, previous_admin_token):
        return "admin"

    if viewer_token and secrets.compare_digest(supplied, viewer_token):
        return "viewer"

    return ""


def require_auth(
    request: Request,
    authorization: Optional[str],
    required_role: str = "viewer",
) -> str:
    role = auth_role_optional(authorization)

    if role:
        if required_role == "admin" and role != "admin":
            raise HTTPException(status_code=403, detail="Admin token required")

        return role

    enforce_auth_failure_limit(request)
    if not role:
        register_auth_failure(request)
        raise HTTPException(status_code=401, detail="Unauthorized")



def get_db():
    conn = sqlite3.connect(
        DB_FILE,
        timeout=30,
        check_same_thread=False,
        isolation_level=None,
    )
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    conn.execute("PRAGMA busy_timeout=30000")
    return conn


def init_db():
    with get_db() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS traffic_samples (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts INTEGER NOT NULL,
                read_mbps REAL DEFAULT 0,
                written_mbps REAL DEFAULT 0,
                active_clients INTEGER DEFAULT 0,
                active_connections INTEGER DEFAULT 0,
                tor_socks_connections INTEGER DEFAULT 0,
                privoxy_connections INTEGER DEFAULT 0,
                streams_total INTEGER DEFAULT 0,
                circuits_built INTEGER DEFAULT 0
            )
        """)

        conn.execute("""
            CREATE TABLE IF NOT EXISTS clients (
                ip TEXT PRIMARY KEY,
                hostname TEXT DEFAULT '',
                mac TEXT DEFAULT '',
                vendor TEXT DEFAULT '',
                device_type TEXT DEFAULT '',
                first_seen INTEGER,
                last_seen INTEGER,
                total_observations INTEGER DEFAULT 0,
                tor_socks_observations INTEGER DEFAULT 0,
                privoxy_observations INTEGER DEFAULT 0,
                last_tor_socks_connections INTEGER DEFAULT 0,
                last_privoxy_connections INTEGER DEFAULT 0,
                last_total_connections INTEGER DEFAULT 0,
                via_npmplus INTEGER DEFAULT 0,
                last_service TEXT DEFAULT ''
            )
        """)

        conn.execute("""
            CREATE TABLE IF NOT EXISTS events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts INTEGER NOT NULL,
                severity TEXT DEFAULT 'info',
                event_type TEXT DEFAULT '',
                message TEXT DEFAULT '',
                details TEXT DEFAULT '',
                source_ip TEXT DEFAULT ''
            )
        """)

        conn.execute("""
            CREATE TABLE IF NOT EXISTS exit_ips (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts INTEGER NOT NULL,
                ip_tor TEXT DEFAULT '',
                istor_tor INTEGER DEFAULT 0,
                ip_privoxy TEXT DEFAULT '',
                istor_privoxy INTEGER DEFAULT 0,
                country TEXT DEFAULT '',
                asn TEXT DEFAULT '',
                isp TEXT DEFAULT ''
            )
        """)

        conn.execute("CREATE INDEX IF NOT EXISTS idx_traffic_ts ON traffic_samples(ts)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_clients_last_seen ON clients(last_seen)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_exit_ts ON exit_ips(ts)")
        conn.commit()




def log_event(severity: str, event_type: str, message: str, details: Optional[dict] = None, source_ip: str = ""):
    details = details or {}

    try:
        config = read_config()
        max_rows = int(config.get("events_max_rows", 5000))

        with get_db() as conn:
            conn.execute(
                """
                INSERT INTO events (ts, severity, event_type, message, details, source_ip)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    now_ts(),
                    severity,
                    event_type,
                    message,
                    json.dumps(details, ensure_ascii=False),
                    source_ip,
                ),
            )

            if max_rows > 0:
                total = conn.execute("SELECT COUNT(*) AS c FROM events").fetchone()["c"]
                extra = int(total) - max_rows

                if extra > 0:
                    conn.execute(
                        """
                        DELETE FROM events
                        WHERE id IN (
                            SELECT id
                            FROM events
                            ORDER BY ts ASC
                            LIMIT ?
                        )
                        """,
                        (extra,),
                    )

    except sqlite3.OperationalError:
        # Mejor perder un evento puntual que tumbar el dashboard.
        pass
    except Exception:
        pass


def parse_env_file(path: Path) -> dict:
    data = {}

    if not path.exists():
        return data

    for line in path.read_text().splitlines():
        line = line.strip()

        if not line or line.startswith("#") or "=" not in line:
            continue

        key, value = line.split("=", 1)
        data[key.strip()] = value.strip().strip('"').strip("'")

    return data


def maybe_alert(key: str, title: str, body: str, min_interval: int = 900):
    current = now_ts()
    last = LAST_ALERTS.get(key, 0)

    if current - last < min_interval:
        return

    LAST_ALERTS[key] = current

    msg = (
        f"<b>{html.escape(title)}</b>\n\n"
        f"{html.escape(body)}\n\n"
        f"Fecha: <code>{html.escape(fmt_ts(current))}</code>"
    )

    send_telegram_message(msg)


def port_open(host: str, port: int, timeout: float = 2.0) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except Exception:
        return False


def systemctl_is_active(service: str) -> bool:
    result = subprocess.run(
        ["systemctl", "is-active", "--quiet", service],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        env=SAFE_SUBPROCESS_ENV,
    )
    return result.returncode == 0


def systemctl_action(service: str, action: str):
    result = run_root_helper(["service-action", service, action], timeout=35)
    result["service"] = service
    result["action"] = action
    return result


def get_journal(service: str, lines: int = 120):
    if service not in LOG_SERVICES:
        raise HTTPException(status_code=400, detail="Servicio no permitido")

    lines = max(1, min(lines, 500))
    result = run_root_helper(["logs", service, "--lines", str(lines)], timeout=25)

    return {
        "service": LOG_SERVICES[service],
        "returncode": result["returncode"],
        "logs": result["stdout"] or result["stderr"],
    }


def tor_controller():
    controller = Controller.from_port(
        address=TOR_CONTROL_HOST,
        port=TOR_CONTROL_PORT,
    )
    controller.authenticate()
    return controller


def get_tor_info():
    info = {
        "control_port": port_open("127.0.0.1", 9051),
        "socks_port": port_open("127.0.0.1", 9050),
        "service_active": systemctl_is_active("tor@default"),
    }

    try:
        with tor_controller() as controller:
            circuits = controller.get_info("circuit-status", "")
            streams = controller.get_info("stream-status", "")
            traffic_read = controller.get_info("traffic/read", "0")
            traffic_written = controller.get_info("traffic/written", "0")

            built_circuits = [
                line for line in circuits.splitlines()
                if " BUILT " in f" {line} "
            ]

            info.update({
                "version": str(controller.get_version()),
                "circuits_total": len(circuits.splitlines()) if circuits else 0,
                "circuits_built": len(built_circuits),
                "streams_total": len(streams.splitlines()) if streams else 0,
                "traffic_read_bytes": int(traffic_read),
                "traffic_written_bytes": int(traffic_written),
                "traffic_read_mb": round(int(traffic_read) / 1024 / 1024, 2),
                "traffic_written_mb": round(int(traffic_written) / 1024 / 1024, 2),
                "newnym_available": controller.is_newnym_available(),
                "newnym_wait_seconds": controller.get_newnym_wait(),
            })
    except Exception as exc:
        info["control_error"] = str(exc)

    return info


def cached_request_exit(kind: str, proxy: str):
    cache = EXIT_CACHE[kind]

    if now_ts() - cache["ts"] < 60 and cache["data"]:
        return cache["data"]

    try:
        response = requests.get(
            "https://check.torproject.org/api/ip",
            proxies={
                "http": proxy,
                "https": proxy,
            },
            headers={"User-Agent": HTTP_USER_AGENT, "Accept": "application/json"},
            timeout=20,
        )
        response.raise_for_status()
        data = response.json()
    except Exception as exc:
        data = {"error": str(exc)}

    EXIT_CACHE[kind] = {
        "ts": now_ts(),
        "data": data,
    }

    return data


def get_exit_ip_via_tor():
    return cached_request_exit("tor", TOR_SOCKS)


def get_exit_ip_via_privoxy():
    return cached_request_exit("privoxy", PRIVOXY_HTTP)


def geolocate_ip(ip: str) -> dict:
    if not ip:
        return {}

    config = read_config()
    if not config.get("external_geoip_enabled", True):
        return {}

    try:
        ip_obj = ipaddress.ip_address(ip)
        if ip_obj.is_private or ip_obj.is_loopback:
            return {}
    except Exception:
        return {}

    ttl = max(60, int(config.get("geoip_cache_minutes", 60)) * 60)
    cached = GEOIP_CACHE.get(ip)
    if cached and now_ts() - int(cached.get("ts", 0)) < ttl:
        return cached.get("data", {})

    try:
        response = requests.get(
            GEOLOOKUP_URL.format(ip=ip),
            headers={"User-Agent": HTTP_USER_AGENT, "Accept": "application/json"},
            timeout=8,
        )
        response.raise_for_status()
        data = response.json()

        if not data.get("success", False):
            result = {}
        else:
            result = {
                "country": data.get("country", ""),
                "region": data.get("region", ""),
                "city": data.get("city", ""),
                "lat": data.get("latitude", None),
                "lon": data.get("longitude", None),
                "timezone": (data.get("timezone") or {}).get("id", ""),
                "asn": (data.get("connection") or {}).get("asn", ""),
                "isp": (data.get("connection") or {}).get("isp", ""),
            }
        GEOIP_CACHE[ip] = {"ts": now_ts(), "data": result}
        return result
    except Exception:
        GEOIP_CACHE[ip] = {"ts": now_ts(), "data": {}}
        return {}


def store_exit_ips(exit_tor: dict, exit_privoxy: dict, geo: dict):
    ip_tor = exit_tor.get("IP", "")
    ip_privoxy = exit_privoxy.get("IP", "")

    if not ip_tor and not ip_privoxy:
        return

    current = now_ts()

    with get_db() as conn:
        previous = conn.execute(
            "SELECT * FROM exit_ips ORDER BY ts DESC LIMIT 1"
        ).fetchone()

        changed = (
            not previous
            or previous["ip_tor"] != ip_tor
            or previous["ip_privoxy"] != ip_privoxy
        )

        if changed:
            conn.execute(
                """
                INSERT INTO exit_ips (
                    ts, ip_tor, istor_tor, ip_privoxy, istor_privoxy, country, asn, isp
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    current,
                    ip_tor,
                    1 if exit_tor.get("IsTor") is True else 0,
                    ip_privoxy,
                    1 if exit_privoxy.get("IsTor") is True else 0,
                    geo.get("country", ""),
                    geo.get("asn", ""),
                    geo.get("isp", ""),
                ),
            )
            conn.commit()

            if previous and read_config().get("alert_exit_ip_change", False):
                maybe_alert(
                    "exit_ip_change",
                    "ProxyTor: cambio de IP de salida",
                    f"IP anterior: {previous['ip_tor']}\nIP nueva: {ip_tor}",
                    min_interval=60,
                )

            log_event(
                "info",
                "exit_ip_change",
                f"Cambio de IP Tor: {ip_tor}",
                {
                    "ip_tor": ip_tor,
                    "ip_privoxy": ip_privoxy,
                    "geo": geo,
                },
            )


def reverse_dns(ip: str) -> str:
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return ""


def get_mac_from_neigh(ip: str) -> str:
    try:
        result = subprocess.run(
            ["ip", "neigh", "show", ip],
            capture_output=True,
            text=True,
            timeout=3,
            env=SAFE_SUBPROCESS_ENV,
        )

        parts = result.stdout.split()
        for idx, item in enumerate(parts):
            if item == "lladdr" and idx + 1 < len(parts):
                return parts[idx + 1].lower()
    except Exception:
        pass

    return ""


def load_oui_cache():
    global OUI_CACHE

    if OUI_CACHE is not None:
        return OUI_CACHE

    OUI_CACHE = {}
    oui_files = [
        "/usr/share/ieee-data/oui.txt",
        "/var/lib/ieee-data/oui.txt",
    ]

    for oui_file in oui_files:
        try:
            with open(oui_file, "r", errors="ignore") as f:
                for line in f:
                    if "(hex)" not in line:
                        continue

                    prefix, vendor = line.split("(hex)", 1)
                    prefix = prefix.strip().replace("-", "").replace(":", "").upper()

                    if len(prefix) == 6:
                        OUI_CACHE[prefix] = vendor.strip()
        except Exception:
            continue

    return OUI_CACHE


def load_oui_vendor(mac: str) -> str:
    if not mac or len(mac) < 8:
        return ""

    prefix = mac.upper().replace(":", "").replace("-", "")[:6]
    cache = load_oui_cache()
    return cache.get(prefix, "")


def normalize_mac(mac: str) -> str:
    if not mac:
        return ""

    clean = mac.strip().lower().replace("-", ":")
    parts = [part.zfill(2) for part in clean.split(":") if part]

    if len(parts) != 6:
        return clean

    return ":".join(parts)


def get_device_alias(ip: str, mac: str) -> dict:
    config = read_config()
    aliases = config.get("device_aliases", {})

    if not isinstance(aliases, dict):
        return {}

    normalized_mac = normalize_mac(mac)

    candidates = [
        ip,
        normalized_mac,
        normalized_mac.upper(),
        mac,
        mac.upper() if mac else "",
    ]

    for candidate in candidates:
        if candidate and candidate in aliases:
            alias = aliases.get(candidate, {})
            if isinstance(alias, dict):
                return alias
            return {"name": str(alias)}

    return {}


def guess_usage_type(client: dict) -> str:
    privoxy_connections = int(client.get("privoxy_connections", 0) or 0)
    tor_socks_connections = int(client.get("tor_socks_connections", 0) or 0)

    if privoxy_connections > 0 and tor_socks_connections > 0:
        return "Privoxy + SOCKS"

    if privoxy_connections > 0:
        return "HTTP proxy / Privoxy"

    if tor_socks_connections > 0:
        return "SOCKS5 / Tor"

    return ""


def guess_device_confidence(hostname: str, vendor: str, device_type: str, alias: dict) -> str:
    if alias:
        return "alta"

    value = f"{hostname} {vendor} {device_type}".lower()

    if hostname and device_type != "Desconocido":
        return "media"

    if any(item in value for item in [
        "apple", "samsung", "xiaomi", "huawei", "mikrotik",
        "intel", "realtek", "wistron", "liteon", "lite-on",
        "foxconn", "hon hai", "compal", "quanta", "azurewave",
        "dell", "lenovo", "hewlett", "hp", "asus", "acer",
        "microsoft", "raspberry", "espressif", "tuya", "sonoff"
    ]):
        return "media"

    if device_type != "Desconocido":
        return "baja"

    return "baja"


def guess_device_type(hostname: str, vendor: str, ip: str) -> str:
    value = f"{hostname} {vendor}".lower()

    if ip.startswith("127."):
        return "Localhost"

    if "iphone" in value or "ipad" in value:
        return "Apple / iOS"
    if "macbook" in value or "imac" in value or "macos" in value:
        return "Apple / macOS"
    if "apple" in value:
        return "Apple / iOS/macOS"

    if "android" in value:
        return "Android"
    if "samsung" in value:
        return "Android / Samsung"
    if "xiaomi" in value or "redmi" in value or "poco" in value:
        return "Android / Xiaomi"
    if "huawei" in value or "honor" in value:
        return "Android / Huawei"

    if "windows" in value or "desktop" in value:
        return "PC Windows"
    if "linux" in value or "debian" in value or "ubuntu" in value:
        return "Linux"

    if "mikrotik" in value or "router" in value or "gateway" in value:
        return "Router/Firewall"

    # OEM / NIC vendors commonly seen in laptops and PCs.
    if any(item in value for item in [
        "wistron",
        "liteon",
        "lite-on",
        "foxconn",
        "hon hai",
        "compal",
        "quanta",
        "azurewave",
        "pegatron",
        "inventec",
        "intel",
        "realtek",
        "killer",
        "broadcom",
        "atheros",
        "qualcomm",
        "mediatek",
    ]):
        return "PC / Laptop"

    if any(item in value for item in [
        "dell",
        "lenovo",
        "hewlett",
        "hp ",
        "asus",
        "acer",
        "msi",
        "toshiba",
        "fujitsu",
        "microsoft",
    ]):
        return "PC / Laptop"

    if any(item in value for item in [
        "raspberry",
        "espressif",
        "sonoff",
        "tuya",
        "aqara",
        "lumi",
    ]):
        return "IoT / Embedded"

    return "Desconocido"


def get_client_connections():
    config = read_config()
    npmplus_ips = set(config.get("npmplus_ips", []))

    grouped = defaultdict(lambda: {
        "ip": "",
        "hostname": "",
        "mac": "",
        "vendor": "",
        "device_type": "",
        "tor_socks_connections": 0,
        "privoxy_connections": 0,
        "total_connections": 0,
        "ports": set(),
        "via_npmplus": False,
        "note": "",
    })

    try:
        connections = psutil.net_connections(kind="tcp")
    except Exception:
        connections = []

    for conn in connections:
        if not conn.laddr or not conn.raddr:
            continue

        local_port = conn.laddr.port

        if local_port not in (9050, 8118):
            continue

        if conn.status not in ("ESTABLISHED", "SYN_RECV", "SYN_SENT"):
            continue

        ip = conn.raddr.ip

        if ip in ("127.0.0.1", "::1"):
            continue

        entry = grouped[ip]
        entry["ip"] = ip
        entry["total_connections"] += 1
        entry["ports"].add(local_port)

        if local_port == 9050:
            entry["tor_socks_connections"] += 1
        elif local_port == 8118:
            entry["privoxy_connections"] += 1

        if ip in npmplus_ips:
            entry["via_npmplus"] = True
            entry["note"] = "Tráfico vía NPMplus Stream; IP real no visible desde proxytor"

    result = []

    for ip, entry in grouped.items():
        hostname = reverse_dns(ip)
        mac = get_mac_from_neigh(ip)
        vendor = load_oui_vendor(mac)
        device_type = "NPMplus / Stream TCP" if entry["via_npmplus"] else guess_device_type(hostname, vendor, ip)

        alias = get_device_alias(ip, mac)
        usage_type = guess_usage_type(entry)

        alias_name = alias.get("name", "") if isinstance(alias, dict) else ""
        alias_type = alias.get("type", "") if isinstance(alias, dict) else ""
        alias_usage = alias.get("usage", "") if isinstance(alias, dict) else ""

        if alias_type:
            device_type = alias_type

        if alias_usage:
            usage_type = alias_usage

        confidence = guess_device_confidence(hostname, vendor, device_type, alias)

        display_device_type = device_type
        if usage_type:
            display_device_type = f"{device_type} · {usage_type}"

        entry["hostname"] = hostname
        entry["mac"] = mac
        entry["vendor"] = vendor
        entry["alias"] = alias_name
        entry["usage_type"] = usage_type
        entry["confidence"] = confidence
        entry["device_type"] = display_device_type
        entry["raw_device_type"] = device_type
        entry["ports"] = sorted(list(entry["ports"]))

        if alias_name:
            entry["note"] = f"Alias manual: {alias_name}"

        result.append(entry)

    result.sort(key=lambda x: x["total_connections"], reverse=True)
    return result



def update_clients_db(clients: list):
    config = read_config()
    current = now_ts()
    new_client_events = []

    with get_db() as conn:
        conn.execute("BEGIN IMMEDIATE")

        try:
            for client in clients:
                ip = client["ip"]
                previous = conn.execute(
                    "SELECT ip FROM clients WHERE ip = ?",
                    (ip,),
                ).fetchone()

                service = []
                if client["tor_socks_connections"]:
                    service.append("SOCKS")
                if client["privoxy_connections"]:
                    service.append("Privoxy")

                service_last = ",".join(service)

                if previous:
                    conn.execute(
                        """
                        UPDATE clients
                        SET
                            hostname = ?,
                            mac = ?,
                            vendor = ?,
                            device_type = ?,
                            last_seen = ?,
                            total_observations = total_observations + ?,
                            tor_socks_observations = tor_socks_observations + ?,
                            privoxy_observations = privoxy_observations + ?,
                            last_tor_socks_connections = ?,
                            last_privoxy_connections = ?,
                            last_total_connections = ?,
                            via_npmplus = ?,
                            last_service = ?
                        WHERE ip = ?
                        """,
                        (
                            client.get("hostname", ""),
                            client.get("mac", ""),
                            client.get("vendor", ""),
                            client.get("device_type", ""),
                            current,
                            client.get("total_connections", 0),
                            client.get("tor_socks_connections", 0),
                            client.get("privoxy_connections", 0),
                            client.get("tor_socks_connections", 0),
                            client.get("privoxy_connections", 0),
                            client.get("total_connections", 0),
                            1 if client.get("via_npmplus") else 0,
                            service_last,
                            ip,
                        ),
                    )
                else:
                    conn.execute(
                        """
                        INSERT INTO clients (
                            ip, hostname, mac, vendor, device_type,
                            first_seen, last_seen,
                            total_observations, tor_socks_observations, privoxy_observations,
                            last_tor_socks_connections, last_privoxy_connections, last_total_connections,
                            via_npmplus, last_service
                        )
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            ip,
                            client.get("hostname", ""),
                            client.get("mac", ""),
                            client.get("vendor", ""),
                            client.get("device_type", ""),
                            current,
                            current,
                            client.get("total_connections", 0),
                            client.get("tor_socks_connections", 0),
                            client.get("privoxy_connections", 0),
                            client.get("tor_socks_connections", 0),
                            client.get("privoxy_connections", 0),
                            client.get("total_connections", 0),
                            1 if client.get("via_npmplus") else 0,
                            service_last,
                        ),
                    )

                    new_client_events.append((ip, dict(client)))

            conn.execute("COMMIT")

        except Exception:
            conn.execute("ROLLBACK")
            raise

    # Los eventos se registran fuera de la transacción principal para evitar database locked.
    for ip, client in new_client_events:
        log_event(
            "info",
            "new_client",
            f"Nuevo cliente detectado: {ip}",
            client,
            source_ip=ip,
        )

        if config.get("alert_new_client", False):
            maybe_alert(
                f"new_client_{ip}",
                "ProxyTor: nuevo cliente",
                f"IP: {ip}\\nTipo: {client.get('device_type', 'Desconocido')}",
                min_interval=3600,
            )


def build_history_sample(tor_info: dict, clients: list):
    global LAST_TRAFFIC_SAMPLE

    current = time.time()
    read_bytes = int(tor_info.get("traffic_read_bytes", 0))
    written_bytes = int(tor_info.get("traffic_written_bytes", 0))

    read_mbps = 0.0
    written_mbps = 0.0

    if LAST_TRAFFIC_SAMPLE:
        previous_time = LAST_TRAFFIC_SAMPLE["timestamp"]
        previous_read = LAST_TRAFFIC_SAMPLE["read_bytes"]
        previous_written = LAST_TRAFFIC_SAMPLE["written_bytes"]

        delta_time = max(current - previous_time, 1)
        delta_read = max(read_bytes - previous_read, 0)
        delta_written = max(written_bytes - previous_written, 0)

        read_mbps = round((delta_read * 8) / delta_time / 1_000_000, 4)
        written_mbps = round((delta_written * 8) / delta_time / 1_000_000, 4)

    LAST_TRAFFIC_SAMPLE = {
        "timestamp": current,
        "read_bytes": read_bytes,
        "written_bytes": written_bytes,
    }

    sample = {
        "timestamp": int(current),
        "read_mbps": read_mbps,
        "written_mbps": written_mbps,
        "active_clients": len(clients),
        "active_connections": sum(c["total_connections"] for c in clients),
        "tor_socks_connections": sum(c["tor_socks_connections"] for c in clients),
        "privoxy_connections": sum(c["privoxy_connections"] for c in clients),
        "streams_total": tor_info.get("streams_total", 0),
        "circuits_built": tor_info.get("circuits_built", 0),
    }

    with get_db() as conn:
        conn.execute(
            """
            INSERT INTO traffic_samples (
                ts, read_mbps, written_mbps, active_clients, active_connections,
                tor_socks_connections, privoxy_connections, streams_total, circuits_built
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                sample["timestamp"],
                sample["read_mbps"],
                sample["written_mbps"],
                sample["active_clients"],
                sample["active_connections"],
                sample["tor_socks_connections"],
                sample["privoxy_connections"],
                sample["streams_total"],
                sample["circuits_built"],
            ),
        )
        conn.commit()

    return sample


def assess_alerts(stats_payload: dict):
    config = read_config()

    if config.get("alert_service_down", True):
        if not stats_payload["services"]["tor"]:
            maybe_alert(
                "tor_down",
                "ProxyTor: Tor caído",
                "El servicio tor@default no está activo.",
                min_interval=900,
            )

        if not stats_payload["services"]["privoxy"]:
            maybe_alert(
                "privoxy_down",
                "ProxyTor: Privoxy caído",
                "El servicio privoxy no está activo.",
                min_interval=900,
            )

    threshold = int(config.get("alert_connection_threshold", 30))
    active_connections = stats_payload["connections"]["active_connections"]

    if threshold > 0 and active_connections >= threshold:
        maybe_alert(
            "high_connections",
            "ProxyTor: muchas conexiones activas",
            f"Conexiones activas: {active_connections}\nUmbral: {threshold}",
            min_interval=600,
        )


def rows_to_dicts(rows):
    result = []

    for row in rows:
        item = dict(row)
        if "ts" in item:
            item["time"] = fmt_ts(item["ts"])
        if "first_seen" in item:
            item["first_seen_text"] = fmt_ts(item["first_seen"])
        if "last_seen" in item:
            item["last_seen_text"] = fmt_ts(item["last_seen"])
        result.append(item)

    return result


@app.on_event("startup")
def startup_event():
    ensure_files()
    init_db()
    log_event("info", "api_start", "ProxyTor API iniciada")


@app.get("/", response_class=HTMLResponse)
def dashboard():
    return r"""
<!doctype html>
<html lang="es">
<head>
  <meta charset="utf-8">
  <title>ProxyTor Dashboard</title>
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <style>
    :root {
      --bg: #f4f7fb;
      --panel: #ffffff;
      --panel-soft: #f8fafc;
      --text: #172033;
      --muted: #6b7280;
      --border: #e5e7eb;
      --green: #10b981;
      --green-soft: #d1fae5;
      --red: #ef4444;
      --red-soft: #fee2e2;
      --yellow: #f59e0b;
      --yellow-soft: #fef3c7;
      --blue: #2563eb;
      --shadow: 0 8px 24px rgba(15,23,42,.06);
      --radius: 16px;
    }

    * { box-sizing: border-box; }

    body {
      margin: 0;
      background: var(--bg);
      color: var(--text);
      font-family: Inter, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
    }

    .app {
      display: grid;
      grid-template-columns: 260px 1fr;
      min-height: 100vh;
    }

    aside {
      background: #111827;
      color: white;
      padding: 24px 18px;
      position: sticky;
      top: 0;
      height: 100vh;
    }

    .brand {
      display: flex;
      align-items: center;
      gap: 12px;
      margin-bottom: 30px;
    }

    .brand-logo {
      width: 42px;
      height: 42px;
      border-radius: 12px;
      background: linear-gradient(135deg, #10b981, #2563eb);
      display: grid;
      place-items: center;
      font-weight: 900;
      font-size: 20px;
      box-shadow: 0 10px 30px rgba(16,185,129,.35);
    }

    .brand-title {
      font-size: 18px;
      font-weight: 800;
      line-height: 1.1;
    }

    .brand-subtitle {
      color: #9ca3af;
      font-size: 12px;
      margin-top: 2px;
    }

    .brand-link {
      display: inline-block;
      color: #93c5fd;
      font-size: 12px;
      margin-top: 6px;
      text-decoration: none;
      font-weight: 700;
    }

    .brand-link:hover {
      color: #bfdbfe;
      text-decoration: underline;
    }

    .version-footer {
      color: #9ca3af;
      font-size: 11px;
      line-height: 1.5;
      margin-top: 12px;
      padding-top: 12px;
      border-top: 1px solid rgba(255,255,255,.12);
    }

    .version-footer a {
      color: #93c5fd;
      text-decoration: none;
      font-weight: 700;
    }

    .version-footer a:hover {
      text-decoration: underline;
    }

    nav {
      display: flex;
      flex-direction: column;
      gap: 8px;
    }

    nav a {
      color: #d1d5db;
      text-decoration: none;
      padding: 12px 14px;
      border-radius: 12px;
      font-size: 14px;
      display: flex;
      align-items: center;
      gap: 10px;
    }

    nav a:hover,
    nav a.active {
      background: rgba(255,255,255,.09);
      color: white;
    }

    .sidebar-footer {
      position: absolute;
      bottom: 20px;
      left: 18px;
      right: 18px;
      color: #9ca3af;
      font-size: 12px;
      line-height: 1.5;
    }

    main {
      padding: 24px;
      overflow: hidden;
    }

    .topbar {
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 16px;
      margin-bottom: 22px;
    }

    .title h1 {
      margin: 0;
      font-size: 28px;
      letter-spacing: -0.04em;
    }

    .title p {
      margin: 6px 0 0;
      color: var(--muted);
      font-size: 14px;
    }

    .token-panel {
      display: flex;
      align-items: center;
      gap: 10px;
      background: var(--panel);
      border: 1px solid var(--border);
      box-shadow: var(--shadow);
      padding: 10px;
      border-radius: var(--radius);
      min-width: 500px;
    }

    input, select {
      border: 1px solid var(--border);
      border-radius: 12px;
      padding: 11px 12px;
      background: var(--panel-soft);
      color: var(--text);
      width: 100%;
      outline: none;
    }

    button {
      border: 0;
      border-radius: 12px;
      padding: 11px 14px;
      font-weight: 700;
      cursor: pointer;
      background: var(--blue);
      color: white;
      white-space: nowrap;
    }

    button.secondary {
      background: var(--panel-soft);
      color: var(--text);
      border: 1px solid var(--border);
    }

    button.danger {
      background: var(--red);
      color: white;
    }

    button.success {
      background: var(--green);
      color: white;
    }

    .grid {
      display: grid;
      grid-template-columns: repeat(4, minmax(0, 1fr));
      gap: 16px;
    }

    .card {
      background: var(--panel);
      border: 1px solid var(--border);
      border-radius: var(--radius);
      box-shadow: var(--shadow);
      padding: 18px;
    }

    .card-header {
      display: flex;
      justify-content: space-between;
      gap: 12px;
      align-items: center;
      margin-bottom: 12px;
    }

    .card h2 {
      margin: 0;
      font-size: 14px;
      color: var(--muted);
      font-weight: 700;
    }

    .metric {
      font-size: 28px;
      font-weight: 900;
      letter-spacing: -0.05em;
      word-break: break-word;
    }

    .hint {
      color: var(--muted);
      font-size: 13px;
      margin-top: 6px;
      word-break: break-word;
    }

    .wide { grid-column: span 2; }
    .full { grid-column: 1 / -1; }

    .badge {
      display: inline-flex;
      align-items: center;
      gap: 7px;
      padding: 6px 10px;
      border-radius: 999px;
      font-size: 12px;
      font-weight: 800;
    }

    .badge.ok {
      color: #047857;
      background: var(--green-soft);
    }

    .badge.bad {
      color: #b91c1c;
      background: var(--red-soft);
    }

    .badge.warn {
      color: #92400e;
      background: var(--yellow-soft);
    }

    .dot {
      width: 8px;
      height: 8px;
      border-radius: 50%;
      background: currentColor;
    }

    canvas {
      width: 100%;
      height: 260px;
      display: block;
      background: linear-gradient(180deg, #ffffff, #f8fafc);
      border: 1px solid var(--border);
      border-radius: 14px;
    }

    .actions {
      display: flex;
      flex-wrap: wrap;
      gap: 10px;
    }

    table {
      width: 100%;
      border-collapse: collapse;
      font-size: 13px;
    }

    th, td {
      text-align: left;
      padding: 12px 10px;
      border-bottom: 1px solid var(--border);
      vertical-align: top;
    }

    th {
      color: var(--muted);
      font-size: 12px;
      text-transform: uppercase;
      letter-spacing: .04em;
      background: var(--panel-soft);
    }

    tbody tr:hover td {
      background: #f9fafb;
    }

    .mono {
      font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
      font-size: 12px;
    }

    pre {
      margin: 0;
      background: #0f172a;
      color: #dbeafe;
      border-radius: 14px;
      padding: 16px;
      overflow: auto;
      max-height: 380px;
      font-size: 13px;
      line-height: 1.45;
    }

    .section-title {
      margin: 28px 0 14px;
      font-size: 18px;
      font-weight: 900;
      letter-spacing: -0.03em;
    }

    .mini-row {
      display: flex;
      flex-wrap: wrap;
      gap: 8px;
      margin-top: 10px;
    }

    .pill {
      padding: 6px 9px;
      border-radius: 999px;
      background: var(--panel-soft);
      border: 1px solid var(--border);
      color: var(--muted);
      font-size: 12px;
      font-weight: 700;
    }

    .map-fallback {
      margin-top: 14px;
      padding: 18px;
      border: 1px dashed var(--border);
      border-radius: 16px;
      background: linear-gradient(180deg, #f8fafc, #eef2f7);
    }

    .map-fallback-title {
      margin: 0 0 6px;
      font-size: 14px;
      font-weight: 800;
      color: var(--text);
    }

    .map-fallback-body {
      margin: 0;
      color: var(--muted);
      font-size: 13px;
      line-height: 1.5;
    }

    .map-fallback-link {
      display: inline-flex;
      margin-top: 12px;
      color: var(--blue);
      font-size: 13px;
      font-weight: 700;
      text-decoration: none;
    }

    .map-fallback-link:hover {
      text-decoration: underline;
    }

    
    .btn-mini {
      padding: 6px 8px;
      font-size: 11px;
      border-radius: 8px;
      margin: 2px;
    }

    .ban-controls {
      display: flex;
      flex-wrap: wrap;
      gap: 8px;
      margin-bottom: 14px;
      align-items: center;
    }

    .ban-controls input {
      max-width: 260px;
    }

    .tag-active {
      color: #047857;
      background: #d1fae5;
      padding: 4px 8px;
      border-radius: 999px;
      font-weight: 800;
      font-size: 12px;
    }

    .tag-inactive {
      color: #6b7280;
      background: #f3f4f6;
      padding: 4px 8px;
      border-radius: 999px;
      font-weight: 800;
      font-size: 12px;
    }

    @media (max-width: 1100px) {
      .app { grid-template-columns: 1fr; }
      aside { height: auto; position: relative; }
      .sidebar-footer { position: static; margin-top: 20px; }
      .topbar { flex-direction: column; align-items: stretch; }
      .token-panel { min-width: 0; width: 100%; }
      .grid { grid-template-columns: repeat(2, minmax(0, 1fr)); }
      .wide { grid-column: span 2; }
    }

    @media (max-width: 640px) {
      main { padding: 16px; }
      .grid { grid-template-columns: 1fr; }
      .wide { grid-column: span 1; }
      .token-panel { flex-direction: column; align-items: stretch; }
    }
  </style>
</head>

<body>
  <div class="app">
    <aside>
      <div class="brand">
        <div class="brand-logo">T</div>
        <div>
          <div class="brand-title">ProxyTor</div>
          <div class="brand-subtitle">Tor + Privoxy Gateway</div>
          <a class="brand-link" href="https://github.com/alvarodgarcia/proxytor-gateway" target="_blank" rel="noopener noreferrer">GitHub project</a>
        </div>
      </div>

      <nav>
        <a class="active" href="#overview">📊 Resumen</a>
        <a href="#traffic">📈 Tráfico</a>
        <a href="#clients">👥 Clientes</a>
        <a href="#events">🧾 Eventos</a>
        <a href="#bans">⛔ Baneos</a>
        <a href="#actions">⚙️ Acciones</a>
        <a href="#logs">📜 Logs</a>
      </nav>

      <div class="sidebar-footer">
        SOCKS: <b>9050</b><br>
        Privoxy: <b>8118</b><br>
        API: <b>8088</b><br>
        DB: <b>SQLite</b><br><br>
        ProxyTor Gateway · Tor + Privoxy · Secure Proxy Dashboard

        <div class="version-footer">
          ProxyTor Gateway · v0.1.0<br>
          Published: 2026-04-29<br>
          <a href="https://github.com/alvarodgarcia/proxytor-gateway" target="_blank" rel="noopener noreferrer">GitHub repository</a>
        </div>
      </div>
    </aside>

    <main>
      <section class="topbar">
        <div class="title">
          <h1>Dashboard</h1>
          <p>Estado, tráfico, clientes recientes, auditoría y acciones rápidas.</p>
        </div>

        <div class="token-panel">
          <input id="token" type="password" placeholder="Token admin o viewer">
          <button onclick="saveToken()">Guardar</button>
          <button class="secondary" onclick="loadAll()">Actualizar</button>
          <button id="rotateAdminTopButton" class="danger" onclick="rotateToken()">Rotar admin</button>
        </div>
      </section>

      <div id="overview" class="grid">
        <div class="card">
          <div class="card-header">
            <h2>Rol</h2>
            <span id="roleBadge" class="badge warn"><span class="dot"></span>N/D</span>
          </div>
          <div id="roleText" class="hint">---</div>
        </div>

        <div class="card">
          <div class="card-header">
            <h2>Tor</h2>
            <span id="torBadge" class="badge warn"><span class="dot"></span>N/D</span>
          </div>
          <div id="torVersion" class="hint">---</div>
          <div class="mini-row">
            <span id="socksBadge" class="pill">SOCKS 9050: ---</span>
            <span id="controlBadge" class="pill">Control 9051: ---</span>
          </div>
        </div>

        <div class="card">
          <div class="card-header">
            <h2>Privoxy</h2>
            <span id="privoxyBadge" class="badge warn"><span class="dot"></span>N/D</span>
          </div>
          <div class="metric">8118</div>
          <div class="hint">Forward proxy HTTP hacia Tor</div>
        </div>

        <div class="card">
          <div class="card-header">
            <h2>Clientes recientes</h2>
          </div>
          <div id="recentClients" class="metric">---</div>
          <div class="hint">Últimos 10 minutos</div>
        </div>

        <div class="card">
          <div class="card-header">
            <h2>Clientes activos</h2>
          </div>
          <div id="activeClients" class="metric">---</div>
          <div class="hint">Conexiones en este instante</div>
        </div>

        <div class="card">
          <div class="card-header">
            <h2>Conexiones activas</h2>
          </div>
          <div id="activeConnections" class="metric">---</div>
          <div id="connectionsBreakdown" class="hint">---</div>
        </div>

        <div class="card wide">
          <div class="card-header">
            <h2>Salida Tor</h2>
          </div>

          <div id="exitIp" class="metric mono">---</div>
          <div id="exitGeo" class="hint">Geolocalización no disponible</div>

          <div style="display:flex;gap:10px;flex-wrap:wrap;margin-top:12px;">
            <span id="exitTorStatus" class="badge warn">SOCKS Tor: ---</span>
            <span id="exitPrivoxyStatus" class="badge warn">Privoxy: ---</span>
          </div>

          <div id="exitAsn" class="hint" style="margin-top:10px;">ASN/ISP: ---</div>
          <div id="exitMismatch" class="hint" style="display:none;margin-top:8px;color:#f59e0b;">---</div>

          <iframe
            id="exitMap"
            loading="lazy"
            referrerpolicy="no-referrer"
            style="width:100%;height:230px;border:0;border-radius:16px;margin-top:14px;display:none;background:#e5e7eb;">
          </iframe>

          <div id="exitMapUnavailable" class="map-fallback" style="margin-top:12px;">
            <p id="exitMapUnavailableTitle" class="map-fallback-title">Mapa no disponible</p>
            <p id="exitMapUnavailableBody" class="map-fallback-body">
              No hay coordenadas válidas disponibles para mostrar esta salida en el mapa.
            </p>
            <a
              id="exitMapUnavailableLink"
              class="map-fallback-link"
              href="#"
              target="_blank"
              rel="noopener noreferrer"
              style="display:none;">
              Abrir ubicación externa
            </a>
          </div>
        </div>

        <div class="card">
          <div class="card-header">
            <h2>Circuitos Tor</h2>
          </div>
          <div id="circuits" class="metric">---</div>
          <div id="streams" class="hint">---</div>
        </div>

        <div class="card">
          <div class="card-header">
            <h2>Tráfico leído</h2>
          </div>
          <div id="readMb" class="metric">---</div>
          <div id="readRate" class="hint">---</div>
        </div>

        <div class="card">
          <div class="card-header">
            <h2>Tráfico enviado</h2>
          </div>
          <div id="writtenMb" class="metric">---</div>
          <div id="writtenRate" class="hint">---</div>
        </div>

        <div class="card">
          <div class="card-header">
            <h2>Sistema</h2>
          </div>
          <div id="cpu" class="metric">---</div>
          <div id="mem" class="hint">---</div>
        </div>
      </div>

      <h2 id="traffic" class="section-title">Tráfico y conexiones</h2>

      <section class="grid">
        <div class="card wide">
          <div class="card-header">
            <h2>Tráfico Tor</h2>
            <select id="historyHours" onchange="changePeriod()">
              <option value="1">Última hora</option>
              <option value="6">Últimas 6 h</option>
              <option value="24">Últimas 24 h</option>
            </select>
            <button class="secondary" onclick="resetChartZoom()">Reset zoom</button>
          </div>
          <canvas id="trafficChart" width="900" height="280"></canvas>
          <div id="zoomInfo" class="hint">Arrastra sobre la gráfica para hacer zoom. Doble click para resetear.</div>
        </div>

        <div class="card wide">
          <div class="card-header">
            <h2>Clientes / conexiones</h2>
          </div>
          <canvas id="connectionsChart" width="900" height="280"></canvas>
          <div class="hint">Clientes únicos y conexiones TCP activas.</div>
        </div>
      </section>

      <h2 id="clients" class="section-title">Clientes vistos recientemente</h2>

      <section class="card">
        <div style="overflow:auto;">
          <table>
            <thead>
              <tr>
                <th>IP</th>
                <th>Hostname</th>
                <th>Tipo estimado</th>
                <th>MAC</th>
                <th>Fabricante</th>
                <th>Último servicio</th>
                <th>Última vez visto</th>
                <th>Obs.</th>
                <th>NPMplus</th>
                <th>Acciones</th>
              </tr>
            </thead>
            <tbody id="recentClientsTable">
              <tr><td colspan="10">Sin datos</td></tr>
            </tbody>
          </table>
        </div>
      </section>

      <h2 class="section-title">Conexiones activas ahora</h2>

      <section class="card">
        <div style="overflow:auto;">
          <table>
            <thead>
              <tr>
                <th>IP</th>
                <th>Hostname</th>
                <th>Tipo estimado</th>
                <th>SOCKS</th>
                <th>Privoxy</th>
                <th>Total</th>
                <th>Nota</th>
                <th>Acciones</th>
              </tr>
            </thead>
            <tbody id="activeClientsTable">
              <tr><td colspan="8">Sin datos</td></tr>
            </tbody>
          </table>
        </div>
      </section>

      <h2 id="events" class="section-title">Auditoría / eventos</h2>

      <section class="card">
        <div class="ban-controls">
          <select id="eventsLimit" onchange="loadEvents()">
            <option value="25">Últimos 25</option>
            <option value="50" selected>Últimos 50</option>
            <option value="100">Últimos 100</option>
            <option value="250">Últimos 250</option>
            <option value="500">Últimos 500</option>
          </select>

          <input id="eventsDateFrom" type="date">
          <input id="eventsDateTo" type="date">

          <button class="secondary" onclick="downloadEvents('csv')">Descargar CSV</button>
          <button class="secondary" onclick="downloadEvents('json')">Descargar JSON</button>
          <button class="secondary" onclick="loadEvents()">Actualizar eventos</button>
        </div>

        <div style="overflow:auto;">
          <table>
            <thead>
              <tr>
                <th>Fecha</th>
                <th>Severidad</th>
                <th>Tipo</th>
                <th>Mensaje</th>
                <th>IP origen</th>
              </tr>
            </thead>
            <tbody id="eventsTable">
              <tr><td colspan="5">Sin eventos</td></tr>
            </tbody>
          </table>
        </div>
      </section>


      <h2 id="bans" class="section-title">IPs baneadas</h2>

      <section class="card">
        <div id="banManualControls" class="ban-controls">
          <input id="manualBanIp" placeholder="IP a bannear, ej. CLIENT_IP">
          <button class="danger" onclick="banManual('3600')">Ban 1h</button>
          <button class="danger" onclick="banManual('86400')">Ban 24h</button>
          <button class="danger" onclick="banManual('0')">Ban permanente</button>
          <button class="secondary" onclick="loadBans()">Actualizar bans</button>
        </div>

        <div style="overflow:auto;">
          <table>
            <thead>
              <tr>
                <th>IP</th>
                <th>Estado</th>
                <th>Motivo</th>
                <th>Origen</th>
                <th>Creado</th>
                <th>Expira</th>
                <th>Acciones</th>
              </tr>
            </thead>
            <tbody id="bansTable">
              <tr><td colspan="7">Sin bans registrados</td></tr>
            </tbody>
          </table>
        </div>
      </section>


      <h2 id="actionsTitle" class="section-title">Acciones</h2>

      <section id="actionsCard" class="card">
        <div class="actions">
          <button class="success" onclick="newnym()">Nueva identidad Tor</button>
          <button onclick="serviceAction('tor','reload')">Reload Tor</button>
          <button class="danger" onclick="serviceAction('tor','restart')">Reiniciar Tor</button>
          <button class="danger" onclick="serviceAction('privoxy','restart')">Reiniciar Privoxy</button>
          <button class="danger" onclick="rotateViewerToken()">Rotar viewer</button>
          <button class="secondary" onclick="getLogs('tor')">Logs Tor</button>
          <button class="secondary" onclick="getLogs('privoxy')">Logs Privoxy</button>
          <button class="secondary" onclick="getLogs('api')">Logs API</button>
          <button class="secondary" onclick="getLogs('telegram')">Logs Telegram</button>
          <button class="secondary" onclick="getLogs('token-rotate')">Logs rotación token</button>
        </div>
      </section>

      <h2 id="logs" class="section-title">Salida / Logs</h2>

      <section class="card">
        <pre id="output">Introduce el token y pulsa Guardar.</pre>
      </section>
    </main>
  </div>

  <script>
    const tokenInput = document.getElementById("token");
    const output = document.getElementById("output");
    let chartZoom = null;
    let chartBaseHours = 1;
    let lastHistoryData = [];
    let isChartDragging = false;
    let chartDragCanvasId = null;
    let chartDragStartX = null;
    let chartDragCurrentX = null;
    let currentRole = "viewer";
    let currentToken = "";

    function saveToken() {
      currentToken = tokenInput.value.trim();
      tokenInput.value = "";

      if (!currentToken) {
        writeOutput("Token eliminado de la sesión actual.");
        return;
      }

      writeOutput("Token cargado solo en memoria para esta sesión del navegador.");
      loadAll();
    }

    function getToken() {
      return currentToken || tokenInput.value.trim() || "";
    }

    function headers() {
      const token = getToken();
      return token ? { "Authorization": "Bearer " + token } : {};
    }

    function writeOutput(data) {
      if (typeof data === "string") {
        output.textContent = data;
      } else {
        output.textContent = JSON.stringify(data, null, 2);
      }
    }

    function setBadge(id, ok) {
      const el = document.getElementById(id);
      const state = ok === true ? "ok" : ok === false ? "bad" : "warn";
      const text = ok === true ? "OK" : ok === false ? "KO" : "N/D";
      el.className = "badge " + state;
      el.replaceChildren();

      const dot = document.createElement("span");
      dot.className = "dot";
      el.appendChild(dot);
      el.appendChild(document.createTextNode(text));
    }

    function clearElement(el) {
      if (el) el.replaceChildren();
    }

    function appendTextCell(row, value, className = "") {
      const td = document.createElement("td");
      if (className) td.className = className;
      td.textContent = value;
      row.appendChild(td);
      return td;
    }

    function appendEmptyRow(tbody, colspan, text) {
      clearElement(tbody);
      const tr = document.createElement("tr");
      const td = document.createElement("td");
      td.colSpan = colspan;
      td.textContent = text;
      tr.appendChild(td);
      tbody.appendChild(tr);
    }

    function createMiniButton(text, className, onClick) {
      const button = document.createElement("button");
      button.className = className;
      button.textContent = text;
      button.addEventListener("click", onClick);
      return button;
    }

    function appendBanButtons(container, ip) {
      container.appendChild(
        createMiniButton("Ban 1h", "btn-mini danger", () => banClient(ip, 3600))
      );
      container.appendChild(
        createMiniButton("Ban 24h", "btn-mini danger", () => banClient(ip, 86400))
      );
      container.appendChild(
        createMiniButton("Permanente", "btn-mini danger", () => banClient(ip, 0))
      );
    }

    async function apiGet(path) {
      const r = await fetch(path, { headers: headers() });
      const text = await r.text();

      if (!r.ok) throw new Error("HTTP " + r.status + " - " + text);

      try { return JSON.parse(text); }
      catch { return text; }
    }

    async function apiPost(path) {
      const r = await fetch(path, {
        method: "POST",
        headers: headers()
      });

      const text = await r.text();

      if (!r.ok) throw new Error("HTTP " + r.status + " - " + text);

      try { return JSON.parse(text); }
      catch { return text; }
    }
    function getChartTooltip() {
      let tooltip = document.getElementById("chartTooltip");

      if (!tooltip) {
        tooltip = document.createElement("div");
        tooltip.id = "chartTooltip";
        tooltip.style.position = "fixed";
        tooltip.style.zIndex = "9999";
        tooltip.style.pointerEvents = "none";
        tooltip.style.background = "#111827";
        tooltip.style.color = "#ffffff";
        tooltip.style.padding = "10px 12px";
        tooltip.style.borderRadius = "10px";
        tooltip.style.fontSize = "12px";
        tooltip.style.boxShadow = "0 10px 30px rgba(0,0,0,.25)";
        tooltip.style.display = "none";
        tooltip.style.maxWidth = "280px";
        document.body.appendChild(tooltip);
      }

      return tooltip;
    }

    function formatChartTime(ts) {
      const d = new Date(Number(ts) * 1000);

      return d.toLocaleString("es-ES", {
        day: "2-digit",
        month: "2-digit",
        hour: "2-digit",
        minute: "2-digit",
        second: "2-digit"
      });
    }

    function formatHourOnly(ts) {
      const d = new Date(Number(ts) * 1000);
      return String(d.getHours()).padStart(2, "0") + ":00";
    }

    function getChartTimeRange(hours) {
      const nowSec = Math.floor(Date.now() / 1000);

      if (chartZoom && chartZoom.startSec && chartZoom.endSec) {
        return {
          startSec: chartZoom.startSec,
          endSec: chartZoom.endSec,
          zoomed: true
        };
      }

      return {
        startSec: nowSec - (hours * 3600),
        endSec: nowSec,
        zoomed: false
      };
    }

    function updateZoomInfo() {
      const el = document.getElementById("zoomInfo");
      if (!el) return;

      if (!chartZoom) {
        el.textContent = "Arrastra sobre la gráfica para hacer zoom. Doble click para resetear.";
        return;
      }

      el.textContent =
        "Zoom activo: " +
        formatChartTime(chartZoom.startSec) +
        " → " +
        formatChartTime(chartZoom.endSec) +
        ". Doble click o Reset zoom para volver.";
    }

    function resetChartZoom() {
      chartZoom = null;
      updateZoomInfo();
      renderHistoryCharts();
    }

    function changePeriod() {
      chartZoom = null;
      loadHistory();
    }

    function installChartInteractions(canvasId) {
      const canvas = document.getElementById(canvasId);

      if (!canvas || canvas.dataset.interactionsInstalled === "1") return;

      canvas.dataset.interactionsInstalled = "1";
      canvas.style.cursor = "crosshair";

      canvas.addEventListener("mousedown", function(event) {
        const state = window.__proxytorCharts?.[canvasId];
        if (!state) return;

        const rect = canvas.getBoundingClientRect();
        const scaleX = canvas.width / rect.width;
        const mx = (event.clientX - rect.left) * scaleX;

        if (mx < state.pLeft || mx > state.width - state.pRight) return;

        isChartDragging = true;
        chartDragCanvasId = canvasId;
        chartDragStartX = mx;
        chartDragCurrentX = mx;

        const tooltip = getChartTooltip();
        tooltip.style.display = "none";
      });

      canvas.addEventListener("mousemove", function(event) {
        const state = window.__proxytorCharts?.[canvasId];
        if (!state || !state.points || state.points.length === 0) return;

        const rect = canvas.getBoundingClientRect();
        const scaleX = canvas.width / rect.width;
        const scaleY = canvas.height / rect.height;

        const mx = (event.clientX - rect.left) * scaleX;
        const my = (event.clientY - rect.top) * scaleY;

        if (isChartDragging && chartDragCanvasId === canvasId) {
          chartDragCurrentX = Math.max(state.pLeft, Math.min(state.width - state.pRight, mx));
          renderHistoryCharts();
          return;
        }

        let nearest = null;
        let nearestDistance = Infinity;

        for (const point of state.points) {
          const dx = Math.abs(point.x - mx);
          const dyA = Math.abs(point.yA - my);
          const dyB = Math.abs(point.yB - my);
          const dy = Math.min(dyA, dyB);
          const distance = dx + (dy * 0.25);

          if (distance < nearestDistance) {
            nearestDistance = distance;
            nearest = point;
          }
        }

        const tooltip = getChartTooltip();

        if (!nearest || Math.abs(nearest.x - mx) > 35) {
          tooltip.style.display = "none";
          return;
        }

        tooltip.replaceChildren();

        const title = document.createElement("div");
        title.style.fontWeight = "800";
        title.style.marginBottom = "6px";
        title.textContent = formatChartTime(nearest.ts);
        tooltip.appendChild(title);

        const lineA = document.createElement("div");
        const dotA = document.createElement("span");
        dotA.style.color = "#93c5fd";
        dotA.textContent = "●";
        const valueA = document.createElement("b");
        valueA.textContent = nearest.valueA;
        lineA.appendChild(dotA);
        lineA.appendChild(document.createTextNode(" " + state.labelA + ": "));
        lineA.appendChild(valueA);
        tooltip.appendChild(lineA);

        const lineB = document.createElement("div");
        const dotB = document.createElement("span");
        dotB.style.color = "#86efac";
        dotB.textContent = "●";
        const valueB = document.createElement("b");
        valueB.textContent = nearest.valueB;
        lineB.appendChild(dotB);
        lineB.appendChild(document.createTextNode(" " + state.labelB + ": "));
        lineB.appendChild(valueB);
        tooltip.appendChild(lineB);

        tooltip.style.left = (event.clientX + 14) + "px";
        tooltip.style.top = (event.clientY + 14) + "px";
        tooltip.style.display = "block";
      });

      canvas.addEventListener("mouseup", function(event) {
        if (!isChartDragging || chartDragCanvasId !== canvasId) return;

        const state = window.__proxytorCharts?.[canvasId];
        if (!state) return;

        const startX = Math.max(state.pLeft, Math.min(state.width - state.pRight, chartDragStartX));
        const endX = Math.max(state.pLeft, Math.min(state.width - state.pRight, chartDragCurrentX));

        isChartDragging = false;
        chartDragCanvasId = null;

        if (Math.abs(endX - startX) < 20) {
          renderHistoryCharts();
          return;
        }

        const minX = Math.min(startX, endX);
        const maxX = Math.max(startX, endX);

        const startRatio = (minX - state.pLeft) / Math.max(state.chartW, 1);
        const endRatio = (maxX - state.pLeft) / Math.max(state.chartW, 1);

        const selectedStart = Math.floor(state.startSec + (startRatio * (state.endSec - state.startSec)));
        const selectedEnd = Math.ceil(state.startSec + (endRatio * (state.endSec - state.startSec)));

        if ((selectedEnd - selectedStart) < 60) {
          writeOutput("El tramo seleccionado es demasiado pequeño. Selecciona al menos 1 minuto.");
          renderHistoryCharts();
          return;
        }

        chartZoom = {
          startSec: selectedStart,
          endSec: selectedEnd
        };

        updateZoomInfo();
        renderHistoryCharts();
      });

      canvas.addEventListener("mouseleave", function() {
        const tooltip = getChartTooltip();
        tooltip.style.display = "none";

        if (isChartDragging && chartDragCanvasId === canvasId) {
          isChartDragging = false;
          chartDragCanvasId = null;
          renderHistoryCharts();
        }
      });

      canvas.addEventListener("dblclick", function() {
        resetChartZoom();
      });
    }

    function drawChart(canvasId, points, seriesAKey, seriesBKey, labelA, labelB, hours) {
      const canvas = document.getElementById(canvasId);
      const ctx = canvas.getContext("2d");

      installChartInteractions(canvasId);

      if (!window.__proxytorCharts) {
        window.__proxytorCharts = {};
      }

      const w = canvas.width;
      const h = canvas.height;
      const pLeft = 54;
      const pRight = 24;
      const pTop = 34;
      const pBottom = 42;

      ctx.clearRect(0, 0, w, h);
      ctx.fillStyle = "#ffffff";
      ctx.fillRect(0, 0, w, h);

      const range = getChartTimeRange(hours);
      const startSec = range.startSec;
      const endSec = range.endSec;

      const filteredPoints = points
        .filter(x => Number(x.ts) >= startSec && Number(x.ts) <= endSec)
        .sort((a, b) => Number(a.ts) - Number(b.ts));

      const valuesA = filteredPoints.map(x => Number(x[seriesAKey] || 0));
      const valuesB = filteredPoints.map(x => Number(x[seriesBKey] || 0));
      const all = [...valuesA, ...valuesB, 0.01];
      const max = Math.max(...all) || 1;

      const chartW = w - pLeft - pRight;
      const chartH = h - pTop - pBottom;

      function xForTs(ts) {
        const ratio = (Number(ts) - startSec) / Math.max(endSec - startSec, 1);
        return pLeft + Math.max(0, Math.min(1, ratio)) * chartW;
      }

      function yForValue(v) {
        return pTop + chartH - ((v / max) * chartH);
      }

      ctx.strokeStyle = "#e5e7eb";
      ctx.lineWidth = 1;
      ctx.fillStyle = "#6b7280";
      ctx.font = "12px system-ui";

      for (let i = 0; i <= 4; i++) {
        const y = pTop + (chartH / 4) * i;
        ctx.beginPath();
        ctx.moveTo(pLeft, y);
        ctx.lineTo(w - pRight, y);
        ctx.stroke();

        const value = max - ((max / 4) * i);
        ctx.fillText(value.toFixed(max < 1 ? 3 : 1), 8, y + 4);
      }

      let tickSec;
      const totalSeconds = endSec - startSec;

      if (totalSeconds <= 3600) {
        tickSec = Math.ceil(startSec / 600) * 600;
      } else {
        tickSec = Math.ceil(startSec / 3600) * 3600;
      }

      const tickStep = totalSeconds <= 3600 ? 600 : 3600;

      while (tickSec <= endSec) {
        const x = xForTs(tickSec);

        ctx.strokeStyle = "#eef2f7";
        ctx.beginPath();
        ctx.moveTo(x, pTop);
        ctx.lineTo(x, pTop + chartH);
        ctx.stroke();

        const d = new Date(tickSec * 1000);
        let label;

        if (tickStep === 600) {
          label = String(d.getHours()).padStart(2, "0") + ":" + String(d.getMinutes()).padStart(2, "0");
        } else {
          label = String(d.getHours()).padStart(2, "0") + ":00";
        }

        ctx.fillStyle = "#6b7280";
        ctx.font = "12px system-ui";
        ctx.fillText(label, x - 16, h - 16);

        tickSec += tickStep;
      }

      function plot(key, color) {
        ctx.strokeStyle = color;
        ctx.lineWidth = 3;
        ctx.beginPath();

        filteredPoints.forEach((point, i) => {
          const x = xForTs(point.ts);
          const y = yForValue(Number(point[key] || 0));

          if (i === 0) ctx.moveTo(x, y);
          else ctx.lineTo(x, y);
        });

        ctx.stroke();

        ctx.fillStyle = color;
        for (const point of filteredPoints) {
          const x = xForTs(point.ts);
          const y = yForValue(Number(point[key] || 0));

          ctx.beginPath();
          ctx.arc(x, y, 2.5, 0, Math.PI * 2);
          ctx.fill();
        }
      }

      plot(seriesAKey, "#2563eb");
      plot(seriesBKey, "#10b981");

      const hoverPoints = filteredPoints.map(point => ({
        ts: Number(point.ts),
        x: xForTs(point.ts),
        yA: yForValue(Number(point[seriesAKey] || 0)),
        yB: yForValue(Number(point[seriesBKey] || 0)),
        valueA: Number(point[seriesAKey] || 0).toFixed(seriesAKey.includes("mbps") ? 4 : 0),
        valueB: Number(point[seriesBKey] || 0).toFixed(seriesBKey.includes("mbps") ? 4 : 0)
      }));

      window.__proxytorCharts[canvasId] = {
        points: hoverPoints,
        labelA,
        labelB,
        seriesAKey,
        seriesBKey,
        hours,
        startSec,
        endSec,
        width: w,
        height: h,
        pLeft,
        pRight,
        pTop,
        pBottom,
        chartW,
        chartH
      };

      if (isChartDragging && chartDragCanvasId === canvasId && chartDragStartX !== null && chartDragCurrentX !== null) {
        const x1 = Math.max(pLeft, Math.min(w - pRight, chartDragStartX));
        const x2 = Math.max(pLeft, Math.min(w - pRight, chartDragCurrentX));
        const left = Math.min(x1, x2);
        const width = Math.abs(x2 - x1);

        ctx.fillStyle = "rgba(37, 99, 235, 0.16)";
        ctx.fillRect(left, pTop, width, chartH);

        ctx.strokeStyle = "rgba(37, 99, 235, 0.75)";
        ctx.lineWidth = 2;
        ctx.strokeRect(left, pTop, width, chartH);
      }

      ctx.fillStyle = "#2563eb";
      ctx.font = "13px system-ui";
      ctx.fillText(labelA, pLeft, 20);

      ctx.fillStyle = "#10b981";
      ctx.fillText(labelB, pLeft + 140, 20);

      ctx.fillStyle = "#6b7280";
      const periodLabel = range.zoomed
        ? "Zoom: " + formatChartTime(startSec) + " → " + formatChartTime(endSec)
        : "Periodo: " + hours + "h";

      ctx.fillText(periodLabel + " · máx: " + max.toFixed(max < 1 ? 3 : 1), pLeft + 300, 20);

      ctx.strokeStyle = "#d1d5db";
      ctx.lineWidth = 1;
      ctx.beginPath();
      ctx.moveTo(pLeft, pTop);
      ctx.lineTo(pLeft, pTop + chartH);
      ctx.lineTo(w - pRight, pTop + chartH);
      ctx.stroke();

      updateZoomInfo();
    }

    function renderHistoryCharts() {
      const hours = chartBaseHours || Number(document.getElementById("historyHours").value || "1");

      drawChart(
        "trafficChart",
        lastHistoryData,
        "read_mbps",
        "written_mbps",
        "Lectura Mbps",
        "Escritura Mbps",
        hours
      );

      drawChart(
        "connectionsChart",
        lastHistoryData,
        "active_clients",
        "active_connections",
        "Clientes",
        "Conexiones",
        hours
      );
    }
    function renderRecentClients(clients) {
      const tbody = document.getElementById("recentClientsTable");
      clearElement(tbody);

      if (!clients || clients.length === 0) {
        appendEmptyRow(tbody, 10, "Sin clientes recientes");
        return;
      }

      for (const c of clients) {
        const ip = c.ip || "";
        const isNpmplus = c.via_npmplus ? true : false;
        const canBan = currentRole === "admin" && ip && !isNpmplus;

        const tr = document.createElement("tr");
        appendTextCell(tr, ip, "mono");
        appendTextCell(tr, c.hostname || "-");
        appendTextCell(tr, c.device_type || "Desconocido");
        appendTextCell(tr, c.mac || "-", "mono");
        appendTextCell(tr, c.vendor || "-");
        appendTextCell(tr, c.last_service || "-");
        appendTextCell(tr, c.last_seen_text || "-");

        const observations = document.createElement("td");
        const bold = document.createElement("b");
        bold.textContent = String(c.total_observations || 0);
        observations.appendChild(bold);
        tr.appendChild(observations);

        appendTextCell(tr, isNpmplus ? "Sí" : "No");

        const actionsTd = document.createElement("td");
        if (canBan) {
          appendBanButtons(actionsTd, ip);
        } else {
          actionsTd.textContent = currentRole === "admin" && isNpmplus ? "Protegido" : "Solo lectura";
        }
        tr.appendChild(actionsTd);
        tbody.appendChild(tr);
      }
    }

    function renderActiveClients(clients) {
      const tbody = document.getElementById("activeClientsTable");
      clearElement(tbody);

      if (!clients || clients.length === 0) {
        appendEmptyRow(tbody, 8, "Sin conexiones activas");
        return;
      }

      for (const c of clients) {
        const ip = c.ip || "";
        const isNpmplus = c.via_npmplus ? true : false;
        const canBan = currentRole === "admin" && ip && !isNpmplus;

        const tr = document.createElement("tr");
        appendTextCell(tr, ip, "mono");
        appendTextCell(tr, c.hostname || "-");
        appendTextCell(tr, c.device_type || "Desconocido");
        appendTextCell(tr, String(c.tor_socks_connections || 0));
        appendTextCell(tr, String(c.privoxy_connections || 0));

        const totalTd = document.createElement("td");
        const totalBold = document.createElement("b");
        totalBold.textContent = String(c.total_connections || 0);
        totalTd.appendChild(totalBold);
        tr.appendChild(totalTd);

        appendTextCell(tr, c.note || "-");

        const actionsTd = document.createElement("td");
        if (canBan) {
          appendBanButtons(actionsTd, ip);
        } else {
          actionsTd.textContent = currentRole === "admin" && isNpmplus ? "Protegido" : "Solo lectura";
        }
        tr.appendChild(actionsTd);
        tbody.appendChild(tr);
      }
    }


    function renderEvents(events) {
      const tbody = document.getElementById("eventsTable");
      clearElement(tbody);

      if (!events || events.length === 0) {
        appendEmptyRow(tbody, 5, "Sin eventos");
        return;
      }

      for (const e of events) {
        const tr = document.createElement("tr");
        appendTextCell(tr, e.time || "");
        appendTextCell(tr, e.severity || "");
        appendTextCell(tr, e.event_type || "");
        appendTextCell(tr, e.message || "");
        appendTextCell(tr, e.source_ip || "-", "mono");
        tbody.appendChild(tr);
      }
    }

    function applyRoleVisibility(role) {
      currentRole = role || "viewer";
      const isAdmin = currentRole === "admin";

      const actionsTitle = document.getElementById("actionsTitle");
      const actionsCard = document.getElementById("actionsCard");
      const rotateAdminTopButton = document.getElementById("rotateAdminTopButton");
      const banManualControls = document.getElementById("banManualControls");

      if (actionsTitle) actionsTitle.style.display = isAdmin ? "" : "none";
      if (actionsCard) actionsCard.style.display = isAdmin ? "" : "none";
      if (rotateAdminTopButton) rotateAdminTopButton.style.display = isAdmin ? "" : "none";
      if (banManualControls) banManualControls.style.display = isAdmin ? "" : "none";
    }

    function requireAdminUi() {
      if (currentRole !== "admin") {
        writeOutput("Acción no permitida: el token viewer solo permite visualización.");
        return false;
      }
      return true;
    }

    function renderBans(bans) {
      const tbody = document.getElementById("bansTable");
      if (!tbody) return;

      clearElement(tbody);

      if (!bans || bans.length === 0) {
        appendEmptyRow(tbody, 7, "Sin bans registrados");
        return;
      }

      for (const b of bans) {
        const ip = b.ip || "";
        const active = Number(b.active) === 1;

        const tr = document.createElement("tr");
        appendTextCell(tr, ip, "mono");

        const statusTd = document.createElement("td");
        const statusSpan = document.createElement("span");
        statusSpan.className = active ? "tag-active" : "tag-inactive";
        statusSpan.textContent = active ? "Activo" : "Inactivo";
        statusTd.appendChild(statusSpan);
        tr.appendChild(statusTd);

        appendTextCell(tr, b.reason || "-");
        appendTextCell(tr, b.source || "-");
        appendTextCell(tr, b.created_text || "-");
        appendTextCell(tr, b.expires_text || "-");

        const actionsTd = document.createElement("td");
        if (currentRole === "admin") {
          if (active) {
            actionsTd.appendChild(
              createMiniButton("Unban", "btn-mini success", () => unbanClient(ip))
            );
          } else {
            appendBanButtons(actionsTd, ip);
          }
        } else {
          actionsTd.textContent = "Solo lectura";
        }
        tr.appendChild(actionsTd);
        tbody.appendChild(tr);
      }
    }

    async function loadBans() {
      try {
        const data = await apiGet("/api/bans?active_only=false");
        renderBans(data.bans || []);
      } catch (e) {
        writeOutput("ERROR cargando bans: " + e.message);
      }
    }

    async function banClient(ip, durationSeconds) {
      if (!requireAdminUi()) return;

      const label = Number(durationSeconds) === 0 ? "permanente" : (Number(durationSeconds) === 3600 ? "1h" : "24h");
      const ok = confirm("¿Seguro que quieres bannear " + ip + " durante " + label + "?");
      if (!ok) return;

      try {
        const path = "/api/action/ban/" + encodeURIComponent(ip)
          + "?duration_seconds=" + encodeURIComponent(durationSeconds)
          + "&reason=" + encodeURIComponent("dashboard_" + label);

        const data = await apiPost(path);
        writeOutput(data);
        await loadBans();
        await loadRecentClients();
        await loadStats();
      } catch (e) {
        writeOutput("ERROR baneando cliente: " + e.message);
      }
    }

    async function banManual(durationSeconds) {
      if (!requireAdminUi()) return;

      const input = document.getElementById("manualBanIp");
      const ip = input ? input.value.trim() : "";

      if (!ip) {
        writeOutput("Introduce una IP para bannear.");
        return;
      }

      await banClient(ip, durationSeconds);
    }

    async function unbanClient(ip) {
      if (!requireAdminUi()) return;

      const ok = confirm("¿Seguro que quieres quitar el ban a " + ip + "?");
      if (!ok) return;

      try {
        const data = await apiPost("/api/action/unban/" + encodeURIComponent(ip));
        writeOutput(data);
        await loadBans();
        await loadRecentClients();
        await loadStats();
      } catch (e) {
        writeOutput("ERROR quitando ban: " + e.message);
      }
    }


    async function loadMe() {
      const data = await apiGet("/api/me");

      const role = data.role || "viewer";
      const isAdmin = role === "admin";

      const el = document.getElementById("roleBadge");
      el.className = "badge " + (isAdmin ? "ok" : "warn");
      el.replaceChildren();
      const dot = document.createElement("span");
      dot.className = "dot";
      el.appendChild(dot);
      el.appendChild(document.createTextNode(role.toUpperCase()));

      document.getElementById("roleText").textContent =
        isAdmin ? "Acceso completo" : "Solo lectura";

      applyRoleVisibility(role);
    }


    function updateExitCard(data) {
      const exitData = data.exit || {};
      const geo = exitData.geo || {};

      const ip = exitData.ip || "N/D";
      const privoxyIp = exitData.privoxy_ip || "N/D";

      document.getElementById("exitIp").textContent = ip;

      const locationParts = [];
      if (geo.city) locationParts.push(geo.city);
      if (geo.region) locationParts.push(geo.region);
      if (geo.country) locationParts.push(geo.country);

      document.getElementById("exitGeo").textContent =
        locationParts.length ? locationParts.join(", ") : "Geolocalización no disponible";

      document.getElementById("exitAsn").textContent =
        "ASN/ISP: " + (geo.asn || "-") + " / " + (geo.isp || "-");

      const torOk = exitData.is_tor === true;
      const privoxyOk = exitData.privoxy_is_tor === true;

      const torStatus = document.getElementById("exitTorStatus");
      torStatus.className = "badge " + (torOk ? "ok" : "warn");
      torStatus.textContent = "SOCKS Tor: " + (torOk ? "OK" : "KO");

      const privoxyStatus = document.getElementById("exitPrivoxyStatus");
      privoxyStatus.className = "badge " + (privoxyOk ? "ok" : "warn");
      privoxyStatus.textContent = "Privoxy: " + (privoxyOk ? "OK" : "KO") + " · " + privoxyIp;

      const mismatch = document.getElementById("exitMismatch");
      if (exitData.same_exit_ip === false) {
        mismatch.style.display = "block";
        mismatch.textContent = "Aviso: SOCKS Tor y Privoxy no devuelven la misma IP de salida.";
      } else {
        mismatch.style.display = "none";
        mismatch.textContent = "";
      }

      const lat = geo.lat;
      const lon = geo.lon;
      const map = document.getElementById("exitMap");
      const unavailable = document.getElementById("exitMapUnavailable");
      const unavailableTitle = document.getElementById("exitMapUnavailableTitle");
      const unavailableBody = document.getElementById("exitMapUnavailableBody");
      const unavailableLink = document.getElementById("exitMapUnavailableLink");

      function setMapFallback(title, body, linkHref, linkText) {
        map.removeAttribute("src");
        map.style.display = "none";

        unavailableTitle.textContent = title;
        unavailableBody.textContent = body;

        if (linkHref) {
          unavailableLink.href = linkHref;
          unavailableLink.textContent = linkText || "Abrir ubicación externa";
          unavailableLink.style.display = "inline-flex";
        } else {
          unavailableLink.removeAttribute("href");
          unavailableLink.style.display = "none";
          unavailableLink.textContent = "";
        }

        unavailable.style.display = "block";
      }

      if (lat !== null && lat !== undefined && lon !== null && lon !== undefined) {
        const latNum = Number(lat);
        const lonNum = Number(lon);
        const delta = 0.08;

        if (!Number.isNaN(latNum) && !Number.isNaN(lonNum)) {
          const bbox = [
            lonNum - delta,
            latNum - delta,
            lonNum + delta,
            latNum + delta
          ].join(",");

          map.src =
            "https://www.openstreetmap.org/export/embed.html?bbox=" +
            encodeURIComponent(bbox) +
            "&layer=mapnik&marker=" +
            encodeURIComponent(latNum + "," + lonNum);

          map.style.display = "block";
          unavailable.style.display = "none";
          return;
        }
      }

      if (!exitData.ip || exitData.ip === "N/D") {
        setMapFallback(
          "Esperando IP de salida",
          "Todavía no hay una IP pública de Tor disponible para ubicar en el mapa."
        );
        return;
      }

      if (locationParts.length) {
        setMapFallback(
          "Ubicación aproximada disponible",
          "Se ha resuelto la zona de salida, pero no hay coordenadas válidas para incrustar el mapa.",
          "https://www.openstreetmap.org/search?query=" + encodeURIComponent(locationParts.join(", ")),
          "Buscar zona en OpenStreetMap"
        );
        return;
      }

      setMapFallback(
        "Mapa no disponible",
        "La IP de salida existe, pero el proveedor de geolocalización no ha devuelto coordenadas utilizables.",
        "https://ipwho.is/" + encodeURIComponent(exitData.ip),
        "Ver detalle externo de la IP"
      );
    }


    async function loadStats() {
      const data = await apiGet("/api/stats");

      setBadge("torBadge", data.services.tor);
      setBadge("privoxyBadge", data.services.privoxy);

      document.getElementById("socksBadge").textContent =
        "SOCKS 9050: " + (data.ports["9050_socks"] ? "OK" : "KO");

      document.getElementById("controlBadge").textContent =
        "Control 9051: " + (data.ports["9051_control"] ? "OK" : "KO");

      document.getElementById("torVersion").textContent =
        data.tor.version ? "Versión: " + data.tor.version : data.tor.control_error || "---";

      updateExitCard(data);

      document.getElementById("circuits").textContent =
        (data.tor.circuits_built ?? 0) + " / " + (data.tor.circuits_total ?? 0);

      document.getElementById("streams").textContent =
        "Streams Tor: " + (data.tor.streams_total ?? 0);

      document.getElementById("readMb").textContent =
        (data.tor.traffic_read_mb ?? 0) + " MB";

      document.getElementById("writtenMb").textContent =
        (data.tor.traffic_written_mb ?? 0) + " MB";

      document.getElementById("readRate").textContent =
        "Actual: " + data.sample.read_mbps + " Mbps";

      document.getElementById("writtenRate").textContent =
        "Actual: " + data.sample.written_mbps + " Mbps";

      document.getElementById("cpu").textContent =
        data.system.cpu_percent + "% CPU";

      document.getElementById("mem").textContent =
        "RAM: " + Math.round(data.system.memory.percent) + "%";

      document.getElementById("activeClients").textContent =
        data.connections.active_clients;

      document.getElementById("activeConnections").textContent =
        data.connections.active_connections;

      document.getElementById("connectionsBreakdown").textContent =
        "SOCKS: " + data.connections.tor_socks_connections +
        " · Privoxy: " + data.connections.privoxy_connections;

      renderActiveClients(data.connections.clients);
      writeOutput(data);
    }
    async function loadHistory() {
      const hours = Number(document.getElementById("historyHours").value || "1");
      chartBaseHours = hours;

      const history = await apiGet("/api/history?hours=" + hours);
      lastHistoryData = history || [];

      renderHistoryCharts();
    }


    async function loadRecentClients() {
      const data = await apiGet("/api/clients/recent?minutes=10");
      document.getElementById("recentClients").textContent = data.count;
      renderRecentClients(data.clients);
    }

    function initEventsDates() {
      const from = document.getElementById("eventsDateFrom");
      const to = document.getElementById("eventsDateTo");

      if (!from || !to) return;

      const today = new Date();
      const todayText = today.toISOString().slice(0, 10);

      const yesterday = new Date(Date.now() - 24 * 3600 * 1000);
      const yesterdayText = yesterday.toISOString().slice(0, 10);

      if (!from.value) from.value = yesterdayText;
      if (!to.value) to.value = todayText;
    }

    async function loadEvents() {
      initEventsDates();

      const limitEl = document.getElementById("eventsLimit");
      const limit = limitEl ? Number(limitEl.value || "50") : 50;

      const data = await apiGet("/api/events?limit=" + encodeURIComponent(limit));
      renderEvents(data.events);
    }

    async function downloadEvents(format) {
      initEventsDates();

      const from = document.getElementById("eventsDateFrom")?.value;
      const to = document.getElementById("eventsDateTo")?.value;

      if (!from || !to) {
        writeOutput("Selecciona fecha desde y fecha hasta.");
        return;
      }

      const url =
        "/api/events/export?date_from=" + encodeURIComponent(from) +
        "&date_to=" + encodeURIComponent(to) +
        "&format=" + encodeURIComponent(format);

      try {
        const response = await fetch(url, { headers: headers() });

        if (!response.ok) {
          const text = await response.text();
          throw new Error("HTTP " + response.status + " - " + text);
        }

        const blob = await response.blob();
        const objectUrl = URL.createObjectURL(blob);

        const a = document.createElement("a");
        a.href = objectUrl;
        a.download = "proxytor-events-" + from + "_to_" + to + "." + format;
        document.body.appendChild(a);
        a.click();
        a.remove();

        URL.revokeObjectURL(objectUrl);

        writeOutput("Exportación generada: " + format.toUpperCase() + " " + from + " → " + to);
      } catch (e) {
        writeOutput("ERROR exportando eventos: " + e.message);
      }
    }


    async function loadAll() {
      try {
        await loadMe();
        await loadStats();
        await loadHistory();
        await loadRecentClients();
        await loadEvents();
      } catch (e) {
        writeOutput("ERROR: " + e.message);
      }
    }

    async function newnym() {
      if (!requireAdminUi()) return;
      try {
        const data = await apiPost("/api/action/newnym");
        writeOutput(data);
        setTimeout(loadAll, 2500);
      } catch (e) {
        writeOutput("ERROR: " + e.message);
      }
    }

    async function rotateToken() {
      if (!requireAdminUi()) return;
      const ok = confirm("¿Seguro que quieres rotar el token ADMIN? El token anterior seguirá funcionando durante 10 minutos.");
      if (!ok) return;

      try {
        const data = await apiPost("/api/action/rotate-token");
        tokenInput.value = "";
        writeOutput(data);
      } catch (e) {
        writeOutput("ERROR: " + e.message);
      }
    }

    async function rotateViewerToken() {
      if (!requireAdminUi()) return;
      const ok = confirm("¿Seguro que quieres rotar el token VIEWER?");
      if (!ok) return;

      try {
        const data = await apiPost("/api/action/rotate-viewer-token");
        writeOutput(data);
      } catch (e) {
        writeOutput("ERROR: " + e.message);
      }
    }

    async function serviceAction(service, action) {
      if (!requireAdminUi()) return;
      const confirmText = prompt("Escribe CONFIRMAR para ejecutar " + action + " sobre " + service);
      if (confirmText !== "CONFIRMAR") return;

      try {
        const data = await apiPost("/api/service/" + service + "/" + action);
        writeOutput(data);
        setTimeout(loadAll, 2500);
      } catch (e) {
        writeOutput("ERROR: " + e.message);
      }
    }

    async function getLogs(service) {
      if (!requireAdminUi()) return;
      try {
        const data = await apiGet("/api/logs/" + service);
        writeOutput(data.logs || data);
      } catch (e) {
        writeOutput("ERROR: " + e.message);
      }
    }

    if (getToken()) {
      loadAll();
    }

    setInterval(() => {
      if (getToken()) loadAll();
    }, 10000);
  </script>
</body>
</html>
"""


@app.get("/api/me")
def me(request: Request, authorization: Optional[str] = Header(default=None)):
    role = require_auth(request, authorization, "viewer")
    return {"role": role}


@app.get("/api/health")
def health(request: Request, authorization: Optional[str] = Header(default=None)):
    require_auth(request, authorization, "viewer")

    return {
        "tor_service": systemctl_is_active("tor@default"),
        "privoxy_service": systemctl_is_active("privoxy"),
        "tor_socks_9050": port_open("127.0.0.1", 9050),
        "tor_control_9051": port_open("127.0.0.1", 9051),
        "privoxy_8118": port_open("127.0.0.1", 8118),
    }


@app.get("/api/stats")
def stats(request: Request, authorization: Optional[str] = Header(default=None)):
    require_auth(request, authorization, "viewer")

    tor_info = get_tor_info()
    clients = get_client_connections()

    update_clients_db(clients)
    sample = build_history_sample(tor_info, clients)

    exit_tor = get_exit_ip_via_tor()
    exit_privoxy = get_exit_ip_via_privoxy()
    geo = geolocate_ip(exit_tor.get("IP", ""))

    store_exit_ips(exit_tor, exit_privoxy, geo)

    exit_status = {
        "ip": exit_tor.get("IP", ""),
        "is_tor": exit_tor.get("IsTor", False),
        "privoxy_ip": exit_privoxy.get("IP", ""),
        "privoxy_is_tor": exit_privoxy.get("IsTor", False),
        "same_exit_ip": exit_tor.get("IP", "") == exit_privoxy.get("IP", ""),
        "geo": geo,
    }

    payload = {
        "system": {
            "hostname": socket.gethostname(),
            "cpu_percent": psutil.cpu_percent(interval=0.5),
            "memory": psutil.virtual_memory()._asdict(),
            "disk_root": psutil.disk_usage("/")._asdict(),
            "boot_time": psutil.boot_time(),
        },
        "services": {
            "tor": systemctl_is_active("tor@default"),
            "privoxy": systemctl_is_active("privoxy"),
        },
        "ports": {
            "9050_socks": port_open("127.0.0.1", 9050),
            "9051_control": port_open("127.0.0.1", 9051),
            "8118_privoxy": port_open("127.0.0.1", 8118),
        },
        "tor": tor_info,
        "exit": exit_status,
        "exit_ip_tor": exit_tor,
        "exit_ip_privoxy": exit_privoxy,
        "exit_geo": geo,
        "connections": {
            "active_clients": len(clients),
            "active_connections": sum(c["total_connections"] for c in clients),
            "tor_socks_connections": sum(c["tor_socks_connections"] for c in clients),
            "privoxy_connections": sum(c["privoxy_connections"] for c in clients),
            "clients": clients,
        },
        "sample": sample,
    }

    assess_alerts(payload)

    return payload


@app.get("/api/history")
def history(
    request: Request,
    hours: int = 1,
    authorization: Optional[str] = Header(default=None),
):
    require_auth(request, authorization, "viewer")

    hours = max(1, min(hours, 168))
    since = now_ts() - (hours * 3600)

    with get_db() as conn:
        rows = conn.execute(
            """
            SELECT ts, read_mbps, written_mbps, active_clients, active_connections,
                   tor_socks_connections, privoxy_connections, streams_total, circuits_built
            FROM traffic_samples
            WHERE ts >= ?
            ORDER BY ts ASC
            """,
            (since,),
        ).fetchall()

    return rows_to_dicts(rows)


@app.get("/api/connections")
def connections(request: Request, authorization: Optional[str] = Header(default=None)):
    require_auth(request, authorization, "viewer")

    clients = get_client_connections()

    return {
        "active_clients": len(clients),
        "active_connections": sum(c["total_connections"] for c in clients),
        "tor_socks_connections": sum(c["tor_socks_connections"] for c in clients),
        "privoxy_connections": sum(c["privoxy_connections"] for c in clients),
        "clients": clients,
    }


@app.get("/api/clients/recent")
def recent_clients(
    request: Request,
    minutes: int = 10,
    authorization: Optional[str] = Header(default=None),
):
    require_auth(request, authorization, "viewer")

    minutes = max(1, min(minutes, 1440))
    since = now_ts() - (minutes * 60)

    with get_db() as conn:
        rows = conn.execute(
            """
            SELECT *
            FROM clients
            WHERE last_seen >= ?
            ORDER BY last_seen DESC
            """,
            (since,),
        ).fetchall()

    clients = rows_to_dicts(rows)

    return {
        "minutes": minutes,
        "count": len(clients),
        "clients": clients,
    }


@app.get("/api/events")
def events(
    request: Request,
    limit: int = 50,
    authorization: Optional[str] = Header(default=None),
):
    require_auth(request, authorization, "viewer")

    limit = max(1, min(limit, 500))

    with get_db() as conn:
        rows = conn.execute(
            """
            SELECT id, ts, severity, event_type, message, details, source_ip
            FROM events
            ORDER BY ts DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()

    return {
        "count": len(rows),
        "events": rows_to_dicts(rows),
    }


@app.get("/api/logs/{service}")
def logs(service: str, request: Request, authorization: Optional[str] = Header(default=None)):
    require_auth(request, authorization, "admin")
    log_event("info", "logs_read", f"Consulta de logs: {service}")
    return get_journal(service)


@app.post("/api/action/newnym")
def newnym(request: Request, authorization: Optional[str] = Header(default=None)):
    require_auth(request, authorization, "admin")
    enforce_admin_action_limit(request)

    try:
        before = get_exit_ip_via_tor()

        with tor_controller() as controller:
            available = controller.is_newnym_available()
            wait = controller.get_newnym_wait()

            if not available:
                return {
                    "ok": False,
                    "message": "NEWNYM no disponible todavía",
                    "wait_seconds": wait,
                }

            controller.signal(Signal.NEWNYM)

        EXIT_CACHE["tor"] = {"ts": 0, "data": {}}
        EXIT_CACHE["privoxy"] = {"ts": 0, "data": {}}

        time.sleep(2)
        after = get_exit_ip_via_tor()

        log_event(
            "info",
            "newnym",
            "Nueva identidad Tor solicitada",
            {
                "before": before,
                "after": after,
            },
        )

        return {
            "ok": True,
            "message": "Nueva identidad solicitada a Tor",
            "before": before,
            "after": after,
        }

    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


@app.post("/api/action/rotate-token")
def rotate_token(request: Request, authorization: Optional[str] = Header(default=None)):
    require_auth(request, authorization, "admin")
    enforce_admin_action_limit(request)

    write_new_token(TOKEN_FILE, TOKEN_PREVIOUS_FILE)

    log_event("warning", "rotate_admin_token", "Token admin rotado")

    send_telegram_message("<b>ProxyTor: token admin rotado</b>\n\nRecoge el nuevo token directamente del servidor.")

    return {
        "ok": True,
        "message": "Token admin rotado correctamente. Recoge el nuevo token en el servidor.",
        "token_grace_seconds": PREVIOUS_TOKEN_GRACE_SECONDS,
        "token_retrieval": f"sudo cat {TOKEN_FILE}",
    }


@app.post("/api/action/rotate-viewer-token")
def rotate_viewer_token(request: Request, authorization: Optional[str] = Header(default=None)):
    require_auth(request, authorization, "admin")
    enforce_admin_action_limit(request)

    write_new_token(VIEWER_TOKEN_FILE, None)

    log_event("warning", "rotate_viewer_token", "Token viewer rotado")

    return {
        "ok": True,
        "message": "Token viewer rotado correctamente. Recoge el nuevo token en el servidor.",
        "token_retrieval": f"sudo cat {VIEWER_TOKEN_FILE}",
    }


@app.post("/api/service/{service}/{action}")
def service_action(
    request: Request,
    service: str,
    action: str,
    authorization: Optional[str] = Header(default=None),
):
    require_auth(request, authorization, "admin")
    enforce_admin_action_limit(request)

    if service not in ACTION_SERVICES:
        raise HTTPException(status_code=400, detail="Servicio no permitido")

    if action not in ALLOWED_ACTIONS:
        raise HTTPException(status_code=400, detail="Acción no permitida")

    unit = ACTION_SERVICES[service]
    result = systemctl_action(service, action)
    result["active_after"] = systemctl_is_active(unit)

    log_event(
        "warning",
        "service_action",
        f"{action} ejecutado sobre {unit}",
        result,
    )

    return result


@app.get("/api/config")
def get_config(request: Request, authorization: Optional[str] = Header(default=None)):
    require_auth(request, authorization, "admin")
    return read_config()


@app.post("/api/config")
def set_config(
    request: Request,
    config: dict,
    authorization: Optional[str] = Header(default=None),
):
    require_auth(request, authorization, "admin")
    enforce_admin_action_limit(request)
    write_config(config)
    log_event("warning", "config_update", "Configuración ProxyTor actualizada", config)
    return read_config()


# ============================================================
# ProxyTor Abuse Detection + Telegram Ban Actions
# ============================================================

ABUSE_DEFAULTS = {
    "abuse_detection_enabled": True,
    "abuse_connections_per_client": 25,
    "abuse_alert_interval_seconds": 900,
    "ban_ports": [9050, 8118],
    "protected_ips": [
        "127.0.0.1",
        "LAN_GATEWAY_IP",
        "NPMPLUS_IP_1",
        "NPMPLUS_IP_2",
        "NPMPLUS_VIP"
    ]
}


def abuse_config() -> dict:
    config = read_config()
    merged = ABUSE_DEFAULTS.copy()
    merged.update(config)
    return merged


def init_abuse_db():
    with get_db() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS bans (
                ip TEXT PRIMARY KEY,
                reason TEXT DEFAULT '',
                created_ts INTEGER NOT NULL,
                expires_ts INTEGER DEFAULT 0,
                active INTEGER DEFAULT 1,
                source TEXT DEFAULT 'manual'
            )
        """)

        conn.execute("""
            CREATE TABLE IF NOT EXISTS abuse_alerts (
                ip TEXT PRIMARY KEY,
                last_alert_ts INTEGER NOT NULL,
                last_connections INTEGER DEFAULT 0,
                reason TEXT DEFAULT ''
            )
        """)

        conn.execute("CREATE INDEX IF NOT EXISTS idx_bans_active ON bans(active)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_bans_expires ON bans(expires_ts)")
        conn.commit()


def ensure_ban_chain():
    # Chain propia para no tocar reglas generales.
    result = run_root_helper(["iptables-ensure-chain"], timeout=20)
    if result["returncode"] != 0:
        raise RuntimeError(result["stderr"] or "No se pudo preparar la chain de bans")


def iptables_ban_ip(ip: str):
    result = run_root_helper(["iptables-ban-ip", ip], timeout=20)
    if result["returncode"] != 0:
        raise RuntimeError(result["stderr"] or f"No se pudo banear {ip}")


def iptables_unban_ip(ip: str):
    result = run_root_helper(["iptables-unban-ip", ip], timeout=20)
    if result["returncode"] != 0:
        raise RuntimeError(result["stderr"] or f"No se pudo desbanear {ip}")


def is_ip_bannable(ip: str) -> tuple[bool, str]:
    try:
        parsed = ipaddress.ip_address(ip)
    except Exception:
        return False, "IP no válida"

    if parsed.is_loopback:
        return False, "No se permite bannear loopback"

    config = abuse_config()
    protected = set(config.get("protected_ips", []))
    npmplus_ips = set(config.get("npmplus_ips", []))

    if ip in protected:
        return False, "IP protegida"

    if ip in npmplus_ips:
        return False, "IP de NPMplus protegida"

    return True, "OK"


def is_ip_banned(ip: str) -> bool:
    expire_old_bans()

    with get_db() as conn:
        row = conn.execute(
            "SELECT active FROM bans WHERE ip = ? AND active = 1",
            (ip,),
        ).fetchone()

    return bool(row)


def ban_ip(ip: str, duration_seconds: int = 0, reason: str = "manual", source: str = "manual") -> dict:
    allowed, msg = is_ip_bannable(ip)

    if not allowed:
        return {
            "ok": False,
            "ip": ip,
            "message": msg,
        }

    created = now_ts()
    expires = 0

    if duration_seconds and duration_seconds > 0:
        expires = created + int(duration_seconds)

    try:
        iptables_ban_ip(ip)
    except Exception as exc:
        return {
            "ok": False,
            "ip": ip,
            "message": f"No se pudo aplicar el ban en firewall: {exc}",
        }

    with get_db() as conn:
        conn.execute(
            """
            INSERT INTO bans (ip, reason, created_ts, expires_ts, active, source)
            VALUES (?, ?, ?, ?, 1, ?)
            ON CONFLICT(ip) DO UPDATE SET
                reason = excluded.reason,
                created_ts = excluded.created_ts,
                expires_ts = excluded.expires_ts,
                active = 1,
                source = excluded.source
            """,
            (ip, reason, created, expires, source),
        )
        conn.commit()

    log_event(
        "warning",
        "client_banned",
        f"Cliente baneado: {ip}",
        {
            "ip": ip,
            "duration_seconds": duration_seconds,
            "expires_ts": expires,
            "reason": reason,
            "source": source,
        },
        source_ip=ip,
    )

    send_telegram_message(
        "<b>ProxyTor: cliente baneado</b>\n\n"
        f"IP: <code>{html.escape(ip)}</code>\n"
        f"Motivo: <code>{html.escape(reason)}</code>\n"
        f"Duración: <code>{'permanente' if expires == 0 else str(duration_seconds) + 's'}</code>"
    )

    return {
        "ok": True,
        "ip": ip,
        "message": "IP baneada",
        "duration_seconds": duration_seconds,
        "expires_ts": expires,
    }


def unban_ip(ip: str, source: str = "manual") -> dict:
    try:
        iptables_unban_ip(ip)
    except Exception as exc:
        return {
            "ok": False,
            "ip": ip,
            "message": f"No se pudo retirar el ban en firewall: {exc}",
        }

    with get_db() as conn:
        conn.execute(
            "UPDATE bans SET active = 0 WHERE ip = ?",
            (ip,),
        )
        conn.commit()

    log_event(
        "warning",
        "client_unbanned",
        f"Cliente desbaneado: {ip}",
        {
            "ip": ip,
            "source": source,
        },
        source_ip=ip,
    )

    send_telegram_message(
        "<b>ProxyTor: cliente desbaneado</b>\n\n"
        f"IP: <code>{html.escape(ip)}</code>"
    )

    return {
        "ok": True,
        "ip": ip,
        "message": "IP desbaneada",
    }


def expire_old_bans():
    current = now_ts()

    try:
        ensure_ban_chain()
    except Exception as exc:
        log_event(
            "warning",
            "firewall_unavailable",
            f"No se pudieron revisar bans expirados: {exc}",
        )
        return

    with get_db() as conn:
        rows = conn.execute(
            """
            SELECT ip
            FROM bans
            WHERE active = 1
              AND expires_ts > 0
              AND expires_ts <= ?
            """,
            (current,),
        ).fetchall()

        for row in rows:
            ip = row["ip"]
            conn.execute(
                "UPDATE bans SET active = 0 WHERE ip = ?",
                (ip,),
            )
            iptables_unban_ip(ip)

            log_event(
                "info",
                "ban_expired",
                f"Ban expirado: {ip}",
                {"ip": ip},
                source_ip=ip,
            )

        conn.commit()


def apply_active_bans():
    try:
        ensure_ban_chain()
    except Exception as exc:
        log_event(
            "warning",
            "firewall_unavailable",
            f"Firewall no disponible para aplicar bans: {exc}",
        )
        return

    expire_old_bans()

    with get_db() as conn:
        rows = conn.execute(
            "SELECT ip FROM bans WHERE active = 1",
        ).fetchall()

    for row in rows:
        iptables_ban_ip(row["ip"])


def get_bans(active_only: bool = False):
    expire_old_bans()

    query = """
        SELECT ip, reason, created_ts, expires_ts, active, source
        FROM bans
    """

    params = []

    if active_only:
        query += " WHERE active = 1"

    query += " ORDER BY created_ts DESC"

    with get_db() as conn:
        rows = conn.execute(query, params).fetchall()

    bans = []

    for row in rows:
        item = dict(row)
        item["created_text"] = fmt_ts(item["created_ts"])
        item["expires_text"] = "Permanente" if not item["expires_ts"] else fmt_ts(item["expires_ts"])
        bans.append(item)

    return bans


def send_telegram_message(message: str, reply_markup: Optional[dict] = None):
    config = read_config()

    if not config.get("telegram_alerts", True):
        return False

    tg = parse_env_file(TELEGRAM_CONFIG)
    bot_token = tg.get("TELEGRAM_BOT_TOKEN", "")
    chat_id = tg.get("TELEGRAM_CHAT_ID", "")

    if not bot_token or not chat_id:
        return False

    data = {
        "chat_id": chat_id,
        "text": message,
        "parse_mode": "HTML",
        "disable_web_page_preview": True,
    }

    if reply_markup:
        data["reply_markup"] = json.dumps(reply_markup)

    try:
        response = requests.post(
            f"https://api.telegram.org/bot{bot_token}/sendMessage",
            data=data,
            headers={"User-Agent": HTTP_USER_AGENT, "Accept": "application/json"},
            timeout=12,
        )
        response.raise_for_status()
        return True
    except Exception:
        return False


def send_abuse_alert(client: dict):
    ip = client.get("ip", "")
    total = int(client.get("total_connections", 0))
    socks = int(client.get("tor_socks_connections", 0))
    privoxy = int(client.get("privoxy_connections", 0))
    device_type = client.get("device_type", "Desconocido")
    hostname = client.get("hostname", "")

    keyboard = {
        "inline_keyboard": [
            [
                {"text": "Ban 1h", "callback_data": f"ban|{ip}|3600"},
                {"text": "Ban 24h", "callback_data": f"ban|{ip}|86400"}
            ],
            [
                {"text": "Ban permanente", "callback_data": f"ban|{ip}|0"},
                {"text": "Ignorar", "callback_data": f"ignore|{ip}"}
            ]
        ]
    }

    message = (
        "<b>ProxyTor: posible abuso detectado</b>\n\n"
        f"IP: <code>{html.escape(ip)}</code>\n"
        f"Hostname: <code>{html.escape(hostname or '-')}</code>\n"
        f"Tipo: <code>{html.escape(device_type)}</code>\n"
        f"Conexiones totales: <code>{total}</code>\n"
        f"SOCKS: <code>{socks}</code>\n"
        f"Privoxy: <code>{privoxy}</code>\n\n"
        "Puedes bannear este cliente desde los botones inferiores."
    )

    send_telegram_message(message, reply_markup=keyboard)

    log_event(
        "warning",
        "abuse_detected",
        f"Posible abuso detectado: {ip}",
        client,
        source_ip=ip,
    )


def check_abuse_clients(clients: list):
    config = abuse_config()

    if not config.get("abuse_detection_enabled", True):
        return

    threshold = int(config.get("abuse_connections_per_client", 25))
    interval = int(config.get("abuse_alert_interval_seconds", 900))
    current = now_ts()

    protected = set(config.get("protected_ips", [])) | set(config.get("npmplus_ips", []))

    for client in clients:
        ip = client.get("ip", "")
        total = int(client.get("total_connections", 0))

        if not ip or ip in protected:
            continue

        if client.get("via_npmplus"):
            continue

        if is_ip_banned(ip):
            continue

        if total < threshold:
            continue

        with get_db() as conn:
            row = conn.execute(
                "SELECT last_alert_ts FROM abuse_alerts WHERE ip = ?",
                (ip,),
            ).fetchone()

            if row and current - int(row["last_alert_ts"]) < interval:
                continue

            conn.execute(
                """
                INSERT INTO abuse_alerts (ip, last_alert_ts, last_connections, reason)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(ip) DO UPDATE SET
                    last_alert_ts = excluded.last_alert_ts,
                    last_connections = excluded.last_connections,
                    reason = excluded.reason
                """,
                (
                    ip,
                    current,
                    total,
                    f"{total} conexiones activas",
                ),
            )
            conn.commit()

        send_abuse_alert(client)


# Guardamos referencia a assess_alerts anterior y la ampliamos.
try:
    _previous_assess_alerts = assess_alerts
except NameError:
    _previous_assess_alerts = None


def assess_alerts(stats_payload: dict):
    if _previous_assess_alerts:
        try:
            _previous_assess_alerts(stats_payload)
        except Exception:
            pass

    try:
        clients = stats_payload.get("connections", {}).get("clients", [])
        check_abuse_clients(clients)
    except Exception as exc:
        log_event(
            "error",
            "abuse_detection_error",
            f"Error en detección de abuso: {exc}",
        )


@app.on_event("startup")
def startup_abuse_event():
    init_abuse_db()
    apply_active_bans()
    log_event("info", "abuse_module_start", "Módulo de abuso y ban iniciado")


@app.get("/api/bans")
def api_bans(
    request: Request,
    active_only: bool = False,
    authorization: Optional[str] = Header(default=None),
):
    require_auth(request, authorization, "viewer")

    return {
        "active_only": active_only,
        "bans": get_bans(active_only=active_only),
    }


@app.post("/api/action/ban/{ip}")
def api_ban_ip(
    request: Request,
    ip: str,
    duration_seconds: int = 0,
    reason: str = "manual",
    authorization: Optional[str] = Header(default=None),
):
    require_auth(request, authorization, "admin")
    enforce_admin_action_limit(request)
    return ban_ip(ip, duration_seconds, reason, source="api")


@app.post("/api/action/unban/{ip}")
def api_unban_ip(
    request: Request,
    ip: str,
    authorization: Optional[str] = Header(default=None),
):
    require_auth(request, authorization, "admin")
    enforce_admin_action_limit(request)
    return unban_ip(ip, source="api")


@app.post("/api/action/ban-cleanup")
def api_ban_cleanup(
    request: Request,
    authorization: Optional[str] = Header(default=None),
):
    require_auth(request, authorization, "admin")
    enforce_admin_action_limit(request)
    expire_old_bans()
    apply_active_bans()
    return {
        "ok": True,
        "message": "Bans revisados y aplicados",
    }



@app.get("/api/events/export")
def events_export(
    request: Request,
    date_from: str,
    date_to: str,
    format: str = "csv",
    authorization: Optional[str] = Header(default=None),
):
    require_auth(request, authorization, "viewer")

    config = read_config()

    if not config.get("events_export_enabled", True):
        raise HTTPException(status_code=403, detail="Events export disabled")

    try:
        start_dt = datetime.strptime(date_from, "%Y-%m-%d")
        end_dt = datetime.strptime(date_to, "%Y-%m-%d") + timedelta(days=1)
    except Exception:
        raise HTTPException(status_code=400, detail="Formato de fecha inválido. Usa YYYY-MM-DD")

    start_ts = int(time.mktime(start_dt.timetuple()))
    end_ts = int(time.mktime(end_dt.timetuple()))

    if end_ts <= start_ts:
        raise HTTPException(status_code=400, detail="Rango de fechas inválido")

    with get_db() as conn:
        rows = conn.execute(
            """
            SELECT id, ts, severity, event_type, message, details, source_ip
            FROM events
            WHERE ts >= ?
              AND ts < ?
            ORDER BY ts ASC
            """,
            (start_ts, end_ts),
        ).fetchall()

    items = rows_to_dicts(rows)
    export_format = format.lower().strip()

    if export_format == "json":
        content = json.dumps(items, ensure_ascii=False, indent=2)
        filename = f"proxytor-events-{date_from}_to_{date_to}.json"

        return Response(
            content=content,
            media_type="application/json",
            headers={
                "Content-Disposition": f'attachment; filename="{filename}"'
            },
        )

    if export_format != "csv":
        raise HTTPException(status_code=400, detail="Formato no soportado. Usa csv o json")

    output = io.StringIO()
    writer = csv.writer(output)

    writer.writerow([
        "id",
        "fecha",
        "timestamp",
        "severidad",
        "tipo",
        "mensaje",
        "ip_origen",
        "detalles",
    ])

    for item in items:
        writer.writerow([
            item.get("id", ""),
            item.get("time", ""),
            item.get("ts", ""),
            item.get("severity", ""),
            item.get("event_type", ""),
            item.get("message", ""),
            item.get("source_ip", ""),
            item.get("details", ""),
        ])

    filename = f"proxytor-events-{date_from}_to_{date_to}.csv"

    return Response(
        content=output.getvalue(),
        media_type="text/csv; charset=utf-8",
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"'
        },
    )
