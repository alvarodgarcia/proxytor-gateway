import os
import time
import socket
import secrets
import subprocess
from pathlib import Path

import requests


TOKEN_FILE = Path("/etc/proxytor-api/token")
TOKEN_PREVIOUS_FILE = Path("/etc/proxytor-api/token.previous")

VIEWER_TOKEN_FILE = Path("/etc/proxytor-api/token.viewer")
VIEWER_TOKEN_PREVIOUS_FILE = Path("/etc/proxytor-api/token.viewer.previous")

TELEGRAM_CONFIG = Path("/etc/default/proxytor-telegram")

DEFAULT_PROXYTOR_URL = "https://proxytor.example.com/"
LOCAL_API_URL = "http://127.0.0.1:8088"


def load_env_file(path: Path) -> dict:
    values = {}

    if not path.exists():
        return values

    content = path.read_text()

    for line in content.splitlines():
        line = line.strip()

        if not line or line.startswith("#") or "=" not in line:
            continue

        key, value = line.split("=", 1)
        values[key.strip()] = value.strip().strip('"').strip("'")

    return values


def ensure_token_file(path: Path) -> str:
    path.parent.mkdir(parents=True, exist_ok=True)

    if not path.exists():
        token = secrets.token_hex(32)
        path.write_text(token + "\n")
        os.chmod(path, 0o600)
        return token

    token = path.read_text().strip()

    if not token:
        token = secrets.token_hex(32)
        path.write_text(token + "\n")
        os.chmod(path, 0o600)

    return token


def get_token(path: Path) -> str:
    try:
        return ensure_token_file(path)
    except Exception:
        return ""


def rotate_token(path: Path, previous_path: Path) -> str:
    path.parent.mkdir(parents=True, exist_ok=True)

    current = ""
    if path.exists():
        current = path.read_text().strip()

    if current:
        previous_path.write_text(current + "\n")
        os.chmod(previous_path, 0o600)

    new_token = secrets.token_hex(32)

    tmp_file = path.with_suffix(".tmp")
    tmp_file.write_text(new_token + "\n")
    os.chmod(tmp_file, 0o600)
    os.replace(tmp_file, path)
    os.chmod(path, 0o600)

    return new_token


def api_headers():
    token = get_token(TOKEN_FILE)

    return {
        "Authorization": f"Bearer {token}"
    }


def api_post(path: str, params: dict | None = None):
    try:
        response = requests.post(
            LOCAL_API_URL + path,
            headers=api_headers(),
            params=params or {},
            timeout=20,
        )
        try:
            return response.status_code, response.json()
        except Exception:
            return response.status_code, {"text": response.text}
    except Exception as exc:
        return 0, {"error": str(exc)}


def api_get(path: str, params: dict | None = None):
    try:
        response = requests.get(
            LOCAL_API_URL + path,
            headers=api_headers(),
            params=params or {},
            timeout=20,
        )
        try:
            return response.status_code, response.json()
        except Exception:
            return response.status_code, {"text": response.text}
    except Exception as exc:
        return 0, {"error": str(exc)}


def parse_duration(value: str) -> int:
    value = value.lower().strip()

    if value in ("0", "perm", "permanent", "permanente"):
        return 0

    if value.endswith("h"):
        return int(value[:-1]) * 3600

    if value.endswith("m"):
        return int(value[:-1]) * 60

    if value.endswith("s"):
        return int(value[:-1])

    return int(value)


def human_duration(seconds: int) -> str:
    if seconds == 0:
        return "permanente"

    if seconds % 86400 == 0:
        return f"{seconds // 86400}d"

    if seconds % 3600 == 0:
        return f"{seconds // 3600}h"

    if seconds % 60 == 0:
        return f"{seconds // 60}m"

    return f"{seconds}s"


def systemctl_is_active(service: str) -> bool:
    result = subprocess.run(
        ["systemctl", "is-active", "--quiet", service],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    return result.returncode == 0


def port_open(host: str, port: int, timeout: float = 2.0) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except Exception:
        return False


def get_exit_ip_via_privoxy() -> dict:
    try:
        response = requests.get(
            "https://check.torproject.org/api/ip",
            proxies={
                "http": "http://127.0.0.1:8118",
                "https": "http://127.0.0.1:8118",
            },
            timeout=20,
        )
        return response.json()
    except Exception as exc:
        return {"error": str(exc)}


def get_exit_ip_via_tor() -> dict:
    try:
        response = requests.get(
            "https://check.torproject.org/api/ip",
            proxies={
                "http": "socks5h://127.0.0.1:9050",
                "https": "socks5h://127.0.0.1:9050",
            },
            timeout=20,
        )
        return response.json()
    except Exception as exc:
        return {"error": str(exc)}


tg_env = load_env_file(TELEGRAM_CONFIG)

BOT_TOKEN = tg_env.get("TELEGRAM_BOT_TOKEN", "")
AUTHORIZED_CHAT_ID = str(tg_env.get("TELEGRAM_CHAT_ID", ""))
PROXYTOR_URL = tg_env.get("PROXYTOR_URL", DEFAULT_PROXYTOR_URL)

BASE_URL = f"https://api.telegram.org/bot{BOT_TOKEN}"


def send_message(chat_id, text, reply_markup=None):
    try:
        data = {
            "chat_id": chat_id,
            "text": text,
            "parse_mode": "HTML",
            "disable_web_page_preview": True,
        }

        if reply_markup:
            import json
            data["reply_markup"] = json.dumps(reply_markup)

        requests.post(
            f"{BASE_URL}/sendMessage",
            data=data,
            timeout=15,
        )
    except Exception as exc:
        print(f"ERROR enviando mensaje Telegram: {exc}", flush=True)


def answer_callback(callback_query_id, text="OK"):
    try:
        requests.post(
            f"{BASE_URL}/answerCallbackQuery",
            data={
                "callback_query_id": callback_query_id,
                "text": text,
                "show_alert": False,
            },
            timeout=10,
        )
    except Exception:
        pass


def send_not_authorized(chat_id):
    send_message(chat_id, "No autorizado.")


def command_help() -> str:
    return (
        "<b>ProxyTor Bot</b>\n\n"
        "Comandos disponibles:\n\n"
        "/token - Ver token lector/viewer\n"
        "/token_viewer - Ver token lector/viewer\n"
        "/token_admin - Ver token administrador\n"
        "/rotate_viewer_token - Rotar token lector/viewer\n"
        "/rotate_admin_token - Rotar token administrador\n"
        "/rotate_token - Rotar token administrador\n"
        "/status - Estado básico\n"
        "/url - URL del dashboard\n"
        "/bans - Ver IPs baneadas\n"
        "/ban IP 1h - Ban temporal\n"
        "/ban IP 24h - Ban 24 horas\n"
        "/ban IP permanente - Ban permanente\n"
        "/unban IP - Quitar ban\n"
        "/help - Ayuda\n\n"
        "Ejemplos:\n"
        "<code>/ban CLIENT_IP 1h</code>\n"
        "<code>/ban CLIENT_IP permanente</code>\n"
        "<code>/unban CLIENT_IP</code>"
    )


def handle_callback(callback):
    callback_id = callback.get("id")
    message = callback.get("message", {})
    chat = message.get("chat", {})
    chat_id = str(chat.get("id", ""))
    data = callback.get("data", "")

    if chat_id != AUTHORIZED_CHAT_ID:
        answer_callback(callback_id, "No autorizado")
        return

    parts = data.split("|")

    if not parts:
        answer_callback(callback_id, "Callback inválido")
        return

    action = parts[0]

    if action == "ban" and len(parts) == 3:
        ip = parts[1]
        duration = int(parts[2])

        status, result = api_post(
            f"/api/action/ban/{ip}",
            params={
                "duration_seconds": duration,
                "reason": f"abuse_alert_telegram_{human_duration(duration)}",
            },
        )

        if status == 200 and result.get("ok"):
            answer_callback(callback_id, "Cliente baneado")
            send_message(
                chat_id,
                "<b>ProxyTor: ban aplicado</b>\n\n"
                f"IP: <code>{ip}</code>\n"
                f"Duración: <code>{human_duration(duration)}</code>"
            )
        else:
            answer_callback(callback_id, "No se pudo bannear")
            send_message(
                chat_id,
                "<b>Error aplicando ban</b>\n\n"
                f"IP: <code>{ip}</code>\n"
                f"Resultado: <code>{result}</code>"
            )

    elif action == "ignore" and len(parts) == 2:
        ip = parts[1]
        answer_callback(callback_id, "Ignorado")
        send_message(
            chat_id,
            "<b>ProxyTor: alerta ignorada</b>\n\n"
            f"IP: <code>{ip}</code>"
        )

    else:
        answer_callback(callback_id, "Callback no reconocido")


def handle_message(message):
    chat = message.get("chat", {})
    chat_id = str(chat.get("id", ""))
    text = message.get("text", "").strip()

    if chat_id != AUTHORIZED_CHAT_ID:
        send_not_authorized(chat_id)
        return

    if text in ("/start", "/help"):
        send_message(chat_id, command_help())

    elif text == "/url":
        send_message(
            chat_id,
            f"<b>ProxyTor Dashboard</b>\n\n"
            f"<code>{PROXYTOR_URL}</code>"
        )

    elif text in ("/token", "/token_viewer"):
        viewer_token = get_token(VIEWER_TOKEN_FILE)

        msg = (
            "<b>ProxyTor VIEWER Token</b>\n\n"
            "Permisos: solo lectura.\n\n"
            f"URL:\n<code>{PROXYTOR_URL}</code>\n\n"
            f"Token viewer:\n<code>{viewer_token}</code>"
        )

        send_message(chat_id, msg)

    elif text == "/token_admin":
        admin_token = get_token(TOKEN_FILE)

        msg = (
            "<b>ProxyTor ADMIN Token</b>\n\n"
            "Permisos: acciones completas.\n\n"
            f"URL:\n<code>{PROXYTOR_URL}</code>\n\n"
            f"Token admin:\n<code>{admin_token}</code>"
        )

        send_message(chat_id, msg)

    elif text in ("/rotate_token", "/rotate_admin_token"):
        new_token = rotate_token(TOKEN_FILE, TOKEN_PREVIOUS_FILE)

        msg = (
            "<b>ProxyTor ADMIN Token rotado</b>\n\n"
            "El token admin anterior ha dejado de ser válido.\n\n"
            f"URL:\n<code>{PROXYTOR_URL}</code>\n\n"
            f"Nuevo token admin:\n<code>{new_token}</code>"
        )

        send_message(chat_id, msg)

    elif text == "/rotate_viewer_token":
        new_token = rotate_token(VIEWER_TOKEN_FILE, VIEWER_TOKEN_PREVIOUS_FILE)

        msg = (
            "<b>ProxyTor VIEWER Token rotado</b>\n\n"
            "El token viewer anterior ha dejado de ser válido.\n\n"
            f"URL:\n<code>{PROXYTOR_URL}</code>\n\n"
            f"Nuevo token viewer:\n<code>{new_token}</code>"
        )

        send_message(chat_id, msg)

    elif text == "/bans":
        status, result = api_get("/api/bans", params={"active_only": True})

        if status != 200:
            send_message(chat_id, f"Error consultando bans: <code>{result}</code>")
            return

        bans = result.get("bans", [])

        if not bans:
            send_message(chat_id, "No hay IPs baneadas activas.")
            return

        lines = ["<b>ProxyTor Bans activos</b>\n"]

        for ban in bans:
            lines.append(
                f"IP: <code>{ban.get('ip')}</code>\n"
                f"Motivo: <code>{ban.get('reason')}</code>\n"
                f"Expira: <code>{ban.get('expires_text')}</code>\n"
            )

        send_message(chat_id, "\n".join(lines))

    elif text.startswith("/ban "):
        parts = text.split()

        if len(parts) < 3:
            send_message(chat_id, "Uso: <code>/ban IP 1h</code>")
            return

        ip = parts[1]
        duration_text = parts[2]

        try:
            duration = parse_duration(duration_text)
        except Exception:
            send_message(chat_id, "Duración no válida. Usa 1h, 24h, 30m o permanente.")
            return

        status, result = api_post(
            f"/api/action/ban/{ip}",
            params={
                "duration_seconds": duration,
                "reason": f"manual_telegram_{human_duration(duration)}",
            },
        )

        send_message(
            chat_id,
            "<b>Resultado ban</b>\n\n"
            f"HTTP: <code>{status}</code>\n"
            f"Respuesta: <code>{result}</code>"
        )

    elif text.startswith("/unban "):
        parts = text.split()

        if len(parts) < 2:
            send_message(chat_id, "Uso: <code>/unban IP</code>")
            return

        ip = parts[1]

        status, result = api_post(f"/api/action/unban/{ip}")

        send_message(
            chat_id,
            "<b>Resultado unban</b>\n\n"
            f"HTTP: <code>{status}</code>\n"
            f"Respuesta: <code>{result}</code>"
        )

    elif text == "/status":
        tor_active = systemctl_is_active("tor@default")
        privoxy_active = systemctl_is_active("privoxy")
        api_active = systemctl_is_active("proxytor-api")
        telegram_active = systemctl_is_active("proxytor-telegram-bot")
        token_rotate_timer = systemctl_is_active("proxytor-token-rotate.timer")

        socks_9050 = port_open("127.0.0.1", 9050)
        control_9051 = port_open("127.0.0.1", 9051)
        privoxy_8118 = port_open("127.0.0.1", 8118)
        api_8088 = port_open("127.0.0.1", 8088)

        exit_tor = get_exit_ip_via_tor()
        exit_privoxy = get_exit_ip_via_privoxy()

        msg = (
            "<b>ProxyTor Status</b>\n\n"
            f"Tor service: <code>{tor_active}</code>\n"
            f"Privoxy service: <code>{privoxy_active}</code>\n"
            f"API service: <code>{api_active}</code>\n"
            f"Telegram bot: <code>{telegram_active}</code>\n"
            f"Token rotate timer: <code>{token_rotate_timer}</code>\n\n"
            f"SOCKS 9050: <code>{socks_9050}</code>\n"
            f"ControlPort 9051: <code>{control_9051}</code>\n"
            f"Privoxy 8118: <code>{privoxy_8118}</code>\n"
            f"API 8088: <code>{api_8088}</code>\n\n"
            f"Tor IP: <code>{exit_tor.get('IP', 'N/D')}</code>\n"
            f"Tor IsTor: <code>{exit_tor.get('IsTor', 'N/D')}</code>\n\n"
            f"Privoxy IP: <code>{exit_privoxy.get('IP', 'N/D')}</code>\n"
            f"Privoxy IsTor: <code>{exit_privoxy.get('IsTor', 'N/D')}</code>\n\n"
            f"URL: <code>{PROXYTOR_URL}</code>"
        )

        send_message(chat_id, msg)

    else:
        send_message(
            chat_id,
            "Comando no reconocido.\n\n" + command_help()
        )


def clear_webhook():
    try:
        requests.get(
            f"{BASE_URL}/deleteWebhook",
            params={"drop_pending_updates": "true"},
            timeout=10,
        )
    except Exception:
        pass


def main():
    if not BOT_TOKEN:
        raise RuntimeError("Falta TELEGRAM_BOT_TOKEN en /etc/default/proxytor-telegram")

    if not AUTHORIZED_CHAT_ID:
        raise RuntimeError("Falta TELEGRAM_CHAT_ID en /etc/default/proxytor-telegram")

    ensure_token_file(TOKEN_FILE)
    ensure_token_file(VIEWER_TOKEN_FILE)

    clear_webhook()

    offset = None

    print("ProxyTor Telegram Bot iniciado.", flush=True)
    print(f"Chat autorizado: {AUTHORIZED_CHAT_ID}", flush=True)
    print(f"Dashboard URL: {PROXYTOR_URL}", flush=True)

    while True:
        try:
            params = {
                "timeout": 30,
                "allowed_updates": '["message","callback_query"]',
            }

            if offset:
                params["offset"] = offset

            response = requests.get(
                f"{BASE_URL}/getUpdates",
                params=params,
                timeout=40,
            )

            data = response.json()

            if not data.get("ok"):
                print(f"Respuesta Telegram no OK: {data}", flush=True)
                time.sleep(5)
                continue

            for update in data.get("result", []):
                offset = update["update_id"] + 1

                if "callback_query" in update:
                    handle_callback(update["callback_query"])

                message = update.get("message")
                if message:
                    handle_message(message)

        except Exception as exc:
            print(f"ERROR: {exc}", flush=True)
            time.sleep(5)


if __name__ == "__main__":
    main()
