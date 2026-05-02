#!/usr/bin/env bash
set -euo pipefail

INSTALL_DIR="${INSTALL_DIR:-/opt/proxytor-api}"
CONFIG_DIR="${CONFIG_DIR:-/etc/proxytor-api}"
DATA_DIR="${DATA_DIR:-/var/lib/proxytor-api}"
DEFAULT_DIR="/etc/default"
BACKUP_ROOT="${BACKUP_ROOT:-/root/proxytor-install-backups}"
BACKUP_DIR="$BACKUP_ROOT/$(date +%F_%H%M%S)"
LOG_FILE="${LOG_FILE:-/var/log/proxytor-install.log}"

FORCE_CONFIG="false"
DRY_RUN="false"
SKIP_PACKAGES="false"

usage() {
  cat <<'EOF'
ProxyTor Gateway installer

Usage:
  sudo bash scripts/install.sh [options]

Options:
  --force-config    Replace /etc/tor/torrc and /etc/privoxy/config with ProxyTor examples.
  --dry-run         Show actions without changing files or restarting services.
  --skip-packages   Skip apt update/install. Useful for repeat runs in prepared systems.
  -h, --help        Show this help.

Default behaviour is conservative and safer to re-run:
  - existing tokens are preserved
  - existing config.json is preserved
  - existing Telegram env file is preserved
  - existing Tor/Privoxy configs are not overwritten unless --force-config is used
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --force-config)
      FORCE_CONFIG="true"
      shift
      ;;
    --dry-run)
      DRY_RUN="true"
      shift
      ;;
    --skip-packages)
      SKIP_PACKAGES="true"
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "ERROR: unknown option: $1" >&2
      usage
      exit 1
      ;;
  esac
done

if [[ "${EUID}" -ne 0 ]]; then
  echo "ERROR: this installer must be run as root." >&2
  exit 1
fi

touch "$LOG_FILE"
chmod 600 "$LOG_FILE"
exec > >(tee -a "$LOG_FILE") 2>&1

# Track whether Tor/Privoxy configuration existed before package installation.
# Debian packages create default config files during apt install; those should not
# be treated as user-provided pre-existing configuration on a fresh install.
HAD_TOR_CONFIG="false"
HAD_PRIVOXY_CONFIG="false"

if [[ -f /etc/tor/torrc ]]; then
  HAD_TOR_CONFIG="true"
fi

if [[ -f /etc/privoxy/config ]]; then
  HAD_PRIVOXY_CONFIG="true"
fi

echo "=================================================="
echo " ProxyTor Gateway installer"
echo "=================================================="
echo "Install dir : $INSTALL_DIR"
echo "Config dir  : $CONFIG_DIR"
echo "Data dir    : $DATA_DIR"
echo "Backup dir  : $BACKUP_DIR"
echo "Force config: $FORCE_CONFIG"
echo "Dry run     : $DRY_RUN"
echo

run() {
  if [[ "$DRY_RUN" == "true" ]]; then
    printf '[dry-run] '
    printf '%q ' "$@"
    printf '\n'
  else
    "$@"
  fi
}

ensure_backup_dir() {
  if [[ "$DRY_RUN" == "true" ]]; then
    echo "[dry-run] mkdir -p $BACKUP_DIR"
  else
    mkdir -p "$BACKUP_DIR"
  fi
}

backup_file() {
  local source_file="$1"

  if [[ ! -e "$source_file" ]]; then
    return 0
  fi

  ensure_backup_dir

  local safe_name
  safe_name="${source_file#/}"
  safe_name="${safe_name//\//__}"

  run cp -a "$source_file" "$BACKUP_DIR/$safe_name"
}

install_file() {
  local source_file="$1"
  local destination_file="$2"
  local mode="${3:-644}"

  backup_file "$destination_file"
  run install -D -m "$mode" "$source_file" "$destination_file"
}

install_if_missing() {
  local source_file="$1"
  local destination_file="$2"
  local mode="${3:-600}"

  if [[ -e "$destination_file" ]]; then
    echo "Preserving existing file: $destination_file"
    return 0
  fi

  run install -D -m "$mode" "$source_file" "$destination_file"
}

copy_example() {
  local source_file="$1"
  local destination_file="$2"
  local mode="${3:-644}"

  run install -D -m "$mode" "$source_file" "$destination_file"
}

write_token_if_missing() {
  local token_file="$1"

  if [[ -f "$token_file" ]]; then
    echo "Preserving existing token: $token_file"
    run chmod 600 "$token_file"
    run chown root:root "$token_file"
    return 0
  fi

  if [[ "$DRY_RUN" == "true" ]]; then
    echo "[dry-run] generate token: $token_file"
  else
    umask 077
    openssl rand -hex 32 > "$token_file"
    chmod 600 "$token_file"
    chown root:root "$token_file"
  fi
}

detect_server_ip() {
  local detected_ip=""

  detected_ip="$(ip -4 route get 1.1.1.1 2>/dev/null | awk '{for (i=1; i<=NF; i++) if ($i == "src") {print $(i+1); exit}}')"

  if [[ -z "$detected_ip" ]]; then
    detected_ip="$(hostname -I 2>/dev/null | awk '{print $1}')"
  fi

  if [[ -z "$detected_ip" ]]; then
    detected_ip="SERVER_IP"
  fi

  echo "$detected_ip"
}

print_final_summary() {
  local server_ip
  server_ip="$(detect_server_ip)"

  echo
  echo "=================================================="
  echo " ProxyTor Gateway installation summary"
  echo "=================================================="
  echo
  echo "Dashboard:"
  echo "  http://${server_ip}:8088/"
  echo
  echo "Proxy endpoints:"
  echo "  Privoxy HTTP proxy : http://${server_ip}:8118"
  echo "  Tor SOCKS5 proxy   : ${server_ip}:9050"
  echo
  echo "Local service checks:"
  echo "  systemctl status tor@default --no-pager"
  echo "  systemctl status privoxy --no-pager"
  echo "  systemctl status proxytor-api --no-pager"
  echo
  echo "Logs:"
  echo "  Installer : $LOG_FILE"
  echo "  API       : journalctl -u proxytor-api -n 120 --no-pager"
  echo "  Tor       : journalctl -u tor@default -n 120 --no-pager"
  echo "  Privoxy   : journalctl -u privoxy -n 120 --no-pager"
  echo

  echo "Admin token:"
  if [[ "$DRY_RUN" == "true" ]]; then
    echo "  [dry-run] $CONFIG_DIR/token"
  elif [[ -f "$CONFIG_DIR/token" ]]; then
    cat "$CONFIG_DIR/token"
  else
    echo "  Not available yet: $CONFIG_DIR/token"
  fi

  echo
  echo "Viewer token:"
  if [[ "$DRY_RUN" == "true" ]]; then
    echo "  [dry-run] $CONFIG_DIR/token.viewer"
  elif [[ -f "$CONFIG_DIR/token.viewer" ]]; then
    cat "$CONFIG_DIR/token.viewer"
  else
    echo "  Not available yet: $CONFIG_DIR/token.viewer"
  fi

  echo
  echo "Optional admin token auto-rotation:"
  echo "  sudo systemctl enable --now proxytor-token-rotate.timer"
  echo "  systemctl list-timers | grep proxytor"
  echo "  systemctl status proxytor-token-rotate.timer --no-pager"
  echo "  sudo /opt/proxytor-api/scripts/rotate-token.sh"
  echo "  sudo systemctl disable --now proxytor-token-rotate.timer"
  echo
  echo "Note: automatic rotation only affects the admin token. Viewer token rotation remains manual."
}

on_install_error() {
  local exit_code="$?"

  echo
  echo "==================================================" >&2
  echo " ProxyTor Gateway installer failed" >&2
  echo "==================================================" >&2
  echo "Exit code: $exit_code" >&2
  echo "Installer log: $LOG_FILE" >&2
  echo

  systemctl status tor@default --no-pager >&2 || true
  systemctl status privoxy --no-pager >&2 || true
  systemctl status proxytor-api --no-pager >&2 || true

  echo
  echo "Recent ProxyTor API logs:" >&2
  journalctl -u proxytor-api -n 120 --no-pager >&2 || true

  print_final_summary || true

  exit "$exit_code"
}

trap on_install_error ERR

validate_tor_config() {
  if [[ "$DRY_RUN" == "true" ]]; then
    echo "[dry-run] runuser -u debian-tor -- tor --verify-config -f /etc/tor/torrc"
    return 0
  fi

  if command -v tor >/dev/null 2>&1 && id debian-tor >/dev/null 2>&1; then
    runuser -u debian-tor -- tor --verify-config -f /etc/tor/torrc
  fi
}

validate_privoxy_config() {
  if [[ "$DRY_RUN" == "true" ]]; then
    echo "[dry-run] validate privoxy config"
    return 0
  fi

  if command -v privoxy >/dev/null 2>&1; then
    if privoxy --help 2>&1 | grep -q -- "--config-test"; then
      privoxy --config-test /etc/privoxy/config >/dev/null
    else
      echo "Privoxy config-test option not available; skipping syntax validation."
    fi
  fi
}

wait_for_listening_port() {
  local port="$1"
  local name="$2"
  local retries="${3:-30}"
  local delay="${4:-1}"

  if [[ "$DRY_RUN" == "true" ]]; then
    echo "[dry-run] wait for $name to listen on port $port"
    return 0
  fi

  for _ in $(seq 1 "$retries"); do
    if ss -lntH | awk '{print $4}' | grep -Eq "(:|\])${port}$"; then
      echo "$name is listening on port $port"
      return 0
    fi
    sleep "$delay"
  done

  echo "ERROR: $name is not listening on port $port after ${retries}s" >&2
  echo "Current listening proxy ports:" >&2
  ss -lntp | grep -E ':9050|:9051|:8118|:8088' >&2 || true

  if [[ "$name" == "ProxyTor API" ]]; then
    echo
    echo "ProxyTor API service status:" >&2
    systemctl status proxytor-api --no-pager >&2 || true
    echo
    echo "ProxyTor API recent logs:" >&2
    journalctl -u proxytor-api -n 80 --no-pager >&2 || true
  fi

  return 1
}

echo "[1/10] Installing packages..."
if [[ "$SKIP_PACKAGES" == "true" ]]; then
  echo "Skipping package installation by request."
else
  run apt update
  run apt install -y \
    tor tor-geoipdb torsocks obfs4proxy proxychains \
    privoxy \
    python3 python3-venv python3-pip \
    sqlite3 iptables curl ca-certificates jq openssl iproute2
fi

echo "[2/10] Creating directories..."
run mkdir -p "$INSTALL_DIR" "$CONFIG_DIR" "$DATA_DIR" "$INSTALL_DIR/scripts" "$DEFAULT_DIR"

echo "[3/10] Installing application files..."
install_file proxytor_api/app.py "$INSTALL_DIR/app.py" 644
install_file telegram_bot/telegram_token_bot.py "$INSTALL_DIR/telegram_token_bot.py" 644
install_file scripts/rotate-token.sh "$INSTALL_DIR/scripts/rotate-token.sh" 755

echo "[4/10] Creating/updating Python virtual environment..."
if [[ ! -d "$INSTALL_DIR/venv" ]]; then
  run python3 -m venv "$INSTALL_DIR/venv"
else
  echo "Reusing existing virtual environment: $INSTALL_DIR/venv"
fi

run "$INSTALL_DIR/venv/bin/pip" install --upgrade pip
run "$INSTALL_DIR/venv/bin/pip" install -r proxytor_api/requirements.txt

echo "[5/10] Creating tokens if missing..."
write_token_if_missing "$CONFIG_DIR/token"
write_token_if_missing "$CONFIG_DIR/token.viewer"

echo "[6/10] Installing ProxyTor configuration..."
install_if_missing config/config.example.json "$CONFIG_DIR/config.json" 600
copy_example config/config.example.json "$CONFIG_DIR/config.example.json" 600

install_if_missing config/proxytor-telegram.example "$DEFAULT_DIR/proxytor-telegram" 600
copy_example config/proxytor-telegram.example "$DEFAULT_DIR/proxytor-telegram.example" 600

echo "[7/10] Installing Tor and Privoxy configuration examples..."
copy_example config/torrc.example /etc/tor/torrc.proxytor.example 644
copy_example config/privoxy.example /etc/privoxy/config.proxytor.example 644

if [[ "$HAD_TOR_CONFIG" != "true" ]]; then
  echo "No pre-existing Tor config found before package installation. Installing ProxyTor torrc."
  install_file config/torrc.example /etc/tor/torrc 644
elif [[ "$FORCE_CONFIG" == "true" ]]; then
  echo "Replacing existing Tor config because --force-config was used."
  install_file config/torrc.example /etc/tor/torrc 644
else
  echo "Preserving existing Tor config: /etc/tor/torrc"
  echo "ProxyTor example available at: /etc/tor/torrc.proxytor.example"
fi

if [[ "$HAD_PRIVOXY_CONFIG" != "true" ]]; then
  echo "No pre-existing Privoxy config found before package installation. Installing ProxyTor Privoxy config."
  install_file config/privoxy.example /etc/privoxy/config 644
elif [[ "$FORCE_CONFIG" == "true" ]]; then
  echo "Replacing existing Privoxy config because --force-config was used."
  install_file config/privoxy.example /etc/privoxy/config 644
else
  echo "Preserving existing Privoxy config: /etc/privoxy/config"
  echo "ProxyTor example available at: /etc/privoxy/config.proxytor.example"
fi

echo "[8/10] Installing systemd services..."
install_file systemd/proxytor-api.service /etc/systemd/system/proxytor-api.service 644
install_file systemd/proxytor-telegram-bot.service /etc/systemd/system/proxytor-telegram-bot.service 644

if [[ -f systemd/proxytor-token-rotate.service ]]; then
  install_file systemd/proxytor-token-rotate.service /etc/systemd/system/proxytor-token-rotate.service 644
fi

if [[ -f systemd/proxytor-token-rotate.timer ]]; then
  install_file systemd/proxytor-token-rotate.timer /etc/systemd/system/proxytor-token-rotate.timer 644
fi

run systemctl daemon-reload

echo "[9/10] Validating and enabling core services..."
validate_tor_config
validate_privoxy_config

run systemctl enable tor@default privoxy proxytor-api
run systemctl restart tor@default
run systemctl restart privoxy
run systemctl restart proxytor-api

wait_for_listening_port 9050 "Tor SOCKS" 30 1
wait_for_listening_port 9051 "Tor ControlPort" 30 1
wait_for_listening_port 8118 "Privoxy" 30 1
wait_for_listening_port 8088 "ProxyTor API" 60 1

trap - ERR

print_final_summary

echo
echo "Configuration notes:"
echo "- Existing /etc/tor/torrc and /etc/privoxy/config are preserved by default."
echo "- ProxyTor examples are available at:"
echo "  /etc/tor/torrc.proxytor.example"
echo "  /etc/privoxy/config.proxytor.example"
echo "- Use --force-config only if you explicitly want to replace Tor/Privoxy configs."
echo "- Backups are stored under: $BACKUP_DIR"
echo
echo "Optional next steps:"
echo "- Edit /etc/default/proxytor-telegram and enable proxytor-telegram-bot if Telegram is required."
echo "- Review /etc/proxytor-api/config.json before exposing the dashboard behind a reverse proxy."
echo "- Keep ports 9050 and 8118 restricted to trusted clients."
echo
echo "[10/10] Done."

