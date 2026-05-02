#!/usr/bin/env bash
set -euo pipefail

INSTALL_DIR="${INSTALL_DIR:-/opt/proxytor-api}"
CONFIG_DIR="${CONFIG_DIR:-/etc/proxytor-api}"
DATA_DIR="${DATA_DIR:-/var/lib/proxytor-api}"
DEFAULT_DIR="/etc/default"
BACKUP_ROOT="${BACKUP_ROOT:-/root/proxytor-install-backups}"
BACKUP_DIR="$BACKUP_ROOT/$(date +%F_%H%M%S)"

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

SERVER_IP="$(detect_server_ip)"

echo "[10/10] Done."
echo

echo "Admin token:"
if [[ "$DRY_RUN" == "true" ]]; then
  echo "[dry-run] $CONFIG_DIR/token"
else
  cat "$CONFIG_DIR/token"
fi

echo
echo "Viewer token:"
if [[ "$DRY_RUN" == "true" ]]; then
  echo "[dry-run] $CONFIG_DIR/token.viewer"
else
  cat "$CONFIG_DIR/token.viewer"
fi

echo
echo "Open dashboard:"
echo "http://${SERVER_IP}:8088/"
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

echo "Optional admin token auto-rotation:"
echo "- Enable 24h admin token rotation:"
echo "  sudo systemctl enable --now proxytor-token-rotate.timer"
echo "- Check next scheduled rotation:"
echo "  systemctl list-timers | grep proxytor"
echo "- Check timer status:"
echo "  systemctl status proxytor-token-rotate.timer --no-pager"
echo "- Rotate admin token manually now:"
echo "  sudo /opt/proxytor-api/scripts/rotate-token.sh"
echo "- Disable automatic rotation if needed:"
echo "  sudo systemctl disable --now proxytor-token-rotate.timer"
echo

echo "Note: automatic rotation only affects the admin token. Viewer token rotation remains manual."
