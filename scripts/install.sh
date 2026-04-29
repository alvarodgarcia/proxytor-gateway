#!/usr/bin/env bash
set -euo pipefail

echo "=================================================="
echo " ProxyTor Gateway installer"
echo "=================================================="

INSTALL_DIR="/opt/proxytor-api"
CONFIG_DIR="/etc/proxytor-api"
DATA_DIR="/var/lib/proxytor-api"
BACKUP_SUFFIX="proxytor-backup-$(date +%F_%H%M%S)"

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

echo "[1/10] Installing packages..."
apt update
apt install -y \
  tor tor-geoipdb torsocks obfs4proxy proxychains \
  privoxy \
  python3 python3-venv python3-pip \
  sqlite3 iptables curl ca-certificates jq openssl iproute2

echo "[2/10] Creating directories..."
mkdir -p "$INSTALL_DIR" "$CONFIG_DIR" "$DATA_DIR" "$INSTALL_DIR/scripts" /etc/default

echo "[3/10] Installing application files..."
cp proxytor_api/app.py "$INSTALL_DIR/app.py"
cp telegram_bot/telegram_token_bot.py "$INSTALL_DIR/telegram_token_bot.py"
cp scripts/rotate-token.sh "$INSTALL_DIR/scripts/rotate-token.sh"
chmod +x "$INSTALL_DIR/scripts/rotate-token.sh"

echo "[4/10] Creating Python virtual environment..."
python3 -m venv "$INSTALL_DIR/venv"
"$INSTALL_DIR/venv/bin/pip" install --upgrade pip
"$INSTALL_DIR/venv/bin/pip" install -r proxytor_api/requirements.txt

echo "[5/10] Creating tokens..."
if [[ ! -f "$CONFIG_DIR/token" ]]; then
  openssl rand -hex 32 > "$CONFIG_DIR/token"
fi

if [[ ! -f "$CONFIG_DIR/token.viewer" ]]; then
  openssl rand -hex 32 > "$CONFIG_DIR/token.viewer"
fi

chmod 600 "$CONFIG_DIR/token" "$CONFIG_DIR/token.viewer"
chown root:root "$CONFIG_DIR/token" "$CONFIG_DIR/token.viewer"

echo "[6/10] Installing ProxyTor configuration..."
if [[ ! -f "$CONFIG_DIR/config.json" ]]; then
  cp config/config.example.json "$CONFIG_DIR/config.json"
  chmod 600 "$CONFIG_DIR/config.json"
fi

if [[ ! -f /etc/default/proxytor-telegram ]]; then
  cp config/proxytor-telegram.example /etc/default/proxytor-telegram
  chmod 600 /etc/default/proxytor-telegram
fi

echo "[7/10] Applying Tor and Privoxy example configuration..."
if [[ -f /etc/tor/torrc ]]; then
  cp -a /etc/tor/torrc "/etc/tor/torrc.$BACKUP_SUFFIX"
fi
cp config/torrc.example /etc/tor/torrc

if [[ -f /etc/privoxy/config ]]; then
  cp -a /etc/privoxy/config "/etc/privoxy/config.$BACKUP_SUFFIX"
fi
cp config/privoxy.example /etc/privoxy/config

echo "[8/10] Installing systemd services..."
cp systemd/proxytor-api.service /etc/systemd/system/
cp systemd/proxytor-telegram-bot.service /etc/systemd/system/
cp systemd/proxytor-token-rotate.service /etc/systemd/system/ 2>/dev/null || true
cp systemd/proxytor-token-rotate.timer /etc/systemd/system/ 2>/dev/null || true

systemctl daemon-reload

echo "[9/10] Enabling core services..."
systemctl enable tor@default privoxy proxytor-api
systemctl restart tor@default
systemctl restart privoxy
systemctl restart proxytor-api

SERVER_IP="$(detect_server_ip)"

echo "[10/10] Done."
echo
echo "Admin token:"
cat "$CONFIG_DIR/token"
echo
echo "Viewer token:"
cat "$CONFIG_DIR/token.viewer"
echo
echo "Open dashboard:"
echo "http://${SERVER_IP}:8088/"
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
