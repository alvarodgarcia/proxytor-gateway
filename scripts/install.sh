#!/usr/bin/env bash
set -euo pipefail

echo "=================================================="
echo " ProxyTor Gateway installer"
echo "=================================================="

INSTALL_DIR="/opt/proxytor-api"
CONFIG_DIR="/etc/proxytor-api"
DATA_DIR="/var/lib/proxytor-api"

echo "[1/9] Installing packages..."
apt update
apt install -y \
  tor tor-geoipdb torsocks obfs4proxy proxychains \
  privoxy \
  python3 python3-venv python3-pip \
  sqlite3 iptables curl ca-certificates jq

echo "[2/9] Creating directories..."
mkdir -p "$INSTALL_DIR" "$CONFIG_DIR" "$DATA_DIR"

echo "[3/9] Installing application files..."
cp proxytor_api/app.py "$INSTALL_DIR/app.py"
cp telegram_bot/telegram_token_bot.py "$INSTALL_DIR/telegram_token_bot.py"

echo "[4/9] Creating Python virtual environment..."
python3 -m venv "$INSTALL_DIR/venv"
"$INSTALL_DIR/venv/bin/pip" install --upgrade pip
"$INSTALL_DIR/venv/bin/pip" install -r proxytor_api/requirements.txt

echo "[5/9] Creating tokens..."
if [[ ! -f "$CONFIG_DIR/token" ]]; then
  openssl rand -hex 32 > "$CONFIG_DIR/token"
fi

if [[ ! -f "$CONFIG_DIR/token.viewer" ]]; then
  openssl rand -hex 32 > "$CONFIG_DIR/token.viewer"
fi

chmod 600 "$CONFIG_DIR/token" "$CONFIG_DIR/token.viewer"

echo "[6/9] Installing example config if missing..."
if [[ ! -f "$CONFIG_DIR/config.json" ]]; then
  cp config/config.example.json "$CONFIG_DIR/config.json"
  chmod 600 "$CONFIG_DIR/config.json"
fi

if [[ ! -f /etc/default/proxytor-telegram ]]; then
  cp config/proxytor-telegram.example /etc/default/proxytor-telegram
  chmod 600 /etc/default/proxytor-telegram
fi

echo "[7/9] Installing systemd services..."
cp systemd/proxytor-api.service /etc/systemd/system/
cp systemd/proxytor-telegram-bot.service /etc/systemd/system/
cp systemd/proxytor-token-rotate.service /etc/systemd/system/ 2>/dev/null || true
cp systemd/proxytor-token-rotate.timer /etc/systemd/system/ 2>/dev/null || true

systemctl daemon-reload

echo "[8/9] Enabling services..."
systemctl enable tor@default privoxy proxytor-api
systemctl restart tor@default
systemctl restart privoxy
systemctl restart proxytor-api

echo "[9/9] Done."
echo
echo "Admin token:"
cat "$CONFIG_DIR/token"
echo
echo "Viewer token:"
cat "$CONFIG_DIR/token.viewer"
echo
echo "Open dashboard:"
echo "http://SERVER_IP:8088/"
