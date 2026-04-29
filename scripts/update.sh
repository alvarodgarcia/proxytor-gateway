#!/usr/bin/env bash
set -euo pipefail

echo "=================================================="
echo " ProxyTor Gateway updater"
echo "=================================================="

echo "[1/5] Updating package lists..."
apt update

echo "[2/5] Updating Tor/Privoxy packages..."
apt install --only-upgrade -y tor tor-geoipdb torsocks obfs4proxy proxychains privoxy || true

echo "[3/5] Validating Tor configuration..."
runuser -u debian-tor -- tor --verify-config -f /etc/tor/torrc

echo "[4/5] Restarting services..."
systemctl restart tor@default
systemctl restart privoxy
systemctl restart proxytor-api || true
systemctl restart proxytor-telegram-bot || true

echo "[5/5] Checking ports..."
ss -lntup | egrep ':9050|:9051|:8118|:8088' || true

echo "Update completed."
