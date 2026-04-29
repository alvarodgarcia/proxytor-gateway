#!/usr/bin/env bash
set -euo pipefail

REPO_URL="${REPO_URL:-https://github.com/alvarodgarcia/proxytor-gateway.git}"
REPO_DIR="${REPO_DIR:-/opt/proxytor-gateway}"
INSTALL_DIR="${INSTALL_DIR:-/opt/proxytor-api}"
CONFIG_DIR="${CONFIG_DIR:-/etc/proxytor-api}"
DATA_DIR="${DATA_DIR:-/var/lib/proxytor-api}"
BRANCH="${BRANCH:-main}"
BACKUP_DIR="/root/backup_proxytor_update_$(date +%F_%H%M%S)"

if [[ "${EUID}" -ne 0 ]]; then
  echo "ERROR: this updater must be run as root."
  exit 1
fi

echo "=================================================="
echo " ProxyTor Gateway updater"
echo "=================================================="
echo "Repository : $REPO_URL"
echo "Branch     : $BRANCH"
echo "Repo dir   : $REPO_DIR"
echo "Install dir: $INSTALL_DIR"
echo

echo "[1/10] Preparing repository..."
if [[ ! -d "$REPO_DIR/.git" ]]; then
  echo "Repository not found at $REPO_DIR. Cloning..."
  mkdir -p "$(dirname "$REPO_DIR")"
  git clone --branch "$BRANCH" "$REPO_URL" "$REPO_DIR"
fi

cd "$REPO_DIR"

echo "[2/10] Fetching latest Git changes..."
git fetch origin "$BRANCH" --tags

LOCAL_COMMIT="$(git rev-parse HEAD)"
REMOTE_COMMIT="$(git rev-parse "origin/$BRANCH")"

echo "Local commit : $LOCAL_COMMIT"
echo "Remote commit: $REMOTE_COMMIT"

if [[ "$LOCAL_COMMIT" == "$REMOTE_COMMIT" ]]; then
  GIT_UPDATE_NEEDED="false"
  echo "ProxyTor Gateway source is already up to date."
else
  GIT_UPDATE_NEEDED="true"
  echo "New ProxyTor Gateway source version available."
fi

echo "[3/10] Creating backup..."
mkdir -p "$BACKUP_DIR/opt" "$BACKUP_DIR/etc" "$BACKUP_DIR/default" "$BACKUP_DIR/systemd"

if [[ -d "$INSTALL_DIR" ]]; then
  cp -a "$INSTALL_DIR" "$BACKUP_DIR/opt/proxytor-api"
fi

if [[ -d "$CONFIG_DIR" ]]; then
  cp -a "$CONFIG_DIR" "$BACKUP_DIR/etc/proxytor-api"
fi

if [[ -d "$DATA_DIR" ]]; then
  cp -a "$DATA_DIR" "$BACKUP_DIR/var_lib_proxytor-api"
fi

if [[ -f /etc/default/proxytor-telegram ]]; then
  cp -a /etc/default/proxytor-telegram "$BACKUP_DIR/default/proxytor-telegram"
fi

for unit in \
  proxytor-api.service \
  proxytor-telegram-bot.service \
  proxytor-token-rotate.service \
  proxytor-token-rotate.timer
  do
    if [[ -f "/etc/systemd/system/$unit" ]]; then
      cp -a "/etc/systemd/system/$unit" "$BACKUP_DIR/systemd/$unit"
    fi
  done

echo "Backup created at: $BACKUP_DIR"

echo "[4/10] Updating system packages..."
apt update
apt install --only-upgrade -y \
  tor tor-geoipdb torsocks obfs4proxy proxychains privoxy \
  || true

if [[ "$GIT_UPDATE_NEEDED" == "true" ]]; then
  echo "[5/10] Updating repository working tree..."
  git pull --ff-only origin "$BRANCH"
else
  echo "[5/10] Skipping Git pull. Already up to date."
fi

echo "[6/10] Deploying ProxyTor application files..."
mkdir -p "$INSTALL_DIR" "$INSTALL_DIR/scripts" "$CONFIG_DIR" "$DATA_DIR"

cp proxytor_api/app.py "$INSTALL_DIR/app.py"
cp telegram_bot/telegram_token_bot.py "$INSTALL_DIR/telegram_token_bot.py"
cp scripts/rotate-token.sh "$INSTALL_DIR/scripts/rotate-token.sh"
chmod +x "$INSTALL_DIR/scripts/rotate-token.sh"

if [[ -d "$INSTALL_DIR/venv" ]]; then
  "$INSTALL_DIR/venv/bin/pip" install --upgrade pip
  "$INSTALL_DIR/venv/bin/pip" install -r proxytor_api/requirements.txt
else
  python3 -m venv "$INSTALL_DIR/venv"
  "$INSTALL_DIR/venv/bin/pip" install --upgrade pip
  "$INSTALL_DIR/venv/bin/pip" install -r proxytor_api/requirements.txt
fi

echo "[7/10] Updating systemd units..."
cp systemd/proxytor-api.service /etc/systemd/system/
cp systemd/proxytor-telegram-bot.service /etc/systemd/system/
cp systemd/proxytor-token-rotate.service /etc/systemd/system/ 2>/dev/null || true
cp systemd/proxytor-token-rotate.timer /etc/systemd/system/ 2>/dev/null || true
systemctl daemon-reload

echo "[8/10] Ensuring local configuration files exist..."
if [[ ! -f "$CONFIG_DIR/config.json" ]]; then
  cp config/config.example.json "$CONFIG_DIR/config.json"
  chmod 600 "$CONFIG_DIR/config.json"
fi

if [[ ! -f /etc/default/proxytor-telegram ]]; then
  cp config/proxytor-telegram.example /etc/default/proxytor-telegram
  chmod 600 /etc/default/proxytor-telegram
fi

echo "[9/10] Validating Tor configuration..."
runuser -u debian-tor -- tor --verify-config -f /etc/tor/torrc

echo "[10/10] Restarting and checking services..."
systemctl restart tor@default
systemctl restart privoxy
systemctl restart proxytor-api || true
systemctl restart proxytor-telegram-bot || true

echo
echo "Listening ports:"
ss -lntup | grep -E ':9050|:9051|:8118|:8088' || true

echo
echo "Current ProxyTor Gateway version:"
cd "$REPO_DIR"
git log -1 --oneline

echo
echo "Update completed."
echo "Backup: $BACKUP_DIR"
