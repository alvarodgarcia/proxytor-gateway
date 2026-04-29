#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo "Usage: $0 /root/backup_proxytor_YYYY-MM-DD_HHMMSS"
  exit 1
fi

BACKUP_DIR="$1"

if [[ ! -d "$BACKUP_DIR" ]]; then
  echo "Backup directory not found: $BACKUP_DIR"
  exit 1
fi

systemctl stop proxytor-api 2>/dev/null || true
systemctl stop proxytor-telegram-bot 2>/dev/null || true

if [[ -d "$BACKUP_DIR/opt/proxytor-api" ]]; then
  rm -rf /opt/proxytor-api
  cp -a "$BACKUP_DIR/opt/proxytor-api" /opt/proxytor-api
fi

if [[ -d "$BACKUP_DIR/etc/proxytor-api" ]]; then
  rm -rf /etc/proxytor-api
  cp -a "$BACKUP_DIR/etc/proxytor-api" /etc/proxytor-api
fi

if [[ -f "$BACKUP_DIR/default/proxytor-telegram" ]]; then
  cp -a "$BACKUP_DIR/default/proxytor-telegram" /etc/default/proxytor-telegram
fi

if [[ -d "$BACKUP_DIR/systemd" ]]; then
  cp -a "$BACKUP_DIR/systemd/"* /etc/systemd/system/ 2>/dev/null || true
fi

if [[ -f "$BACKUP_DIR/etc/tor/torrc" ]]; then
  cp -a "$BACKUP_DIR/etc/tor/torrc" /etc/tor/torrc
fi

if [[ -f "$BACKUP_DIR/etc/privoxy/config" ]]; then
  cp -a "$BACKUP_DIR/etc/privoxy/config" /etc/privoxy/config
fi

systemctl daemon-reload
systemctl start tor@default 2>/dev/null || true
systemctl start privoxy 2>/dev/null || true
systemctl start proxytor-api 2>/dev/null || true
systemctl start proxytor-telegram-bot 2>/dev/null || true

echo "Restore completed from: $BACKUP_DIR"
