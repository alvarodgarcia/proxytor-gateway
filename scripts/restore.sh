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

if [[ -d "$BACKUP_DIR/proxytor-api" ]]; then
  rm -rf /opt/proxytor-api
  cp -a "$BACKUP_DIR/proxytor-api" /opt/
fi

if [[ -d "$BACKUP_DIR/proxytor-api" ]]; then
  cp -a "$BACKUP_DIR/proxytor-api" /etc/ 2>/dev/null || true
fi

systemctl daemon-reload
systemctl start proxytor-api 2>/dev/null || true
systemctl start proxytor-telegram-bot 2>/dev/null || true

echo "Restore completed from: $BACKUP_DIR"
