#!/usr/bin/env bash
set -euo pipefail

BACKUP_DIR="/root/proxytor-backup-$(date +%F_%H%M%S)"
mkdir -p "$BACKUP_DIR"

cp -a /opt/proxytor-api "$BACKUP_DIR/" 2>/dev/null || true
cp -a /etc/proxytor-api "$BACKUP_DIR/" 2>/dev/null || true
cp -a /etc/default/proxytor-telegram "$BACKUP_DIR/" 2>/dev/null || true
cp -a /etc/systemd/system/proxytor-*.service "$BACKUP_DIR/" 2>/dev/null || true
cp -a /etc/systemd/system/proxytor-*.timer "$BACKUP_DIR/" 2>/dev/null || true

if [ -f /var/lib/proxytor-api/proxytor.db ]; then
  cp -a /var/lib/proxytor-api/proxytor.db "$BACKUP_DIR/"
fi

tar czf "${BACKUP_DIR}.tgz" -C "$(dirname "$BACKUP_DIR")" "$(basename "$BACKUP_DIR")"
echo "Backup created: ${BACKUP_DIR}.tgz"
