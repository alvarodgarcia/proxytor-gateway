#!/usr/bin/env bash
set -euo pipefail

BACKUP_DIR="/root/backup_proxytor_$(date +%F_%H%M%S)"

mkdir -p "$BACKUP_DIR"

cp -a /opt/proxytor-api "$BACKUP_DIR/" 2>/dev/null || true
cp -a /etc/proxytor-api "$BACKUP_DIR/" 2>/dev/null || true
cp -a /etc/default/proxytor-telegram "$BACKUP_DIR/" 2>/dev/null || true
cp -a /etc/systemd/system/proxytor-api.service "$BACKUP_DIR/" 2>/dev/null || true
cp -a /etc/systemd/system/proxytor-telegram-bot.service "$BACKUP_DIR/" 2>/dev/null || true
cp -a /etc/systemd/system/proxytor-token-rotate.service "$BACKUP_DIR/" 2>/dev/null || true
cp -a /etc/systemd/system/proxytor-token-rotate.timer "$BACKUP_DIR/" 2>/dev/null || true

echo "Backup created at: $BACKUP_DIR"
