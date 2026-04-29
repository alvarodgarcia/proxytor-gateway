#!/usr/bin/env bash
set -euo pipefail

BACKUP_DIR="/root/backup_proxytor_$(date +%F_%H%M%S)"

mkdir -p "$BACKUP_DIR/opt"
mkdir -p "$BACKUP_DIR/etc"
mkdir -p "$BACKUP_DIR/systemd"
mkdir -p "$BACKUP_DIR/default"

if [[ -d /opt/proxytor-api ]]; then
  cp -a /opt/proxytor-api "$BACKUP_DIR/opt/proxytor-api"
fi

if [[ -d /etc/proxytor-api ]]; then
  cp -a /etc/proxytor-api "$BACKUP_DIR/etc/proxytor-api"
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

if [[ -f /etc/tor/torrc ]]; then
  mkdir -p "$BACKUP_DIR/etc/tor"
  cp -a /etc/tor/torrc "$BACKUP_DIR/etc/tor/torrc"
fi

if [[ -f /etc/privoxy/config ]]; then
  mkdir -p "$BACKUP_DIR/etc/privoxy"
  cp -a /etc/privoxy/config "$BACKUP_DIR/etc/privoxy/config"
fi

echo "Backup created at: $BACKUP_DIR"
