#!/usr/bin/env bash
set -euo pipefail

TOKEN_DIR="/etc/proxytor-api"
TOKEN_FILE="${TOKEN_DIR}/token"
PREVIOUS_FILE="${TOKEN_DIR}/token.previous"

mkdir -p "$TOKEN_DIR"

if [[ -f "$TOKEN_FILE" ]]; then
  cp "$TOKEN_FILE" "$PREVIOUS_FILE"
  chmod 600 "$PREVIOUS_FILE"
fi

NEW_TOKEN="$(openssl rand -hex 32)"
echo "$NEW_TOKEN" > "$TOKEN_FILE"

chmod 600 "$TOKEN_FILE"
chown root:root "$TOKEN_FILE"

echo "ProxyTor admin token rotated."
echo "$NEW_TOKEN"
