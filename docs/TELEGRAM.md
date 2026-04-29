# Telegram Bot

ProxyTor Gateway can optionally use a Telegram bot for operational actions and notifications.

The bot can be used to:

- Retrieve viewer/admin tokens.
- Rotate tokens.
- Check service status.
- Receive abuse alerts.
- Ban or unban client IPs.

## Configuration

Copy the example file:

```bash
sudo cp config/proxytor-telegram.example /etc/default/proxytor-telegram
sudo nano /etc/default/proxytor-telegram
sudo chmod 600 /etc/default/proxytor-telegram
```

Required values:

| Variable | Description |
|---|---|
| `TELEGRAM_BOT_TOKEN` | Telegram bot token generated with BotFather |
| `TELEGRAM_CHAT_ID` | Authorized Telegram chat ID |
| `PROXYTOR_URL` | Public or internal dashboard URL |

Example:

```bash
TELEGRAM_BOT_TOKEN="YOUR_TELEGRAM_BOT_TOKEN"
TELEGRAM_CHAT_ID="YOUR_TELEGRAM_CHAT_ID"
PROXYTOR_URL="https://proxytor.example.com/"
```

## Service management

Enable and start the bot:

```bash
sudo systemctl enable --now proxytor-telegram-bot
```

Check status:

```bash
sudo systemctl status proxytor-telegram-bot --no-pager
```

View logs:

```bash
sudo journalctl -u proxytor-telegram-bot -n 100 --no-pager
```

## Commands

| Command | Purpose |
|---|---|
| `/start` | Show help |
| `/help` | Show help |
| `/token` | Show viewer token |
| `/token_viewer` | Show viewer token |
| `/token_admin` | Show admin token |
| `/rotate_viewer_token` | Rotate viewer token |
| `/rotate_admin_token` | Rotate admin token |
| `/status` | Show service and proxy status |
| `/url` | Show dashboard URL |
| `/bans` | Show active bans |
| `/ban IP 1h` | Ban an IP for 1 hour |
| `/ban IP 24h` | Ban an IP for 24 hours |
| `/ban IP permanent` | Ban an IP permanently |
| `/unban IP` | Remove an active ban |

## Security notes

- The bot should only answer the configured `TELEGRAM_CHAT_ID`.
- Keep `TELEGRAM_BOT_TOKEN` private.
- Treat `/token_admin` as sensitive.
- Avoid forwarding bot messages containing tokens.
