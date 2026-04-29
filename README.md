# ProxyTor Gateway

**ProxyTor Gateway** is a self-hosted Tor and Privoxy gateway with a web dashboard, Telegram integration, token-based access control, audit logging, traffic visibility, abuse detection and client ban management.

It is intended for homelabs, controlled security labs, privacy-aware self-hosted environments and internal infrastructure where a managed Tor/HTTP proxy gateway is required.

> **Project status:** v0.1.0 — Initial public release.  
> Review and adapt the configuration before using it in production.

---

## Key Features

- Tor SOCKS5 proxy gateway.
- Privoxy HTTP proxy forwarding traffic through Tor.
- FastAPI-based web dashboard and API.
- Admin and viewer access tokens.
- Telegram bot integration.
- Dynamic token rotation.
- Traffic and connection metrics.
- Recent client visibility.
- Audit and event logging.
- CSV/JSON audit export by date range.
- Abuse detection based on connection thresholds.
- Ban/unban controls from dashboard and Telegram.
- SQLite persistence.
- systemd service units.
- Reverse proxy friendly deployment.

---

## Architecture

### Proxy Flow

```text
Clients
  |
  |-- HTTP Proxy  :8118 --> Privoxy
  |                         |
  |-- SOCKS5 Proxy :9050 --> Tor
                            |
                            v
                       Tor Network
                            |
                            v
                         Internet
Dashboard/API Flow
Operator Browser
  |
  |-- Direct Access
  |     `-- http://PROXYTOR_IP:8088
  |
  `-- Reverse Proxy / VPN / NPMplus
        `-- ProxyTor API :8088
Telegram Workflow
Telegram Bot
  |
  `-- Local ProxyTor API
        |-- Status checks
        |-- Token retrieval and rotation
        |-- Ban/unban actions
        `-- Abuse alerts
Components
| Component       |  Default Port | Description                               |
| --------------- | ------------: | ----------------------------------------- |
| Tor SOCKS       |    `9050/tcp` | SOCKS5 proxy for trusted clients          |
| Tor ControlPort |    `9051/tcp` | Local-only Tor control interface          |
| Privoxy         |    `8118/tcp` | HTTP proxy forwarding through Tor         |
| ProxyTor API    |    `8088/tcp` | FastAPI dashboard and API                 |
| SQLite          |    Local file | Events, clients, traffic samples and bans |
| Telegram Bot    | Outbound only | Optional operational interface            |

Requirements
Recommended environment:

Debian 12 Bookworm.
Python 3.11 or newer.
systemd.
Tor.
Privoxy.
SQLite.
iptables.
Optional: NPMplus or another reverse proxy.
Optional: Telegram bot.
Security Notice
Do not expose these ports directly to the Internet:

Port	Service
9050/tcp	Tor SOCKS proxy
8118/tcp	Privoxy HTTP proxy
8088/tcp	ProxyTor API/dashboard
Recommended protections:

Keep proxy ports available only on trusted networks.
Publish the dashboard only through VPN, private access or a properly protected reverse proxy.
Use strong admin/viewer tokens.
Rotate tokens periodically.
Keep Telegram bot credentials private.
Never commit real tokens, internal IP addresses, production domains or private configuration.
Repository Layout
proxytor-gateway/
├── README.md
├── LICENSE
├── CHANGELOG.md
├── SECURITY.md
├── config/
│   ├── config.example.json
│   ├── proxytor-telegram.example
│   ├── torrc.example
│   └── privoxy.example
├── docs/
│   ├── DEPLOYMENT.md
│   ├── SECURITY.md
│   ├── TELEGRAM.md
│   ├── NPMPLUS.md
│   └── API.md
├── proxytor_api/
│   ├── app.py
│   ├── __init__.py
│   └── requirements.txt
├── telegram_bot/
│   └── telegram_token_bot.py
├── systemd/
│   ├── proxytor-api.service
│   ├── proxytor-telegram-bot.service
│   ├── proxytor-token-rotate.service
│   └── proxytor-token-rotate.timer
└── scripts/
    ├── install.sh
    ├── update.sh
    ├── backup.sh
    ├── restore.sh
    └── rotate-token.sh
Installation
Clone the repository:
git clone https://github.com/alvarodgarcia/proxytor-gateway.git
cd proxytor-gateway
Run the installer:
sudo bash scripts/install.sh
The installer will:

Install required packages.
Create /opt/proxytor-api.
Create /etc/proxytor-api.
Create /var/lib/proxytor-api.
Generate admin and viewer tokens.
Install systemd services.
Start the API service.

After installation, retrieve the generated tokens:
sudo cat /etc/proxytor-api/token
sudo cat /etc/proxytor-api/token.viewer
Open the dashboard:
http://PROXYTOR_IP:8088/
Configuration
Main configuration file:
/etc/proxytor-api/config.json
Example:
{
  "npmplus_ips": [
    "NPMPLUS_IP_1",
    "NPMPLUS_IP_2",
    "NPMPLUS_VIP"
  ],
  "protected_ips": [
    "127.0.0.1",
    "LAN_GATEWAY_IP",
    "PROXYTOR_IP"
  ],
  "recent_minutes": 10,
  "alert_service_down": true,
  "alert_exit_ip_change": false,
  "alert_new_client": false,
  "alert_connection_threshold": 60,
  "telegram_alerts": true,
  "abuse_detection_enabled": true,
  "abuse_connections_per_client": 25,
  "abuse_alert_interval_seconds": 900,
  "events_view_limit": 50,
  "events_max_view_limit": 500,
  "events_max_rows": 5000,
  "events_export_enabled": true,
  "ban_ports": [9050, 8118]
}
Telegram Bot

Copy the example configuration:
sudo cp config/proxytor-telegram.example /etc/default/proxytor-telegram
sudo nano /etc/default/proxytor-telegram
sudo chmod 600 /etc/default/proxytor-telegram
Required values:
TELEGRAM_BOT_TOKEN="YOUR_TELEGRAM_BOT_TOKEN"
TELEGRAM_CHAT_ID="YOUR_TELEGRAM_CHAT_ID"
PROXYTOR_URL="https://proxytor.example.com/"
Enable and start the bot:
sudo systemctl enable --now proxytor-telegram-bot
Available commands:
/start
/help
/token
/token_viewer
/token_admin
/rotate_viewer_token
/rotate_admin_token
/status
/url
/bans
/ban IP 1h
/ban IP 24h
/ban IP permanent
/unban IP
Reverse Proxy / NPMplus

Recommended dashboard publishing model:
Domain: proxytor.example.com
Scheme: http
Forward Host/IP: PROXYTOR_IP
Forward Port: 8088
Websockets: Off
Force SSL: On
HTTP/2: On
Do not expose Tor SOCKS or Privoxy as standard HTTP proxy hosts.

If using TCP streams through a reverse proxy, ProxyTor may only see the reverse proxy IP instead of the real client IP.
Audit and Event Export

ProxyTor stores operational events in SQLite.

The dashboard allows:

Limiting visible audit events.
Exporting events by date range.
Downloading CSV.
Downloading JSON.

API example:
curl -H "Authorization: Bearer VIEWER_TOKEN" \
  "http://127.0.0.1:8088/api/events/export?date_from=2026-01-01&date_to=2026-01-31&format=csv" \
  -o proxytor-events.csv
Abuse Detection and Banning

ProxyTor can detect clients with excessive active connections.

When abuse is detected:

A warning event is stored.
Telegram can send an alert.
The operator can ban the client for:
1 hour.
24 hours.
Permanently.

Ban actions are applied through a dedicated iptables chain:
PROXYTOR_BAN
Only configured proxy ports are affected.

Useful Commands

Check services:
systemctl status tor@default --no-pager
systemctl status privoxy --no-pager
systemctl status proxytor-api --no-pager
systemctl status proxytor-telegram-bot --no-pager
Check listening ports:
ss -lntup | egrep ':9050|:9051|:8118|:8088'
Test Tor SOCKS:
curl --socks5-hostname 127.0.0.1:9050 https://check.torproject.org/api/ip
Test Privoxy:
curl -x http://127.0.0.1:8118 https://check.torproject.org/api/ip
Backup:
sudo bash scripts/backup.sh
Update:
sudo bash scripts/update.sh
Rotate admin token:
sudo bash scripts/rotate-token.sh
Operational Notes
Viewer vs Admin

ProxyTor uses two token roles:
viewer -> read-only dashboard and metrics
admin  -> full control, service actions, token rotation and ban management
Sensitive actions must require the admin token.

Events

Event storage is limited by configuration:
{
  "events_max_rows": 5000,
  "events_view_limit": 50,
  "events_max_view_limit": 500
}
This prevents uncontrolled SQLite growth.

Tor Exit IP Alerts

Tor exit IP changes can be logged without sending Telegram notifications:
{
  "alert_exit_ip_change": false
}
This is the recommended default.

Project Status

ProxyTor Gateway is currently in early public release.

Current focus:

Make deployment repeatable.
Keep configuration generic.
Improve documentation.
Harden operational workflows.
Avoid committing environment-specific values.
Roadmap

Planned improvements:

More robust installer idempotency.
Dashboard screenshots.
GitHub Actions linting.
Release packaging.
Docker/LXC examples.
Optional nftables backend.
Optional allowlist mode.
Better device fingerprinting.
Dashboard configuration editor.
Disclaimer

ProxyTor Gateway is intended for legitimate privacy, research, testing and controlled security lab use.

Users are responsible for complying with applicable laws and policies in their jurisdiction and environment.

License

This project is released under the MIT License.
